import { createHash, createVerify, generateKeyPairSync, randomBytes } from 'node:crypto';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import {
  GitHubInstallationStatusValue,
  MembershipStatusValue,
  normalizeEmail,
  normalizeSlug,
  OrganizationRoleValue,
  UserStatusValue,
  type GitHubInstallationStatus,
  type MembershipStatus,
  type OrganizationRole,
  type UserStatus,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import type { GitHubRuntimeConfig } from '../config/env.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';
import { createAuthService } from '../modules/auth/auth.service.js';
import type { AuthStore } from '../modules/auth/auth.store.js';
import { createJwtService } from '../modules/auth/jwt.service.js';
import { createPasswordService } from '../modules/auth/password.service.js';
import { createGitHubClient } from '../modules/github/github.client.js';
import { createGitHubAppJwt } from '../modules/github/github.jwt.js';
import { createGitHubService } from '../modules/github/github.service.js';
import type { GitHubIntegrationStore } from '../modules/github/github.store.js';
import type { PublicGitHubInstallation } from '../modules/github/github.types.js';
import { createOrganizationService } from '../modules/organizations/organization.service.js';
import type { OrganizationStore } from '../modules/organizations/organization.store.js';

function generateTestRsaKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

const TEST_KEYS = generateTestRsaKeyPair();

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'test_github_jwt_access_secret_minimum_32_characters',
  jwtAccessTtl: '15m',
  jwtAccessTtlSeconds: 900,
  jwtIssuer: 'vibeshield-api',
  jwtAudience: 'vibeshield-clients',
  refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
  isProduction: false,
  cookiePath: '/api/v1/auth',
  allowedOrigins: ['http://localhost:5173'],
};

const TEST_GITHUB_CONFIG: GitHubRuntimeConfig = {
  appId: 77777,
  appSlug: 'vibeshield-test-app',
  privateKeyPem: TEST_KEYS.privateKeyPem,
  clientId: 'Iv1.testclient1234',
  clientSecret: 'gh_client_secret_test_value_123456',
  webhookSecret: 'whsec_test_webhook_secret_at_least_32_chars',
};

function makeObjectId(counter: number): string {
  return counter.toString(16).padStart(24, '0');
}

function createInMemoryGitHubHarness(
  options: {
    nowRef?: { current: Date };
    fetchImpl?: typeof fetch;
    githubConfig?: GitHubRuntimeConfig | null;
  } = {}
) {
  let idCounter = 1;
  const nowRef = options.nowRef ?? { current: new Date() };
  const users = new Map<
    string,
    {
      id: string;
      email: string;
      displayName: string;
      passwordHash: string;
      status: UserStatus;
      createdAt: Date;
      updatedAt: Date;
    }
  >();
  const sessions = new Map<
    string,
    {
      id: string;
      userId: string;
      refreshTokenHash: string;
      previousRefreshTokenHash: string | null;
      expiresAt: Date;
      revokedAt: Date | null;
      lastUsedAt: Date | null;
      createdAt: Date;
    }
  >();
  const rotatedTokens = new Set<string>();
  const orgs = new Map<
    string,
    { id: string; name: string; slug: string; createdBy: string; createdAt: Date; updatedAt: Date }
  >();
  const memberships = new Map<
    string,
    {
      id: string;
      userId: string;
      organizationId: string;
      role: OrganizationRole;
      status: MembershipStatus;
      createdAt: Date;
      updatedAt: Date;
    }
  >();
  const oauthStates = new Map<
    string,
    {
      stateHash: string;
      userId: string;
      organizationId: string;
      usedAt: Date | null;
      expiresAt: Date;
    }
  >();
  const installations = new Map<string, PublicGitHubInstallation>();
  const auditLogs: Array<Record<string, unknown>> = [];

  const authStore: AuthStore = {
    async createUser(input) {
      const id = makeObjectId(idCounter++);
      const now = nowRef.current;
      const user = {
        id,
        email: normalizeEmail(input.email),
        displayName: input.displayName,
        passwordHash: input.passwordHash,
        status: input.status,
        createdAt: now,
        updatedAt: now,
      };
      users.set(id, user);
      return {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        status: user.status,
        createdAt: user.createdAt,
      };
    },
    async findUserWithPasswordByEmail(email) {
      const normalized = normalizeEmail(email);
      return Array.from(users.values()).find((u) => u.email === normalized) ?? null;
    },
    async findActiveUserById(id) {
      const u = users.get(id);
      if (!u || u.status !== UserStatusValue.ACTIVE) {
        return null;
      }
      return {
        id: u.id,
        email: u.email,
        displayName: u.displayName,
        status: u.status,
        createdAt: u.createdAt,
      };
    },
    async createSession(input) {
      const id = makeObjectId(idCounter++);
      const session = {
        id,
        userId: input.userId,
        refreshTokenHash: input.refreshTokenHash,
        previousRefreshTokenHash: null,
        expiresAt: input.expiresAt,
        revokedAt: null,
        lastUsedAt: input.lastUsedAt,
        createdAt: nowRef.current,
      };
      sessions.set(id, session);
      return { id: session.id, userId: session.userId };
    },
    async rotateSession() {
      return null;
    },
    async recordRotatedToken(input) {
      rotatedTokens.add(input.tokenHash);
    },
    async revokeSessionByPreviousTokenHash() {
      return false;
    },
    async revokeSessionByRotatedTokenHash(hash) {
      return rotatedTokens.has(hash);
    },
    async findActiveSessionByIdAndUserId(sessionId, userId, now) {
      const s = sessions.get(sessionId);
      if (!s || s.userId !== userId || s.revokedAt !== null || s.expiresAt <= now) {
        return null;
      }
      return { id: s.id, userId: s.userId };
    },
    async revokeSessionById(sessionId, revokedAt) {
      const s = sessions.get(sessionId);
      if (s && !s.revokedAt) {
        s.revokedAt = revokedAt;
      }
    },
    async revokeSessionByIdAndUserId(sessionId, userId, revokedAt) {
      const s = sessions.get(sessionId);
      if (s && s.userId === userId && !s.revokedAt) {
        s.revokedAt = revokedAt;
      }
    },
    async revokeSessionByTokenHash(hash, revokedAt) {
      const s = Array.from(sessions.values()).find((item) => item.refreshTokenHash === hash);
      if (s && !s.revokedAt) {
        s.revokedAt = revokedAt;
      }
    },
  };

  const orgStore: OrganizationStore = {
    async withTransaction(work) {
      return work({});
    },
    async acquireOrganizationLock(organizationId) {
      return orgs.has(organizationId);
    },
    async createOrganization(input) {
      const id = makeObjectId(idCounter++);
      const now = nowRef.current;
      const org = {
        id,
        name: input.name,
        slug: normalizeSlug(input.slug),
        createdBy: input.createdBy,
        createdAt: now,
        updatedAt: now,
      };
      orgs.set(id, org);
      return org;
    },
    async findOrganizationById(id) {
      return orgs.get(id) ?? null;
    },
    async updateOrganizationById() {
      return null;
    },
    async deleteOrganizationById(id) {
      return orgs.delete(id);
    },
    async hasProjectsInOrganization() {
      return false;
    },
    async listActiveOrganizationsForUser(userId) {
      return Array.from(memberships.values())
        .filter((m) => m.userId === userId && m.status === MembershipStatusValue.ACTIVE)
        .map((m) => ({ ...orgs.get(m.organizationId)!, role: m.role }));
    },
    async createMembership(input) {
      const id = makeObjectId(idCounter++);
      const now = nowRef.current;
      const rec = {
        id,
        userId: input.userId,
        organizationId: input.organizationId,
        role: input.role,
        status: input.status,
        createdAt: now,
        updatedAt: now,
      };
      memberships.set(id, rec);
      return rec;
    },
    async findActiveMembership(organizationId, userId) {
      return (
        Array.from(memberships.values()).find(
          (m) =>
            m.organizationId === organizationId &&
            m.userId === userId &&
            m.status === MembershipStatusValue.ACTIVE
        ) ?? null
      );
    },
    async findMembershipByIdInOrganization(orgId, membershipId) {
      const m = memberships.get(membershipId);
      return m && m.organizationId === orgId ? m : null;
    },
    async findMembershipByOrgAndUser(orgId, userId) {
      return (
        Array.from(memberships.values()).find(
          (m) => m.organizationId === orgId && m.userId === userId
        ) ?? null
      );
    },
    async listMembersInOrganization() {
      return [];
    },
    async updateMembershipByIdInOrganization() {
      return null;
    },
    async deleteMembershipByIdInOrganization() {
      return false;
    },
    async deleteAllMembershipsInOrganization() {
      return;
    },
    async countActiveOwnersExcluding() {
      return 1;
    },
    async countActiveOwners() {
      return 1;
    },
    async findUserByEmail(email) {
      return Array.from(users.values()).find((u) => u.email === normalizeEmail(email)) ?? null;
    },
    async findUserById(userId) {
      return users.get(userId) ?? null;
    },
  };

  const githubStore: GitHubIntegrationStore = {
    async withTransaction(work) {
      return work({});
    },
    async acquireOrganizationLock(organizationId) {
      return orgs.has(organizationId);
    },
    async findActiveMembership(organizationId, userId) {
      return orgStore.findActiveMembership(organizationId, userId);
    },
    async createOAuthState(input) {
      oauthStates.set(input.stateHash, {
        ...input,
        usedAt: null,
      });
    },
    async consumeOAuthState(input) {
      const rec = oauthStates.get(input.stateHash);
      if (
        !rec ||
        rec.userId !== input.userId ||
        rec.organizationId !== input.organizationId ||
        rec.usedAt !== null ||
        rec.expiresAt.getTime() <= input.now.getTime()
      ) {
        return false;
      }
      rec.usedAt = input.now;
      return true;
    },
    async findActiveInstallationByGitHubId(githubInstallationId) {
      return (
        Array.from(installations.values()).find(
          (inst) =>
            inst.githubInstallationId === githubInstallationId &&
            (inst.status === GitHubInstallationStatusValue.ACTIVE ||
              inst.status === GitHubInstallationStatusValue.SUSPENDED)
        ) ?? null
      );
    },
    async findInstallationByIdInOrganization(organizationId, installationRecordId) {
      const rec = installations.get(installationRecordId);
      return rec && rec.organizationId === organizationId ? rec : null;
    },
    async listInstallationsInOrganization(organizationId) {
      return Array.from(installations.values()).filter(
        (inst) =>
          inst.organizationId === organizationId &&
          inst.status !== GitHubInstallationStatusValue.DISCONNECTED
      );
    },
    async createInstallation(input) {
      const id = makeObjectId(idCounter++);
      const now = nowRef.current;
      const rec: PublicGitHubInstallation = {
        id,
        organizationId: input.organizationId,
        githubInstallationId: input.githubInstallationId,
        githubAppId: input.githubAppId,
        accountId: input.accountId,
        accountLogin: input.accountLogin,
        accountType: input.accountType,
        repositorySelection: input.repositorySelection,
        grantedPermissions: input.grantedPermissions,
        status: input.status,
        suspendedAt: input.suspendedAt,
        revokedAt: input.revokedAt,
        lastSyncedAt: input.lastSyncedAt,
        createdAt: now,
        updatedAt: now,
      };
      installations.set(id, rec);
      return rec;
    },
    async updateInstallationInOrganization(organizationId, installationRecordId, updates) {
      const existing = installations.get(installationRecordId);
      if (!existing || existing.organizationId !== organizationId) {
        return null;
      }
      const next: PublicGitHubInstallation = {
        ...existing,
        ...updates,
        updatedAt: nowRef.current,
      };
      installations.set(installationRecordId, next);
      return next;
    },
    async createAuditLog(input) {
      auditLogs.push(input);
    },
  };

  const authService = createAuthService({
    store: authStore,
    passwordService: createPasswordService(),
    jwtService: createJwtService(),
    config: TEST_AUTH_CONFIG,
    now: () => nowRef.current,
  });

  const orgService = createOrganizationService({ store: orgStore });
  const resolvedGitHubConfig =
    options.githubConfig === undefined ? TEST_GITHUB_CONFIG : options.githubConfig;
  const githubClient =
    resolvedGitHubConfig && options.fetchImpl
      ? createGitHubClient({
          config: resolvedGitHubConfig,
          fetchImpl: options.fetchImpl,
          now: () => nowRef.current,
          retryDelayMs: 5,
        })
      : undefined;

  const githubService = createGitHubService({
    config: resolvedGitHubConfig,
    githubClient,
    store: githubStore,
    now: () => nowRef.current,
  });

  const app = createApp({
    auth: { authService, config: TEST_AUTH_CONFIG },
    organizations: {
      authService,
      authConfig: TEST_AUTH_CONFIG,
      organizationService: orgService,
      githubService,
    },
  });

  async function registerAndCreateSession(email: string, displayName: string) {
    const res = await request(app).post('/api/v1/auth/register').send({
      email,
      displayName,
      password: 'StrongPassword123!',
    });
    const loginRes = await request(app).post('/api/v1/auth/login').send({
      email,
      password: 'StrongPassword123!',
    });
    return {
      userId: res.body.user.id as string,
      token: loginRes.body.accessToken as string,
    };
  }

  return {
    app,
    nowRef,
    orgStore,
    githubStore,
    installations,
    oauthStates,
    auditLogs,
    setInstallationStatus(id: string, status: GitHubInstallationStatus) {
      const rec = installations.get(id);
      if (rec) {
        rec.status = status;
        if (status === GitHubInstallationStatusValue.SUSPENDED) {
          rec.suspendedAt = nowRef.current;
        }
        if (status === GitHubInstallationStatusValue.REVOKED) {
          rec.revokedAt = nowRef.current;
        }
      }
    },
    registerAndCreateSession,
  };
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

describe('GitHub App Client, JWT Generation, Installation Flow & Repository Discovery', () => {
  describe('GitHub App JWT Generation', () => {
    it('generates valid RS256 JWTs with clock-skew iat and <=10m exp verifiable by the App public key', () => {
      const fixedNow = new Date('2026-11-27T10:00:00.000Z');
      const jwt = createGitHubAppJwt({
        appId: TEST_GITHUB_CONFIG.appId,
        privateKeyPem: TEST_KEYS.privateKeyPem,
        now: () => fixedNow,
      });

      const parts = jwt.split('.');
      expect(parts).toHaveLength(3);
      const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

      expect(header).toEqual({ alg: 'RS256', typ: 'JWT' });
      const nowSeconds = Math.floor(fixedNow.getTime() / 1000);
      expect(payload).toEqual({
        iss: String(TEST_GITHUB_CONFIG.appId),
        iat: nowSeconds - 60,
        exp: nowSeconds + 540,
      });
      expect(payload.exp - payload.iat).toBeLessThanOrEqual(600);

      const verifier = createVerify('RSA-SHA256');
      verifier.update(`${headerB64}.${payloadB64}`, 'utf8');
      verifier.end();
      const verified = verifier.verify(
        TEST_KEYS.publicKeyPem,
        Buffer.from(signatureB64, 'base64url')
      );
      expect(verified).toBe(true);
    });

    it('rejects invalid private keys without leaking key material', () => {
      const badPem = '-----BEGIN PRIVATE KEY-----\nLEAKED_KEY_MATERIAL\n-----END PRIVATE KEY-----';
      let caught: unknown;
      try {
        createGitHubAppJwt({ appId: 123, privateKeyPem: badPem });
      } catch (error) {
        caught = error;
      }
      expect(caught).toMatchObject({ statusCode: 500, code: 'GITHUB_CONFIGURATION_ERROR' });
      expect((caught as Error).message).not.toContain('LEAKED_KEY_MATERIAL');
    });
  });

  describe('GitHub HTTP Client Hardening', () => {
    it('sets official headers, rejects unrestricted custom base URLs, validates responses, and enforces Link same-origin pagination', async () => {
      expect(() =>
        createGitHubClient({
          config: TEST_GITHUB_CONFIG,
          apiBaseUrl: 'https://evil.attacker.example',
        })
      ).toThrow(/restricted/i);

      const fetchMock = vi.fn<typeof fetch>(async (url, init) => {
        const u = String(url);
        const headers = init?.headers as Record<string, string>;
        expect(headers.Accept).toBe('application/vnd.github+json');
        expect(headers['X-GitHub-Api-Version']).toBe('2022-11-28');
        expect(headers['User-Agent']).toBe('VibeShield-API');

        if (u.includes('/user/installations') && u.includes('page=1')) {
          return jsonResponse(
            {
              total_count: 2,
              installations: [
                {
                  id: 101,
                  app_id: TEST_GITHUB_CONFIG.appId,
                  account: { id: 11, login: 'acme-gh', type: 'Organization' },
                  repository_selection: 'selected',
                  suspended_at: null,
                },
                {
                  id: 999,
                  app_id: 999999, // Other GitHub App must be filtered out
                  account: { id: 22, login: 'other', type: 'User' },
                  repository_selection: 'all',
                },
              ],
            },
            200,
            // Ensure evil cross-origin Link header does NOT trick client into SSRF
            { link: '<https://evil.attacker.example/steal-token?page=2>; rel="next"' }
          );
        }

        return jsonResponse({ message: 'not found' }, 404);
      });

      const client = createGitHubClient({ config: TEST_GITHUB_CONFIG, fetchImpl: fetchMock });
      const installs = await client.listUserInstallations('ghu_user_token_value_123456');
      expect(installs).toEqual([
        {
          githubInstallationId: 101,
          accountLogin: 'acme-gh',
          accountType: 'Organization',
          repositorySelection: 'selected',
          suspendedAt: null,
        },
      ]);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('rejects malformed payloads, handles auth errors, rate limits, network timeouts, bounded retries, and redacts tokens', async () => {
      // 1. Invalid JSON schema from GitHub
      const malformedClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        fetchImpl: async () => jsonResponse({ unexpected: 'shape' }, 200),
      });
      await expect(malformedClient.getAppInstallation(10)).rejects.toMatchObject({
        statusCode: 502,
        code: 'INVALID_GITHUB_RESPONSE',
      });

      // 2. 401 auth error
      const authErrorClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        fetchImpl: async () => jsonResponse({ message: 'Bad credentials' }, 401),
      });
      await expect(
        authErrorClient.listUserInstallations('ghu_token_abc123456')
      ).rejects.toMatchObject({
        statusCode: 502,
        code: 'GITHUB_AUTH_FAILED',
      });

      // 3. Rate limiting (403 x-ratelimit-remaining: 0 and 429 Retry-After) without infinite retries
      const rateLimitFetch = vi.fn<typeof fetch>(async () =>
        jsonResponse({ message: 'API rate limit exceeded' }, 403, {
          'x-ratelimit-remaining': '0',
          'retry-after': '120',
        })
      );
      const rateLimitClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        fetchImpl: rateLimitFetch,
      });
      await expect(
        rateLimitClient.listInstallationRepositories('ghs_token_xyz123456', {
          page: 1,
          perPage: 30,
        })
      ).rejects.toMatchObject({
        statusCode: 429,
        code: 'GITHUB_RATE_LIMITED',
        details: { retryAfterSeconds: 120 },
      });
      expect(rateLimitFetch).toHaveBeenCalledTimes(1);

      // 4. Timeout handling
      const timeoutClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        fetchImpl: async () => {
          const err = new Error('The operation timed out');
          err.name = 'TimeoutError';
          throw err;
        },
      });
      await expect(timeoutClient.exchangeOAuthCode('code_1')).rejects.toMatchObject({
        statusCode: 504,
        code: 'GITHUB_API_TIMEOUT',
      });

      // 5. Bounded retry on GET 503 + token redaction on network error
      const flakyFetch = vi.fn<typeof fetch>(async () => {
        throw new Error('ECONNRESET with Bearer ghs_secretTokenValue12345');
      });
      const flakyClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        fetchImpl: flakyFetch,
        retryDelayMs: 1,
      });
      let netErr: unknown;
      try {
        await flakyClient.listUserInstallations('ghs_secretTokenValue12345');
      } catch (e) {
        netErr = e;
      }
      expect(flakyFetch).toHaveBeenCalledTimes(2); // Initial + 1 bounded retry
      expect(netErr).toMatchObject({ statusCode: 502, code: 'GITHUB_API_UNAVAILABLE' });
      expect((netErr as Error).message).not.toContain('ghs_secretTokenValue12345');
    });
  });

  describe('Installation Flow, RBAC, Anti-Replay & Cross-Tenant Isolation', () => {
    it('enforces auth, org membership, and OWNER/ADMIN-only permissions across all GitHub endpoints', async () => {
      const h = createInMemoryGitHubHarness();
      const owner = await h.registerAndCreateSession('gh-owner@test.dev', 'Owner');
      const member = await h.registerAndCreateSession('gh-member@test.dev', 'Member');
      const viewer = await h.registerAndCreateSession('gh-viewer@test.dev', 'Viewer');
      const outsider = await h.registerAndCreateSession('gh-outsider@test.dev', 'Outsider');

      const orgRes = await request(h.app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Acme Security', slug: 'acme-security' });
      const orgId = orgRes.body.organization.id as string;

      await request(h.app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ email: 'gh-member@test.dev', role: 'MEMBER' });
      await request(h.app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ email: 'gh-viewer@test.dev', role: 'VIEWER' });

      // Unauthenticated -> 401
      expect(
        (await request(h.app).get(`/api/v1/organizations/${orgId}/github/repositories`)).status
      ).toBe(401);

      // Non-member -> 404 (no existence leak)
      expect(
        (
          await request(h.app)
            .post(`/api/v1/organizations/${orgId}/github/installations/start`)
            .set('Authorization', `Bearer ${outsider.token}`)
            .send({ mode: 'install' })
        ).status
      ).toBe(404);

      // MEMBER and VIEWER -> 403 on all GitHub endpoints
      for (const user of [member, viewer]) {
        expect(
          (
            await request(h.app)
              .post(`/api/v1/organizations/${orgId}/github/installations/start`)
              .set('Authorization', `Bearer ${user.token}`)
              .send({})
          ).status
        ).toBe(403);
        expect(
          (
            await request(h.app)
              .post(`/api/v1/organizations/${orgId}/github/installations/complete`)
              .set('Authorization', `Bearer ${user.token}`)
              .send({ state: 'a'.repeat(32), code: 'code_1', installationId: 10 })
          ).status
        ).toBe(403);
        expect(
          (
            await request(h.app)
              .get(`/api/v1/organizations/${orgId}/github/installations`)
              .set('Authorization', `Bearer ${user.token}`)
          ).status
        ).toBe(403);
        expect(
          (
            await request(h.app)
              .get(`/api/v1/organizations/${orgId}/github/repositories`)
              .set('Authorization', `Bearer ${user.token}`)
          ).status
        ).toBe(403);
      }
    });

    it('rejects expired, replayed, wrong-user, wrong-org states and mismatched GitHub ownership', async () => {
      const fetchImpl = vi.fn<typeof fetch>(async (url) => {
        const u = String(url);
        if (u.endsWith('/login/oauth/access_token')) {
          return jsonResponse({ access_token: 'ghu_ephemeral_user_token_123456' });
        }
        if (u.includes('/user/installations')) {
          return jsonResponse({
            total_count: 1,
            installations: [
              {
                id: 5001,
                app_id: TEST_GITHUB_CONFIG.appId,
                account: { id: 801, login: 'acme-gh', type: 'Organization' },
                repository_selection: 'selected',
              },
            ],
          });
        }
        if (u.endsWith('/app/installations/5001')) {
          return jsonResponse({
            id: 5001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 801, login: 'acme-gh', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read', metadata: 'read' },
            suspended_at: null,
          });
        }
        return jsonResponse({ message: 'Not found' }, 404);
      });

      const h = createInMemoryGitHubHarness({ fetchImpl });
      const owner = await h.registerAndCreateSession('state-owner@test.dev', 'Owner');
      const admin = await h.registerAndCreateSession('state-admin@test.dev', 'Admin');

      const orgARes = await request(h.app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Org Alpha', slug: 'org-alpha' });
      const orgAId = orgARes.body.organization.id as string;

      await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/members`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ email: 'state-admin@test.dev', role: 'ADMIN' });

      const orgBRes = await request(h.app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Org Beta', slug: 'org-beta' });
      const orgBId = orgBRes.body.organization.id as string;

      // 1. Start installation in Org A
      const startRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      expect(startRes.status).toBe(200);
      const rawState = new URL(startRes.body.authorizeUrl as string).searchParams.get('state')!;
      expect(rawState.length).toBeGreaterThanOrEqual(32);
      // Verify raw state was NOT persisted in plaintext
      expect(h.oauthStates.has(rawState)).toBe(false);
      const expectedHash = createHash('sha256').update(rawState).digest('hex');
      expect(h.oauthStates.has(expectedHash)).toBe(true);

      // 2. Wrong user attempting to consume owner's state -> 400 INVALID_OAUTH_STATE
      const wrongUserRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${admin.token}`)
        .send({ state: rawState, code: 'oauth_code', installationId: 5001 });
      expect(wrongUserRes.status).toBe(400);
      expect(wrongUserRes.body.error.code).toBe('INVALID_OAUTH_STATE');

      // 3. Wrong org attempting to consume state -> 400 INVALID_OAUTH_STATE
      const wrongOrgRes = await request(h.app)
        .post(`/api/v1/organizations/${orgBId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: rawState, code: 'oauth_code', installationId: 5001 });
      expect(wrongOrgRes.status).toBe(400);
      expect(wrongOrgRes.body.error.code).toBe('INVALID_OAUTH_STATE');

      // 4. Attempting to link installation NOT owned by authenticating GitHub account -> 403 (and state is consumed!)
      const hijackRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: rawState, code: 'oauth_code', installationId: 99999 });
      expect(hijackRes.status).toBe(403);
      expect(hijackRes.body.error.code).toBe('GITHUB_INSTALLATION_NOT_OWNED');

      // 5. Replaying same state after failure -> 400 INVALID_OAUTH_STATE
      const replayRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: rawState, code: 'oauth_code', installationId: 5001 });
      expect(replayRes.status).toBe(400);
      expect(replayRes.body.error.code).toBe('INVALID_OAUTH_STATE');

      // 6. Expired state -> 400 INVALID_OAUTH_STATE
      const start2 = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'authorize' });
      const state2 = new URL(start2.body.authorizeUrl as string).searchParams.get('state')!;
      h.nowRef.current = new Date(h.nowRef.current.getTime() + 15 * 60 * 1000);
      const expiredRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: state2, code: 'oauth_code', installationId: 5001 });
      expect(expiredRes.status).toBe(400);
      expect(expiredRes.body.error.code).toBe('INVALID_OAUTH_STATE');

      // 7. Separated setup callback without OAuth code -> 400 GITHUB_USER_AUTHORIZATION_REQUIRED
      const start3 = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const state3 = new URL(start3.body.authorizeUrl as string).searchParams.get('state')!;
      const noCodeRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: state3, installationId: 5001, setupAction: 'install' });
      expect(noCodeRes.status).toBe(400);
      expect(noCodeRes.body.error.code).toBe('GITHUB_USER_AUTHORIZATION_REQUIRED');

      // 8. setupAction=request without installationId -> 202 APPROVAL_REQUESTED
      const start4 = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const state4 = new URL(start4.body.authorizeUrl as string).searchParams.get('state')!;
      const requestApprovalRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: state4, code: 'oauth_code', setupAction: 'request' });
      expect(requestApprovalRes.status).toBe(202);
      expect(requestApprovalRes.body.status).toBe('APPROVAL_REQUESTED');

      // 8b. Separated user OAuth discovery via /installations/authorize-list
      const startList = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'authorize' });
      const listState = new URL(startList.body.authorizeUrl as string).searchParams.get('state')!;
      const discoverListRes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/authorize-list`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: listState, code: 'oauth_code' });
      expect(discoverListRes.status).toBe(200);
      expect(discoverListRes.body.installations).toHaveLength(1);
      expect(discoverListRes.body.installations[0].githubInstallationId).toBe(5001);

      // 9. Successful linking in Org A, then blocking same active installationId in Org B (without leaking Org A)
      const start5 = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const state5 = new URL(start5.body.authorizeUrl as string).searchParams.get('state')!;
      const linkARes = await request(h.app)
        .post(`/api/v1/organizations/${orgAId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: state5, code: 'oauth_code', installationId: 5001, setupAction: 'install' });
      expect(linkARes.status).toBe(200);
      expect(linkARes.body.status).toBe('CONNECTED');
      expect(linkARes.body.installation.githubInstallationId).toBe(5001);
      const installARecordId = linkARes.body.installation.id as string;

      const startB = await request(h.app)
        .post(`/api/v1/organizations/${orgBId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'authorize' });
      const stateB = new URL(startB.body.authorizeUrl as string).searchParams.get('state')!;
      const linkBRes = await request(h.app)
        .post(`/api/v1/organizations/${orgBId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: stateB, code: 'oauth_code', installationId: 5001 });
      expect(linkBRes.status).toBe(409);
      expect(linkBRes.body.error.code).toBe('GITHUB_INSTALLATION_UNAVAILABLE');
      expect(JSON.stringify(linkBRes.body)).not.toContain(orgAId);

      // 10. Org B attempting IDOR on Org A's installationRecordId via /repositories -> safe 404
      const idorReposRes = await request(h.app)
        .get(
          `/api/v1/organizations/${orgBId}/github/repositories?installationRecordId=${installARecordId}`
        )
        .set('Authorization', `Bearer ${owner.token}`);
      expect(idorReposRes.status).toBe(404);
      expect(idorReposRes.body.error.code).toBe('GITHUB_INSTALLATION_NOT_FOUND');
    });
  });

  describe('Repository Discovery, Pagination, State Handling & Unconfigured Startup', () => {
    it('discovers bounded safe repositories without exposing installation tokens and handles suspended/revoked states', async () => {
      const secretIat = `ghs_${randomBytes(16).toString('hex')}`;
      const fetchImpl = vi.fn<typeof fetch>(async (url, init) => {
        const u = String(url);
        if (u.endsWith('/login/oauth/access_token')) {
          return jsonResponse({ access_token: 'ghu_user_token_123456' });
        }
        if (u.includes('/user/installations')) {
          return jsonResponse({
            total_count: 1,
            installations: [
              {
                id: 6001,
                app_id: TEST_GITHUB_CONFIG.appId,
                account: { id: 901, login: 'sec-org', type: 'Organization' },
                repository_selection: 'all',
              },
            ],
          });
        }
        if (u.endsWith('/app/installations/6001')) {
          return jsonResponse({
            id: 6001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 901, login: 'sec-org', type: 'Organization' },
            repository_selection: 'all',
            permissions: { contents: 'read', metadata: 'read' },
            suspended_at: null,
          });
        }
        if (u.endsWith('/app/installations/6001/access_tokens')) {
          return jsonResponse({
            token: secretIat,
            expires_at: '2026-11-27T11:00:00.000Z',
          });
        }
        if (u.includes('/installation/repositories')) {
          const authHeader = (init?.headers as Record<string, string>)?.Authorization;
          expect(authHeader).toBe(`Bearer ${secretIat}`);
          return jsonResponse({
            total_count: 25,
            repositories: [
              {
                id: 4201,
                name: 'api-gateway',
                full_name: 'sec-org/api-gateway',
                owner: { login: 'sec-org', avatar_url: 'https://ignored.example/avatar.png' },
                default_branch: 'main',
                private: true,
                archived: false,
                html_url: 'https://github.com/sec-org/api-gateway',
                extra_internal_field: 'must_not_leak',
              },
            ],
          });
        }
        return jsonResponse({ message: 'Not found' }, 404);
      });

      const h = createInMemoryGitHubHarness({ fetchImpl });
      const owner = await h.registerAndCreateSession('repo-owner@test.dev', 'Owner');
      const orgRes = await request(h.app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Sec Org', slug: 'sec-org' });
      const orgId = orgRes.body.organization.id as string;

      const startRes = await request(h.app)
        .post(`/api/v1/organizations/${orgId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const state = new URL(startRes.body.authorizeUrl as string).searchParams.get('state')!;
      const completeRes = await request(h.app)
        .post(`/api/v1/organizations/${orgId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state, code: 'oauth_code', installationId: 6001 });
      const installRecordId = completeRes.body.installation.id as string;

      // Valid paginated repository discovery
      const reposRes = await request(h.app)
        .get(`/api/v1/organizations/${orgId}/github/repositories?page=1&perPage=10`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(reposRes.status).toBe(200);
      expect(reposRes.body).toEqual({
        installationId: installRecordId,
        githubInstallationId: 6001,
        repositories: [
          {
            githubRepositoryId: 4201,
            name: 'api-gateway',
            fullName: 'sec-org/api-gateway',
            ownerLogin: 'sec-org',
            defaultBranch: 'main',
            isPrivate: true,
            isArchived: false,
            htmlUrl: 'https://github.com/sec-org/api-gateway',
          },
        ],
        pagination: {
          page: 1,
          perPage: 10,
          total: 25,
          totalPages: 3,
          hasNextPage: true,
        },
      });
      expect(JSON.stringify(reposRes.body)).not.toContain(secretIat);
      expect(JSON.stringify(reposRes.body)).not.toContain('must_not_leak');

      // Enforce pagination bounds (perPage > 100, page > 100)
      const invalidPageRes = await request(h.app)
        .get(`/api/v1/organizations/${orgId}/github/repositories?page=101&perPage=101`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(invalidPageRes.status).toBe(400);

      // Handle SUSPENDED and REVOKED states gracefully
      h.setInstallationStatus(installRecordId, GitHubInstallationStatusValue.SUSPENDED);
      const suspendedRes = await request(h.app)
        .get(`/api/v1/organizations/${orgId}/github/repositories`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(suspendedRes.status).toBe(409);
      expect(suspendedRes.body.error.code).toBe('GITHUB_INSTALLATION_SUSPENDED');

      h.setInstallationStatus(installRecordId, GitHubInstallationStatusValue.REVOKED);
      const revokedRes = await request(h.app)
        .get(`/api/v1/organizations/${orgId}/github/repositories`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(revokedRes.status).toBe(409);
      expect(revokedRes.body.error.code).toBe('GITHUB_INSTALLATION_REVOKED');
    });

    it('keeps existing app functional when GitHub integration is unconfigured and returns 503 on GitHub routes', async () => {
      const h = createInMemoryGitHubHarness({ githubConfig: null });
      const owner = await h.registerAndCreateSession('unconf@test.dev', 'Owner');
      const orgRes = await request(h.app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Plain Org', slug: 'plain-org' });
      expect(orgRes.status).toBe(201);

      const startRes = await request(h.app)
        .post(`/api/v1/organizations/${orgRes.body.organization.id}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({});
      expect(startRes.status).toBe(503);
      expect(startRes.body.error.code).toBe('GITHUB_INTEGRATION_NOT_CONFIGURED');
    });
  });
});
