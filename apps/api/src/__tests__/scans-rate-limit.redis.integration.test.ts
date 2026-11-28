import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildScanCreationRateLimitKey,
  consumeScanCreationRateLimit,
  RedisConnectionManager,
} from '@vibeshield/queue';
import type { PublicScanRecord } from '@vibeshield/types';
import { createApp } from '../app.js';
import { createRedisScanCreationRateLimiter } from '../middlewares/scan-rate-limit.js';
import {
  createAuthService,
  type AuthStore,
  type StoredSessionRef,
  type StoredUserWithPassword,
} from '../modules/auth/auth.service.js';
import type { AuthRuntimeConfig, PublicUser } from '../modules/auth/auth.types.js';
import { createOrganizationService } from '../modules/organizations/organization.service.js';
import type {
  OrganizationStore,
  StoredMembershipRecord,
  StoredUserSummary,
} from '../modules/organizations/organization.store.js';
import type {
  AuthorizedOrganizationMembership,
  OrganizationMemberView,
  OrganizationSummary,
  PublicOrganization,
} from '../modules/organizations/organization.types.js';
import type { ScanService } from '../modules/scans/scan.service.js';

const REDIS_URI = process.env.REDIS_INTEGRATION_URI;

const AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'redis_rate_limit_integration_secret_32_chars!',
  jwtAccessTtl: '15m',
  jwtAccessTtlSeconds: 900,
  jwtIssuer: 'vibeshield-api',
  jwtAudience: 'vibeshield-clients',
  refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
  isProduction: false,
  cookiePath: '/api/v1/auth',
  cookieSameSite: 'lax',
};

class MinimalInMemoryAuthOrgStore implements AuthStore, OrganizationStore {
  private users = new Map<string, StoredUserWithPassword>();
  private sessions = new Map<string, { id: string; userId: string; expiresAt: Date }>();
  private orgs = new Map<string, PublicOrganization>();
  private memberships = new Map<string, StoredMembershipRecord>();

  async createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
  }): Promise<PublicUser> {
    const id = randomBytes(12).toString('hex');
    const record: StoredUserWithPassword = { id, ...input, createdAt: new Date() };
    this.users.set(id, record);
    return {
      id,
      email: input.email,
      displayName: input.displayName,
      status: input.status,
      createdAt: record.createdAt,
    };
  }
  async findUserWithPasswordByEmail(email: string): Promise<StoredUserWithPassword | null> {
    for (const u of this.users.values()) if (u.email === email) return { ...u };
    return null;
  }
  async findActiveUserById(userId: string): Promise<PublicUser | null> {
    const u = this.users.get(userId);
    if (!u || u.status !== 'ACTIVE') return null;
    return {
      id: u.id,
      email: u.email,
      displayName: u.displayName,
      status: u.status,
      createdAt: u.createdAt,
    };
  }
  async createSession(input: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
  }): Promise<StoredSessionRef> {
    const id = randomBytes(12).toString('hex');
    this.sessions.set(id, { id, userId: input.userId, expiresAt: input.expiresAt });
    return { id, userId: input.userId, expiresAt: input.expiresAt };
  }
  async findActiveSessionByIdAndUserId(
    sessionId: string,
    userId: string,
    now: Date
  ): Promise<StoredSessionRef | null> {
    const s = this.sessions.get(sessionId);
    if (!s || s.userId !== userId || s.expiresAt <= now) return null;
    return { id: s.id, userId: s.userId };
  }
  async revokeSessionById(): Promise<void> {}
  async revokeSessionByIdAndUserId(): Promise<void> {}
  async revokeSessionByTokenHash(): Promise<void> {}
  async withTransaction<T>(work: (tx: unknown) => Promise<T>): Promise<T> {
    return work({});
  }
  async acquireOrganizationLock(): Promise<boolean> {
    return true;
  }
  async createOrganization(input: {
    name: string;
    slug: string;
    createdBy: string;
  }): Promise<PublicOrganization> {
    const id = randomBytes(12).toString('hex');
    const now = new Date();
    const org: PublicOrganization = { id, ...input, createdAt: now, updatedAt: now };
    this.orgs.set(id, org);
    return { ...org };
  }
  async findOrganizationById(id: string): Promise<PublicOrganization | null> {
    return this.orgs.get(id) ?? null;
  }
  async updateOrganizationById(): Promise<PublicOrganization | null> {
    return null;
  }
  async deleteOrganizationById(): Promise<boolean> {
    return false;
  }
  async hasProjectsInOrganization(): Promise<boolean> {
    return false;
  }
  async listActiveOrganizationsForUser(): Promise<OrganizationSummary[]> {
    return [];
  }
  async createMembership(input: {
    userId: string;
    organizationId: string;
    role: 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER';
    status: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
  }): Promise<StoredMembershipRecord> {
    const id = randomBytes(12).toString('hex');
    const record: StoredMembershipRecord = { id, ...input, createdAt: new Date() };
    this.memberships.set(id, record);
    return { ...record };
  }
  async findActiveMembership(
    organizationId: string,
    userId: string
  ): Promise<AuthorizedOrganizationMembership | null> {
    for (const m of this.memberships.values()) {
      if (m.organizationId === organizationId && m.userId === userId && m.status === 'ACTIVE') {
        return { ...m };
      }
    }
    return null;
  }
  async findMembershipByIdInOrganization(): Promise<StoredMembershipRecord | null> {
    return null;
  }
  async findMembershipByOrgAndUser(): Promise<StoredMembershipRecord | null> {
    return null;
  }
  async listMembersInOrganization(): Promise<OrganizationMemberView[]> {
    return [];
  }
  async updateMembershipByIdInOrganization(): Promise<StoredMembershipRecord | null> {
    return null;
  }
  async deleteMembershipByIdInOrganization(): Promise<boolean> {
    return false;
  }
  async deleteAllMembershipsInOrganization(): Promise<void> {}
  async countActiveOwnersExcluding(): Promise<number> {
    return 0;
  }
  async countActiveOwners(): Promise<number> {
    return 1;
  }
  async findUserByEmail(): Promise<StoredUserSummary | null> {
    return null;
  }
  async findUserById(): Promise<StoredUserSummary | null> {
    return null;
  }
}

describe.skipIf(!REDIS_URI)('Scan Creation Rate Limiting — Real Redis Integration Tests', () => {
  const managers: RedisConnectionManager[] = [];

  afterEach(async () => {
    for (const mgr of managers.splice(0)) {
      await mgr.disconnect().catch(() => undefined);
    }
  });

  afterAll(async () => {
    for (const mgr of managers.splice(0)) {
      await mgr.disconnect().catch(() => undefined);
    }
  });

  it('enforces per-(organizationId, userId) limits in Redis, expires windows, and fails closed when disconnected', async () => {
    const manager = new RedisConnectionManager();
    managers.push(manager);
    await manager.connect({ url: REDIS_URI!, connectTimeoutMs: 5000 });

    const store = new MinimalInMemoryAuthOrgStore();
    const authService = createAuthService({ config: AUTH_CONFIG, store });
    const organizationService = createOrganizationService({ store });

    const mockScan: PublicScanRecord = {
      id: randomBytes(12).toString('hex'),
      organizationId: randomBytes(12).toString('hex'),
      projectId: randomBytes(12).toString('hex'),
      repositoryConnectionId: randomBytes(12).toString('hex'),
      githubInstallationId: 1,
      githubRepositoryId: 2,
      requestedRef: 'main',
      requestedCommitHash: null,
      resolvedCommitSha: null,
      status: 'QUEUED',
      isActive: true,
      triggerSource: 'manual',
      createdByUserId: null,
      correlationId: null,
      attemptCount: 0,
      maxAttempts: 3,
      lease: null,
      cancellation: { requestedAt: null, requestedByUserId: null, reason: null },
      acquisition: null,
      failureCode: null,
      failureMessage: null,
      queuedAt: new Date(),
      startedAt: null,
      acquiringAt: null,
      preparedAt: null,
      inProgressAt: null,
      completedAt: null,
      failedAt: null,
      cancelledAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const scanService: ScanService = {
      createScan: vi.fn().mockResolvedValue(mockScan),
      listScans: vi.fn(),
      getScan: vi.fn(),
      cancelScan: vi.fn(),
    };

    const app = createApp({
      auth: { authService, config: AUTH_CONFIG },
      organizations: { organizationService, authService, authConfig: AUTH_CONFIG },
      scanService,
      scanCreateRateLimiter: createRedisScanCreationRateLimiter(manager, {
        maxRequests: 2,
        windowMs: 1_200,
      }),
    });

    async function setupUserAndOrg(tag: string) {
      const email = `redis-rl-${tag}-${randomBytes(3).toString('hex')}@test.com`;
      const password = 'redis-rate-limit-password-123!';
      await request(app).post('/api/v1/auth/register').send({ email, displayName: tag, password });
      const login = await request(app).post('/api/v1/auth/login').send({ email, password });
      const token = login.body.accessToken as string;
      const org = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: `Org ${tag}`, slug: `org-${tag}-${randomBytes(3).toString('hex')}` });
      return { token, orgId: org.body.organization.id as string };
    }

    const user1 = await setupUserAndOrg('u1');
    const user2 = await setupUserAndOrg('u2');
    const projectId = randomBytes(12).toString('hex');

    // Clean any pre-existing key
    const client = manager.getQueueClient() as unknown as { del: (k: string) => Promise<number> };
    await client.del(buildScanCreationRateLimitKey(user1.orgId, 'dummy')).catch(() => undefined);

    // 1. User 1: 2 allowed, 3rd returns 429
    const r1 = await request(app)
      .post(`/api/v1/organizations/${user1.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ requestedRef: 'main' });
    expect(r1.status).toBe(201);
    expect(r1.headers['x-ratelimit-remaining']).toBe('1');

    const r2 = await request(app)
      .post(`/api/v1/organizations/${user1.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ requestedRef: 'main' });
    expect(r2.status).toBe(201);
    expect(r2.headers['x-ratelimit-remaining']).toBe('0');

    const r3 = await request(app)
      .post(`/api/v1/organizations/${user1.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ requestedRef: 'main' });
    expect(r3.status).toBe(429);
    expect(r3.body.error.code).toBe('RATE_LIMIT_EXCEEDED');

    // 2. User 2 in Org 2 is unaffected
    const u2r1 = await request(app)
      .post(`/api/v1/organizations/${user2.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user2.token}`)
      .send({ requestedRef: 'main' });
    expect(u2r1.status).toBe(201);

    // 3. Wait for Redis window TTL to expire -> User 1 is allowed again
    await new Promise((resolve) => setTimeout(resolve, 1_350));
    const rAfterReset = await request(app)
      .post(`/api/v1/organizations/${user1.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ requestedRef: 'main' });
    expect(rAfterReset.status).toBe(201);

    // 4. Direct helper & middleware fail closed when Redis is disconnected
    await manager.disconnect();
    await expect(
      consumeScanCreationRateLimit(manager, {
        organizationId: user1.orgId,
        userId: 'user-1',
        maxRequests: 2,
        windowMs: 5_000,
      })
    ).rejects.toThrow();

    const rDisconnected = await request(app)
      .post(`/api/v1/organizations/${user1.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ requestedRef: 'main' });
    expect(rDisconnected.status).toBe(503);
    expect(rDisconnected.body.error.code).toBe('RATE_LIMIT_UNAVAILABLE');
  });
});
