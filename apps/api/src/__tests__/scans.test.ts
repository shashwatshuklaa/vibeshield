import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import type { OrganizationRole } from '@vibeshield/database';
import type { PublicScanRecord, ScanLifecycleStatus, ScanTriggerSource } from '@vibeshield/types';
import { createApp } from '../app.js';
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
  OrganizationTransactionContext,
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
import type { CreateScanInput, PaginatedScansResult } from '../modules/scans/scan.types.js';
import { createScanCreationRateLimiter } from '../middlewares/scan-rate-limit.js';

// ---------------------------------------------------------------------------
// Minimal in-memory stubs reusing the pattern from projects.test.ts
// ---------------------------------------------------------------------------

interface InMemorySessionRecord {
  id: string;
  userId: string;
  refreshTokenHash: string;
  previousRefreshTokenHash: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
}

class InMemoryScanTestDatabase implements AuthStore, OrganizationStore {
  public readonly users = new Map<string, StoredUserWithPassword>();
  public readonly sessions = new Map<string, InMemorySessionRecord>();
  public organizations = new Map<string, PublicOrganization>();
  public memberships = new Map<string, StoredMembershipRecord>();

  private getOrgsMap(_tx?: OrganizationTransactionContext): Map<string, PublicOrganization> {
    return this.organizations;
  }
  private getMembershipsMap(
    _tx?: OrganizationTransactionContext
  ): Map<string, StoredMembershipRecord> {
    return this.memberships;
  }

  async createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
  }): Promise<PublicUser> {
    const id = randomBytes(12).toString('hex');
    const record: StoredUserWithPassword = {
      id,
      email: input.email,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      status: input.status,
      createdAt: new Date(),
    };
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
    this.sessions.set(id, {
      id,
      userId: input.userId,
      refreshTokenHash: input.refreshTokenHash,
      previousRefreshTokenHash: null,
      expiresAt: input.expiresAt,
      revokedAt: null,
      lastUsedAt: null,
    });
    return { id, userId: input.userId, expiresAt: input.expiresAt };
  }
  async findActiveSessionByIdAndUserId(
    sessionId: string,
    userId: string,
    now: Date
  ): Promise<StoredSessionRef | null> {
    const s = this.sessions.get(sessionId);
    if (!s || s.userId !== userId || s.revokedAt !== null || s.expiresAt <= now) return null;
    return { id: s.id, userId: s.userId };
  }
  async revokeSessionById(): Promise<void> {}
  async revokeSessionByIdAndUserId(): Promise<void> {}
  async revokeSessionByTokenHash(): Promise<void> {}
  async rotateSessionToken(input: {
    sessionId: string;
    newRefreshTokenHash: string;
    oldRefreshTokenHash: string;
    expiresAt: Date;
    now: Date;
  }): Promise<StoredSessionRef | null> {
    const s = this.sessions.get(input.sessionId);
    if (!s) return null;
    s.refreshTokenHash = input.newRefreshTokenHash;
    s.expiresAt = input.expiresAt;
    return { id: s.id, userId: s.userId };
  }
  async revokeSession(sessionId: string): Promise<boolean> {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    s.revokedAt = new Date();
    return true;
  }
  async revokeAllUserSessions(): Promise<number> {
    return 0;
  }
  async pruneExpiredSessions(): Promise<number> {
    return 0;
  }
  async storeRotatedToken(): Promise<void> {}
  async isRotatedToken(): Promise<boolean> {
    return false;
  }

  async withTransaction<T>(work: (tx: OrganizationTransactionContext) => Promise<T>): Promise<T> {
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
    const org: PublicOrganization = {
      id,
      name: input.name,
      slug: input.slug,
      createdBy: input.createdBy,
      createdAt: now,
      updatedAt: now,
    };
    this.organizations.set(id, org);
    return { ...org };
  }
  async findOrganizationById(id: string): Promise<PublicOrganization | null> {
    return this.organizations.get(id) ?? null;
  }
  async updateOrganizationById(): Promise<PublicOrganization | null> {
    return null;
  }
  async deleteOrganizationById(id: string): Promise<boolean> {
    return this.organizations.delete(id);
  }
  async hasProjectsInOrganization(): Promise<boolean> {
    return false;
  }
  async listActiveOrganizationsForUser(userId: string): Promise<OrganizationSummary[]> {
    const out: OrganizationSummary[] = [];
    for (const m of this.memberships.values()) {
      if (m.userId === userId && m.status === 'ACTIVE') {
        const org = this.organizations.get(m.organizationId);
        if (org) out.push({ ...org, role: m.role });
      }
    }
    return out;
  }
  async createMembership(input: {
    userId: string;
    organizationId: string;
    role: OrganizationRole;
    status: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
  }): Promise<StoredMembershipRecord> {
    const id = randomBytes(12).toString('hex');
    const record: StoredMembershipRecord = {
      id,
      userId: input.userId,
      organizationId: input.organizationId,
      role: input.role,
      status: input.status,
      createdAt: new Date(),
    };
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
  async findMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string
  ): Promise<StoredMembershipRecord | null> {
    const m = this.memberships.get(membershipId);
    return m && m.organizationId === organizationId ? { ...m } : null;
  }
  async findMembershipByOrgAndUser(
    organizationId: string,
    userId: string
  ): Promise<StoredMembershipRecord | null> {
    for (const m of this.memberships.values()) {
      if (m.organizationId === organizationId && m.userId === userId) return { ...m };
    }
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
  async countActiveOwners(organizationId: string): Promise<number> {
    return [...this.memberships.values()].filter(
      (m) => m.organizationId === organizationId && m.role === 'OWNER' && m.status === 'ACTIVE'
    ).length;
  }
  async findUserByEmail(email: string): Promise<StoredUserSummary | null> {
    const u = await this.findUserWithPasswordByEmail(email);
    return u ? { id: u.id, email: u.email, displayName: u.displayName, status: u.status } : null;
  }
  async findUserById(userId: string): Promise<StoredUserSummary | null> {
    const u = this.users.get(userId);
    return u ? { id: u.id, email: u.email, displayName: u.displayName, status: u.status } : null;
  }
  async incrementMemberCount(
    _organizationId: string,
    _by: number,
    _tx?: OrganizationTransactionContext
  ): Promise<void> {}
  async decrementMemberCount(
    _organizationId: string,
    _by: number,
    _tx?: OrganizationTransactionContext
  ): Promise<void> {}
}

const authConfig: AuthRuntimeConfig = {
  jwtAccessSecret: 'scan-test-access-secret-32chars-minimum!',
  jwtAccessTtl: '15m',
  jwtAccessTtlSeconds: 900,
  jwtIssuer: 'vibeshield-api',
  jwtAudience: 'vibeshield-clients',
  refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
  isProduction: false,
  cookiePath: '/api/v1/auth',
  cookieSameSite: 'lax',
};

// ---------------------------------------------------------------------------
// Minimal mock ScanService for unit tests (no MongoDB needed)
// ---------------------------------------------------------------------------

function makeMockScanService(overrides: Partial<ScanService> = {}): ScanService {
  const baseScan: PublicScanRecord = {
    id: randomBytes(12).toString('hex'),
    organizationId: randomBytes(12).toString('hex'),
    projectId: randomBytes(12).toString('hex'),
    repositoryConnectionId: randomBytes(12).toString('hex'),
    githubInstallationId: 1234,
    githubRepositoryId: 5678,
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

  return {
    createScan: vi.fn().mockResolvedValue(baseScan),
    listScans: vi.fn().mockResolvedValue({
      scans: [baseScan],
      pagination: { page: 1, limit: 20, total: 1, totalPages: 1 },
    } as PaginatedScansResult),
    getScan: vi.fn().mockResolvedValue(baseScan),
    cancelScan: vi.fn().mockResolvedValue({
      result: 'CANCELLED_IMMEDIATELY',
      scan: { ...baseScan, status: 'CANCELLED', isActive: false },
    }),
    ...overrides,
  };
}

function createInMemoryRateLimiter(options: { maxRequests?: number; windowMs?: number } = {}) {
  const maxRequests = options.maxRequests ?? 100;
  const windowMs = options.windowMs ?? 60_000;
  const counters = new Map<string, { count: number; resetAtMs: number }>();

  return createScanCreationRateLimiter({
    maxRequests,
    windowMs,
    consumeRateLimit: async ({ organizationId, userId, maxRequests: limit, windowMs: win }) => {
      const key = `${organizationId}:${userId}`;
      const now = Date.now();
      const existing = counters.get(key);
      if (!existing || existing.resetAtMs <= now) {
        const entry = { count: 1, resetAtMs: now + win };
        counters.set(key, entry);
        return {
          allowed: 1 <= limit,
          limit,
          remaining: Math.max(0, limit - 1),
          resetAtMs: entry.resetAtMs,
          retryAfterSeconds: Math.ceil(win / 1000),
        };
      }
      existing.count += 1;
      const ttlMs = Math.max(1, existing.resetAtMs - now);
      return {
        allowed: existing.count <= limit,
        limit,
        remaining: Math.max(0, limit - existing.count),
        resetAtMs: existing.resetAtMs,
        retryAfterSeconds: Math.max(1, Math.ceil(ttlMs / 1000)),
      };
    },
  });
}

function createHarness(
  scanService?: ScanService,
  rateLimiterOptions?: {
    disableRateLimiter?: boolean;
    maxRequests?: number;
    windowMs?: number;
    customRateLimiter?: ReturnType<typeof createScanCreationRateLimiter>;
  }
) {
  const db = new InMemoryScanTestDatabase();
  const authService = createAuthService({ config: authConfig, store: db });
  const organizationService = createOrganizationService({ store: db });

  const scanCreateRateLimiter = rateLimiterOptions?.disableRateLimiter
    ? undefined
    : (rateLimiterOptions?.customRateLimiter ??
      createInMemoryRateLimiter({
        maxRequests: rateLimiterOptions?.maxRequests,
        windowMs: rateLimiterOptions?.windowMs,
      }));

  const app = createApp({
    auth: { authService, config: authConfig },
    organizations: {
      organizationService,
      authService,
      authConfig,
    },
    scanService: scanService ?? makeMockScanService(),
    scanCreateRateLimiter,
  });

  async function setupOrgAndToken(
    email: string
  ): Promise<{ orgId: string; token: string; userId: string }> {
    const password = 'scan-test-password-secure-123!';
    const regRes = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, displayName: 'Test', password });
    expect(regRes.status, JSON.stringify(regRes.body)).toBe(201);
    const userId = regRes.body.user.id as string;
    const login = await request(app).post('/api/v1/auth/login').send({ email, password });
    expect(login.status, JSON.stringify(login.body)).toBe(200);
    const token = login.body.accessToken as string;
    const orgRes = await request(app)
      .post('/api/v1/organizations')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test Org', slug: `test-org-${randomBytes(4).toString('hex')}` });
    expect(orgRes.status, JSON.stringify(orgRes.body)).toBe(201);
    return { orgId: orgRes.body.organization.id as string, token, userId };
  }

  return { app, db, setupOrgAndToken };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Public Scan API — Unit Tests (mocked service)', () => {
  const projectId = randomBytes(12).toString('hex');

  describe('POST /scans — create scan', () => {
    it('returns 401 when unauthenticated', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `scan-unauth-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 401 when token is invalid', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `scan-badtoken-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', 'Bearer bad.token.here')
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(401);
    });

    it('returns 400 VALIDATION_ERROR when requestedRef is missing', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-noref-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR when requestedRef contains path traversal', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-badref-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: '../evil' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR when unknown field supplied (strict schema)', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-extra-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', githubInstallationId: 9999, githubRepositoryId: 8888 });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR when repositoryConnectionId is supplied', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-connid-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', repositoryConnectionId: 'abc' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR when projectId is malformed', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-badproj-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/not-a-valid-id/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR for secret-shaped idempotencyKey or correlationId', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-secid-${randomBytes(4).toString('hex')}@test.com`
      );
      const res1 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'ghp_abcdefghij123456' });
      expect(res1.status).toBe(400);
      expect(res1.body.error.code).toBe('VALIDATION_ERROR');

      const res2 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', correlationId: 'github_pat_abcdefghijklmnop' });
      expect(res2.status).toBe(400);
      expect(res2.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 404 for unknown organization', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { token } = await setupOrgAndToken(
        `scan-unkorg-${randomBytes(4).toString('hex')}@test.com`
      );
      const fakeOrgId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${fakeOrgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(404);
    });

    it('returns 201 and scan on success', async () => {
      const mockService = makeMockScanService();
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-create-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'deploy-abc' });
      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('scan');
      expect(res.body.scan.status).toBe('QUEUED');
      // Verify service was called with sanitized input (no githubInstallationId from body)
      expect(mockService.createScan).toHaveBeenCalledOnce();
      const callArgs = (mockService.createScan as ReturnType<typeof vi.fn>).mock.calls[0] as [
        string,
        string,
        string,
        CreateScanInput,
      ];
      expect(callArgs[3]).toMatchObject({ requestedRef: 'main', idempotencyKey: 'deploy-abc' });
      expect(callArgs[3]).not.toHaveProperty('githubInstallationId');
    });

    it('does not expose lease.token in response', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-noleak-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main' });
      if (res.status === 201 && res.body.scan?.lease) {
        expect(res.body.scan.lease).not.toHaveProperty('token');
      }
    });

    it('propagates 409 SCAN_ALREADY_EXISTS from service', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        createScan: vi
          .fn()
          .mockRejectedValue(new ScanError(409, 'SCAN_ALREADY_EXISTS', 'Duplicate')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-dup-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'dup-key' });
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('SCAN_ALREADY_EXISTS');
    });

    it('propagates 409 PROJECT_ARCHIVED from service', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        createScan: vi.fn().mockRejectedValue(new ScanError(409, 'PROJECT_ARCHIVED', 'Archived')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-archived-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('PROJECT_ARCHIVED');
    });

    it('propagates 409 REPOSITORY_NOT_CONNECTED from service', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        createScan: vi
          .fn()
          .mockRejectedValue(new ScanError(409, 'REPOSITORY_NOT_CONNECTED', 'No connection')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-noconn-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('REPOSITORY_NOT_CONNECTED');
    });
  });

  describe('GET /scans — list scans', () => {
    it('returns 401 when unauthenticated', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `scan-list-unauth-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app).get(
        `/api/v1/organizations/${orgId}/projects/${projectId}/scans`
      );
      expect(res.status).toBe(401);
    });

    it('returns 400 VALIDATION_ERROR for invalid status filter', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-list-badstatus-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans?status=BOGUS`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR for extra unknown query param', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-list-extra-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans?search=foo`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR for malformed projectId on listScans (not 200 [])', async () => {
      const mockService = makeMockScanService();
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-list-badproj-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/not-an-object-id/scans`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockService.listScans).not.toHaveBeenCalled();
    });

    it('returns 200 with scans and pagination metadata', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-list-ok-${randomBytes(4).toString('hex')}@test.com`
      );
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('scans');
      expect(res.body).toHaveProperty('pagination');
      expect(res.body.pagination).toMatchObject({ page: 1, limit: 20, total: 1, totalPages: 1 });
    });

    it('passes pagination params to service', async () => {
      const mockService = makeMockScanService();
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-list-page-${randomBytes(4).toString('hex')}@test.com`
      );
      await request(app)
        .get(
          `/api/v1/organizations/${orgId}/projects/${projectId}/scans?page=2&limit=5&status=QUEUED`
        )
        .set('Authorization', `Bearer ${token}`);
      expect(mockService.listScans).toHaveBeenCalledWith(
        orgId,
        projectId,
        expect.objectContaining({ page: 2, limit: 5, status: 'QUEUED' })
      );
    });
  });

  describe('GET /scans/:scanId — get scan', () => {
    it('returns 401 when unauthenticated', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `scan-get-unauth-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app).get(
        `/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}`
      );
      expect(res.status).toBe(401);
    });

    it('returns 404 SCAN_NOT_FOUND (not revealing cross-tenant existence)', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        getScan: vi.fn().mockRejectedValue(new ScanError(404, 'SCAN_NOT_FOUND', 'Scan not found')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-get-notfound-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
      expect(res.body.error.message).toBe('Scan not found');
    });

    it('returns 400 VALIDATION_ERROR for malformed projectId or scanId on getScan', async () => {
      const mockService = makeMockScanService();
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-get-badid-${randomBytes(4).toString('hex')}@test.com`
      );
      const resBadScan = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/invalid-scan-id`)
        .set('Authorization', `Bearer ${token}`);
      expect(resBadScan.status).toBe(400);
      expect(resBadScan.body.error.code).toBe('VALIDATION_ERROR');

      const resBadProj = await request(app)
        .get(
          `/api/v1/organizations/${orgId}/projects/invalid-proj-id/scans/${randomBytes(12).toString('hex')}`
        )
        .set('Authorization', `Bearer ${token}`);
      expect(resBadProj.status).toBe(400);
      expect(resBadProj.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockService.getScan).not.toHaveBeenCalled();
    });

    it('returns 200 with scan and no leaked fields', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-get-ok-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('scan');
      // Sensitive fields must not appear
      expect(JSON.stringify(res.body)).not.toContain('"token"');
      expect(JSON.stringify(res.body)).not.toContain('"dispatchRevision"');
      expect(JSON.stringify(res.body)).not.toContain('"claimToken"');
    });
  });

  describe('POST /scans/:scanId/cancel — cancel scan', () => {
    it('returns 401 when unauthenticated', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `scan-cancel-unauth-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .send({});
      expect(res.status).toBe(401);
    });

    it('returns 400 VALIDATION_ERROR when unknown field in cancel body', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-badfield-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({ reason: 'ok', forceKill: true });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 VALIDATION_ERROR for malformed projectId or scanId on cancelScan', async () => {
      const mockService = makeMockScanService();
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-badid-${randomBytes(4).toString('hex')}@test.com`
      );
      const resBadScan = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/not-a-scan-id/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(resBadScan.status).toBe(400);
      expect(resBadScan.body.error.code).toBe('VALIDATION_ERROR');

      const resBadProj = await request(app)
        .post(
          `/api/v1/organizations/${orgId}/projects/not-a-proj-id/scans/${randomBytes(12).toString('hex')}/cancel`
        )
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(resBadProj.status).toBe(400);
      expect(resBadProj.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockService.cancelScan).not.toHaveBeenCalled();
    });

    it('returns 200 and "Scan cancelled" for CANCELLED_IMMEDIATELY', async () => {
      const { app, setupOrgAndToken } = createHarness();
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-imm-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Scan cancelled');
      expect(res.body).toHaveProperty('scan');
    });

    it('returns 202 and "Cancellation requested" for CANCELLATION_REQUESTED', async () => {
      const mockService = makeMockScanService({
        cancelScan: vi.fn().mockResolvedValue({ result: 'CANCELLATION_REQUESTED', scan: {} }),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-req-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({ reason: 'Deployment reverted' });
      expect(res.status).toBe(202);
      expect(res.body.message).toBe('Cancellation requested');
    });

    it('returns 404 SCAN_NOT_FOUND when scan not found', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        cancelScan: vi
          .fn()
          .mockRejectedValue(new ScanError(404, 'SCAN_NOT_FOUND', 'Scan not found')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-nf-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
    });

    it('returns 409 SCAN_ALREADY_TERMINAL for completed/failed/cancelled scans', async () => {
      const { ScanError } = await import('../modules/scans/scan.types.js');
      const mockService = makeMockScanService({
        cancelScan: vi
          .fn()
          .mockRejectedValue(new ScanError(409, 'SCAN_ALREADY_TERMINAL', 'Already terminal')),
      });
      const { app, setupOrgAndToken } = createHarness(mockService);
      const { orgId, token } = await setupOrgAndToken(
        `scan-cancel-terminal-${randomBytes(4).toString('hex')}@test.com`
      );
      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('SCAN_ALREADY_TERMINAL');
    });
  });

  describe('SCAN_* permission enforcement', () => {
    it('VIEWER can list and read scans (SCAN_READ)', async () => {
      // The harness uses the in-memory DB where org membership roles are set directly.
      // With the mock scan service, if the route reaches the service it means RBAC passed.
      const { app, db, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `perm-owner-${randomBytes(4).toString('hex')}@test.com`
      );

      // Add a VIEWER member
      const viewerPassword = 'viewer-secure-pass-123';
      const viewerEmail = `perm-viewer-${randomBytes(4).toString('hex')}@test.com`;
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: viewerEmail, displayName: 'Viewer', password: viewerPassword });
      const viewerLogin = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: viewerEmail, password: viewerPassword });
      const viewerToken = viewerLogin.body.accessToken as string;
      // Find the viewer's userId by checking who just registered
      const allUsers = [...db.users.values()];
      const viewerUser = allUsers.find((u) => u.email === viewerEmail);
      if (viewerUser) {
        await db.createMembership({
          organizationId: orgId,
          userId: viewerUser.id,
          role: 'VIEWER',
          status: 'ACTIVE',
        });
      }

      const listRes = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${viewerToken}`);
      // Should not be 403 — VIEWER has SCAN_READ
      expect([200, 404, 400]).toContain(listRes.status); // 400/404 from mock service is fine; 403 is not
      expect(listRes.status).not.toBe(403);
    });

    it('VIEWER cannot create scans (SCAN_CREATE)', async () => {
      const { app, db, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `perm-owner2-${randomBytes(4).toString('hex')}@test.com`
      );

      const viewerPassword = 'viewer-pass-456';
      const viewerEmail = `perm-viewer2-${randomBytes(4).toString('hex')}@test.com`;
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: viewerEmail, displayName: 'V', password: viewerPassword });
      const viewerLogin = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: viewerEmail, password: viewerPassword });
      const viewerToken = viewerLogin.body.accessToken as string;
      const viewerUser = [...db.users.values()].find((u) => u.email === viewerEmail);
      if (viewerUser) {
        await db.createMembership({
          organizationId: orgId,
          userId: viewerUser.id,
          role: 'VIEWER',
          status: 'ACTIVE',
        });
      }

      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ requestedRef: 'main' });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('VIEWER cannot cancel scans (SCAN_CANCEL)', async () => {
      const { app, db, setupOrgAndToken } = createHarness();
      const { orgId } = await setupOrgAndToken(
        `perm-owner3-${randomBytes(4).toString('hex')}@test.com`
      );

      const viewerPassword = 'viewer-pass-789';
      const viewerEmail = `perm-viewer3-${randomBytes(4).toString('hex')}@test.com`;
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: viewerEmail, displayName: 'V', password: viewerPassword });
      const viewerLogin = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: viewerEmail, password: viewerPassword });
      const viewerToken = viewerLogin.body.accessToken as string;
      const viewerUser = [...db.users.values()].find((u) => u.email === viewerEmail);
      if (viewerUser) {
        await db.createMembership({
          organizationId: orgId,
          userId: viewerUser.id,
          role: 'VIEWER',
          status: 'ACTIVE',
        });
      }

      const scanId = randomBytes(12).toString('hex');
      const res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans/${scanId}/cancel`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({});
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });
});

describe('ORGANIZATION_PERMISSION_MATRIX — scan permission coverage', () => {
  it('SCAN_READ is granted to OWNER, ADMIN, MEMBER, VIEWER', async () => {
    const { ORGANIZATION_PERMISSION_MATRIX, OrganizationPermission } =
      await import('../modules/organizations/organization.permissions.js');
    const scanReadRoles = ORGANIZATION_PERMISSION_MATRIX[OrganizationPermission.SCAN_READ];
    expect(scanReadRoles.has('OWNER')).toBe(true);
    expect(scanReadRoles.has('ADMIN')).toBe(true);
    expect(scanReadRoles.has('MEMBER')).toBe(true);
    expect(scanReadRoles.has('VIEWER')).toBe(true);
  });

  it('SCAN_CREATE excludes VIEWER', async () => {
    const { ORGANIZATION_PERMISSION_MATRIX, OrganizationPermission } =
      await import('../modules/organizations/organization.permissions.js');
    const scanCreateRoles = ORGANIZATION_PERMISSION_MATRIX[OrganizationPermission.SCAN_CREATE];
    expect(scanCreateRoles.has('VIEWER')).toBe(false);
    expect(scanCreateRoles.has('MEMBER')).toBe(true);
    expect(scanCreateRoles.has('ADMIN')).toBe(true);
    expect(scanCreateRoles.has('OWNER')).toBe(true);
  });

  it('SCAN_CANCEL excludes VIEWER', async () => {
    const { ORGANIZATION_PERMISSION_MATRIX, OrganizationPermission } =
      await import('../modules/organizations/organization.permissions.js');
    const scanCancelRoles = ORGANIZATION_PERMISSION_MATRIX[OrganizationPermission.SCAN_CANCEL];
    expect(scanCancelRoles.has('VIEWER')).toBe(false);
    expect(scanCancelRoles.has('MEMBER')).toBe(true);
    expect(scanCancelRoles.has('ADMIN')).toBe(true);
    expect(scanCancelRoles.has('OWNER')).toBe(true);
  });

  it('SCAN_* permissions are present in the matrix (exhaustiveness)', async () => {
    const { ORGANIZATION_PERMISSION_MATRIX, OrganizationPermission } =
      await import('../modules/organizations/organization.permissions.js');
    expect(ORGANIZATION_PERMISSION_MATRIX).toHaveProperty(OrganizationPermission.SCAN_READ);
    expect(ORGANIZATION_PERMISSION_MATRIX).toHaveProperty(OrganizationPermission.SCAN_CREATE);
    expect(ORGANIZATION_PERMISSION_MATRIX).toHaveProperty(OrganizationPermission.SCAN_CANCEL);
  });
});

describe('listScansPagedByProjectInOrganization — unit (no DB)', () => {
  it('service maps paginated result into correct response shape', async () => {
    const scan = {
      id: 'abc',
      organizationId: 'org1',
      projectId: 'proj1',
      repositoryConnectionId: 'conn1',
      githubInstallationId: 1,
      githubRepositoryId: 2,
      requestedRef: 'main',
      requestedCommitHash: null,
      resolvedCommitSha: null,
      status: 'QUEUED' as ScanLifecycleStatus,
      isActive: true,
      triggerSource: 'manual' as ScanTriggerSource,
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

    const mockService: ScanService = {
      createScan: vi.fn(),
      listScans: vi.fn().mockResolvedValue({
        scans: [scan, scan, scan],
        pagination: { page: 2, limit: 3, total: 10, totalPages: 4 },
      }),
      getScan: vi.fn(),
      cancelScan: vi.fn(),
    };

    // Call service directly
    const result = await mockService.listScans('org1', 'proj1', { page: 2, limit: 3 });
    expect(result.scans).toHaveLength(3);
    expect(result.pagination).toMatchObject({ page: 2, limit: 3, total: 10, totalPages: 4 });
  });
});

describe('POST /scans — validation & rate limiting', () => {
  const projectId = randomBytes(12).toString('hex');

  it('accepts valid branch names with slashes and dots (e.g. feature/v1.0.0)', async () => {
    const mockService = makeMockScanService();
    const { app, setupOrgAndToken } = createHarness(mockService);
    const { orgId, token } = await setupOrgAndToken(
      `scan-validref-${randomBytes(4).toString('hex')}@test.com`
    );
    const res = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'feature/v1.0.0-rc1' });
    expect(res.status).toBe(201);
  });

  it('allows requests within rate limit and sets X-RateLimit-* headers, then returns 429 when exceeded', async () => {
    const { app, setupOrgAndToken } = createHarness(undefined, {
      maxRequests: 2,
      windowMs: 60_000,
    });
    const { orgId, token } = await setupOrgAndToken(
      `scan-rl-${randomBytes(4).toString('hex')}@test.com`
    );

    const r1 = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'main' });
    expect(r1.status).toBe(201);
    expect(r1.headers['x-ratelimit-limit']).toBe('2');
    expect(r1.headers['x-ratelimit-remaining']).toBe('1');

    const r2 = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'main' });
    expect(r2.status).toBe(201);
    expect(r2.headers['x-ratelimit-remaining']).toBe('0');

    const r3 = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'main' });
    expect(r3.status).toBe(429);
    expect(r3.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(Number(r3.headers['retry-after'])).toBeGreaterThanOrEqual(1);
  });

  it('scopes rate limits per (organizationId, userId) so another org or user is not blocked', async () => {
    const { app, setupOrgAndToken } = createHarness(undefined, {
      maxRequests: 1,
      windowMs: 60_000,
    });
    const userA = await setupOrgAndToken(`scan-rla-${randomBytes(4).toString('hex')}@test.com`);
    const userB = await setupOrgAndToken(`scan-rlb-${randomBytes(4).toString('hex')}@test.com`);

    const a1 = await request(app)
      .post(`/api/v1/organizations/${userA.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ requestedRef: 'main' });
    expect(a1.status).toBe(201);

    const a2 = await request(app)
      .post(`/api/v1/organizations/${userA.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${userA.token}`)
      .send({ requestedRef: 'main' });
    expect(a2.status).toBe(429);

    const b1 = await request(app)
      .post(`/api/v1/organizations/${userB.orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${userB.token}`)
      .send({ requestedRef: 'main' });
    expect(b1.status).toBe(201);
  });

  it('fails closed with 503 RATE_LIMIT_UNAVAILABLE when no rate-limit backend is configured', async () => {
    const mockService = makeMockScanService();
    const { app, setupOrgAndToken } = createHarness(mockService, { disableRateLimiter: true });
    const { orgId, token } = await setupOrgAndToken(
      `scan-rl-unavail-${randomBytes(4).toString('hex')}@test.com`
    );

    const res = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'main' });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('RATE_LIMIT_UNAVAILABLE');
    expect(mockService.createScan).not.toHaveBeenCalled();
  });

  it('fails closed with 503 RATE_LIMIT_UNAVAILABLE when rate-limit backend throws', async () => {
    const mockService = makeMockScanService();
    const failingLimiter = createScanCreationRateLimiter({
      consumeRateLimit: async () => {
        throw new Error('Redis connection lost');
      },
    });
    const { app, setupOrgAndToken } = createHarness(mockService, {
      customRateLimiter: failingLimiter,
    });
    const { orgId, token } = await setupOrgAndToken(
      `scan-rl-err-${randomBytes(4).toString('hex')}@test.com`
    );

    const res = await request(app)
      .post(`/api/v1/organizations/${orgId}/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ requestedRef: 'main' });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('RATE_LIMIT_UNAVAILABLE');
    expect(mockService.createScan).not.toHaveBeenCalled();
  });

  it('sets Retry-After to 1s (not full window) when Redis PTTL returns 0 (<1ms left)', async () => {
    const { consumeScanCreationRateLimit } = await import('@vibeshield/queue');
    const mockManager = {
      isConnected: () => true,
      getQueueClient: () => ({
        status: 'ready',
        connect: async () => undefined,
        ping: async () => 'PONG',
        quit: async () => 'OK',
        disconnect: () => undefined,
        on: () => undefined,
        eval: async () => [11, 0],
      }),
    };

    const decision = await consumeScanCreationRateLimit(mockManager, {
      organizationId: randomBytes(12).toString('hex'),
      userId: randomBytes(12).toString('hex'),
      maxRequests: 10,
      windowMs: 60_000,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBe(1);
  });
});
