import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import type { MembershipStatus, OrganizationRole, UserStatus } from '@vibeshield/database';
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

interface InMemorySessionRecord {
  id: string;
  userId: string;
  refreshTokenHash: string;
  previousRefreshTokenHash: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
}

interface SnapshotTx {
  startSeq: number;
  orgs: Map<string, PublicOrganization>;
  memberships: Map<string, StoredMembershipRecord>;
  touchedOrgIds: Set<string>;
  touchedMembershipIds: Set<string>;
}

class WriteConflictError extends Error {
  public readonly code = 112;
  constructor(message = 'WriteConflict error: this operation conflicted with another operation') {
    super(message);
    this.name = 'WriteConflictError';
  }
}

class InMemorySharedDatabase implements AuthStore, OrganizationStore {
  public readonly users = new Map<string, StoredUserWithPassword>();
  public readonly sessions = new Map<string, InMemorySessionRecord>();
  public readonly rotatedTokens = new Map<string, { sessionId: string; expiresAt: Date }>();
  public organizations = new Map<string, PublicOrganization>();
  public memberships = new Map<string, StoredMembershipRecord>();
  public orgIdsWithProjects = new Set<string>();
  public failNextMembershipCreate = false;
  public operationTrace: string[] = [];
  public writeConflictCount = 0;

  private commitSeq = 0;
  private orgDocVersions = new Map<string, number>();
  private membershipDocVersions = new Map<string, number>();
  private orgLockVersions = new Map<string, number>();

  /**
   * Optional hook invoked inside `withTransaction` right after `acquireOrganizationLock`
   * to test deterministic overlapping transaction interleavings without a global lock.
   */
  public onAfterLockAcquired?: (organizationId: string, tx: SnapshotTx) => Promise<void>;

  private getOrgsMap(tx?: OrganizationTransactionContext): Map<string, PublicOrganization> {
    return tx ? (tx as SnapshotTx).orgs : this.organizations;
  }

  private getMembershipsMap(
    tx?: OrganizationTransactionContext
  ): Map<string, StoredMembershipRecord> {
    return tx ? (tx as SnapshotTx).memberships : this.memberships;
  }

  // --- AuthStore ---
  async createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: UserStatus;
  }): Promise<PublicUser> {
    for (const existing of this.users.values()) {
      if (existing.email === input.email) {
        const err = new Error('E11000 duplicate key error') as Error & { code: number };
        err.code = 11000;
        throw err;
      }
    }
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
      id: record.id,
      email: record.email,
      displayName: record.displayName,
      status: record.status,
      createdAt: record.createdAt,
    };
  }

  async findUserWithPasswordByEmail(email: string): Promise<StoredUserWithPassword | null> {
    for (const user of this.users.values()) {
      if (user.email === email) return { ...user };
    }
    return null;
  }

  async findActiveUserById(userId: string): Promise<PublicUser | null> {
    const user = this.users.get(userId);
    if (!user || user.status !== 'ACTIVE') return null;
    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  async createSession(input: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }): Promise<StoredSessionRef> {
    const id = randomBytes(12).toString('hex');
    this.sessions.set(id, {
      id,
      userId: input.userId,
      refreshTokenHash: input.refreshTokenHash,
      previousRefreshTokenHash: null,
      expiresAt: input.expiresAt,
      revokedAt: null,
      lastUsedAt: input.lastUsedAt,
    });
    return { id, userId: input.userId };
  }

  async rotateSession(): Promise<StoredSessionRef | null> {
    return null;
  }

  async recordRotatedToken(): Promise<void> {}
  async revokeSessionByPreviousTokenHash(): Promise<boolean> {
    return false;
  }
  async revokeSessionByRotatedTokenHash(): Promise<boolean> {
    return false;
  }

  async findActiveSessionByIdAndUserId(
    sessionId: string,
    userId: string,
    now: Date
  ): Promise<StoredSessionRef | null> {
    const session = this.sessions.get(sessionId);
    if (
      !session ||
      session.userId !== userId ||
      session.revokedAt !== null ||
      session.expiresAt <= now
    ) {
      return null;
    }
    return { id: session.id, userId: session.userId };
  }

  async revokeSessionById(): Promise<void> {}
  async revokeSessionByIdAndUserId(): Promise<void> {}
  async revokeSessionByTokenHash(): Promise<void> {}

  // --- OrganizationStore (Snapshot Isolation Simulator — NO global lock) ---
  async withTransaction<T>(work: (tx: OrganizationTransactionContext) => Promise<T>): Promise<T> {
    const maxRetries = 5;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const startSeq = this.commitSeq;
      const tx: SnapshotTx = {
        startSeq,
        orgs: new Map([...this.organizations.entries()].map(([k, v]) => [k, { ...v }])),
        memberships: new Map([...this.memberships.entries()].map(([k, v]) => [k, { ...v }])),
        touchedOrgIds: new Set<string>(),
        touchedMembershipIds: new Set<string>(),
      };

      try {
        const result = await work(tx);

        // Snapshot-isolation commit validation: conflict only if a written document changed since startSeq
        for (const orgId of tx.touchedOrgIds) {
          if ((this.orgDocVersions.get(orgId) ?? 0) > tx.startSeq) {
            throw new WriteConflictError(`WriteConflict on Organization ${orgId}`);
          }
        }
        for (const membershipId of tx.touchedMembershipIds) {
          if ((this.membershipDocVersions.get(membershipId) ?? 0) > tx.startSeq) {
            throw new WriteConflictError(`WriteConflict on OrganizationMembership ${membershipId}`);
          }
        }

        // Enforce unique constraints at commit time
        const seenSlugs = new Set<string>();
        for (const org of tx.orgs.values()) {
          if (seenSlugs.has(org.slug)) {
            const err = new Error('E11000 duplicate slug') as Error & { code: number };
            err.code = 11000;
            throw err;
          }
          seenSlugs.add(org.slug);
        }
        const seenMembers = new Set<string>();
        for (const m of tx.memberships.values()) {
          const key = `${m.organizationId}:${m.userId}`;
          if (seenMembers.has(key)) {
            const err = new Error('E11000 duplicate membership') as Error & { code: number };
            err.code = 11000;
            throw err;
          }
          seenMembers.add(key);
        }

        // Atomic commit
        this.commitSeq++;
        this.organizations = tx.orgs;
        this.memberships = tx.memberships;
        for (const orgId of tx.touchedOrgIds) {
          this.orgDocVersions.set(orgId, this.commitSeq);
        }
        for (const membershipId of tx.touchedMembershipIds) {
          this.membershipDocVersions.set(membershipId, this.commitSeq);
        }
        return result;
      } catch (error) {
        if (error instanceof WriteConflictError && attempt < maxRetries) {
          this.writeConflictCount++;
          continue;
        }
        throw error;
      }
    }

    throw new WriteConflictError('Exceeded bounded transaction retries');
  }

  async acquireOrganizationLock(
    organizationId: string,
    tx: OrganizationTransactionContext
  ): Promise<boolean> {
    this.operationTrace.push(`acquireOrganizationLock:${organizationId}`);
    const snapshotTx = tx as SnapshotTx;
    const org = snapshotTx.orgs.get(organizationId);
    if (!org) {
      return false;
    }

    snapshotTx.touchedOrgIds.add(organizationId);
    const prevVersion = this.orgLockVersions.get(organizationId) ?? 0;
    this.orgLockVersions.set(organizationId, prevVersion + 1);

    if (this.onAfterLockAcquired) {
      await this.onAfterLockAcquired(organizationId, snapshotTx);
    }

    return true;
  }

  async createOrganization(
    input: {
      name: string;
      slug: string;
      createdBy: string;
    },
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization> {
    const orgs = this.getOrgsMap(tx);
    for (const org of orgs.values()) {
      if (org.slug === input.slug) {
        const err = new Error('E11000 duplicate slug') as Error & { code: number };
        err.code = 11000;
        throw err;
      }
    }
    const now = new Date();
    const org: PublicOrganization = {
      id: randomBytes(12).toString('hex'),
      name: input.name,
      slug: input.slug,
      createdBy: input.createdBy,
      createdAt: now,
      updatedAt: now,
    };
    orgs.set(org.id, org);
    if (tx) {
      (tx as SnapshotTx).touchedOrgIds.add(org.id);
    }
    return { ...org };
  }

  async findOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization | null> {
    const org = this.getOrgsMap(tx).get(organizationId);
    return org ? { ...org } : null;
  }

  async updateOrganizationById(
    organizationId: string,
    updates: { name?: string; slug?: string },
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization | null> {
    this.operationTrace.push(`updateOrganizationById:${organizationId}`);
    const orgs = this.getOrgsMap(tx);
    const org = orgs.get(organizationId);
    if (!org) return null;

    if (updates.slug !== undefined) {
      for (const other of orgs.values()) {
        if (other.id !== organizationId && other.slug === updates.slug) {
          const err = new Error('E11000 duplicate slug') as Error & { code: number };
          err.code = 11000;
          throw err;
        }
      }
      org.slug = updates.slug;
    }
    if (updates.name !== undefined) {
      org.name = updates.name;
    }
    org.updatedAt = new Date();
    if (tx) {
      (tx as SnapshotTx).touchedOrgIds.add(organizationId);
    }
    return { ...org };
  }

  async deleteOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean> {
    this.operationTrace.push(`deleteOrganizationById:${organizationId}`);
    if (tx) {
      (tx as SnapshotTx).touchedOrgIds.add(organizationId);
    }
    return this.getOrgsMap(tx).delete(organizationId);
  }

  async hasProjectsInOrganization(organizationId: string): Promise<boolean> {
    return this.orgIdsWithProjects.has(organizationId);
  }

  async listActiveOrganizationsForUser(userId: string): Promise<OrganizationSummary[]> {
    const results: OrganizationSummary[] = [];
    for (const membership of this.memberships.values()) {
      if (membership.userId === userId && membership.status === 'ACTIVE') {
        const org = this.organizations.get(membership.organizationId);
        if (org) {
          results.push({ ...org, role: membership.role });
        }
      }
    }
    return results;
  }

  async createMembership(
    input: {
      userId: string;
      organizationId: string;
      role: OrganizationRole;
      status: MembershipStatus;
    },
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord> {
    this.operationTrace.push(`createMembership:${input.organizationId}`);
    if (this.failNextMembershipCreate) {
      this.failNextMembershipCreate = false;
      throw new Error('Simulated membership write failure');
    }

    const memberships = this.getMembershipsMap(tx);
    for (const existing of memberships.values()) {
      if (existing.organizationId === input.organizationId && existing.userId === input.userId) {
        const err = new Error('E11000 duplicate membership') as Error & { code: number };
        err.code = 11000;
        throw err;
      }
    }

    const record: StoredMembershipRecord = {
      id: randomBytes(12).toString('hex'),
      userId: input.userId,
      organizationId: input.organizationId,
      role: input.role,
      status: input.status,
      createdAt: new Date(),
    };
    memberships.set(record.id, record);
    if (tx) {
      (tx as SnapshotTx).touchedMembershipIds.add(record.id);
    }
    return { ...record };
  }

  async findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null> {
    if (tx) {
      this.operationTrace.push(`findActiveMembershipInTx:${organizationId}`);
    }
    for (const membership of this.getMembershipsMap(tx).values()) {
      if (
        membership.organizationId === organizationId &&
        membership.userId === userId &&
        membership.status === 'ACTIVE'
      ) {
        return {
          id: membership.id,
          userId: membership.userId,
          organizationId: membership.organizationId,
          role: membership.role,
          status: membership.status,
        };
      }
    }
    return null;
  }

  async findMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null> {
    const m = this.getMembershipsMap(tx).get(membershipId);
    if (!m || m.organizationId !== organizationId) return null;
    return { ...m };
  }

  async findMembershipByOrgAndUser(
    organizationId: string,
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null> {
    for (const m of this.getMembershipsMap(tx).values()) {
      if (m.organizationId === organizationId && m.userId === userId) {
        return { ...m };
      }
    }
    return null;
  }

  async listMembersInOrganization(organizationId: string): Promise<OrganizationMemberView[]> {
    const results: OrganizationMemberView[] = [];
    for (const m of this.memberships.values()) {
      if (m.organizationId === organizationId) {
        const user = this.users.get(m.userId);
        if (user) {
          results.push({
            membershipId: m.id,
            userId: user.id,
            email: user.email,
            displayName: user.displayName,
            role: m.role,
            status: m.status,
            createdAt: m.createdAt,
          });
        }
      }
    }
    return results;
  }

  async updateMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    updates: { role?: OrganizationRole; status?: MembershipStatus },
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null> {
    this.operationTrace.push(`updateMembership:${organizationId}`);
    const memberships = this.getMembershipsMap(tx);
    const m = memberships.get(membershipId);
    if (!m || m.organizationId !== organizationId) return null;
    if (updates.role !== undefined) m.role = updates.role;
    if (updates.status !== undefined) m.status = updates.status;
    if (tx) {
      (tx as SnapshotTx).touchedMembershipIds.add(membershipId);
    }
    return { ...m };
  }

  async deleteMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean> {
    this.operationTrace.push(`deleteMembership:${organizationId}`);
    const memberships = this.getMembershipsMap(tx);
    const m = memberships.get(membershipId);
    if (!m || m.organizationId !== organizationId) return false;
    if (tx) {
      (tx as SnapshotTx).touchedMembershipIds.add(membershipId);
    }
    return memberships.delete(membershipId);
  }

  async deleteAllMembershipsInOrganization(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<void> {
    const memberships = this.getMembershipsMap(tx);
    for (const [id, m] of memberships.entries()) {
      if (m.organizationId === organizationId) {
        memberships.delete(id);
        if (tx) {
          (tx as SnapshotTx).touchedMembershipIds.add(id);
        }
      }
    }
  }

  async countActiveOwnersExcluding(
    organizationId: string,
    excludedMembershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<number> {
    this.operationTrace.push(`countActiveOwnersExcluding:${organizationId}`);
    let count = 0;
    for (const m of this.getMembershipsMap(tx).values()) {
      if (
        m.organizationId === organizationId &&
        m.role === 'OWNER' &&
        m.status === 'ACTIVE' &&
        m.id !== excludedMembershipId
      ) {
        count++;
      }
    }
    return count;
  }

  async countActiveOwners(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<number> {
    this.operationTrace.push(`countActiveOwners:${organizationId}`);
    let count = 0;
    for (const m of this.getMembershipsMap(tx).values()) {
      if (m.organizationId === organizationId && m.role === 'OWNER' && m.status === 'ACTIVE') {
        count++;
      }
    }
    return count;
  }

  async findUserByEmail(email: string): Promise<StoredUserSummary | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          status: user.status,
        };
      }
    }
    return null;
  }

  async findUserById(userId: string): Promise<StoredUserSummary | null> {
    const user = this.users.get(userId);
    if (!user) return null;
    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      status: user.status,
    };
  }
}

function createHarness() {
  const db = new InMemorySharedDatabase();
  const authConfig: AuthRuntimeConfig = {
    jwtAccessSecret: 'test_org_jwt_access_secret_at_least_32_characters_long',
    jwtAccessTtl: '15m',
    jwtAccessTtlSeconds: 900,
    jwtIssuer: 'vibeshield-api',
    jwtAudience: 'vibeshield-clients',
    refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
    isProduction: false,
    cookiePath: '/api/v1/auth',
    allowedOrigins: ['http://localhost:5173'],
  };

  const authService = createAuthService({ config: authConfig, store: db });
  const organizationService = createOrganizationService({ store: db });

  const app = createApp({
    auth: { authService, config: authConfig },
    organizations: { organizationService, authService, authConfig },
  });

  async function registerAndLogin(email: string, displayName: string) {
    const password = 'strong-test-passphrase-123';
    const reg = await request(app).post('/api/v1/auth/register').send({
      email,
      displayName,
      password,
    });
    const login = await request(app).post('/api/v1/auth/login').send({
      email,
      password,
    });
    return {
      user: reg.body.user as PublicUser,
      accessToken: login.body.accessToken as string,
    };
  }

  return { app, db, authService, organizationService, registerAndLogin };
}

describe('Organizations and Multi-Tenant RBAC', () => {
  describe('Organization creation (POST /api/v1/organizations)', () => {
    it('requires authentication', async () => {
      const { app } = createHarness();
      const res = await request(app).post('/api/v1/organizations').send({
        name: 'Acme Security',
        slug: 'acme-security',
      });
      expect(res.status).toBe(401);
    });

    it('creates an organization and initial ACTIVE OWNER membership atomically', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('owner@example.com', 'Owner User');

      const res = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({
          name: '  Acme Security  ',
          slug: '  Acme-Sec  ',
        });

      expect(res.status).toBe(201);
      expect(res.body.organization).toMatchObject({
        name: 'Acme Security',
        slug: 'acme-sec',
        createdBy: owner.user.id,
        role: 'OWNER',
      });

      expect(db.organizations.size).toBe(1);
      expect(db.memberships.size).toBe(1);
      const [membership] = [...db.memberships.values()];
      expect(membership).toMatchObject({
        userId: owner.user.id,
        organizationId: res.body.organization.id,
        role: 'OWNER',
        status: 'ACTIVE',
      });
    });

    it('rolls back organization creation when membership write fails in transaction', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('rollback@example.com', 'Rollback');

      db.failNextMembershipCreate = true;

      const res = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({
          name: 'Rollback Org',
          slug: 'rollback-org',
        });

      expect(res.status).toBe(500);
      expect(db.organizations.size).toBe(0);
      expect(db.memberships.size).toBe(0);
    });

    it('rejects duplicate normalized slugs and untrusted fields like createdBy', async () => {
      const { app, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('dup@example.com', 'Dup');

      const untrustedRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({
          name: 'Valid Org',
          slug: 'valid-org',
          createdBy: randomBytes(12).toString('hex'),
        });
      expect(untrustedRes.status).toBe(400);

      const first = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Org One', slug: 'shared-slug' });
      expect(first.status).toBe(201);

      const second = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Org Two', slug: '  SHARED-SLUG  ' });
      expect(second.status).toBe(409);
      expect(second.body.error.code).toBe('ORGANIZATION_SLUG_EXISTS');
    });
  });

  describe('Organization listing, retrieval, and multi-tenant isolation', () => {
    it('lists only organizations with ACTIVE membership and denies INVITED/SUSPENDED/non-members without leaking existence', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const alice = await registerAndLogin('alice@example.com', 'Alice');
      const bob = await registerAndLogin('bob@example.com', 'Bob');

      const aliceOrg = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ name: 'Alice Org', slug: 'alice-org' });

      const bobOrg1 = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .send({ name: 'Bob Private', slug: 'bob-private' });

      const bobOrg2 = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .send({ name: 'Bob Invited', slug: 'bob-invited' });

      const bobOrg3 = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .send({ name: 'Bob Suspended', slug: 'bob-suspended' });

      await db.createMembership({
        userId: alice.user.id,
        organizationId: bobOrg2.body.organization.id,
        role: 'MEMBER',
        status: 'INVITED',
      });
      await db.createMembership({
        userId: alice.user.id,
        organizationId: bobOrg3.body.organization.id,
        role: 'MEMBER',
        status: 'SUSPENDED',
      });

      const listRes = await request(app)
        .get('/api/v1/organizations')
        .set('Authorization', `Bearer ${alice.accessToken}`);
      expect(listRes.status).toBe(200);
      expect(listRes.body.organizations).toHaveLength(1);
      expect(listRes.body.organizations[0].id).toBe(aliceOrg.body.organization.id);
      expect(listRes.body.organizations[0].role).toBe('OWNER');

      // Non-member, INVITED, and SUSPENDED all get 404 without leaking org existence
      for (const blockedOrgId of [
        bobOrg1.body.organization.id,
        bobOrg2.body.organization.id,
        bobOrg3.body.organization.id,
        randomBytes(12).toString('hex'),
      ]) {
        const getRes = await request(app)
          .get(`/api/v1/organizations/${blockedOrgId}`)
          .set('Authorization', `Bearer ${alice.accessToken}`);
        expect(getRes.status).toBe(404);
        expect(getRes.body.error.code).toBe('ORGANIZATION_NOT_FOUND');
      }

      // Invalid ObjectId gets 400
      const invalidIdRes = await request(app)
        .get('/api/v1/organizations/not-an-object-id')
        .set('Authorization', `Bearer ${alice.accessToken}`);
      expect(invalidIdRes.status).toBe(400);
      expect(invalidIdRes.body.error.code).toBe('INVALID_ORGANIZATION_ID');
    });
  });

  describe('RBAC Permission Matrix, Membership Management, and Cross-Org Isolation', () => {
    it('enforces OWNER, ADMIN, MEMBER, and VIEWER permissions and blocks privilege escalation', async () => {
      const { app, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('owner@rbac.dev', 'Owner');
      const admin = await registerAndLogin('admin@rbac.dev', 'Admin');
      const member = await registerAndLogin('member@rbac.dev', 'Member');
      const viewer = await registerAndLogin('viewer@rbac.dev', 'Viewer');
      const candidate = await registerAndLogin('candidate@rbac.dev', 'Candidate');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'RBAC Org', slug: 'rbac-org' });
      const orgId = orgRes.body.organization.id as string;

      // OWNER adds ADMIN, MEMBER, VIEWER; cannot assign OWNER via add
      const addOwnerAttempt = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: candidate.user.email, role: 'OWNER' });
      expect(addOwnerAttempt.status).toBe(403);

      const addAdmin = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: '  ADMIN@RBAC.DEV  ', role: 'ADMIN' });
      expect(addAdmin.status).toBe(201);
      const adminMembershipId = addAdmin.body.member.membershipId as string;

      const addMember = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ email: member.user.email, role: 'MEMBER' });
      expect(addMember.status).toBe(201);
      const memberMembershipId = addMember.body.member.membershipId as string;

      const addViewer = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ email: viewer.user.email, role: 'VIEWER' });
      expect(addViewer.status).toBe(201);
      const viewerMembershipId = addViewer.body.member.membershipId as string;

      // Duplicate membership rejected with 409
      const dupMember = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: member.user.email, role: 'VIEWER' });
      expect(dupMember.status).toBe(409);

      // Unknown email rejected with 404
      const unknownEmail = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: 'ghost@rbac.dev', role: 'VIEWER' });
      expect(unknownEmail.status).toBe(404);

      // ADMIN cannot assign ADMIN or OWNER
      const adminAssignAdmin = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ email: candidate.user.email, role: 'ADMIN' });
      expect(adminAssignAdmin.status).toBe(403);

      const adminPromoteMemberToAdmin = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${memberMembershipId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ role: 'ADMIN' });
      expect(adminPromoteMemberToAdmin.status).toBe(403);

      // ADMIN can switch MEMBER <-> VIEWER
      const adminDemoteMember = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${memberMembershipId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ role: 'VIEWER' });
      expect(adminDemoteMember.status).toBe(200);
      expect(adminDemoteMember.body.member.role).toBe('VIEWER');

      // Restore MEMBER role
      await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${memberMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ role: 'MEMBER' });

      // Users cannot escalate/modify their own role
      const adminSelfPromote = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${adminMembershipId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ role: 'OWNER' });
      expect(adminSelfPromote.status).toBe(403);

      // ADMIN cannot modify or delete OWNER membership
      const membersRes = await request(app)
        .get(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${viewer.accessToken}`);
      expect(membersRes.status).toBe(200);
      expect(membersRes.body.members).toHaveLength(4);
      expect(JSON.stringify(membersRes.body)).not.toContain('passwordHash');

      const ownerMembershipId = membersRes.body.members.find(
        (m: OrganizationMemberView) => m.userId === owner.user.id
      ).membershipId as string;

      const adminModifyOwner = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${ownerMembershipId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ role: 'VIEWER' });
      expect(adminModifyOwner.status).toBe(403);

      const adminRemoveOwner = await request(app)
        .delete(`/api/v1/organizations/${orgId}/members/${ownerMembershipId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`);
      expect(adminRemoveOwner.status).toBe(403);

      // ADMIN can update org details, cannot delete org
      const adminUpdateOrg = await request(app)
        .patch(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)
        .send({ name: 'RBAC Org Updated' });
      expect(adminUpdateOrg.status).toBe(200);
      expect(adminUpdateOrg.body.organization.name).toBe('RBAC Org Updated');

      const adminDeleteOrg = await request(app)
        .delete(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`);
      expect(adminDeleteOrg.status).toBe(403);

      // MEMBER and VIEWER can read org/members, cannot mutate org or other members
      for (const readOnlyActor of [member, viewer]) {
        expect(
          (
            await request(app)
              .get(`/api/v1/organizations/${orgId}`)
              .set('Authorization', `Bearer ${readOnlyActor.accessToken}`)
          ).status
        ).toBe(200);

        expect(
          (
            await request(app)
              .patch(`/api/v1/organizations/${orgId}`)
              .set('Authorization', `Bearer ${readOnlyActor.accessToken}`)
              .send({ name: 'Hacked' })
          ).status
        ).toBe(403);

        expect(
          (
            await request(app)
              .post(`/api/v1/organizations/${orgId}/members`)
              .set('Authorization', `Bearer ${readOnlyActor.accessToken}`)
              .send({ email: candidate.user.email, role: 'VIEWER' })
          ).status
        ).toBe(403);
      }

      // Invalid status transition ACTIVE -> INVITED rejected with 400
      const invalidTransition = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${viewerMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ status: 'INVITED' });
      expect(invalidTransition.status).toBe(400);
      expect(invalidTransition.body.error.code).toBe('INVALID_STATUS_TRANSITION');

      // Cross-organization IDOR attempt: membershipId from Org B cannot be modified via Org A
      const otherOrgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Other Org', slug: 'other-org' });
      const otherOrgId = otherOrgRes.body.organization.id as string;

      const crossOrgPatch = await request(app)
        .patch(`/api/v1/organizations/${otherOrgId}/members/${viewerMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ role: 'ADMIN' });
      expect(crossOrgPatch.status).toBe(404);
      expect(crossOrgPatch.body.error.code).toBe('MEMBERSHIP_NOT_FOUND');

      // Concurrent duplicate addMember race yields one 201 and one 409
      const [c1, c2] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${orgId}/members`)
          .set('Authorization', `Bearer ${owner.accessToken}`)
          .send({ email: candidate.user.email, role: 'MEMBER' }),
        request(app)
          .post(`/api/v1/organizations/${orgId}/members`)
          .set('Authorization', `Bearer ${owner.accessToken}`)
          .send({ email: candidate.user.email, role: 'MEMBER' }),
      ]);
      expect([c1.status, c2.status].sort()).toEqual([201, 409]);
    });

    it('reuses established organizationAuth context without duplicate membership queries', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('cache@rbac.dev', 'Cache Owner');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Cache Org', slug: 'cache-org' });
      const orgId = orgRes.body.organization.id as string;

      const spy = vi.spyOn(db, 'findActiveMembership');
      const res = await request(app)
        .get(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`);

      expect(res.status).toBe(200);
      expect(spy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Ownership Transfer, Last-OWNER Protection, and Organization Deletion', () => {
    it('transfers ownership transactionally, demotes previous OWNER to ADMIN, and protects last OWNER', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('primary@own.dev', 'Primary');
      const successor = await registerAndLogin('successor@own.dev', 'Successor');
      const outsider = await registerAndLogin('outsider@own.dev', 'Outsider');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Ownership Org', slug: 'ownership-org' });
      const orgId = orgRes.body.organization.id as string;

      const membersInitial = await request(app)
        .get(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      const ownerMembershipId = membersInitial.body.members[0].membershipId as string;

      // Last active OWNER cannot demote, suspend, or remove themselves
      const suspendSelf = await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${ownerMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ status: 'SUSPENDED' });
      expect(suspendSelf.status).toBe(403);

      const leaveAsLastOwner = await request(app)
        .delete(`/api/v1/organizations/${orgId}/members/${ownerMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(leaveAsLastOwner.status).toBe(409);
      expect(leaveAsLastOwner.body.error.code).toBe('LAST_OWNER_REQUIRED');

      // Cannot transfer to non-member or suspended member
      const toNonMember = await request(app)
        .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ targetUserId: outsider.user.id });
      expect(toNonMember.status).toBe(400);

      const addSuccessor = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: successor.user.email, role: 'ADMIN' });
      const successorMembershipId = addSuccessor.body.member.membershipId as string;

      // Non-OWNER (ADMIN) cannot transfer ownership
      const unauthorizedTransfer = await request(app)
        .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
        .set('Authorization', `Bearer ${successor.accessToken}`)
        .send({ targetUserId: successor.user.id });
      expect(unauthorizedTransfer.status).toBe(403);

      // Suspend successor temporarily -> target must be ACTIVE
      await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${successorMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ status: 'SUSPENDED' });

      const toSuspended = await request(app)
        .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ targetUserId: successor.user.id });
      expect(toSuspended.status).toBe(400);

      // Re-activate successor and perform ownership transfer
      await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${successorMembershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ status: 'ACTIVE' });

      const transferRes = await request(app)
        .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ targetUserId: successor.user.id });
      expect(transferRes.status).toBe(200);
      expect(transferRes.body.transfer).toEqual({
        organizationId: orgId,
        previousOwnerUserId: owner.user.id,
        newOwnerUserId: successor.user.id,
      });

      // Verify roles after transfer: successor=OWNER, previous owner=ADMIN
      expect(db.memberships.get(successorMembershipId)?.role).toBe('OWNER');
      expect(db.memberships.get(ownerMembershipId)?.role).toBe('ADMIN');
      expect(await db.countActiveOwners(orgId)).toBe(1);

      // Previous owner (now ADMIN) can no longer delete the organization
      const oldOwnerDeleteAttempt = await request(app)
        .delete(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(oldOwnerDeleteAttempt.status).toBe(403);

      // Concurrent transfer + self-leave race never leaves 0 active owners
      const [r1, r2] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
          .set('Authorization', `Bearer ${successor.accessToken}`)
          .send({ targetUserId: owner.user.id }),
        request(app)
          .delete(`/api/v1/organizations/${orgId}/members/${successorMembershipId}`)
          .set('Authorization', `Bearer ${successor.accessToken}`),
      ]);
      expect([r1.status, r2.status]).toContain(200);
      expect(await db.countActiveOwners(orgId)).toBe(1);

      // Active OWNER deletes the organization transactionally without leaving orphaned memberships
      const currentOwnerToken =
        db.memberships.get(ownerMembershipId)?.role === 'OWNER'
          ? owner.accessToken
          : successor.accessToken;

      const deleteRes = await request(app)
        .delete(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${currentOwnerToken}`);
      expect(deleteRes.status).toBe(200);
      expect(db.organizations.size).toBe(0);
      expect(db.memberships.size).toBe(0);
    });
  });

  describe('Per-Organization Transaction Lock, Write-Skew Prevention, and Revalidation', () => {
    it('acquires the organization mutation lock BEFORE reading memberships/owners across all mutations', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('lockorder@own.dev', 'Lock Owner');
      const memberUser = await registerAndLogin('lockmember@own.dev', 'Lock Member');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Lock Order Org', slug: 'lock-order-org' });
      const orgId = orgRes.body.organization.id as string;

      // 1. updateOrganization
      db.operationTrace = [];
      await request(app)
        .patch(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Updated Name' });
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);
      expect(db.operationTrace.indexOf(`findActiveMembershipInTx:${orgId}`)).toBeGreaterThan(0);

      // 2. addMember
      db.operationTrace = [];
      const addRes = await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: memberUser.user.email, role: 'MEMBER' });
      const membershipId = addRes.body.member.membershipId as string;
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);
      expect(db.operationTrace.indexOf(`findActiveMembershipInTx:${orgId}`)).toBeGreaterThan(0);

      // 3. updateMember
      db.operationTrace = [];
      await request(app)
        .patch(`/api/v1/organizations/${orgId}/members/${membershipId}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ role: 'VIEWER' });
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);

      // 4. transferOwnership
      db.operationTrace = [];
      await request(app)
        .post(`/api/v1/organizations/${orgId}/transfer-ownership`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ targetUserId: memberUser.user.id });
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);
      expect(db.operationTrace.indexOf(`countActiveOwners:${orgId}`)).toBeGreaterThan(0);

      // 5. removeMember (by new owner removing old owner who is now ADMIN)
      const membersRes = await request(app)
        .get(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${memberUser.accessToken}`);
      const oldOwnerMembershipId = membersRes.body.members.find(
        (m: OrganizationMemberView) => m.userId === owner.user.id
      ).membershipId as string;

      db.operationTrace = [];
      await request(app)
        .delete(`/api/v1/organizations/${orgId}/members/${oldOwnerMembershipId}`)
        .set('Authorization', `Bearer ${memberUser.accessToken}`);
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);

      // 6. deleteOrganization
      db.operationTrace = [];
      await request(app)
        .delete(`/api/v1/organizations/${orgId}`)
        .set('Authorization', `Bearer ${memberUser.accessToken}`);
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);
    });

    it('prevents two-OWNER mutual removal/demotion write skew under snapshot isolation', async () => {
      const { db, organizationService, registerAndLogin } = createHarness();
      const owner1 = await registerAndLogin('skew1@own.dev', 'Owner One');
      const owner2 = await registerAndLogin('skew2@own.dev', 'Owner Two');

      const org = await organizationService.createOrganization(owner1.user.id, {
        name: 'Two Owner Org',
        slug: 'two-owner-org',
      });
      const m2 = await db.createMembership({
        userId: owner2.user.id,
        organizationId: org.id,
        role: 'OWNER',
        status: 'ACTIVE',
      });
      const m1 = (await db.findMembershipByOrgAndUser(org.id, owner1.user.id))!;

      // Force both transactions to start on the exact same snapshot before either commits
      let enteredCount = 0;
      let releaseBarrier!: () => void;
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });
      let barrierDone = false;

      db.onAfterLockAcquired = async () => {
        if (barrierDone) return;
        enteredCount++;
        if (enteredCount === 2) {
          barrierDone = true;
          releaseBarrier();
        } else {
          await barrier;
        }
      };

      const [res1, res2] = await Promise.allSettled([
        organizationService.removeMember(owner1.user.id, org.id, m2.id),
        organizationService.removeMember(owner2.user.id, org.id, m1.id),
      ]);

      db.onAfterLockAcquired = undefined;

      const fulfilled = [res1, res2].filter((r) => r.status === 'fulfilled');
      const rejected = [res1, res2].filter((r) => r.status === 'rejected');

      // Exactly one succeeds; the second hits WriteConflict on the Organization lock,
      // retries against the updated snapshot, sees 1 remaining OWNER, and fails safely!
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(db.writeConflictCount).toBeGreaterThanOrEqual(1);
      expect(await db.countActiveOwners(org.id)).toBe(1);
    });

    it('prevents addMember vs deleteOrganization race from creating orphaned memberships', async () => {
      const { db, organizationService, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('delrace-owner@own.dev', 'Owner');
      const candidate = await registerAndLogin('delrace-cand@own.dev', 'Candidate');

      const org = await organizationService.createOrganization(owner.user.id, {
        name: 'Delete Race Org',
        slug: 'delete-race-org',
      });

      let enteredCount = 0;
      let releaseBarrier!: () => void;
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });
      let barrierDone = false;

      db.onAfterLockAcquired = async () => {
        if (barrierDone) return;
        enteredCount++;
        if (enteredCount === 2) {
          barrierDone = true;
          releaseBarrier();
        } else {
          await barrier;
        }
      };

      const [delRes, addRes] = await Promise.allSettled([
        organizationService.deleteOrganization(owner.user.id, org.id),
        organizationService.addMember(owner.user.id, org.id, {
          email: candidate.user.email,
          role: 'MEMBER',
        }),
      ]);

      db.onAfterLockAcquired = undefined;

      // Whichever commits second must observe the consistent state (no orphaned membership)
      if (delRes.status === 'fulfilled') {
        expect(db.organizations.has(org.id)).toBe(false);
        expect(
          [...db.memberships.values()].filter((m) => m.organizationId === org.id)
        ).toHaveLength(0);
      } else {
        expect(addRes.status).toBe('fulfilled');
      }
    });

    it('aborts mutations with 404 when the organization is missing or deleted, and rolls back addMember on failure', async () => {
      const { db, organizationService, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('missing@own.dev', 'Owner');
      const candidate = await registerAndLogin('missing-cand@own.dev', 'Candidate');

      const org = await organizationService.createOrganization(owner.user.id, {
        name: 'Temp Org',
        slug: 'temp-org',
      });

      // addMember failure rolls back cleanly without partial membership
      db.failNextMembershipCreate = true;
      await expect(
        organizationService.addMember(owner.user.id, org.id, {
          email: candidate.user.email,
          role: 'MEMBER',
        })
      ).rejects.toThrow('Simulated membership write failure');
      expect(db.memberships.size).toBe(1);

      // Delete org then invoke service mutations directly -> lock fails with 404
      await organizationService.deleteOrganization(owner.user.id, org.id);
      await expect(
        organizationService.addMember(owner.user.id, org.id, {
          email: candidate.user.email,
          role: 'MEMBER',
        })
      ).rejects.toMatchObject({ statusCode: 404, code: 'ORGANIZATION_NOT_FOUND' });

      await expect(
        organizationService.updateOrganization(owner.user.id, org.id, { name: 'Ghost' })
      ).rejects.toMatchObject({ statusCode: 404, code: 'ORGANIZATION_NOT_FOUND' });
    });

    it('revalidates actor ACTIVE membership and role inside the transaction rather than trusting stale middleware context', async () => {
      const { db, organizationService, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('reval-owner@own.dev', 'Owner');
      const admin = await registerAndLogin('reval-admin@own.dev', 'Admin');

      const org = await organizationService.createOrganization(owner.user.id, {
        name: 'Reval Org',
        slug: 'reval-org',
      });
      const adminMembership = await db.createMembership({
        userId: admin.user.id,
        organizationId: org.id,
        role: 'ADMIN',
        status: 'ACTIVE',
      });

      // Simulate admin getting demoted to VIEWER after middleware passed, right before transaction runs
      db.memberships.get(adminMembership.id)!.role = 'VIEWER';

      await expect(
        organizationService.updateOrganization(admin.user.id, org.id, { name: 'Unauthorized' })
      ).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });

      await expect(
        organizationService.addMember(admin.user.id, org.id, {
          email: owner.user.email,
          role: 'MEMBER',
        })
      ).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    });

    it('allows concurrent mutations on different organizations without global lock contention', async () => {
      const { db, organizationService, registerAndLogin } = createHarness();
      const ownerA = await registerAndLogin('orga@own.dev', 'Owner A');
      const ownerB = await registerAndLogin('orgb@own.dev', 'Owner B');

      const orgA = await organizationService.createOrganization(ownerA.user.id, {
        name: 'Org A',
        slug: 'org-a',
      });
      const orgB = await organizationService.createOrganization(ownerB.user.id, {
        name: 'Org B',
        slug: 'org-b',
      });

      let enteredCount = 0;
      let releaseBarrier!: () => void;
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });
      let barrierDone = false;

      // Both transactions overlap simultaneously; neither blocks or conflicts with the other!
      db.onAfterLockAcquired = async () => {
        if (barrierDone) return;
        enteredCount++;
        if (enteredCount === 2) {
          barrierDone = true;
          releaseBarrier();
        } else {
          await barrier;
        }
      };

      db.writeConflictCount = 0;
      const [updatedA, updatedB] = await Promise.all([
        organizationService.updateOrganization(ownerA.user.id, orgA.id, { name: 'Org A New' }),
        organizationService.updateOrganization(ownerB.user.id, orgB.id, { name: 'Org B New' }),
      ]);

      db.onAfterLockAcquired = undefined;

      expect(updatedA.name).toBe('Org A New');
      expect(updatedB.name).toBe('Org B New');
      expect(db.writeConflictCount).toBe(0);
    });
  });
});
