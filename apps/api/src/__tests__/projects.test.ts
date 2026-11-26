import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
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
import { createProjectService } from '../modules/projects/project.service.js';
import type { ProjectStore, ProjectTransactionContext } from '../modules/projects/project.store.js';
import type { ListProjectsQuery, PublicProject } from '../modules/projects/project.types.js';

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
  projects: Map<string, PublicProject>;
  touchedOrgIds: Set<string>;
  touchedMembershipIds: Set<string>;
  touchedProjectIds: Set<string>;
}

class WriteConflictError extends Error {
  public readonly code = 112;
  constructor(message = 'WriteConflict') {
    super(message);
    this.name = 'WriteConflictError';
  }
}

class InMemoryProjectTestDatabase implements AuthStore, OrganizationStore, ProjectStore {
  public readonly users = new Map<string, StoredUserWithPassword>();
  public readonly sessions = new Map<string, InMemorySessionRecord>();
  public organizations = new Map<string, PublicOrganization>();
  public memberships = new Map<string, StoredMembershipRecord>();
  public projects = new Map<string, PublicProject>();
  public failNextProjectCreate = false;
  public operationTrace: string[] = [];

  private commitSeq = 0;
  private orgDocVersions = new Map<string, number>();
  private membershipDocVersions = new Map<string, number>();
  private projectDocVersions = new Map<string, number>();

  private getOrgsMap(tx?: OrganizationTransactionContext): Map<string, PublicOrganization> {
    return tx ? (tx as SnapshotTx).orgs : this.organizations;
  }

  private getMembershipsMap(
    tx?: OrganizationTransactionContext
  ): Map<string, StoredMembershipRecord> {
    return tx ? (tx as SnapshotTx).memberships : this.memberships;
  }

  private getProjectsMap(tx?: ProjectTransactionContext): Map<string, PublicProject> {
    return tx ? (tx as SnapshotTx).projects : this.projects;
  }

  // --- AuthStore ---
  async createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: UserStatus;
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
    const s = this.sessions.get(sessionId);
    if (!s || s.userId !== userId || s.revokedAt !== null || s.expiresAt <= now) return null;
    return { id: s.id, userId: s.userId };
  }
  async revokeSessionById(): Promise<void> {}
  async revokeSessionByIdAndUserId(): Promise<void> {}
  async revokeSessionByTokenHash(): Promise<void> {}

  // --- Shared Transaction & Lock ---
  async withTransaction<T>(work: (tx: SnapshotTx) => Promise<T>): Promise<T> {
    const maxRetries = 5;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const startSeq = this.commitSeq;
      const tx: SnapshotTx = {
        startSeq,
        orgs: new Map([...this.organizations.entries()].map(([k, v]) => [k, { ...v }])),
        memberships: new Map([...this.memberships.entries()].map(([k, v]) => [k, { ...v }])),
        projects: new Map([...this.projects.entries()].map(([k, v]) => [k, { ...v }])),
        touchedOrgIds: new Set<string>(),
        touchedMembershipIds: new Set<string>(),
        touchedProjectIds: new Set<string>(),
      };

      try {
        const result = await work(tx);

        for (const id of tx.touchedOrgIds) {
          if ((this.orgDocVersions.get(id) ?? 0) > tx.startSeq) throw new WriteConflictError();
        }
        for (const id of tx.touchedMembershipIds) {
          if ((this.membershipDocVersions.get(id) ?? 0) > tx.startSeq)
            throw new WriteConflictError();
        }
        for (const id of tx.touchedProjectIds) {
          if ((this.projectDocVersions.get(id) ?? 0) > tx.startSeq) throw new WriteConflictError();
        }

        const seenProjectSlugs = new Set<string>();
        for (const p of tx.projects.values()) {
          const key = `${p.organizationId}:${p.slug}`;
          if (seenProjectSlugs.has(key)) {
            const err = new Error('E11000 duplicate project slug') as Error & { code: number };
            err.code = 11000;
            throw err;
          }
          seenProjectSlugs.add(key);
        }

        this.commitSeq++;
        this.organizations = tx.orgs;
        this.memberships = tx.memberships;
        this.projects = tx.projects;
        for (const id of tx.touchedOrgIds) this.orgDocVersions.set(id, this.commitSeq);
        for (const id of tx.touchedMembershipIds)
          this.membershipDocVersions.set(id, this.commitSeq);
        for (const id of tx.touchedProjectIds) this.projectDocVersions.set(id, this.commitSeq);

        return result;
      } catch (error) {
        if (error instanceof WriteConflictError && attempt < maxRetries) {
          continue;
        }
        throw error;
      }
    }
    throw new WriteConflictError();
  }

  async acquireOrganizationLock(
    organizationId: string,
    tx: OrganizationTransactionContext
  ): Promise<boolean> {
    this.operationTrace.push(`acquireOrganizationLock:${organizationId}`);
    const snapshotTx = tx as SnapshotTx;
    if (!snapshotTx.orgs.has(organizationId)) return false;
    snapshotTx.touchedOrgIds.add(organizationId);
    return true;
  }

  // --- OrganizationStore ---
  async createOrganization(
    input: { name: string; slug: string; createdBy: string },
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization> {
    const orgs = this.getOrgsMap(tx);
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
    if (tx) (tx as SnapshotTx).touchedOrgIds.add(org.id);
    return { ...org };
  }

  async findOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization | null> {
    const org = this.getOrgsMap(tx).get(organizationId);
    return org ? { ...org } : null;
  }

  async updateOrganizationById(): Promise<PublicOrganization | null> {
    return null;
  }
  async deleteOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean> {
    if (tx) (tx as SnapshotTx).touchedOrgIds.add(organizationId);
    return this.getOrgsMap(tx).delete(organizationId);
  }
  async hasProjectsInOrganization(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean> {
    for (const p of this.getProjectsMap(tx).values()) {
      if (p.organizationId === organizationId) return true;
    }
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
  async createMembership(
    input: {
      userId: string;
      organizationId: string;
      role: OrganizationRole;
      status: MembershipStatus;
    },
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord> {
    const memberships = this.getMembershipsMap(tx);
    const record: StoredMembershipRecord = {
      id: randomBytes(12).toString('hex'),
      userId: input.userId,
      organizationId: input.organizationId,
      role: input.role,
      status: input.status,
      createdAt: new Date(),
    };
    memberships.set(record.id, record);
    if (tx) (tx as SnapshotTx).touchedMembershipIds.add(record.id);
    return { ...record };
  }
  async findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null> {
    if (tx) this.operationTrace.push(`findActiveMembershipInTx:${organizationId}`);
    for (const m of this.getMembershipsMap(tx).values()) {
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
  async deleteAllMembershipsInOrganization(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<void> {
    const map = this.getMembershipsMap(tx);
    for (const [id, m] of map.entries()) {
      if (m.organizationId === organizationId) {
        map.delete(id);
        if (tx) (tx as SnapshotTx).touchedMembershipIds.add(id);
      }
    }
  }
  async countActiveOwnersExcluding(): Promise<number> {
    return 0;
  }
  async countActiveOwners(): Promise<number> {
    return 1;
  }
  async findUserByEmail(email: string): Promise<StoredUserSummary | null> {
    for (const u of this.users.values()) {
      if (u.email === email) return { ...u };
    }
    return null;
  }
  async findUserById(userId: string): Promise<StoredUserSummary | null> {
    const u = this.users.get(userId);
    return u ? { ...u } : null;
  }

  // --- ProjectStore ---
  async createProject(
    input: {
      organizationId: string;
      name: string;
      slug: string;
      description?: string;
      createdBy: string;
    },
    tx?: ProjectTransactionContext
  ): Promise<PublicProject> {
    this.operationTrace.push(`createProject:${input.organizationId}`);
    if (this.failNextProjectCreate) {
      this.failNextProjectCreate = false;
      throw new Error('Simulated project insert failure');
    }

    const projects = this.getProjectsMap(tx);
    for (const existing of projects.values()) {
      if (existing.organizationId === input.organizationId && existing.slug === input.slug) {
        const err = new Error('E11000 duplicate project slug') as Error & { code: number };
        err.code = 11000;
        throw err;
      }
    }

    const now = new Date();
    const project: PublicProject = {
      id: randomBytes(12).toString('hex'),
      organizationId: input.organizationId,
      name: input.name,
      slug: input.slug,
      description: input.description ?? null,
      createdBy: input.createdBy,
      archivedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    projects.set(project.id, project);
    if (tx) (tx as SnapshotTx).touchedProjectIds.add(project.id);
    return { ...project };
  }

  async findProjectByIdInOrganization(
    organizationId: string,
    projectId: string,
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null> {
    const project = this.getProjectsMap(tx).get(projectId);
    if (!project || project.organizationId !== organizationId) return null;
    return { ...project };
  }

  async listProjectsInOrganization(
    organizationId: string,
    query: ListProjectsQuery
  ): Promise<{ projects: PublicProject[]; total: number }> {
    const matched: PublicProject[] = [];
    for (const p of this.projects.values()) {
      if (p.organizationId !== organizationId) continue;
      if (query.archived === 'false' && p.archivedAt !== null) continue;
      if (query.archived === 'true' && p.archivedAt === null) continue;
      if (query.search && !p.name.toLowerCase().includes(query.search.toLowerCase())) continue;
      matched.push({ ...p });
    }

    matched.sort((a, b) => {
      const timeDiff = b.createdAt.getTime() - a.createdAt.getTime();
      return timeDiff !== 0 ? timeDiff : b.id.localeCompare(a.id);
    });

    const skip = (query.page - 1) * query.limit;
    return {
      projects: matched.slice(skip, skip + query.limit),
      total: matched.length,
    };
  }

  async updateProjectByIdInOrganization(
    organizationId: string,
    projectId: string,
    updates: { name?: string; slug?: string; description?: string | null },
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null> {
    const projects = this.getProjectsMap(tx);
    const project = projects.get(projectId);
    if (!project || project.organizationId !== organizationId) return null;

    if (updates.slug !== undefined) {
      for (const other of projects.values()) {
        if (
          other.id !== projectId &&
          other.organizationId === organizationId &&
          other.slug === updates.slug
        ) {
          const err = new Error('E11000 duplicate project slug') as Error & { code: number };
          err.code = 11000;
          throw err;
        }
      }
      project.slug = updates.slug;
    }
    if (updates.name !== undefined) project.name = updates.name;
    if (updates.description !== undefined) project.description = updates.description;
    project.updatedAt = new Date();
    if (tx) (tx as SnapshotTx).touchedProjectIds.add(projectId);
    return { ...project };
  }

  async setProjectArchivedAtInOrganization(
    organizationId: string,
    projectId: string,
    archivedAt: Date | null,
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null> {
    const projects = this.getProjectsMap(tx);
    const project = projects.get(projectId);
    if (!project || project.organizationId !== organizationId) return null;
    project.archivedAt = archivedAt;
    project.updatedAt = new Date();
    if (tx) (tx as SnapshotTx).touchedProjectIds.add(projectId);
    return { ...project };
  }
}

function createHarness() {
  const db = new InMemoryProjectTestDatabase();
  const authConfig: AuthRuntimeConfig = {
    jwtAccessSecret: 'test_proj_jwt_access_secret_at_least_32_characters_long',
    jwtAccessTtl: '15m',
    jwtAccessTtlSeconds: 900,
    jwtIssuer: 'vibeshield-api',
    jwtAudience: 'vibeshield-clients',
    refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
    isProduction: false,
    cookiePath: '/api/v1/auth',
    allowedOrigins: ['http://localhost:5173'],
  };

  let clockTime = new Date('2026-05-01T10:00:00.000Z');
  const authService = createAuthService({ config: authConfig, store: db });
  const organizationService = createOrganizationService({ store: db });
  const projectService = createProjectService({ store: db, now: () => clockTime });

  const app = createApp({
    auth: { authService, config: authConfig },
    organizations: { organizationService, projectService, authService, authConfig },
  });

  async function registerAndLogin(email: string, displayName: string) {
    const password = 'strong-project-passphrase-123';
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

  return {
    app,
    db,
    projectService,
    organizationService,
    registerAndLogin,
    setNow: (d: Date) => {
      clockTime = d;
    },
  };
}

describe('Organization-Scoped Project Management and RBAC', () => {
  describe('CRUD Lifecycle, Pagination, Search, and Filtering', () => {
    it('creates, lists, retrieves, updates, archives, and restores projects cleanly', async () => {
      const { app, db, registerAndLogin, setNow } = createHarness();
      const owner = await registerAndLogin('proj-owner@example.com', 'Proj Owner');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Acme Security', slug: 'acme-sec' });
      const orgId = orgRes.body.organization.id as string;

      // Create projects
      db.operationTrace = [];
      const p1Res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({
          name: '  Gateway API (v2)  ',
          slug: '  Gateway-API-V2  ',
          description: '  Edge proxy service  ',
        });

      expect(p1Res.status).toBe(201);
      expect(p1Res.body.project).toMatchObject({
        organizationId: orgId,
        name: 'Gateway API (v2)',
        slug: 'gateway-api-v2',
        description: 'Edge proxy service',
        createdBy: owner.user.id,
        archivedAt: null,
      });
      expect(db.operationTrace[0]).toBe(`acquireOrganizationLock:${orgId}`);
      expect(db.operationTrace.indexOf(`findActiveMembershipInTx:${orgId}`)).toBeGreaterThan(0);

      const p1Id = p1Res.body.project.id as string;

      const p2Res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Billing Worker', slug: 'billing-worker' });
      expect(p2Res.status).toBe(201);

      const p3Res = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Billing Dashboard', slug: 'billing-dashboard' });
      expect(p3Res.status).toBe(201);
      const p3Id = p3Res.body.project.id as string;

      // Get by ID
      const getRes = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects/${p1Id}`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(getRes.status).toBe(200);
      expect(getRes.body.project.id).toBe(p1Id);

      // Update name, slug, description, and clear description
      const patchRes = await request(app)
        .patch(`/api/v1/organizations/${orgId}/projects/${p1Id}`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Gateway Core', slug: 'gateway-core', description: '' });
      expect(patchRes.status).toBe(200);
      expect(patchRes.body.project).toMatchObject({
        name: 'Gateway Core',
        slug: 'gateway-core',
        description: null,
      });

      // Archive (and verify idempotency preserves original archivedAt)
      const archiveTime1 = new Date('2026-05-01T12:00:00.000Z');
      setNow(archiveTime1);
      const archiveRes1 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${p3Id}/archive`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(archiveRes1.status).toBe(200);
      expect(archiveRes1.body.project.archivedAt).toBe(archiveTime1.toISOString());

      setNow(new Date('2026-05-01T13:00:00.000Z'));
      const archiveRes2 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${p3Id}/archive`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(archiveRes2.status).toBe(200);
      expect(archiveRes2.body.project.archivedAt).toBe(archiveTime1.toISOString());

      // List active (default archived=false) vs archived=true vs archived=all + search + pagination
      const listActive = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects?page=1&limit=1`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(listActive.status).toBe(200);
      expect(listActive.body.projects).toHaveLength(1);
      expect(listActive.body.pagination).toEqual({
        page: 1,
        limit: 1,
        total: 2,
        totalPages: 2,
      });

      const listArchived = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects?archived=true`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(listArchived.status).toBe(200);
      expect(listArchived.body.projects.map((p: PublicProject) => p.id)).toEqual([p3Id]);

      const searchAll = await request(app)
        .get(`/api/v1/organizations/${orgId}/projects?archived=all&search=Billing`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(searchAll.status).toBe(200);
      expect(searchAll.body.projects).toHaveLength(2);

      // Restore (and verify idempotency)
      const restoreRes1 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${p3Id}/restore`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(restoreRes1.status).toBe(200);
      expect(restoreRes1.body.project.archivedAt).toBeNull();

      const restoreRes2 = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects/${p3Id}/restore`)
        .set('Authorization', `Bearer ${owner.accessToken}`);
      expect(restoreRes2.status).toBe(200);
      expect(restoreRes2.body.project.archivedAt).toBeNull();
    });
  });

  describe('RBAC Policy Enforcement', () => {
    it('enforces OWNER, ADMIN, MEMBER, and VIEWER permissions accurately', async () => {
      const { app, db, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('rbac-owner@proj.dev', 'Owner');
      const admin = await registerAndLogin('rbac-admin@proj.dev', 'Admin');
      const member = await registerAndLogin('rbac-member@proj.dev', 'Member');
      const viewer = await registerAndLogin('rbac-viewer@proj.dev', 'Viewer');
      const outsider = await registerAndLogin('rbac-outsider@proj.dev', 'Outsider');

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Project RBAC Org', slug: 'proj-rbac-org' });
      const orgId = orgRes.body.organization.id as string;

      await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: admin.user.email, role: 'ADMIN' });
      await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: member.user.email, role: 'MEMBER' });
      await request(app)
        .post(`/api/v1/organizations/${orgId}/members`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ email: viewer.user.email, role: 'VIEWER' });

      // Unauthenticated rejected
      expect((await request(app).get(`/api/v1/organizations/${orgId}/projects`)).status).toBe(401);

      // Outsider denied (404)
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${outsider.accessToken}`)
        ).status
      ).toBe(404);

      // MEMBER can create and update, CANNOT archive or restore
      const memberCreate = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${member.accessToken}`)
        .send({ name: 'Member App', slug: 'member-app' });
      expect(memberCreate.status).toBe(201);
      const projectId = memberCreate.body.project.id as string;

      const memberUpdate = await request(app)
        .patch(`/api/v1/organizations/${orgId}/projects/${projectId}`)
        .set('Authorization', `Bearer ${member.accessToken}`)
        .send({ name: 'Member App v2' });
      expect(memberUpdate.status).toBe(200);

      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/archive`)
            .set('Authorization', `Bearer ${member.accessToken}`)
        ).status
      ).toBe(403);

      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/restore`)
            .set('Authorization', `Bearer ${member.accessToken}`)
        ).status
      ).toBe(403);

      // VIEWER can list and get, CANNOT create, update, archive, or restore
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
        ).status
      ).toBe(200);
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgId}/projects/${projectId}`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
        ).status
      ).toBe(200);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
            .send({ name: 'Viewer Fail', slug: 'viewer-fail' })
        ).status
      ).toBe(403);
      expect(
        (
          await request(app)
            .patch(`/api/v1/organizations/${orgId}/projects/${projectId}`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
            .send({ name: 'Viewer Hack' })
        ).status
      ).toBe(403);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/archive`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
        ).status
      ).toBe(403);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/restore`)
            .set('Authorization', `Bearer ${viewer.accessToken}`)
        ).status
      ).toBe(403);

      // ADMIN can archive & restore
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/archive`)
            .set('Authorization', `Bearer ${admin.accessToken}`)
        ).status
      ).toBe(200);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects/${projectId}/restore`)
            .set('Authorization', `Bearer ${admin.accessToken}`)
        ).status
      ).toBe(200);

      // Stale middleware role revalidation inside transaction: demote MEMBER -> VIEWER in DB directly
      for (const m of db.memberships.values()) {
        if (m.organizationId === orgId && m.userId === member.user.id) {
          m.role = 'VIEWER';
        }
      }
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${member.accessToken}`)
            .send({ name: 'Demoted Fail', slug: 'demoted-fail' })
        ).status
      ).toBe(403);
    });
  });

  describe('Tenant Isolation, Validation, Uniqueness, and Rollback', () => {
    it('prevents cross-organization IDOR and allows identical slugs in different organizations', async () => {
      const { app, registerAndLogin } = createHarness();
      const alice = await registerAndLogin('iso-alice@proj.dev', 'Alice');
      const bob = await registerAndLogin('iso-bob@proj.dev', 'Bob');

      const orgA = (
        await request(app)
          .post('/api/v1/organizations')
          .set('Authorization', `Bearer ${alice.accessToken}`)
          .send({ name: 'Org A', slug: 'iso-org-a' })
      ).body.organization.id as string;

      const orgB = (
        await request(app)
          .post('/api/v1/organizations')
          .set('Authorization', `Bearer ${bob.accessToken}`)
          .send({ name: 'Org B', slug: 'iso-org-b' })
      ).body.organization.id as string;

      // Same slug allowed in Org A and Org B
      const projA = await request(app)
        .post(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ name: 'Shared Web', slug: 'shared-web' });
      const projB = await request(app)
        .post(`/api/v1/organizations/${orgB}/projects`)
        .set('Authorization', `Bearer ${bob.accessToken}`)
        .send({ name: 'Shared Web', slug: 'shared-web' });

      expect(projA.status).toBe(201);
      expect(projB.status).toBe(201);

      const projBId = projB.body.project.id as string;

      // Duplicate slug within same organization rejected with 409
      const dupInOrgA = await request(app)
        .post(`/api/v1/organizations/${orgA}/projects`)
        .set('Authorization', `Bearer ${alice.accessToken}`)
        .send({ name: 'Duplicate Web', slug: '  SHARED-WEB  ' });
      expect(dupInOrgA.status).toBe(409);
      expect(dupInOrgA.body.error.code).toBe('PROJECT_SLUG_EXISTS');

      // Alice (member of Org A) cannot access Bob's project via Org A URL OR Org B URL
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgA}/projects/${projBId}`)
            .set('Authorization', `Bearer ${alice.accessToken}`)
        ).status
      ).toBe(404);
      expect(
        (
          await request(app)
            .patch(`/api/v1/organizations/${orgA}/projects/${projBId}`)
            .set('Authorization', `Bearer ${alice.accessToken}`)
            .send({ name: 'Cross Org Tamper' })
        ).status
      ).toBe(404);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgA}/projects/${projBId}/archive`)
            .set('Authorization', `Bearer ${alice.accessToken}`)
        ).status
      ).toBe(404);
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgB}/projects/${projBId}`)
            .set('Authorization', `Bearer ${alice.accessToken}`)
        ).status
      ).toBe(404);
    });

    it('rejects invalid ObjectIds, malformed slugs/names, and untrusted body fields', async () => {
      const { app, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('val-owner@proj.dev', 'Val Owner');

      const orgId = (
        await request(app)
          .post('/api/v1/organizations')
          .set('Authorization', `Bearer ${owner.accessToken}`)
          .send({ name: 'Val Org', slug: 'val-org' })
      ).body.organization.id as string;

      // Invalid orgId / projectId
      expect(
        (
          await request(app)
            .get('/api/v1/organizations/bad-id/projects')
            .set('Authorization', `Bearer ${owner.accessToken}`)
        ).status
      ).toBe(400);
      expect(
        (
          await request(app)
            .get(`/api/v1/organizations/${orgId}/projects/bad-proj-id`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
        ).status
      ).toBe(400);

      // Untrusted organizationId / createdBy / archivedAt rejected
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
            .send({
              name: 'Good Name',
              slug: 'good-slug',
              organizationId: randomBytes(12).toString('hex'),
            })
        ).status
      ).toBe(400);
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
            .send({
              name: 'Good Name',
              slug: 'good-slug',
              createdBy: randomBytes(12).toString('hex'),
            })
        ).status
      ).toBe(400);

      // Invalid slug / name
      expect(
        (
          await request(app)
            .post(`/api/v1/organizations/${orgId}/projects`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
            .send({ name: 'A', slug: 'bad--slug' })
        ).status
      ).toBe(400);

      // Create valid project then test immutable fields on PATCH
      const created = await request(app)
        .post(`/api/v1/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${owner.accessToken}`)
        .send({ name: 'Valid Project', slug: 'valid-project' });
      const projectId = created.body.project.id as string;

      expect(
        (
          await request(app)
            .patch(`/api/v1/organizations/${orgId}/projects/${projectId}`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
            .send({ archivedAt: new Date().toISOString() })
        ).status
      ).toBe(400);
      expect(
        (
          await request(app)
            .patch(`/api/v1/organizations/${orgId}/projects/${projectId}`)
            .set('Authorization', `Bearer ${owner.accessToken}`)
            .send({})
        ).status
      ).toBe(400);
    });

    it('rolls back project creation on failure and aborts when organization is deleted', async () => {
      const { db, organizationService, projectService, registerAndLogin } = createHarness();
      const owner = await registerAndLogin('tx-proj@proj.dev', 'Tx Owner');

      const org = await organizationService.createOrganization(owner.user.id, {
        name: 'Tx Org',
        slug: 'tx-org',
      });

      db.failNextProjectCreate = true;
      await expect(
        projectService.createProject(owner.user.id, org.id, {
          name: 'Rollback Project',
          slug: 'rollback-project',
        })
      ).rejects.toThrow('Simulated project insert failure');
      expect(db.projects.size).toBe(0);

      await organizationService.deleteOrganization(owner.user.id, org.id);
      await expect(
        projectService.createProject(owner.user.id, org.id, {
          name: 'Ghost Project',
          slug: 'ghost-project',
        })
      ).rejects.toMatchObject({ statusCode: 404, code: 'ORGANIZATION_NOT_FOUND' });
    });
  });
});
