import { generateKeyPairSync } from 'node:crypto';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import {
  computeConnectionIsActive,
  getEffectiveConnectionStatus,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  IntegrationAuditActionValue,
  MembershipStatusValue,
  normalizeEmail,
  normalizeSlug,
  OrganizationRoleValue,
  RepositoryAccessStateValue,
  UserStatusValue,
  type GitHubInstallationStatus,
  type InstallationAvailability,
  type IntegrationAuditAction,
  type MembershipStatus,
  type OrganizationRole,
  type RepositoryAccessState,
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
import { createGitHubService } from '../modules/github/github.service.js';
import type { PublicGitHubInstallation } from '../modules/github/github.types.js';
import { createGitHubRepositoryConnectionService } from '../modules/github/github-connection.service.js';
import type { GitHubRepositoryConnectionStore } from '../modules/github/github-connection.store.js';
import type { PublicProjectRepositoryConnection } from '../modules/github/github-connection.types.js';
import { createOrganizationService } from '../modules/organizations/organization.service.js';
import type { OrganizationStore } from '../modules/organizations/organization.store.js';
import { createProjectService } from '../modules/projects/project.service.js';
import type { ProjectStore } from '../modules/projects/project.store.js';

const { privateKey: TEST_PRIVATE_KEY_PEM } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'test_connections_jwt_access_secret_minimum_32_chars',
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
  appId: 91919,
  appSlug: 'vibeshield-conn-app',
  privateKeyPem: TEST_PRIVATE_KEY_PEM,
  clientId: 'Iv1.conntestclient',
  clientSecret: 'gh_conn_test_client_secret_value_1234',
  webhookSecret: 'whsec_conn_test_webhook_secret_32_chars_min',
  callbackUrl: 'http://localhost:5173/integrations/github/callback',
};

function makeObjectId(counter: number): string {
  return counter.toString(16).padStart(24, '0');
}

interface StoredConnection extends PublicProjectRepositoryConnection {
  connectedAt: Date;
}

function createConnectionsHarness(
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
    {
      id: string;
      name: string;
      slug: string;
      createdBy: string;
      membershipVersion: number;
      createdAt: Date;
      updatedAt: Date;
    }
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
  const projects = new Map<
    string,
    {
      id: string;
      organizationId: string;
      name: string;
      slug: string;
      description: string | null;
      createdBy: string;
      archivedAt: Date | null;
      createdAt: Date;
      updatedAt: Date;
    }
  >();
  const installations = new Map<string, PublicGitHubInstallation & { isActive: boolean }>();
  const connections = new Map<string, StoredConnection>();
  const auditLogs: Array<{
    organizationId: string;
    projectId: string | null;
    actorUserId: string | null;
    action: IntegrationAuditAction;
    githubInstallationId: number | null;
    githubRepositoryId: number | null;
    metadata: Record<string, unknown>;
    createdAt: Date;
  }> = [];

  const authStore: AuthStore = {
    async createUser(input) {
      const normalized = normalizeEmail(input.email);
      for (const existing of users.values()) {
        if (existing.email === normalized) {
          throw new Error('Duplicate email');
        }
      }
      const id = makeObjectId(idCounter++);
      const ts = nowRef.current;
      const user = {
        id,
        email: normalized,
        displayName: input.displayName,
        passwordHash: input.passwordHash,
        status: input.status,
        createdAt: ts,
        updatedAt: ts,
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

  const organizationStore: OrganizationStore = {
    async withTransaction(work) {
      return work({});
    },
    async acquireOrganizationLock(organizationId) {
      const org = orgs.get(organizationId);
      if (!org) {
        return false;
      }
      org.membershipVersion += 1;
      return true;
    },
    async createOrganization(input) {
      const id = makeObjectId(idCounter++);
      const ts = nowRef.current;
      const org = {
        id,
        name: input.name,
        slug: normalizeSlug(input.slug),
        createdBy: input.createdBy,
        membershipVersion: 0,
        createdAt: ts,
        updatedAt: ts,
      };
      orgs.set(id, org);
      return { ...org };
    },
    async findOrganizationById(organizationId) {
      const org = orgs.get(organizationId);
      return org ? { ...org } : null;
    },
    async updateOrganizationById(organizationId, updates) {
      const org = orgs.get(organizationId);
      if (!org) {
        return null;
      }
      if (updates.name !== undefined) org.name = updates.name;
      if (updates.slug !== undefined) org.slug = normalizeSlug(updates.slug);
      return { ...org };
    },
    async deleteOrganizationById(organizationId) {
      return orgs.delete(organizationId);
    },
    async hasProjectsInOrganization(organizationId) {
      return Array.from(projects.values()).some((p) => p.organizationId === organizationId);
    },
    async listActiveOrganizationsForUser(userId) {
      return Array.from(memberships.values())
        .filter((m) => m.userId === userId && m.status === MembershipStatusValue.ACTIVE)
        .map((m) => ({ ...orgs.get(m.organizationId)!, role: m.role }));
    },
    async createMembership(input) {
      const id = makeObjectId(idCounter++);
      const ts = nowRef.current;
      const membership = {
        id,
        userId: input.userId,
        organizationId: input.organizationId,
        role: input.role,
        status: input.status,
        createdAt: ts,
        updatedAt: ts,
      };
      memberships.set(id, membership);
      return { ...membership };
    },
    async findActiveMembership(organizationId, userId) {
      for (const m of memberships.values()) {
        if (
          m.organizationId === organizationId &&
          m.userId === userId &&
          m.status === MembershipStatusValue.ACTIVE
        ) {
          return { ...m };
        }
      }
      return null;
    },
    async findMembershipByIdInOrganization(organizationId, membershipId) {
      const m = memberships.get(membershipId);
      return m && m.organizationId === organizationId ? { ...m } : null;
    },
    async findMembershipByOrgAndUser(organizationId, userId) {
      for (const m of memberships.values()) {
        if (m.organizationId === organizationId && m.userId === userId) {
          return { ...m };
        }
      }
      return null;
    },
    async listMembersInOrganization(organizationId) {
      return Array.from(memberships.values())
        .filter((m) => m.organizationId === organizationId)
        .map((m) => {
          const user = users.get(m.userId)!;
          return {
            ...m,
            user: { id: user.id, email: user.email, displayName: user.displayName },
          };
        });
    },
    async updateMembershipByIdInOrganization(organizationId, membershipId, updates) {
      const m = memberships.get(membershipId);
      if (!m || m.organizationId !== organizationId) {
        return null;
      }
      if (updates.role !== undefined) m.role = updates.role;
      if (updates.status !== undefined) m.status = updates.status;
      return { ...m };
    },
    async deleteMembershipByIdInOrganization(organizationId, membershipId) {
      const m = memberships.get(membershipId);
      if (!m || m.organizationId !== organizationId) {
        return false;
      }
      return memberships.delete(membershipId);
    },
    async deleteAllMembershipsInOrganization(organizationId) {
      for (const [id, m] of memberships.entries()) {
        if (m.organizationId === organizationId) {
          memberships.delete(id);
        }
      }
    },
    async countActiveOwnersExcluding(organizationId, excludedMembershipId) {
      let count = 0;
      for (const m of memberships.values()) {
        if (
          m.organizationId === organizationId &&
          m.id !== excludedMembershipId &&
          m.role === OrganizationRoleValue.OWNER &&
          m.status === MembershipStatusValue.ACTIVE
        ) {
          count += 1;
        }
      }
      return count;
    },
    async countActiveOwners(organizationId) {
      let count = 0;
      for (const m of memberships.values()) {
        if (
          m.organizationId === organizationId &&
          m.role === OrganizationRoleValue.OWNER &&
          m.status === MembershipStatusValue.ACTIVE
        ) {
          count += 1;
        }
      }
      return count;
    },
    async findUserByEmail(email) {
      const normalized = normalizeEmail(email);
      return Array.from(users.values()).find((u) => u.email === normalized) ?? null;
    },
    async findUserById(userId) {
      return users.get(userId) ?? null;
    },
  };

  const projectStore: ProjectStore = {
    async withTransaction(work) {
      return work({});
    },
    async acquireOrganizationLock(organizationId) {
      return organizationStore.acquireOrganizationLock(organizationId, {});
    },
    async findActiveMembership(organizationId, userId) {
      return organizationStore.findActiveMembership(organizationId, userId);
    },
    async createProject(input) {
      const id = makeObjectId(idCounter++);
      const ts = nowRef.current;
      const project = {
        id,
        organizationId: input.organizationId,
        name: input.name,
        slug: normalizeSlug(input.slug),
        description: input.description ?? null,
        createdBy: input.createdBy,
        archivedAt: null,
        createdAt: ts,
        updatedAt: ts,
      };
      projects.set(id, project);
      return { ...project };
    },
    async findProjectByIdInOrganization(organizationId, projectId) {
      const p = projects.get(projectId);
      if (!p || p.organizationId !== organizationId) {
        return null;
      }
      return { ...p };
    },
    async listProjectsInOrganization(organizationId) {
      const rows = Array.from(projects.values()).filter((p) => p.organizationId === organizationId);
      return { projects: rows, total: rows.length };
    },
    async updateProjectByIdInOrganization(organizationId, projectId, updates) {
      const p = projects.get(projectId);
      if (!p || p.organizationId !== organizationId) {
        return null;
      }
      if (updates.name !== undefined) {
        p.name = updates.name;
      }
      if (updates.slug !== undefined) {
        p.slug = normalizeSlug(updates.slug);
      }
      if (updates.description !== undefined) {
        p.description = updates.description;
      }
      return { ...p };
    },
    async setProjectArchivedAtInOrganization(organizationId, projectId, archivedAt) {
      const p = projects.get(projectId);
      if (!p || p.organizationId !== organizationId) {
        return null;
      }
      p.archivedAt = archivedAt;
      return { ...p };
    },
  };

  const connectionStore: GitHubRepositoryConnectionStore = {
    async withTransaction(work) {
      return work({});
    },
    async acquireOrganizationLock(organizationId) {
      return organizationStore.acquireOrganizationLock(organizationId, {});
    },
    async findActiveMembership(organizationId, userId) {
      return organizationStore.findActiveMembership(organizationId, userId);
    },
    async findProjectByIdInOrganization(organizationId, projectId) {
      const p = projects.get(projectId);
      if (!p || p.organizationId !== organizationId) {
        return null;
      }
      return { id: p.id, organizationId: p.organizationId, archivedAt: p.archivedAt };
    },
    async findInstallationByIdInOrganization(organizationId, installationRecordId) {
      const inst = installations.get(installationRecordId);
      if (!inst || inst.organizationId !== organizationId) {
        return null;
      }
      return { ...inst };
    },
    async updateInstallationStatusInOrganization(organizationId, installationRecordId, updates) {
      const inst = installations.get(installationRecordId);
      if (!inst || inst.organizationId !== organizationId) {
        return null;
      }
      inst.status = updates.status;
      inst.isActive = updates.isActive;
      inst.suspendedAt = updates.suspendedAt;
      inst.revokedAt = updates.revokedAt;
      inst.lastSyncedAt = updates.lastSyncedAt;
      inst.updatedAt = nowRef.current;
      return { ...inst };
    },
    async findActiveConnectionByProjectId(organizationId, projectId) {
      for (const conn of connections.values()) {
        if (
          conn.organizationId === organizationId &&
          conn.projectId === projectId &&
          conn.isActive
        ) {
          return { ...conn };
        }
      }
      return null;
    },
    async findActiveConnectionByOrgAndRepo(organizationId, githubRepositoryId) {
      for (const conn of connections.values()) {
        if (
          conn.organizationId === organizationId &&
          conn.githubRepositoryId === githubRepositoryId &&
          conn.isActive
        ) {
          return { ...conn };
        }
      }
      return null;
    },
    async listActiveConnectionsInOrganization(organizationId, query) {
      const matching = Array.from(connections.values())
        .filter((c) => c.organizationId === organizationId && c.isActive)
        .sort((a, b) => b.connectedAt.getTime() - a.connectedAt.getTime());
      const start = (query.page - 1) * query.perPage;
      return {
        connections: matching.slice(start, start + query.perPage).map((c) => ({ ...c })),
        total: matching.length,
      };
    },
    async createConnection(input) {
      const isActive = computeConnectionIsActive(
        input.repositoryAccessState,
        input.installationAvailability
      );
      if (isActive) {
        for (const existing of connections.values()) {
          if (existing.isActive && existing.projectId === input.projectId) {
            const err = new Error(
              'E11000 duplicate key error index: proj_repo_conn_active_project_unique'
            ) as Error & { code: number };
            err.code = 11000;
            throw err;
          }
          if (
            existing.isActive &&
            existing.organizationId === input.organizationId &&
            existing.githubRepositoryId === input.githubRepositoryId
          ) {
            const err = new Error(
              'E11000 duplicate key error index: proj_repo_conn_active_org_repo_unique'
            ) as Error & { code: number };
            err.code = 11000;
            throw err;
          }
        }
      }
      const id = makeObjectId(idCounter++);
      const ts = nowRef.current;
      const conn: StoredConnection = {
        id,
        organizationId: input.organizationId,
        projectId: input.projectId,
        installationRecordId: input.installationRecordId,
        githubInstallationId: input.githubInstallationId,
        githubRepositoryId: input.githubRepositoryId,
        ownerLogin: input.ownerLogin,
        repoName: input.repoName,
        fullName: input.fullName,
        htmlUrl: input.htmlUrl,
        defaultBranch: input.defaultBranch,
        isPrivate: input.isPrivate,
        isArchivedOnGitHub: input.isArchivedOnGitHub,
        repositoryAccessState: input.repositoryAccessState,
        installationAvailability: input.installationAvailability,
        effectiveStatus: getEffectiveConnectionStatus({
          repositoryAccessState: input.repositoryAccessState,
          installationAvailability: input.installationAvailability,
        }),
        statusReason: input.statusReason,
        isActive,
        connectedByUserId: input.connectedByUserId,
        disconnectedByUserId: null,
        connectedAt: input.connectedAt,
        disconnectedAt: null,
        lastSyncedAt: input.lastSyncedAt,
        lastWebhookAt: null,
        createdAt: ts,
        updatedAt: ts,
      };
      connections.set(id, conn);
      return { ...conn };
    },
    async updateConnectionByIdInOrganization(organizationId, connectionId, updates) {
      const conn = connections.get(connectionId);
      if (!conn || conn.organizationId !== organizationId) {
        return null;
      }
      if (updates.ownerLogin !== undefined) conn.ownerLogin = updates.ownerLogin;
      if (updates.repoName !== undefined) conn.repoName = updates.repoName;
      if (updates.fullName !== undefined) conn.fullName = updates.fullName;
      if (updates.htmlUrl !== undefined) conn.htmlUrl = updates.htmlUrl;
      if (updates.defaultBranch !== undefined) conn.defaultBranch = updates.defaultBranch;
      if (updates.isPrivate !== undefined) conn.isPrivate = updates.isPrivate;
      if (updates.isArchivedOnGitHub !== undefined) {
        conn.isArchivedOnGitHub = updates.isArchivedOnGitHub;
      }
      if (updates.disconnectedByUserId !== undefined) {
        conn.disconnectedByUserId = updates.disconnectedByUserId;
      }
      if (updates.disconnectedAt !== undefined) {
        conn.disconnectedAt = updates.disconnectedAt;
      }
      conn.repositoryAccessState = updates.repositoryAccessState;
      conn.installationAvailability = updates.installationAvailability;
      conn.effectiveStatus = getEffectiveConnectionStatus({
        repositoryAccessState: updates.repositoryAccessState,
        installationAvailability: updates.installationAvailability,
      });
      conn.statusReason = updates.statusReason;
      conn.isActive = computeConnectionIsActive(
        updates.repositoryAccessState,
        updates.installationAvailability
      );
      conn.lastSyncedAt = updates.lastSyncedAt;
      conn.updatedAt = nowRef.current;
      return { ...conn };
    },
    async createAuditLog(input) {
      auditLogs.push({
        organizationId: input.organizationId,
        projectId: input.projectId ?? null,
        actorUserId: input.actorUserId ?? null,
        action: input.action,
        githubInstallationId: input.githubInstallationId ?? null,
        githubRepositoryId: input.githubRepositoryId ?? null,
        metadata: input.metadata ?? {},
        createdAt: nowRef.current,
      });
    },
  };

  const jwtService = createJwtService(TEST_AUTH_CONFIG);
  const passwordService = createPasswordService();
  const authService = createAuthService({
    store: authStore,
    jwtService,
    passwordService,
    config: TEST_AUTH_CONFIG,
    now: () => nowRef.current,
  });
  const organizationService = createOrganizationService({
    store: organizationStore,
    now: () => nowRef.current,
  });
  const projectService = createProjectService({
    store: projectStore,
    now: () => nowRef.current,
  });

  const resolvedGitHubConfig =
    options.githubConfig === undefined ? TEST_GITHUB_CONFIG : options.githubConfig;
  const githubClient = resolvedGitHubConfig
    ? createGitHubClient({
        config: resolvedGitHubConfig,
        fetchImpl: options.fetchImpl,
        now: () => nowRef.current,
      })
    : undefined;

  const githubService = createGitHubService({
    config: resolvedGitHubConfig,
    githubClient,
    now: () => nowRef.current,
  });
  const repositoryConnectionService = createGitHubRepositoryConnectionService({
    config: resolvedGitHubConfig,
    githubClient,
    store: connectionStore,
    now: () => nowRef.current,
  });

  const app = createApp({
    auth: { authService, config: TEST_AUTH_CONFIG },
    organizations: {
      organizationService,
      projectService,
      githubService,
      repositoryConnectionService,
      githubConfig: resolvedGitHubConfig,
      authService,
      authConfig: TEST_AUTH_CONFIG,
    },
  });

  function seedInstallation(input: {
    organizationId: string;
    githubInstallationId: number;
    accountLogin?: string;
    repositorySelection?: 'all' | 'selected';
    status?: GitHubInstallationStatus;
    suspendedAt?: Date | null;
    revokedAt?: Date | null;
  }) {
    const id = makeObjectId(idCounter++);
    const ts = nowRef.current;
    const status = input.status ?? GitHubInstallationStatusValue.ACTIVE;
    const inst = {
      id,
      organizationId: input.organizationId,
      githubInstallationId: input.githubInstallationId,
      githubAppId: TEST_GITHUB_CONFIG.appId,
      accountId: 5000 + input.githubInstallationId,
      accountLogin: input.accountLogin ?? 'acme-security',
      accountType: 'Organization' as const,
      repositorySelection: input.repositorySelection ?? ('selected' as const),
      grantedPermissions: { contents: 'read', metadata: 'read' },
      status,
      isActive: status === GitHubInstallationStatusValue.ACTIVE,
      suspendedAt: input.suspendedAt ?? null,
      revokedAt: input.revokedAt ?? null,
      lastSyncedAt: ts,
      createdAt: ts,
      updatedAt: ts,
    };
    installations.set(id, inst);
    return inst;
  }

  return {
    app,
    users,
    orgs,
    memberships,
    projects,
    installations,
    connections,
    auditLogs,
    seedInstallation,
    seedConnection: (input: {
      id?: string;
      organizationId: string;
      projectId: string;
      installationRecordId: string;
      githubInstallationId: number;
      githubRepositoryId: number;
      fullName?: string;
      repositoryAccessState?: RepositoryAccessState;
      installationAvailability?: InstallationAvailability;
      statusReason?: string | null;
    }) => {
      const fullName = input.fullName ?? 'acme-security/existing-repo';
      const [ownerLogin, repoName] = fullName.split('/');
      const id = input.id ?? makeObjectId(idCounter++);
      const ts = nowRef.current;
      const repositoryAccessState =
        input.repositoryAccessState ?? RepositoryAccessStateValue.CONNECTED;
      const installationAvailability =
        input.installationAvailability ?? InstallationAvailabilityValue.ACTIVE;
      const conn: StoredConnection = {
        id,
        organizationId: input.organizationId,
        projectId: input.projectId,
        installationRecordId: input.installationRecordId,
        githubInstallationId: input.githubInstallationId,
        githubRepositoryId: input.githubRepositoryId,
        ownerLogin: ownerLogin!,
        repoName: repoName!,
        fullName,
        htmlUrl: `https://github.com/${fullName}`,
        defaultBranch: 'main',
        isPrivate: true,
        isArchivedOnGitHub: false,
        repositoryAccessState,
        installationAvailability,
        effectiveStatus: getEffectiveConnectionStatus({
          repositoryAccessState,
          installationAvailability,
        }),
        statusReason: input.statusReason ?? null,
        isActive: computeConnectionIsActive(repositoryAccessState, installationAvailability),
        connectedByUserId: makeObjectId(9999),
        disconnectedByUserId: null,
        connectedAt: ts,
        disconnectedAt: null,
        lastSyncedAt: ts,
        lastWebhookAt: null,
        createdAt: ts,
        updatedAt: ts,
      };
      connections.set(id, conn);
      return conn;
    },
  };
}

async function registerAndLogin(
  app: ReturnType<typeof createApp>,
  email: string,
  displayName = 'Test User'
) {
  await request(app).post('/api/v1/auth/register').send({
    email,
    displayName,
    password: 'StrongPassword123!',
  });
  const res = await request(app).post('/api/v1/auth/login').send({
    email,
    password: 'StrongPassword123!',
  });
  return {
    userId: res.body.user.id as string,
    token: res.body.accessToken as string,
  };
}

async function createOrgAndProject(
  app: ReturnType<typeof createApp>,
  token: string,
  orgName: string,
  projectName: string
) {
  const orgRes = await request(app)
    .post('/api/v1/organizations')
    .set('Authorization', `Bearer ${token}`)
    .send({ name: orgName, slug: orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-') });
  const organizationId = orgRes.body.organization.id as string;

  const projectRes = await request(app)
    .post(`/api/v1/organizations/${organizationId}/projects`)
    .set('Authorization', `Bearer ${token}`)
    .send({ name: projectName, slug: projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-') });
  const projectId = projectRes.body.project.id as string;

  return { organizationId, projectId };
}

function makeGitHubRepoPayload(
  id: number,
  fullName = 'acme-security/web-api',
  overrides: Partial<{
    default_branch: string;
    private: boolean;
    archived: boolean;
    html_url: string;
  }> = {}
) {
  const [ownerLogin, name] = fullName.split('/');
  return {
    id,
    name: name!,
    full_name: fullName,
    owner: { login: ownerLogin! },
    default_branch: overrides.default_branch ?? 'main',
    private: overrides.private ?? true,
    archived: overrides.archived ?? false,
    html_url: overrides.html_url ?? `https://github.com/${fullName}`,
  };
}

describe('Project-to-GitHub Repository Connection & Sync API', () => {
  it('connects an authorized installation repository to a project, fetches metadata authoritatively, audits without leaking tokens, and lists connections', async () => {
    const secretToken = 'ghs_super_secret_iat_must_not_leak_999';
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: null,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: secretToken,
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url.startsWith('https://api.github.com/installation/repositories')) {
        return new Response(
          JSON.stringify({
            total_count: 1,
            repositories: [
              makeGitHubRepoPayload(40001, 'acme-security/core-backend', {
                default_branch: 'develop',
                private: true,
              }),
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'conn-owner@test.dev');
    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'Acme Sec',
      'Core API'
    );
    const installation = harness.seedInstallation({
      organizationId,
      githubInstallationId: 1001,
    });

    const connectRes = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({
        installationRecordId: installation.id,
        githubRepositoryId: 40001,
      });

    expect(connectRes.status).toBe(201);
    expect(connectRes.body.connection).toMatchObject({
      organizationId,
      projectId,
      installationRecordId: installation.id,
      githubInstallationId: 1001,
      githubRepositoryId: 40001,
      ownerLogin: 'acme-security',
      repoName: 'core-backend',
      fullName: 'acme-security/core-backend',
      htmlUrl: 'https://github.com/acme-security/core-backend',
      defaultBranch: 'develop',
      isPrivate: true,
      isArchivedOnGitHub: false,
      repositoryAccessState: 'CONNECTED',
      installationAvailability: 'ACTIVE',
      effectiveStatus: 'CONNECTED',
      isActive: true,
      connectedByUserId: owner.userId,
    });
    expect(JSON.stringify(connectRes.body)).not.toContain(secretToken);

    const getRes = await request(harness.app)
      .get(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.connection.githubRepositoryId).toBe(40001);

    const listRes = await request(harness.app)
      .get(`/api/v1/organizations/${organizationId}/github/connections?page=1&perPage=10`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.connections).toHaveLength(1);
    expect(listRes.body.pagination).toEqual({
      page: 1,
      perPage: 10,
      total: 1,
      totalPages: 1,
    });

    expect(harness.auditLogs).toHaveLength(1);
    expect(harness.auditLogs[0]).toMatchObject({
      organizationId,
      projectId,
      actorUserId: owner.userId,
      action: IntegrationAuditActionValue.REPOSITORY_CONNECTED,
      githubInstallationId: 1001,
      githubRepositoryId: 40001,
    });
  });

  it('rejects strict forged metadata fields, archived projects, cross-org resources, and non-members', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: null,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: 'ghs_tok_unused',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ total_count: 0, repositories: [] }), { status: 200 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const ownerA = await registerAndLogin(harness.app, 'owner-a@test.dev');
    const ownerB = await registerAndLogin(harness.app, 'owner-b@test.dev');
    const orgA = await createOrgAndProject(harness.app, ownerA.token, 'Org A', 'Project A');
    const orgB = await createOrgAndProject(harness.app, ownerB.token, 'Org B', 'Project B');
    const instA = harness.seedInstallation({
      organizationId: orgA.organizationId,
      githubInstallationId: 1001,
    });
    const instB = harness.seedInstallation({
      organizationId: orgB.organizationId,
      githubInstallationId: 2002,
    });

    // Reject extra/forged metadata in body (.strict)
    const forgedRes = await request(harness.app)
      .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/github`)
      .set('Authorization', `Bearer ${ownerA.token}`)
      .send({
        installationRecordId: instA.id,
        githubRepositoryId: 40001,
        fullName: 'attacker/spoofed',
      });
    expect(forgedRes.status).toBe(400);

    // Reject cross-org installation reference (404, no GitHub API call)
    const crossInstRes = await request(harness.app)
      .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/github`)
      .set('Authorization', `Bearer ${ownerA.token}`)
      .send({
        installationRecordId: instB.id,
        githubRepositoryId: 40001,
      });
    expect(crossInstRes.status).toBe(404);
    expect(crossInstRes.body.error.code).toBe('GITHUB_INSTALLATION_NOT_FOUND');
    expect(fetchMock).not.toHaveBeenCalled();

    // Reject cross-org project reference
    const crossProjRes = await request(harness.app)
      .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgB.projectId}/github`)
      .set('Authorization', `Bearer ${ownerA.token}`)
      .send({
        installationRecordId: instA.id,
        githubRepositoryId: 40001,
      });
    expect(crossProjRes.status).toBe(404);
    expect(crossProjRes.body.error.code).toBe('PROJECT_NOT_FOUND');

    // Non-member receives 404
    const nonMemberGet = await request(harness.app)
      .get(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/github`)
      .set('Authorization', `Bearer ${ownerB.token}`);
    expect(nonMemberGet.status).toBe(404);

    // Archived project rejects repository connection (409 PROJECT_ARCHIVED)
    await request(harness.app)
      .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/archive`)
      .set('Authorization', `Bearer ${ownerA.token}`);
    const archivedConnect = await request(harness.app)
      .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/github`)
      .set('Authorization', `Bearer ${ownerA.token}`)
      .send({
        installationRecordId: instA.id,
        githubRepositoryId: 40001,
      });
    expect(archivedConnect.status).toBe(409);
    expect(archivedConnect.body.error.code).toBe('PROJECT_ARCHIVED');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects connecting a public repository that is not granted to the selected installation', async () => {
    // Crucially simulates GitHub allowing GET /repositories/{id} on public repos while
    // omitting them from GET /installation/repositories
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: null,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: 'ghs_selected_only_token',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url.startsWith('https://api.github.com/installation/repositories')) {
        return new Response(
          JSON.stringify({
            total_count: 1,
            repositories: [makeGitHubRepoPayload(11111, 'acme-security/allowed-repo')],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url === 'https://api.github.com/repositories/99999') {
        return new Response(
          JSON.stringify(
            makeGitHubRepoPayload(99999, 'other-org/public-ungranted', { private: false })
          ),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'pubcheck@test.dev');
    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'Acme',
      'Web App'
    );
    const installation = harness.seedInstallation({
      organizationId,
      githubInstallationId: 1001,
    });

    const res = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({
        installationRecordId: installation.id,
        githubRepositoryId: 99999,
      });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('GITHUB_REPOSITORY_NOT_ACCESSIBLE');
    expect(harness.connections.size).toBe(0);
  });

  it('enforces RBAC: MEMBER and VIEWER cannot mutate connections or list org integrations, but can read project connection', async () => {
    const harness = createConnectionsHarness();
    const owner = await registerAndLogin(harness.app, 'rbac-owner@test.dev');
    const admin = await registerAndLogin(harness.app, 'rbac-admin@test.dev');
    const member = await registerAndLogin(harness.app, 'rbac-member@test.dev');
    const viewer = await registerAndLogin(harness.app, 'rbac-viewer@test.dev');

    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'RBAC Org',
      'RBAC Project'
    );

    await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/members`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ email: 'rbac-admin@test.dev', role: 'ADMIN' });
    await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/members`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ email: 'rbac-member@test.dev', role: 'MEMBER' });
    await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/members`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ email: 'rbac-viewer@test.dev', role: 'VIEWER' });

    const inst = harness.seedInstallation({ organizationId, githubInstallationId: 1001 });
    harness.seedConnection({
      organizationId,
      projectId,
      installationRecordId: inst.id,
      githubInstallationId: 1001,
      githubRepositoryId: 40001,
    });

    for (const actorToken of [member.token, viewer.token]) {
      expect(
        (
          await request(harness.app)
            .get(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
            .set('Authorization', `Bearer ${actorToken}`)
        ).status
      ).toBe(200);

      expect(
        (
          await request(harness.app)
            .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
            .set('Authorization', `Bearer ${actorToken}`)
            .send({ installationRecordId: inst.id, githubRepositoryId: 40001 })
        ).status
      ).toBe(403);

      expect(
        (
          await request(harness.app)
            .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
            .set('Authorization', `Bearer ${actorToken}`)
        ).status
      ).toBe(403);

      expect(
        (
          await request(harness.app)
            .delete(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
            .set('Authorization', `Bearer ${actorToken}`)
        ).status
      ).toBe(403);

      expect(
        (
          await request(harness.app)
            .get(`/api/v1/organizations/${organizationId}/github/connections`)
            .set('Authorization', `Bearer ${actorToken}`)
        ).status
      ).toBe(403);
    }

    const adminList = await request(harness.app)
      .get(`/api/v1/organizations/${organizationId}/github/connections`)
      .set('Authorization', `Bearer ${admin.token}`);
    expect(adminList.status).toBe(200);
    expect(adminList.body.connections).toHaveLength(1);
  });

  it('handles duplicate project/repository conflicts (409) and idempotent reconnect (200)', async () => {
    let currentBranch = 'main';
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: null,
          }),
          { status: 200 }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: 'ghs_tok',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201 }
        );
      }
      if (url.startsWith('https://api.github.com/installation/repositories')) {
        return new Response(
          JSON.stringify({
            total_count: 2,
            repositories: [
              makeGitHubRepoPayload(40001, 'acme-security/repo-one', {
                default_branch: currentBranch,
              }),
              makeGitHubRepoPayload(40002, 'acme-security/repo-two'),
            ],
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'dup@test.dev');
    const p1 = await createOrgAndProject(harness.app, owner.token, 'Dup Org', 'Project One');
    const p2Res = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ name: 'Project Two', slug: 'project-two' });
    const projectTwoId = p2Res.body.project.id as string;

    const inst1 = harness.seedInstallation({
      organizationId: p1.organizationId,
      githubInstallationId: 1001,
    });
    const inst2 = harness.seedInstallation({
      organizationId: p1.organizationId,
      githubInstallationId: 1002,
    });

    // First connect succeeds with 201
    const first = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects/${p1.projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst1.id, githubRepositoryId: 40001 });
    expect(first.status).toBe(201);

    // Different repo on already connected project -> 409 PROJECT_ALREADY_CONNECTED
    const diffRepo = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects/${p1.projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst1.id, githubRepositoryId: 40002 });
    expect(diffRepo.status).toBe(409);
    expect(diffRepo.body.error.code).toBe('PROJECT_ALREADY_CONNECTED');

    // Different installation for same project -> 409 PROJECT_ALREADY_CONNECTED
    const diffInst = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects/${p1.projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst2.id, githubRepositoryId: 40001 });
    expect(diffInst.status).toBe(409);
    expect(diffInst.body.error.code).toBe('PROJECT_ALREADY_CONNECTED');

    // Same repo connected to second active project in same org -> 409 REPOSITORY_ALREADY_CONNECTED
    const dupRepo = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects/${projectTwoId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst1.id, githubRepositoryId: 40001 });
    expect(dupRepo.status).toBe(409);
    expect(dupRepo.body.error.code).toBe('REPOSITORY_ALREADY_CONNECTED');

    // Idempotent same repo + same installation -> 200 and refreshes metadata
    currentBranch = 'release';
    const idempotent = await request(harness.app)
      .post(`/api/v1/organizations/${p1.organizationId}/projects/${p1.projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst1.id, githubRepositoryId: 40001 });
    expect(idempotent.status).toBe(200);
    expect(idempotent.body.connection.defaultBranch).toBe('release');
  });

  it('syncs metadata changes, tracks suspension/unsuspension orthogonally without restoring revoked or deleted states, and handles 403/404/410 safely', async () => {
    let installationSuspended: string | null = null;
    let installationFound = true;
    let probeStatus: 200 | 403 | 404 | 410 = 200;
    let repoFullName = 'acme-security/app-v1';
    let repoDefaultBranch = 'main';
    let includeInSelectedList = true;

    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        if (!installationFound) {
          return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
        }
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: installationSuspended,
          }),
          { status: 200 }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: 'ghs_sync_tok',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201 }
        );
      }
      if (url === 'https://api.github.com/repositories/40001') {
        if (probeStatus === 200) {
          return new Response(
            JSON.stringify(
              makeGitHubRepoPayload(40001, repoFullName, {
                default_branch: repoDefaultBranch,
                archived: true,
              })
            ),
            { status: 200 }
          );
        }
        return new Response(JSON.stringify({ message: 'err' }), { status: probeStatus });
      }
      if (url.startsWith('https://api.github.com/installation/repositories')) {
        return new Response(
          JSON.stringify({
            total_count: includeInSelectedList ? 1 : 0,
            repositories: includeInSelectedList
              ? [
                  makeGitHubRepoPayload(40001, repoFullName, {
                    default_branch: repoDefaultBranch,
                    archived: true,
                  }),
                ]
              : [],
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'sync-owner@test.dev');
    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'Sync Org',
      'Sync Project'
    );
    const inst = harness.seedInstallation({
      organizationId,
      githubInstallationId: 1001,
    });
    const seededConn = harness.seedConnection({
      organizationId,
      projectId,
      installationRecordId: inst.id,
      githubInstallationId: 1001,
      githubRepositoryId: 40001,
      fullName: 'acme-security/app-v0',
    });

    // 1. Metadata update (rename, defaultBranch, archived flag)
    repoFullName = 'acme-renamed/app-v2';
    repoDefaultBranch = 'production';
    const metaSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(metaSync.status).toBe(200);
    expect(metaSync.body.connection).toMatchObject({
      ownerLogin: 'acme-renamed',
      repoName: 'app-v2',
      fullName: 'acme-renamed/app-v2',
      htmlUrl: 'https://github.com/acme-renamed/app-v2',
      defaultBranch: 'production',
      isArchivedOnGitHub: true,
      effectiveStatus: 'CONNECTED',
    });

    // 2. Installation suspended -> INSTALLATION_SUSPENDED
    installationSuspended = '2026-11-27T10:00:00Z';
    const suspendSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(suspendSync.status).toBe(200);
    expect(suspendSync.body.connection).toMatchObject({
      repositoryAccessState: 'CONNECTED',
      installationAvailability: 'SUSPENDED',
      effectiveStatus: 'INSTALLATION_SUSPENDED',
      isActive: true,
    });

    // 3. Installation unsuspended while repositoryAccessState is CONNECTED -> CONNECTED
    installationSuspended = null;
    const unsuspendSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(unsuspendSync.status).toBe(200);
    expect(unsuspendSync.body.connection.effectiveStatus).toBe('CONNECTED');

    // 4. Ambiguous 404 from GitHub marks ACCESS_REVOKED (not falsely REPO_DELETED)
    probeStatus = 404;
    const notFoundSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(notFoundSync.status).toBe(200);
    expect(notFoundSync.body.connection).toMatchObject({
      repositoryAccessState: 'ACCESS_REVOKED',
      effectiveStatus: 'ACCESS_REVOKED',
      isActive: true,
    });
    expect(notFoundSync.body.connection.statusReason).toContain('404');

    // 5. Critical invariant: installation suspend -> unsuspend does NOT restore ACCESS_REVOKED!
    installationSuspended = '2026-11-27T11:00:00Z';
    await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    installationSuspended = null;
    probeStatus = 200;
    const afterUnsuspendRevoked = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(afterUnsuspendRevoked.status).toBe(200);
    expect(afterUnsuspendRevoked.body.connection).toMatchObject({
      repositoryAccessState: 'ACCESS_REVOKED',
      installationAvailability: 'ACTIVE',
      effectiveStatus: 'ACCESS_REVOKED',
    });

    // 6. Selected-repo removal catches revoked public repo & 410 Gone marks REPO_DELETED permanently
    const connInMap = harness.connections.get(seededConn.id)!;
    connInMap.repositoryAccessState = RepositoryAccessStateValue.CONNECTED;
    connInMap.effectiveStatus = 'CONNECTED';
    includeInSelectedList = false;
    const removedSelected = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(removedSelected.status).toBe(200);
    expect(removedSelected.body.connection.repositoryAccessState).toBe('ACCESS_REVOKED');

    connInMap.repositoryAccessState = RepositoryAccessStateValue.CONNECTED;
    connInMap.effectiveStatus = 'CONNECTED';
    includeInSelectedList = true;
    probeStatus = 410;
    const goneSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(goneSync.status).toBe(200);
    expect(goneSync.body.connection.effectiveStatus).toBe('REPO_DELETED');

    // Installation revocation on REPO_DELETED keeps repositoryAccessState=REPO_DELETED while updating installationAvailability=REVOKED
    installationFound = false;
    const revokedInstallSync = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(revokedInstallSync.status).toBe(200);
    expect(revokedInstallSync.body.connection).toMatchObject({
      repositoryAccessState: 'REPO_DELETED',
      installationAvailability: 'REVOKED',
      effectiveStatus: 'REPO_DELETED',
    });
  });

  it('disconnects cleanly while preserving historical record and installation, and allows reconnection afterwards', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === 'https://api.github.com/app/installations/1001') {
        return new Response(
          JSON.stringify({
            id: 1001,
            app_id: TEST_GITHUB_CONFIG.appId,
            account: { id: 55, login: 'acme-security', type: 'Organization' },
            repository_selection: 'selected',
            permissions: { contents: 'read' },
            suspended_at: null,
          }),
          { status: 200 }
        );
      }
      if (url === 'https://api.github.com/app/installations/1001/access_tokens') {
        return new Response(
          JSON.stringify({
            token: 'ghs_reconn_tok',
            expires_at: new Date(Date.now() + 3600_000).toISOString(),
          }),
          { status: 201 }
        );
      }
      if (url.startsWith('https://api.github.com/installation/repositories')) {
        return new Response(
          JSON.stringify({
            total_count: 1,
            repositories: [makeGitHubRepoPayload(40001, 'acme-security/reconn-repo')],
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'disc@test.dev');
    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'Disc Org',
      'Disc Project'
    );
    const inst = harness.seedInstallation({ organizationId, githubInstallationId: 1001 });
    const firstConn = harness.seedConnection({
      organizationId,
      projectId,
      installationRecordId: inst.id,
      githubInstallationId: 1001,
      githubRepositoryId: 40001,
    });

    const discRes = await request(harness.app)
      .delete(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(discRes.status).toBe(200);
    expect(discRes.body.connection).toMatchObject({
      id: firstConn.id,
      repositoryAccessState: 'DISCONNECTED',
      effectiveStatus: 'DISCONNECTED',
      isActive: false,
      disconnectedByUserId: owner.userId,
    });
    expect(discRes.body.connection.disconnectedAt).toBeTruthy();

    // Parent installation stays untouched & active
    expect(harness.installations.get(inst.id)?.status).toBe('ACTIVE');

    // Subsequent GET reports 404 REPOSITORY_NOT_CONNECTED
    const getAfter = await request(harness.app)
      .get(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`);
    expect(getAfter.status).toBe(404);
    expect(getAfter.body.error.code).toBe('REPOSITORY_NOT_CONNECTED');

    // Can reconnect cleanly with 201 and creates a new active history record
    const reconnRes = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst.id, githubRepositoryId: 40001 });
    expect(reconnRes.status).toBe(201);
    expect(reconnRes.body.connection.id).not.toBe(firstConn.id);
    expect(harness.connections.size).toBe(2);
    expect(harness.auditLogs.map((a) => a.action)).toEqual([
      IntegrationAuditActionValue.REPOSITORY_DISCONNECTED,
      IntegrationAuditActionValue.REPOSITORY_CONNECTED,
    ]);
  });

  it('surfaces upstream GitHub rate limits without corrupting state', async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ message: 'API rate limit exceeded' }), {
        status: 429,
        headers: { 'retry-after': '45', 'content-type': 'application/json' },
      });
    });

    const harness = createConnectionsHarness({ fetchImpl: fetchMock as unknown as typeof fetch });
    const owner = await registerAndLogin(harness.app, 'ratelimit@test.dev');
    const { organizationId, projectId } = await createOrgAndProject(
      harness.app,
      owner.token,
      'Rate Org',
      'Rate Project'
    );
    const inst = harness.seedInstallation({ organizationId, githubInstallationId: 1001 });

    const res = await request(harness.app)
      .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ installationRecordId: inst.id, githubRepositoryId: 40001 });

    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe('GITHUB_RATE_LIMITED');
    expect(harness.connections.size).toBe(0);
    expect(harness.auditLogs).toHaveLength(0);
  });
});
