import type { ClientSession } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  computeConnectionIsActive,
  getEffectiveConnectionStatus,
  GitHubInstallationModel,
  IntegrationAuditActionValue,
  IntegrationAuditActorTypeValue,
  IntegrationAuditLogModel,
  isValidObjectId,
  MembershipStatusValue,
  OrganizationMembershipModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  runInTransaction,
  type GitHubAccountType,
  type GitHubInstallationStatus,
  type GitHubRepositorySelection,
  type InstallationAvailability,
  type IntegrationAuditAction,
  type RepositoryAccessState,
} from '@vibeshield/database';
import type { AuthorizedOrganizationMembership } from '../organizations/organization.types.js';
import type { PublicGitHubInstallation } from './github.types.js';
import type {
  ListOrganizationConnectionsQuery,
  PublicProjectRepositoryConnection,
} from './github-connection.types.js';

export type GitHubConnectionTransactionContext = ClientSession | unknown;

export interface ConnectionProjectSummary {
  id: string;
  organizationId: string;
  archivedAt: Date | null;
}

export interface GitHubRepositoryConnectionStore {
  withTransaction<T>(work: (tx: GitHubConnectionTransactionContext) => Promise<T>): Promise<T>;
  acquireOrganizationLock(
    organizationId: string,
    tx: GitHubConnectionTransactionContext
  ): Promise<boolean>;
  findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: GitHubConnectionTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null>;
  findProjectByIdInOrganization(
    organizationId: string,
    projectId: string,
    tx?: GitHubConnectionTransactionContext
  ): Promise<ConnectionProjectSummary | null>;
  findInstallationByIdInOrganization(
    organizationId: string,
    installationRecordId: string,
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  updateInstallationStatusInOrganization(
    organizationId: string,
    installationRecordId: string,
    updates: {
      status: GitHubInstallationStatus;
      isActive: boolean;
      suspendedAt: Date | null;
      revokedAt: Date | null;
      lastSyncedAt: Date;
    },
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  findActiveConnectionByProjectId(
    organizationId: string,
    projectId: string,
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicProjectRepositoryConnection | null>;
  findActiveConnectionByOrgAndRepo(
    organizationId: string,
    githubRepositoryId: number,
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicProjectRepositoryConnection | null>;
  listActiveConnectionsInOrganization(
    organizationId: string,
    query: ListOrganizationConnectionsQuery
  ): Promise<{ connections: PublicProjectRepositoryConnection[]; total: number }>;
  createConnection(
    input: {
      organizationId: string;
      projectId: string;
      installationRecordId: string;
      githubInstallationId: number;
      githubRepositoryId: number;
      ownerLogin: string;
      repoName: string;
      fullName: string;
      htmlUrl: string;
      defaultBranch: string;
      isPrivate: boolean;
      isArchivedOnGitHub: boolean;
      repositoryAccessState: RepositoryAccessState;
      installationAvailability: InstallationAvailability;
      statusReason: string | null;
      connectedByUserId: string;
      connectedAt: Date;
      lastSyncedAt: Date;
    },
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicProjectRepositoryConnection>;
  updateConnectionByIdInOrganization(
    organizationId: string,
    connectionId: string,
    updates: {
      ownerLogin?: string;
      repoName?: string;
      fullName?: string;
      htmlUrl?: string;
      defaultBranch?: string;
      isPrivate?: boolean;
      isArchivedOnGitHub?: boolean;
      repositoryAccessState: RepositoryAccessState;
      installationAvailability: InstallationAvailability;
      statusReason: string | null;
      disconnectedByUserId?: string | null;
      disconnectedAt?: Date | null;
      lastSyncedAt: Date;
    },
    tx?: GitHubConnectionTransactionContext
  ): Promise<PublicProjectRepositoryConnection | null>;
  createAuditLog(
    input: {
      organizationId: string;
      projectId?: string | null;
      actorUserId?: string | null;
      action: IntegrationAuditAction;
      githubInstallationId?: number | null;
      githubRepositoryId?: number | null;
      metadata?: Record<string, unknown>;
    },
    tx?: GitHubConnectionTransactionContext
  ): Promise<void>;
}

function asSession(tx?: GitHubConnectionTransactionContext): ClientSession | undefined {
  return tx as ClientSession | undefined;
}

function toPublicGitHubInstallation(doc: {
  _id: { toString(): string };
  organizationId: { toString(): string };
  githubInstallationId: number;
  githubAppId: number;
  accountId: number;
  accountLogin: string;
  accountType: GitHubAccountType;
  repositorySelection: GitHubRepositorySelection;
  grantedPermissions?: Record<string, string>;
  status: GitHubInstallationStatus;
  suspendedAt: Date | null;
  revokedAt: Date | null;
  lastSyncedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}): PublicGitHubInstallation {
  return {
    id: doc._id.toString(),
    organizationId: doc.organizationId.toString(),
    githubInstallationId: doc.githubInstallationId,
    githubAppId: doc.githubAppId,
    accountId: doc.accountId,
    accountLogin: doc.accountLogin,
    accountType: doc.accountType,
    repositorySelection: doc.repositorySelection,
    grantedPermissions: doc.grantedPermissions ? { ...doc.grantedPermissions } : {},
    status: doc.status,
    suspendedAt: doc.suspendedAt ?? null,
    revokedAt: doc.revokedAt ?? null,
    lastSyncedAt: doc.lastSyncedAt,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

function toPublicProjectRepositoryConnection(doc: {
  _id: { toString(): string };
  organizationId: { toString(): string };
  projectId: { toString(): string };
  installationRecordId: { toString(): string };
  githubInstallationId: number;
  githubRepositoryId: number;
  ownerLogin: string;
  repoName: string;
  fullName: string;
  htmlUrl?: string;
  defaultBranch: string;
  isPrivate: boolean;
  isArchivedOnGitHub: boolean;
  repositoryAccessState: RepositoryAccessState;
  installationAvailability: InstallationAvailability;
  statusReason?: string | null;
  isActive: boolean;
  connectedByUserId: { toString(): string };
  disconnectedByUserId?: { toString(): string } | null;
  connectedAt: Date;
  disconnectedAt?: Date | null;
  lastSyncedAt: Date;
  lastWebhookAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}): PublicProjectRepositoryConnection {
  return {
    id: doc._id.toString(),
    organizationId: doc.organizationId.toString(),
    projectId: doc.projectId.toString(),
    installationRecordId: doc.installationRecordId.toString(),
    githubInstallationId: doc.githubInstallationId,
    githubRepositoryId: doc.githubRepositoryId,
    ownerLogin: doc.ownerLogin,
    repoName: doc.repoName,
    fullName: doc.fullName,
    htmlUrl: doc.htmlUrl ?? `https://github.com/${doc.fullName}`,
    defaultBranch: doc.defaultBranch,
    isPrivate: doc.isPrivate,
    isArchivedOnGitHub: doc.isArchivedOnGitHub,
    repositoryAccessState: doc.repositoryAccessState,
    installationAvailability: doc.installationAvailability,
    effectiveStatus: getEffectiveConnectionStatus({
      repositoryAccessState: doc.repositoryAccessState,
      installationAvailability: doc.installationAvailability,
    }),
    statusReason: doc.statusReason ?? null,
    isActive: doc.isActive,
    connectedByUserId: doc.connectedByUserId.toString(),
    disconnectedByUserId: doc.disconnectedByUserId ? doc.disconnectedByUserId.toString() : null,
    connectedAt: doc.connectedAt,
    disconnectedAt: doc.disconnectedAt ?? null,
    lastSyncedAt: doc.lastSyncedAt,
    lastWebhookAt: doc.lastWebhookAt ?? null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export const mongooseGitHubRepositoryConnectionStore: GitHubRepositoryConnectionStore = {
  async withTransaction<T>(
    work: (tx: GitHubConnectionTransactionContext) => Promise<T>
  ): Promise<T> {
    return runInTransaction(async (session) => work(session));
  },

  async acquireOrganizationLock(organizationId, tx) {
    const session = asSession(tx);
    if (!session) {
      throw new Error('Organization mutation lock requires an active MongoDB transaction session');
    }
    return acquireOrganizationMutationLock(organizationId, session);
  },

  async findActiveMembership(organizationId, userId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(userId)) {
      return null;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.findOne({
      organizationId,
      userId,
      status: MembershipStatusValue.ACTIVE,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    if (!doc) {
      return null;
    }
    return {
      id: doc._id.toString(),
      userId: doc.userId.toString(),
      organizationId: doc.organizationId.toString(),
      role: doc.role,
      status: doc.status,
    };
  },

  async findProjectByIdInOrganization(organizationId, projectId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(projectId)) {
      return null;
    }
    const session = asSession(tx);
    const query = ProjectModel.findOne({ _id: projectId, organizationId });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    if (!doc) {
      return null;
    }
    return {
      id: doc._id.toString(),
      organizationId: doc.organizationId.toString(),
      archivedAt: doc.archivedAt ?? null,
    };
  },

  async findInstallationByIdInOrganization(organizationId, installationRecordId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(installationRecordId)) {
      return null;
    }
    const session = asSession(tx);
    const query = GitHubInstallationModel.findOne({
      _id: installationRecordId,
      organizationId,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicGitHubInstallation(doc) : null;
  },

  async updateInstallationStatusInOrganization(organizationId, installationRecordId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(installationRecordId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await GitHubInstallationModel.findOneAndUpdate(
      { _id: installationRecordId, organizationId },
      {
        $set: {
          status: updates.status,
          isActive: updates.isActive,
          suspendedAt: updates.suspendedAt,
          revokedAt: updates.revokedAt,
          lastSyncedAt: updates.lastSyncedAt,
        },
      },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicGitHubInstallation(doc) : null;
  },

  async findActiveConnectionByProjectId(organizationId, projectId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(projectId)) {
      return null;
    }
    const session = asSession(tx);
    const query = ProjectRepositoryConnectionModel.findOne({
      organizationId,
      projectId,
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicProjectRepositoryConnection(doc) : null;
  },

  async findActiveConnectionByOrgAndRepo(organizationId, githubRepositoryId, tx) {
    if (!isValidObjectId(organizationId)) {
      return null;
    }
    const session = asSession(tx);
    const query = ProjectRepositoryConnectionModel.findOne({
      organizationId,
      githubRepositoryId,
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicProjectRepositoryConnection(doc) : null;
  },

  async listActiveConnectionsInOrganization(organizationId, query) {
    if (!isValidObjectId(organizationId)) {
      return { connections: [], total: 0 };
    }
    const filter = {
      organizationId,
      isActive: true,
    };
    const skip = (query.page - 1) * query.perPage;
    const [docs, total] = await Promise.all([
      ProjectRepositoryConnectionModel.find(filter)
        .sort({ connectedAt: -1, _id: -1 })
        .skip(skip)
        .limit(query.perPage),
      ProjectRepositoryConnectionModel.countDocuments(filter),
    ]);

    return {
      connections: docs.map((doc) => toPublicProjectRepositoryConnection(doc)),
      total,
    };
  },

  async createConnection(input, tx) {
    const session = asSession(tx);
    const isActive = computeConnectionIsActive(
      input.repositoryAccessState,
      input.installationAvailability
    );
    const [doc] = await ProjectRepositoryConnectionModel.create(
      [
        {
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
          statusReason: input.statusReason,
          isActive,
          connectedByUserId: input.connectedByUserId,
          disconnectedByUserId: null,
          connectedAt: input.connectedAt,
          disconnectedAt: null,
          lastSyncedAt: input.lastSyncedAt,
          lastWebhookAt: null,
        },
      ],
      session ? { session } : undefined
    );
    return toPublicProjectRepositoryConnection(doc!);
  },

  async updateConnectionByIdInOrganization(organizationId, connectionId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(connectionId)) {
      return null;
    }
    const session = asSession(tx);
    const isActive = computeConnectionIsActive(
      updates.repositoryAccessState,
      updates.installationAvailability
    );
    const setFields: Record<string, unknown> = {
      repositoryAccessState: updates.repositoryAccessState,
      installationAvailability: updates.installationAvailability,
      statusReason: updates.statusReason,
      isActive,
      lastSyncedAt: updates.lastSyncedAt,
    };
    if (updates.ownerLogin !== undefined) {
      setFields.ownerLogin = updates.ownerLogin;
    }
    if (updates.repoName !== undefined) {
      setFields.repoName = updates.repoName;
    }
    if (updates.fullName !== undefined) {
      setFields.fullName = updates.fullName;
    }
    if (updates.htmlUrl !== undefined) {
      setFields.htmlUrl = updates.htmlUrl;
    }
    if (updates.defaultBranch !== undefined) {
      setFields.defaultBranch = updates.defaultBranch;
    }
    if (updates.isPrivate !== undefined) {
      setFields.isPrivate = updates.isPrivate;
    }
    if (updates.isArchivedOnGitHub !== undefined) {
      setFields.isArchivedOnGitHub = updates.isArchivedOnGitHub;
    }
    if (updates.disconnectedByUserId !== undefined) {
      setFields.disconnectedByUserId = updates.disconnectedByUserId;
    }
    if (updates.disconnectedAt !== undefined) {
      setFields.disconnectedAt = updates.disconnectedAt;
    }

    const doc = await ProjectRepositoryConnectionModel.findOneAndUpdate(
      { _id: connectionId, organizationId },
      { $set: setFields },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicProjectRepositoryConnection(doc) : null;
  },

  async createAuditLog(input, tx) {
    const session = asSession(tx);
    await IntegrationAuditLogModel.create(
      [
        {
          organizationId: input.organizationId,
          projectId: input.projectId ?? null,
          actorType: IntegrationAuditActorTypeValue.USER,
          actorUserId: input.actorUserId ?? null,
          action: input.action ?? IntegrationAuditActionValue.REPOSITORY_CONNECTED,
          githubInstallationId: input.githubInstallationId ?? null,
          githubRepositoryId: input.githubRepositoryId ?? null,
          metadata: input.metadata ?? {},
        },
      ],
      session ? { session } : undefined
    );
  },
};
