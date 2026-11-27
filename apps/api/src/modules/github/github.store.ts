import type { ClientSession } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  GitHubOAuthStateModel,
  IntegrationAuditActionValue,
  IntegrationAuditActorTypeValue,
  IntegrationAuditLogModel,
  isValidObjectId,
  MembershipStatusValue,
  OrganizationMembershipModel,
  runInTransaction,
  type GitHubAccountType,
  type GitHubInstallationStatus,
  type GitHubRepositorySelection,
  type IntegrationAuditAction,
} from '@vibeshield/database';
import type { AuthorizedOrganizationMembership } from '../organizations/organization.types.js';
import type { PublicGitHubInstallation } from './github.types.js';

export type GitHubTransactionContext = ClientSession | unknown;

export interface UpsertGitHubInstallationInput {
  organizationId: string;
  githubInstallationId: number;
  githubAppId: number;
  accountId: number;
  accountLogin: string;
  accountType: GitHubAccountType;
  repositorySelection: GitHubRepositorySelection;
  grantedPermissions: Record<string, string>;
  status: GitHubInstallationStatus;
  isActive: boolean;
  connectedByUserId: string;
  suspendedAt: Date | null;
  revokedAt: Date | null;
  lastSyncedAt: Date;
}

export interface GitHubIntegrationStore {
  withTransaction<T>(work: (tx: GitHubTransactionContext) => Promise<T>): Promise<T>;
  acquireOrganizationLock(organizationId: string, tx: GitHubTransactionContext): Promise<boolean>;
  findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: GitHubTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null>;
  createOAuthState(input: {
    stateHash: string;
    userId: string;
    organizationId: string;
    expiresAt: Date;
  }): Promise<void>;
  consumeOAuthState(input: {
    stateHash: string;
    userId: string;
    organizationId: string;
    now: Date;
  }): Promise<boolean>;
  findActiveInstallationByGitHubId(
    githubInstallationId: number,
    tx?: GitHubTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  findInstallationByIdInOrganization(
    organizationId: string,
    installationRecordId: string,
    tx?: GitHubTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  listInstallationsInOrganization(organizationId: string): Promise<PublicGitHubInstallation[]>;
  createInstallation(
    input: UpsertGitHubInstallationInput,
    tx?: GitHubTransactionContext
  ): Promise<PublicGitHubInstallation>;
  updateInstallationInOrganization(
    organizationId: string,
    installationRecordId: string,
    updates: {
      accountId: number;
      accountLogin: string;
      accountType: GitHubAccountType;
      repositorySelection: GitHubRepositorySelection;
      grantedPermissions: Record<string, string>;
      status: GitHubInstallationStatus;
      isActive: boolean;
      suspendedAt: Date | null;
      revokedAt: Date | null;
      lastSyncedAt: Date;
    },
    tx?: GitHubTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
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
    tx?: GitHubTransactionContext
  ): Promise<void>;
}

function asSession(tx?: GitHubTransactionContext): ClientSession | undefined {
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

export const mongooseGitHubIntegrationStore: GitHubIntegrationStore = {
  async withTransaction<T>(work: (tx: GitHubTransactionContext) => Promise<T>): Promise<T> {
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

  async createOAuthState(input) {
    await GitHubOAuthStateModel.create({
      stateHash: input.stateHash,
      userId: input.userId,
      organizationId: input.organizationId,
      usedAt: null,
      expiresAt: input.expiresAt,
    });
  },

  async consumeOAuthState(input) {
    if (!isValidObjectId(input.userId) || !isValidObjectId(input.organizationId)) {
      return false;
    }
    const consumed = await GitHubOAuthStateModel.findOneAndUpdate(
      {
        stateHash: input.stateHash,
        userId: input.userId,
        organizationId: input.organizationId,
        usedAt: null,
        expiresAt: { $gt: input.now },
      },
      {
        $set: { usedAt: input.now },
      },
      {
        returnDocument: 'before',
      }
    );
    return Boolean(consumed);
  },

  async findActiveInstallationByGitHubId(githubInstallationId, tx) {
    const session = asSession(tx);
    const query = GitHubInstallationModel.findOne({
      githubInstallationId,
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicGitHubInstallation(doc) : null;
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

  async listInstallationsInOrganization(organizationId) {
    if (!isValidObjectId(organizationId)) {
      return [];
    }
    const docs = await GitHubInstallationModel.find({
      organizationId,
      status: { $ne: GitHubInstallationStatusValue.DISCONNECTED },
    }).sort({ createdAt: -1, _id: -1 });
    return docs.map((doc) => toPublicGitHubInstallation(doc));
  },

  async createInstallation(input, tx) {
    const session = asSession(tx);
    const [doc] = await GitHubInstallationModel.create(
      [
        {
          organizationId: input.organizationId,
          githubInstallationId: input.githubInstallationId,
          githubAppId: input.githubAppId,
          accountId: input.accountId,
          accountLogin: input.accountLogin,
          accountType: input.accountType,
          repositorySelection: input.repositorySelection,
          grantedPermissions: input.grantedPermissions,
          status: input.status,
          isActive: input.isActive,
          connectedByUserId: input.connectedByUserId,
          disconnectedByUserId: null,
          suspendedAt: input.suspendedAt,
          revokedAt: input.revokedAt,
          lastSyncedAt: input.lastSyncedAt,
        },
      ],
      session ? { session } : undefined
    );
    return toPublicGitHubInstallation(doc!);
  },

  async updateInstallationInOrganization(organizationId, installationRecordId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(installationRecordId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await GitHubInstallationModel.findOneAndUpdate(
      { _id: installationRecordId, organizationId },
      {
        $set: {
          accountId: updates.accountId,
          accountLogin: updates.accountLogin,
          accountType: updates.accountType,
          repositorySelection: updates.repositorySelection,
          grantedPermissions: updates.grantedPermissions,
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

  async createAuditLog(input, tx) {
    const session = asSession(tx);
    await IntegrationAuditLogModel.create(
      [
        {
          organizationId: input.organizationId,
          projectId: input.projectId ?? null,
          actorType: IntegrationAuditActorTypeValue.USER,
          actorUserId: input.actorUserId ?? null,
          action: input.action ?? IntegrationAuditActionValue.INSTALLATION_CONNECTED,
          githubInstallationId: input.githubInstallationId ?? null,
          githubRepositoryId: input.githubRepositoryId ?? null,
          metadata: input.metadata ?? {},
        },
      ],
      session ? { session } : undefined
    );
  },
};
