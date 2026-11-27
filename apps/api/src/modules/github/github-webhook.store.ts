import type { ClientSession } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  computeConnectionIsActive,
  getEffectiveConnectionStatus,
  GitHubInstallationModel,
  IntegrationAuditActorTypeValue,
  IntegrationAuditLogModel,
  isInstallationActiveStatus,
  isValidObjectId,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
  runInTransaction,
  WEBHOOK_DELIVERY_MAX_ORGANIZATIONS,
  WebhookDeliveryModel,
  WebhookDeliveryOutcomeValue,
  type GitHubAccountType,
  type GitHubInstallationStatus,
  type GitHubRepositorySelection,
  type InstallationAvailability,
  type IntegrationAuditAction,
  type RepositoryAccessState,
  type WebhookDeliveryOutcome,
} from '@vibeshield/database';
import type { PublicGitHubInstallation } from './github.types.js';
import type { PublicProjectRepositoryConnection } from './github-connection.types.js';
import type { WebhookDeliveryRecord } from './github-webhook.types.js';

export type WebhookTransactionContext = ClientSession | unknown;

export type ClaimWebhookDeliveryResult =
  | { state: 'CLAIMED'; delivery: WebhookDeliveryRecord }
  | {
      state: 'DUPLICATE_COMPLETED';
      delivery: WebhookDeliveryRecord;
      outcome: Extract<WebhookDeliveryOutcome, 'PROCESSED' | 'IGNORED'>;
    }
  | { state: 'IN_FLIGHT'; delivery: WebhookDeliveryRecord }
  | { state: 'PAYLOAD_MISMATCH'; delivery: WebhookDeliveryRecord };

export interface GitHubWebhookStore {
  withTransaction<T>(work: (tx: WebhookTransactionContext) => Promise<T>): Promise<T>;
  acquireOrganizationLock(organizationId: string, tx: WebhookTransactionContext): Promise<boolean>;
  claimDelivery(input: {
    deliveryId: string;
    event: string;
    action: string | null;
    githubInstallationId: number | null;
    payloadSha256: string;
    now: Date;
    expiresAt: Date;
    staleLeaseBefore: Date;
  }): Promise<ClaimWebhookDeliveryResult>;
  getDeliveryByDeliveryId(deliveryId: string): Promise<WebhookDeliveryRecord | null>;
  setDeliveryTargetOrganizations(input: {
    deliveryId: string;
    attemptCount: number;
    targetOrganizationIds: string[];
  }): Promise<WebhookDeliveryRecord | null>;
  recordOrganizationProgress(
    input: {
      deliveryId: string;
      attemptCount: number;
      organizationId: string;
      processedConnectionsDelta: number;
    },
    tx: WebhookTransactionContext
  ): Promise<WebhookDeliveryRecord | null>;
  completeDelivery(
    input: {
      deliveryId: string;
      attemptCount: number;
      outcome: Extract<WebhookDeliveryOutcome, 'PROCESSED' | 'IGNORED'>;
      outcomeReason: string | null;
      githubInstallationId?: number | null;
      now: Date;
    },
    tx?: WebhookTransactionContext
  ): Promise<WebhookDeliveryRecord | null>;
  failDelivery(input: {
    deliveryId: string;
    attemptCount: number;
    errorCode: string;
    errorMessage: string;
    now: Date;
  }): Promise<WebhookDeliveryRecord | null>;
  findActiveInstallationByGitHubId(
    githubInstallationId: number,
    tx?: WebhookTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  updateInstallationByIdInOrganization(
    organizationId: string,
    installationRecordId: string,
    updates: {
      accountId?: number;
      accountLogin?: string;
      accountType?: GitHubAccountType;
      repositorySelection?: GitHubRepositorySelection;
      grantedPermissions?: Record<string, string>;
      status: GitHubInstallationStatus;
      isActive: boolean;
      suspendedAt: Date | null;
      revokedAt: Date | null;
      lastSyncedAt: Date;
    },
    tx?: WebhookTransactionContext
  ): Promise<PublicGitHubInstallation | null>;
  updateConnectionsAvailabilityForInstallation(
    input: {
      organizationId: string;
      installationRecordId: string;
      installationAvailability: InstallationAvailability;
      reasonForConnected: string | null;
      now: Date;
    },
    tx?: WebhookTransactionContext
  ): Promise<PublicProjectRepositoryConnection[]>;
  listActiveConnectionsByInstallationAndRepoIds(
    organizationId: string,
    installationRecordId: string,
    githubRepositoryIds: number[],
    tx?: WebhookTransactionContext
  ): Promise<PublicProjectRepositoryConnection[]>;
  findDistinctOrganizationIdsByActiveRepositoryId(githubRepositoryId: number): Promise<string[]>;
  listActiveConnectionsByOrgAndRepoId(
    organizationId: string,
    githubRepositoryId: number,
    tx?: WebhookTransactionContext
  ): Promise<PublicProjectRepositoryConnection[]>;
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
      lastSyncedAt: Date;
      lastWebhookAt: Date;
    },
    tx?: WebhookTransactionContext
  ): Promise<PublicProjectRepositoryConnection | null>;
  createAuditLog(
    input: {
      organizationId: string;
      projectId?: string | null;
      action: IntegrationAuditAction;
      githubInstallationId?: number | null;
      githubRepositoryId?: number | null;
      metadata?: Record<string, unknown>;
    },
    tx?: WebhookTransactionContext
  ): Promise<void>;
}

function asSession(tx?: WebhookTransactionContext): ClientSession | undefined {
  return tx as ClientSession | undefined;
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

function toWebhookDeliveryRecord(doc: {
  _id: { toString(): string };
  deliveryId: string;
  event: string;
  action: string | null;
  githubInstallationId: number | null;
  payloadSha256: string;
  outcome: WebhookDeliveryOutcome;
  outcomeReason?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  attemptCount?: number;
  targetOrganizationIds?: Array<{ toString(): string }>;
  completedOrganizationIds?: Array<{ toString(): string }>;
  processedConnectionCount?: number;
  processingStartedAt?: Date | null;
  processedAt?: Date | null;
  failedAt?: Date | null;
  receivedAt: Date;
  expiresAt: Date;
}): WebhookDeliveryRecord {
  return {
    id: doc._id.toString(),
    deliveryId: doc.deliveryId,
    event: doc.event,
    action: doc.action ?? null,
    githubInstallationId: doc.githubInstallationId ?? null,
    payloadSha256: doc.payloadSha256,
    outcome: doc.outcome,
    outcomeReason: doc.outcomeReason ?? null,
    errorCode: doc.errorCode ?? null,
    errorMessage: doc.errorMessage ?? null,
    attemptCount: doc.attemptCount ?? 1,
    targetOrganizationIds: (doc.targetOrganizationIds ?? []).map((id) => id.toString()),
    completedOrganizationIds: (doc.completedOrganizationIds ?? []).map((id) => id.toString()),
    processedConnectionCount: doc.processedConnectionCount ?? 0,
    processingStartedAt: doc.processingStartedAt ?? null,
    processedAt: doc.processedAt ?? null,
    failedAt: doc.failedAt ?? null,
    receivedAt: doc.receivedAt,
    expiresAt: doc.expiresAt,
  };
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

export const mongooseGitHubWebhookStore: GitHubWebhookStore = {
  async withTransaction<T>(work: (tx: WebhookTransactionContext) => Promise<T>): Promise<T> {
    return runInTransaction(async (session) => work(session));
  },

  async acquireOrganizationLock(organizationId, tx) {
    const session = asSession(tx);
    if (!session) {
      throw new Error('Organization mutation lock requires an active MongoDB transaction session');
    }
    return acquireOrganizationMutationLock(organizationId, session);
  },

  async claimDelivery(input) {
    try {
      const [created] = await WebhookDeliveryModel.create([
        {
          deliveryId: input.deliveryId,
          event: input.event,
          action: input.action,
          githubInstallationId: input.githubInstallationId,
          payloadSha256: input.payloadSha256,
          outcome: WebhookDeliveryOutcomeValue.PROCESSING,
          outcomeReason: null,
          errorCode: null,
          errorMessage: null,
          attemptCount: 1,
          processingStartedAt: input.now,
          processedAt: null,
          failedAt: null,
          receivedAt: input.now,
          expiresAt: input.expiresAt,
        },
      ]);
      return { state: 'CLAIMED', delivery: toWebhookDeliveryRecord(created!) };
    } catch (error) {
      if (!isMongoDuplicateKeyError(error)) {
        throw error;
      }
    }

    const existing = await WebhookDeliveryModel.findOne({ deliveryId: input.deliveryId });
    if (!existing) {
      // Rare race if TTL evicted in the instant after duplicate key; retry once cleanly
      const [recreated] = await WebhookDeliveryModel.create([
        {
          deliveryId: input.deliveryId,
          event: input.event,
          action: input.action,
          githubInstallationId: input.githubInstallationId,
          payloadSha256: input.payloadSha256,
          outcome: WebhookDeliveryOutcomeValue.PROCESSING,
          outcomeReason: null,
          errorCode: null,
          errorMessage: null,
          attemptCount: 1,
          processingStartedAt: input.now,
          processedAt: null,
          failedAt: null,
          receivedAt: input.now,
          expiresAt: input.expiresAt,
        },
      ]);
      return { state: 'CLAIMED', delivery: toWebhookDeliveryRecord(recreated!) };
    }

    const existingRecord = toWebhookDeliveryRecord(existing);
    if (
      existingRecord.outcome === WebhookDeliveryOutcomeValue.PROCESSED ||
      existingRecord.outcome === WebhookDeliveryOutcomeValue.IGNORED
    ) {
      return {
        state: 'DUPLICATE_COMPLETED',
        delivery: existingRecord,
        outcome: existingRecord.outcome,
      };
    }

    if (existingRecord.payloadSha256 !== input.payloadSha256) {
      return { state: 'PAYLOAD_MISMATCH', delivery: existingRecord };
    }

    const canClaimRetry =
      existingRecord.outcome === WebhookDeliveryOutcomeValue.FAILED ||
      (existingRecord.outcome === WebhookDeliveryOutcomeValue.PROCESSING &&
        existingRecord.processingStartedAt !== null &&
        existingRecord.processingStartedAt.getTime() <= input.staleLeaseBefore.getTime());

    if (canClaimRetry) {
      const reclaimed = await WebhookDeliveryModel.findOneAndUpdate(
        {
          deliveryId: input.deliveryId,
          payloadSha256: input.payloadSha256,
          $or: [
            { outcome: WebhookDeliveryOutcomeValue.FAILED },
            {
              outcome: WebhookDeliveryOutcomeValue.PROCESSING,
              processingStartedAt: { $lte: input.staleLeaseBefore },
            },
          ],
        },
        {
          $set: {
            event: input.event,
            action: input.action,
            githubInstallationId: input.githubInstallationId,
            outcome: WebhookDeliveryOutcomeValue.PROCESSING,
            outcomeReason: null,
            processingStartedAt: input.now,
          },
          $inc: { attemptCount: 1 },
        },
        { returnDocument: 'after', runValidators: true }
      );

      if (reclaimed) {
        return { state: 'CLAIMED', delivery: toWebhookDeliveryRecord(reclaimed) };
      }

      const latest = await WebhookDeliveryModel.findOne({ deliveryId: input.deliveryId });
      if (latest) {
        const latestRecord = toWebhookDeliveryRecord(latest);
        if (
          latestRecord.outcome === WebhookDeliveryOutcomeValue.PROCESSED ||
          latestRecord.outcome === WebhookDeliveryOutcomeValue.IGNORED
        ) {
          return {
            state: 'DUPLICATE_COMPLETED',
            delivery: latestRecord,
            outcome: latestRecord.outcome,
          };
        }
        return { state: 'IN_FLIGHT', delivery: latestRecord };
      }
    }

    return { state: 'IN_FLIGHT', delivery: existingRecord };
  },

  async getDeliveryByDeliveryId(deliveryId) {
    const doc = await WebhookDeliveryModel.findOne({ deliveryId });
    return doc ? toWebhookDeliveryRecord(doc) : null;
  },

  async setDeliveryTargetOrganizations(input) {
    const uniqueValidIds = Array.from(new Set(input.targetOrganizationIds)).filter(isValidObjectId);
    if (uniqueValidIds.length > WEBHOOK_DELIVERY_MAX_ORGANIZATIONS) {
      throw new Error(
        `Webhook delivery exceeds maximum organization fanout (${WEBHOOK_DELIVERY_MAX_ORGANIZATIONS})`
      );
    }

    const updated = await WebhookDeliveryModel.findOneAndUpdate(
      {
        deliveryId: input.deliveryId,
        outcome: WebhookDeliveryOutcomeValue.PROCESSING,
        attemptCount: input.attemptCount,
        'targetOrganizationIds.0': { $exists: false },
      },
      {
        $set: { targetOrganizationIds: uniqueValidIds },
      },
      { returnDocument: 'after', runValidators: true }
    );
    if (updated) {
      return toWebhookDeliveryRecord(updated);
    }

    const existing = await WebhookDeliveryModel.findOne({ deliveryId: input.deliveryId });
    if (
      existing &&
      existing.outcome === WebhookDeliveryOutcomeValue.PROCESSING &&
      existing.attemptCount === input.attemptCount
    ) {
      return toWebhookDeliveryRecord(existing);
    }
    return null;
  },

  async recordOrganizationProgress(input, tx) {
    if (!isValidObjectId(input.organizationId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await WebhookDeliveryModel.findOneAndUpdate(
      {
        deliveryId: input.deliveryId,
        outcome: WebhookDeliveryOutcomeValue.PROCESSING,
        attemptCount: input.attemptCount,
        completedOrganizationIds: { $ne: input.organizationId },
      },
      {
        $addToSet: { completedOrganizationIds: input.organizationId },
        $inc: { processedConnectionCount: Math.max(0, input.processedConnectionsDelta) },
      },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toWebhookDeliveryRecord(doc) : null;
  },

  async completeDelivery(input, tx) {
    const session = asSession(tx);
    const doc = await WebhookDeliveryModel.findOneAndUpdate(
      {
        deliveryId: input.deliveryId,
        outcome: WebhookDeliveryOutcomeValue.PROCESSING,
        attemptCount: input.attemptCount,
      },
      {
        $set: {
          outcome: input.outcome,
          outcomeReason: input.outcomeReason,
          ...(input.githubInstallationId !== undefined
            ? { githubInstallationId: input.githubInstallationId }
            : {}),
          processedAt: input.now,
          errorCode: null,
          errorMessage: null,
          failedAt: null,
        },
      },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toWebhookDeliveryRecord(doc) : null;
  },

  async failDelivery(input) {
    const doc = await WebhookDeliveryModel.findOneAndUpdate(
      {
        deliveryId: input.deliveryId,
        attemptCount: input.attemptCount,
        outcome: {
          $in: [WebhookDeliveryOutcomeValue.PROCESSING, WebhookDeliveryOutcomeValue.FAILED],
        },
      },
      {
        $set: {
          outcome: WebhookDeliveryOutcomeValue.FAILED,
          errorCode: input.errorCode.slice(0, 64),
          errorMessage: input.errorMessage.slice(0, 500),
          failedAt: input.now,
        },
      },
      { returnDocument: 'after', runValidators: true }
    );
    return doc ? toWebhookDeliveryRecord(doc) : null;
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

  async updateInstallationByIdInOrganization(organizationId, installationRecordId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(installationRecordId)) {
      return null;
    }
    const session = asSession(tx);
    const setFields: Record<string, unknown> = {
      status: updates.status,
      isActive: isInstallationActiveStatus(updates.status),
      suspendedAt: updates.suspendedAt,
      revokedAt: updates.revokedAt,
      lastSyncedAt: updates.lastSyncedAt,
    };
    if (updates.accountId !== undefined) setFields.accountId = updates.accountId;
    if (updates.accountLogin !== undefined) setFields.accountLogin = updates.accountLogin;
    if (updates.accountType !== undefined) setFields.accountType = updates.accountType;
    if (updates.repositorySelection !== undefined) {
      setFields.repositorySelection = updates.repositorySelection;
    }
    if (updates.grantedPermissions !== undefined) {
      setFields.grantedPermissions = updates.grantedPermissions;
    }

    const doc = await GitHubInstallationModel.findOneAndUpdate(
      { _id: installationRecordId, organizationId },
      { $set: setFields },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicGitHubInstallation(doc) : null;
  },

  async updateConnectionsAvailabilityForInstallation(input, tx) {
    if (!isValidObjectId(input.organizationId) || !isValidObjectId(input.installationRecordId)) {
      return [];
    }
    const session = asSession(tx);
    const query = ProjectRepositoryConnectionModel.find({
      organizationId: input.organizationId,
      installationRecordId: input.installationRecordId,
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const existingDocs = await query;
    const updated: PublicProjectRepositoryConnection[] = [];

    for (const doc of existingDocs) {
      const nextIsActive = computeConnectionIsActive(
        doc.repositoryAccessState,
        input.installationAvailability
      );
      const nextStatusReason =
        doc.repositoryAccessState === RepositoryAccessStateValue.CONNECTED
          ? input.reasonForConnected
          : doc.statusReason;

      const nextDoc = await ProjectRepositoryConnectionModel.findOneAndUpdate(
        { _id: doc._id, organizationId: input.organizationId },
        {
          $set: {
            installationAvailability: input.installationAvailability,
            statusReason: nextStatusReason,
            isActive: nextIsActive,
            lastWebhookAt: input.now,
            lastSyncedAt: input.now,
          },
        },
        { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
      );
      if (nextDoc) {
        updated.push(toPublicProjectRepositoryConnection(nextDoc));
      }
    }

    return updated;
  },

  async listActiveConnectionsByInstallationAndRepoIds(
    organizationId,
    installationRecordId,
    githubRepositoryIds,
    tx
  ) {
    if (
      !isValidObjectId(organizationId) ||
      !isValidObjectId(installationRecordId) ||
      githubRepositoryIds.length === 0
    ) {
      return [];
    }
    const session = asSession(tx);
    const query = ProjectRepositoryConnectionModel.find({
      organizationId,
      installationRecordId,
      githubRepositoryId: { $in: githubRepositoryIds },
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const docs = await query;
    return docs.map((doc) => toPublicProjectRepositoryConnection(doc));
  },

  async findDistinctOrganizationIdsByActiveRepositoryId(githubRepositoryId) {
    const orgIds = await ProjectRepositoryConnectionModel.distinct('organizationId', {
      githubRepositoryId,
      isActive: true,
    });
    return orgIds.map((id) => id.toString());
  },

  async listActiveConnectionsByOrgAndRepoId(organizationId, githubRepositoryId, tx) {
    if (!isValidObjectId(organizationId)) {
      return [];
    }
    const session = asSession(tx);
    const query = ProjectRepositoryConnectionModel.find({
      organizationId,
      githubRepositoryId,
      isActive: true,
    });
    if (session) {
      query.session(session);
    }
    const docs = await query;
    return docs.map((doc) => toPublicProjectRepositoryConnection(doc));
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
      lastWebhookAt: updates.lastWebhookAt,
    };
    if (updates.ownerLogin !== undefined) setFields.ownerLogin = updates.ownerLogin;
    if (updates.repoName !== undefined) setFields.repoName = updates.repoName;
    if (updates.fullName !== undefined) setFields.fullName = updates.fullName;
    if (updates.htmlUrl !== undefined) setFields.htmlUrl = updates.htmlUrl;
    if (updates.defaultBranch !== undefined) setFields.defaultBranch = updates.defaultBranch;
    if (updates.isPrivate !== undefined) setFields.isPrivate = updates.isPrivate;
    if (updates.isArchivedOnGitHub !== undefined) {
      setFields.isArchivedOnGitHub = updates.isArchivedOnGitHub;
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
          actorType: IntegrationAuditActorTypeValue.GITHUB_WEBHOOK,
          actorUserId: null,
          action: input.action,
          githubInstallationId: input.githubInstallationId ?? null,
          githubRepositoryId: input.githubRepositoryId ?? null,
          metadata: input.metadata ?? {},
        },
      ],
      session ? { session } : undefined
    );
  },
};
