import { randomBytes } from 'node:crypto';
import type { ClientSession } from 'mongoose';
import {
  isTerminalScanLifecycleStatus,
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  type PublicScanRecord,
  type ScanAcquisitionMetadata,
  type ScanFailureCode,
  type ScanLifecycleStatus,
  type ScanTriggerSource,
} from '@vibeshield/types';
import { redactMongoUri, runInTransaction } from '../connection.js';
import { acquireOrganizationMutationLock } from '../models/organization.model.js';
import { ScanModel, type ScanAttributes } from '../models/scan.model.js';
import { isValidObjectId } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';

export const DEFAULT_SCAN_LEASE_DURATION_MS = 60_000;
const MIN_LEASE_DURATION_MS = 1_000;
const MAX_LEASE_DURATION_MS = 3_600_000;
const FULL_COMMIT_SHA_REGEX = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;

const ALLOWED_SCAN_TRANSITIONS: Readonly<
  Record<ScanLifecycleStatus, ReadonlySet<ScanLifecycleStatus>>
> = Object.freeze({
  [ScanLifecycleStatusValue.QUEUED]: new Set<ScanLifecycleStatus>([
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.FAILED,
    ScanLifecycleStatusValue.CANCELLED,
  ]),
  [ScanLifecycleStatusValue.ACQUIRING]: new Set<ScanLifecycleStatus>([
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.IN_PROGRESS,
    ScanLifecycleStatusValue.FAILED,
    ScanLifecycleStatusValue.CANCELLED,
  ]),
  [ScanLifecycleStatusValue.IN_PROGRESS]: new Set<ScanLifecycleStatus>([
    ScanLifecycleStatusValue.IN_PROGRESS,
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.COMPLETED,
    ScanLifecycleStatusValue.FAILED,
    ScanLifecycleStatusValue.CANCELLED,
  ]),
  [ScanLifecycleStatusValue.COMPLETED]: new Set<ScanLifecycleStatus>(),
  [ScanLifecycleStatusValue.FAILED]: new Set<ScanLifecycleStatus>(),
  [ScanLifecycleStatusValue.CANCELLED]: new Set<ScanLifecycleStatus>(),
});

/**
 * Verifies whether transitioning a persistent scan between two lifecycle states is permitted.
 */
export function isValidScanLifecycleTransition(
  from: ScanLifecycleStatus,
  to: ScanLifecycleStatus
): boolean {
  return ALLOWED_SCAN_TRANSITIONS[from]?.has(to) ?? false;
}

export class ScanLifecycleError extends Error {
  public readonly code: string;

  constructor(message: string, code = 'SCAN_LIFECYCLE_ERROR') {
    super(redactGitHubSecrets(redactMongoUri(message)));
    this.name = 'ScanLifecycleError';
    this.code = code;
  }
}

export type ClaimScanResult =
  | { status: 'CLAIMED'; scan: PublicScanRecord; leaseToken: string }
  | { status: 'CANCELLED'; scan: PublicScanRecord }
  | { status: 'NOT_FOUND' }
  | { status: 'NOT_CLAIMABLE'; currentStatus: ScanLifecycleStatus; scan: PublicScanRecord };

export type ReclaimExpiredLeaseResult =
  | { status: 'RECLAIMED'; scan: PublicScanRecord; leaseToken: string }
  | { status: 'CANCELLED'; scan: PublicScanRecord }
  | { status: 'MAX_ATTEMPTS_EXHAUSTED'; scan: PublicScanRecord }
  | { status: 'NOT_RECLAIMABLE'; scan: PublicScanRecord | null };

export type FencedScanMutationResult =
  | { status: 'UPDATED'; scan: PublicScanRecord }
  | { status: 'CANCEL_REQUESTED'; scan: PublicScanRecord }
  | { status: 'STALE_OR_CONFLICT'; scan: PublicScanRecord | null };

export type RequestCancellationResult =
  | { status: 'CANCELLED_IMMEDIATELY'; scan: PublicScanRecord }
  | { status: 'CANCELLATION_REQUESTED'; scan: PublicScanRecord }
  | { status: 'ALREADY_TERMINAL'; scan: PublicScanRecord }
  | { status: 'NOT_FOUND' };

export interface CreateQueuedScanInput {
  organizationId: string;
  projectId: string;
  repositoryConnectionId: string;
  githubInstallationId: number;
  githubRepositoryId: number;
  requestedRef: string;
  requestedCommitHash?: string | null;
  triggerSource: ScanTriggerSource;
  createdByUserId?: string | null;
  correlationId?: string | null;
  idempotencyKey?: string | null;
  maxAttempts?: number;
  now?: Date;
}

function generateLeaseToken(): string {
  return randomBytes(24).toString('hex');
}

function assertValidLeaseDuration(leaseDurationMs: number): number {
  if (
    !Number.isInteger(leaseDurationMs) ||
    leaseDurationMs < MIN_LEASE_DURATION_MS ||
    leaseDurationMs > MAX_LEASE_DURATION_MS
  ) {
    throw new ScanLifecycleError(
      `Lease duration must be an integer between ${MIN_LEASE_DURATION_MS} and ${MAX_LEASE_DURATION_MS} ms`,
      'INVALID_LEASE_DURATION'
    );
  }
  return leaseDurationMs;
}

function assertValidWorkerIdentity(workerId: string): string {
  const trimmed = workerId.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    throw new ScanLifecycleError(
      'Worker ID must be between 1 and 128 characters',
      'INVALID_WORKER_ID'
    );
  }
  return trimmed;
}

function assertValidLeaseToken(leaseToken: string): string {
  if (typeof leaseToken !== 'string' || leaseToken.trim().length < 16) {
    throw new ScanLifecycleError('Invalid worker fencing token', 'INVALID_LEASE_TOKEN');
  }
  return leaseToken;
}

function assertValidIds(organizationId: string, projectId: string, scanId: string): void {
  if (!isValidObjectId(organizationId) || !isValidObjectId(projectId) || !isValidObjectId(scanId)) {
    throw new ScanLifecycleError(
      'Invalid tenant or scan ObjectId identifier',
      'INVALID_SCAN_IDENTIFIER'
    );
  }
}

export function toPublicScanRecord(
  doc: ScanAttributes & { _id: { toString(): string } }
): PublicScanRecord {
  return {
    id: doc._id.toString(),
    organizationId: doc.organizationId.toString(),
    projectId: doc.projectId.toString(),
    repositoryConnectionId: doc.repositoryConnectionId.toString(),
    githubInstallationId: doc.githubInstallationId,
    githubRepositoryId: doc.githubRepositoryId,
    requestedRef: doc.requestedRef,
    requestedCommitHash: doc.requestedCommitHash ?? null,
    resolvedCommitSha: doc.resolvedCommitSha ?? null,
    status: doc.status,
    isActive: doc.isActive,
    triggerSource: doc.triggerSource,
    createdByUserId: doc.createdByUserId ? doc.createdByUserId.toString() : null,
    correlationId: doc.correlationId ?? null,
    attemptCount: doc.attemptCount,
    maxAttempts: doc.maxAttempts,
    lease: doc.lease
      ? {
          workerId: doc.lease.workerId,
          acquiredAt: doc.lease.acquiredAt,
          heartbeatAt: doc.lease.heartbeatAt,
          expiresAt: doc.lease.expiresAt,
        }
      : null,
    cancellation: {
      requestedAt: doc.cancellation?.requestedAt ?? null,
      requestedByUserId: doc.cancellation?.requestedByUserId
        ? doc.cancellation.requestedByUserId.toString()
        : null,
      reason: doc.cancellation?.reason ?? null,
    },
    acquisition: doc.acquisition
      ? {
          resolvedCommitSha: doc.acquisition.resolvedCommitSha,
          compressedArchiveBytes: doc.acquisition.compressedArchiveBytes,
          extractedBytes: doc.acquisition.extractedBytes,
          extractedFileCount: doc.acquisition.extractedFileCount,
          acquisitionCompletedAt: doc.acquisition.acquisitionCompletedAt,
        }
      : null,
    failureCode: doc.failureCode ?? null,
    failureMessage: doc.failureMessage ?? null,
    queuedAt: doc.queuedAt,
    startedAt: doc.startedAt ?? null,
    acquiringAt: doc.acquiringAt ?? null,
    inProgressAt: doc.inProgressAt ?? null,
    completedAt: doc.completedAt ?? null,
    failedAt: doc.failedAt ?? null,
    cancelledAt: doc.cancelledAt ?? null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

/**
 * Creates a persistent scan record in `QUEUED` state within an optional transaction session.
 */
export async function createQueuedScan(
  input: CreateQueuedScanInput,
  session?: ClientSession
): Promise<PublicScanRecord> {
  if (
    !isValidObjectId(input.organizationId) ||
    !isValidObjectId(input.projectId) ||
    !isValidObjectId(input.repositoryConnectionId)
  ) {
    throw new ScanLifecycleError(
      'Invalid organization, project, or repository connection ID',
      'INVALID_SCAN_IDENTIFIER'
    );
  }
  if (input.createdByUserId && !isValidObjectId(input.createdByUserId)) {
    throw new ScanLifecycleError('Invalid createdByUserId identifier', 'INVALID_SCAN_IDENTIFIER');
  }

  const now = input.now ?? new Date();
  const [created] = await ScanModel.create(
    [
      {
        organizationId: input.organizationId,
        projectId: input.projectId,
        repositoryConnectionId: input.repositoryConnectionId,
        githubInstallationId: input.githubInstallationId,
        githubRepositoryId: input.githubRepositoryId,
        requestedRef: input.requestedRef,
        requestedCommitHash: input.requestedCommitHash ?? null,
        resolvedCommitSha: null,
        status: ScanLifecycleStatusValue.QUEUED,
        isActive: true,
        triggerSource: input.triggerSource,
        createdByUserId: input.createdByUserId ?? null,
        correlationId: input.correlationId ?? null,
        idempotencyKey: input.idempotencyKey ?? null,
        attemptCount: 0,
        maxAttempts: input.maxAttempts ?? 3,
        lease: null,
        queuedAt: now,
      },
    ],
    session ? { session } : {}
  );

  if (!created) {
    throw new ScanLifecycleError('Failed to persist scan record', 'SCAN_CREATE_FAILED');
  }

  return toPublicScanRecord(created);
}

/**
 * Retrieves a single scan strictly scoped to `(organizationId, projectId)`.
 */
export async function findScanByIdInOrganization(input: {
  organizationId: string;
  projectId: string;
  scanId: string;
}): Promise<PublicScanRecord | null> {
  if (
    !isValidObjectId(input.organizationId) ||
    !isValidObjectId(input.projectId) ||
    !isValidObjectId(input.scanId)
  ) {
    return null;
  }

  const doc = await ScanModel.findOne({
    _id: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });

  return doc ? toPublicScanRecord(doc) : null;
}

/**
 * Lists tenant- and project-scoped scans ordered newest first.
 */
export async function listScansByProjectInOrganization(input: {
  organizationId: string;
  projectId: string;
  status?: ScanLifecycleStatus;
  limit?: number;
}): Promise<PublicScanRecord[]> {
  if (!isValidObjectId(input.organizationId) || !isValidObjectId(input.projectId)) {
    return [];
  }

  const limit = Math.min(Math.max(input.limit ?? 20, 1), 100);
  const filter: Record<string, unknown> = {
    organizationId: input.organizationId,
    projectId: input.projectId,
  };
  if (input.status) {
    filter.status = input.status;
  }

  const docs = await ScanModel.find(filter).sort({ createdAt: -1 }).limit(limit);
  return docs.map(toPublicScanRecord);
}

/**
 * Atomically claims a `QUEUED` scan for repository acquisition, minting an opaque fencing token
 * (`leaseToken`) and incrementing `attemptCount`. Respects any pending cancellation request by
 * transitioning the scan cleanly to `CANCELLED` instead of claiming it.
 */
export async function claimQueuedScanForAcquisition(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  workerId: string;
  leaseDurationMs?: number;
  now?: Date;
}): Promise<ClaimScanResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const workerId = assertValidWorkerIdentity(input.workerId);
  const leaseDurationMs = assertValidLeaseDuration(
    input.leaseDurationMs ?? DEFAULT_SCAN_LEASE_DURATION_MS
  );
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + leaseDurationMs);
  const leaseToken = generateLeaseToken();

  const claimed = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: ScanLifecycleStatusValue.QUEUED,
      isActive: true,
      'cancellation.requestedAt': null,
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.ACQUIRING,
        isActive: true,
        startedAt: now,
        acquiringAt: now,
        lease: {
          workerId,
          token: leaseToken,
          acquiredAt: now,
          heartbeatAt: now,
          expiresAt,
        },
      },
      $inc: {
        attemptCount: 1,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (claimed) {
    return {
      status: 'CLAIMED',
      scan: toPublicScanRecord(claimed),
      leaseToken,
    };
  }

  // Respect pre-acquisition cancellation cleanly if the queued scan has a pending cancellation.
  const cancelledQueued = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: ScanLifecycleStatusValue.QUEUED,
      isActive: true,
      'cancellation.requestedAt': { $ne: null },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.CANCELLED,
        isActive: false,
        cancelledAt: now,
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (cancelledQueued) {
    return {
      status: 'CANCELLED',
      scan: toPublicScanRecord(cancelledQueued),
    };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  if (!existing) {
    return { status: 'NOT_FOUND' };
  }
  if (existing.status === ScanLifecycleStatusValue.CANCELLED) {
    return { status: 'CANCELLED', scan: existing };
  }
  return {
    status: 'NOT_CLAIMABLE',
    currentStatus: existing.status,
    scan: existing,
  };
}

/**
 * Reclaims an `ACQUIRING` or `IN_PROGRESS` scan whose worker lease has expired (`expiresAt <= now`),
 * rotating `lease.token` so the prior stalled worker is permanently fenced from updating state.
 */
export async function reclaimExpiredScanLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  workerId: string;
  leaseDurationMs?: number;
  now?: Date;
}): Promise<ReclaimExpiredLeaseResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const workerId = assertValidWorkerIdentity(input.workerId);
  const leaseDurationMs = assertValidLeaseDuration(
    input.leaseDurationMs ?? DEFAULT_SCAN_LEASE_DURATION_MS
  );
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + leaseDurationMs);
  const leaseToken = generateLeaseToken();

  // If cancellation was requested before the stale lease was reclaimed, finalize CANCELLED cleanly.
  const cancelledExpired = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'cancellation.requestedAt': { $ne: null },
      'lease.expiresAt': { $lte: now },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.CANCELLED,
        isActive: false,
        cancelledAt: now,
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (cancelledExpired) {
    return {
      status: 'CANCELLED',
      scan: toPublicScanRecord(cancelledExpired),
    };
  }

  const reclaimed = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'cancellation.requestedAt': null,
      'lease.expiresAt': { $lte: now },
      $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.ACQUIRING,
        isActive: true,
        acquiringAt: now,
        lease: {
          workerId,
          token: leaseToken,
          acquiredAt: now,
          heartbeatAt: now,
          expiresAt,
        },
      },
      $inc: {
        attemptCount: 1,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (reclaimed) {
    return {
      status: 'RECLAIMED',
      scan: toPublicScanRecord(reclaimed),
      leaseToken,
    };
  }

  // Fail permanently if an expired active lease exhausted its bounded attempt budget.
  const exhausted = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'lease.expiresAt': { $lte: now },
      $expr: { $gte: ['$attemptCount', '$maxAttempts'] },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.FAILED,
        isActive: false,
        failedAt: now,
        failureCode: ScanFailureCodeValue.LEASE_EXPIRED,
        failureMessage: 'Worker lease expired after maximum allowed scan attempts',
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (exhausted) {
    return {
      status: 'MAX_ATTEMPTS_EXHAUSTED',
      scan: toPublicScanRecord(exhausted),
    };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return {
    status: 'NOT_RECLAIMABLE',
    scan: existing,
  };
}

/**
 * Extends the active lease heartbeat/expiration only when `leaseToken` matches the live lease
 * and the lease has not yet expired. Surfaces pending cancellation requests via `CANCEL_REQUESTED`.
 */
export async function renewScanWorkerLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  leaseDurationMs?: number;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const leaseDurationMs = assertValidLeaseDuration(
    input.leaseDurationMs ?? DEFAULT_SCAN_LEASE_DURATION_MS
  );
  const now = input.now ?? new Date();
  const nextExpiresAt = new Date(now.getTime() + leaseDurationMs);

  const renewed = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'lease.token': leaseToken,
      'lease.expiresAt': { $gt: now },
    },
    {
      $set: {
        'lease.heartbeatAt': now,
        'lease.expiresAt': nextExpiresAt,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (!renewed) {
    const existing = await findScanByIdInOrganization({
      scanId: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
    });
    return { status: 'STALE_OR_CONFLICT', scan: existing };
  }

  const record = toPublicScanRecord(renewed);
  if (record.cancellation.requestedAt !== null) {
    return { status: 'CANCEL_REQUESTED', scan: record };
  }
  return { status: 'UPDATED', scan: record };
}

/**
 * Atomically records repository acquisition metrics and moves a scan from `ACQUIRING` to
 * `IN_PROGRESS` strictly under valid fencing token, unexpired lease, and no pending cancellation.
 */
export async function transitionScanToInProgress(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  acquisition: Omit<ScanAcquisitionMetadata, 'acquisitionCompletedAt'> & {
    acquisitionCompletedAt?: Date;
  };
  leaseDurationMs?: number;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const normalizedSha = input.acquisition.resolvedCommitSha.trim().toLowerCase();
  if (!FULL_COMMIT_SHA_REGEX.test(normalizedSha)) {
    throw new ScanLifecycleError(
      'Resolved commit SHA must be a full 40- or 64-character hex Git SHA',
      'INVALID_COMMIT_SHA'
    );
  }

  const now = input.now ?? new Date();
  const completedAt = input.acquisition.acquisitionCompletedAt ?? now;
  const setFields: Record<string, unknown> = {
    status: ScanLifecycleStatusValue.IN_PROGRESS,
    resolvedCommitSha: normalizedSha,
    inProgressAt: now,
    'lease.heartbeatAt': now,
    acquisition: {
      resolvedCommitSha: normalizedSha,
      compressedArchiveBytes: input.acquisition.compressedArchiveBytes,
      extractedBytes: input.acquisition.extractedBytes,
      extractedFileCount: input.acquisition.extractedFileCount,
      acquisitionCompletedAt: completedAt,
    },
  };

  if (input.leaseDurationMs !== undefined) {
    const leaseDurationMs = assertValidLeaseDuration(input.leaseDurationMs);
    setFields['lease.expiresAt'] = new Date(now.getTime() + leaseDurationMs);
  }

  const updated = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: ScanLifecycleStatusValue.ACQUIRING,
      isActive: true,
      'cancellation.requestedAt': null,
      'lease.token': leaseToken,
      'lease.expiresAt': { $gt: now },
    },
    { $set: setFields },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  if (
    existing &&
    existing.status === ScanLifecycleStatusValue.ACQUIRING &&
    existing.cancellation.requestedAt !== null
  ) {
    return { status: 'CANCEL_REQUESTED', scan: existing };
  }

  return { status: 'STALE_OR_CONFLICT', scan: existing };
}

/**
 * Atomically transitions an active leased `IN_PROGRESS` scan to `COMPLETED`, clearing the worker lease.
 */
export async function completeScanWithLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();

  const updated = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: ScanLifecycleStatusValue.IN_PROGRESS,
      isActive: true,
      'lease.token': leaseToken,
      'lease.expiresAt': { $gt: now },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.COMPLETED,
        isActive: false,
        completedAt: now,
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return { status: 'STALE_OR_CONFLICT', scan: existing };
}

/**
 * Atomically transitions an active leased scan (`ACQUIRING` or `IN_PROGRESS`) to `FAILED` with
 * redacted failure details while rejecting stale workers whose lease token no longer matches.
 */
export async function failScanWithLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  failureCode: ScanFailureCode;
  failureMessage: string;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();
  const safeMessage = redactGitHubSecrets(redactMongoUri(input.failureMessage)).slice(0, 500);

  const updated = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'lease.token': leaseToken,
      'lease.expiresAt': { $gt: now },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.FAILED,
        isActive: false,
        failedAt: now,
        failureCode: input.failureCode,
        failureMessage: safeMessage,
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return { status: 'STALE_OR_CONFLICT', scan: existing };
}

/**
 * Safely honors a pending or in-flight cancellation from the currently leased worker, moving the
 * scan cleanly to terminal `CANCELLED` status under lease-token fencing.
 */
export async function cancelScanWithLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();

  const updated = await ScanModel.findOneAndUpdate(
    {
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
      status: {
        $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      },
      isActive: true,
      'lease.token': leaseToken,
      'lease.expiresAt': { $gt: now },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.CANCELLED,
        isActive: false,
        cancelledAt: now,
        lease: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
  }

  const existing = await findScanByIdInOrganization({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return { status: 'STALE_OR_CONFLICT', scan: existing };
}

/**
 * Requests cancellation for a tenant-scoped scan inside an organization transaction lock.
 * - If still `QUEUED`, cancels immediately (`CANCELLED`, `isActive: false`).
 * - If `ACQUIRING` or `IN_PROGRESS`, stamps `cancellation.requestedAt` so the active worker halts safely.
 * - If already terminal, preserves terminal state cleanly.
 */
export async function requestScanCancellation(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  requestedByUserId?: string | null;
  reason?: string | null;
  now?: Date;
}): Promise<RequestCancellationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  if (input.requestedByUserId && !isValidObjectId(input.requestedByUserId)) {
    throw new ScanLifecycleError('Invalid requestedByUserId identifier', 'INVALID_SCAN_IDENTIFIER');
  }

  const now = input.now ?? new Date();
  const safeReason =
    typeof input.reason === 'string' && input.reason.trim().length > 0
      ? redactGitHubSecrets(redactMongoUri(input.reason.trim())).slice(0, 300)
      : null;

  return runInTransaction(async (session) => {
    const locked = await acquireOrganizationMutationLock(input.organizationId, session);
    if (!locked) {
      return { status: 'NOT_FOUND' };
    }

    const existing = await ScanModel.findOne({
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
    }).session(session);

    if (!existing) {
      return { status: 'NOT_FOUND' };
    }

    if (isTerminalScanLifecycleStatus(existing.status)) {
      return {
        status: 'ALREADY_TERMINAL',
        scan: toPublicScanRecord(existing),
      };
    }

    const cancellationPayload = {
      requestedAt: existing.cancellation?.requestedAt ?? now,
      requestedByUserId:
        existing.cancellation?.requestedByUserId ?? input.requestedByUserId ?? null,
      reason: existing.cancellation?.reason ?? safeReason,
    };

    if (existing.status === ScanLifecycleStatusValue.QUEUED) {
      const cancelled = await ScanModel.findOneAndUpdate(
        {
          _id: input.scanId,
          organizationId: input.organizationId,
          projectId: input.projectId,
          status: ScanLifecycleStatusValue.QUEUED,
          isActive: true,
        },
        {
          $set: {
            status: ScanLifecycleStatusValue.CANCELLED,
            isActive: false,
            cancelledAt: now,
            lease: null,
            cancellation: cancellationPayload,
          },
        },
        {
          returnDocument: 'after',
          runValidators: true,
          session,
        }
      );

      if (cancelled) {
        return {
          status: 'CANCELLED_IMMEDIATELY',
          scan: toPublicScanRecord(cancelled),
        };
      }
    }

    const marked = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: {
          $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
        },
        isActive: true,
      },
      {
        $set: {
          cancellation: cancellationPayload,
        },
      },
      {
        returnDocument: 'after',
        runValidators: true,
        session,
      }
    );

    if (!marked) {
      const reloaded = await findScanByIdInOrganization({
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      });
      if (!reloaded) {
        return { status: 'NOT_FOUND' };
      }
      return { status: 'ALREADY_TERMINAL', scan: reloaded };
    }

    return {
      status: 'CANCELLATION_REQUESTED',
      scan: toPublicScanRecord(marked),
    };
  });
}
