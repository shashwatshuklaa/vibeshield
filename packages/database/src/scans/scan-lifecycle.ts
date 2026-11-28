import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { ClientSession } from 'mongoose';
import {
  isTerminalScanLifecycleStatus,
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  type AuthorizedScanAcquisitionContext,
  type PublicScanRecord,
  type ScanAcquisitionMetadata,
  type ScanFailureCode,
  type ScanLifecycleStatus,
  type ScanTriggerSource,
} from '@vibeshield/types';
import { redactMongoUri, runInTransaction } from '../connection.js';
import {
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
} from '../models/github-installation.model.js';
import { acquireOrganizationMutationLock } from '../models/organization.model.js';
import { ProjectModel } from '../models/project.model.js';
import {
  getEffectiveConnectionStatus,
  InstallationAvailabilityValue,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
} from '../models/project-repository-connection.model.js';
import { ScanModel, type ScanAttributes } from '../models/scan.model.js';
import { isValidObjectId } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';
import { ScanLifecycleError, suppressScanDispatchOutboxInSession } from './scan-shared.js';

export { ScanLifecycleError };

export const DEFAULT_SCAN_LEASE_DURATION_MS = 60_000;
const MIN_LEASE_DURATION_MS = 1_000;
const MAX_LEASE_DURATION_MS = 3_600_000;
const FULL_COMMIT_SHA_REGEX = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const SAFE_GITHUB_REPO_SEGMENT_REGEX = /^[A-Za-z0-9._-]+$/;

const ALLOWED_SCAN_TRANSITIONS: Readonly<
  Record<ScanLifecycleStatus, ReadonlySet<ScanLifecycleStatus>>
> = Object.freeze({
  [ScanLifecycleStatusValue.QUEUED]: new Set<ScanLifecycleStatus>([
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.FAILED,
    ScanLifecycleStatusValue.CANCELLED,
  ]),
  [ScanLifecycleStatusValue.ACQUIRING]: new Set<ScanLifecycleStatus>([
    ScanLifecycleStatusValue.QUEUED,
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.PREPARED,
    ScanLifecycleStatusValue.IN_PROGRESS,
    ScanLifecycleStatusValue.FAILED,
    ScanLifecycleStatusValue.CANCELLED,
  ]),
  [ScanLifecycleStatusValue.PREPARED]: new Set<ScanLifecycleStatus>(),
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
    preparedAt: doc.preparedAt ?? null,
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

async function applyOptionalSession<TQuery>(
  query: TQuery,
  session?: ClientSession
): Promise<Awaited<TQuery>> {
  if (session && query && typeof (query as { session?: unknown }).session === 'function') {
    return (await (
      query as unknown as { session(s: ClientSession): Promise<Awaited<TQuery>> }
    ).session(session)) as Awaited<TQuery>;
  }
  return await query;
}

/**
 * Reloads a tenant-scoped scan document (optionally including internal `lease.token` when running
 * against a real Mongoose query) without breaking mocked unit-test queries.
 */
async function findRawScanForFencingCheck(
  input: {
    scanId: string;
    organizationId: string;
    projectId: string;
  },
  session?: ClientSession
): Promise<(ScanAttributes & { _id: { toString(): string } }) | null> {
  const query = ScanModel.findOne({
    _id: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });

  if (query && typeof (query as { select?: unknown }).select === 'function') {
    const selectedQuery = (
      query as unknown as {
        select(fields: string): unknown;
      }
    ).select('+lease.token');
    return (await applyOptionalSession(selectedQuery, session)) as
      (ScanAttributes & { _id: { toString(): string } }) | null;
  }

  return (await applyOptionalSession(query, session)) as
    (ScanAttributes & { _id: { toString(): string } }) | null;
}

function classifyFencedUpdateMiss(input: {
  doc: (ScanAttributes & { _id: { toString(): string } }) | null;
  expectedStatuses: readonly ScanLifecycleStatus[];
  leaseToken: string;
  now: Date;
}): FencedScanMutationResult {
  const { doc, expectedStatuses, leaseToken, now } = input;
  if (!doc) {
    return { status: 'STALE_OR_CONFLICT', scan: null };
  }

  const publicRecord = toPublicScanRecord(doc);
  if (!doc.isActive || !expectedStatuses.includes(doc.status)) {
    return { status: 'STALE_OR_CONFLICT', scan: publicRecord };
  }

  // Require an intact stored lease subdocument and valid fencing token before checking cancellation.
  if (
    !doc.lease ||
    typeof doc.lease.token !== 'string' ||
    !constantTimeTokenMatch(doc.lease.token, leaseToken)
  ) {
    return { status: 'STALE_OR_CONFLICT', scan: publicRecord };
  }
  if (!doc.lease.expiresAt || new Date(doc.lease.expiresAt).getTime() <= now.getTime()) {
    return { status: 'STALE_OR_CONFLICT', scan: publicRecord };
  }

  if (doc.cancellation?.requestedAt !== null && doc.cancellation?.requestedAt !== undefined) {
    return { status: 'CANCEL_REQUESTED', scan: publicRecord };
  }

  return { status: 'STALE_OR_CONFLICT', scan: publicRecord };
}

/**
 * Retrieves a single scan strictly scoped to `(organizationId, projectId)`.
 */
export async function findScanByIdInOrganization(
  input: {
    organizationId: string;
    projectId: string;
    scanId: string;
  },
  session?: ClientSession
): Promise<PublicScanRecord | null> {
  if (
    !isValidObjectId(input.organizationId) ||
    !isValidObjectId(input.projectId) ||
    !isValidObjectId(input.scanId)
  ) {
    return null;
  }

  const doc = (await applyOptionalSession(
    ScanModel.findOne({
      _id: input.scanId,
      organizationId: input.organizationId,
      projectId: input.projectId,
    }),
    session
  )) as (ScanAttributes & { _id: { toString(): string } }) | null;

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
      $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
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
  const cancelledQueued = await runInTransaction(async (session) => {
    const cancelled = await ScanModel.findOneAndUpdate(
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
        session,
      }
    );
    if (cancelled) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
    }
    return cancelled;
  });

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

  return await runInTransaction(async (session) => {
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
        session,
      }
    );

    if (cancelledExpired) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
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
          resolvedCommitSha: null,
          acquisition: null,
          inProgressAt: null,
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
        session,
      }
    );

    if (reclaimed) {
      return {
        status: 'RECLAIMED',
        scan: toPublicScanRecord(reclaimed),
        leaseToken,
      };
    }

    // Fail permanently only if an expired active lease exhausted attempts AND has no pending cancellation.
    const exhausted = await ScanModel.findOneAndUpdate(
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
        session,
      }
    );

    if (exhausted) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return {
        status: 'MAX_ATTEMPTS_EXHAUSTED',
        scan: toPublicScanRecord(exhausted),
      };
    }

    // Handle narrow race where cancellation arrived between initial check and exhausted update.
    const cancelledAfterRace = await ScanModel.findOneAndUpdate(
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
        session,
      }
    );

    if (cancelledAfterRace) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return {
        status: 'CANCELLED',
        scan: toPublicScanRecord(cancelledAfterRace),
      };
    }

    const existing = await findScanByIdInOrganization(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    if (existing && existing.status === ScanLifecycleStatusValue.CANCELLED) {
      return {
        status: 'CANCELLED',
        scan: existing,
      };
    }
    return {
      status: 'NOT_RECLAIMABLE',
      scan: existing,
    };
  });
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
 * Atomically records the resolved immutable full commit SHA on an active leased `ACQUIRING` scan
 * before downloading repository contents, respecting cancellation and lease fencing.
 */
export async function setScanResolvedCommitWithLease(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  resolvedCommitSha: string;
  now?: Date;
}): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const normalizedSha = input.resolvedCommitSha.trim().toLowerCase();
  if (!FULL_COMMIT_SHA_REGEX.test(normalizedSha)) {
    throw new ScanLifecycleError(
      'Resolved commit SHA must be a full 40- or 64-character hex Git SHA',
      'INVALID_COMMIT_SHA'
    );
  }

  const now = input.now ?? new Date();
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
    {
      $set: {
        resolvedCommitSha: normalizedSha,
        'lease.heartbeatAt': now,
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

  const rawExisting = await findRawScanForFencingCheck({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return classifyFencedUpdateMiss({
    doc: rawExisting,
    expectedStatuses: [ScanLifecycleStatusValue.ACQUIRING],
    leaseToken,
    now,
  });
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
    isActive: true,
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

  const rawExisting = await findRawScanForFencingCheck({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  return classifyFencedUpdateMiss({
    doc: rawExisting,
    expectedStatuses: [ScanLifecycleStatusValue.ACQUIRING],
    leaseToken,
    now,
  });
}

/**
 * Atomically transitions an active leased `IN_PROGRESS` scan to `COMPLETED`, clearing the worker lease
 * and suppressing any queued dispatch outbox in the same MongoDB transaction.
 * Refuses completion if cancellation has been requested (`CANCEL_REQUESTED`) or the lease is invalid/stale.
 */
export async function completeScanWithLease(
  input: {
    scanId: string;
    organizationId: string;
    projectId: string;
    leaseToken: string;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();

  const execute = async (session: ClientSession): Promise<FencedScanMutationResult> => {
    const updated = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: ScanLifecycleStatusValue.IN_PROGRESS,
        isActive: true,
        'cancellation.requestedAt': null,
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
        session,
      }
    );

    if (updated) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
    }

    const rawExisting = await findRawScanForFencingCheck(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    return classifyFencedUpdateMiss({
      doc: rawExisting,
      expectedStatuses: [ScanLifecycleStatusValue.IN_PROGRESS],
      leaseToken,
      now,
    });
  };

  if (externalSession) {
    return await execute(externalSession);
  }
  return await runInTransaction(execute);
}

/**
 * Atomically transitions an active leased scan (`ACQUIRING` or `IN_PROGRESS`) to `FAILED` with
 * redacted failure details and suppresses its dispatch outbox inside the same transaction while
 * respecting pending cancellations (`CANCEL_REQUESTED`) and rejecting stale lease tokens.
 */
export async function failScanWithLease(
  input: {
    scanId: string;
    organizationId: string;
    projectId: string;
    leaseToken: string;
    failureCode: ScanFailureCode;
    failureMessage: string;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();
  const safeMessage = redactGitHubSecrets(redactMongoUri(input.failureMessage)).slice(0, 500);

  const execute = async (session: ClientSession): Promise<FencedScanMutationResult> => {
    const updated = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: {
          $in: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
        },
        isActive: true,
        'cancellation.requestedAt': null,
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
        session,
      }
    );

    if (updated) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
    }

    const rawExisting = await findRawScanForFencingCheck(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    return classifyFencedUpdateMiss({
      doc: rawExisting,
      expectedStatuses: [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS],
      leaseToken,
      now,
    });
  };

  if (externalSession) {
    return await execute(externalSession);
  }
  return await runInTransaction(execute);
}

/**
 * Safely honors a pending or in-flight cancellation from the currently leased worker, moving the
 * scan cleanly to terminal `CANCELLED` status and suppressing the dispatch outbox atomically.
 */
export async function cancelScanWithLease(
  input: {
    scanId: string;
    organizationId: string;
    projectId: string;
    leaseToken: string;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<FencedScanMutationResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();

  const execute = async (session: ClientSession): Promise<FencedScanMutationResult> => {
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
        session,
      }
    );

    if (updated) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'UPDATED', scan: toPublicScanRecord(updated) };
    }

    const existing = await findScanByIdInOrganization(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    return { status: 'STALE_OR_CONFLICT', scan: existing };
  };

  if (externalSession) {
    return await execute(externalSession);
  }
  return await runInTransaction(execute);
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
        await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
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
      const reloaded = await ScanModel.findOne({
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      }).session(session);
      if (!reloaded) {
        return { status: 'NOT_FOUND' };
      }
      return { status: 'ALREADY_TERMINAL', scan: toPublicScanRecord(reloaded) };
    }

    return {
      status: 'CANCELLATION_REQUESTED',
      scan: toPublicScanRecord(marked),
    };
  });
}

export type ScanAcquisitionDenialReason =
  | 'SCAN_NOT_FOUND'
  | 'SCAN_NOT_ACQUIRING'
  | 'SCAN_INACTIVE'
  | 'SCAN_CANCELLED'
  | 'INVALID_ATTEMPT_STATE'
  | 'LEASE_MISSING'
  | 'WORKER_MISMATCH'
  | 'INVALID_LEASE_TOKEN'
  | 'LEASE_EXPIRED'
  | 'PROJECT_NOT_FOUND'
  | 'PROJECT_ARCHIVED'
  | 'CONNECTION_NOT_FOUND'
  | 'CONNECTION_INACTIVE'
  | 'CONNECTION_METADATA_MISMATCH'
  | 'INSTALLATION_NOT_FOUND'
  | 'INSTALLATION_UNAVAILABLE'
  | 'INSTALLATION_MISMATCH';

export interface VerifyScanAcquisitionAuthorizationInput {
  scanId: string;
  leaseToken: string;
  workerId: string;
  now?: Date;
}

export type VerifyScanAcquisitionAuthorizationResult =
  | { status: 'AUTHORIZED'; context: AuthorizedScanAcquisitionContext }
  | { status: 'DENIED'; reason: ScanAcquisitionDenialReason; message: string };

function constantTimeTokenMatch(expectedToken: string, providedToken: string): boolean {
  if (expectedToken.length === 0 || providedToken.length === 0) {
    return false;
  }
  const expectedDigest = createHash('sha256').update(expectedToken, 'utf8').digest();
  const providedDigest = createHash('sha256').update(providedToken, 'utf8').digest();
  return timingSafeEqual(expectedDigest, providedDigest);
}

/**
 * Authoritatively verifies whether a leased worker may acquire repository source code for a scan.
 *
 * Security invariants enforced server-side from MongoDB authoritative records:
 * 1. Scan exists, is active, is in `ACQUIRING`, and has no recorded cancellation request.
 * 2. Active attempt count is within `1..maxAttempts`.
 * 3. Scan holds a non-expired lease belonging to `workerId` with constant-time `lease.token` match.
 * 4. Parent Project exists in the same organization and is not archived.
 * 5. Parent ProjectRepositoryConnection exists in the same organization & project, is effectively
 *    `CONNECTED` (`isActive: true`), and matches the scan's GitHub installation & repository IDs.
 * 6. Parent GitHubInstallation exists in the same organization, is `ACTIVE` (`isActive: true`,
 *    not suspended, not revoked), and matches the installation ID on both scan and connection.
 *
 * Note on concurrency: checking across Scan, Project, ProjectRepositoryConnection, and
 * GitHubInstallation leaves a narrow race window if cancellation, lease reclamation, project
 * archival, or installation revocation commits concurrently. Future archive download handlers must
 * re-verify active lease fencing and cancellation immediately before streaming contents or saving
 * acquisition metadata.
 */
export async function verifyScanAcquisitionAuthorization(
  input: VerifyScanAcquisitionAuthorizationInput,
  session?: ClientSession
): Promise<VerifyScanAcquisitionAuthorizationResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const workerId = assertValidWorkerIdentity(input.workerId);
  const now = input.now ?? new Date();

  const scan = await ScanModel.findById(input.scanId)
    .select(
      'organizationId projectId repositoryConnectionId githubInstallationId githubRepositoryId requestedRef requestedCommitHash status isActive attemptCount maxAttempts cancellation.requestedAt lease.workerId lease.expiresAt +lease.token'
    )
    .session(session ?? null)
    .lean();

  if (!scan) {
    return {
      status: 'DENIED',
      reason: 'SCAN_NOT_FOUND',
      message: 'Scan record was not found.',
    };
  }

  if (scan.status !== ScanLifecycleStatusValue.ACQUIRING) {
    return {
      status: 'DENIED',
      reason: 'SCAN_NOT_ACQUIRING',
      message: 'Scan is not currently in ACQUIRING status.',
    };
  }

  if (scan.isActive !== true) {
    return {
      status: 'DENIED',
      reason: 'SCAN_INACTIVE',
      message: 'Scan is no longer active.',
    };
  }

  if (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined) {
    return {
      status: 'DENIED',
      reason: 'SCAN_CANCELLED',
      message: 'Scan cancellation has already been requested.',
    };
  }

  if (
    !Number.isInteger(scan.attemptCount) ||
    !Number.isInteger(scan.maxAttempts) ||
    scan.attemptCount < 1 ||
    scan.attemptCount > scan.maxAttempts
  ) {
    return {
      status: 'DENIED',
      reason: 'INVALID_ATTEMPT_STATE',
      message: 'Scan attempt bounds are invalid.',
    };
  }

  if (
    !scan.lease ||
    typeof scan.lease.workerId !== 'string' ||
    typeof scan.lease.token !== 'string' ||
    !scan.lease.expiresAt
  ) {
    return {
      status: 'DENIED',
      reason: 'LEASE_MISSING',
      message: 'Scan does not hold an active worker lease.',
    };
  }

  if (scan.lease.workerId !== workerId) {
    return {
      status: 'DENIED',
      reason: 'WORKER_MISMATCH',
      message: 'Scan lease belongs to a different worker.',
    };
  }

  const providedLeaseToken = typeof input.leaseToken === 'string' ? input.leaseToken : '';
  if (!constantTimeTokenMatch(scan.lease.token, providedLeaseToken)) {
    return {
      status: 'DENIED',
      reason: 'INVALID_LEASE_TOKEN',
      message: 'Invalid worker lease token.',
    };
  }

  if (new Date(scan.lease.expiresAt).getTime() <= now.getTime()) {
    return {
      status: 'DENIED',
      reason: 'LEASE_EXPIRED',
      message: 'Worker lease has expired.',
    };
  }

  const project = await ProjectModel.findOne(
    {
      _id: scan.projectId,
      organizationId: scan.organizationId,
    },
    {
      _id: 1,
      organizationId: 1,
      archivedAt: 1,
    }
  )
    .session(session ?? null)
    .lean();

  if (!project || project.organizationId.toString() !== scan.organizationId.toString()) {
    return {
      status: 'DENIED',
      reason: 'PROJECT_NOT_FOUND',
      message: 'Parent project was not found in the scan organization.',
    };
  }

  if (project.archivedAt !== null && project.archivedAt !== undefined) {
    return {
      status: 'DENIED',
      reason: 'PROJECT_ARCHIVED',
      message: 'Parent project is archived.',
    };
  }

  const connection = await ProjectRepositoryConnectionModel.findOne(
    {
      _id: scan.repositoryConnectionId,
      organizationId: scan.organizationId,
      projectId: scan.projectId,
    },
    {
      _id: 1,
      organizationId: 1,
      projectId: 1,
      installationRecordId: 1,
      githubInstallationId: 1,
      githubRepositoryId: 1,
      ownerLogin: 1,
      repoName: 1,
      repositoryAccessState: 1,
      installationAvailability: 1,
      isActive: 1,
    }
  )
    .session(session ?? null)
    .lean();

  if (
    !connection ||
    connection.organizationId.toString() !== scan.organizationId.toString() ||
    connection.projectId.toString() !== scan.projectId.toString()
  ) {
    return {
      status: 'DENIED',
      reason: 'CONNECTION_NOT_FOUND',
      message: 'Project repository connection was not found.',
    };
  }

  if (
    connection.isActive !== true ||
    connection.repositoryAccessState !== RepositoryAccessStateValue.CONNECTED ||
    connection.installationAvailability !== InstallationAvailabilityValue.ACTIVE ||
    getEffectiveConnectionStatus(connection) !== 'CONNECTED'
  ) {
    return {
      status: 'DENIED',
      reason: 'CONNECTION_INACTIVE',
      message: 'Project repository connection is not active.',
    };
  }

  const ownerLogin = typeof connection.ownerLogin === 'string' ? connection.ownerLogin.trim() : '';
  const repoName = typeof connection.repoName === 'string' ? connection.repoName.trim() : '';
  const isSafeRepoBinding =
    SAFE_GITHUB_REPO_SEGMENT_REGEX.test(ownerLogin) &&
    SAFE_GITHUB_REPO_SEGMENT_REGEX.test(repoName) &&
    ownerLogin !== '.' &&
    ownerLogin !== '..' &&
    repoName !== '.' &&
    repoName !== '..';

  if (
    !isSafeRepoBinding ||
    connection.githubRepositoryId !== scan.githubRepositoryId ||
    connection.githubInstallationId !== scan.githubInstallationId
  ) {
    return {
      status: 'DENIED',
      reason: 'CONNECTION_METADATA_MISMATCH',
      message: 'Scan repository or installation metadata does not match the active connection.',
    };
  }

  const installation = await GitHubInstallationModel.findOne(
    {
      _id: connection.installationRecordId,
      organizationId: scan.organizationId,
    },
    {
      _id: 1,
      organizationId: 1,
      githubInstallationId: 1,
      status: 1,
      isActive: 1,
      suspendedAt: 1,
      revokedAt: 1,
    }
  )
    .session(session ?? null)
    .lean();

  if (!installation || installation.organizationId.toString() !== scan.organizationId.toString()) {
    return {
      status: 'DENIED',
      reason: 'INSTALLATION_NOT_FOUND',
      message: 'GitHub installation record was not found.',
    };
  }

  if (
    installation.status !== GitHubInstallationStatusValue.ACTIVE ||
    installation.isActive !== true ||
    (installation.suspendedAt !== null && installation.suspendedAt !== undefined) ||
    (installation.revokedAt !== null && installation.revokedAt !== undefined)
  ) {
    return {
      status: 'DENIED',
      reason: 'INSTALLATION_UNAVAILABLE',
      message: 'GitHub installation is suspended, revoked, or inactive.',
    };
  }

  if (
    installation.githubInstallationId !== scan.githubInstallationId ||
    installation.githubInstallationId !== connection.githubInstallationId
  ) {
    return {
      status: 'DENIED',
      reason: 'INSTALLATION_MISMATCH',
      message: 'GitHub installation identifier does not match the authorized scan binding.',
    };
  }

  return {
    status: 'AUTHORIZED',
    context: {
      scanId: scan._id.toString(),
      organizationId: scan.organizationId.toString(),
      projectId: scan.projectId.toString(),
      repositoryConnectionId: scan.repositoryConnectionId.toString(),
      githubInstallationId: installation.githubInstallationId,
      githubRepositoryId: connection.githubRepositoryId,
      repositoryOwner: ownerLogin,
      repositoryName: repoName,
      requestedRef: scan.requestedRef,
      requestedCommitHash: scan.requestedCommitHash ?? null,
      attemptCount: scan.attemptCount,
      maxAttempts: scan.maxAttempts,
      workerId: scan.lease.workerId,
      leaseExpiresAt: scan.lease.expiresAt,
    },
  };
}

export type CompleteAcquisitionPreparedResult =
  | { status: 'PREPARED'; scan: PublicScanRecord }
  | { status: 'CANCEL_REQUESTED'; scan: PublicScanRecord }
  | { status: 'STALE_OR_CONFLICT'; scan: PublicScanRecord | null }
  | { status: 'NOT_FOUND' }
  | { status: 'INVALID_TRANSITION'; currentStatus: ScanLifecycleStatus; scan: PublicScanRecord }
  | { status: 'MISSING_RESOLVED_COMMIT'; scan: PublicScanRecord };

export interface CompleteAcquisitionPreparedInput {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  acquisition: {
    compressedArchiveBytes: number;
    extractedBytes: number;
    extractedFileCount: number;
    acquisitionCompletedAt?: Date;
  };
  now?: Date;
}

function assertNonNegativeIntegerMetric(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new ScanLifecycleError(
      `${fieldName} must be a non-negative integer`,
      'INVALID_ACQUISITION_METRICS'
    );
  }
  return value;
}

/**
 * Atomically transitions an `ACQUIRING` scan to terminal/quiescent `PREPARED` state after
 * defensive repository extraction succeeds.
 *
 * Security invariants:
 * - Reads `resolvedCommitSha` exclusively from the authoritative MongoDB `Scan` document.
 * - Requires matching active lease token (verified in constant time and atomically fenced in MongoDB),
 *   non-expired lease (`expiresAt > now`), and `cancellation.requestedAt === null`.
 * - Sets `isActive = false`, clears `lease = null`, stamps `preparedAt`, and leaves `completedAt = null`.
 */
export async function completeAcquisitionPreparedWithLease(
  input: CompleteAcquisitionPreparedInput,
  externalSession?: ClientSession
): Promise<CompleteAcquisitionPreparedResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const compressedArchiveBytes = assertNonNegativeIntegerMetric(
    input.acquisition.compressedArchiveBytes,
    'compressedArchiveBytes'
  );
  const extractedBytes = assertNonNegativeIntegerMetric(
    input.acquisition.extractedBytes,
    'extractedBytes'
  );
  const extractedFileCount = assertNonNegativeIntegerMetric(
    input.acquisition.extractedFileCount,
    'extractedFileCount'
  );

  const now = input.now ?? new Date();
  const acquisitionCompletedAt = input.acquisition.acquisitionCompletedAt ?? now;

  const inspectCurrent = (
    doc: (ScanAttributes & { _id: { toString(): string } }) | null
  ):
    | CompleteAcquisitionPreparedResult
    | { readyDoc: ScanAttributes & { resolvedCommitSha: string } } => {
    if (!doc) {
      return { status: 'NOT_FOUND' };
    }
    const publicScan = toPublicScanRecord(doc);
    if (doc.status !== ScanLifecycleStatusValue.ACQUIRING || !doc.isActive) {
      return {
        status: 'INVALID_TRANSITION',
        currentStatus: doc.status,
        scan: publicScan,
      };
    }
    if (
      !doc.lease ||
      typeof doc.lease.token !== 'string' ||
      !constantTimeTokenMatch(doc.lease.token, leaseToken) ||
      new Date(doc.lease.expiresAt).getTime() <= now.getTime()
    ) {
      return { status: 'STALE_OR_CONFLICT', scan: publicScan };
    }
    if (doc.cancellation?.requestedAt !== null && doc.cancellation?.requestedAt !== undefined) {
      return { status: 'CANCEL_REQUESTED', scan: publicScan };
    }
    if (
      typeof doc.resolvedCommitSha !== 'string' ||
      !FULL_COMMIT_SHA_REGEX.test(doc.resolvedCommitSha)
    ) {
      return { status: 'MISSING_RESOLVED_COMMIT', scan: publicScan };
    }
    return { readyDoc: doc as ScanAttributes & { resolvedCommitSha: string } };
  };

  const execute = async (session: ClientSession): Promise<CompleteAcquisitionPreparedResult> => {
    const currentDoc = await findRawScanForFencingCheck(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    const preCheck = inspectCurrent(currentDoc);
    if (!('readyDoc' in preCheck)) {
      return preCheck;
    }

    const authoritativeCommitSha = preCheck.readyDoc.resolvedCommitSha;
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
        resolvedCommitSha: authoritativeCommitSha,
      },
      {
        $set: {
          status: ScanLifecycleStatusValue.PREPARED,
          isActive: false,
          preparedAt: now,
          lease: null,
          acquisition: {
            resolvedCommitSha: authoritativeCommitSha,
            compressedArchiveBytes,
            extractedBytes,
            extractedFileCount,
            acquisitionCompletedAt,
          },
        },
      },
      {
        returnDocument: 'after',
        runValidators: true,
        session,
      }
    );

    if (updated) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'PREPARED', scan: toPublicScanRecord(updated) };
    }

    const racedDoc = await findRawScanForFencingCheck(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    const postCheck = inspectCurrent(racedDoc);
    if (!('readyDoc' in postCheck)) {
      return postCheck;
    }
    return { status: 'STALE_OR_CONFLICT', scan: toPublicScanRecord(racedDoc!) };
  };

  if (externalSession) {
    return await execute(externalSession);
  }
  return await runInTransaction(execute);
}

export type ReleaseScanLeaseForRetryResult =
  | { status: 'RELEASED'; scan: PublicScanRecord }
  | { status: 'CANCEL_REQUESTED'; scan: PublicScanRecord }
  | { status: 'ATTEMPTS_EXHAUSTED'; scan: PublicScanRecord }
  | { status: 'STALE_OR_CONFLICT'; scan: PublicScanRecord | null }
  | { status: 'NOT_FOUND' }
  | { status: 'INVALID_TRANSITION'; currentStatus: ScanLifecycleStatus; scan: PublicScanRecord };

/**
 * Voluntarily releases a leased `ACQUIRING` scan back to `QUEUED` after a retryable failure so
 * BullMQ can schedule an immediate exponential-backoff retry without waiting for lease expiry.
 *
 * Distinction across lease mechanisms:
 * - `releaseScanLeaseForRetry`: called by the active leaseholder on transient error; preserves
 *   `attemptCount` & `idempotencyKey`, clears lease/resolvedCommitSha/acquisition, moves `ACQUIRING -> QUEUED`.
 * - `reclaimExpiredScanLease`: called by another worker after `lease.expiresAt <= now` to take over execution
 *   with a rotated `lease.token` and incremented `attemptCount`.
 * - Expired-lease recovery (`recoverExpiredScanLeaseCandidate`): coordinator/sweeper primitive that finalizes
 *   cancelled or attempt-exhausted scans, or resets recoverable stalled scans to `QUEUED` for re-dispatch.
 */
export async function releaseScanLeaseForRetry(input: {
  scanId: string;
  organizationId: string;
  projectId: string;
  leaseToken: string;
  now?: Date;
}): Promise<ReleaseScanLeaseForRetryResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const leaseToken = assertValidLeaseToken(input.leaseToken);
  const now = input.now ?? new Date();

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
      $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
    },
    {
      $set: {
        status: ScanLifecycleStatusValue.QUEUED,
        isActive: true,
        lease: null,
        resolvedCommitSha: null,
        acquisition: null,
        acquiringAt: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'RELEASED', scan: toPublicScanRecord(updated) };
  }

  const rawDoc = await findRawScanForFencingCheck({
    scanId: input.scanId,
    organizationId: input.organizationId,
    projectId: input.projectId,
  });
  if (!rawDoc) {
    return { status: 'NOT_FOUND' };
  }

  const publicScan = toPublicScanRecord(rawDoc);
  if (rawDoc.status !== ScanLifecycleStatusValue.ACQUIRING || !rawDoc.isActive) {
    return {
      status: 'INVALID_TRANSITION',
      currentStatus: rawDoc.status,
      scan: publicScan,
    };
  }
  if (
    !rawDoc.lease ||
    typeof rawDoc.lease.token !== 'string' ||
    !constantTimeTokenMatch(rawDoc.lease.token, leaseToken) ||
    new Date(rawDoc.lease.expiresAt).getTime() <= now.getTime()
  ) {
    return { status: 'STALE_OR_CONFLICT', scan: publicScan };
  }
  if (rawDoc.cancellation?.requestedAt !== null && rawDoc.cancellation?.requestedAt !== undefined) {
    return { status: 'CANCEL_REQUESTED', scan: publicScan };
  }
  if (rawDoc.attemptCount >= rawDoc.maxAttempts) {
    return { status: 'ATTEMPTS_EXHAUSTED', scan: publicScan };
  }

  return { status: 'STALE_OR_CONFLICT', scan: publicScan };
}

export interface ScanExecutionTarget {
  scanId: string;
  organizationId: string;
  projectId: string;
  repositoryConnectionId: string;
  githubInstallationId: number;
  githubRepositoryId: number;
  repositoryOwner: string;
  repositoryName: string;
  requestedRef: string;
  requestedCommitHash: string | null;
  resolvedCommitSha: string | null;
  status: ScanLifecycleStatus;
  isActive: boolean;
  triggerSource: ScanTriggerSource;
  attemptCount: number;
  maxAttempts: number;
  cancellationRequestedAt: Date | null;
  lease: {
    workerId: string;
    acquiredAt: Date;
    heartbeatAt: Date;
    expiresAt: Date;
  } | null;
  queuedAt: Date;
  startedAt: Date | null;
}

export type LoadScanExecutionTargetResult =
  | { status: 'EXECUTABLE'; target: ScanExecutionTarget }
  | { status: 'NOT_FOUND' }
  | {
      status: 'TERMINAL';
      scanId: string;
      organizationId: string;
      projectId: string;
      currentStatus: ScanLifecycleStatus;
    }
  | {
      status: 'CANCEL_REQUESTED';
      scanId: string;
      organizationId: string;
      projectId: string;
      currentStatus: ScanLifecycleStatus;
      attemptCount: number;
      maxAttempts: number;
    }
  | {
      status: 'INVALID_BINDING';
      scanId: string;
      organizationId: string;
      projectId: string;
      currentStatus: ScanLifecycleStatus;
      reason: ScanAcquisitionDenialReason;
      failureCode: ScanFailureCode;
      message: string;
    };

/**
 * Loads the narrow, credential-free authoritative execution target for a worker given only `scanId`.
 * Never selects or exposes `lease.token` or any GitHub credentials. Validates parent project,
 * repository connection, and GitHub installation integrity from authoritative MongoDB references.
 */
export async function loadScanExecutionTarget(
  scanId: string,
  session?: ClientSession
): Promise<LoadScanExecutionTargetResult> {
  if (!isValidObjectId(scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }

  const scan = await ScanModel.findById(scanId)
    .select(
      '_id organizationId projectId repositoryConnectionId githubInstallationId githubRepositoryId requestedRef requestedCommitHash resolvedCommitSha status isActive triggerSource attemptCount maxAttempts cancellation.requestedAt lease.workerId lease.acquiredAt lease.heartbeatAt lease.expiresAt queuedAt startedAt'
    )
    .session(session ?? null)
    .lean();

  if (!scan) {
    return { status: 'NOT_FOUND' };
  }

  const orgId = scan.organizationId.toString();
  const projectId = scan.projectId.toString();

  if (isTerminalScanLifecycleStatus(scan.status) || !scan.isActive) {
    return {
      status: 'TERMINAL',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
    };
  }

  if (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined) {
    return {
      status: 'CANCEL_REQUESTED',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      attemptCount: scan.attemptCount,
      maxAttempts: scan.maxAttempts,
    };
  }

  const project = await ProjectModel.findOne(
    { _id: scan.projectId, organizationId: scan.organizationId },
    { _id: 1, organizationId: 1, archivedAt: 1 }
  )
    .session(session ?? null)
    .lean();

  if (!project || project.organizationId.toString() !== orgId) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'PROJECT_NOT_FOUND',
      failureCode: ScanFailureCodeValue.PROJECT_NOT_FOUND,
      message: 'Parent project was not found in the scan organization.',
    };
  }

  if (project.archivedAt !== null && project.archivedAt !== undefined) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'PROJECT_ARCHIVED',
      failureCode: ScanFailureCodeValue.PROJECT_ARCHIVED,
      message: 'Parent project is archived.',
    };
  }

  const connection = await ProjectRepositoryConnectionModel.findOne(
    {
      _id: scan.repositoryConnectionId,
      organizationId: scan.organizationId,
      projectId: scan.projectId,
    },
    {
      _id: 1,
      organizationId: 1,
      projectId: 1,
      installationRecordId: 1,
      githubInstallationId: 1,
      githubRepositoryId: 1,
      ownerLogin: 1,
      repoName: 1,
      repositoryAccessState: 1,
      installationAvailability: 1,
      isActive: 1,
    }
  )
    .session(session ?? null)
    .lean();

  if (
    !connection ||
    connection.organizationId.toString() !== orgId ||
    connection.projectId.toString() !== projectId
  ) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'CONNECTION_NOT_FOUND',
      failureCode: ScanFailureCodeValue.REPOSITORY_DISCONNECTED,
      message: 'Project repository connection was not found.',
    };
  }

  const effectiveConnStatus = getEffectiveConnectionStatus(connection);
  if (connection.isActive !== true || effectiveConnStatus !== 'CONNECTED') {
    const failureCode =
      effectiveConnStatus === 'REPO_DELETED'
        ? ScanFailureCodeValue.REPOSITORY_DELETED
        : effectiveConnStatus === 'ACCESS_REVOKED'
          ? ScanFailureCodeValue.REPOSITORY_ACCESS_REVOKED
          : effectiveConnStatus === 'INSTALLATION_SUSPENDED'
            ? ScanFailureCodeValue.INSTALLATION_SUSPENDED
            : ScanFailureCodeValue.REPOSITORY_DISCONNECTED;
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'CONNECTION_INACTIVE',
      failureCode,
      message: 'Project repository connection is not active.',
    };
  }

  const ownerLogin = typeof connection.ownerLogin === 'string' ? connection.ownerLogin.trim() : '';
  const repoName = typeof connection.repoName === 'string' ? connection.repoName.trim() : '';
  const isSafeBinding =
    SAFE_GITHUB_REPO_SEGMENT_REGEX.test(ownerLogin) &&
    SAFE_GITHUB_REPO_SEGMENT_REGEX.test(repoName) &&
    ownerLogin !== '.' &&
    ownerLogin !== '..' &&
    repoName !== '.' &&
    repoName !== '..';

  if (
    !isSafeBinding ||
    connection.githubRepositoryId !== scan.githubRepositoryId ||
    connection.githubInstallationId !== scan.githubInstallationId
  ) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'CONNECTION_METADATA_MISMATCH',
      failureCode: ScanFailureCodeValue.REPOSITORY_DISCONNECTED,
      message: 'Scan repository or installation binding does not match active connection.',
    };
  }

  const installation = await GitHubInstallationModel.findOne(
    {
      _id: connection.installationRecordId,
      organizationId: scan.organizationId,
    },
    {
      _id: 1,
      organizationId: 1,
      githubInstallationId: 1,
      status: 1,
      isActive: 1,
      suspendedAt: 1,
      revokedAt: 1,
    }
  )
    .session(session ?? null)
    .lean();

  if (!installation || installation.organizationId.toString() !== orgId) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'INSTALLATION_NOT_FOUND',
      failureCode: ScanFailureCodeValue.INSTALLATION_NOT_FOUND,
      message: 'GitHub installation record was not found.',
    };
  }

  if (
    installation.status !== GitHubInstallationStatusValue.ACTIVE ||
    installation.isActive !== true ||
    (installation.suspendedAt !== null && installation.suspendedAt !== undefined) ||
    (installation.revokedAt !== null && installation.revokedAt !== undefined)
  ) {
    const failureCode =
      installation.status === GitHubInstallationStatusValue.SUSPENDED
        ? ScanFailureCodeValue.INSTALLATION_SUSPENDED
        : ScanFailureCodeValue.INSTALLATION_REVOKED;
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'INSTALLATION_UNAVAILABLE',
      failureCode,
      message: 'GitHub installation is suspended, revoked, or inactive.',
    };
  }

  if (
    installation.githubInstallationId !== scan.githubInstallationId ||
    installation.githubInstallationId !== connection.githubInstallationId
  ) {
    return {
      status: 'INVALID_BINDING',
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      currentStatus: scan.status,
      reason: 'INSTALLATION_MISMATCH',
      failureCode: ScanFailureCodeValue.INSTALLATION_REVOKED,
      message: 'GitHub installation identifier does not match the authorized scan binding.',
    };
  }

  return {
    status: 'EXECUTABLE',
    target: {
      scanId: scan._id.toString(),
      organizationId: orgId,
      projectId,
      repositoryConnectionId: scan.repositoryConnectionId.toString(),
      githubInstallationId: installation.githubInstallationId,
      githubRepositoryId: connection.githubRepositoryId,
      repositoryOwner: ownerLogin,
      repositoryName: repoName,
      requestedRef: scan.requestedRef,
      requestedCommitHash: scan.requestedCommitHash ?? null,
      resolvedCommitSha: scan.resolvedCommitSha ?? null,
      status: scan.status,
      isActive: scan.isActive,
      triggerSource: scan.triggerSource,
      attemptCount: scan.attemptCount,
      maxAttempts: scan.maxAttempts,
      cancellationRequestedAt: scan.cancellation?.requestedAt ?? null,
      lease: scan.lease
        ? {
            workerId: scan.lease.workerId,
            acquiredAt: scan.lease.acquiredAt,
            heartbeatAt: scan.lease.heartbeatAt,
            expiresAt: scan.lease.expiresAt,
          }
        : null,
      queuedAt: scan.queuedAt,
      startedAt: scan.startedAt ?? null,
    },
  };
}

export interface ExpiredScanLeaseCandidate {
  scanId: string;
  organizationId: string;
  projectId: string;
  status: ScanLifecycleStatus;
  attemptCount: number;
  maxAttempts: number;
  cancellationRequestedAt: Date | null;
  leaseWorkerId: string;
  leaseExpiresAt: Date;
}

/**
 * Returns a bounded batch of expired active `ACQUIRING` / `IN_PROGRESS` scans backed by the
 * `scans_active_lease_expires_idx` index, never selecting `lease.token`.
 */
export async function findExpiredActiveScanLeaseCandidates(
  input: {
    limit?: number;
    statuses?: readonly ScanLifecycleStatus[];
    now?: Date;
  } = {}
): Promise<ExpiredScanLeaseCandidate[]> {
  const limit = Math.min(Math.max(Math.trunc(input.limit ?? 25), 1), 100);
  const now = input.now ?? new Date();
  const targetStatuses = input.statuses ?? [
    ScanLifecycleStatusValue.ACQUIRING,
    ScanLifecycleStatusValue.IN_PROGRESS,
  ];

  const docs = await ScanModel.find({
    isActive: true,
    status: { $in: targetStatuses },
    'lease.expiresAt': { $lte: now },
  })
    .select(
      '_id organizationId projectId status attemptCount maxAttempts cancellation.requestedAt lease.workerId lease.expiresAt'
    )
    .sort({ 'lease.expiresAt': 1 })
    .limit(limit)
    .lean();

  return docs
    .filter((doc) => doc.lease && doc.lease.expiresAt)
    .map((doc) => ({
      scanId: doc._id.toString(),
      organizationId: doc.organizationId.toString(),
      projectId: doc.projectId.toString(),
      status: doc.status,
      attemptCount: doc.attemptCount,
      maxAttempts: doc.maxAttempts,
      cancellationRequestedAt: doc.cancellation?.requestedAt ?? null,
      leaseWorkerId: doc.lease!.workerId,
      leaseExpiresAt: doc.lease!.expiresAt,
    }));
}

export type RecoverExpiredScanLeaseResult =
  | { status: 'REQUEUED_FOR_RECOVERY'; scan: PublicScanRecord }
  | { status: 'FINALIZED_CANCELLED'; scan: PublicScanRecord }
  | { status: 'FINALIZED_EXHAUSTED'; scan: PublicScanRecord }
  | { status: 'ALREADY_HANDLED'; scan: PublicScanRecord | null };

/**
 * Atomically recovers a single expired active scan (`ACQUIRING` / `IN_PROGRESS`) under concurrent
 * sweepers by fencing strictly on `isActive: true` and `'lease.expiresAt': { $lte: now }`.
 * Clears/invalidates the expired worker lease so stale workers are permanently fenced afterward.
 */
export async function recoverExpiredScanLeaseCandidate(
  input: {
    scanId: string;
    organizationId: string;
    projectId: string;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<RecoverExpiredScanLeaseResult> {
  assertValidIds(input.organizationId, input.projectId, input.scanId);
  const now = input.now ?? new Date();
  const activeStatuses = [ScanLifecycleStatusValue.ACQUIRING, ScanLifecycleStatusValue.IN_PROGRESS];

  const execute = async (session: ClientSession): Promise<RecoverExpiredScanLeaseResult> => {
    const cancelled = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: { $in: activeStatuses },
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
        session,
      }
    );

    if (cancelled) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'FINALIZED_CANCELLED', scan: toPublicScanRecord(cancelled) };
    }

    const exhausted = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: { $in: activeStatuses },
        isActive: true,
        'cancellation.requestedAt': null,
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
        session,
      }
    );

    if (exhausted) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'FINALIZED_EXHAUSTED', scan: toPublicScanRecord(exhausted) };
    }

    const requeued = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: { $in: activeStatuses },
        isActive: true,
        'cancellation.requestedAt': null,
        'lease.expiresAt': { $lte: now },
        $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
      },
      {
        $set: {
          status: ScanLifecycleStatusValue.QUEUED,
          isActive: true,
          lease: null,
          resolvedCommitSha: null,
          acquisition: null,
          acquiringAt: null,
          inProgressAt: null,
        },
      },
      {
        returnDocument: 'after',
        runValidators: true,
        session,
      }
    );

    if (requeued) {
      return { status: 'REQUEUED_FOR_RECOVERY', scan: toPublicScanRecord(requeued) };
    }

    // Catch narrow race where cancellation landed after the initial check and before exhausted/requeued updates.
    const cancelledAfterRace = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
        status: { $in: activeStatuses },
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
        session,
      }
    );

    if (cancelledAfterRace) {
      await suppressScanDispatchOutboxInSession({ scanId: input.scanId, now }, session);
      return { status: 'FINALIZED_CANCELLED', scan: toPublicScanRecord(cancelledAfterRace) };
    }

    const existing = await findScanByIdInOrganization(
      {
        scanId: input.scanId,
        organizationId: input.organizationId,
        projectId: input.projectId,
      },
      session
    );
    return { status: 'ALREADY_HANDLED', scan: existing };
  };

  if (externalSession) {
    return await execute(externalSession);
  }
  return await runInTransaction(execute);
}

export interface ListScansPagedInput {
  organizationId: string;
  projectId: string;
  status?: ScanLifecycleStatus;
  triggerSource?: ScanTriggerSource;
  page: number;
  limit: number;
}

export interface ListScansPagedResult {
  scans: PublicScanRecord[];
  total: number;
}

/**
 * Returns a paginated, tenant-scoped slice of scans for a project, ordered newest-first.
 * Uses `{ createdAt: -1, _id: -1 }` for deterministic ordering when timestamps collide.
 * Both `status` and `triggerSource` filters are optional and independently composable.
 * Returns an empty result (never throws) for invalid ObjectIds.
 */
export async function listScansPagedByProjectInOrganization(
  input: ListScansPagedInput
): Promise<ListScansPagedResult> {
  if (!isValidObjectId(input.organizationId) || !isValidObjectId(input.projectId)) {
    return { scans: [], total: 0 };
  }

  const page = Math.max(Math.trunc(input.page), 1);
  const limit = Math.min(Math.max(Math.trunc(input.limit), 1), 100);
  const skip = (page - 1) * limit;

  const filter: Record<string, unknown> = {
    organizationId: input.organizationId,
    projectId: input.projectId,
  };
  if (input.status) {
    filter.status = input.status;
  }
  if (input.triggerSource) {
    filter.triggerSource = input.triggerSource;
  }

  const [docs, total] = await Promise.all([
    ScanModel.find(filter).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(limit),
    ScanModel.countDocuments(filter),
  ]);

  return {
    scans: docs.map(toPublicScanRecord),
    total,
  };
}
