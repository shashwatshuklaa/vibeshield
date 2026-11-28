import type { ClientSession } from 'mongoose';
import { isTerminalScanLifecycleStatus, type PublicScanRecord } from '@vibeshield/types';
import { redactMongoUri, runInTransaction } from '../connection.js';
import {
  OutboxDispatchStateValue,
  ScanDispatchOutboxModel,
  type OutboxDispatchState,
  type ScanDispatchOutboxAttributes,
} from '../models/scan-dispatch-outbox.model.js';
import { ScanModel } from '../models/scan.model.js';
import { isValidObjectId } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';
import {
  createQueuedScan,
  ScanLifecycleError,
  type CreateQueuedScanInput,
} from './scan-lifecycle.js';

export interface PublicScanDispatchOutboxRecord {
  id: string;
  scanId: string;
  organizationId: string;
  projectId: string;
  state: OutboxDispatchState;
  attempts: number;
  dispatchGeneration: number;
  jobId: string;
  nextAttemptAt: Date;
  lastError: string | null;
  dispatchedAt: Date | null;
  suppressedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export function formatScanDispatchJobId(scanId: string, dispatchGeneration: number): string {
  if (!isValidObjectId(scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  if (
    !Number.isSafeInteger(dispatchGeneration) ||
    dispatchGeneration < 1 ||
    dispatchGeneration > 1_000_000
  ) {
    throw new ScanLifecycleError(
      'dispatchGeneration must be an integer between 1 and 1000000',
      'INVALID_DISPATCH_GENERATION'
    );
  }
  return `scan-${scanId.toLowerCase()}-${dispatchGeneration}`;
}

export function toPublicScanDispatchOutboxRecord(
  doc: ScanDispatchOutboxAttributes & { _id: { toString(): string } }
): PublicScanDispatchOutboxRecord {
  const scanId = doc.scanId.toString();
  return {
    id: doc._id.toString(),
    scanId,
    organizationId: doc.organizationId.toString(),
    projectId: doc.projectId.toString(),
    state: doc.state,
    attempts: doc.attempts,
    dispatchGeneration: doc.dispatchGeneration,
    jobId: formatScanDispatchJobId(scanId, doc.dispatchGeneration),
    nextAttemptAt: doc.nextAttemptAt,
    lastError: doc.lastError ?? null,
    dispatchedAt: doc.dispatchedAt ?? null,
    suppressedAt: doc.suppressedAt ?? null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

function assertValidGeneration(generation: number): number {
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > 1_000_000) {
    throw new ScanLifecycleError(
      'dispatchGeneration must be a positive integer',
      'INVALID_DISPATCH_GENERATION'
    );
  }
  return generation;
}

function sanitizeErrorSummary(message: string): string {
  return redactGitHubSecrets(redactMongoUri(message.trim())).slice(0, 500);
}

export interface CreateQueuedScanWithOutboxResult {
  scan: PublicScanRecord;
  outbox: PublicScanDispatchOutboxRecord;
  jobId: string;
}

/**
 * Atomically creates both a `QUEUED` persistent scan and its initial `PENDING` dispatch outbox
 * record (`dispatchGeneration: 1`) inside one MongoDB transaction so neither can commit alone.
 */
export async function createQueuedScanWithOutbox(
  input: CreateQueuedScanInput,
  externalSession?: ClientSession
): Promise<CreateQueuedScanWithOutboxResult> {
  const execute = async (session: ClientSession): Promise<CreateQueuedScanWithOutboxResult> => {
    const now = input.now ?? new Date();
    const scan = await createQueuedScan({ ...input, now }, session);

    const [outboxDoc] = await ScanDispatchOutboxModel.create(
      [
        {
          scanId: scan.id,
          organizationId: scan.organizationId,
          projectId: scan.projectId,
          state: OutboxDispatchStateValue.PENDING,
          attempts: 0,
          dispatchGeneration: 1,
          nextAttemptAt: now,
          lastError: null,
          dispatchedAt: null,
          suppressedAt: null,
        },
      ],
      { session }
    );

    if (!outboxDoc) {
      throw new ScanLifecycleError(
        'Failed to create scan dispatch outbox record',
        'OUTBOX_CREATE_FAILED'
      );
    }

    const outbox = toPublicScanDispatchOutboxRecord(outboxDoc);
    return {
      scan,
      outbox,
      jobId: outbox.jobId,
    };
  };

  if (externalSession) {
    return await execute(externalSession);
  }

  return await runInTransaction(execute);
}

/**
 * Queries bounded pending/retryable outbox entries whose `nextAttemptAt <= now`.
 */
export async function findPendingScanDispatchOutboxCandidates(
  input: {
    limit?: number;
    now?: Date;
  } = {}
): Promise<PublicScanDispatchOutboxRecord[]> {
  const limit = Math.min(Math.max(Math.trunc(input.limit ?? 50), 1), 100);
  const now = input.now ?? new Date();

  const docs = await ScanDispatchOutboxModel.find({
    state: OutboxDispatchStateValue.PENDING,
    nextAttemptAt: { $lte: now },
  })
    .sort({ nextAttemptAt: 1 })
    .limit(limit);

  return docs.map(toPublicScanDispatchOutboxRecord);
}

export type ClaimPendingScanDispatchResult =
  | { status: 'CLAIMED'; outbox: PublicScanDispatchOutboxRecord; jobId: string }
  | { status: 'SUPPRESSED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_OR_CONFLICT' }
  | { status: 'NOT_FOUND' };

/**
 * Atomically claims a `PENDING` outbox record for dispatch in a given `dispatchGeneration`,
 * bumping `nextAttemptAt` by `claimWindowMs` and incrementing `attempts`. Automatically suppresses
 * dispatch if the referenced Scan has been cancelled, terminated, or removed.
 */
export async function claimPendingScanDispatch(input: {
  scanId: string;
  dispatchGeneration: number;
  claimWindowMs?: number;
  now?: Date;
}): Promise<ClaimPendingScanDispatchResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const generation = assertValidGeneration(input.dispatchGeneration);
  const claimWindowMs = Math.min(
    Math.max(Math.trunc(input.claimWindowMs ?? 30_000), 1_000),
    300_000
  );
  const now = input.now ?? new Date();
  const nextClaimExpiry = new Date(now.getTime() + claimWindowMs);

  const claimed = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
      nextAttemptAt: { $lte: now },
    },
    {
      $set: {
        nextAttemptAt: nextClaimExpiry,
      },
      $inc: {
        attempts: 1,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (!claimed) {
    const existing = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId });
    return existing ? { status: 'STALE_OR_CONFLICT' } : { status: 'NOT_FOUND' };
  }

  const scan = await ScanModel.findOne({
    _id: input.scanId,
    organizationId: claimed.organizationId,
    projectId: claimed.projectId,
  })
    .select('_id status isActive cancellation.requestedAt')
    .lean();

  if (
    !scan ||
    !scan.isActive ||
    isTerminalScanLifecycleStatus(scan.status) ||
    (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined)
  ) {
    const suppressed = await suppressScanDispatchOutbox({
      scanId: input.scanId,
      dispatchGeneration: generation,
      now,
    });
    if (suppressed.status === 'SUPPRESSED') {
      return { status: 'SUPPRESSED', outbox: suppressed.outbox };
    }
    return { status: 'STALE_OR_CONFLICT' };
  }

  const publicOutbox = toPublicScanDispatchOutboxRecord(claimed);
  return {
    status: 'CLAIMED',
    outbox: publicOutbox,
    jobId: publicOutbox.jobId,
  };
}

export type MarkScanDispatchSucceededResult =
  | { status: 'DISPATCHED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Marks a `PENDING` outbox record as `DISPATCHED`, strictly fenced by `dispatchGeneration` so an
 * older dispatcher cannot overwrite a newer re-armed dispatch generation.
 */
export async function markScanDispatchSucceeded(input: {
  scanId: string;
  dispatchGeneration: number;
  now?: Date;
}): Promise<MarkScanDispatchSucceededResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const generation = assertValidGeneration(input.dispatchGeneration);
  const now = input.now ?? new Date();

  const updated = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
    },
    {
      $set: {
        state: OutboxDispatchStateValue.DISPATCHED,
        dispatchedAt: now,
        suppressedAt: null,
        lastError: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'DISPATCHED', outbox: toPublicScanDispatchOutboxRecord(updated) };
  }

  const existing = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId });
  return existing ? { status: 'STALE_GENERATION' } : { status: 'NOT_FOUND' };
}

export type RecordScanDispatchFailureResult =
  | { status: 'SCHEDULED_RETRY'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Records a safe, credential-redacted error on a `PENDING` outbox entry and schedules the next
 * retry attempt while fenced by `dispatchGeneration`.
 */
export async function recordScanDispatchFailure(input: {
  scanId: string;
  dispatchGeneration: number;
  errorMessage: string;
  retryDelayMs?: number;
  now?: Date;
}): Promise<RecordScanDispatchFailureResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const generation = assertValidGeneration(input.dispatchGeneration);
  const retryDelayMs = Math.min(Math.max(Math.trunc(input.retryDelayMs ?? 5_000), 100), 3_600_000);
  const now = input.now ?? new Date();
  const nextAttemptAt = new Date(now.getTime() + retryDelayMs);

  const updated = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
    },
    {
      $set: {
        lastError: sanitizeErrorSummary(input.errorMessage),
        nextAttemptAt,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (updated) {
    return { status: 'SCHEDULED_RETRY', outbox: toPublicScanDispatchOutboxRecord(updated) };
  }

  const existing = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId });
  return existing ? { status: 'STALE_GENERATION' } : { status: 'NOT_FOUND' };
}

export type SuppressScanDispatchOutboxResult =
  | { status: 'SUPPRESSED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Marks a scan's outbox record `SUPPRESSED` when its scan reaches a terminal or cancelled state.
 */
export async function suppressScanDispatchOutbox(
  input: {
    scanId: string;
    dispatchGeneration?: number;
    now?: Date;
  },
  session?: ClientSession
): Promise<SuppressScanDispatchOutboxResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const now = input.now ?? new Date();
  const filter: Record<string, unknown> = {
    scanId: input.scanId,
  };
  if (input.dispatchGeneration !== undefined) {
    filter.dispatchGeneration = assertValidGeneration(input.dispatchGeneration);
  }

  const updated = await ScanDispatchOutboxModel.findOneAndUpdate(
    filter,
    {
      $set: {
        state: OutboxDispatchStateValue.SUPPRESSED,
        suppressedAt: now,
        dispatchedAt: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
      ...(session ? { session } : {}),
    }
  );

  if (updated) {
    return { status: 'SUPPRESSED', outbox: toPublicScanDispatchOutboxRecord(updated) };
  }

  const existing = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId }).session(
    session ?? null
  );
  return existing ? { status: 'STALE_GENERATION' } : { status: 'NOT_FOUND' };
}

export type RearmScanDispatchOutboxResult =
  | { status: 'REARMED'; outbox: PublicScanDispatchOutboxRecord; jobId: string }
  | { status: 'SUPPRESSED_TERMINAL'; outbox: PublicScanDispatchOutboxRecord | null }
  | { status: 'STALE_OR_CONFLICT' }
  | { status: 'NOT_FOUND' };

/**
 * Safely re-arms the scan's unique outbox record for a new `dispatchGeneration` (`dispatchGeneration + 1`),
 * enabling recovery when a previously dispatched BullMQ job was dropped while the scan remains `QUEUED`.
 * Suppresses instead of re-arming if the associated scan is cancelled, inactive, or terminal.
 */
export async function rearmScanDispatchOutbox(
  input: {
    scanId: string;
    expectedGeneration?: number;
    nextAttemptAt?: Date;
    now?: Date;
  },
  session?: ClientSession
): Promise<RearmScanDispatchOutboxResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const now = input.now ?? new Date();
  const nextAttemptAt = input.nextAttemptAt ?? now;

  const existingOutbox = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId }).session(
    session ?? null
  );
  if (!existingOutbox) {
    return { status: 'NOT_FOUND' };
  }

  const scan = await ScanModel.findOne({
    _id: input.scanId,
    organizationId: existingOutbox.organizationId,
    projectId: existingOutbox.projectId,
  })
    .select('_id status isActive cancellation.requestedAt')
    .session(session ?? null)
    .lean();

  if (
    !scan ||
    !scan.isActive ||
    isTerminalScanLifecycleStatus(scan.status) ||
    (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined)
  ) {
    const sup = await suppressScanDispatchOutbox({ scanId: input.scanId, now }, session);
    return {
      status: 'SUPPRESSED_TERMINAL',
      outbox:
        sup.status === 'SUPPRESSED' ? sup.outbox : toPublicScanDispatchOutboxRecord(existingOutbox),
    };
  }

  if (scan.status !== 'QUEUED') {
    return { status: 'STALE_OR_CONFLICT' };
  }

  const filter: Record<string, unknown> = {
    scanId: input.scanId,
    state: { $ne: OutboxDispatchStateValue.SUPPRESSED },
  };
  if (input.expectedGeneration !== undefined) {
    filter.dispatchGeneration = assertValidGeneration(input.expectedGeneration);
  } else {
    filter.dispatchGeneration = existingOutbox.dispatchGeneration;
  }

  const rearmed = await ScanDispatchOutboxModel.findOneAndUpdate(
    filter,
    {
      $set: {
        state: OutboxDispatchStateValue.PENDING,
        nextAttemptAt,
        dispatchedAt: null,
        suppressedAt: null,
        lastError: null,
      },
      $inc: {
        dispatchGeneration: 1,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
      ...(session ? { session } : {}),
    }
  );

  if (!rearmed) {
    return { status: 'STALE_OR_CONFLICT' };
  }

  const outbox = toPublicScanDispatchOutboxRecord(rearmed);
  return {
    status: 'REARMED',
    outbox,
    jobId: outbox.jobId,
  };
}
