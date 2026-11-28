import type { ClientSession } from 'mongoose';
import {
  isTerminalScanLifecycleStatus,
  ScanLifecycleStatusValue,
  type PublicScanRecord,
} from '@vibeshield/types';
import { redactMongoUri, runInTransaction } from '../connection.js';
import {
  OutboxDispatchStateValue,
  ScanDispatchOutboxModel,
} from '../models/scan-dispatch-outbox.model.js';
import { ScanModel } from '../models/scan.model.js';
import { isValidObjectId } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';
import { createQueuedScan, type CreateQueuedScanInput } from './scan-lifecycle.js';
import {
  assertValidGeneration,
  formatScanDispatchJobId,
  generateOutboxClaimToken,
  MAX_DISPATCH_GENERATION,
  MAX_OUTBOX_ATTEMPTS,
  ScanLifecycleError,
  suppressScanDispatchOutboxInSession,
  toPublicScanDispatchOutboxRecord,
  type PublicScanDispatchOutboxRecord,
  type SuppressScanDispatchOutboxResult,
} from './scan-shared.js';

export {
  formatScanDispatchJobId,
  MAX_DISPATCH_GENERATION,
  MAX_OUTBOX_ATTEMPTS,
  toPublicScanDispatchOutboxRecord,
  type PublicScanDispatchOutboxRecord,
  type SuppressScanDispatchOutboxResult,
};

const MIN_OUTBOX_CLAIM_TOKEN_LENGTH = 16;
const MAX_OUTBOX_CLAIM_TOKEN_LENGTH = 128;

function sanitizeErrorSummary(message: string): string {
  return redactGitHubSecrets(redactMongoUri(message.trim())).slice(0, 500);
}

function assertValidClaimToken(claimToken: string): string {
  if (typeof claimToken !== 'string') {
    throw new ScanLifecycleError(
      'Invalid outbox claim fencing token',
      'INVALID_OUTBOX_CLAIM_TOKEN'
    );
  }
  const trimmed = claimToken.trim();
  if (
    trimmed.length < MIN_OUTBOX_CLAIM_TOKEN_LENGTH ||
    claimToken.length > MAX_OUTBOX_CLAIM_TOKEN_LENGTH
  ) {
    throw new ScanLifecycleError(
      'Invalid outbox claim fencing token',
      'INVALID_OUTBOX_CLAIM_TOKEN'
    );
  }
  return claimToken;
}

async function applySession<TQuery>(
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
          claimToken: null,
          nextAttemptAt: now,
          lastError: null,
          dispatchedAt: null,
          suppressedAt: null,
          exhaustedAt: null,
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
 * Queries bounded pending/retryable outbox entries whose `nextAttemptAt <= now` and
 * `attempts < MAX_OUTBOX_ATTEMPTS`, never returning exhausted records or exposing `claimToken`.
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
    attempts: { $lt: MAX_OUTBOX_ATTEMPTS },
  })
    .sort({ nextAttemptAt: 1 })
    .limit(limit);

  return docs.map(toPublicScanDispatchOutboxRecord);
}

/**
 * Queries bounded outbox entries that have reached `EXHAUSTED` state so future reconcilers or
 * operators can inspect and fail or explicitly recover permanently failing dispatches.
 */
export async function findExhaustedScanDispatchOutboxCandidates(
  input: {
    limit?: number;
  } = {}
): Promise<PublicScanDispatchOutboxRecord[]> {
  const limit = Math.min(Math.max(Math.trunc(input.limit ?? 50), 1), 100);

  const docs = await ScanDispatchOutboxModel.find({
    state: OutboxDispatchStateValue.EXHAUSTED,
  })
    .sort({ exhaustedAt: 1 })
    .limit(limit);

  return docs.map(toPublicScanDispatchOutboxRecord);
}

/**
 * Queries bounded `PENDING` outbox entries whose `attempts >= MAX_OUTBOX_ATTEMPTS` and whose
 * claim window has expired (`nextAttemptAt <= now`), e.g. when a dispatcher crashed on its final
 * attempt before recording failure.
 */
export async function findExpiredMaxAttemptPendingOutboxCandidates(
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
    attempts: { $gte: MAX_OUTBOX_ATTEMPTS },
  })
    .sort({ nextAttemptAt: 1 })
    .limit(limit);

  return docs.map(toPublicScanDispatchOutboxRecord);
}

export type FinalizeExpiredMaxAttemptOutboxResult =
  | { status: 'FINALIZED_EXHAUSTED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'NOT_ELIGIBLE'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'NOT_FOUND' };

/**
 * Atomically finalizes an abandoned `PENDING` outbox record whose `attempts >= MAX_OUTBOX_ATTEMPTS`
 * and whose claim window has expired (`nextAttemptAt <= now`) into `EXHAUSTED`, clearing any stale
 * `claimToken` while preserving existing sanitized diagnostics and refusing to modify unexpired,
 * sub-maximum, dispatched, suppressed, or generation-mismatched records.
 */
export async function finalizeExpiredMaxAttemptOutboxCandidate(
  input: {
    scanId: string;
    dispatchGeneration?: number;
    now?: Date;
  },
  session?: ClientSession
): Promise<FinalizeExpiredMaxAttemptOutboxResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const now = input.now ?? new Date();
  const filter: Record<string, unknown> = {
    scanId: input.scanId,
    state: OutboxDispatchStateValue.PENDING,
    attempts: { $gte: MAX_OUTBOX_ATTEMPTS },
    nextAttemptAt: { $lte: now },
  };
  if (input.dispatchGeneration !== undefined) {
    filter.dispatchGeneration = assertValidGeneration(input.dispatchGeneration);
  }

  const finalized = await ScanDispatchOutboxModel.findOneAndUpdate(
    filter,
    {
      $set: {
        state: OutboxDispatchStateValue.EXHAUSTED,
        exhaustedAt: now,
        dispatchedAt: null,
        suppressedAt: null,
        claimToken: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
      ...(session ? { session } : {}),
    }
  );

  if (finalized) {
    return {
      status: 'FINALIZED_EXHAUSTED',
      outbox: toPublicScanDispatchOutboxRecord(finalized),
    };
  }

  const existing = await applySession(
    ScanDispatchOutboxModel.findOne({ scanId: input.scanId }),
    session
  );
  if (!existing) {
    return { status: 'NOT_FOUND' };
  }
  return {
    status: 'NOT_ELIGIBLE',
    outbox: toPublicScanDispatchOutboxRecord(existing),
  };
}

export type ClaimPendingScanDispatchResult =
  | {
      status: 'CLAIMED';
      outbox: PublicScanDispatchOutboxRecord;
      jobId: string;
      claimToken: string;
    }
  | { status: 'SUPPRESSED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'EXHAUSTED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_OR_CONFLICT' }
  | { status: 'NOT_FOUND' };

/**
 * Atomically claims a `PENDING` outbox record for dispatch in a given `dispatchGeneration` inside a
 * MongoDB transaction:
 * - Only authorizes enqueueing when the authoritative `Scan` is `QUEUED`, `isActive: true`,
 *   uncancelled, and `attemptCount < maxAttempts` (never dispatching while `ACQUIRING`/`IN_PROGRESS`).
 * - Fences against concurrent `Scan` transitions using `$inc: { dispatchRevision: 1 }` on `ScanModel`,
 *   forcing MongoDB `WriteConflict` retries under snapshot isolation instead of write skew.
 * - Never increments `attempts` when the scan is cancelled, terminal, ineligible, or already exhausted.
 * - Mints a fresh per-claim secret `claimToken` (`select: false`), bumping `nextAttemptAt` by
 *   `claimWindowMs` and incrementing `attempts` only while `attempts < MAX_OUTBOX_ATTEMPTS`.
 */
export async function claimPendingScanDispatch(
  input: {
    scanId: string;
    dispatchGeneration: number;
    claimWindowMs?: number;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<ClaimPendingScanDispatchResult> {
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

  const execute = async (session: ClientSession): Promise<ClaimPendingScanDispatchResult> => {
    const existingOutbox = await applySession(
      ScanDispatchOutboxModel.findOne({ scanId: input.scanId }),
      session
    );
    if (!existingOutbox) {
      return { status: 'NOT_FOUND' };
    }

    if (
      existingOutbox.state === OutboxDispatchStateValue.EXHAUSTED &&
      existingOutbox.dispatchGeneration === generation
    ) {
      return {
        status: 'EXHAUSTED',
        outbox: toPublicScanDispatchOutboxRecord(existingOutbox),
      };
    }

    if (
      existingOutbox.state !== OutboxDispatchStateValue.PENDING ||
      existingOutbox.dispatchGeneration !== generation ||
      existingOutbox.nextAttemptAt.getTime() > now.getTime()
    ) {
      return { status: 'STALE_OR_CONFLICT' };
    }

    const scanQuery = ScanModel.findOne({
      _id: input.scanId,
      organizationId: existingOutbox.organizationId,
      projectId: existingOutbox.projectId,
    });
    const scanSelected =
      scanQuery && typeof (scanQuery as { select?: unknown }).select === 'function'
        ? (scanQuery as { select(fields: string): typeof scanQuery }).select(
            '_id status isActive cancellation.requestedAt attemptCount maxAttempts'
          )
        : scanQuery;
    const scan = await applySession(scanSelected, session);

    if (
      !scan ||
      !scan.isActive ||
      isTerminalScanLifecycleStatus(scan.status) ||
      (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined)
    ) {
      const suppressed = await suppressScanDispatchOutboxInSession(
        {
          scanId: input.scanId,
          dispatchGeneration: generation,
          now,
        },
        session
      );
      if (suppressed.status === 'SUPPRESSED') {
        return { status: 'SUPPRESSED', outbox: suppressed.outbox };
      }
      return { status: 'STALE_OR_CONFLICT' };
    }

    if (scan.status !== ScanLifecycleStatusValue.QUEUED || scan.attemptCount >= scan.maxAttempts) {
      return { status: 'STALE_OR_CONFLICT' };
    }

    if (existingOutbox.attempts >= MAX_OUTBOX_ATTEMPTS) {
      const exhausted = await ScanDispatchOutboxModel.findOneAndUpdate(
        {
          scanId: input.scanId,
          state: OutboxDispatchStateValue.PENDING,
          dispatchGeneration: generation,
          attempts: { $gte: MAX_OUTBOX_ATTEMPTS },
        },
        {
          $set: {
            state: OutboxDispatchStateValue.EXHAUSTED,
            exhaustedAt: now,
            dispatchedAt: null,
            suppressedAt: null,
            claimToken: null,
          },
        },
        {
          returnDocument: 'after',
          runValidators: true,
          session,
        }
      );

      if (exhausted) {
        return {
          status: 'EXHAUSTED',
          outbox: toPublicScanDispatchOutboxRecord(exhausted),
        };
      }
      return { status: 'STALE_OR_CONFLICT' };
    }

    // Write-fence the QUEUED scan inside the transaction so concurrent claims or cancellations
    // trigger MongoDB WriteConflict rather than committing stale snapshot reads.
    const fencedScan = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: existingOutbox.organizationId,
        projectId: existingOutbox.projectId,
        status: ScanLifecycleStatusValue.QUEUED,
        isActive: true,
        'cancellation.requestedAt': null,
        $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
      },
      {
        $inc: {
          dispatchRevision: 1,
        },
      },
      {
        returnDocument: 'after',
        session,
      }
    );

    if (!fencedScan) {
      return { status: 'STALE_OR_CONFLICT' };
    }

    const claimToken = generateOutboxClaimToken();
    const claimed = await ScanDispatchOutboxModel.findOneAndUpdate(
      {
        scanId: input.scanId,
        state: OutboxDispatchStateValue.PENDING,
        dispatchGeneration: generation,
        nextAttemptAt: { $lte: now },
        attempts: { $lt: MAX_OUTBOX_ATTEMPTS },
      },
      {
        $set: {
          nextAttemptAt: nextClaimExpiry,
          claimToken,
        },
        $inc: {
          attempts: 1,
        },
      },
      {
        returnDocument: 'after',
        runValidators: true,
        session,
      }
    );

    if (!claimed) {
      return { status: 'STALE_OR_CONFLICT' };
    }

    const publicOutbox = toPublicScanDispatchOutboxRecord(claimed);
    return {
      status: 'CLAIMED',
      outbox: publicOutbox,
      jobId: publicOutbox.jobId,
      claimToken,
    };
  };

  if (externalSession) {
    return await execute(externalSession);
  }

  return await runInTransaction(execute);
}

export type MarkScanDispatchSucceededResult =
  | { status: 'DISPATCHED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_CLAIM' }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Marks a `PENDING` outbox record as `DISPATCHED`, strictly fenced by both `dispatchGeneration` and
 * the active per-claim `claimToken` so older or supplanted dispatchers cannot commit success.
 * Clears `claimToken` upon transition.
 */
export async function markScanDispatchSucceeded(input: {
  scanId: string;
  dispatchGeneration: number;
  claimToken: string;
  now?: Date;
}): Promise<MarkScanDispatchSucceededResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const generation = assertValidGeneration(input.dispatchGeneration);
  const claimToken = assertValidClaimToken(input.claimToken);
  const now = input.now ?? new Date();

  const updated = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
      claimToken,
    },
    {
      $set: {
        state: OutboxDispatchStateValue.DISPATCHED,
        dispatchedAt: now,
        suppressedAt: null,
        exhaustedAt: null,
        lastError: null,
        claimToken: null,
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
  if (!existing) {
    return { status: 'NOT_FOUND' };
  }
  if (
    existing.state !== OutboxDispatchStateValue.PENDING ||
    existing.dispatchGeneration !== generation
  ) {
    return { status: 'STALE_GENERATION' };
  }
  return { status: 'STALE_CLAIM' };
}

export type RecordScanDispatchFailureResult =
  | { status: 'SCHEDULED_RETRY'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'EXHAUSTED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_CLAIM' }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Records a safe, credential-redacted error on a `PENDING` outbox entry while fenced by both
 * `dispatchGeneration` and `claimToken`. Clears `claimToken` on completion and transitions to
 * `EXHAUSTED` once `attempts >= MAX_OUTBOX_ATTEMPTS`.
 */
export async function recordScanDispatchFailure(input: {
  scanId: string;
  dispatchGeneration: number;
  claimToken: string;
  errorMessage: string;
  retryDelayMs?: number;
  now?: Date;
}): Promise<RecordScanDispatchFailureResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  const generation = assertValidGeneration(input.dispatchGeneration);
  const claimToken = assertValidClaimToken(input.claimToken);
  const retryDelayMs = Math.min(Math.max(Math.trunc(input.retryDelayMs ?? 5_000), 100), 3_600_000);
  const now = input.now ?? new Date();
  const nextAttemptAt = new Date(now.getTime() + retryDelayMs);
  const safeError = sanitizeErrorSummary(input.errorMessage);

  const retryUpdated = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
      claimToken,
      attempts: { $lt: MAX_OUTBOX_ATTEMPTS },
    },
    {
      $set: {
        lastError: safeError,
        nextAttemptAt,
        claimToken: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (retryUpdated) {
    return { status: 'SCHEDULED_RETRY', outbox: toPublicScanDispatchOutboxRecord(retryUpdated) };
  }

  const exhaustedUpdated = await ScanDispatchOutboxModel.findOneAndUpdate(
    {
      scanId: input.scanId,
      state: OutboxDispatchStateValue.PENDING,
      dispatchGeneration: generation,
      claimToken,
      attempts: { $gte: MAX_OUTBOX_ATTEMPTS },
    },
    {
      $set: {
        state: OutboxDispatchStateValue.EXHAUSTED,
        exhaustedAt: now,
        dispatchedAt: null,
        suppressedAt: null,
        lastError: safeError,
        claimToken: null,
      },
    },
    {
      returnDocument: 'after',
      runValidators: true,
    }
  );

  if (exhaustedUpdated) {
    return { status: 'EXHAUSTED', outbox: toPublicScanDispatchOutboxRecord(exhaustedUpdated) };
  }

  const existing = await ScanDispatchOutboxModel.findOne({ scanId: input.scanId });
  if (!existing) {
    return { status: 'NOT_FOUND' };
  }
  if (
    existing.state !== OutboxDispatchStateValue.PENDING ||
    existing.dispatchGeneration !== generation
  ) {
    return { status: 'STALE_GENERATION' };
  }
  return { status: 'STALE_CLAIM' };
}

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
  return await suppressScanDispatchOutboxInSession(input, session);
}

export type RearmScanDispatchOutboxResult =
  | { status: 'REARMED'; outbox: PublicScanDispatchOutboxRecord; jobId: string }
  | { status: 'SUPPRESSED_TERMINAL'; outbox: PublicScanDispatchOutboxRecord | null }
  | { status: 'STALE_OR_CONFLICT' }
  | { status: 'NOT_FOUND' };

/**
 * Safely re-arms the scan's unique outbox record inside a MongoDB transaction for a new
 * `dispatchGeneration` (`dispatchGeneration + 1`), resetting `attempts: 0` and clearing any prior
 * `claimToken` / `exhaustedAt` so recovery can enqueue `scan-{scanId}-{newGeneration}`.
 *
 * Concurrency guarantee: Executes inside a transaction and performs a conditional write fence
 * (`$inc: { dispatchRevision: 1 }`) on the authoritative `QUEUED` `Scan` document so concurrent
 * cancellations or worker claims trigger MongoDB `WriteConflict` instead of WiredTiger write skew.
 *
 * Coordinator note: Future periodic recovery loops calling `recoverExpiredScanLeaseCandidate()`
 * should pass one shared `ClientSession` from `runInTransaction` and invoke either
 * `rearmScanDispatchOutbox({ scanId }, session)` (on `REQUEUED_FOR_RECOVERY`) or
 * `suppressScanDispatchOutbox({ scanId }, session)` inside that same transaction.
 */
export async function rearmScanDispatchOutbox(
  input: {
    scanId: string;
    expectedGeneration?: number;
    nextAttemptAt?: Date;
    now?: Date;
  },
  externalSession?: ClientSession
): Promise<RearmScanDispatchOutboxResult> {
  if (!isValidObjectId(input.scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  if (input.expectedGeneration !== undefined) {
    assertValidGeneration(input.expectedGeneration);
  }
  const now = input.now ?? new Date();
  const nextAttemptAt = input.nextAttemptAt ?? now;

  const execute = async (session: ClientSession): Promise<RearmScanDispatchOutboxResult> => {
    const existingOutbox = await applySession(
      ScanDispatchOutboxModel.findOne({ scanId: input.scanId }),
      session
    );
    if (!existingOutbox) {
      return { status: 'NOT_FOUND' };
    }

    // Write-fence the QUEUED Scan document inside this transaction so concurrent cancellation or
    // worker claim triggers MongoDB WriteConflict (never snapshot write skew).
    const fencedScan = await ScanModel.findOneAndUpdate(
      {
        _id: input.scanId,
        organizationId: existingOutbox.organizationId,
        projectId: existingOutbox.projectId,
        status: ScanLifecycleStatusValue.QUEUED,
        isActive: true,
        'cancellation.requestedAt': null,
        $expr: { $lt: ['$attemptCount', '$maxAttempts'] },
      },
      {
        $inc: {
          dispatchRevision: 1,
        },
      },
      {
        returnDocument: 'after',
        session,
      }
    );

    if (!fencedScan) {
      const scanQuery = ScanModel.findOne({
        _id: input.scanId,
        organizationId: existingOutbox.organizationId,
        projectId: existingOutbox.projectId,
      });
      const scanSelected =
        scanQuery && typeof (scanQuery as { select?: unknown }).select === 'function'
          ? (scanQuery as { select(fields: string): typeof scanQuery }).select(
              '_id status isActive cancellation.requestedAt'
            )
          : scanQuery;
      const scan = await applySession(scanSelected, session);

      if (
        !scan ||
        !scan.isActive ||
        isTerminalScanLifecycleStatus(scan.status) ||
        (scan.cancellation?.requestedAt !== null && scan.cancellation?.requestedAt !== undefined)
      ) {
        const sup = await suppressScanDispatchOutboxInSession(
          { scanId: input.scanId, now },
          session
        );
        return {
          status: 'SUPPRESSED_TERMINAL',
          outbox:
            sup.status === 'SUPPRESSED'
              ? sup.outbox
              : toPublicScanDispatchOutboxRecord(existingOutbox),
        };
      }

      return { status: 'STALE_OR_CONFLICT' };
    }

    const expectedGen =
      input.expectedGeneration !== undefined
        ? assertValidGeneration(input.expectedGeneration)
        : existingOutbox.dispatchGeneration;

    if (expectedGen >= MAX_DISPATCH_GENERATION) {
      throw new ScanLifecycleError(
        `dispatchGeneration cannot exceed ${MAX_DISPATCH_GENERATION}`,
        'INVALID_DISPATCH_GENERATION'
      );
    }

    const rearmed = await ScanDispatchOutboxModel.findOneAndUpdate(
      {
        scanId: input.scanId,
        state: { $ne: OutboxDispatchStateValue.SUPPRESSED },
        dispatchGeneration: expectedGen,
      },
      {
        $set: {
          state: OutboxDispatchStateValue.PENDING,
          attempts: 0,
          nextAttemptAt,
          dispatchedAt: null,
          suppressedAt: null,
          exhaustedAt: null,
          lastError: null,
          claimToken: null,
        },
        $inc: {
          dispatchGeneration: 1,
        },
      },
      {
        returnDocument: 'after',
        runValidators: true,
        session,
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
  };

  if (externalSession) {
    return await execute(externalSession);
  }

  return await runInTransaction(execute);
}
