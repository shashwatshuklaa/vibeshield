import { randomBytes } from 'node:crypto';
import type { ClientSession } from 'mongoose';
import { redactMongoUri } from '../connection.js';
import {
  OutboxDispatchStateValue,
  ScanDispatchOutboxModel,
  type OutboxDispatchState,
  type ScanDispatchOutboxAttributes,
} from '../models/scan-dispatch-outbox.model.js';
import { isValidObjectId } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';

export const MAX_DISPATCH_GENERATION = 1_000_000;
export { MAX_OUTBOX_ATTEMPTS } from '../models/scan-dispatch-outbox.model.js';

export class ScanLifecycleError extends Error {
  public readonly code: string;

  constructor(message: string, code = 'SCAN_LIFECYCLE_ERROR') {
    super(redactGitHubSecrets(redactMongoUri(message)));
    this.name = 'ScanLifecycleError';
    this.code = code;
  }
}

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
  exhaustedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export function generateOutboxClaimToken(): string {
  return randomBytes(24).toString('hex');
}

export function formatScanDispatchJobId(scanId: string, dispatchGeneration: number): string {
  if (!isValidObjectId(scanId)) {
    throw new ScanLifecycleError('Invalid scan ObjectId identifier', 'INVALID_SCAN_IDENTIFIER');
  }
  if (
    !Number.isSafeInteger(dispatchGeneration) ||
    dispatchGeneration < 1 ||
    dispatchGeneration > MAX_DISPATCH_GENERATION
  ) {
    throw new ScanLifecycleError(
      `dispatchGeneration must be an integer between 1 and ${MAX_DISPATCH_GENERATION}`,
      'INVALID_DISPATCH_GENERATION'
    );
  }
  return `scan-${scanId.toLowerCase()}-${dispatchGeneration}`;
}

export function assertValidGeneration(generation: number): number {
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > MAX_DISPATCH_GENERATION) {
    throw new ScanLifecycleError(
      'dispatchGeneration must be a positive integer',
      'INVALID_DISPATCH_GENERATION'
    );
  }
  return generation;
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
    exhaustedAt: doc.exhaustedAt ?? null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export type SuppressScanDispatchOutboxResult =
  | { status: 'SUPPRESSED'; outbox: PublicScanDispatchOutboxRecord }
  | { status: 'STALE_GENERATION' }
  | { status: 'NOT_FOUND' };

/**
 * Low-level outbox suppression helper shared between scan lifecycle transactions and outbox dispatchers.
 * Always clears `claimToken` so no live or stalled dispatcher can commit against a terminal scan.
 */
export async function suppressScanDispatchOutboxInSession(
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
        exhaustedAt: null,
        claimToken: null,
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

  const existingQuery = ScanDispatchOutboxModel.findOne({ scanId: input.scanId });
  const existing =
    existingQuery &&
    typeof (existingQuery as { session?: unknown }).session === 'function' &&
    session
      ? await (existingQuery as { session(s: ClientSession | null): typeof existingQuery }).session(
          session
        )
      : await existingQuery;

  return existing ? { status: 'STALE_GENERATION' } : { status: 'NOT_FOUND' };
}
