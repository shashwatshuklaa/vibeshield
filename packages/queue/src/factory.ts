import {
  Queue,
  UnrecoverableError,
  Worker,
  type ConnectionOptions,
  type Job,
  type KeepJobs,
  type Processor,
  type QueueOptions,
  type WorkerOptions,
} from 'bullmq';
import {
  buildDefaultJobOptions,
  DEFAULT_MONGODB_SCAN_LEASE_DURATION_MS,
  DEFAULT_QUEUE_POLICY,
  isValidQueueName,
  QUEUE_KEY_PREFIX,
  QUEUE_NAMES,
} from './contracts.js';
import { extractRedisUrlPassword, formatSafeRedisError } from './redaction.js';
import {
  buildRedisConnectionOptions,
  RedisConnectionError,
  type RedisConnectionManager,
} from './redis.js';
import type {
  CreateBullQueueOptions,
  QueueHealthSummary,
  QueueLogger,
  RedisConfigOptions,
  ScanQueueJobPayload,
  WorkerPolicyOptions,
} from './types.js';

export { UnrecoverableError, type Job, type Processor };

/**
 * Default BullMQ worker lock and stalled-job timings.
 * `lockDuration` (75_000 ms) intentionally exceeds `DEFAULT_MONGODB_SCAN_LEASE_DURATION_MS`
 * (60_000 ms) so crashed workers' BullMQ locks do not expire and trigger premature stalled
 * re-deliveries before the authoritative MongoDB lease expires (healthy workers renew locks
 * automatically at `lockDuration / 2`).
 */
export const DEFAULT_WORKER_POLICY = Object.freeze({
  concurrency: 2,
  lockDuration: 75_000,
  stalledInterval: 30_000,
  maxStalledCount: 2,
  maxStartedAttempts: 5,
});

/**
 * Verifies whether BullMQ worker `lockDurationMs` exceeds the MongoDB `scanLeaseDurationMs` so
 * stalled-job detection does not prematurely re-deliver a job while its Mongo lease is still valid.
 */
export function isWorkerLockAlignedWithScanLease(input: {
  lockDurationMs: number;
  scanLeaseDurationMs?: number;
}): boolean {
  const leaseDurationMs = input.scanLeaseDurationMs ?? DEFAULT_MONGODB_SCAN_LEASE_DURATION_MS;
  return (
    Number.isFinite(input.lockDurationMs) &&
    Number.isFinite(leaseDurationMs) &&
    input.lockDurationMs > leaseDurationMs
  );
}

export interface ManagedQueueHandle<TData = ScanQueueJobPayload, TName extends string = string> {
  readonly name: string;
  readonly queue: Queue<TData, void, TName>;
  close(): Promise<void>;
}

export interface ManagedWorkerHandle<
  TData = ScanQueueJobPayload,
  TResult = unknown,
  TName extends string = string,
> {
  readonly name: string;
  readonly worker: Worker<TData, TResult, TName>;
  readonly concurrency: number;
  close(force?: boolean): Promise<void>;
}

export interface CreateBullWorkerOptions extends WorkerPolicyOptions {
  redis: RedisConfigOptions;
  prefix?: string;
  autorun?: boolean;
  skipWaitingForReady?: boolean;
  removeOnComplete?: KeepJobs;
  removeOnFail?: KeepJobs;
  logger?: QueueLogger;
}

/**
 * Instantiates a BullMQ `Queue` backed by a connected Queue-role Redis client with validated
 * queue naming, bounded exponential retry/backoff defaults, and bounded job retention.
 */
export function createBullQueue<TData = ScanQueueJobPayload, TName extends string = string>(
  queueName: string,
  connectionManager: RedisConnectionManager,
  options: CreateBullQueueOptions = {}
): ManagedQueueHandle<TData, TName> {
  if (!isValidQueueName(queueName)) {
    throw new RedisConnectionError(
      'Queue name must be lowercase alphanumeric/dot/hyphen/underscore and must not contain colons.',
      'INVALID_QUEUE_NAME'
    );
  }

  const queueClient = connectionManager.getQueueClient();
  const queueOptions: QueueOptions = {
    connection: queueClient as unknown as ConnectionOptions,
    prefix: options.prefix ?? QUEUE_KEY_PREFIX,
    defaultJobOptions: buildDefaultJobOptions(options.defaultJobOptions),
    skipWaitingForReady: options.skipWaitingForReady ?? true,
  };

  const queue = new Queue<TData, void, TName>(queueName, queueOptions);

  // Prevent unhandled EventEmitter 'error' crashes if Redis drops asynchronously
  queue.on('error', () => {
    // Connection errors are surfaced via RedisConnectionManager logger/status
  });

  return {
    name: queueName,
    queue,
    async close(): Promise<void> {
      await queue.close();
    },
  };
}

/**
 * Creates the primary `vibeshield-v1-scan-jobs` BullMQ queue foundation without scheduling any jobs.
 */
export function createScanJobsQueue(
  connectionManager: RedisConnectionManager,
  options: CreateBullQueueOptions = {}
): ManagedQueueHandle<ScanQueueJobPayload, 'scan'> {
  return createBullQueue<ScanQueueJobPayload, 'scan'>(
    QUEUE_NAMES.SCAN_JOBS,
    connectionManager,
    options
  );
}

/**
 * Inspects queue health and bounded job counts when Redis is connected without leaking secrets.
 */
export async function inspectQueueHealth(
  handle: Pick<ManagedQueueHandle<unknown, string>, 'name' | 'queue'> | null | undefined,
  connectionManager: RedisConnectionManager,
  enabled: boolean
): Promise<QueueHealthSummary> {
  const redisStatus = connectionManager.getStatus(enabled);
  const queueName = handle?.name ?? QUEUE_NAMES.SCAN_JOBS;

  if (!enabled || !handle || !redisStatus.isConnected) {
    return {
      queueName,
      redis: redisStatus,
    };
  }

  try {
    const rawCounts = await handle.queue.getJobCounts(
      'waiting',
      'active',
      'delayed',
      'failed',
      'completed'
    );
    return {
      queueName,
      redis: redisStatus,
      counts: {
        waiting: rawCounts.waiting ?? 0,
        active: rawCounts.active ?? 0,
        delayed: rawCounts.delayed ?? 0,
        failed: rawCounts.failed ?? 0,
        completed: rawCounts.completed ?? 0,
      },
    };
  } catch {
    return {
      queueName,
      redis: {
        enabled: true,
        state: 'unavailable',
        isConnected: false,
      },
    };
  }
}

/**
 * Closes all provided queue handles first and then cleanly closes the owned Redis connection.
 */
export async function closeQueueResources(
  handles: ReadonlyArray<Pick<ManagedQueueHandle<unknown, string>, 'close'> | null | undefined>,
  connectionManager: RedisConnectionManager
): Promise<void> {
  let firstError: unknown = null;

  for (const handle of handles) {
    if (!handle) {
      continue;
    }
    try {
      await handle.close();
    } catch (error) {
      if (!firstError) {
        firstError = error;
      }
    }
  }

  try {
    await connectionManager.disconnect();
  } catch (error) {
    if (!firstError) {
      firstError = error;
    }
  }

  if (firstError) {
    throw firstError;
  }
}

function validatePositiveIntRange(value: number, min: number, max: number, label: string): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RedisConnectionError(
      `${label} must be an integer between ${min} and ${max}.`,
      'INVALID_WORKER_CONFIG'
    );
  }
  return value;
}

/**
 * Normalizes and validates bounded concurrency, lock duration, and stalled-job recovery settings.
 */
export function buildWorkerPolicyOptions(
  overrides: WorkerPolicyOptions = {}
): Required<WorkerPolicyOptions> {
  const concurrency = validatePositiveIntRange(
    overrides.concurrency ?? DEFAULT_WORKER_POLICY.concurrency,
    1,
    50,
    'Worker concurrency'
  );
  const lockDuration = validatePositiveIntRange(
    overrides.lockDuration ?? DEFAULT_WORKER_POLICY.lockDuration,
    5_000,
    600_000,
    'Worker lockDuration'
  );
  const stalledInterval = validatePositiveIntRange(
    overrides.stalledInterval ?? DEFAULT_WORKER_POLICY.stalledInterval,
    5_000,
    600_000,
    'Worker stalledInterval'
  );
  const maxStalledCount = validatePositiveIntRange(
    overrides.maxStalledCount ?? DEFAULT_WORKER_POLICY.maxStalledCount,
    0,
    10,
    'Worker maxStalledCount'
  );
  const maxStartedAttempts = validatePositiveIntRange(
    overrides.maxStartedAttempts ?? DEFAULT_WORKER_POLICY.maxStartedAttempts,
    1,
    20,
    'Worker maxStartedAttempts'
  );

  return {
    concurrency,
    lockDuration,
    stalledInterval,
    maxStalledCount,
    maxStartedAttempts,
  };
}

/**
 * Instantiates a BullMQ `Worker` with Worker-role Redis options (`maxRetriesPerRequest: null`),
 * explicit bounded concurrency/stalled-job settings, and credential-redacted error logging.
 */
export function createBullWorker<
  TData = ScanQueueJobPayload,
  TResult = unknown,
  TName extends string = string,
>(
  queueName: string,
  processor: Processor<TData, TResult, TName>,
  options: CreateBullWorkerOptions
): ManagedWorkerHandle<TData, TResult, TName> {
  if (!isValidQueueName(queueName)) {
    throw new RedisConnectionError(
      'Queue name must be lowercase alphanumeric/dot/hyphen/underscore and must not contain colons.',
      'INVALID_QUEUE_NAME'
    );
  }

  if (typeof processor !== 'function') {
    throw new RedisConnectionError(
      'Worker job processor function must be explicitly provided.',
      'INVALID_WORKER_PROCESSOR'
    );
  }

  const workerRedisOptions = buildRedisConnectionOptions(options.redis, 'worker');
  const secretValues = [extractRedisUrlPassword(options.redis.url)].filter(
    (secret): secret is string => Boolean(secret)
  );
  const policy = buildWorkerPolicyOptions(options);

  const workerOptions: WorkerOptions = {
    connection: workerRedisOptions as ConnectionOptions,
    prefix: options.prefix ?? QUEUE_KEY_PREFIX,
    autorun: options.autorun ?? true,
    concurrency: policy.concurrency,
    lockDuration: policy.lockDuration,
    stalledInterval: policy.stalledInterval,
    maxStalledCount: policy.maxStalledCount,
    maxStartedAttempts: policy.maxStartedAttempts,
    removeOnComplete: options.removeOnComplete ?? { ...DEFAULT_QUEUE_POLICY.removeOnComplete },
    removeOnFail: options.removeOnFail ?? { ...DEFAULT_QUEUE_POLICY.removeOnFail },
    skipWaitingForReady: options.skipWaitingForReady ?? false,
  };

  const worker = new Worker<TData, TResult, TName>(queueName, processor, workerOptions);

  // Prevent unhandled EventEmitter 'error' crashes and ensure secrets are never logged raw.
  worker.on('error', (error: Error) => {
    options.logger?.error?.(
      `[BullWorker:${queueName}] Worker error: ${formatSafeRedisError(error, secretValues)}`
    );
  });

  return {
    name: queueName,
    worker,
    concurrency: policy.concurrency,
    async close(force = false): Promise<void> {
      await worker.close(force);
    },
  };
}

/**
 * Creates a BullMQ Worker bound to the primary `vibeshield-v1-scan-jobs` queue using an explicit
 * caller-supplied processor.
 */
export function createScanJobsWorker<TResult = void>(
  processor: Processor<ScanQueueJobPayload, TResult, 'scan'>,
  options: CreateBullWorkerOptions
): ManagedWorkerHandle<ScanQueueJobPayload, TResult, 'scan'> {
  return createBullWorker<ScanQueueJobPayload, TResult, 'scan'>(
    QUEUE_NAMES.SCAN_JOBS,
    processor,
    options
  );
}

/**
 * Gracefully closes a BullMQ worker within `graceTimeoutMs`, forcing connection shutdown if active
 * jobs exceed the shutdown grace period so worker termination remains deterministic.
 */
export async function closeWorkerWithGrace(
  handle: Pick<ManagedWorkerHandle<unknown, unknown, string>, 'close'> | null | undefined,
  graceTimeoutMs = 10_000
): Promise<{ timedOut: boolean }> {
  if (!handle) {
    return { timedOut: false };
  }

  const boundedTimeoutMs =
    Number.isFinite(graceTimeoutMs) && graceTimeoutMs > 0 ? graceTimeoutMs : 10_000;

  let timeoutHandle: NodeJS.Timeout | undefined;
  let timedOut = false;

  const closePromise = handle.close(false);
  // Ensure slow or rejected graceful close never causes unhandledRejection if timeout fires first.
  closePromise.catch(() => undefined);

  try {
    const timeoutPromise = new Promise<'timeout'>((resolve) => {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        resolve('timeout');
      }, boundedTimeoutMs);
    });

    const outcome = await Promise.race([
      closePromise.then(() => 'closed' as const),
      timeoutPromise,
    ]);
    if (outcome === 'timeout') {
      await handle.close(true);
    } else {
      await closePromise;
    }
    return { timedOut };
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
}
