import { Queue, type ConnectionOptions, type QueueOptions } from 'bullmq';
import {
  buildDefaultJobOptions,
  isValidQueueName,
  QUEUE_KEY_PREFIX,
  QUEUE_NAMES,
} from './contracts.js';
import { RedisConnectionError, type RedisConnectionManager } from './redis.js';
import type { CreateBullQueueOptions, QueueHealthSummary, ScanQueueJobPayload } from './types.js';

export interface ManagedQueueHandle<TData = ScanQueueJobPayload, TName extends string = string> {
  readonly name: string;
  readonly queue: Queue<TData, void, TName>;
  close(): Promise<void>;
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
