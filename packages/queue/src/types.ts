import type { BackoffOptions, DefaultJobOptions, KeepJobs } from 'bullmq';

/**
 * Normalized Redis connection lifecycle states exposed by `@vibeshield/queue`.
 */
export type RedisConnectionState =
  | 'disabled'
  | 'not_initialized'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnecting'
  | 'unavailable';

/**
 * Snapshot of the Redis connection health without exposing raw URIs or credentials.
 */
export interface RedisConnectionStatus {
  enabled: boolean;
  state: RedisConnectionState;
  isConnected: boolean;
}

/**
 * Optional logger interface for queue and Redis lifecycle events.
 * Callers must only receive redacted, credential-free log messages.
 */
export interface QueueLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

/**
 * Validated Redis connection configuration derived from runtime environment or options.
 */
export interface RedisConfigOptions {
  url: string;
  connectTimeoutMs?: number;
  commandTimeoutMs?: number;
  maxRetriesPerRequest?: number;
  enableOfflineQueue?: boolean;
  maxReconnectAttempts?: number;
  retryDelayBaseMs?: number;
  maxRetryDelayMs?: number;
  tlsRejectUnauthorized?: boolean;
}

/**
 * Runtime queue subsystem configuration used by API and worker hosts.
 */
export interface QueueRuntimeConfig {
  enabled: boolean;
  required: boolean;
  redis: RedisConfigOptions;
  defaultAttempts: number;
  backoffDelayMs: number;
}

/**
 * Role separating fast-fail API queue connections from blocking BullMQ worker connections.
 */
export type RedisConnectionRole = 'queue' | 'worker';

/**
 * Strictly minimal BullMQ scan-job payload carrying only the authoritative `scanId` identifier.
 * Workers must load and verify organization, project, repository, branch, commit, and permissions
 * directly from MongoDB rather than trusting queued fields.
 */
export interface ScanQueueJobPayload {
  scanId: string;
}

/**
 * Canonical retry and retention policy for BullMQ queues.
 */
export interface QueuePolicyDefaults {
  attempts: number;
  backoff: BackoffOptions;
  removeOnComplete: KeepJobs;
  removeOnFail: KeepJobs;
}

/**
 * Options for instantiating a BullMQ queue via the factory.
 */
export interface CreateBullQueueOptions {
  defaultJobOptions?: Partial<DefaultJobOptions>;
  prefix?: string;
  skipWaitingForReady?: boolean;
}

/**
 * Safe summary of BullMQ queue job counts and Redis readiness.
 */
export interface QueueHealthSummary {
  queueName: string;
  redis: RedisConnectionStatus;
  counts?: {
    waiting: number;
    active: number;
    delayed: number;
    failed: number;
    completed: number;
  };
}

/**
 * Bounded lifecycle states for a standalone BullMQ worker runtime.
 */
export type WorkerLifecycleState =
  'not_initialized' | 'starting' | 'ready' | 'stopping' | 'stopped' | 'failed';

/**
 * Configurable concurrency, lock, and stalled-job policy options for BullMQ workers.
 */
export interface WorkerPolicyOptions {
  concurrency?: number;
  lockDuration?: number;
  stalledInterval?: number;
  maxStalledCount?: number;
  maxStartedAttempts?: number;
}

/**
 * Safe runtime health snapshot for a BullMQ worker host without exposing Redis credentials.
 */
export interface WorkerHealthSummary {
  queueName: string;
  state: WorkerLifecycleState;
  isReady: boolean;
  isRunning: boolean;
  concurrency: number;
}
