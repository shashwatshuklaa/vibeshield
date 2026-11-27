import type { BackoffOptions, DefaultJobOptions, KeepJobs } from 'bullmq';
import type { ScanStatus } from '@vibeshield/types';

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
 * Common metadata carried with queued background jobs without secrets or large blobs.
 */
export interface QueueJobMetadata {
  correlationId?: string;
  organizationId: string;
  projectId: string;
  triggeredByUserId?: string | null;
  triggerSource: 'manual' | 'webhook' | 'scheduled' | 'system';
  enqueuedAt: string;
}

/**
 * Minimal initial scan-job payload contract backed by shared `@vibeshield/types` enums.
 * Deliberately contains identifiers and execution references only (no secrets or source archives).
 */
export interface ScanQueueJobPayload {
  scanId: string;
  organizationId: string;
  projectId: string;
  installationRecordId?: string | null;
  githubRepositoryId?: number | null;
  commitHash: string;
  branch: string;
  status: ScanStatus;
  metadata: QueueJobMetadata;
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
