import { DEFAULT_CONNECT_OPTIONS, isValidMongoUri } from '@vibeshield/database';
import { type BaseEnv, baseEnvSchema, validateEnv, z } from '@vibeshield/env';
import {
  DEFAULT_REDIS_OPTIONS,
  DEFAULT_WORKER_POLICY,
  isValidQueueName,
  isValidRedisUrl,
  QUEUE_KEY_PREFIX,
} from '@vibeshield/queue';

const workerEnvSchema = baseEnvSchema
  .pick({
    NODE_ENV: true,
    LOG_LEVEL: true,
  })
  .extend({
    LOG_LEVEL: baseEnvSchema.shape.LOG_LEVEL.or(z.literal('silent')).default('info'),
    MONGODB_URI: z
      .string({ required_error: 'MONGODB_URI is required for @vibeshield/security-worker.' })
      .trim()
      .min(1, 'MONGODB_URI is required for @vibeshield/security-worker.')
      .refine((value) => isValidMongoUri(value), {
        message: 'MONGODB_URI must be a valid mongodb:// or mongodb+srv:// connection URI.',
      }),
    MONGODB_CONNECT_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .min(100)
      .max(60_000)
      .default(DEFAULT_CONNECT_OPTIONS.connectTimeoutMS ?? 10_000),
    REDIS_URL: z
      .string({ required_error: 'REDIS_URL is required for @vibeshield/security-worker.' })
      .trim()
      .min(1, 'REDIS_URL is required for @vibeshield/security-worker.')
      .refine((value) => isValidRedisUrl(value), {
        message: 'REDIS_URL must be a valid redis:// or rediss:// connection URL.',
      }),
    REDIS_CONNECT_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .min(100)
      .max(60_000)
      .default(DEFAULT_REDIS_OPTIONS.connectTimeoutMs),
    REDIS_MAX_RECONNECT_ATTEMPTS: z.coerce
      .number()
      .int()
      .min(0)
      .max(100)
      .default(DEFAULT_REDIS_OPTIONS.maxReconnectAttempts),
    WORKER_CONCURRENCY: z.coerce
      .number()
      .int()
      .min(1)
      .max(50)
      .default(DEFAULT_WORKER_POLICY.concurrency),
    WORKER_LOCK_DURATION: z.coerce
      .number()
      .int()
      .min(5_000)
      .max(600_000)
      .default(DEFAULT_WORKER_POLICY.lockDuration),
    WORKER_STALLED_INTERVAL: z.coerce
      .number()
      .int()
      .min(5_000)
      .max(600_000)
      .default(DEFAULT_WORKER_POLICY.stalledInterval),
    WORKER_MAX_STALLED_COUNT: z.coerce
      .number()
      .int()
      .min(0)
      .max(10)
      .default(DEFAULT_WORKER_POLICY.maxStalledCount),
    WORKER_MAX_STARTED_ATTEMPTS: z.coerce
      .number()
      .int()
      .min(1)
      .max(20)
      .default(DEFAULT_WORKER_POLICY.maxStartedAttempts),
    WORKER_LEASE_DURATION_MS: z.coerce.number().int().min(5_000).max(600_000).default(60_000),
    WORKER_SHUTDOWN_GRACE_MS: z.coerce.number().int().min(500).max(120_000).default(10_000),
    QUEUE_PREFIX: z
      .string()
      .trim()
      .default(QUEUE_KEY_PREFIX)
      .refine((value) => isValidQueueName(value), {
        message:
          'QUEUE_PREFIX must be lowercase alphanumeric/dot/hyphen/underscore and must not contain colons.',
      }),
  });

export type WorkerEnvInput = z.infer<typeof workerEnvSchema>;

/**
 * Validated runtime configuration for the standalone security worker application.
 * Intentionally excludes HTTP ports and GitHub App private keys.
 */
export interface WorkerConfig {
  nodeEnv: BaseEnv['NODE_ENV'];
  logLevel: BaseEnv['LOG_LEVEL'] | 'silent';
  mongodbUri: string;
  mongodbConnectTimeoutMs: number;
  redisUrl: string;
  redisConnectTimeoutMs: number;
  redisMaxReconnectAttempts: number;
  concurrency: number;
  lockDuration: number;
  stalledInterval: number;
  maxStalledCount: number;
  maxStartedAttempts: number;
  leaseDurationMs: number;
  shutdownGraceMs: number;
  queuePrefix: string;
}

/**
 * Parses and validates environment configuration required to boot the security worker runtime.
 * Never embeds credentials in thrown validation errors.
 */
export function loadWorkerConfig(
  rawEnv: Record<string, string | undefined> = process.env
): WorkerConfig {
  const parsed = validateEnv(workerEnvSchema, rawEnv);

  return {
    nodeEnv: parsed.NODE_ENV,
    logLevel: parsed.LOG_LEVEL,
    mongodbUri: parsed.MONGODB_URI,
    mongodbConnectTimeoutMs: parsed.MONGODB_CONNECT_TIMEOUT_MS,
    redisUrl: parsed.REDIS_URL,
    redisConnectTimeoutMs: parsed.REDIS_CONNECT_TIMEOUT_MS,
    redisMaxReconnectAttempts: parsed.REDIS_MAX_RECONNECT_ATTEMPTS,
    concurrency: parsed.WORKER_CONCURRENCY,
    lockDuration: parsed.WORKER_LOCK_DURATION,
    stalledInterval: parsed.WORKER_STALLED_INTERVAL,
    maxStalledCount: parsed.WORKER_MAX_STALLED_COUNT,
    maxStartedAttempts: parsed.WORKER_MAX_STARTED_ATTEMPTS,
    leaseDurationMs: parsed.WORKER_LEASE_DURATION_MS,
    shutdownGraceMs: parsed.WORKER_SHUTDOWN_GRACE_MS,
    queuePrefix: parsed.QUEUE_PREFIX,
  };
}
