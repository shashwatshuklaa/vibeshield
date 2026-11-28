import path from 'node:path';
import { DEFAULT_CONNECT_OPTIONS, isValidMongoUri } from '@vibeshield/database';
import { type BaseEnv, baseEnvSchema, validateEnv, z } from '@vibeshield/env';
import {
  DEFAULT_REDIS_OPTIONS,
  DEFAULT_WORKER_POLICY,
  isValidQueueName,
  isValidRedisUrl,
  QUEUE_KEY_PREFIX,
} from '@vibeshield/queue';

const MIN_INTERNAL_AUTH_SECRET_LENGTH = 32;

/**
 * Validates that an optional configured workspace parent directory is an absolute path without
 * NUL bytes and not filesystem root.
 */
export function isValidWorkspaceParentDir(rawDir: string): boolean {
  if (typeof rawDir !== 'string') {
    return false;
  }
  const trimmed = rawDir.trim();
  if (trimmed.length === 0 || trimmed.includes('\0') || !path.isAbsolute(trimmed)) {
    return false;
  }
  const resolved = path.resolve(trimmed);
  return resolved !== path.parse(resolved).root;
}

/**
 * Validates that a configured internal API base URL is a clean HTTP/HTTPS origin without
 * embedded credentials, query strings, fragments, whitespace, wildcards, or custom path prefixes.
 */
export function isValidInternalApiBaseUrl(rawUrl: string): boolean {
  if (
    typeof rawUrl !== 'string' ||
    rawUrl.length === 0 ||
    /\s/.test(rawUrl) ||
    rawUrl.includes('*')
  ) {
    return false;
  }

  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    if (parsed.username || parsed.password) {
      return false;
    }
    if (parsed.search || rawUrl.includes('?') || parsed.hash || rawUrl.includes('#')) {
      return false;
    }
    if (!parsed.hostname) {
      return false;
    }
    if (parsed.pathname !== '/' && parsed.pathname !== '') {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Normalizes a validated internal API base URL to its canonical `scheme://host[:port]` origin.
 */
export function normalizeInternalApiBaseUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (!isValidInternalApiBaseUrl(trimmed)) {
    throw new Error('Invalid INTERNAL_API_BASE_URL configuration.');
  }
  return new URL(trimmed).origin;
}

/**
 * Validates that an internal HMAC secret meets minimum security length requirements.
 */
export function isValidInternalWorkerAuthSecret(secret: string): boolean {
  return (
    typeof secret === 'string' &&
    secret.length >= MIN_INTERNAL_AUTH_SECRET_LENGTH &&
    secret.trim().length >= MIN_INTERNAL_AUTH_SECRET_LENGTH
  );
}

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
    WORKER_WORKSPACE_DIR: z
      .string()
      .trim()
      .refine(isValidWorkspaceParentDir, {
        message:
          'WORKER_WORKSPACE_DIR must be an absolute non-root directory path without NUL bytes.',
      })
      .transform((value) => path.resolve(value))
      .optional(),
    INTERNAL_API_BASE_URL: z
      .string()
      .trim()
      .refine(isValidInternalApiBaseUrl, {
        message:
          'INTERNAL_API_BASE_URL must be an HTTP/HTTPS origin without credentials, query strings, fragments, or path prefixes.',
      })
      .transform((value) => new URL(value).origin)
      .optional(),
    INTERNAL_WORKER_AUTH_SECRET: z
      .string()
      .min(
        MIN_INTERNAL_AUTH_SECRET_LENGTH,
        `INTERNAL_WORKER_AUTH_SECRET must be at least ${MIN_INTERNAL_AUTH_SECRET_LENGTH} characters.`
      )
      .refine((secret) => secret.trim().length >= MIN_INTERNAL_AUTH_SECRET_LENGTH, {
        message: `INTERNAL_WORKER_AUTH_SECRET must contain at least ${MIN_INTERNAL_AUTH_SECRET_LENGTH} non-whitespace characters.`,
      })
      .optional(),
    // Optional sibling env vars accepted strictly for cross-secret collision checks and never retained on WorkerConfig.
    JWT_ACCESS_SECRET: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),
    GITHUB_WEBHOOK_SECRET: z.string().optional(),
    GITHUB_WEBHOOK_SECRET_PREVIOUS: z.string().optional(),
    GITHUB_APP_PRIVATE_KEY: z.string().optional(),
  })
  .superRefine((env, ctx) => {
    const hasBaseUrl = env.INTERNAL_API_BASE_URL !== undefined;
    const hasAuthSecret = env.INTERNAL_WORKER_AUTH_SECRET !== undefined;

    if (hasBaseUrl && !hasAuthSecret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['INTERNAL_WORKER_AUTH_SECRET'],
        message:
          'INTERNAL_WORKER_AUTH_SECRET is required when INTERNAL_API_BASE_URL is configured.',
      });
    }

    if (hasAuthSecret && !hasBaseUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['INTERNAL_API_BASE_URL'],
        message:
          'INTERNAL_API_BASE_URL is required when INTERNAL_WORKER_AUTH_SECRET is configured.',
      });
    }

    if (env.INTERNAL_WORKER_AUTH_SECRET !== undefined) {
      const forbiddenMatches = [
        env.JWT_ACCESS_SECRET,
        env.GITHUB_CLIENT_SECRET,
        env.GITHUB_WEBHOOK_SECRET,
        env.GITHUB_WEBHOOK_SECRET_PREVIOUS,
        env.GITHUB_APP_PRIVATE_KEY,
      ].filter((secret): secret is string => typeof secret === 'string' && secret.length > 0);

      if (forbiddenMatches.includes(env.INTERNAL_WORKER_AUTH_SECRET)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['INTERNAL_WORKER_AUTH_SECRET'],
          message:
            'INTERNAL_WORKER_AUTH_SECRET must be distinct from JWT_ACCESS_SECRET and GitHub secrets.',
        });
      }
    }
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
  workspaceParentDir?: string;
  internalApiBaseUrl?: string;
  readonly internalWorkerAuthSecret?: string;
}

/**
 * Parses and validates environment configuration required to boot the security worker runtime.
 * Never embeds credentials in thrown validation errors or exposes internal HMAC secrets during JSON serialization.
 */
export function loadWorkerConfig(
  rawEnv: Record<string, string | undefined> = process.env
): WorkerConfig {
  const parsed = validateEnv(workerEnvSchema, rawEnv);

  const config: WorkerConfig = {
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
    ...(parsed.WORKER_WORKSPACE_DIR !== undefined
      ? { workspaceParentDir: parsed.WORKER_WORKSPACE_DIR }
      : {}),
    ...(parsed.INTERNAL_API_BASE_URL !== undefined
      ? { internalApiBaseUrl: parsed.INTERNAL_API_BASE_URL }
      : {}),
  };

  if (parsed.INTERNAL_WORKER_AUTH_SECRET !== undefined) {
    Object.defineProperty(config, 'internalWorkerAuthSecret', {
      value: parsed.INTERNAL_WORKER_AUTH_SECRET,
      enumerable: false,
      writable: false,
      configurable: true,
    });
  }

  return config;
}
