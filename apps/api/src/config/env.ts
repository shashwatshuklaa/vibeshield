import { createPrivateKey } from 'node:crypto';
import {
  isValidMongoUri,
  normalizeSlug,
  redactGitHubSecrets,
  SLUG_REGEX,
} from '@vibeshield/database';
import {
  DEFAULT_QUEUE_POLICY,
  DEFAULT_REDIS_OPTIONS,
  isValidRedisUrl,
  type QueueRuntimeConfig,
} from '@vibeshield/queue';
import { baseEnvSchema, validateEnv, z } from '@vibeshield/env';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';

export interface GitHubRuntimeConfig {
  appId: number;
  appSlug: string;
  privateKeyPem: string;
  clientId: string;
  clientSecret: string;
  webhookSecret: string;
  previousWebhookSecret?: string;
  callbackUrl: string;
}

export const REQUIRED_GITHUB_ENV_KEYS = [
  'GITHUB_APP_ID',
  'GITHUB_APP_SLUG',
  'GITHUB_APP_PRIVATE_KEY',
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_WEBHOOK_SECRET',
  'GITHUB_CALLBACK_URL',
] as const;

export function isValidGitHubCallbackUrl(raw: string): boolean {
  if (typeof raw !== 'string' || raw.includes('*') || /\s/.test(raw)) {
    return false;
  }
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Normalizes escaped newline sequences (`\n` and `\r\n`) in PEM private key configuration.
 */
export function normalizePemPrivateKey(raw: string): string {
  return raw.replace(/\r\n/g, '\n').replace(/\\n/g, '\n').trim();
}

/**
 * Validates that a PEM string represents a parseable RSA private key suitable for GitHub App JWT signing.
 */
export function isValidGitHubAppPrivateKey(raw: string): boolean {
  try {
    const normalized = normalizePemPrivateKey(raw);
    if (!normalized.includes('BEGIN') || !normalized.includes('PRIVATE KEY')) {
      return false;
    }
    const key = createPrivateKey({ key: normalized, format: 'pem' });
    return key.type === 'private' && key.asymmetricKeyType === 'rsa';
  } catch {
    return false;
  }
}

const DURATION_REGEX = /^[1-9]\d*[smhd]$/;

const DURATION_MULTIPLIERS_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
};

/**
 * Parses a comma-separated list of HTTP(S) origins into normalized origin strings.
 */
export function parseCorsOrigins(raw: string): string[] {
  const parts = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  if (parts.length === 0) {
    throw new Error('At least one valid origin is required');
  }

  return parts.map((entry) => {
    const parsed = new URL(entry);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Origin must use http or https protocol');
    }
    return parsed.origin;
  });
}

function isValidCorsOriginList(raw: string): boolean {
  try {
    parseCorsOrigins(raw);
    return true;
  } catch {
    return false;
  }
}

/**
 * Parses a positive duration string (e.g., '15m', '7d') into seconds.
 */
export function parseDurationToSeconds(duration: string): number {
  const match = /^([1-9]\d*)([smhd])$/.exec(duration);
  if (!match) {
    throw new Error('Invalid duration format');
  }

  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = DURATION_MULTIPLIERS_SECONDS[unit];
  if (!multiplier) {
    throw new Error('Invalid duration unit');
  }

  return amount * multiplier;
}

/**
 * Extended environment schema specific to the API application.
 */
const baseApiEnvSchema = baseEnvSchema.extend({
  /**
   * Host address to bind the HTTP server to.
   * Defaults to '0.0.0.0' for container and network accessibility.
   */
  HOST: z.string().default('0.0.0.0'),

  /**
   * Base route prefix for versioned API endpoints.
   */
  API_PREFIX: z.string().default('/api/v1'),

  /**
   * Allowed frontend origin(s) (comma-separated HTTP/HTTPS URLs) for browser CSRF/Origin checks.
   */
  CORS_ORIGIN: z.string().min(1).default('http://localhost:5173').refine(isValidCorsOriginList, {
    message: 'Must be one or more valid HTTP/HTTPS origins (comma-separated)',
  }),

  /**
   * MongoDB connection URI for the API service.
   * Validated explicitly without exposing credentials in errors or logs.
   */
  MONGODB_URI: z.string().min(1).refine(isValidMongoUri, {
    message: 'Must be a valid MongoDB connection URI (mongodb:// or mongodb+srv://)',
  }),

  /**
   * Secret key for signing HS256 JWT access tokens.
   * Must be at least 32 characters with no hardcoded default.
   */
  JWT_ACCESS_SECRET: z.string().min(32),

  /**
   * Short-lived access token lifetime (e.g., '15m').
   */
  JWT_ACCESS_TTL: z
    .string()
    .regex(DURATION_REGEX, 'Must be a valid positive duration (e.g. 15m, 1h)')
    .default('15m'),

  /**
   * Expected JWT issuer claim (`iss`).
   */
  JWT_ISSUER: z.string().min(1).default('vibeshield-api'),

  /**
   * Expected JWT audience claim (`aud`).
   */
  JWT_AUDIENCE: z.string().min(1).default('vibeshield-clients'),

  /**
   * Refresh token and session lifetime (e.g., '7d').
   */
  AUTH_REFRESH_TOKEN_TTL: z
    .string()
    .regex(DURATION_REGEX, 'Must be a valid positive duration (e.g. 7d, 24h)')
    .default('7d'),

  /**
   * Optional GitHub App numeric identifier (required when GitHub integration is enabled).
   */
  GITHUB_APP_ID: z
    .string()
    .trim()
    .regex(/^[1-9]\d*$/, 'Must be a positive integer')
    .transform(Number)
    .refine((id) => Number.isSafeInteger(id) && id >= 1, {
      message: 'Must be a valid positive integer',
    })
    .optional(),

  /**
   * Optional GitHub App URL slug (required when GitHub integration is enabled).
   */
  GITHUB_APP_SLUG: z
    .string()
    .trim()
    .min(1, 'Must not be empty')
    .max(100, 'Cannot exceed 100 characters')
    .transform((value) => normalizeSlug(value))
    .refine((value) => SLUG_REGEX.test(value), {
      message: 'Must be a valid lowercase hyphenated slug',
    })
    .optional(),

  /**
   * Optional GitHub App RSA private key in PEM format (supports escaped `\n` newlines).
   */
  GITHUB_APP_PRIVATE_KEY: z
    .string()
    .min(1, 'Must not be empty')
    .transform(normalizePemPrivateKey)
    .refine(isValidGitHubAppPrivateKey, {
      message: 'Must be a valid RSA PEM private key',
    })
    .optional(),

  /**
   * Optional GitHub App OAuth Client ID (required when GitHub integration is enabled).
   */
  GITHUB_CLIENT_ID: z
    .string()
    .trim()
    .min(8)
    .max(128)
    .regex(/^[^\s]+$/, 'Must not contain whitespace')
    .optional(),

  /**
   * Optional GitHub App OAuth Client Secret (required when GitHub integration is enabled).
   */
  GITHUB_CLIENT_SECRET: z
    .string()
    .trim()
    .min(20)
    .max(256)
    .regex(/^[^\s]+$/, 'Must not contain whitespace')
    .optional(),

  /**
   * Optional primary GitHub webhook HMAC secret (required when GitHub integration is enabled).
   */
  GITHUB_WEBHOOK_SECRET: z.string().min(32).max(256).optional(),

  /**
   * Optional previous GitHub webhook HMAC secret for zero-downtime secret rotation.
   */
  GITHUB_WEBHOOK_SECRET_PREVIOUS: z.string().min(32).max(256).optional(),

  /**
   * Optional exact registered GitHub App OAuth callback URL (no wildcards, queries, or fragments).
   */
  GITHUB_CALLBACK_URL: z
    .string()
    .trim()
    .refine(isValidGitHubCallbackUrl, {
      message:
        'Must be a valid HTTP/HTTPS callback URL without wildcards, query parameters, or fragments',
    })
    .optional(),

  /**
   * Explicitly enables optional Redis & BullMQ queue integration in the API process.
   */
  QUEUE_ENABLED: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),

  /**
   * When true alongside QUEUE_ENABLED=true, API startup fails closed if Redis cannot be reached.
   */
  REDIS_REQUIRED: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),

  /**
   * Redis connection URI (redis:// or rediss://). Required when QUEUE_ENABLED=true.
   */
  REDIS_URL: z
    .string()
    .trim()
    .min(1)
    .refine(isValidRedisUrl, {
      message: 'Must be a valid Redis connection URI (redis:// or rediss://)',
    })
    .optional(),

  /**
   * TCP connection timeout in milliseconds for Redis connections (100-60000).
   */
  REDIS_CONNECT_TIMEOUT_MS: z
    .string()
    .trim()
    .regex(/^\d+$/, 'Must be a positive integer timeout in milliseconds')
    .transform(Number)
    .refine((ms) => ms >= 100 && ms <= 60_000, {
      message: 'Must be between 100 and 60000 milliseconds',
    })
    .optional(),

  /**
   * Command timeout in milliseconds for non-blocking Queue producer Redis operations (100-60000).
   */
  REDIS_COMMAND_TIMEOUT_MS: z
    .string()
    .trim()
    .regex(/^\d+$/, 'Must be a positive integer timeout in milliseconds')
    .transform(Number)
    .refine((ms) => ms >= 100 && ms <= 60_000, {
      message: 'Must be between 100 and 60000 milliseconds',
    })
    .optional(),

  /**
   * Default bounded BullMQ job attempts before moving a job to failed (1-20).
   */
  QUEUE_DEFAULT_ATTEMPTS: z
    .string()
    .trim()
    .regex(/^\d+$/, 'Must be a positive integer attempt count')
    .transform(Number)
    .refine((attempts) => attempts >= 1 && attempts <= 20, {
      message: 'Must be between 1 and 20 attempts',
    })
    .optional(),

  /**
   * Base delay in milliseconds for exponential job retry backoff (100-60000).
   */
  QUEUE_BACKOFF_DELAY_MS: z
    .string()
    .trim()
    .regex(/^\d+$/, 'Must be a positive integer backoff delay in milliseconds')
    .transform(Number)
    .refine((ms) => ms >= 100 && ms <= 60_000, {
      message: 'Must be between 100 and 60000 milliseconds',
    })
    .optional(),
});

export const apiEnvSchema = baseApiEnvSchema.superRefine((env, ctx) => {
  if (env.REDIS_REQUIRED && !env.QUEUE_ENABLED) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['QUEUE_ENABLED'],
      message: 'QUEUE_ENABLED must be true when REDIS_REQUIRED is true',
    });
  }

  if (env.QUEUE_ENABLED && env.REDIS_URL === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['REDIS_URL'],
      message: 'REDIS_URL is required when QUEUE_ENABLED is true',
    });
  }

  const hasAnyGitHubSetting =
    REQUIRED_GITHUB_ENV_KEYS.some((key) => env[key] !== undefined) ||
    env.GITHUB_WEBHOOK_SECRET_PREVIOUS !== undefined;

  if (!hasAnyGitHubSetting) {
    return;
  }

  for (const key of REQUIRED_GITHUB_ENV_KEYS) {
    if (env[key] === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [key],
        message: 'Missing required GitHub integration environment variable',
      });
    }
  }

  if (env.NODE_ENV === 'production' && env.GITHUB_CALLBACK_URL !== undefined) {
    const parsed = new URL(env.GITHUB_CALLBACK_URL);
    if (parsed.protocol !== 'https:') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['GITHUB_CALLBACK_URL'],
        message: 'GITHUB_CALLBACK_URL must use HTTPS in production',
      });
    }
  }
});

export type ApiEnv = z.infer<typeof apiEnvSchema>;

/**
 * Validates and retrieves the API environment configuration.
 * Must be invoked at application startup, not during module evaluation.
 */
export function getApiConfig(source?: Record<string, string | undefined>): ApiEnv {
  return validateEnv(apiEnvSchema, source);
}

/**
 * Builds runtime authentication configuration from validated API environment values.
 */
export function toAuthConfig(env: ApiEnv): AuthRuntimeConfig {
  return {
    jwtAccessSecret: env.JWT_ACCESS_SECRET,
    jwtAccessTtl: env.JWT_ACCESS_TTL,
    jwtAccessTtlSeconds: parseDurationToSeconds(env.JWT_ACCESS_TTL),
    jwtIssuer: env.JWT_ISSUER,
    jwtAudience: env.JWT_AUDIENCE,
    refreshTokenTtlSeconds: parseDurationToSeconds(env.AUTH_REFRESH_TOKEN_TTL),
    isProduction: env.NODE_ENV === 'production',
    cookiePath: `${env.API_PREFIX}/auth`,
    allowedOrigins: parseCorsOrigins(env.CORS_ORIGIN),
  };
}

/**
 * Extracts validated GitHub App runtime configuration, or returns `null` when
 * GitHub integration is intentionally left unconfigured.
 */
export function toGitHubConfig(env: ApiEnv): GitHubRuntimeConfig | null {
  if (
    env.GITHUB_APP_ID === undefined ||
    env.GITHUB_APP_SLUG === undefined ||
    env.GITHUB_APP_PRIVATE_KEY === undefined ||
    env.GITHUB_CLIENT_ID === undefined ||
    env.GITHUB_CLIENT_SECRET === undefined ||
    env.GITHUB_WEBHOOK_SECRET === undefined ||
    env.GITHUB_CALLBACK_URL === undefined
  ) {
    return null;
  }

  return {
    appId: env.GITHUB_APP_ID,
    appSlug: env.GITHUB_APP_SLUG,
    privateKeyPem: env.GITHUB_APP_PRIVATE_KEY,
    clientId: env.GITHUB_CLIENT_ID,
    clientSecret: env.GITHUB_CLIENT_SECRET,
    webhookSecret: env.GITHUB_WEBHOOK_SECRET,
    callbackUrl: env.GITHUB_CALLBACK_URL,
    ...(env.GITHUB_WEBHOOK_SECRET_PREVIOUS !== undefined
      ? { previousWebhookSecret: env.GITHUB_WEBHOOK_SECRET_PREVIOUS }
      : {}),
  };
}

/**
 * Extracts validated optional Redis & BullMQ queue runtime configuration, or returns `null` when
 * queue functionality is disabled (`QUEUE_ENABLED !== true`).
 */
export function toQueueConfig(env: ApiEnv): QueueRuntimeConfig | null {
  if (!env.QUEUE_ENABLED || !env.REDIS_URL) {
    return null;
  }

  return {
    enabled: true,
    required: env.REDIS_REQUIRED === true,
    redis: {
      url: env.REDIS_URL,
      connectTimeoutMs: env.REDIS_CONNECT_TIMEOUT_MS ?? DEFAULT_REDIS_OPTIONS.connectTimeoutMs,
      ...(env.REDIS_COMMAND_TIMEOUT_MS !== undefined
        ? { commandTimeoutMs: env.REDIS_COMMAND_TIMEOUT_MS }
        : {}),
    },
    defaultAttempts: env.QUEUE_DEFAULT_ATTEMPTS ?? DEFAULT_QUEUE_POLICY.attempts,
    backoffDelayMs: env.QUEUE_BACKOFF_DELAY_MS ?? DEFAULT_QUEUE_POLICY.backoff.delay ?? 1000,
  };
}

/**
 * Redacts GitHub tokens, PEM private keys, Authorization credentials, and configured
 * GitHub API secret values from arbitrary strings.
 */
export function redactGitHubEnvSecrets(
  input: string,
  env?: Partial<
    Pick<
      ApiEnv,
      | 'GITHUB_APP_PRIVATE_KEY'
      | 'GITHUB_CLIENT_SECRET'
      | 'GITHUB_WEBHOOK_SECRET'
      | 'GITHUB_WEBHOOK_SECRET_PREVIOUS'
    >
  >
): string {
  return redactGitHubSecrets(
    input,
    env
      ? [
          env.GITHUB_APP_PRIVATE_KEY,
          env.GITHUB_CLIENT_SECRET,
          env.GITHUB_WEBHOOK_SECRET,
          env.GITHUB_WEBHOOK_SECRET_PREVIOUS,
        ]
      : []
  );
}
