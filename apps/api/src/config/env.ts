import { isValidMongoUri } from '@vibeshield/database';
import { baseEnvSchema, validateEnv, z } from '@vibeshield/env';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';

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
export const apiEnvSchema = baseEnvSchema.extend({
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
