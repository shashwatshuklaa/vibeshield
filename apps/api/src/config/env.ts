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
  };
}
