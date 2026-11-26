import { isValidMongoUri } from '@vibeshield/database';
import { baseEnvSchema, validateEnv, z } from '@vibeshield/env';

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
});

export type ApiEnv = z.infer<typeof apiEnvSchema>;

/**
 * Validates and retrieves the API environment configuration.
 * Must be invoked at application startup, not during module evaluation.
 */
export function getApiConfig(source?: Record<string, string | undefined>): ApiEnv {
  return validateEnv(apiEnvSchema, source);
}
