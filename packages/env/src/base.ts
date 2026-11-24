import { z } from 'zod';

/**
 * Standard Node environments recognized across VibeShield.
 */
export const NodeEnvEnum = z.enum(['development', 'production', 'test']);
export type NodeEnv = z.infer<typeof NodeEnvEnum>;

/**
 * Foundational environment schema providing standard variables common to all Node services.
 * Applications and workers can extend this schema with their domain-specific variables.
 */
export const baseEnvSchema = z.object({
  /**
   * Current execution environment.
   */
  NODE_ENV: NodeEnvEnum.default('development'),

  /**
   * Port on which the HTTP server or service listens.
   * Coerces numeric strings (e.g. "3000") to numbers safely.
   */
  PORT: z
    .string()
    .regex(/^\d+$/, 'Must be a positive integer port number')
    .transform(Number)
    .refine((port) => port > 0 && port <= 65535, {
      message: 'Port must be between 1 and 65535',
    })
    .optional(),

  /**
   * Logging verbosity level.
   */
  LOG_LEVEL: z
    .enum(['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'])
    .default('info'),
});

export type BaseEnv = z.infer<typeof baseEnvSchema>;
