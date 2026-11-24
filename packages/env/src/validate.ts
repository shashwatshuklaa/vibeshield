import type { ZodTypeAny, z } from 'zod';
import { EnvValidationError } from './error.js';

/**
 * Validates an environment object against a provided Zod schema.
 *
 * @param schema - The Zod schema defining required and optional environment variables.
 * @param source - The environment record to validate. Defaults to process.env.
 * @returns The parsed and typed environment configuration.
 * @throws {EnvValidationError} If validation fails, containing sanitized, non-leaking error messages.
 */
export function validateEnv<TSchema extends ZodTypeAny>(
  schema: TSchema,
  source: Record<string, string | undefined> = process.env
): z.infer<TSchema> {
  const result = schema.safeParse(source);

  if (!result.success) {
    throw EnvValidationError.fromZodError(result.error);
  }

  return result.data;
}
