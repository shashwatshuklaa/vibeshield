import { EMAIL_REGEX, normalizeEmail } from '@vibeshield/database';
import { z } from '@vibeshield/env';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

const normalizedEmailSchema = z
  .string()
  .trim()
  .min(1, 'Email is required')
  .max(320, 'Email cannot exceed 320 characters')
  .refine((value) => EMAIL_REGEX.test(value), {
    message: 'Must be a valid email address',
  })
  .transform((value) => normalizeEmail(value));

/**
 * Validation schema for `POST /api/v1/auth/register`.
 */
export const registerSchema = z.object({
  email: normalizedEmailSchema,
  displayName: z
    .string()
    .trim()
    .min(1, 'Display name is required')
    .max(100, 'Display name cannot exceed 100 characters'),
  password: z
    .string()
    .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`)
    .max(PASSWORD_MAX_LENGTH, `Password cannot exceed ${PASSWORD_MAX_LENGTH} characters`),
});

/**
 * Validation schema for `POST /api/v1/auth/login`.
 */
export const loginSchema = z.object({
  email: normalizedEmailSchema,
  password: z
    .string()
    .min(1, 'Password is required')
    .max(PASSWORD_MAX_LENGTH, `Password cannot exceed ${PASSWORD_MAX_LENGTH} characters`),
});

export type RegisterSchemaInput = z.infer<typeof registerSchema>;
export type LoginSchemaInput = z.infer<typeof loginSchema>;
