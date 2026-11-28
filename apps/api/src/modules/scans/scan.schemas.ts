import { SCAN_LIFECYCLE_STATUSES, SCAN_TRIGGER_SOURCES } from '@vibeshield/types';
import { z } from '@vibeshield/env';

/**
 * Validates a Git reference using the same rules enforced by the ScanModel validator:
 * - Length 1–255 characters.
 * - No ASCII control characters.
 * - No path-unsafe patterns (double dots, leading/trailing slash, .lock suffix, etc.).
 * - No embedded secrets (private keys, GitHub tokens, MongoDB URIs).
 */
const UNSAFE_REF_CHARS_REGEX = /[\s~^:?*[\\]|\.\.|^\/|\/$|\.lock$/;
const INLINE_SECRET_CHECK_REGEX =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9_=-]{10,}|github_pat_[A-Za-z0-9_]{16,})\b|rediss?:\/\/|mongodb(?:\+srv)?:\/\//i;

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isValidGitRef(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 255 &&
    !hasControlCharacter(value) &&
    !UNSAFE_REF_CHARS_REGEX.test(value) &&
    !INLINE_SECRET_CHECK_REGEX.test(value)
  );
}

const SAFE_IDENTIFIER_REGEX = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Schema for `POST /api/v1/organizations/:organizationId/projects/:projectId/scans`.
 *
 * Strict mode rejects any client-supplied repository identifiers, installation IDs,
 * triggerSource, maxAttempts, createdByUserId, or organizationId — these are always
 * resolved from trusted database records or authenticated session context.
 */
export const createScanBodySchema = z
  .object({
    requestedRef: z
      .string()
      .trim()
      .min(1, 'Git reference must not be empty')
      .max(255, 'Git reference cannot exceed 255 characters')
      .refine(isValidGitRef, {
        message:
          'Git reference contains invalid characters or patterns (control characters, path traversal, embedded secrets)',
      }),
    idempotencyKey: z
      .string()
      .trim()
      .regex(
        SAFE_IDENTIFIER_REGEX,
        'Idempotency key must be 1–128 characters: letters, digits, dots, underscores, hyphens'
      )
      .nullable()
      .optional(),
    correlationId: z
      .string()
      .trim()
      .regex(
        SAFE_IDENTIFIER_REGEX,
        'Correlation ID must be 1–128 characters: letters, digits, dots, underscores, hyphens'
      )
      .nullable()
      .optional(),
  })
  .strict();

/**
 * Query schema for `GET /api/v1/organizations/:organizationId/projects/:projectId/scans`.
 */
export const listScansQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).max(10_000).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: z.enum(SCAN_LIFECYCLE_STATUSES).optional(),
    triggerSource: z.enum(SCAN_TRIGGER_SOURCES).optional(),
  })
  .strict();

/**
 * Schema for `POST /api/v1/organizations/:organizationId/projects/:projectId/scans/:scanId/cancel`.
 */
export const cancelScanBodySchema = z
  .object({
    reason: z
      .string()
      .trim()
      .max(300, 'Cancellation reason cannot exceed 300 characters')
      .nullable()
      .optional(),
  })
  .strict();
