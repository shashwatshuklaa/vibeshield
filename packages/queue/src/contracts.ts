import type { DefaultJobOptions } from 'bullmq';
import { z } from 'zod';
import type { QueuePolicyDefaults, ScanQueueJobPayload } from './types.js';

/**
 * Versioned, colon-free BullMQ queue names used across VibeShield.
 * Names avoid `:` because BullMQ reserves colons for internal Redis key namespaces.
 */
export const QUEUE_NAMES = {
  SCAN_JOBS: 'vibeshield-v1-scan-jobs',
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

export const QUEUE_KEY_PREFIX = 'vibeshield';

const VALID_QUEUE_NAME_REGEX = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const OBJECT_ID_HEX_REGEX = /^[a-fA-F0-9]{24}$/;

/**
 * Lower numeric value = higher BullMQ execution priority (`0` is unprioritized in BullMQ).
 */
export const JOB_PRIORITIES = {
  CRITICAL: 1,
  HIGH: 2,
  NORMAL: 5,
  LOW: 10,
} as const;

export const DEFAULT_QUEUE_POLICY: Readonly<QueuePolicyDefaults> = Object.freeze({
  attempts: 3,
  backoff: Object.freeze({
    type: 'exponential',
    delay: 1000,
  }),
  removeOnComplete: Object.freeze({
    age: 24 * 60 * 60, // Keep completed jobs at most 24 hours
    count: 1000, // Keep at most 1000 recent completed jobs
  }),
  removeOnFail: Object.freeze({
    age: 7 * 24 * 60 * 60, // Keep failed jobs at most 7 days for post-mortem
    count: 2000, // Cap failed-set growth
  }),
});

export const MAX_JOB_PAYLOAD_BYTES = 16 * 1024; // 16 KB cap to prevent bloated Redis payloads

const SENSITIVE_FIELD_NAME_REGEX =
  /token|secret|private.?key|password|authorization|cookie|pem|credential|signature|api.?key|archive|tarball|source.?code/i;

const INLINE_CREDENTIAL_PATTERN =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9_=-]{10,}|github_pat_[A-Za-z0-9_]{16,})\b|rediss?:\/\/|mongodb(?:\+srv)?:\/\//i;

/**
 * Validates that a BullMQ queue name is non-empty, bounded, and free of colons (`:`).
 */
export function isValidQueueName(name: string): boolean {
  return typeof name === 'string' && !name.includes(':') && VALID_QUEUE_NAME_REGEX.test(name);
}

/**
 * Builds deterministic, colon-free BullMQ job IDs incorporating both `scanId` and monotonically
 * increasing `dispatchGeneration` (`scan-{scanId}-{generation}`), collapsing duplicates within a
 * generation while permitting explicit re-dispatch on new generations.
 */
export function buildScanJobId(input: { scanId: string; dispatchGeneration: number }): string {
  const trimmedScanId = typeof input.scanId === 'string' ? input.scanId.trim() : '';
  if (!OBJECT_ID_HEX_REGEX.test(trimmedScanId)) {
    throw new Error('Invalid scanId for scan job ID: must be a 24-character hex ObjectId');
  }
  if (
    !Number.isSafeInteger(input.dispatchGeneration) ||
    input.dispatchGeneration < 1 ||
    input.dispatchGeneration > 1_000_000
  ) {
    throw new Error('Invalid dispatchGeneration for scan job ID: must be an integer >= 1');
  }

  return `scan-${trimmedScanId.toLowerCase()}-${input.dispatchGeneration}`;
}

/**
 * Merges baseline bounded retry/retention defaults with explicit caller overrides while preventing
 * unbounded retries or unlimited completed/failed retention.
 */
export function buildDefaultJobOptions(
  overrides: Partial<DefaultJobOptions> = {}
): DefaultJobOptions {
  const attempts =
    typeof overrides.attempts === 'number' &&
    Number.isInteger(overrides.attempts) &&
    overrides.attempts >= 1 &&
    overrides.attempts <= 20
      ? overrides.attempts
      : DEFAULT_QUEUE_POLICY.attempts;

  return {
    attempts,
    backoff: overrides.backoff ?? { ...DEFAULT_QUEUE_POLICY.backoff },
    removeOnComplete:
      overrides.removeOnComplete === undefined || overrides.removeOnComplete === false
        ? { ...DEFAULT_QUEUE_POLICY.removeOnComplete }
        : overrides.removeOnComplete,
    removeOnFail:
      overrides.removeOnFail === undefined || overrides.removeOnFail === false
        ? { ...DEFAULT_QUEUE_POLICY.removeOnFail }
        : overrides.removeOnFail,
    ...(overrides.priority !== undefined ? { priority: overrides.priority } : {}),
    ...(overrides.delay !== undefined ? { delay: overrides.delay } : {}),
    sizeLimit: overrides.sizeLimit ?? MAX_JOB_PAYLOAD_BYTES,
  };
}

export const scanQueueJobPayloadSchema = z
  .object({
    scanId: z
      .string()
      .trim()
      .regex(OBJECT_ID_HEX_REGEX, 'scanId must be a valid 24-character hex ObjectId')
      .transform((value) => value.toLowerCase()),
  })
  .strict();

function assertNoSecretsOrOversizedPayload(value: unknown): void {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current === 'string') {
      if (INLINE_CREDENTIAL_PATTERN.test(current)) {
        throw new Error(
          'Job payload must not contain credentials, private keys, or connection URIs'
        );
      }
    } else if (Array.isArray(current)) {
      for (const item of current) {
        stack.push(item);
      }
    } else if (current !== null && typeof current === 'object') {
      for (const [key, entry] of Object.entries(current)) {
        if (SENSITIVE_FIELD_NAME_REGEX.test(key)) {
          throw new Error(`Disallowed sensitive key "${key}" in Redis job payload`);
        }
        stack.push(entry);
      }
    }
  }

  const serializedBytes = Buffer.byteLength(JSON.stringify(value), 'utf8');
  if (serializedBytes > MAX_JOB_PAYLOAD_BYTES) {
    throw new Error(`Job payload exceeds maximum allowed size (${MAX_JOB_PAYLOAD_BYTES} bytes)`);
  }
}

/**
 * Strictly validates a minimal `{ scanId }` scan-job payload before enqueueing or processing,
 * rejecting unknown keys, invalid ObjectId formats, oversized blobs, and inline credentials.
 */
export function validateScanQueueJobPayload(input: unknown): ScanQueueJobPayload {
  assertNoSecretsOrOversizedPayload(input);
  return scanQueueJobPayloadSchema.parse(input);
}
