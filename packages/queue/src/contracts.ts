import type { DefaultJobOptions } from 'bullmq';
import { z } from 'zod';
import { ScanStatus } from '@vibeshield/types';
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
const VALID_JOB_ID_REGEX = /^[A-Za-z0-9._-]{1,128}$/;

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
 * Builds deterministic, colon-free BullMQ job IDs so duplicate dispatches collapse safely.
 */
export function buildScanJobId(input: {
  organizationId: string;
  projectId: string;
  scanId: string;
}): string {
  const cleanSegment = (value: string, label: string): string => {
    const trimmed = value.trim();
    if (!VALID_JOB_ID_REGEX.test(trimmed)) {
      throw new Error(`Invalid ${label} segment for scan job ID`);
    }
    return trimmed;
  };

  const org = cleanSegment(input.organizationId, 'organizationId');
  const proj = cleanSegment(input.projectId, 'projectId');
  const scan = cleanSegment(input.scanId, 'scanId');
  const jobId = `scan-${org}-${proj}-${scan}`;

  if (jobId.length > 180) {
    throw new Error('Generated scan job ID exceeds maximum allowed length');
  }
  return jobId;
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

const safeIdentifierSchema = z.string().trim().min(1).max(128);

export const queueJobMetadataSchema = z
  .object({
    correlationId: safeIdentifierSchema.optional(),
    organizationId: safeIdentifierSchema,
    projectId: safeIdentifierSchema,
    triggeredByUserId: safeIdentifierSchema.nullable().optional(),
    triggerSource: z.enum(['manual', 'webhook', 'scheduled', 'system']),
    enqueuedAt: z.string().trim().min(1).max(64),
  })
  .strict();

export const scanQueueJobPayloadSchema = z
  .object({
    scanId: safeIdentifierSchema,
    organizationId: safeIdentifierSchema,
    projectId: safeIdentifierSchema,
    installationRecordId: safeIdentifierSchema.nullable().optional(),
    githubRepositoryId: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).nullable().optional(),
    commitHash: z
      .string()
      .trim()
      .regex(/^[a-fA-F0-9]{7,64}$/, 'Commit hash must be a valid Git SHA hex string'),
    branch: z.string().trim().min(1).max(255),
    status: z.nativeEnum(ScanStatus),
    metadata: queueJobMetadataSchema,
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
 * Strictly validates an initial scan-job payload before enqueueing, blocking unvalidated keys,
 * oversized blobs, inline credentials, and private keys.
 */
export function validateScanQueueJobPayload(input: unknown): ScanQueueJobPayload {
  assertNoSecretsOrOversizedPayload(input);
  const parsed = scanQueueJobPayloadSchema.parse(input);
  if (
    parsed.metadata.organizationId !== parsed.organizationId ||
    parsed.metadata.projectId !== parsed.projectId
  ) {
    throw new Error('Job payload organizationId/projectId must match metadata ownership fields');
  }
  return parsed;
}
