import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import {
  isTerminalScanLifecycleStatus,
  SCAN_FAILURE_CODES,
  SCAN_LIFECYCLE_STATUSES,
  SCAN_TRIGGER_SOURCES,
  ScanLifecycleStatusValue,
  type ScanFailureCode,
  type ScanLifecycleStatus,
  type ScanTriggerSource,
} from '@vibeshield/types';
import { redactMongoUri } from '../connection.js';
import { getOrCreateModel } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';

const REQUESTED_COMMIT_SHA_REGEX = /^[a-f0-9]{7,64}$/;
const FULL_COMMIT_SHA_REGEX = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const SAFE_IDENTIFIER_REGEX = /^[A-Za-z0-9._-]{1,128}$/;
const UNSAFE_REF_CHARS_REGEX = /[\s~^:?*[\\]|\.\.|^\/|\/$|\.lock$/;
const INLINE_SECRET_CHECK_REGEX =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9_=-]{10,}|github_pat_[A-Za-z0-9_]{16,})\b|rediss?:\/\/|mongodb(?:\+srv)?:\/\//i;

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function isPositiveInt(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

function isNonNegativeInt(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isValidGitRef(value: unknown): boolean {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 255 &&
    !hasControlCharacter(value) &&
    !UNSAFE_REF_CHARS_REGEX.test(value) &&
    !INLINE_SECRET_CHECK_REGEX.test(value)
  );
}

function isNullableHexSha(value: unknown): boolean {
  return value === null || (typeof value === 'string' && REQUESTED_COMMIT_SHA_REGEX.test(value));
}

function isNullableFullCommitSha(value: unknown): boolean {
  return value === null || (typeof value === 'string' && FULL_COMMIT_SHA_REGEX.test(value));
}

function isNullableSafeIdentifier(value: unknown): boolean {
  return (
    value === null ||
    (typeof value === 'string' &&
      SAFE_IDENTIFIER_REGEX.test(value) &&
      !INLINE_SECRET_CHECK_REGEX.test(value))
  );
}

function normalizeNullableLowerHex(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value ?? null;
  }
  const trimmed = value.trim().toLowerCase();
  return trimmed.length === 0 ? null : trimmed;
}

function sanitizeNullableText(value: unknown, maxLength: number): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const redacted = redactGitHubSecrets(redactMongoUri(trimmed));
  return redacted.length > maxLength ? redacted.slice(0, maxLength) : redacted;
}

export interface ScanWorkerLeaseAttributes {
  workerId: string;
  token: string;
  acquiredAt: Date;
  heartbeatAt: Date;
  expiresAt: Date;
}

export interface ScanCancellationAttributes {
  requestedAt: Date | null;
  requestedByUserId: Types.ObjectId | null;
  reason: string | null;
}

export interface ScanAcquisitionAttributes {
  resolvedCommitSha: string;
  compressedArchiveBytes: number;
  extractedBytes: number;
  extractedFileCount: number;
  acquisitionCompletedAt: Date;
}

export interface ScanAttributes {
  organizationId: Types.ObjectId;
  projectId: Types.ObjectId;
  repositoryConnectionId: Types.ObjectId;
  githubInstallationId: number;
  githubRepositoryId: number;
  requestedRef: string;
  requestedCommitHash: string | null;
  resolvedCommitSha: string | null;
  status: ScanLifecycleStatus;
  isActive: boolean;
  triggerSource: ScanTriggerSource;
  createdByUserId: Types.ObjectId | null;
  correlationId: string | null;
  idempotencyKey: string | null;
  attemptCount: number;
  maxAttempts: number;
  lease: ScanWorkerLeaseAttributes | null;
  cancellation: ScanCancellationAttributes;
  acquisition: ScanAcquisitionAttributes | null;
  failureCode: ScanFailureCode | null;
  failureMessage: string | null;
  queuedAt: Date;
  startedAt: Date | null;
  acquiringAt: Date | null;
  inProgressAt: Date | null;
  completedAt: Date | null;
  failedAt: Date | null;
  cancelledAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type ScanDocument = HydratedDocument<ScanAttributes>;

const scanWorkerLeaseSchema = new Schema<ScanWorkerLeaseAttributes>(
  {
    workerId: {
      type: String,
      required: [true, 'Worker identifier is required for an active lease'],
      trim: true,
      minlength: [1, 'Worker identifier must not be empty'],
      maxlength: [128, 'Worker identifier cannot exceed 128 characters'],
      validate: {
        validator: (value: unknown) =>
          typeof value === 'string' && !INLINE_SECRET_CHECK_REGEX.test(value),
        message: 'Worker identifier contains disallowed secret pattern',
      },
    },
    token: {
      type: String,
      required: [true, 'Worker fencing token is required for an active lease'],
      select: false,
      minlength: [16, 'Worker fencing token is too short'],
      maxlength: [128, 'Worker fencing token cannot exceed 128 characters'],
    },
    acquiredAt: {
      type: Date,
      required: [true, 'Lease acquiredAt timestamp is required'],
    },
    heartbeatAt: {
      type: Date,
      required: [true, 'Lease heartbeatAt timestamp is required'],
    },
    expiresAt: {
      type: Date,
      required: [true, 'Lease expiresAt timestamp is required'],
    },
  },
  {
    _id: false,
    strict: 'throw',
  }
);

const scanCancellationSchema = new Schema<ScanCancellationAttributes>(
  {
    requestedAt: {
      type: Date,
      default: null,
    },
    requestedByUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    reason: {
      type: String,
      default: null,
      maxlength: [300, 'Cancellation reason cannot exceed 300 characters'],
      set: (value: unknown) => sanitizeNullableText(value, 300),
    },
  },
  {
    _id: false,
    strict: 'throw',
  }
);

const scanAcquisitionSchema = new Schema<ScanAcquisitionAttributes>(
  {
    resolvedCommitSha: {
      type: String,
      required: [true, 'Resolved immutable commit SHA is required'],
      trim: true,
      lowercase: true,
      validate: {
        validator: (value: unknown) =>
          typeof value === 'string' && FULL_COMMIT_SHA_REGEX.test(value),
        message: 'Resolved commit SHA must be a full 40- or 64-character hex Git SHA',
      },
    },
    compressedArchiveBytes: {
      type: Number,
      required: [true, 'Compressed archive byte size is required'],
      validate: {
        validator: isNonNegativeInt,
        message: 'Compressed archive size must be a non-negative integer',
      },
    },
    extractedBytes: {
      type: Number,
      required: [true, 'Extracted byte size is required'],
      validate: {
        validator: isNonNegativeInt,
        message: 'Extracted byte size must be a non-negative integer',
      },
    },
    extractedFileCount: {
      type: Number,
      required: [true, 'Extracted file count is required'],
      validate: {
        validator: isNonNegativeInt,
        message: 'Extracted file count must be a non-negative integer',
      },
    },
    acquisitionCompletedAt: {
      type: Date,
      required: [true, 'Acquisition completion timestamp is required'],
    },
  },
  {
    _id: false,
    strict: 'throw',
  }
);

function sanitizeScanSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  if (ret.lease && typeof ret.lease === 'object' && !Array.isArray(ret.lease)) {
    const leaseCopy = { ...(ret.lease as Record<string, unknown>) };
    delete leaseCopy.token;
    ret.lease = leaseCopy;
  }
  return ret;
}

export const scanSchema = new Schema<ScanAttributes>(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'Organization reference is required'],
    },
    projectId: {
      type: Schema.Types.ObjectId,
      ref: 'Project',
      required: [true, 'Project reference is required'],
    },
    repositoryConnectionId: {
      type: Schema.Types.ObjectId,
      ref: 'ProjectRepositoryConnection',
      required: [true, 'Project repository connection reference is required'],
    },
    githubInstallationId: {
      type: Number,
      required: [true, 'GitHub installation ID is required'],
      validate: {
        validator: isPositiveInt,
        message: 'GitHub installation ID must be a positive integer',
      },
    },
    githubRepositoryId: {
      type: Number,
      required: [true, 'GitHub repository ID is required'],
      validate: {
        validator: isPositiveInt,
        message: 'GitHub repository ID must be a positive integer',
      },
    },
    requestedRef: {
      type: String,
      required: [true, 'Target branch or Git reference is required'],
      trim: true,
      validate: {
        validator: isValidGitRef,
        message: 'Requested Git reference is invalid or contains unsafe characters',
      },
    },
    requestedCommitHash: {
      type: String,
      default: null,
      set: normalizeNullableLowerHex,
      validate: {
        validator: isNullableHexSha,
        message: 'Requested commit hash must be null or a valid 7-64 char hex Git SHA',
      },
    },
    resolvedCommitSha: {
      type: String,
      default: null,
      set: normalizeNullableLowerHex,
      validate: {
        validator: isNullableFullCommitSha,
        message: 'Resolved commit SHA must be null or a valid 40/64 char hex Git SHA',
      },
    },
    status: {
      type: String,
      required: true,
      enum: {
        values: SCAN_LIFECYCLE_STATUSES,
        message: 'Invalid scan lifecycle status',
      },
      default: ScanLifecycleStatusValue.QUEUED,
    },
    isActive: {
      type: Boolean,
      required: true,
    },
    triggerSource: {
      type: String,
      required: [true, 'Scan trigger source is required'],
      enum: {
        values: SCAN_TRIGGER_SOURCES,
        message: 'Invalid scan trigger source',
      },
    },
    createdByUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    correlationId: {
      type: String,
      default: null,
      trim: true,
      validate: {
        validator: isNullableSafeIdentifier,
        message: 'Correlation ID must be null or a bounded safe identifier',
      },
    },
    idempotencyKey: {
      type: String,
      default: null,
      trim: true,
      validate: {
        validator: isNullableSafeIdentifier,
        message: 'Idempotency key must be null or a bounded safe identifier',
      },
    },
    attemptCount: {
      type: Number,
      required: true,
      default: 0,
      min: [0, 'Attempt count cannot be negative'],
      max: [100, 'Attempt count cannot exceed 100'],
      validate: {
        validator: isNonNegativeInt,
        message: 'Attempt count must be a non-negative integer',
      },
    },
    maxAttempts: {
      type: Number,
      required: true,
      default: 3,
      min: [1, 'Max attempts must be at least 1'],
      max: [20, 'Max attempts cannot exceed 20'],
      validate: {
        validator: isPositiveInt,
        message: 'Max attempts must be a positive integer',
      },
    },
    lease: {
      type: scanWorkerLeaseSchema,
      default: null,
    },
    cancellation: {
      type: scanCancellationSchema,
      default: () => ({
        requestedAt: null,
        requestedByUserId: null,
        reason: null,
      }),
    },
    acquisition: {
      type: scanAcquisitionSchema,
      default: null,
    },
    failureCode: {
      type: String,
      default: null,
      validate: {
        validator: (value: unknown) =>
          value === null || (SCAN_FAILURE_CODES as readonly string[]).includes(String(value)),
        message: 'Invalid scan failure code',
      },
    },
    failureMessage: {
      type: String,
      default: null,
      maxlength: [500, 'Failure message cannot exceed 500 characters'],
      set: (value: unknown) => sanitizeNullableText(value, 500),
    },
    queuedAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    startedAt: {
      type: Date,
      default: null,
    },
    acquiringAt: {
      type: Date,
      default: null,
    },
    inProgressAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    failedAt: {
      type: Date,
      default: null,
    },
    cancelledAt: {
      type: Date,
      default: null,
    },
  },
  {
    collection: 'scans',
    timestamps: true,
    strict: 'throw',
    toJSON: {
      transform: sanitizeScanSerializedOutput,
    },
    toObject: {
      transform: sanitizeScanSerializedOutput,
    },
  }
);

scanSchema.pre('validate', function () {
  const expectedActive = !isTerminalScanLifecycleStatus(this.status);
  if (this.isActive === undefined) {
    this.isActive = expectedActive;
  } else if (typeof this.status === 'string' && this.isActive !== expectedActive) {
    this.invalidate(
      'isActive',
      'isActive must be true for QUEUED/ACQUIRING/IN_PROGRESS scans and false for terminal states'
    );
  }
});

scanSchema.index(
  { organizationId: 1, projectId: 1, createdAt: -1 },
  { name: 'scans_org_project_created_idx' }
);
scanSchema.index(
  { organizationId: 1, projectId: 1, isActive: 1, createdAt: -1 },
  { name: 'scans_org_project_active_idx' }
);
scanSchema.index({ organizationId: 1, status: 1, createdAt: 1 }, { name: 'scans_org_status_idx' });
scanSchema.index(
  { isActive: 1, status: 1, 'lease.expiresAt': 1 },
  { name: 'scans_active_lease_expires_idx' }
);
scanSchema.index(
  { organizationId: 1, projectId: 1, idempotencyKey: 1 },
  {
    unique: true,
    partialFilterExpression: { idempotencyKey: { $type: 'string' } },
    name: 'scans_org_project_idempotency_unique',
  }
);

export const ScanModel: Model<ScanAttributes> = getOrCreateModel<ScanAttributes>(
  'Scan',
  scanSchema
);
