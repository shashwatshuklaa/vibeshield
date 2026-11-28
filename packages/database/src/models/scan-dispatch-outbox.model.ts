import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { redactMongoUri } from '../connection.js';
import { getOrCreateModel } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';

export const OUTBOX_DISPATCH_STATES = ['PENDING', 'DISPATCHED', 'SUPPRESSED'] as const;
export type OutboxDispatchState = (typeof OUTBOX_DISPATCH_STATES)[number];

export const OutboxDispatchStateValue = {
  PENDING: 'PENDING',
  DISPATCHED: 'DISPATCHED',
  SUPPRESSED: 'SUPPRESSED',
} as const satisfies Record<OutboxDispatchState, OutboxDispatchState>;

function isNonNegativeInt(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isPositiveInt(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

function sanitizeSafeOutboxError(value: unknown): string | null {
  if (value === null || value === undefined || typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const urlSanitized = trimmed.replace(/https?:\/\/[^\s"'<>()]+/gi, (matchedUrl) => {
    try {
      const parsed = new URL(matchedUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return '[REDACTED_URL]';
      }
      const hasQuery = parsed.search.length > 0 || matchedUrl.includes('?');
      return `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}${hasQuery ? '?[REDACTED_QUERY]' : ''}`;
    } catch {
      return '[REDACTED_URL]';
    }
  });
  const redacted = redactGitHubSecrets(redactMongoUri(urlSanitized));
  return redacted.length > 500 ? redacted.slice(0, 500) : redacted;
}

export interface ScanDispatchOutboxAttributes {
  scanId: Types.ObjectId;
  organizationId: Types.ObjectId;
  projectId: Types.ObjectId;
  state: OutboxDispatchState;
  attempts: number;
  dispatchGeneration: number;
  nextAttemptAt: Date;
  lastError: string | null;
  dispatchedAt: Date | null;
  suppressedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type ScanDispatchOutboxDocument = HydratedDocument<ScanDispatchOutboxAttributes>;

function sanitizeOutboxSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const scanDispatchOutboxSchema = new Schema<ScanDispatchOutboxAttributes>(
  {
    scanId: {
      type: Schema.Types.ObjectId,
      ref: 'Scan',
      required: [true, 'Scan reference is required'],
    },
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
    state: {
      type: String,
      required: true,
      enum: {
        values: OUTBOX_DISPATCH_STATES,
        message: 'Invalid scan dispatch outbox state',
      },
      default: OutboxDispatchStateValue.PENDING,
    },
    attempts: {
      type: Number,
      required: true,
      default: 0,
      min: [0, 'Dispatch attempt count cannot be negative'],
      max: [10_000, 'Dispatch attempt count exceeds maximum allowed bound'],
      validate: {
        validator: isNonNegativeInt,
        message: 'Dispatch attempts must be a non-negative integer',
      },
    },
    dispatchGeneration: {
      type: Number,
      required: true,
      default: 1,
      min: [1, 'Dispatch generation must be at least 1'],
      max: [1_000_000, 'Dispatch generation exceeds maximum allowed bound'],
      validate: {
        validator: isPositiveInt,
        message: 'Dispatch generation must be a positive integer',
      },
    },
    nextAttemptAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    lastError: {
      type: String,
      default: null,
      maxlength: [500, 'Outbox error summary cannot exceed 500 characters'],
      set: sanitizeSafeOutboxError,
    },
    dispatchedAt: {
      type: Date,
      default: null,
    },
    suppressedAt: {
      type: Date,
      default: null,
    },
  },
  {
    collection: 'scan_dispatch_outbox',
    timestamps: true,
    strict: 'throw',
    toJSON: {
      transform: sanitizeOutboxSerializedOutput,
    },
    toObject: {
      transform: sanitizeOutboxSerializedOutput,
    },
  }
);

scanDispatchOutboxSchema.pre('validate', function () {
  if (this.state === OutboxDispatchStateValue.PENDING) {
    if (this.dispatchedAt !== null && this.dispatchedAt !== undefined) {
      this.invalidate('dispatchedAt', 'PENDING outbox record must have dispatchedAt set to null');
    }
    if (this.suppressedAt !== null && this.suppressedAt !== undefined) {
      this.invalidate('suppressedAt', 'PENDING outbox record must have suppressedAt set to null');
    }
  } else if (this.state === OutboxDispatchStateValue.DISPATCHED) {
    if (!(this.dispatchedAt instanceof Date)) {
      this.invalidate('dispatchedAt', 'DISPATCHED outbox record requires dispatchedAt timestamp');
    }
    if (this.suppressedAt !== null && this.suppressedAt !== undefined) {
      this.invalidate('suppressedAt', 'DISPATCHED outbox record must not set suppressedAt');
    }
  } else if (this.state === OutboxDispatchStateValue.SUPPRESSED) {
    if (!(this.suppressedAt instanceof Date)) {
      this.invalidate('suppressedAt', 'SUPPRESSED outbox record requires suppressedAt timestamp');
    }
    if (this.dispatchedAt !== null && this.dispatchedAt !== undefined) {
      this.invalidate('dispatchedAt', 'SUPPRESSED outbox record must not set dispatchedAt');
    }
  }
});

scanDispatchOutboxSchema.index({ scanId: 1 }, { unique: true, name: 'scan_outbox_scan_unique' });
scanDispatchOutboxSchema.index(
  { state: 1, nextAttemptAt: 1 },
  { name: 'scan_outbox_state_next_attempt_idx' }
);
scanDispatchOutboxSchema.index(
  { organizationId: 1, projectId: 1, createdAt: -1 },
  { name: 'scan_outbox_org_project_created_idx' }
);

export const ScanDispatchOutboxModel: Model<ScanDispatchOutboxAttributes> =
  getOrCreateModel<ScanDispatchOutboxAttributes>('ScanDispatchOutbox', scanDispatchOutboxSchema);
