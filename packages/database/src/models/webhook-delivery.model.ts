import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';
import { redactGitHubSecrets } from '../utils/redaction.js';

export const WEBHOOK_DELIVERY_OUTCOMES = ['PROCESSING', 'PROCESSED', 'IGNORED', 'FAILED'] as const;
export type WebhookDeliveryOutcome = (typeof WEBHOOK_DELIVERY_OUTCOMES)[number];

export const WebhookDeliveryOutcomeValue = {
  PROCESSING: 'PROCESSING',
  PROCESSED: 'PROCESSED',
  IGNORED: 'IGNORED',
  FAILED: 'FAILED',
} as const satisfies Record<WebhookDeliveryOutcome, WebhookDeliveryOutcome>;

export const WEBHOOK_DELIVERY_MAX_ORGANIZATIONS = 1000;

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/;

function isNullablePositiveInteger(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isInteger(value) && value >= 1);
}

function isPositiveInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

function isNonNegativeInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isBoundedObjectIdArray(value: unknown): boolean {
  return Array.isArray(value) && value.length <= WEBHOOK_DELIVERY_MAX_ORGANIZATIONS;
}

export interface WebhookDeliveryAttributes {
  deliveryId: string;
  event: string;
  action: string | null;
  githubInstallationId: number | null;
  payloadSha256: string;
  outcome: WebhookDeliveryOutcome;
  outcomeReason: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  attemptCount: number;
  targetOrganizationIds: Types.ObjectId[];
  completedOrganizationIds: Types.ObjectId[];
  processedConnectionCount: number;
  processingStartedAt: Date | null;
  processedAt: Date | null;
  failedAt: Date | null;
  receivedAt: Date;
  expiresAt: Date;
}

export type WebhookDeliveryDocument = HydratedDocument<WebhookDeliveryAttributes>;

function sanitizeWebhookDeliveryOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const webhookDeliverySchema = new Schema<WebhookDeliveryAttributes>(
  {
    deliveryId: {
      type: String,
      required: [true, 'Webhook delivery ID is required'],
      trim: true,
      minlength: [1, 'Webhook delivery ID must not be empty'],
      maxlength: [128, 'Webhook delivery ID cannot exceed 128 characters'],
    },
    event: {
      type: String,
      required: [true, 'Webhook event name is required'],
      trim: true,
      minlength: [1, 'Webhook event name must not be empty'],
      maxlength: [64, 'Webhook event name cannot exceed 64 characters'],
    },
    action: {
      type: String,
      trim: true,
      maxlength: [64, 'Webhook action cannot exceed 64 characters'],
      default: null,
    },
    githubInstallationId: {
      type: Number,
      default: null,
      validate: {
        validator: isNullablePositiveInteger,
        message: 'GitHub installation ID must be null or a positive integer',
      },
    },
    payloadSha256: {
      type: String,
      required: [true, 'Webhook payload SHA-256 digest is required'],
      trim: true,
      lowercase: true,
      validate: {
        validator: (value: string) => SHA256_HEX_REGEX.test(value),
        message: 'Webhook payload SHA-256 must be a 64-character hex digest',
      },
    },
    outcome: {
      type: String,
      required: [true, 'Webhook delivery outcome is required'],
      enum: {
        values: WEBHOOK_DELIVERY_OUTCOMES,
        message: 'Invalid webhook delivery outcome',
      },
    },
    outcomeReason: {
      type: String,
      trim: true,
      maxlength: [500, 'Webhook outcome reason cannot exceed 500 characters'],
      default: null,
    },
    errorCode: {
      type: String,
      trim: true,
      maxlength: [64, 'Webhook error code cannot exceed 64 characters'],
      default: null,
    },
    errorMessage: {
      type: String,
      trim: true,
      maxlength: [500, 'Webhook error message cannot exceed 500 characters'],
      set: (value: unknown) =>
        typeof value === 'string' ? redactGitHubSecrets(value).slice(0, 500) : value,
      default: null,
    },
    attemptCount: {
      type: Number,
      required: true,
      default: 1,
      validate: {
        validator: isPositiveInteger,
        message: 'Webhook attempt count must be a positive integer',
      },
    },
    targetOrganizationIds: {
      type: [{ type: Schema.Types.ObjectId, ref: 'Organization' }],
      default: () => [],
      validate: {
        validator: isBoundedObjectIdArray,
        message: `Target organization IDs cannot exceed ${WEBHOOK_DELIVERY_MAX_ORGANIZATIONS} entries`,
      },
    },
    completedOrganizationIds: {
      type: [{ type: Schema.Types.ObjectId, ref: 'Organization' }],
      default: () => [],
      validate: {
        validator: isBoundedObjectIdArray,
        message: `Completed organization IDs cannot exceed ${WEBHOOK_DELIVERY_MAX_ORGANIZATIONS} entries`,
      },
    },
    processedConnectionCount: {
      type: Number,
      required: true,
      default: 0,
      validate: {
        validator: isNonNegativeInteger,
        message: 'Processed connection count must be a non-negative integer',
      },
    },
    processingStartedAt: {
      type: Date,
      default: null,
    },
    processedAt: {
      type: Date,
      default: null,
    },
    failedAt: {
      type: Date,
      default: null,
    },
    receivedAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    expiresAt: {
      type: Date,
      required: [true, 'Webhook delivery expiration timestamp is required'],
    },
  },
  {
    collection: 'webhook_deliveries',
    timestamps: false,
    toJSON: {
      transform: sanitizeWebhookDeliveryOutput,
    },
    toObject: {
      transform: sanitizeWebhookDeliveryOutput,
    },
  }
);

webhookDeliverySchema.index(
  { deliveryId: 1 },
  { unique: true, name: 'webhook_deliveries_delivery_id_unique' }
);
webhookDeliverySchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, name: 'webhook_deliveries_expires_at_ttl_idx' }
);
webhookDeliverySchema.index(
  { githubInstallationId: 1, receivedAt: -1 },
  { name: 'webhook_deliveries_installation_received_idx' }
);

export const WebhookDeliveryModel: Model<WebhookDeliveryAttributes> =
  getOrCreateModel<WebhookDeliveryAttributes>('WebhookDelivery', webhookDeliverySchema);
