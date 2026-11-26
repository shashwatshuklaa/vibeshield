import { Schema, type HydratedDocument, type Model } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export const WEBHOOK_DELIVERY_OUTCOMES = ['PROCESSED', 'IGNORED', 'FAILED'] as const;
export type WebhookDeliveryOutcome = (typeof WEBHOOK_DELIVERY_OUTCOMES)[number];

export const WebhookDeliveryOutcomeValue = {
  PROCESSED: 'PROCESSED',
  IGNORED: 'IGNORED',
  FAILED: 'FAILED',
} as const satisfies Record<WebhookDeliveryOutcome, WebhookDeliveryOutcome>;

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/;

function isNullablePositiveInteger(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isInteger(value) && value >= 1);
}

export interface WebhookDeliveryAttributes {
  deliveryId: string;
  event: string;
  action: string | null;
  githubInstallationId: number | null;
  payloadSha256: string;
  outcome: WebhookDeliveryOutcome;
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
