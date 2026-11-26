import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';
import { isValidAuditMetadata, sanitizeAuditMetadata } from '../utils/redaction.js';

export const INTEGRATION_AUDIT_ACTOR_TYPES = ['USER', 'GITHUB_WEBHOOK', 'SYSTEM'] as const;
export type IntegrationAuditActorType = (typeof INTEGRATION_AUDIT_ACTOR_TYPES)[number];

export const IntegrationAuditActorTypeValue = {
  USER: 'USER',
  GITHUB_WEBHOOK: 'GITHUB_WEBHOOK',
  SYSTEM: 'SYSTEM',
} as const satisfies Record<IntegrationAuditActorType, IntegrationAuditActorType>;

export const INTEGRATION_AUDIT_ACTIONS = [
  'INSTALLATION_CONNECTED',
  'INSTALLATION_DISCONNECTED',
  'INSTALLATION_SUSPENDED',
  'INSTALLATION_UNSUSPENDED',
  'INSTALLATION_REVOKED',
  'REPOSITORY_CONNECTED',
  'REPOSITORY_SYNCED',
  'REPOSITORY_DISCONNECTED',
  'REPOSITORY_ACCESS_REVOKED',
  'REPOSITORY_DELETED',
] as const;
export type IntegrationAuditAction = (typeof INTEGRATION_AUDIT_ACTIONS)[number];

export const IntegrationAuditActionValue = {
  INSTALLATION_CONNECTED: 'INSTALLATION_CONNECTED',
  INSTALLATION_DISCONNECTED: 'INSTALLATION_DISCONNECTED',
  INSTALLATION_SUSPENDED: 'INSTALLATION_SUSPENDED',
  INSTALLATION_UNSUSPENDED: 'INSTALLATION_UNSUSPENDED',
  INSTALLATION_REVOKED: 'INSTALLATION_REVOKED',
  REPOSITORY_CONNECTED: 'REPOSITORY_CONNECTED',
  REPOSITORY_SYNCED: 'REPOSITORY_SYNCED',
  REPOSITORY_DISCONNECTED: 'REPOSITORY_DISCONNECTED',
  REPOSITORY_ACCESS_REVOKED: 'REPOSITORY_ACCESS_REVOKED',
  REPOSITORY_DELETED: 'REPOSITORY_DELETED',
} as const satisfies Record<IntegrationAuditAction, IntegrationAuditAction>;

function isNullablePositiveInteger(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isInteger(value) && value >= 1);
}

export interface IntegrationAuditLogAttributes {
  organizationId: Types.ObjectId;
  projectId: Types.ObjectId | null;
  actorType: IntegrationAuditActorType;
  actorUserId: Types.ObjectId | null;
  action: IntegrationAuditAction;
  githubInstallationId: number | null;
  githubRepositoryId: number | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

export type IntegrationAuditLogDocument = HydratedDocument<IntegrationAuditLogAttributes>;

function sanitizeIntegrationAuditLogOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const integrationAuditLogSchema = new Schema<IntegrationAuditLogAttributes>(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'Organization reference is required'],
    },
    projectId: {
      type: Schema.Types.ObjectId,
      ref: 'Project',
      default: null,
    },
    actorType: {
      type: String,
      required: [true, 'Audit actor type is required'],
      enum: {
        values: INTEGRATION_AUDIT_ACTOR_TYPES,
        message: 'Invalid audit actor type',
      },
    },
    actorUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    action: {
      type: String,
      required: [true, 'Audit action is required'],
      enum: {
        values: INTEGRATION_AUDIT_ACTIONS,
        message: 'Invalid integration audit action',
      },
    },
    githubInstallationId: {
      type: Number,
      default: null,
      validate: {
        validator: isNullablePositiveInteger,
        message: 'GitHub installation ID must be null or a positive integer',
      },
    },
    githubRepositoryId: {
      type: Number,
      default: null,
      validate: {
        validator: isNullablePositiveInteger,
        message: 'GitHub repository ID must be null or a positive integer',
      },
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: () => ({}),
      set: (value: unknown) => sanitizeAuditMetadata(value),
      validate: {
        validator: isValidAuditMetadata,
        message: 'Audit metadata must be a bounded, credential-free plain object',
      },
    },
    createdAt: {
      type: Date,
      required: true,
      immutable: true,
      default: () => new Date(),
    },
  },
  {
    collection: 'integration_audit_logs',
    timestamps: { createdAt: true, updatedAt: false },
    toJSON: {
      transform: sanitizeIntegrationAuditLogOutput,
    },
    toObject: {
      transform: sanitizeIntegrationAuditLogOutput,
    },
  }
);

// Reinforce append-only semantics at the Mongoose query layer
integrationAuditLogSchema.pre(
  ['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'findOneAndReplace'],
  function () {
    throw new Error('IntegrationAuditLog records are append-only and cannot be modified');
  }
);

integrationAuditLogSchema.index(
  { organizationId: 1, createdAt: -1 },
  { name: 'integration_audit_logs_org_created_idx' }
);
integrationAuditLogSchema.index(
  { organizationId: 1, projectId: 1, createdAt: -1 },
  { name: 'integration_audit_logs_org_project_created_idx' }
);

export const IntegrationAuditLogModel: Model<IntegrationAuditLogAttributes> =
  getOrCreateModel<IntegrationAuditLogAttributes>('IntegrationAuditLog', integrationAuditLogSchema);
