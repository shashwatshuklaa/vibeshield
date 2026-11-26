import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export interface SessionAttributes {
  userId: Types.ObjectId;
  refreshTokenHash: string;
  previousRefreshTokenHash: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type SessionDocument = HydratedDocument<SessionAttributes>;

function sanitizeSessionSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.refreshTokenHash;
  delete ret.previousRefreshTokenHash;
  delete ret.__v;
  return ret;
}

export const sessionSchema = new Schema<SessionAttributes>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Session user reference is required'],
    },
    refreshTokenHash: {
      type: String,
      required: [true, 'Refresh token hash is required'],
      select: false,
    },
    previousRefreshTokenHash: {
      type: String,
      default: null,
      select: false,
    },
    expiresAt: {
      type: Date,
      required: [true, 'Session expiration timestamp is required'],
    },
    revokedAt: {
      type: Date,
      default: null,
    },
    lastUsedAt: {
      type: Date,
      default: null,
    },
  },
  {
    collection: 'sessions',
    timestamps: true,
    toJSON: {
      transform: sanitizeSessionSerializedOutput,
    },
    toObject: {
      transform: sanitizeSessionSerializedOutput,
    },
  }
);

sessionSchema.index(
  { refreshTokenHash: 1 },
  { unique: true, name: 'sessions_refresh_token_hash_unique' }
);
sessionSchema.index(
  { previousRefreshTokenHash: 1 },
  {
    name: 'sessions_prev_refresh_token_hash_idx',
    partialFilterExpression: { previousRefreshTokenHash: { $type: 'string' } },
  }
);
sessionSchema.index(
  { userId: 1, revokedAt: 1, expiresAt: 1 },
  { name: 'sessions_user_active_idx' }
);
sessionSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, name: 'sessions_expires_at_ttl_idx' }
);

export const SessionModel: Model<SessionAttributes> = getOrCreateModel<SessionAttributes>(
  'Session',
  sessionSchema
);
