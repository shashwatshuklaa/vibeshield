import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export interface RotatedRefreshTokenAttributes {
  sessionId: Types.ObjectId;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
}

export type RotatedRefreshTokenDocument = HydratedDocument<RotatedRefreshTokenAttributes>;

function sanitizeRotatedTokenSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.tokenHash;
  delete ret.__v;
  return ret;
}

export const rotatedRefreshTokenSchema = new Schema<RotatedRefreshTokenAttributes>(
  {
    sessionId: {
      type: Schema.Types.ObjectId,
      ref: 'Session',
      required: [true, 'Session reference is required'],
    },
    tokenHash: {
      type: String,
      required: [true, 'Rotated token hash is required'],
      select: false,
    },
    expiresAt: {
      type: Date,
      required: [true, 'Rotated token expiration timestamp is required'],
    },
  },
  {
    collection: 'rotated_refresh_tokens',
    timestamps: { createdAt: true, updatedAt: false },
    toJSON: {
      transform: sanitizeRotatedTokenSerializedOutput,
    },
    toObject: {
      transform: sanitizeRotatedTokenSerializedOutput,
    },
  }
);

rotatedRefreshTokenSchema.index(
  { tokenHash: 1 },
  { unique: true, name: 'rotated_tokens_hash_unique' }
);
rotatedRefreshTokenSchema.index({ sessionId: 1 }, { name: 'rotated_tokens_session_idx' });
rotatedRefreshTokenSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, name: 'rotated_tokens_expires_at_ttl_idx' }
);

export const RotatedRefreshTokenModel: Model<RotatedRefreshTokenAttributes> =
  getOrCreateModel<RotatedRefreshTokenAttributes>('RotatedRefreshToken', rotatedRefreshTokenSchema);
