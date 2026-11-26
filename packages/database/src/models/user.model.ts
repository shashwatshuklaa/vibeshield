import { Schema, type HydratedDocument, type Model } from 'mongoose';
import { EMAIL_REGEX, getOrCreateModel, normalizeEmail } from '../utils/normalization.js';

export const USER_STATUSES = ['ACTIVE', 'INACTIVE', 'SUSPENDED'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

export const UserStatusValue = {
  ACTIVE: 'ACTIVE',
  INACTIVE: 'INACTIVE',
  SUSPENDED: 'SUSPENDED',
} as const satisfies Record<UserStatus, UserStatus>;

export interface UserAttributes {
  email: string;
  displayName: string;
  passwordHash: string;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
}

export type UserDocument = HydratedDocument<UserAttributes>;

function sanitizeUserSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.passwordHash;
  delete ret.__v;
  return ret;
}

export const userSchema = new Schema<UserAttributes>(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      trim: true,
      lowercase: true,
      maxlength: [320, 'Email cannot exceed 320 characters'],
      set: normalizeEmail,
      validate: {
        validator: (value: string) => EMAIL_REGEX.test(value),
        message: 'Invalid email address format',
      },
    },
    displayName: {
      type: String,
      required: [true, 'Display name is required'],
      trim: true,
      minlength: [1, 'Display name must be at least 1 character'],
      maxlength: [100, 'Display name cannot exceed 100 characters'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
      select: false,
    },
    status: {
      type: String,
      required: true,
      enum: {
        values: USER_STATUSES,
        message: 'Invalid user account status',
      },
      default: UserStatusValue.ACTIVE,
    },
  },
  {
    collection: 'users',
    timestamps: true,
    toJSON: {
      transform: sanitizeUserSerializedOutput,
    },
    toObject: {
      transform: sanitizeUserSerializedOutput,
    },
  }
);

userSchema.index({ email: 1 }, { unique: true, name: 'users_email_unique' });
userSchema.index({ status: 1 }, { name: 'users_status_idx' });

export const UserModel: Model<UserAttributes> = getOrCreateModel<UserAttributes>(
  'User',
  userSchema
);
