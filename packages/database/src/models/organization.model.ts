import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel, normalizeSlug, SLUG_REGEX } from '../utils/normalization.js';

export interface OrganizationAttributes {
  name: string;
  slug: string;
  createdBy: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

export type OrganizationDocument = HydratedDocument<OrganizationAttributes>;

function sanitizeOrganizationSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const organizationSchema = new Schema<OrganizationAttributes>(
  {
    name: {
      type: String,
      required: [true, 'Organization name is required'],
      trim: true,
      minlength: [2, 'Organization name must be at least 2 characters'],
      maxlength: [100, 'Organization name cannot exceed 100 characters'],
    },
    slug: {
      type: String,
      required: [true, 'Organization slug is required'],
      trim: true,
      lowercase: true,
      minlength: [2, 'Organization slug must be at least 2 characters'],
      maxlength: [64, 'Organization slug cannot exceed 64 characters'],
      set: normalizeSlug,
      validate: {
        validator: (value: string) => SLUG_REGEX.test(value),
        message: 'Organization slug must contain lowercase letters, numbers, and single hyphens',
      },
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Organization creator reference is required'],
    },
  },
  {
    collection: 'organizations',
    timestamps: true,
    toJSON: {
      transform: sanitizeOrganizationSerializedOutput,
    },
    toObject: {
      transform: sanitizeOrganizationSerializedOutput,
    },
  }
);

organizationSchema.index({ slug: 1 }, { unique: true, name: 'organizations_slug_unique' });
organizationSchema.index({ createdBy: 1 }, { name: 'organizations_created_by_idx' });

export const OrganizationModel: Model<OrganizationAttributes> =
  getOrCreateModel<OrganizationAttributes>('Organization', organizationSchema);
