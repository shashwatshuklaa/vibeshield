import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel, normalizeSlug, SLUG_REGEX } from '../utils/normalization.js';

export interface ProjectAttributes {
  organizationId: Types.ObjectId;
  name: string;
  slug: string;
  description?: string;
  createdBy: Types.ObjectId;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type ProjectDocument = HydratedDocument<ProjectAttributes>;

function sanitizeProjectSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const projectSchema = new Schema<ProjectAttributes>(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'Organization reference is required'],
    },
    name: {
      type: String,
      required: [true, 'Project name is required'],
      trim: true,
      minlength: [2, 'Project name must be at least 2 characters'],
      maxlength: [120, 'Project name cannot exceed 120 characters'],
    },
    slug: {
      type: String,
      required: [true, 'Project slug is required'],
      trim: true,
      lowercase: true,
      minlength: [2, 'Project slug must be at least 2 characters'],
      maxlength: [64, 'Project slug cannot exceed 64 characters'],
      set: normalizeSlug,
      validate: {
        validator: (value: string) => SLUG_REGEX.test(value),
        message: 'Project slug must contain lowercase letters, numbers, and single hyphens',
      },
    },
    description: {
      type: String,
      trim: true,
      maxlength: [1000, 'Project description cannot exceed 1000 characters'],
      default: undefined,
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Project creator reference is required'],
    },
    archivedAt: {
      type: Date,
      default: null,
    },
  },
  {
    collection: 'projects',
    timestamps: true,
    toJSON: {
      transform: sanitizeProjectSerializedOutput,
    },
    toObject: {
      transform: sanitizeProjectSerializedOutput,
    },
  }
);

projectSchema.index(
  { organizationId: 1, slug: 1 },
  { unique: true, name: 'projects_org_slug_unique' }
);
projectSchema.index(
  { organizationId: 1, archivedAt: 1, createdAt: -1 },
  { name: 'projects_org_archived_created_idx' }
);
projectSchema.index({ createdBy: 1 }, { name: 'projects_created_by_idx' });

export const ProjectModel: Model<ProjectAttributes> = getOrCreateModel<ProjectAttributes>(
  'Project',
  projectSchema
);
