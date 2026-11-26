import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export const GITHUB_ACCOUNT_TYPES = ['User', 'Organization'] as const;
export type GitHubAccountType = (typeof GITHUB_ACCOUNT_TYPES)[number];

export const GitHubAccountTypeValue = {
  USER: 'User',
  ORGANIZATION: 'Organization',
} as const satisfies Record<'USER' | 'ORGANIZATION', GitHubAccountType>;

export const GITHUB_REPOSITORY_SELECTIONS = ['all', 'selected'] as const;
export type GitHubRepositorySelection = (typeof GITHUB_REPOSITORY_SELECTIONS)[number];

export const GitHubRepositorySelectionValue = {
  ALL: 'all',
  SELECTED: 'selected',
} as const satisfies Record<'ALL' | 'SELECTED', GitHubRepositorySelection>;

export const GITHUB_INSTALLATION_STATUSES = [
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'DISCONNECTED',
] as const;
export type GitHubInstallationStatus = (typeof GITHUB_INSTALLATION_STATUSES)[number];

export const GitHubInstallationStatusValue = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  REVOKED: 'REVOKED',
  DISCONNECTED: 'DISCONNECTED',
} as const satisfies Record<GitHubInstallationStatus, GitHubInstallationStatus>;

export function isInstallationActiveStatus(status: unknown): boolean {
  return (
    status === GitHubInstallationStatusValue.ACTIVE ||
    status === GitHubInstallationStatusValue.SUSPENDED
  );
}

function isPositiveInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

function isValidGrantedPermissions(value: unknown): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 30) {
    return false;
  }
  return entries.every(
    ([k, v]) =>
      typeof k === 'string' &&
      k.length > 0 &&
      k.length <= 64 &&
      typeof v === 'string' &&
      v.length > 0 &&
      v.length <= 32
  );
}

export interface GitHubInstallationAttributes {
  organizationId: Types.ObjectId;
  githubInstallationId: number;
  githubAppId: number;
  accountId: number;
  accountLogin: string;
  accountType: GitHubAccountType;
  repositorySelection: GitHubRepositorySelection;
  grantedPermissions: Record<string, string>;
  status: GitHubInstallationStatus;
  isActive: boolean;
  connectedByUserId: Types.ObjectId;
  disconnectedByUserId: Types.ObjectId | null;
  suspendedAt: Date | null;
  revokedAt: Date | null;
  lastSyncedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type GitHubInstallationDocument = HydratedDocument<GitHubInstallationAttributes>;

function sanitizeGitHubInstallationOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const githubInstallationSchema: Schema<GitHubInstallationAttributes> =
  new Schema<GitHubInstallationAttributes>(
    {
      organizationId: {
        type: Schema.Types.ObjectId,
        ref: 'Organization',
        required: [true, 'Organization reference is required'],
      },
      githubInstallationId: {
        type: Number,
        required: [true, 'GitHub installation ID is required'],
        validate: {
          validator: isPositiveInteger,
          message: 'GitHub installation ID must be a positive integer',
        },
      },
      githubAppId: {
        type: Number,
        required: [true, 'GitHub App ID is required'],
        validate: {
          validator: isPositiveInteger,
          message: 'GitHub App ID must be a positive integer',
        },
      },
      accountId: {
        type: Number,
        required: [true, 'GitHub account ID is required'],
        validate: {
          validator: isPositiveInteger,
          message: 'GitHub account ID must be a positive integer',
        },
      },
      accountLogin: {
        type: String,
        required: [true, 'GitHub account login is required'],
        trim: true,
        minlength: [1, 'GitHub account login must not be empty'],
        maxlength: [100, 'GitHub account login cannot exceed 100 characters'],
      },
      accountType: {
        type: String,
        required: [true, 'GitHub account type is required'],
        enum: {
          values: GITHUB_ACCOUNT_TYPES,
          message: 'Invalid GitHub account type',
        },
      },
      repositorySelection: {
        type: String,
        required: [true, 'Repository selection mode is required'],
        enum: {
          values: GITHUB_REPOSITORY_SELECTIONS,
          message: 'Invalid repository selection mode',
        },
      },
      grantedPermissions: {
        type: Schema.Types.Mixed,
        default: () => ({}),
        validate: {
          validator: isValidGrantedPermissions,
          message: 'Granted permissions must be a bounded string key-value map',
        },
      },
      status: {
        type: String,
        required: true,
        enum: {
          values: GITHUB_INSTALLATION_STATUSES,
          message: 'Invalid GitHub installation status',
        },
        default: GitHubInstallationStatusValue.ACTIVE,
      },
      isActive: {
        type: Boolean,
        required: true,
      },
      connectedByUserId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'Connecting user reference is required'],
      },
      disconnectedByUserId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        default: null,
      },
      suspendedAt: {
        type: Date,
        default: null,
      },
      revokedAt: {
        type: Date,
        default: null,
      },
      lastSyncedAt: {
        type: Date,
        required: [true, 'Last synced timestamp is required'],
        default: () => new Date(),
      },
    },
    {
      collection: 'github_installations',
      timestamps: true,
      toJSON: {
        transform: sanitizeGitHubInstallationOutput,
      },
      toObject: {
        transform: sanitizeGitHubInstallationOutput,
      },
    }
  );

githubInstallationSchema.pre('validate', function () {
  const expectedActive = isInstallationActiveStatus(this.status);
  if (this.isActive === undefined) {
    this.isActive = expectedActive;
  } else if (typeof this.status === 'string' && this.isActive !== expectedActive) {
    this.invalidate(
      'isActive',
      'isActive must match installation lifecycle status (true for ACTIVE/SUSPENDED, false otherwise)'
    );
  }
});

githubInstallationSchema.index(
  { githubInstallationId: 1 },
  {
    unique: true,
    partialFilterExpression: { isActive: true },
    name: 'github_installations_active_id_unique',
  }
);
githubInstallationSchema.index(
  { organizationId: 1, isActive: 1, status: 1 },
  { name: 'github_installations_org_active_status_idx' }
);
githubInstallationSchema.index(
  { organizationId: 1, githubInstallationId: 1 },
  { name: 'github_installations_org_gh_id_idx' }
);

export const GitHubInstallationModel: Model<GitHubInstallationAttributes> =
  getOrCreateModel<GitHubInstallationAttributes>('GitHubInstallation', githubInstallationSchema);
