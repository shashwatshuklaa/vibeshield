import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export const REPOSITORY_ACCESS_STATES = [
  'CONNECTED',
  'ACCESS_REVOKED',
  'REPO_DELETED',
  'DISCONNECTED',
] as const;
export type RepositoryAccessState = (typeof REPOSITORY_ACCESS_STATES)[number];

export const RepositoryAccessStateValue = {
  CONNECTED: 'CONNECTED',
  ACCESS_REVOKED: 'ACCESS_REVOKED',
  REPO_DELETED: 'REPO_DELETED',
  DISCONNECTED: 'DISCONNECTED',
} as const satisfies Record<RepositoryAccessState, RepositoryAccessState>;

export const INSTALLATION_AVAILABILITIES = [
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'DISCONNECTED',
] as const;
export type InstallationAvailability = (typeof INSTALLATION_AVAILABILITIES)[number];

export const InstallationAvailabilityValue = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  REVOKED: 'REVOKED',
  DISCONNECTED: 'DISCONNECTED',
} as const satisfies Record<InstallationAvailability, InstallationAvailability>;

export const EFFECTIVE_CONNECTION_STATUSES = [
  'CONNECTED',
  'ACCESS_REVOKED',
  'REPO_DELETED',
  'INSTALLATION_SUSPENDED',
  'DISCONNECTED',
] as const;
export type EffectiveConnectionStatus = (typeof EFFECTIVE_CONNECTION_STATUSES)[number];

const FULL_NAME_REGEX = /^[^/\s]+\/[^/\s]+$/;

function isPositiveInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

/**
 * Computes whether a project repository connection occupies its active uniqueness slot.
 * Only explicit disconnection (either at repository or parent installation level) clears `isActive`.
 */
export function computeConnectionIsActive(
  repositoryAccessState: unknown,
  installationAvailability: unknown
): boolean {
  return (
    repositoryAccessState !== RepositoryAccessStateValue.DISCONNECTED &&
    installationAvailability !== InstallationAvailabilityValue.DISCONNECTED
  );
}

/**
 * Derives the effective operational status from orthogonal repository-access and
 * installation-availability states without letting suspend/unsuspend clobber revocation.
 */
export function getEffectiveConnectionStatus(state: {
  repositoryAccessState: RepositoryAccessState;
  installationAvailability: InstallationAvailability;
}): EffectiveConnectionStatus {
  if (
    state.repositoryAccessState === RepositoryAccessStateValue.DISCONNECTED ||
    state.installationAvailability === InstallationAvailabilityValue.DISCONNECTED
  ) {
    return 'DISCONNECTED';
  }
  if (state.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED) {
    return 'REPO_DELETED';
  }
  if (
    state.repositoryAccessState === RepositoryAccessStateValue.ACCESS_REVOKED ||
    state.installationAvailability === InstallationAvailabilityValue.REVOKED
  ) {
    return 'ACCESS_REVOKED';
  }
  if (state.installationAvailability === InstallationAvailabilityValue.SUSPENDED) {
    return 'INSTALLATION_SUSPENDED';
  }
  return 'CONNECTED';
}

export interface ProjectRepositoryConnectionAttributes {
  organizationId: Types.ObjectId;
  projectId: Types.ObjectId;
  installationRecordId: Types.ObjectId;
  githubInstallationId: number;
  githubRepositoryId: number;
  ownerLogin: string;
  repoName: string;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  isArchivedOnGitHub: boolean;
  repositoryAccessState: RepositoryAccessState;
  installationAvailability: InstallationAvailability;
  statusReason: string | null;
  isActive: boolean;
  connectedByUserId: Types.ObjectId;
  disconnectedByUserId: Types.ObjectId | null;
  connectedAt: Date;
  disconnectedAt: Date | null;
  lastSyncedAt: Date;
  lastWebhookAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type ProjectRepositoryConnectionDocument =
  HydratedDocument<ProjectRepositoryConnectionAttributes>;

function sanitizeProjectRepositoryConnectionOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const projectRepositoryConnectionSchema: Schema<ProjectRepositoryConnectionAttributes> =
  new Schema<ProjectRepositoryConnectionAttributes>(
    {
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
      installationRecordId: {
        type: Schema.Types.ObjectId,
        ref: 'GitHubInstallation',
        required: [true, 'GitHub installation record reference is required'],
      },
      githubInstallationId: {
        type: Number,
        required: [true, 'GitHub installation ID is required'],
        validate: {
          validator: isPositiveInteger,
          message: 'GitHub installation ID must be a positive integer',
        },
      },
      githubRepositoryId: {
        type: Number,
        required: [true, 'GitHub repository ID is required'],
        validate: {
          validator: isPositiveInteger,
          message: 'GitHub repository ID must be a positive integer',
        },
      },
      ownerLogin: {
        type: String,
        required: [true, 'Repository owner login is required'],
        trim: true,
        minlength: [1, 'Repository owner login must not be empty'],
        maxlength: [100, 'Repository owner login cannot exceed 100 characters'],
      },
      repoName: {
        type: String,
        required: [true, 'Repository name is required'],
        trim: true,
        minlength: [1, 'Repository name must not be empty'],
        maxlength: [100, 'Repository name cannot exceed 100 characters'],
      },
      fullName: {
        type: String,
        required: [true, 'Repository full name is required'],
        trim: true,
        minlength: [3, 'Repository full name must be at least 3 characters'],
        maxlength: [201, 'Repository full name cannot exceed 201 characters'],
        validate: {
          validator: (value: string) => FULL_NAME_REGEX.test(value),
          message: 'Repository full name must follow owner/repo format',
        },
      },
      defaultBranch: {
        type: String,
        required: [true, 'Repository default branch is required'],
        trim: true,
        minlength: [1, 'Default branch must not be empty'],
        maxlength: [255, 'Default branch cannot exceed 255 characters'],
      },
      isPrivate: {
        type: Boolean,
        required: [true, 'Repository visibility flag is required'],
      },
      isArchivedOnGitHub: {
        type: Boolean,
        required: true,
        default: false,
      },
      repositoryAccessState: {
        type: String,
        required: true,
        enum: {
          values: REPOSITORY_ACCESS_STATES,
          message: 'Invalid repository access state',
        },
        default: RepositoryAccessStateValue.CONNECTED,
      },
      installationAvailability: {
        type: String,
        required: true,
        enum: {
          values: INSTALLATION_AVAILABILITIES,
          message: 'Invalid installation availability state',
        },
        default: InstallationAvailabilityValue.ACTIVE,
      },
      statusReason: {
        type: String,
        trim: true,
        maxlength: [500, 'Status reason cannot exceed 500 characters'],
        default: null,
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
      connectedAt: {
        type: Date,
        required: true,
        default: () => new Date(),
      },
      disconnectedAt: {
        type: Date,
        default: null,
      },
      lastSyncedAt: {
        type: Date,
        required: true,
        default: () => new Date(),
      },
      lastWebhookAt: {
        type: Date,
        default: null,
      },
    },
    {
      collection: 'project_repository_connections',
      timestamps: true,
      toJSON: {
        transform: sanitizeProjectRepositoryConnectionOutput,
      },
      toObject: {
        transform: sanitizeProjectRepositoryConnectionOutput,
      },
    }
  );

projectRepositoryConnectionSchema.pre('validate', function () {
  const expectedActive = computeConnectionIsActive(
    this.repositoryAccessState,
    this.installationAvailability
  );
  if (this.isActive === undefined) {
    this.isActive = expectedActive;
  } else if (
    typeof this.repositoryAccessState === 'string' &&
    typeof this.installationAvailability === 'string' &&
    this.isActive !== expectedActive
  ) {
    this.invalidate(
      'isActive',
      'isActive must be false when repositoryAccessState or installationAvailability is DISCONNECTED, and true otherwise'
    );
  }
});

projectRepositoryConnectionSchema.index(
  { projectId: 1 },
  {
    unique: true,
    partialFilterExpression: { isActive: true },
    name: 'proj_repo_conn_active_project_unique',
  }
);
projectRepositoryConnectionSchema.index(
  { organizationId: 1, githubRepositoryId: 1 },
  {
    unique: true,
    partialFilterExpression: { isActive: true },
    name: 'proj_repo_conn_active_org_repo_unique',
  }
);
projectRepositoryConnectionSchema.index(
  { githubInstallationId: 1, githubRepositoryId: 1, isActive: 1 },
  { name: 'proj_repo_conn_webhook_lookup_idx' }
);
projectRepositoryConnectionSchema.index(
  { organizationId: 1, projectId: 1, isActive: 1 },
  { name: 'proj_repo_conn_org_project_active_idx' }
);

projectRepositoryConnectionSchema.index(
  { installationRecordId: 1, isActive: 1 },
  { name: 'proj_repo_conn_installation_active_idx' }
);

export const ProjectRepositoryConnectionModel: Model<ProjectRepositoryConnectionAttributes> =
  getOrCreateModel<ProjectRepositoryConnectionAttributes>(
    'ProjectRepositoryConnection',
    projectRepositoryConnectionSchema
  );
