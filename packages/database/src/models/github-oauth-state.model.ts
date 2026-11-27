import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

const SHA256_HEX_REGEX = /^[a-f0-9]{64}$/;

export const GITHUB_OAUTH_STATE_KINDS = ['OAUTH_AUTHORIZE', 'INSTALLATION_SELECTION'] as const;
export type GitHubOAuthStateKind = (typeof GITHUB_OAUTH_STATE_KINDS)[number];

export const GitHubOAuthStateKindValue = {
  OAUTH_AUTHORIZE: 'OAUTH_AUTHORIZE',
  INSTALLATION_SELECTION: 'INSTALLATION_SELECTION',
} as const satisfies Record<GitHubOAuthStateKind, GitHubOAuthStateKind>;

export interface GitHubOAuthStateAttributes {
  stateHash: string;
  kind: GitHubOAuthStateKind;
  userId: Types.ObjectId;
  organizationId: Types.ObjectId;
  encryptedCodeVerifier: string | null;
  allowedInstallationIds?: number[];
  usedAt: Date | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type GitHubOAuthStateDocument = HydratedDocument<GitHubOAuthStateAttributes>;

function sanitizeGitHubOAuthStateOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.stateHash;
  delete ret.encryptedCodeVerifier;
  delete ret.__v;
  return ret;
}

export const githubOAuthStateSchema: Schema<GitHubOAuthStateAttributes> =
  new Schema<GitHubOAuthStateAttributes>(
    {
      stateHash: {
        type: String,
        required: [true, 'OAuth state hash is required'],
        trim: true,
        lowercase: true,
        select: false,
        validate: {
          validator: (value: string) => SHA256_HEX_REGEX.test(value),
          message: 'OAuth state hash must be a 64-character SHA-256 hex digest',
        },
      },
      kind: {
        type: String,
        required: true,
        enum: {
          values: GITHUB_OAUTH_STATE_KINDS,
          message: 'Invalid GitHub OAuth state kind',
        },
        default: GitHubOAuthStateKindValue.OAUTH_AUTHORIZE,
      },
      userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User reference is required'],
      },
      organizationId: {
        type: Schema.Types.ObjectId,
        ref: 'Organization',
        required: [true, 'Organization reference is required'],
      },
      encryptedCodeVerifier: {
        type: String,
        default: null,
        select: false,
      },
      allowedInstallationIds: {
        type: [Number],
        default: undefined,
        validate: {
          validator: (values: unknown) =>
            values === undefined ||
            (Array.isArray(values) &&
              values.length <= 200 &&
              values.every((v) => typeof v === 'number' && Number.isInteger(v) && v >= 1)),
          message: 'Allowed installation IDs must be bounded positive integers',
        },
      },
      usedAt: {
        type: Date,
        default: null,
      },
      expiresAt: {
        type: Date,
        required: [true, 'OAuth state expiration timestamp is required'],
      },
    },
    {
      collection: 'github_oauth_states',
      timestamps: true,
      toJSON: {
        transform: sanitizeGitHubOAuthStateOutput,
      },
      toObject: {
        transform: sanitizeGitHubOAuthStateOutput,
      },
    }
  );

githubOAuthStateSchema.index(
  { stateHash: 1 },
  { unique: true, name: 'github_oauth_states_hash_unique' }
);
githubOAuthStateSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, name: 'github_oauth_states_expires_at_ttl_idx' }
);
githubOAuthStateSchema.index(
  { organizationId: 1, userId: 1, expiresAt: 1 },
  { name: 'github_oauth_states_org_user_exp_idx' }
);

export const GitHubOAuthStateModel: Model<GitHubOAuthStateAttributes> =
  getOrCreateModel<GitHubOAuthStateAttributes>('GitHubOAuthState', githubOAuthStateSchema);
