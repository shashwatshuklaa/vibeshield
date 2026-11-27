import type {
  GitHubAccountType,
  GitHubInstallationStatus,
  GitHubRepositorySelection,
} from '@vibeshield/database';
import { HttpError } from '../../utils/http-error.js';

export type GitHubInstallationFlowMode = 'install' | 'authorize';
export type GitHubSetupAction = 'install' | 'update' | 'request';

/**
 * Safe public representation of a GitHub App installation linked to an organization.
 */
export interface PublicGitHubInstallation {
  id: string;
  organizationId: string;
  githubInstallationId: number;
  githubAppId: number;
  accountId: number;
  accountLogin: string;
  accountType: GitHubAccountType;
  repositorySelection: GitHubRepositorySelection;
  grantedPermissions: Record<string, string>;
  status: GitHubInstallationStatus;
  suspendedAt: Date | null;
  revokedAt: Date | null;
  lastSyncedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Safe GitHub installation summary discovered via user OAuth prior to linking.
 */
export interface DiscoveredUserGitHubInstallation {
  githubInstallationId: number;
  accountLogin: string;
  accountType: GitHubAccountType;
  repositorySelection: GitHubRepositorySelection;
  suspendedAt: string | null;
}

/**
 * Safe repository metadata returned by installation repository discovery.
 */
export interface PublicGitHubRepository {
  githubRepositoryId: number;
  name: string;
  fullName: string;
  ownerLogin: string;
  defaultBranch: string;
  isPrivate: boolean;
  isArchived: boolean;
  htmlUrl: string;
}

export interface StartGitHubInstallationInput {
  mode: GitHubInstallationFlowMode;
}

export interface StartGitHubInstallationResult {
  mode: GitHubInstallationFlowMode;
  authorizeUrl: string;
  expiresAt: Date;
}

export interface DiscoverUserInstallationsInput {
  state: string;
  code: string;
}

export interface DiscoverUserInstallationsResult {
  installations: DiscoveredUserGitHubInstallation[];
  linkState: string;
  expiresAt: Date;
}

export interface CompleteGitHubInstallationInput {
  state: string;
  code?: string;
  installationId?: number;
  setupAction?: GitHubSetupAction;
  error?: string;
  errorDescription?: string;
}

export interface CompleteGitHubInstallationResult {
  status: 'CONNECTED' | 'APPROVAL_REQUESTED';
  installation: PublicGitHubInstallation | null;
  message?: string;
}

export interface ListGitHubRepositoriesQuery {
  installationRecordId?: string;
  page: number;
  perPage: number;
}

export interface PaginatedGitHubRepositoriesResult {
  installationId: string;
  githubInstallationId: number;
  repositories: PublicGitHubRepository[];
  pagination: {
    page: number;
    perPage: number;
    total: number;
    totalPages: number;
    hasNextPage: boolean;
  };
}

/**
 * Input required to mint a least-privilege installation token scoped to a single repository.
 */
export interface CreateRepositoryAcquisitionTokenInput {
  installationId: number;
  githubRepositoryId: number;
}

/**
 * Ephemeral in-memory GitHub App installation access token locked to one repository and read-only contents.
 * Must NEVER be persisted to MongoDB/Redis or returned in HTTP responses.
 */
export interface RepositoryAcquisitionToken {
  token: string;
  expiresAt: Date;
  installationId: number;
  githubRepositoryId: number;
  permissions: {
    contents: 'read';
    metadata?: 'read';
  };
}

/**
 * Outcome of revoking a GitHub installation access token via `DELETE /installation/token`.
 */
export interface RevokeInstallationTokenResult {
  revoked: true;
  alreadyInvalidOrExpired: boolean;
}

export interface ResolveGitHubCommitInput {
  installationToken: string;
  owner: string;
  repo: string;
  ref: string;
  signal?: AbortSignal;
}

export interface OpenRepositoryTarballStreamInput {
  installationToken: string;
  owner: string;
  repo: string;
  commitSha: string;
  maxArchiveBytes: number;
  timeoutMs?: number;
  codeloadTimeoutMs?: number;
  signal?: AbortSignal;
}

export interface GitHubTarballStreamHandle {
  body: ReadableStream<Uint8Array>;
  declaredContentLength: number | null;
}

/**
 * Operational error thrown by GitHub integration operations.
 */
export class GitHubError extends HttpError {
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(statusCode, code, message, details);
    this.name = 'GitHubError';
  }
}
