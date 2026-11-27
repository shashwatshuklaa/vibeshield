import type {
  EffectiveConnectionStatus,
  InstallationAvailability,
  RepositoryAccessState,
} from '@vibeshield/database';

/**
 * Safe public representation of a project's attached GitHub repository connection.
 */
export interface PublicProjectRepositoryConnection {
  id: string;
  organizationId: string;
  projectId: string;
  installationRecordId: string;
  githubInstallationId: number;
  githubRepositoryId: number;
  ownerLogin: string;
  repoName: string;
  fullName: string;
  htmlUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  isArchivedOnGitHub: boolean;
  repositoryAccessState: RepositoryAccessState;
  installationAvailability: InstallationAvailability;
  effectiveStatus: EffectiveConnectionStatus;
  statusReason: string | null;
  isActive: boolean;
  connectedByUserId: string;
  disconnectedByUserId: string | null;
  connectedAt: Date;
  disconnectedAt: Date | null;
  lastSyncedAt: Date;
  lastWebhookAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConnectProjectRepositoryInput {
  installationRecordId: string;
  githubRepositoryId: number;
}

export interface ConnectProjectRepositoryResult {
  created: boolean;
  connection: PublicProjectRepositoryConnection;
}

export interface ListOrganizationConnectionsQuery {
  page: number;
  perPage: number;
}

export interface PaginatedOrganizationConnectionsResult {
  connections: PublicProjectRepositoryConnection[];
  pagination: {
    page: number;
    perPage: number;
    total: number;
    totalPages: number;
  };
}
