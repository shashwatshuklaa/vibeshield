/**
 * Lifecycle state of a project's underlying GitHub repository link and accessibility.
 */
export type RepositoryAccessState =
  'CONNECTED' | 'ACCESS_REVOKED' | 'REPO_DELETED' | 'DISCONNECTED';

/**
 * Availability state mirrored from the parent GitHub App installation.
 */
export type InstallationAvailability = 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'DISCONNECTED';

/**
 * Represents a tenant-scoped software project in VibeShield.
 * Repository metadata lives separately in `ProjectRepositoryConnection` to keep project
 * CRUD decoupled from external VCS integration state.
 */
export interface Project {
  /**
   * Unique identifier of the project.
   */
  id: string;

  /**
   * Owning organization identifier.
   */
  organizationId: string;

  /**
   * Human-readable project name.
   */
  name: string;

  /**
   * Organization-scoped URL-safe project slug.
   */
  slug: string;

  /**
   * Optional project summary description.
   */
  description: string | null;

  /**
   * User ID of the project creator.
   */
  createdBy: string;

  /**
   * Soft-archive timestamp, or null when active.
   */
  archivedAt: Date | string | null;

  /**
   * Timestamp when the project was created.
   */
  createdAt: Date | string;

  /**
   * Timestamp when the project was last updated.
   */
  updatedAt: Date | string;
}

/**
 * Represents an attached GitHub repository linked to a VibeShield project via a
 * verified GitHub App installation.
 */
export interface ProjectRepositoryConnection {
  id: string;
  organizationId: string;
  projectId: string;
  installationRecordId: string;
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
  connectedByUserId: string;
  disconnectedByUserId: string | null;
  connectedAt: Date | string;
  disconnectedAt: Date | string | null;
  lastSyncedAt: Date | string;
  lastWebhookAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}
