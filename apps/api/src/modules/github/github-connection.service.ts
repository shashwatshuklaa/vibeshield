import {
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  IntegrationAuditActionValue,
  isInstallationActiveStatus,
  isValidObjectId,
  RepositoryAccessStateValue,
  type GitHubInstallationStatus,
  type InstallationAvailability,
  type IntegrationAuditAction,
  type RepositoryAccessState,
} from '@vibeshield/database';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import {
  hasOrganizationPermission,
  OrganizationPermission,
} from '../organizations/organization.permissions.js';
import { OrganizationError } from '../organizations/organization.types.js';
import { ProjectError } from '../projects/project.types.js';
import { createGitHubClient, type GitHubClient } from './github.client.js';
import { GitHubError, type PublicGitHubRepository } from './github.types.js';
import {
  mongooseGitHubRepositoryConnectionStore,
  type GitHubRepositoryConnectionStore,
} from './github-connection.store.js';
import type {
  ConnectProjectRepositoryInput,
  ConnectProjectRepositoryResult,
  ListOrganizationConnectionsQuery,
  PaginatedOrganizationConnectionsResult,
  PublicProjectRepositoryConnection,
} from './github-connection.types.js';

export interface GitHubRepositoryConnectionServiceDependencies {
  config?: GitHubRuntimeConfig | null;
  githubClient?: GitHubClient;
  store?: GitHubRepositoryConnectionStore;
  now?: () => Date;
}

export interface GitHubRepositoryConnectionService {
  connectRepository(
    actorUserId: string,
    organizationId: string,
    projectId: string,
    input: ConnectProjectRepositoryInput
  ): Promise<ConnectProjectRepositoryResult>;
  getProjectRepository(
    organizationId: string,
    projectId: string
  ): Promise<PublicProjectRepositoryConnection>;
  syncProjectRepository(
    actorUserId: string,
    organizationId: string,
    projectId: string
  ): Promise<PublicProjectRepositoryConnection>;
  disconnectRepository(
    actorUserId: string,
    organizationId: string,
    projectId: string
  ): Promise<PublicProjectRepositoryConnection>;
  listOrganizationConnections(
    organizationId: string,
    query: ListOrganizationConnectionsQuery
  ): Promise<PaginatedOrganizationConnectionsResult>;
}

function toInstallationAvailability(status: GitHubInstallationStatus): InstallationAvailability {
  switch (status) {
    case GitHubInstallationStatusValue.ACTIVE:
      return InstallationAvailabilityValue.ACTIVE;
    case GitHubInstallationStatusValue.SUSPENDED:
      return InstallationAvailabilityValue.SUSPENDED;
    case GitHubInstallationStatusValue.REVOKED:
      return InstallationAvailabilityValue.REVOKED;
    case GitHubInstallationStatusValue.DISCONNECTED:
      return InstallationAvailabilityValue.DISCONNECTED;
  }
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

function mapDuplicateConnectionError(error: unknown): GitHubError {
  const err = error as {
    message?: string;
    keyPattern?: Record<string, unknown>;
    cause?: { message?: string; keyPattern?: Record<string, unknown> };
  };
  const message = `${err.message ?? ''} ${err.cause?.message ?? ''}`;
  const keyPattern = err.keyPattern ?? err.cause?.keyPattern ?? {};

  if (
    message.includes('proj_repo_conn_active_org_repo_unique') ||
    'githubRepositoryId' in keyPattern
  ) {
    return new GitHubError(
      409,
      'REPOSITORY_ALREADY_CONNECTED',
      'GitHub repository is already connected to another active project in this organization'
    );
  }

  return new GitHubError(
    409,
    'PROJECT_ALREADY_CONNECTED',
    'Project already has an active GitHub repository connection'
  );
}

/**
 * Creates the service managing project-to-GitHub repository connections, synchronization,
 * and safe lifecycle detachment with transactional organization locking.
 */
export function createGitHubRepositoryConnectionService(
  dependencies: GitHubRepositoryConnectionServiceDependencies = {}
): GitHubRepositoryConnectionService {
  const store = dependencies.store ?? mongooseGitHubRepositoryConnectionStore;
  const now = dependencies.now ?? (() => new Date());
  const resolvedConfig = dependencies.config ?? null;
  const resolvedClient =
    dependencies.githubClient ??
    (resolvedConfig ? createGitHubClient({ config: resolvedConfig, now }) : null);

  function requireGitHubClient(): GitHubClient {
    if (!resolvedClient) {
      throw new GitHubError(
        503,
        'GITHUB_INTEGRATION_NOT_CONFIGURED',
        'GitHub integration is not configured on this server'
      );
    }
    return resolvedClient;
  }

  return {
    async connectRepository(actorUserId, organizationId, projectId, input) {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }
      if (!isValidObjectId(input.installationRecordId)) {
        throw new GitHubError(
          404,
          'GITHUB_INSTALLATION_NOT_FOUND',
          'GitHub installation not found'
        );
      }

      const client = requireGitHubClient();

      // Pre-flight tenant-scoped validation before calling GitHub APIs
      const project = await store.findProjectByIdInOrganization(organizationId, projectId);
      if (!project) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }
      if (project.archivedAt !== null) {
        throw new GitHubError(
          409,
          'PROJECT_ARCHIVED',
          'Cannot connect a GitHub repository to an archived project'
        );
      }

      const installation = await store.findInstallationByIdInOrganization(
        organizationId,
        input.installationRecordId
      );
      if (!installation) {
        throw new GitHubError(
          404,
          'GITHUB_INSTALLATION_NOT_FOUND',
          'GitHub installation not found'
        );
      }
      if (!isInstallationActiveStatus(installation.status)) {
        throw new GitHubError(
          409,
          'GITHUB_INSTALLATION_UNAVAILABLE',
          'GitHub App installation is not active for repository connections'
        );
      }

      const [existingProjectConn, existingRepoConn] = await Promise.all([
        store.findActiveConnectionByProjectId(organizationId, projectId),
        store.findActiveConnectionByOrgAndRepo(organizationId, input.githubRepositoryId),
      ]);

      if (existingRepoConn && existingRepoConn.projectId !== projectId) {
        throw new GitHubError(
          409,
          'REPOSITORY_ALREADY_CONNECTED',
          'GitHub repository is already connected to another active project in this organization'
        );
      }

      if (existingProjectConn) {
        if (existingProjectConn.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED) {
          throw new GitHubError(
            409,
            'PROJECT_ALREADY_CONNECTED',
            'Disconnect the deleted repository record before connecting a repository to this project'
          );
        }
        if (
          existingProjectConn.githubRepositoryId !== input.githubRepositoryId ||
          existingProjectConn.installationRecordId !== installation.id
        ) {
          throw new GitHubError(
            409,
            'PROJECT_ALREADY_CONNECTED',
            'Project already has an active GitHub repository connection'
          );
        }
      }

      // Authoritative GitHub API checks outside MongoDB transaction lock
      let authoritativeInstallation;
      try {
        authoritativeInstallation = await client.getAppInstallation(
          installation.githubInstallationId
        );
      } catch (error) {
        if (error instanceof GitHubError && error.statusCode === 404) {
          throw new GitHubError(
            409,
            'GITHUB_INSTALLATION_UNAVAILABLE',
            'GitHub App installation was not found on GitHub'
          );
        }
        throw error;
      }

      if (authoritativeInstallation.suspendedAt !== null) {
        throw new GitHubError(
          409,
          'GITHUB_INSTALLATION_UNAVAILABLE',
          'GitHub App installation is suspended on GitHub'
        );
      }

      const installationToken = await client.createInstallationAccessToken(
        installation.githubInstallationId
      );
      const verifiedRepo = await client.findInstallationRepositoryById(
        installationToken,
        input.githubRepositoryId
      );

      if (!verifiedRepo) {
        throw new GitHubError(
          403,
          'GITHUB_REPOSITORY_NOT_ACCESSIBLE',
          'GitHub repository is not accessible through the selected installation'
        );
      }

      const syncTime = now();

      try {
        return await store.withTransaction(async (tx) => {
          const locked = await store.acquireOrganizationLock(organizationId, tx);
          if (!locked) {
            throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
          }

          const membership = await store.findActiveMembership(organizationId, actorUserId, tx);
          if (!membership) {
            throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
          }
          if (
            !hasOrganizationPermission(
              membership.role,
              OrganizationPermission.GITHUB_INTEGRATION_MANAGE
            )
          ) {
            throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
          }

          const txProject = await store.findProjectByIdInOrganization(
            organizationId,
            projectId,
            tx
          );
          if (!txProject) {
            throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
          }
          if (txProject.archivedAt !== null) {
            throw new GitHubError(
              409,
              'PROJECT_ARCHIVED',
              'Cannot connect a GitHub repository to an archived project'
            );
          }

          const txInstallation = await store.findInstallationByIdInOrganization(
            organizationId,
            input.installationRecordId,
            tx
          );
          if (!txInstallation) {
            throw new GitHubError(
              404,
              'GITHUB_INSTALLATION_NOT_FOUND',
              'GitHub installation not found'
            );
          }
          if (!isInstallationActiveStatus(txInstallation.status)) {
            throw new GitHubError(
              409,
              'GITHUB_INSTALLATION_UNAVAILABLE',
              'GitHub App installation is not active for repository connections'
            );
          }

          const [txProjectConn, txRepoConn] = await Promise.all([
            store.findActiveConnectionByProjectId(organizationId, projectId, tx),
            store.findActiveConnectionByOrgAndRepo(
              organizationId,
              verifiedRepo.githubRepositoryId,
              tx
            ),
          ]);

          if (txRepoConn && txRepoConn.projectId !== projectId) {
            throw new GitHubError(
              409,
              'REPOSITORY_ALREADY_CONNECTED',
              'GitHub repository is already connected to another active project in this organization'
            );
          }

          if (txProjectConn) {
            if (txProjectConn.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED) {
              throw new GitHubError(
                409,
                'PROJECT_ALREADY_CONNECTED',
                'Disconnect the deleted repository record before connecting a repository to this project'
              );
            }
            if (
              txProjectConn.githubRepositoryId !== verifiedRepo.githubRepositoryId ||
              txProjectConn.installationRecordId !== txInstallation.id
            ) {
              throw new GitHubError(
                409,
                'PROJECT_ALREADY_CONNECTED',
                'Project already has an active GitHub repository connection'
              );
            }

            const refreshed = await store.updateConnectionByIdInOrganization(
              organizationId,
              txProjectConn.id,
              {
                ownerLogin: verifiedRepo.ownerLogin,
                repoName: verifiedRepo.name,
                fullName: verifiedRepo.fullName,
                htmlUrl: verifiedRepo.htmlUrl,
                defaultBranch: verifiedRepo.defaultBranch,
                isPrivate: verifiedRepo.isPrivate,
                isArchivedOnGitHub: verifiedRepo.isArchived,
                repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
                installationAvailability: InstallationAvailabilityValue.ACTIVE,
                statusReason: null,
                lastSyncedAt: syncTime,
              },
              tx
            );

            if (!refreshed) {
              throw new GitHubError(
                404,
                'REPOSITORY_NOT_CONNECTED',
                'Active repository connection not found'
              );
            }

            await store.createAuditLog(
              {
                organizationId,
                projectId,
                actorUserId,
                action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
                githubInstallationId: txInstallation.githubInstallationId,
                githubRepositoryId: verifiedRepo.githubRepositoryId,
                metadata: {
                  reconnected: true,
                  fullName: verifiedRepo.fullName,
                  defaultBranch: verifiedRepo.defaultBranch,
                  isPrivate: verifiedRepo.isPrivate,
                },
              },
              tx
            );

            return {
              created: false,
              connection: refreshed,
            };
          }

          const created = await store.createConnection(
            {
              organizationId,
              projectId,
              installationRecordId: txInstallation.id,
              githubInstallationId: txInstallation.githubInstallationId,
              githubRepositoryId: verifiedRepo.githubRepositoryId,
              ownerLogin: verifiedRepo.ownerLogin,
              repoName: verifiedRepo.name,
              fullName: verifiedRepo.fullName,
              htmlUrl: verifiedRepo.htmlUrl,
              defaultBranch: verifiedRepo.defaultBranch,
              isPrivate: verifiedRepo.isPrivate,
              isArchivedOnGitHub: verifiedRepo.isArchived,
              repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
              installationAvailability: InstallationAvailabilityValue.ACTIVE,
              statusReason: null,
              connectedByUserId: actorUserId,
              connectedAt: syncTime,
              lastSyncedAt: syncTime,
            },
            tx
          );

          await store.createAuditLog(
            {
              organizationId,
              projectId,
              actorUserId,
              action: IntegrationAuditActionValue.REPOSITORY_CONNECTED,
              githubInstallationId: txInstallation.githubInstallationId,
              githubRepositoryId: verifiedRepo.githubRepositoryId,
              metadata: {
                installationRecordId: txInstallation.id,
                fullName: verifiedRepo.fullName,
                defaultBranch: verifiedRepo.defaultBranch,
                isPrivate: verifiedRepo.isPrivate,
              },
            },
            tx
          );

          return {
            created: true,
            connection: created,
          };
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw mapDuplicateConnectionError(error);
        }
        throw error;
      }
    },

    async getProjectRepository(organizationId, projectId) {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      const project = await store.findProjectByIdInOrganization(organizationId, projectId);
      if (!project) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      const connection = await store.findActiveConnectionByProjectId(organizationId, projectId);
      if (!connection) {
        throw new GitHubError(
          404,
          'REPOSITORY_NOT_CONNECTED',
          'Project does not have an active GitHub repository connection'
        );
      }

      return connection;
    },

    async syncProjectRepository(actorUserId, organizationId, projectId) {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      const client = requireGitHubClient();

      const project = await store.findProjectByIdInOrganization(organizationId, projectId);
      if (!project) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      const existingConnection = await store.findActiveConnectionByProjectId(
        organizationId,
        projectId
      );
      if (!existingConnection) {
        throw new GitHubError(
          404,
          'REPOSITORY_NOT_CONNECTED',
          'Project does not have an active GitHub repository connection'
        );
      }

      const installation = await store.findInstallationByIdInOrganization(
        organizationId,
        existingConnection.installationRecordId
      );
      if (!installation) {
        throw new GitHubError(
          404,
          'GITHUB_INSTALLATION_NOT_FOUND',
          'GitHub installation not found'
        );
      }

      const syncTime = now();
      let nextInstallationStatus: GitHubInstallationStatus = installation.status;
      let nextSuspendedAt: Date | null = installation.suspendedAt;
      let nextRevokedAt: Date | null = installation.revokedAt;

      if (
        installation.status !== GitHubInstallationStatusValue.REVOKED &&
        installation.status !== GitHubInstallationStatusValue.DISCONNECTED
      ) {
        try {
          const authoritativeInstallation = await client.getAppInstallation(
            installation.githubInstallationId
          );
          if (authoritativeInstallation.suspendedAt !== null) {
            nextInstallationStatus = GitHubInstallationStatusValue.SUSPENDED;
            nextSuspendedAt = authoritativeInstallation.suspendedAt;
            nextRevokedAt = null;
          } else {
            nextInstallationStatus = GitHubInstallationStatusValue.ACTIVE;
            nextSuspendedAt = null;
            nextRevokedAt = null;
          }
        } catch (error) {
          if (error instanceof GitHubError && error.statusCode === 404) {
            nextInstallationStatus = GitHubInstallationStatusValue.REVOKED;
            nextRevokedAt = syncTime;
          } else {
            throw error;
          }
        }
      }

      const nextInstallationAvailability = toInstallationAvailability(nextInstallationStatus);

      let nextRepoAccessState: RepositoryAccessState = existingConnection.repositoryAccessState;
      let nextStatusReason: string | null = existingConnection.statusReason;
      let updatedRepoMetadata: PublicGitHubRepository | null = null;
      let auditAction: IntegrationAuditAction = IntegrationAuditActionValue.REPOSITORY_SYNCED;

      // Never allow installation unsuspend or manual sync to override REPO_DELETED or restore ACCESS_REVOKED
      const canInspectRepository =
        nextInstallationAvailability === InstallationAvailabilityValue.ACTIVE &&
        existingConnection.repositoryAccessState === RepositoryAccessStateValue.CONNECTED;

      if (canInspectRepository) {
        const installationToken = await client.createInstallationAccessToken(
          installation.githubInstallationId
        );
        const probe = await client.probeRepositoryById(
          installationToken,
          existingConnection.githubRepositoryId
        );

        if (probe.status === 'GONE') {
          nextRepoAccessState = RepositoryAccessStateValue.REPO_DELETED;
          nextStatusReason = 'Repository returned 410 Gone on GitHub';
          auditAction = IntegrationAuditActionValue.REPOSITORY_DELETED;
        } else if (probe.status === 'ACCESS_REVOKED') {
          nextRepoAccessState = RepositoryAccessStateValue.ACCESS_REVOKED;
          nextStatusReason = 'GitHub denied access to the connected repository';
          auditAction = IntegrationAuditActionValue.REPOSITORY_ACCESS_REVOKED;
        } else if (probe.status === 'NOT_FOUND') {
          // GitHub returns 404 for unauthorized private repositories to avoid leaking existence,
          // so REST sync marks ambiguous 404s as ACCESS_REVOKED (awaiting deletion webhook when applicable).
          nextRepoAccessState = RepositoryAccessStateValue.ACCESS_REVOKED;
          nextStatusReason =
            'Repository was not accessible (GitHub returned 404 Not Found; access may be revoked or repository deleted)';
          auditAction = IntegrationAuditActionValue.REPOSITORY_ACCESS_REVOKED;
        } else if (probe.status === 'ACCESSIBLE') {
          // Verify selected-repository installations still grant access (guards against public repo leaks)
          if (installation.repositorySelection === 'selected') {
            const grantedRepo = await client.findInstallationRepositoryById(
              installationToken,
              existingConnection.githubRepositoryId
            );
            if (!grantedRepo) {
              nextRepoAccessState = RepositoryAccessStateValue.ACCESS_REVOKED;
              nextStatusReason = 'Repository is no longer granted to this GitHub App installation';
              auditAction = IntegrationAuditActionValue.REPOSITORY_ACCESS_REVOKED;
            } else {
              updatedRepoMetadata = grantedRepo;
              nextRepoAccessState = RepositoryAccessStateValue.CONNECTED;
              nextStatusReason = null;
            }
          } else {
            updatedRepoMetadata = probe.repository;
            nextRepoAccessState = RepositoryAccessStateValue.CONNECTED;
            nextStatusReason = null;
          }
        }
      } else if (nextInstallationAvailability === InstallationAvailabilityValue.SUSPENDED) {
        if (installation.status !== GitHubInstallationStatusValue.SUSPENDED) {
          auditAction = IntegrationAuditActionValue.INSTALLATION_SUSPENDED;
        }
        if (existingConnection.repositoryAccessState === RepositoryAccessStateValue.CONNECTED) {
          nextStatusReason = 'GitHub App installation is suspended';
        }
      } else if (nextInstallationAvailability === InstallationAvailabilityValue.REVOKED) {
        if (installation.status !== GitHubInstallationStatusValue.REVOKED) {
          auditAction = IntegrationAuditActionValue.INSTALLATION_REVOKED;
        }
        if (existingConnection.repositoryAccessState === RepositoryAccessStateValue.CONNECTED) {
          nextStatusReason = 'GitHub App installation was revoked on GitHub';
        }
      }

      return store.withTransaction(async (tx) => {
        const locked = await store.acquireOrganizationLock(organizationId, tx);
        if (!locked) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }

        const membership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!membership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
        if (
          !hasOrganizationPermission(
            membership.role,
            OrganizationPermission.GITHUB_INTEGRATION_MANAGE
          )
        ) {
          throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
        }

        const txProject = await store.findProjectByIdInOrganization(organizationId, projectId, tx);
        if (!txProject) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }

        const txConnection = await store.findActiveConnectionByProjectId(
          organizationId,
          projectId,
          tx
        );
        if (!txConnection) {
          throw new GitHubError(
            404,
            'REPOSITORY_NOT_CONNECTED',
            'Project does not have an active GitHub repository connection'
          );
        }

        await store.updateInstallationStatusInOrganization(
          organizationId,
          installation.id,
          {
            status: nextInstallationStatus,
            isActive: isInstallationActiveStatus(nextInstallationStatus),
            suspendedAt: nextSuspendedAt,
            revokedAt: nextRevokedAt,
            lastSyncedAt: syncTime,
          },
          tx
        );

        // Preserve terminal repository access states against concurrent revocation/deletion updates
        let effectiveRepoAccessState = nextRepoAccessState;
        let effectiveStatusReason = nextStatusReason;
        let effectiveMetadata = updatedRepoMetadata;

        if (txConnection.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED) {
          effectiveRepoAccessState = RepositoryAccessStateValue.REPO_DELETED;
          effectiveStatusReason = txConnection.statusReason;
          effectiveMetadata = null;
        } else if (
          txConnection.repositoryAccessState === RepositoryAccessStateValue.ACCESS_REVOKED &&
          effectiveRepoAccessState === RepositoryAccessStateValue.CONNECTED
        ) {
          effectiveRepoAccessState = RepositoryAccessStateValue.ACCESS_REVOKED;
          effectiveStatusReason = txConnection.statusReason;
          effectiveMetadata = null;
        }

        const updatedConnection = await store.updateConnectionByIdInOrganization(
          organizationId,
          txConnection.id,
          {
            ...(effectiveMetadata
              ? {
                  ownerLogin: effectiveMetadata.ownerLogin,
                  repoName: effectiveMetadata.name,
                  fullName: effectiveMetadata.fullName,
                  htmlUrl: effectiveMetadata.htmlUrl,
                  defaultBranch: effectiveMetadata.defaultBranch,
                  isPrivate: effectiveMetadata.isPrivate,
                  isArchivedOnGitHub: effectiveMetadata.isArchived,
                }
              : {}),
            repositoryAccessState: effectiveRepoAccessState,
            installationAvailability: nextInstallationAvailability,
            statusReason: effectiveStatusReason,
            lastSyncedAt: syncTime,
          },
          tx
        );

        if (!updatedConnection) {
          throw new GitHubError(
            404,
            'REPOSITORY_NOT_CONNECTED',
            'Project does not have an active GitHub repository connection'
          );
        }

        await store.createAuditLog(
          {
            organizationId,
            projectId,
            actorUserId,
            action: auditAction,
            githubInstallationId: installation.githubInstallationId,
            githubRepositoryId: txConnection.githubRepositoryId,
            metadata: {
              fullName: updatedConnection.fullName,
              defaultBranch: updatedConnection.defaultBranch,
              repositoryAccessState: updatedConnection.repositoryAccessState,
              installationAvailability: updatedConnection.installationAvailability,
              effectiveStatus: updatedConnection.effectiveStatus,
            },
          },
          tx
        );

        return updatedConnection;
      });
    },

    async disconnectRepository(actorUserId, organizationId, projectId) {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      const disconnectTime = now();

      return store.withTransaction(async (tx) => {
        const locked = await store.acquireOrganizationLock(organizationId, tx);
        if (!locked) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }

        const membership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!membership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
        if (
          !hasOrganizationPermission(
            membership.role,
            OrganizationPermission.GITHUB_INTEGRATION_MANAGE
          )
        ) {
          throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
        }

        const txProject = await store.findProjectByIdInOrganization(organizationId, projectId, tx);
        if (!txProject) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }

        const existingConnection = await store.findActiveConnectionByProjectId(
          organizationId,
          projectId,
          tx
        );
        if (!existingConnection) {
          throw new GitHubError(
            404,
            'REPOSITORY_NOT_CONNECTED',
            'Project does not have an active GitHub repository connection'
          );
        }

        const disconnected = await store.updateConnectionByIdInOrganization(
          organizationId,
          existingConnection.id,
          {
            repositoryAccessState: RepositoryAccessStateValue.DISCONNECTED,
            installationAvailability: existingConnection.installationAvailability,
            statusReason: 'Disconnected by organization administrator',
            disconnectedByUserId: actorUserId,
            disconnectedAt: disconnectTime,
            lastSyncedAt: disconnectTime,
          },
          tx
        );

        if (!disconnected) {
          throw new GitHubError(
            404,
            'REPOSITORY_NOT_CONNECTED',
            'Project does not have an active GitHub repository connection'
          );
        }

        await store.createAuditLog(
          {
            organizationId,
            projectId,
            actorUserId,
            action: IntegrationAuditActionValue.REPOSITORY_DISCONNECTED,
            githubInstallationId: existingConnection.githubInstallationId,
            githubRepositoryId: existingConnection.githubRepositoryId,
            metadata: {
              fullName: existingConnection.fullName,
              connectionId: existingConnection.id,
            },
          },
          tx
        );

        return disconnected;
      });
    },

    async listOrganizationConnections(organizationId, query) {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }

      const { connections, total } = await store.listActiveConnectionsInOrganization(
        organizationId,
        query
      );

      const totalPages = total === 0 ? 0 : Math.ceil(total / query.perPage);
      return {
        connections,
        pagination: {
          page: query.page,
          perPage: query.perPage,
          total,
          totalPages,
        },
      };
    },
  };
}
