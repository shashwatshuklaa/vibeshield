import { createHash, randomBytes } from 'node:crypto';
import {
  GitHubInstallationStatusValue,
  IntegrationAuditActionValue,
  isValidObjectId,
} from '@vibeshield/database';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import {
  hasOrganizationPermission,
  OrganizationPermission,
} from '../organizations/organization.permissions.js';
import { OrganizationError } from '../organizations/organization.types.js';
import { createGitHubClient, type GitHubClient } from './github.client.js';
import { mongooseGitHubIntegrationStore, type GitHubIntegrationStore } from './github.store.js';
import {
  GitHubError,
  type CompleteGitHubInstallationInput,
  type CompleteGitHubInstallationResult,
  type DiscoveredUserGitHubInstallation,
  type ListGitHubRepositoriesQuery,
  type PaginatedGitHubRepositoriesResult,
  type PublicGitHubInstallation,
  type StartGitHubInstallationInput,
  type StartGitHubInstallationResult,
} from './github.types.js';

const DEFAULT_OAUTH_STATE_TTL_SECONDS = 600; // 10 minutes

export interface GitHubServiceDependencies {
  config?: GitHubRuntimeConfig | null;
  githubClient?: GitHubClient;
  store?: GitHubIntegrationStore;
  now?: () => Date;
  oauthStateTtlSeconds?: number;
  generateState?: () => string;
}

export interface GitHubService {
  startInstallation(
    actorUserId: string,
    organizationId: string,
    input: StartGitHubInstallationInput
  ): Promise<StartGitHubInstallationResult>;
  discoverUserInstallations(
    actorUserId: string,
    organizationId: string,
    input: { state: string; code: string }
  ): Promise<DiscoveredUserGitHubInstallation[]>;
  completeInstallation(
    actorUserId: string,
    organizationId: string,
    input: CompleteGitHubInstallationInput
  ): Promise<CompleteGitHubInstallationResult>;
  listInstallations(organizationId: string): Promise<PublicGitHubInstallation[]>;
  listRepositories(
    organizationId: string,
    query: ListGitHubRepositoriesQuery
  ): Promise<PaginatedGitHubRepositoriesResult>;
}

function hashOAuthState(rawState: string): string {
  return createHash('sha256').update(rawState, 'utf8').digest('hex');
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

/**
 * Creates the GitHub App installation and repository discovery service.
 * Enforces state hashing/anti-replay, GitHub user installation ownership verification,
 * authoritative App metadata fetching, and transactional organization locking.
 */
export function createGitHubService(dependencies: GitHubServiceDependencies = {}): GitHubService {
  const store = dependencies.store ?? mongooseGitHubIntegrationStore;
  const now = dependencies.now ?? (() => new Date());
  const oauthStateTtlSeconds = dependencies.oauthStateTtlSeconds ?? DEFAULT_OAUTH_STATE_TTL_SECONDS;
  const generateState = dependencies.generateState ?? (() => randomBytes(32).toString('base64url'));

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

  function requireGitHubConfig(): GitHubRuntimeConfig {
    if (!resolvedConfig) {
      throw new GitHubError(
        503,
        'GITHUB_INTEGRATION_NOT_CONFIGURED',
        'GitHub integration is not configured on this server'
      );
    }
    return resolvedConfig;
  }

  return {
    async startInstallation(
      actorUserId: string,
      organizationId: string,
      input: StartGitHubInstallationInput
    ): Promise<StartGitHubInstallationResult> {
      const config = requireGitHubConfig();

      const membership = await store.findActiveMembership(organizationId, actorUserId);
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

      const rawState = generateState();
      const stateHash = hashOAuthState(rawState);
      const expiresAt = new Date(now().getTime() + oauthStateTtlSeconds * 1000);

      await store.createOAuthState({
        stateHash,
        userId: actorUserId,
        organizationId,
        expiresAt,
      });

      const authorizeUrl =
        input.mode === 'authorize'
          ? `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(config.clientId)}&state=${encodeURIComponent(rawState)}`
          : `https://github.com/apps/${encodeURIComponent(config.appSlug)}/installations/new?state=${encodeURIComponent(rawState)}`;

      return {
        mode: input.mode,
        authorizeUrl,
        expiresAt,
      };
    },

    async discoverUserInstallations(
      actorUserId: string,
      organizationId: string,
      input: { state: string; code: string }
    ): Promise<DiscoveredUserGitHubInstallation[]> {
      const client = requireGitHubClient();

      const consumed = await store.consumeOAuthState({
        stateHash: hashOAuthState(input.state),
        userId: actorUserId,
        organizationId,
        now: now(),
      });
      if (!consumed) {
        throw new GitHubError(
          400,
          'INVALID_OAUTH_STATE',
          'GitHub authorization state is invalid, expired, or has already been used'
        );
      }

      const userAccessToken = await client.exchangeOAuthCode(input.code);
      return client.listUserInstallations(userAccessToken);
    },

    async completeInstallation(
      actorUserId: string,
      organizationId: string,
      input: CompleteGitHubInstallationInput
    ): Promise<CompleteGitHubInstallationResult> {
      const client = requireGitHubClient();
      const currentNow = now();

      const consumed = await store.consumeOAuthState({
        stateHash: hashOAuthState(input.state),
        userId: actorUserId,
        organizationId,
        now: currentNow,
      });
      if (!consumed) {
        throw new GitHubError(
          400,
          'INVALID_OAUTH_STATE',
          'GitHub authorization state is invalid, expired, or has already been used'
        );
      }

      if (input.setupAction === 'request' && input.installationId === undefined) {
        return {
          status: 'APPROVAL_REQUESTED',
          installation: null,
          message:
            'GitHub organization administrator approval is required before this installation can be linked',
        };
      }

      if (!input.code) {
        throw new GitHubError(
          400,
          'GITHUB_USER_AUTHORIZATION_REQUIRED',
          'GitHub user OAuth authorization code is required to verify installation ownership'
        );
      }

      if (input.installationId === undefined) {
        throw new GitHubError(
          400,
          'GITHUB_INSTALLATION_ID_REQUIRED',
          'GitHub installation identifier is required to complete linking'
        );
      }

      const targetInstallationId = input.installationId;

      // Verify ownership via GitHub API before opening a database transaction lock
      const userAccessToken = await client.exchangeOAuthCode(input.code);
      const userInstallations = await client.listUserInstallations(userAccessToken);
      const ownsInstallation = userInstallations.some(
        (inst) => inst.githubInstallationId === targetInstallationId
      );

      if (!ownsInstallation) {
        throw new GitHubError(
          403,
          'GITHUB_INSTALLATION_NOT_OWNED',
          'The authenticated GitHub account does not have access to this installation'
        );
      }

      const authoritative = await client.getAppInstallation(targetInstallationId);
      const nextStatus = authoritative.suspendedAt
        ? GitHubInstallationStatusValue.SUSPENDED
        : GitHubInstallationStatusValue.ACTIVE;
      const syncTime = now();

      try {
        const savedInstallation = await store.withTransaction(async (tx) => {
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

          const existingActive = await store.findActiveInstallationByGitHubId(
            authoritative.githubInstallationId,
            tx
          );

          if (existingActive && existingActive.organizationId !== organizationId) {
            throw new GitHubError(
              409,
              'GITHUB_INSTALLATION_UNAVAILABLE',
              'This GitHub installation cannot be linked to this organization'
            );
          }

          const installation =
            existingActive && existingActive.organizationId === organizationId
              ? await store.updateInstallationInOrganization(
                  organizationId,
                  existingActive.id,
                  {
                    accountId: authoritative.accountId,
                    accountLogin: authoritative.accountLogin,
                    accountType: authoritative.accountType,
                    repositorySelection: authoritative.repositorySelection,
                    grantedPermissions: authoritative.grantedPermissions,
                    status: nextStatus,
                    isActive: true,
                    suspendedAt: authoritative.suspendedAt,
                    revokedAt: null,
                    lastSyncedAt: syncTime,
                  },
                  tx
                )
              : await store.createInstallation(
                  {
                    organizationId,
                    githubInstallationId: authoritative.githubInstallationId,
                    githubAppId: authoritative.githubAppId,
                    accountId: authoritative.accountId,
                    accountLogin: authoritative.accountLogin,
                    accountType: authoritative.accountType,
                    repositorySelection: authoritative.repositorySelection,
                    grantedPermissions: authoritative.grantedPermissions,
                    status: nextStatus,
                    isActive: true,
                    connectedByUserId: actorUserId,
                    suspendedAt: authoritative.suspendedAt,
                    revokedAt: null,
                    lastSyncedAt: syncTime,
                  },
                  tx
                );

          if (!installation) {
            throw new GitHubError(
              404,
              'GITHUB_INSTALLATION_NOT_FOUND',
              'GitHub installation could not be updated'
            );
          }

          await store.createAuditLog(
            {
              organizationId,
              actorUserId,
              action: IntegrationAuditActionValue.INSTALLATION_CONNECTED,
              githubInstallationId: installation.githubInstallationId,
              metadata: {
                accountLogin: installation.accountLogin,
                accountType: installation.accountType,
                repositorySelection: installation.repositorySelection,
                setupAction: input.setupAction ?? 'install',
              },
            },
            tx
          );

          return installation;
        });

        return {
          status: 'CONNECTED',
          installation: savedInstallation,
        };
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new GitHubError(
            409,
            'GITHUB_INSTALLATION_UNAVAILABLE',
            'This GitHub installation cannot be linked to this organization'
          );
        }
        throw error;
      }
    },

    async listInstallations(organizationId: string): Promise<PublicGitHubInstallation[]> {
      return store.listInstallationsInOrganization(organizationId);
    },

    async listRepositories(
      organizationId: string,
      query: ListGitHubRepositoriesQuery
    ): Promise<PaginatedGitHubRepositoriesResult> {
      const client = requireGitHubClient();

      let installation: PublicGitHubInstallation | null = null;

      if (query.installationRecordId !== undefined) {
        if (!isValidObjectId(query.installationRecordId)) {
          throw new GitHubError(
            400,
            'INVALID_INSTALLATION_ID',
            'Invalid GitHub installation identifier'
          );
        }
        installation = await store.findInstallationByIdInOrganization(
          organizationId,
          query.installationRecordId
        );
        if (!installation || installation.status === GitHubInstallationStatusValue.DISCONNECTED) {
          throw new GitHubError(
            404,
            'GITHUB_INSTALLATION_NOT_FOUND',
            'GitHub App installation not found'
          );
        }
      } else {
        const installations = await store.listInstallationsInOrganization(organizationId);
        if (installations.length === 0) {
          throw new GitHubError(
            404,
            'GITHUB_INSTALLATION_NOT_FOUND',
            'No GitHub App installation is connected to this organization'
          );
        }
        if (installations.length > 1) {
          throw new GitHubError(
            400,
            'INSTALLATION_SELECTION_REQUIRED',
            'Multiple GitHub App installations are linked; specify installationRecordId'
          );
        }
        installation = installations[0]!;
      }

      if (installation.status === GitHubInstallationStatusValue.REVOKED) {
        throw new GitHubError(
          409,
          'GITHUB_INSTALLATION_REVOKED',
          'GitHub App installation access has been revoked'
        );
      }

      if (installation.status === GitHubInstallationStatusValue.SUSPENDED) {
        throw new GitHubError(
          409,
          'GITHUB_INSTALLATION_SUSPENDED',
          'GitHub App installation is suspended on GitHub'
        );
      }

      // Mint ephemeral installation access token solely in memory for this operation
      const installationToken = await client.createInstallationAccessToken(
        installation.githubInstallationId
      );
      const repoPage = await client.listInstallationRepositories(installationToken, {
        page: query.page,
        perPage: query.perPage,
      });

      const totalPages =
        repoPage.totalCount === 0 ? 0 : Math.ceil(repoPage.totalCount / query.perPage);

      return {
        installationId: installation.id,
        githubInstallationId: installation.githubInstallationId,
        repositories: repoPage.repositories,
        pagination: {
          page: query.page,
          perPage: query.perPage,
          total: repoPage.totalCount,
          totalPages,
          hasNextPage: repoPage.hasNextPage,
        },
      };
    },
  };
}
