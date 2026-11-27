import { Router, type RequestHandler } from 'express';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { requireOrganizationPermission } from '../../middlewares/authorize-organization.js';
import { OrganizationPermission } from '../organizations/organization.permissions.js';
import { createGitHubController } from './github.controller.js';
import { createGitHubService, type GitHubService } from './github.service.js';
import { createGitHubRepositoryConnectionController } from './github-connection.controller.js';
import {
  createGitHubRepositoryConnectionService,
  type GitHubRepositoryConnectionService,
} from './github-connection.service.js';

export interface GitHubRouterDependencies {
  githubService?: GitHubService;
  repositoryConnectionService?: GitHubRepositoryConnectionService;
  githubConfig?: GitHubRuntimeConfig | null;
  requireOrgMembership: RequestHandler;
}

/**
 * Creates the organization-scoped GitHub App integration router (`/:organizationId/github/*`).
 */
export function createGitHubRouter(dependencies: GitHubRouterDependencies): Router {
  const router: Router = Router({ mergeParams: true });
  const githubService =
    dependencies.githubService ?? createGitHubService({ config: dependencies.githubConfig });
  const repositoryConnectionService =
    dependencies.repositoryConnectionService ??
    createGitHubRepositoryConnectionService({ config: dependencies.githubConfig });
  const controller = createGitHubController(githubService);
  const connectionController = createGitHubRepositoryConnectionController(
    repositoryConnectionService
  );
  const { requireOrgMembership } = dependencies;

  router.post(
    '/installations/start',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    controller.startInstallation
  );
  router.post(
    '/installations/authorize-list',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    controller.discoverUserInstallations
  );
  router.post(
    '/installations/complete',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    controller.completeInstallation
  );
  router.get(
    '/installations',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_READ),
    controller.listInstallations
  );
  router.get(
    '/repositories',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_READ),
    controller.listRepositories
  );
  router.get(
    '/connections',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_READ),
    connectionController.listByOrganization
  );

  return router;
}
