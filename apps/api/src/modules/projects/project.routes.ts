import { Router, type RequestHandler } from 'express';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { requireOrganizationPermission } from '../../middlewares/authorize-organization.js';
import { createGitHubRepositoryConnectionController } from '../github/github-connection.controller.js';
import {
  createGitHubRepositoryConnectionService,
  type GitHubRepositoryConnectionService,
} from '../github/github-connection.service.js';
import { OrganizationPermission } from '../organizations/organization.permissions.js';
import { createProjectController } from './project.controller.js';
import { createProjectService, type ProjectService } from './project.service.js';

export interface ProjectRouterDependencies {
  projectService?: ProjectService;
  repositoryConnectionService?: GitHubRepositoryConnectionService;
  githubConfig?: GitHubRuntimeConfig | null;
  requireOrgMembership: RequestHandler;
}

/**
 * Creates the organization-scoped projects router (`/:organizationId/projects/*`).
 */
export function createProjectRouter(dependencies: ProjectRouterDependencies): Router {
  const router: Router = Router({ mergeParams: true });
  const projectService = dependencies.projectService ?? createProjectService();
  const repositoryConnectionService =
    dependencies.repositoryConnectionService ??
    createGitHubRepositoryConnectionService({ config: dependencies.githubConfig });
  const controller = createProjectController(projectService);
  const connectionController = createGitHubRepositoryConnectionController(
    repositoryConnectionService
  );
  const { requireOrgMembership } = dependencies;

  router.post(
    '/',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_CREATE),
    controller.create
  );
  router.get(
    '/',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_READ),
    controller.list
  );
  router.get(
    '/:projectId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_READ),
    controller.getById
  );
  router.patch(
    '/:projectId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_UPDATE),
    controller.update
  );
  router.post(
    '/:projectId/archive',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_ARCHIVE),
    controller.archive
  );
  router.post(
    '/:projectId/restore',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_RESTORE),
    controller.restore
  );
  router.post(
    '/:projectId/github',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    connectionController.connect
  );
  router.get(
    '/:projectId/github',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.PROJECT_READ),
    connectionController.getByProject
  );
  router.post(
    '/:projectId/github/sync',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    connectionController.sync
  );
  router.delete(
    '/:projectId/github',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.GITHUB_INTEGRATION_MANAGE),
    connectionController.disconnect
  );

  return router;
}
