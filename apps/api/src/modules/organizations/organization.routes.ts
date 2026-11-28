import { Router } from 'express';
import { createAuthenticateMiddleware } from '../../middlewares/authenticate.js';
import {
  createRequireOrganizationMembershipMiddleware,
  requireOrganizationPermission,
} from '../../middlewares/authorize-organization.js';
import type { AuthService } from '../auth/auth.service.js';
import { createAuthService } from '../auth/auth.service.js';
import type { AuthRuntimeConfig } from '../auth/auth.types.js';
import { createGitHubRouter } from '../github/github.routes.js';
import type { GitHubService } from '../github/github.service.js';
import type { GitHubRepositoryConnectionService } from '../github/github-connection.service.js';
import { createProjectRouter } from '../projects/project.routes.js';
import type { ProjectService } from '../projects/project.service.js';
import type { ScanService } from '../scans/scan.service.js';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { createOrganizationController } from './organization.controller.js';
import { OrganizationPermission } from './organization.permissions.js';
import { createOrganizationService, type OrganizationService } from './organization.service.js';

export interface OrganizationRouterDependencies {
  organizationService?: OrganizationService;
  projectService?: ProjectService;
  githubService?: GitHubService;
  repositoryConnectionService?: GitHubRepositoryConnectionService;
  githubConfig?: GitHubRuntimeConfig | null;
  authService?: Pick<AuthService, 'authenticateAccessToken'>;
  authConfig?: AuthRuntimeConfig;
  scanService?: ScanService;
  scanCreateRateLimiter?: import('express').RequestHandler;
}

/**
 * Creates the organization & RBAC router (`/organizations/*`).
 */
export function createOrganizationRouter(
  dependencies: OrganizationRouterDependencies = {}
): Router {
  const router: Router = Router();
  const authService =
    dependencies.authService ?? createAuthService({ config: dependencies.authConfig });
  const organizationService = dependencies.organizationService ?? createOrganizationService();

  const authenticate = createAuthenticateMiddleware(authService);
  const requireOrgMembership = createRequireOrganizationMembershipMiddleware(organizationService);
  const controller = createOrganizationController(organizationService);

  router.use(authenticate);

  router.post('/', controller.create);
  router.get('/', controller.list);

  router.get(
    '/:organizationId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.ORG_READ),
    controller.getById
  );
  router.patch(
    '/:organizationId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.ORG_UPDATE),
    controller.update
  );
  router.delete(
    '/:organizationId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.ORG_DELETE),
    controller.remove
  );

  router.get(
    '/:organizationId/members',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.MEMBER_READ),
    controller.listMembers
  );
  router.post(
    '/:organizationId/members',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.MEMBER_ADD),
    controller.addMember
  );
  router.patch(
    '/:organizationId/members/:membershipId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.MEMBER_UPDATE),
    controller.updateMember
  );
  router.delete(
    '/:organizationId/members/:membershipId',
    requireOrgMembership,
    controller.removeMember
  );

  router.post(
    '/:organizationId/transfer-ownership',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.OWNERSHIP_TRANSFER),
    controller.transferOwnership
  );

  router.use(
    '/:organizationId/projects',
    createProjectRouter({
      projectService: dependencies.projectService,
      repositoryConnectionService: dependencies.repositoryConnectionService,
      githubConfig: dependencies.githubConfig,
      requireOrgMembership,
      scanService: dependencies.scanService,
      scanCreateRateLimiter: dependencies.scanCreateRateLimiter,
    })
  );

  router.use(
    '/:organizationId/github',
    createGitHubRouter({
      githubService: dependencies.githubService,
      repositoryConnectionService: dependencies.repositoryConnectionService,
      githubConfig: dependencies.githubConfig,
      requireOrgMembership,
    })
  );

  return router;
}
