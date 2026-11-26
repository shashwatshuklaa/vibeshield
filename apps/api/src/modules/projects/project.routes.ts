import { Router, type RequestHandler } from 'express';
import { requireOrganizationPermission } from '../../middlewares/authorize-organization.js';
import { OrganizationPermission } from '../organizations/organization.permissions.js';
import { createProjectController } from './project.controller.js';
import { createProjectService, type ProjectService } from './project.service.js';

export interface ProjectRouterDependencies {
  projectService?: ProjectService;
  requireOrgMembership: RequestHandler;
}

/**
 * Creates the organization-scoped projects router (`/:organizationId/projects/*`).
 */
export function createProjectRouter(dependencies: ProjectRouterDependencies): Router {
  const router: Router = Router({ mergeParams: true });
  const projectService = dependencies.projectService ?? createProjectService();
  const controller = createProjectController(projectService);
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

  return router;
}
