import type { NextFunction, Request, Response } from 'express';
import { OrganizationError } from '../organizations/organization.types.js';
import {
  createProjectSchema,
  listProjectsQuerySchema,
  updateProjectSchema,
} from './project.schemas.js';
import type { ProjectService } from './project.service.js';

function getSingleParam(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * Creates thin HTTP controllers for organization-scoped project endpoints.
 */
export function createProjectController(projectService: ProjectService) {
  return {
    async create(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = createProjectSchema.parse(req.body);
        const project = await projectService.createProject(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          parsed
        );
        res.status(201).json({ project });
      } catch (error) {
        next(error);
      }
    },

    async list(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const query = listProjectsQuerySchema.parse(req.query);
        const result = await projectService.listProjects(
          req.organizationAuth.organization.id,
          query
        );
        res.status(200).json(result);
      } catch (error) {
        next(error);
      }
    },

    async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const project = await projectService.getProject(
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ project });
      } catch (error) {
        next(error);
      }
    },

    async update(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = updateProjectSchema.parse(req.body);
        const projectId = getSingleParam(req.params.projectId);
        const project = await projectService.updateProject(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId,
          parsed
        );
        res.status(200).json({ project });
      } catch (error) {
        next(error);
      }
    },

    async archive(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const project = await projectService.archiveProject(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ project });
      } catch (error) {
        next(error);
      }
    },

    async restore(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const project = await projectService.restoreProject(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ project });
      } catch (error) {
        next(error);
      }
    },
  };
}
