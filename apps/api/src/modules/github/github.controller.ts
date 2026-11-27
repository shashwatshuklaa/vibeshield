import type { NextFunction, Request, Response } from 'express';
import { OrganizationError } from '../organizations/organization.types.js';
import {
  completeGitHubInstallationSchema,
  discoverUserInstallationsSchema,
  listGitHubRepositoriesQuerySchema,
  startGitHubInstallationSchema,
} from './github.schemas.js';
import type { GitHubService } from './github.service.js';

/**
 * Creates thin HTTP controllers for organization-scoped GitHub installation and
 * repository discovery endpoints.
 */
export function createGitHubController(githubService: GitHubService) {
  return {
    async startInstallation(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = startGitHubInstallationSchema.parse(req.body ?? {});
        const result = await githubService.startInstallation(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          parsed
        );
        res.status(200).json(result);
      } catch (error) {
        next(error);
      }
    },

    async discoverUserInstallations(
      req: Request,
      res: Response,
      next: NextFunction
    ): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = discoverUserInstallationsSchema.parse(req.body);
        const installations = await githubService.discoverUserInstallations(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          parsed
        );
        res.status(200).json({ installations });
      } catch (error) {
        next(error);
      }
    },

    async completeInstallation(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = completeGitHubInstallationSchema.parse(req.body);
        const result = await githubService.completeInstallation(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          parsed
        );
        const statusCode = result.status === 'APPROVAL_REQUESTED' ? 202 : 200;
        res.status(statusCode).json(result);
      } catch (error) {
        next(error);
      }
    },

    async listInstallations(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const installations = await githubService.listInstallations(
          req.organizationAuth.organization.id
        );
        res.status(200).json({ installations });
      } catch (error) {
        next(error);
      }
    },

    async listRepositories(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const query = listGitHubRepositoriesQuerySchema.parse(req.query);
        const result = await githubService.listRepositories(
          req.organizationAuth.organization.id,
          query
        );
        res.status(200).json(result);
      } catch (error) {
        next(error);
      }
    },
  };
}
