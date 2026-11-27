import type { NextFunction, Request, Response } from 'express';
import { OrganizationError } from '../organizations/organization.types.js';
import {
  connectProjectRepositorySchema,
  listOrganizationConnectionsQuerySchema,
} from './github-connection.schemas.js';
import type { GitHubRepositoryConnectionService } from './github-connection.service.js';

function getSingleParam(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * Creates thin HTTP controllers for project-to-GitHub repository connections and
 * organization-scoped connection listing.
 */
export function createGitHubRepositoryConnectionController(
  connectionService: GitHubRepositoryConnectionService
) {
  return {
    async connect(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const parsed = connectProjectRepositorySchema.parse(req.body);
        const result = await connectionService.connectRepository(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId,
          parsed
        );
        res.status(result.created ? 201 : 200).json({ connection: result.connection });
      } catch (error) {
        next(error);
      }
    },

    async getByProject(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const connection = await connectionService.getProjectRepository(
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ connection });
      } catch (error) {
        next(error);
      }
    },

    async sync(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const connection = await connectionService.syncProjectRepository(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ connection });
      } catch (error) {
        next(error);
      }
    },

    async disconnect(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params.projectId);
        const connection = await connectionService.disconnectRepository(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId
        );
        res.status(200).json({ connection });
      } catch (error) {
        next(error);
      }
    },

    async listByOrganization(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const query = listOrganizationConnectionsQuerySchema.parse(req.query);
        const result = await connectionService.listOrganizationConnections(
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
