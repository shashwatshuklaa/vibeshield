import type { NextFunction, Request, Response } from 'express';
import { OrganizationError } from '../organizations/organization.types.js';
import {
  cancelScanBodySchema,
  createScanBodySchema,
  listScansQuerySchema,
} from './scan.schemas.js';
import type { ScanService } from './scan.service.js';

function getSingleParam(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * Creates thin HTTP controllers for organization-scoped public scan endpoints.
 *
 * All handlers follow the existing project-controller pattern:
 *  1. Guard against missing req.auth / req.organizationAuth (defense-in-depth; middleware should have blocked earlier).
 *  2. Parse and validate request with Zod (throws ZodError → 400 VALIDATION_ERROR via error handler).
 *  3. Call service method.
 *  4. Respond.
 *  5. Forward any error to next().
 */
export function createScanController(scanService: ScanService) {
  return {
    async create(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params['projectId']);
        const parsed = createScanBodySchema.parse(req.body);
        const scan = await scanService.createScan(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId,
          parsed
        );
        res.status(201).json({ scan });
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
        const projectId = getSingleParam(req.params['projectId']);
        const query = listScansQuerySchema.parse(req.query);
        const result = await scanService.listScans(
          req.organizationAuth.organization.id,
          projectId,
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
        const projectId = getSingleParam(req.params['projectId']);
        const scanId = getSingleParam(req.params['scanId']);
        const scan = await scanService.getScan(
          req.organizationAuth.organization.id,
          projectId,
          scanId
        );
        res.status(200).json({ scan });
      } catch (error) {
        next(error);
      }
    },

    async cancel(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const projectId = getSingleParam(req.params['projectId']);
        const scanId = getSingleParam(req.params['scanId']);
        const parsed = cancelScanBodySchema.parse(req.body);
        const { result, scan } = await scanService.cancelScan(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          projectId,
          scanId,
          parsed
        );

        const statusCode = result === 'CANCELLED_IMMEDIATELY' ? 200 : 202;
        const message =
          result === 'CANCELLED_IMMEDIATELY' ? 'Scan cancelled' : 'Cancellation requested';
        res.status(statusCode).json({ scan, message });
      } catch (error) {
        next(error);
      }
    },
  };
}
