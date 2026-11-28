import { Router, type RequestHandler } from 'express';
import { requireOrganizationPermission } from '../../middlewares/authorize-organization.js';
import { createScanCreationRateLimiter } from '../../middlewares/scan-rate-limit.js';
import { OrganizationPermission } from '../organizations/organization.permissions.js';
import { createScanController } from './scan.controller.js';
import { createScanService, type ScanService } from './scan.service.js';

export interface ScanRouterDependencies {
  requireOrgMembership: RequestHandler;
  scanService?: ScanService;
  scanCreateRateLimiter?: RequestHandler;
}

/**
 * Creates the organization-scoped public scan router.
 *
 * Mounted at `/:organizationId/projects/:projectId/scans` via `project.routes.ts`
 * using `Router({ mergeParams: true })` so that `organizationId` and `projectId`
 * are always present in `req.params`.
 *
 * Route protection:
 *   authenticate (org router)
 *   → requireOrgMembership (validates organizationId, sets req.organizationAuth)
 *   → requireOrganizationPermission(SCAN_*)
 *   → controller handler
 *
 * No endpoint is reachable before both authentication and RBAC checks pass.
 *
 * Rate limiting for scan creation is implemented as a focused in-process token-bucket
 * per (organizationId, userId). See NOTE below for Scope D details.
 */
export function createScanRouter(dependencies: ScanRouterDependencies): Router {
  const router: Router = Router({ mergeParams: true });
  const { requireOrgMembership } = dependencies;
  const scanService = dependencies.scanService ?? createScanService();
  const scanCreateRateLimiter =
    dependencies.scanCreateRateLimiter ?? createScanCreationRateLimiter();
  const controller = createScanController(scanService);

  // POST /:projectId/scans — create a new scan
  router.post(
    '/',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.SCAN_CREATE),
    scanCreateRateLimiter,
    controller.create
  );

  // GET /:projectId/scans — list scans with pagination and optional filters
  router.get(
    '/',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.SCAN_READ),
    controller.list
  );

  // GET /:projectId/scans/:scanId — retrieve scan details
  router.get(
    '/:scanId',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.SCAN_READ),
    controller.getById
  );

  // POST /:projectId/scans/:scanId/cancel — request scan cancellation
  router.post(
    '/:scanId/cancel',
    requireOrgMembership,
    requireOrganizationPermission(OrganizationPermission.SCAN_CANCEL),
    controller.cancel
  );

  return router;
}
