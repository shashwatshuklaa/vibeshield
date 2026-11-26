import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { OrganizationRole } from '@vibeshield/database';
import {
  hasOrganizationPermission,
  type OrganizationPermissionType,
} from '../modules/organizations/organization.permissions.js';
import type { OrganizationService } from '../modules/organizations/organization.service.js';
import { OrganizationError } from '../modules/organizations/organization.types.js';
import { AuthError } from '../modules/auth/auth.types.js';

/**
 * Resolves and caches the authenticated user's ACTIVE membership in `:organizationId`.
 * Rejects unauthenticated callers (401), invalid ObjectIds (400), and missing/non-active memberships (404).
 */
export function createRequireOrganizationMembershipMiddleware(
  organizationService: Pick<OrganizationService, 'resolveOrganizationAuth'>
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const userId = req.auth?.user.id;
      if (!userId) {
        next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
        return;
      }

      const rawOrganizationId = req.params.organizationId;
      const organizationId = Array.isArray(rawOrganizationId)
        ? rawOrganizationId[0]
        : rawOrganizationId;

      if (typeof organizationId !== 'string' || organizationId.length === 0) {
        next(
          new OrganizationError(400, 'INVALID_ORGANIZATION_ID', 'Invalid organization identifier')
        );
        return;
      }

      // Reuse already-established context on the same request to avoid duplicate DB lookups
      if (
        req.organizationAuth &&
        req.organizationAuth.organization.id === organizationId &&
        req.organizationAuth.membership.userId === userId
      ) {
        next();
        return;
      }

      req.organizationAuth = await organizationService.resolveOrganizationAuth(
        userId,
        organizationId
      );
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Enforces a centralized organization permission against the established `req.organizationAuth`.
 */
export function requireOrganizationPermission(
  permission: OrganizationPermissionType
): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const authContext = req.organizationAuth;
    if (!authContext) {
      next(new OrganizationError(403, 'FORBIDDEN', 'Organization authorization context missing'));
      return;
    }

    if (!hasOrganizationPermission(authContext.membership.role, permission)) {
      next(new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions'));
      return;
    }

    next();
  };
}

/**
 * Enforces that the authenticated member holds one of the explicitly allowed roles.
 */
export function requireOrganizationRoles(...allowedRoles: OrganizationRole[]): RequestHandler {
  const roleSet = new Set<OrganizationRole>(allowedRoles);

  return (req: Request, _res: Response, next: NextFunction): void => {
    const authContext = req.organizationAuth;
    if (!authContext) {
      next(new OrganizationError(403, 'FORBIDDEN', 'Organization authorization context missing'));
      return;
    }

    if (!roleSet.has(authContext.membership.role)) {
      next(new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions'));
      return;
    }

    next();
  };
}
