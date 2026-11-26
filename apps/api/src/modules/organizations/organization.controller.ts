import type { NextFunction, Request, Response } from 'express';
import { AuthError } from '../auth/auth.types.js';
import {
  addOrganizationMemberSchema,
  createOrganizationSchema,
  transferOwnershipSchema,
  updateOrganizationMemberSchema,
  updateOrganizationSchema,
} from './organization.schemas.js';
import type { OrganizationService } from './organization.service.js';
import { OrganizationError } from './organization.types.js';

function getSingleParam(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * Creates thin HTTP handlers for organization and membership endpoints.
 */
export function createOrganizationController(organizationService: OrganizationService) {
  return {
    async create(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth) {
          next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
          return;
        }
        const parsed = createOrganizationSchema.parse(req.body);
        const organization = await organizationService.createOrganization(req.auth.user.id, parsed);
        res.status(201).json({ organization });
      } catch (error) {
        next(error);
      }
    },

    async list(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth) {
          next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
          return;
        }
        const organizations = await organizationService.listOrganizationsForUser(req.auth.user.id);
        res.status(200).json({ organizations });
      } catch (error) {
        next(error);
      }
    },

    getById(req: Request, res: Response, next: NextFunction): void {
      if (!req.organizationAuth) {
        next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
        return;
      }
      const organization = organizationService.getOrganization(req.organizationAuth);
      res.status(200).json({ organization });
    },

    async update(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = updateOrganizationSchema.parse(req.body);
        const organization = await organizationService.updateOrganization(
          req.organizationAuth,
          parsed
        );
        res.status(200).json({ organization });
      } catch (error) {
        next(error);
      }
    },

    async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        await organizationService.deleteOrganization(
          req.auth.user.id,
          req.organizationAuth.organization.id
        );
        res.status(200).json({ message: 'Organization deleted successfully' });
      } catch (error) {
        next(error);
      }
    },

    async listMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const members = await organizationService.listMembers(req.organizationAuth.organization.id);
        res.status(200).json({ members });
      } catch (error) {
        next(error);
      }
    },

    async addMember(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = addOrganizationMemberSchema.parse(req.body);
        const member = await organizationService.addMember(
          req.organizationAuth.membership.role,
          req.organizationAuth.organization.id,
          parsed
        );
        res.status(201).json({ member });
      } catch (error) {
        next(error);
      }
    },

    async updateMember(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = updateOrganizationMemberSchema.parse(req.body);
        const membershipId = getSingleParam(req.params.membershipId);
        const member = await organizationService.updateMember(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          membershipId,
          parsed
        );
        res.status(200).json({ member });
      } catch (error) {
        next(error);
      }
    },

    async removeMember(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const membershipId = getSingleParam(req.params.membershipId);
        await organizationService.removeMember(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          membershipId
        );
        res.status(200).json({ message: 'Membership removed successfully' });
      } catch (error) {
        next(error);
      }
    },

    async transferOwnership(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        if (!req.auth || !req.organizationAuth) {
          next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
          return;
        }
        const parsed = transferOwnershipSchema.parse(req.body);
        const transfer = await organizationService.transferOwnership(
          req.auth.user.id,
          req.organizationAuth.organization.id,
          parsed
        );
        res.status(200).json({ transfer });
      } catch (error) {
        next(error);
      }
    },
  };
}
