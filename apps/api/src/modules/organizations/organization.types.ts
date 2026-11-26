import type {} from 'express';
import type { MembershipStatus, OrganizationRole } from '@vibeshield/database';
import { HttpError } from '../../utils/http-error.js';

/**
 * Safe public organization representation returned to authorized members.
 */
export interface PublicOrganization {
  id: string;
  name: string;
  slug: string;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Organization representation including the authenticated user's active role.
 */
export interface OrganizationSummary extends PublicOrganization {
  role: OrganizationRole;
}

/**
 * Safe member representation returned by organization member endpoints.
 */
export interface OrganizationMemberView {
  membershipId: string;
  userId: string;
  email: string;
  displayName: string;
  role: OrganizationRole;
  status: MembershipStatus;
  createdAt: Date;
}

/**
 * Active membership record attached to the authorized organization request context.
 */
export interface AuthorizedOrganizationMembership {
  id: string;
  userId: string;
  organizationId: string;
  role: OrganizationRole;
  status: MembershipStatus;
}

/**
 * Request-scoped authorization context established by organization authorization middleware.
 */
export interface OrganizationAuthContext {
  organization: PublicOrganization;
  membership: AuthorizedOrganizationMembership;
}

export interface CreateOrganizationInput {
  name: string;
  slug: string;
}

export interface UpdateOrganizationInput {
  name?: string;
  slug?: string;
}

export interface AddOrganizationMemberInput {
  email: string;
  role: OrganizationRole;
}

export interface UpdateOrganizationMemberInput {
  role?: OrganizationRole;
  status?: MembershipStatus;
}

export interface TransferOwnershipInput {
  targetUserId: string;
}

export interface TransferOwnershipResult {
  organizationId: string;
  previousOwnerUserId: string;
  newOwnerUserId: string;
}

/**
 * Operational error thrown by organization management and RBAC components.
 */
export class OrganizationError extends HttpError {
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(statusCode, code, message, details);
    this.name = 'OrganizationError';
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      organizationAuth?: OrganizationAuthContext;
    }
  }
}
