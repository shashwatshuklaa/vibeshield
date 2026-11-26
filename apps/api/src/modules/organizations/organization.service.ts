import {
  isValidObjectId,
  MembershipStatusValue,
  normalizeEmail,
  normalizeSlug,
  OrganizationRoleValue,
  UserStatusValue,
  type OrganizationRole,
} from '@vibeshield/database';
import {
  assertCanAddMemberWithRole,
  assertCanModifyMembership,
  assertCanRemoveMembership,
} from './organization.permissions.js';
import { mongooseOrganizationStore, type OrganizationStore } from './organization.store.js';
import {
  OrganizationError,
  type AddOrganizationMemberInput,
  type CreateOrganizationInput,
  type OrganizationAuthContext,
  type OrganizationMemberView,
  type OrganizationSummary,
  type PublicOrganization,
  type TransferOwnershipInput,
  type TransferOwnershipResult,
  type UpdateOrganizationInput,
  type UpdateOrganizationMemberInput,
} from './organization.types.js';

export interface OrganizationServiceDependencies {
  store?: OrganizationStore;
}

export interface OrganizationService {
  resolveOrganizationAuth(userId: string, organizationId: string): Promise<OrganizationAuthContext>;
  createOrganization(
    actorUserId: string,
    input: CreateOrganizationInput
  ): Promise<OrganizationSummary>;
  listOrganizationsForUser(userId: string): Promise<OrganizationSummary[]>;
  getOrganization(authContext: OrganizationAuthContext): OrganizationSummary;
  updateOrganization(
    authContext: OrganizationAuthContext,
    input: UpdateOrganizationInput
  ): Promise<OrganizationSummary>;
  deleteOrganization(actorUserId: string, organizationId: string): Promise<void>;
  listMembers(organizationId: string): Promise<OrganizationMemberView[]>;
  addMember(
    actorRole: OrganizationRole,
    organizationId: string,
    input: AddOrganizationMemberInput
  ): Promise<OrganizationMemberView>;
  updateMember(
    actorUserId: string,
    organizationId: string,
    membershipId: string,
    input: UpdateOrganizationMemberInput
  ): Promise<OrganizationMemberView>;
  removeMember(actorUserId: string, organizationId: string, membershipId: string): Promise<void>;
  transferOwnership(
    actorUserId: string,
    organizationId: string,
    input: TransferOwnershipInput
  ): Promise<TransferOwnershipResult>;
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

function toOrganizationSummary(
  org: PublicOrganization,
  role: OrganizationRole
): OrganizationSummary {
  return {
    ...org,
    role,
  };
}

/**
 * Creates the multi-tenant organization & RBAC service.
 * Enforces membership boundaries, permission matrix rules, and MongoDB transactions
 * for multi-document ownership invariants.
 */
export function createOrganizationService(
  dependencies: OrganizationServiceDependencies = {}
): OrganizationService {
  const store = dependencies.store ?? mongooseOrganizationStore;

  return {
    async resolveOrganizationAuth(
      userId: string,
      organizationId: string
    ): Promise<OrganizationAuthContext> {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(
          400,
          'INVALID_ORGANIZATION_ID',
          'Invalid organization identifier'
        );
      }

      const membership = await store.findActiveMembership(organizationId, userId);
      if (!membership) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }

      const organization = await store.findOrganizationById(organizationId);
      if (!organization) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }

      return { organization, membership };
    },

    async createOrganization(
      actorUserId: string,
      input: CreateOrganizationInput
    ): Promise<OrganizationSummary> {
      const normalizedSlug = normalizeSlug(input.slug);
      const trimmedName = input.name.trim();

      try {
        return await store.withTransaction(async (tx) => {
          const organization = await store.createOrganization(
            {
              name: trimmedName,
              slug: normalizedSlug,
              createdBy: actorUserId,
            },
            tx
          );

          await store.createMembership(
            {
              userId: actorUserId,
              organizationId: organization.id,
              role: OrganizationRoleValue.OWNER,
              status: MembershipStatusValue.ACTIVE,
            },
            tx
          );

          return toOrganizationSummary(organization, OrganizationRoleValue.OWNER);
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new OrganizationError(
            409,
            'ORGANIZATION_SLUG_EXISTS',
            'An organization with this slug already exists'
          );
        }
        throw error;
      }
    },

    async listOrganizationsForUser(userId: string): Promise<OrganizationSummary[]> {
      return store.listActiveOrganizationsForUser(userId);
    },

    getOrganization(authContext: OrganizationAuthContext): OrganizationSummary {
      return toOrganizationSummary(authContext.organization, authContext.membership.role);
    },

    async updateOrganization(
      authContext: OrganizationAuthContext,
      input: UpdateOrganizationInput
    ): Promise<OrganizationSummary> {
      const updates: { name?: string; slug?: string } = {};
      if (input.name !== undefined) {
        updates.name = input.name.trim();
      }
      if (input.slug !== undefined) {
        updates.slug = normalizeSlug(input.slug);
      }

      try {
        const updated = await store.updateOrganizationById(authContext.organization.id, updates);
        if (!updated) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
        return toOrganizationSummary(updated, authContext.membership.role);
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new OrganizationError(
            409,
            'ORGANIZATION_SLUG_EXISTS',
            'An organization with this slug already exists'
          );
        }
        throw error;
      }
    },

    async deleteOrganization(actorUserId: string, organizationId: string): Promise<void> {
      await store.withTransaction(async (tx) => {
        const membership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!membership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
        if (membership.role !== OrganizationRoleValue.OWNER) {
          throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
        }

        const hasProjects = await store.hasProjectsInOrganization(organizationId, tx);
        if (hasProjects) {
          throw new OrganizationError(
            409,
            'ORGANIZATION_HAS_PROJECTS',
            'Organization cannot be deleted while projects still exist'
          );
        }

        await store.deleteAllMembershipsInOrganization(organizationId, tx);
        const deleted = await store.deleteOrganizationById(organizationId, tx);
        if (!deleted) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
      });
    },

    async listMembers(organizationId: string): Promise<OrganizationMemberView[]> {
      return store.listMembersInOrganization(organizationId);
    },

    async addMember(
      actorRole: OrganizationRole,
      organizationId: string,
      input: AddOrganizationMemberInput
    ): Promise<OrganizationMemberView> {
      assertCanAddMemberWithRole(actorRole, input.role);

      const normalizedEmail = normalizeEmail(input.email);
      const targetUser = await store.findUserByEmail(normalizedEmail);
      if (!targetUser) {
        throw new OrganizationError(404, 'USER_NOT_FOUND', 'User with this email was not found');
      }

      if (targetUser.status !== UserStatusValue.ACTIVE) {
        throw new OrganizationError(
          400,
          'USER_NOT_ACTIVE',
          'Only active user accounts can be added to an organization'
        );
      }

      try {
        const membership = await store.createMembership({
          userId: targetUser.id,
          organizationId,
          role: input.role,
          status: MembershipStatusValue.ACTIVE,
        });

        return {
          membershipId: membership.id,
          userId: targetUser.id,
          email: targetUser.email,
          displayName: targetUser.displayName,
          role: membership.role,
          status: membership.status,
          createdAt: membership.createdAt,
        };
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new OrganizationError(
            409,
            'MEMBERSHIP_ALREADY_EXISTS',
            'User is already a member of this organization'
          );
        }
        throw error;
      }
    },

    async updateMember(
      actorUserId: string,
      organizationId: string,
      membershipId: string,
      input: UpdateOrganizationMemberInput
    ): Promise<OrganizationMemberView> {
      if (!isValidObjectId(membershipId)) {
        throw new OrganizationError(400, 'INVALID_MEMBERSHIP_ID', 'Invalid membership identifier');
      }

      return store.withTransaction(async (tx) => {
        const actorMembership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!actorMembership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }

        const targetMembership = await store.findMembershipByIdInOrganization(
          organizationId,
          membershipId,
          tx
        );
        if (!targetMembership) {
          throw new OrganizationError(404, 'MEMBERSHIP_NOT_FOUND', 'Membership not found');
        }

        assertCanModifyMembership({
          actorUserId,
          actorRole: actorMembership.role,
          targetUserId: targetMembership.userId,
          currentTargetRole: targetMembership.role,
          currentTargetStatus: targetMembership.status,
          nextRole: input.role,
          nextStatus: input.status,
        });

        const nextRole = input.role ?? targetMembership.role;
        const nextStatus = input.status ?? targetMembership.status;

        const isActiveOwnerLeavingOwnerRoleOrStatus =
          targetMembership.role === OrganizationRoleValue.OWNER &&
          targetMembership.status === MembershipStatusValue.ACTIVE &&
          (nextRole !== OrganizationRoleValue.OWNER || nextStatus !== MembershipStatusValue.ACTIVE);

        if (isActiveOwnerLeavingOwnerRoleOrStatus) {
          const remainingOwners = await store.countActiveOwnersExcluding(
            organizationId,
            targetMembership.id,
            tx
          );
          if (remainingOwners < 1) {
            throw new OrganizationError(
              409,
              'LAST_OWNER_REQUIRED',
              'Cannot demote or suspend the last active organization owner'
            );
          }
        }

        const updated = await store.updateMembershipByIdInOrganization(
          organizationId,
          membershipId,
          {
            ...(input.role !== undefined ? { role: input.role } : {}),
            ...(input.status !== undefined ? { status: input.status } : {}),
          },
          tx
        );
        if (!updated) {
          throw new OrganizationError(404, 'MEMBERSHIP_NOT_FOUND', 'Membership not found');
        }

        const members = await store.listMembersInOrganization(organizationId);
        const foundView = members.find((m) => m.membershipId === updated.id);
        if (foundView) {
          return {
            ...foundView,
            role: updated.role,
            status: updated.status,
          };
        }

        return {
          membershipId: updated.id,
          userId: updated.userId,
          email: '',
          displayName: '',
          role: updated.role,
          status: updated.status,
          createdAt: updated.createdAt,
        };
      });
    },

    async removeMember(
      actorUserId: string,
      organizationId: string,
      membershipId: string
    ): Promise<void> {
      if (!isValidObjectId(membershipId)) {
        throw new OrganizationError(400, 'INVALID_MEMBERSHIP_ID', 'Invalid membership identifier');
      }

      await store.withTransaction(async (tx) => {
        const actorMembership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!actorMembership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }

        const targetMembership = await store.findMembershipByIdInOrganization(
          organizationId,
          membershipId,
          tx
        );
        if (!targetMembership) {
          throw new OrganizationError(404, 'MEMBERSHIP_NOT_FOUND', 'Membership not found');
        }

        assertCanRemoveMembership({
          actorUserId,
          actorRole: actorMembership.role,
          targetUserId: targetMembership.userId,
          currentTargetRole: targetMembership.role,
        });

        const isActiveOwner =
          targetMembership.role === OrganizationRoleValue.OWNER &&
          targetMembership.status === MembershipStatusValue.ACTIVE;

        if (isActiveOwner) {
          const remainingOwners = await store.countActiveOwnersExcluding(
            organizationId,
            targetMembership.id,
            tx
          );
          if (remainingOwners < 1) {
            throw new OrganizationError(
              409,
              'LAST_OWNER_REQUIRED',
              'Cannot remove the last active organization owner; transfer ownership first'
            );
          }
        }

        const deleted = await store.deleteMembershipByIdInOrganization(
          organizationId,
          membershipId,
          tx
        );
        if (!deleted) {
          throw new OrganizationError(404, 'MEMBERSHIP_NOT_FOUND', 'Membership not found');
        }
      });
    },

    async transferOwnership(
      actorUserId: string,
      organizationId: string,
      input: TransferOwnershipInput
    ): Promise<TransferOwnershipResult> {
      if (!isValidObjectId(input.targetUserId)) {
        throw new OrganizationError(400, 'INVALID_USER_ID', 'Invalid user identifier');
      }

      if (input.targetUserId === actorUserId) {
        throw new OrganizationError(
          400,
          'INVALID_OWNERSHIP_TRANSFER',
          'Cannot transfer organization ownership to yourself'
        );
      }

      return store.withTransaction(async (tx) => {
        const actorMembership = await store.findActiveMembership(organizationId, actorUserId, tx);
        if (!actorMembership) {
          throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
        }
        if (actorMembership.role !== OrganizationRoleValue.OWNER) {
          throw new OrganizationError(
            403,
            'FORBIDDEN',
            'Only an active organization owner can transfer ownership'
          );
        }

        const targetMembership = await store.findMembershipByOrgAndUser(
          organizationId,
          input.targetUserId,
          tx
        );
        if (!targetMembership || targetMembership.status !== MembershipStatusValue.ACTIVE) {
          throw new OrganizationError(
            400,
            'INVALID_OWNERSHIP_TARGET',
            'Target user must have an active membership in this organization'
          );
        }

        // Establish new OWNER first before demoting the previous OWNER
        const promoted = await store.updateMembershipByIdInOrganization(
          organizationId,
          targetMembership.id,
          { role: OrganizationRoleValue.OWNER },
          tx
        );
        if (!promoted || promoted.role !== OrganizationRoleValue.OWNER) {
          throw new OrganizationError(
            409,
            'OWNERSHIP_TRANSFER_CONFLICT',
            'Unable to promote target member to owner'
          );
        }

        const demoted = await store.updateMembershipByIdInOrganization(
          organizationId,
          actorMembership.id,
          { role: OrganizationRoleValue.ADMIN },
          tx
        );
        if (!demoted || demoted.role !== OrganizationRoleValue.ADMIN) {
          throw new OrganizationError(
            409,
            'OWNERSHIP_TRANSFER_CONFLICT',
            'Unable to demote previous owner during ownership transfer'
          );
        }

        const activeOwners = await store.countActiveOwners(organizationId, tx);
        if (activeOwners < 1) {
          throw new OrganizationError(
            409,
            'LAST_OWNER_REQUIRED',
            'Organization must retain at least one active owner'
          );
        }

        return {
          organizationId,
          previousOwnerUserId: actorUserId,
          newOwnerUserId: input.targetUserId,
        };
      });
    },
  };
}
