import {
  MembershipStatusValue,
  OrganizationRoleValue,
  type MembershipStatus,
  type OrganizationRole,
} from '@vibeshield/database';
import { OrganizationError } from './organization.types.js';

export const OrganizationPermission = {
  ORG_READ: 'ORG_READ',
  ORG_UPDATE: 'ORG_UPDATE',
  ORG_DELETE: 'ORG_DELETE',
  MEMBER_READ: 'MEMBER_READ',
  MEMBER_ADD: 'MEMBER_ADD',
  MEMBER_UPDATE: 'MEMBER_UPDATE',
  MEMBER_REMOVE: 'MEMBER_REMOVE',
  OWNERSHIP_TRANSFER: 'OWNERSHIP_TRANSFER',
  PROJECT_READ: 'PROJECT_READ',
  PROJECT_CREATE: 'PROJECT_CREATE',
  PROJECT_UPDATE: 'PROJECT_UPDATE',
  PROJECT_ARCHIVE: 'PROJECT_ARCHIVE',
  PROJECT_RESTORE: 'PROJECT_RESTORE',
  GITHUB_INTEGRATION_READ: 'GITHUB_INTEGRATION_READ',
  GITHUB_INTEGRATION_MANAGE: 'GITHUB_INTEGRATION_MANAGE',
} as const;

export type OrganizationPermissionType =
  (typeof OrganizationPermission)[keyof typeof OrganizationPermission];

/**
 * Centralized role-to-permission matrix governing all organization-scoped operations.
 */
export const ORGANIZATION_PERMISSION_MATRIX: Readonly<
  Record<OrganizationPermissionType, ReadonlySet<OrganizationRole>>
> = Object.freeze({
  [OrganizationPermission.ORG_READ]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
    OrganizationRoleValue.MEMBER,
    OrganizationRoleValue.VIEWER,
  ]),
  [OrganizationPermission.ORG_UPDATE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.ORG_DELETE]: new Set<OrganizationRole>([OrganizationRoleValue.OWNER]),
  [OrganizationPermission.MEMBER_READ]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
    OrganizationRoleValue.MEMBER,
    OrganizationRoleValue.VIEWER,
  ]),
  [OrganizationPermission.MEMBER_ADD]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.MEMBER_UPDATE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.MEMBER_REMOVE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.OWNERSHIP_TRANSFER]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
  ]),
  [OrganizationPermission.PROJECT_READ]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
    OrganizationRoleValue.MEMBER,
    OrganizationRoleValue.VIEWER,
  ]),
  [OrganizationPermission.PROJECT_CREATE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
    OrganizationRoleValue.MEMBER,
  ]),
  [OrganizationPermission.PROJECT_UPDATE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
    OrganizationRoleValue.MEMBER,
  ]),
  [OrganizationPermission.PROJECT_ARCHIVE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.PROJECT_RESTORE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.GITHUB_INTEGRATION_READ]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
  [OrganizationPermission.GITHUB_INTEGRATION_MANAGE]: new Set<OrganizationRole>([
    OrganizationRoleValue.OWNER,
    OrganizationRoleValue.ADMIN,
  ]),
});

const ASSIGNABLE_ROLES_BY_ACTOR: Readonly<Record<OrganizationRole, ReadonlySet<OrganizationRole>>> =
  Object.freeze({
    [OrganizationRoleValue.OWNER]: new Set<OrganizationRole>([
      OrganizationRoleValue.ADMIN,
      OrganizationRoleValue.MEMBER,
      OrganizationRoleValue.VIEWER,
    ]),
    [OrganizationRoleValue.ADMIN]: new Set<OrganizationRole>([
      OrganizationRoleValue.MEMBER,
      OrganizationRoleValue.VIEWER,
    ]),
    [OrganizationRoleValue.MEMBER]: new Set<OrganizationRole>(),
    [OrganizationRoleValue.VIEWER]: new Set<OrganizationRole>(),
  });

const ALLOWED_STATUS_TRANSITIONS: Readonly<
  Record<MembershipStatus, ReadonlySet<MembershipStatus>>
> = Object.freeze({
  [MembershipStatusValue.INVITED]: new Set<MembershipStatus>([
    MembershipStatusValue.ACTIVE,
    MembershipStatusValue.SUSPENDED,
  ]),
  [MembershipStatusValue.ACTIVE]: new Set<MembershipStatus>([MembershipStatusValue.SUSPENDED]),
  [MembershipStatusValue.SUSPENDED]: new Set<MembershipStatus>([MembershipStatusValue.ACTIVE]),
});

/**
 * Checks whether an organization role holds the specified permission.
 */
export function hasOrganizationPermission(
  role: OrganizationRole,
  permission: OrganizationPermissionType
): boolean {
  return ORGANIZATION_PERMISSION_MATRIX[permission].has(role);
}

/**
 * Returns whether an actor role may assign the target role when adding a member.
 */
export function canAssignRole(actorRole: OrganizationRole, targetRole: OrganizationRole): boolean {
  if (targetRole === OrganizationRoleValue.OWNER) {
    return false;
  }
  return ASSIGNABLE_ROLES_BY_ACTOR[actorRole].has(targetRole);
}

/**
 * Enforces role-assignment rules when adding a user to an organization.
 */
export function assertCanAddMemberWithRole(
  actorRole: OrganizationRole,
  targetRole: OrganizationRole
): void {
  if (!hasOrganizationPermission(actorRole, OrganizationPermission.MEMBER_ADD)) {
    throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
  }

  if (targetRole === OrganizationRoleValue.OWNER) {
    throw new OrganizationError(
      403,
      'FORBIDDEN',
      'OWNER role can only be assigned via ownership transfer'
    );
  }

  if (!canAssignRole(actorRole, targetRole)) {
    throw new OrganizationError(
      403,
      'FORBIDDEN',
      'Your role does not permit assigning the requested membership role'
    );
  }
}

export interface ModifyMembershipRuleInput {
  actorUserId: string;
  actorRole: OrganizationRole;
  targetUserId: string;
  currentTargetRole: OrganizationRole;
  currentTargetStatus: MembershipStatus;
  nextRole?: OrganizationRole;
  nextStatus?: MembershipStatus;
}

/**
 * Enforces RBAC, anti-self-escalation, and status transition rules for membership updates.
 */
export function assertCanModifyMembership(input: ModifyMembershipRuleInput): void {
  const {
    actorUserId,
    actorRole,
    targetUserId,
    currentTargetRole,
    currentTargetStatus,
    nextRole,
    nextStatus,
  } = input;

  if (!hasOrganizationPermission(actorRole, OrganizationPermission.MEMBER_UPDATE)) {
    throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
  }

  if (actorUserId === targetUserId) {
    if (nextRole !== undefined && nextRole !== currentTargetRole) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'Users cannot modify their own role or escalate privileges'
      );
    }
    if (nextStatus !== undefined && nextStatus !== currentTargetStatus) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'Users cannot modify their own membership status directly'
      );
    }
  }

  if (actorRole === OrganizationRoleValue.ADMIN) {
    if (
      currentTargetRole === OrganizationRoleValue.OWNER ||
      currentTargetRole === OrganizationRoleValue.ADMIN
    ) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'Admins can only manage MEMBER and VIEWER memberships'
      );
    }
    if (nextRole !== undefined && !canAssignRole(actorRole, nextRole)) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'Admins can only assign MEMBER or VIEWER roles'
      );
    }
  }

  if (nextRole !== undefined && nextRole !== currentTargetRole) {
    if (nextRole === OrganizationRoleValue.OWNER) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'OWNER role can only be assigned via ownership transfer'
      );
    }
    if (!canAssignRole(actorRole, nextRole)) {
      throw new OrganizationError(
        403,
        'FORBIDDEN',
        'Your role does not permit assigning the requested membership role'
      );
    }
  }

  if (nextStatus !== undefined && nextStatus !== currentTargetStatus) {
    const allowedNext = ALLOWED_STATUS_TRANSITIONS[currentTargetStatus];
    if (!allowedNext.has(nextStatus)) {
      throw new OrganizationError(
        400,
        'INVALID_STATUS_TRANSITION',
        `Cannot transition membership status from ${currentTargetStatus} to ${nextStatus}`
      );
    }
  }
}

export interface RemoveMembershipRuleInput {
  actorUserId: string;
  actorRole: OrganizationRole;
  targetUserId: string;
  currentTargetRole: OrganizationRole;
}

/**
 * Enforces RBAC rules for membership removal and leaving an organization.
 */
export function assertCanRemoveMembership(input: RemoveMembershipRuleInput): void {
  const { actorUserId, actorRole, targetUserId, currentTargetRole } = input;

  // Leaving the organization is permitted for the member themselves (last-OWNER checked in service transaction)
  if (actorUserId === targetUserId) {
    return;
  }

  if (!hasOrganizationPermission(actorRole, OrganizationPermission.MEMBER_REMOVE)) {
    throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
  }

  if (
    actorRole === OrganizationRoleValue.ADMIN &&
    (currentTargetRole === OrganizationRoleValue.OWNER ||
      currentTargetRole === OrganizationRoleValue.ADMIN)
  ) {
    throw new OrganizationError(
      403,
      'FORBIDDEN',
      'Admins can only remove MEMBER or VIEWER memberships'
    );
  }
}
