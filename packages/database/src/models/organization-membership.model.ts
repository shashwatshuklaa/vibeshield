import { Schema, type HydratedDocument, type Model, type Types } from 'mongoose';
import { getOrCreateModel } from '../utils/normalization.js';

export const ORGANIZATION_ROLES = ['OWNER', 'ADMIN', 'MEMBER', 'VIEWER'] as const;
export type OrganizationRole = (typeof ORGANIZATION_ROLES)[number];

export const OrganizationRoleValue = {
  OWNER: 'OWNER',
  ADMIN: 'ADMIN',
  MEMBER: 'MEMBER',
  VIEWER: 'VIEWER',
} as const satisfies Record<OrganizationRole, OrganizationRole>;

export const MEMBERSHIP_STATUSES = ['ACTIVE', 'INVITED', 'SUSPENDED'] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

export const MembershipStatusValue = {
  ACTIVE: 'ACTIVE',
  INVITED: 'INVITED',
  SUSPENDED: 'SUSPENDED',
} as const satisfies Record<MembershipStatus, MembershipStatus>;

export interface OrganizationMembershipAttributes {
  userId: Types.ObjectId;
  organizationId: Types.ObjectId;
  role: OrganizationRole;
  status: MembershipStatus;
  createdAt: Date;
  updatedAt: Date;
}

export type OrganizationMembershipDocument = HydratedDocument<OrganizationMembershipAttributes>;

function sanitizeMembershipSerializedOutput(
  _doc: unknown,
  ret: Record<string, unknown>
): Record<string, unknown> {
  delete ret.__v;
  return ret;
}

export const organizationMembershipSchema = new Schema<OrganizationMembershipAttributes>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User reference is required'],
    },
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'Organization reference is required'],
    },
    role: {
      type: String,
      required: [true, 'Membership role is required'],
      enum: {
        values: ORGANIZATION_ROLES,
        message: 'Invalid organization membership role',
      },
    },
    status: {
      type: String,
      required: true,
      enum: {
        values: MEMBERSHIP_STATUSES,
        message: 'Invalid organization membership status',
      },
      default: MembershipStatusValue.ACTIVE,
    },
  },
  {
    collection: 'organization_memberships',
    timestamps: true,
    toJSON: {
      transform: sanitizeMembershipSerializedOutput,
    },
    toObject: {
      transform: sanitizeMembershipSerializedOutput,
    },
  }
);

organizationMembershipSchema.index(
  { organizationId: 1, userId: 1 },
  { unique: true, name: 'org_memberships_org_user_unique' }
);
organizationMembershipSchema.index(
  { userId: 1, status: 1 },
  { name: 'org_memberships_user_status_idx' }
);
organizationMembershipSchema.index(
  { organizationId: 1, role: 1, status: 1 },
  { name: 'org_memberships_org_role_status_idx' }
);

export const OrganizationMembershipModel: Model<OrganizationMembershipAttributes> =
  getOrCreateModel<OrganizationMembershipAttributes>(
    'OrganizationMembership',
    organizationMembershipSchema
  );
