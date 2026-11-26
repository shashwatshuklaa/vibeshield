import type { ClientSession } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  isValidObjectId,
  MembershipStatusValue,
  OrganizationMembershipModel,
  OrganizationModel,
  OrganizationRoleValue,
  ProjectModel,
  runInTransaction,
  UserModel,
  type MembershipStatus,
  type OrganizationRole,
  type UserStatus,
} from '@vibeshield/database';
import type {
  AuthorizedOrganizationMembership,
  OrganizationMemberView,
  OrganizationSummary,
  PublicOrganization,
} from './organization.types.js';

export type OrganizationTransactionContext = ClientSession | unknown;

export interface StoredUserSummary {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
}

export interface StoredMembershipRecord {
  id: string;
  userId: string;
  organizationId: string;
  role: OrganizationRole;
  status: MembershipStatus;
  createdAt: Date;
}

export interface OrganizationStore {
  withTransaction<T>(work: (tx: OrganizationTransactionContext) => Promise<T>): Promise<T>;
  acquireOrganizationLock(
    organizationId: string,
    tx: OrganizationTransactionContext
  ): Promise<boolean>;
  createOrganization(
    input: { name: string; slug: string; createdBy: string },
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization>;
  findOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization | null>;
  updateOrganizationById(
    organizationId: string,
    updates: { name?: string; slug?: string },
    tx?: OrganizationTransactionContext
  ): Promise<PublicOrganization | null>;
  deleteOrganizationById(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean>;
  hasProjectsInOrganization(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean>;
  listActiveOrganizationsForUser(userId: string): Promise<OrganizationSummary[]>;
  createMembership(
    input: {
      userId: string;
      organizationId: string;
      role: OrganizationRole;
      status: MembershipStatus;
    },
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord>;
  findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null>;
  findMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null>;
  findMembershipByOrgAndUser(
    organizationId: string,
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null>;
  listMembersInOrganization(organizationId: string): Promise<OrganizationMemberView[]>;
  updateMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    updates: { role?: OrganizationRole; status?: MembershipStatus },
    tx?: OrganizationTransactionContext
  ): Promise<StoredMembershipRecord | null>;
  deleteMembershipByIdInOrganization(
    organizationId: string,
    membershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<boolean>;
  deleteAllMembershipsInOrganization(
    organizationId: string,
    tx?: OrganizationTransactionContext
  ): Promise<void>;
  countActiveOwnersExcluding(
    organizationId: string,
    excludedMembershipId: string,
    tx?: OrganizationTransactionContext
  ): Promise<number>;
  countActiveOwners(organizationId: string, tx?: OrganizationTransactionContext): Promise<number>;
  findUserByEmail(
    email: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredUserSummary | null>;
  findUserById(
    userId: string,
    tx?: OrganizationTransactionContext
  ): Promise<StoredUserSummary | null>;
}

function asSession(tx?: OrganizationTransactionContext): ClientSession | undefined {
  return tx as ClientSession | undefined;
}

function toPublicOrganization(doc: {
  _id: { toString(): string };
  name: string;
  slug: string;
  createdBy: { toString(): string };
  createdAt: Date;
  updatedAt: Date;
}): PublicOrganization {
  return {
    id: doc._id.toString(),
    name: doc.name,
    slug: doc.slug,
    createdBy: doc.createdBy.toString(),
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

function toStoredMembership(doc: {
  _id: { toString(): string };
  userId: { toString(): string };
  organizationId: { toString(): string };
  role: OrganizationRole;
  status: MembershipStatus;
  createdAt: Date;
}): StoredMembershipRecord {
  return {
    id: doc._id.toString(),
    userId: doc.userId.toString(),
    organizationId: doc.organizationId.toString(),
    role: doc.role,
    status: doc.status,
    createdAt: doc.createdAt,
  };
}

export const mongooseOrganizationStore: OrganizationStore = {
  async withTransaction<T>(work: (tx: OrganizationTransactionContext) => Promise<T>): Promise<T> {
    return runInTransaction(async (session) => work(session));
  },

  async acquireOrganizationLock(organizationId, tx) {
    const session = asSession(tx);
    if (!session) {
      throw new Error('Organization mutation lock requires an active MongoDB transaction session');
    }
    return acquireOrganizationMutationLock(organizationId, session);
  },

  async createOrganization(input, tx) {
    const session = asSession(tx);
    const [doc] = await OrganizationModel.create(
      [
        {
          name: input.name,
          slug: input.slug,
          createdBy: input.createdBy,
        },
      ],
      session ? { session } : undefined
    );
    return toPublicOrganization(doc!);
  },

  async findOrganizationById(organizationId, tx) {
    if (!isValidObjectId(organizationId)) {
      return null;
    }
    const session = asSession(tx);
    const query = OrganizationModel.findById(organizationId);
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicOrganization(doc) : null;
  },

  async updateOrganizationById(organizationId, updates, tx) {
    if (!isValidObjectId(organizationId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await OrganizationModel.findOneAndUpdate(
      { _id: organizationId },
      { $set: updates },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicOrganization(doc) : null;
  },

  async deleteOrganizationById(organizationId, tx) {
    if (!isValidObjectId(organizationId)) {
      return false;
    }
    const session = asSession(tx);
    const result = await OrganizationModel.deleteOne(
      { _id: organizationId },
      session ? { session } : undefined
    );
    return result.deletedCount > 0;
  },

  async hasProjectsInOrganization(organizationId, tx) {
    if (!isValidObjectId(organizationId)) {
      return false;
    }
    const session = asSession(tx);
    const query = ProjectModel.exists({ organizationId });
    if (session) {
      query.session(session);
    }
    const existing = await query;
    return Boolean(existing);
  },

  async listActiveOrganizationsForUser(userId) {
    if (!isValidObjectId(userId)) {
      return [];
    }

    const memberships = await OrganizationMembershipModel.find({
      userId,
      status: MembershipStatusValue.ACTIVE,
    }).sort({ createdAt: -1 });

    if (memberships.length === 0) {
      return [];
    }

    const orgIds = memberships.map((m) => m.organizationId);
    const orgs = await OrganizationModel.find({ _id: { $in: orgIds } });
    const orgMap = new Map(orgs.map((org) => [org._id.toString(), toPublicOrganization(org)]));

    const summaries: OrganizationSummary[] = [];
    for (const membership of memberships) {
      const org = orgMap.get(membership.organizationId.toString());
      if (org) {
        summaries.push({
          ...org,
          role: membership.role,
        });
      }
    }
    return summaries;
  },

  async createMembership(input, tx) {
    const session = asSession(tx);
    const [doc] = await OrganizationMembershipModel.create(
      [
        {
          userId: input.userId,
          organizationId: input.organizationId,
          role: input.role,
          status: input.status,
        },
      ],
      session ? { session } : undefined
    );
    return toStoredMembership(doc!);
  },

  async findActiveMembership(organizationId, userId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(userId)) {
      return null;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.findOne({
      organizationId,
      userId,
      status: MembershipStatusValue.ACTIVE,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    if (!doc) {
      return null;
    }
    return {
      id: doc._id.toString(),
      userId: doc.userId.toString(),
      organizationId: doc.organizationId.toString(),
      role: doc.role,
      status: doc.status,
    };
  },

  async findMembershipByIdInOrganization(organizationId, membershipId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(membershipId)) {
      return null;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.findOne({
      _id: membershipId,
      organizationId,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toStoredMembership(doc) : null;
  },

  async findMembershipByOrgAndUser(organizationId, userId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(userId)) {
      return null;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.findOne({
      organizationId,
      userId,
    });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toStoredMembership(doc) : null;
  },

  async listMembersInOrganization(organizationId) {
    if (!isValidObjectId(organizationId)) {
      return [];
    }

    const memberships = await OrganizationMembershipModel.find({ organizationId }).sort({
      createdAt: 1,
    });
    if (memberships.length === 0) {
      return [];
    }

    const userIds = memberships.map((m) => m.userId);
    const users = await UserModel.find({ _id: { $in: userIds } });
    const userMap = new Map(users.map((u) => [u._id.toString(), u]));

    const members: OrganizationMemberView[] = [];
    for (const membership of memberships) {
      const user = userMap.get(membership.userId.toString());
      if (!user) {
        continue;
      }
      members.push({
        membershipId: membership._id.toString(),
        userId: user._id.toString(),
        email: user.email,
        displayName: user.displayName,
        role: membership.role,
        status: membership.status,
        createdAt: membership.createdAt,
      });
    }
    return members;
  },

  async updateMembershipByIdInOrganization(organizationId, membershipId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(membershipId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await OrganizationMembershipModel.findOneAndUpdate(
      { _id: membershipId, organizationId },
      { $set: updates },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toStoredMembership(doc) : null;
  },

  async deleteMembershipByIdInOrganization(organizationId, membershipId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(membershipId)) {
      return false;
    }
    const session = asSession(tx);
    const result = await OrganizationMembershipModel.deleteOne(
      { _id: membershipId, organizationId },
      session ? { session } : undefined
    );
    return result.deletedCount > 0;
  },

  async deleteAllMembershipsInOrganization(organizationId, tx) {
    if (!isValidObjectId(organizationId)) {
      return;
    }
    const session = asSession(tx);
    await OrganizationMembershipModel.deleteMany(
      { organizationId },
      session ? { session } : undefined
    );
  },

  async countActiveOwnersExcluding(organizationId, excludedMembershipId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(excludedMembershipId)) {
      return 0;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.countDocuments({
      organizationId,
      role: OrganizationRoleValue.OWNER,
      status: MembershipStatusValue.ACTIVE,
      _id: { $ne: excludedMembershipId },
    });
    if (session) {
      query.session(session);
    }
    return query;
  },

  async countActiveOwners(organizationId, tx) {
    if (!isValidObjectId(organizationId)) {
      return 0;
    }
    const session = asSession(tx);
    const query = OrganizationMembershipModel.countDocuments({
      organizationId,
      role: OrganizationRoleValue.OWNER,
      status: MembershipStatusValue.ACTIVE,
    });
    if (session) {
      query.session(session);
    }
    return query;
  },

  async findUserByEmail(email, tx) {
    const session = asSession(tx);
    const query = UserModel.findOne({ email });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    if (!doc) {
      return null;
    }
    return {
      id: doc._id.toString(),
      email: doc.email,
      displayName: doc.displayName,
      status: doc.status,
    };
  },

  async findUserById(userId, tx) {
    if (!isValidObjectId(userId)) {
      return null;
    }
    const session = asSession(tx);
    const query = UserModel.findById(userId);
    if (session) {
      query.session(session);
    }
    const doc = await query;
    if (!doc) {
      return null;
    }
    return {
      id: doc._id.toString(),
      email: doc.email,
      displayName: doc.displayName,
      status: doc.status,
    };
  },
};
