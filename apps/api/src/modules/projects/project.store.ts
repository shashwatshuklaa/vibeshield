import type { ClientSession } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  isValidObjectId,
  MembershipStatusValue,
  OrganizationMembershipModel,
  ProjectModel,
  runInTransaction,
} from '@vibeshield/database';
import type { AuthorizedOrganizationMembership } from '../organizations/organization.types.js';
import type { ListProjectsQuery, PublicProject } from './project.types.js';

export type ProjectTransactionContext = ClientSession | unknown;

export interface ProjectStore {
  withTransaction<T>(work: (tx: ProjectTransactionContext) => Promise<T>): Promise<T>;
  acquireOrganizationLock(organizationId: string, tx: ProjectTransactionContext): Promise<boolean>;
  findActiveMembership(
    organizationId: string,
    userId: string,
    tx?: ProjectTransactionContext
  ): Promise<AuthorizedOrganizationMembership | null>;
  createProject(
    input: {
      organizationId: string;
      name: string;
      slug: string;
      description?: string;
      createdBy: string;
    },
    tx?: ProjectTransactionContext
  ): Promise<PublicProject>;
  findProjectByIdInOrganization(
    organizationId: string,
    projectId: string,
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null>;
  listProjectsInOrganization(
    organizationId: string,
    query: ListProjectsQuery
  ): Promise<{ projects: PublicProject[]; total: number }>;
  updateProjectByIdInOrganization(
    organizationId: string,
    projectId: string,
    updates: {
      name?: string;
      slug?: string;
      description?: string | null;
    },
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null>;
  setProjectArchivedAtInOrganization(
    organizationId: string,
    projectId: string,
    archivedAt: Date | null,
    tx?: ProjectTransactionContext
  ): Promise<PublicProject | null>;
}

function asSession(tx?: ProjectTransactionContext): ClientSession | undefined {
  return tx as ClientSession | undefined;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toPublicProject(doc: {
  _id: { toString(): string };
  organizationId: { toString(): string };
  name: string;
  slug: string;
  description?: string;
  createdBy: { toString(): string };
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}): PublicProject {
  return {
    id: doc._id.toString(),
    organizationId: doc.organizationId.toString(),
    name: doc.name,
    slug: doc.slug,
    description: doc.description ?? null,
    createdBy: doc.createdBy.toString(),
    archivedAt: doc.archivedAt ?? null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export const mongooseProjectStore: ProjectStore = {
  async withTransaction<T>(work: (tx: ProjectTransactionContext) => Promise<T>): Promise<T> {
    return runInTransaction(async (session) => work(session));
  },

  async acquireOrganizationLock(organizationId, tx) {
    const session = asSession(tx);
    if (!session) {
      throw new Error('Organization mutation lock requires an active MongoDB transaction session');
    }
    return acquireOrganizationMutationLock(organizationId, session);
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

  async createProject(input, tx) {
    const session = asSession(tx);
    const [doc] = await ProjectModel.create(
      [
        {
          organizationId: input.organizationId,
          name: input.name,
          slug: input.slug,
          ...(input.description !== undefined ? { description: input.description } : {}),
          createdBy: input.createdBy,
          archivedAt: null,
        },
      ],
      session ? { session } : undefined
    );
    return toPublicProject(doc!);
  },

  async findProjectByIdInOrganization(organizationId, projectId, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(projectId)) {
      return null;
    }
    const session = asSession(tx);
    const query = ProjectModel.findOne({ _id: projectId, organizationId });
    if (session) {
      query.session(session);
    }
    const doc = await query;
    return doc ? toPublicProject(doc) : null;
  },

  async listProjectsInOrganization(organizationId, query) {
    if (!isValidObjectId(organizationId)) {
      return { projects: [], total: 0 };
    }

    const filter: Record<string, unknown> = { organizationId };

    if (query.archived === 'false') {
      filter.archivedAt = null;
    } else if (query.archived === 'true') {
      filter.archivedAt = { $ne: null };
    }

    if (query.search) {
      filter.name = { $regex: escapeRegExp(query.search), $options: 'i' };
    }

    const skip = (query.page - 1) * query.limit;

    const [docs, total] = await Promise.all([
      ProjectModel.find(filter).sort({ createdAt: -1, _id: -1 }).skip(skip).limit(query.limit),
      ProjectModel.countDocuments(filter),
    ]);

    return {
      projects: docs.map((doc) => toPublicProject(doc)),
      total,
    };
  },

  async updateProjectByIdInOrganization(organizationId, projectId, updates, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(projectId)) {
      return null;
    }

    const setFields: Record<string, unknown> = {};
    const unsetFields: Record<string, 1> = {};

    if (updates.name !== undefined) {
      setFields.name = updates.name;
    }
    if (updates.slug !== undefined) {
      setFields.slug = updates.slug;
    }
    if (updates.description === null) {
      unsetFields.description = 1;
    } else if (updates.description !== undefined) {
      setFields.description = updates.description;
    }

    const updateDocument: Record<string, unknown> = {};
    if (Object.keys(setFields).length > 0) {
      updateDocument.$set = setFields;
    }
    if (Object.keys(unsetFields).length > 0) {
      updateDocument.$unset = unsetFields;
    }

    const session = asSession(tx);
    const doc = await ProjectModel.findOneAndUpdate(
      { _id: projectId, organizationId },
      updateDocument,
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicProject(doc) : null;
  },

  async setProjectArchivedAtInOrganization(organizationId, projectId, archivedAt, tx) {
    if (!isValidObjectId(organizationId) || !isValidObjectId(projectId)) {
      return null;
    }
    const session = asSession(tx);
    const doc = await ProjectModel.findOneAndUpdate(
      { _id: projectId, organizationId },
      { $set: { archivedAt } },
      { returnDocument: 'after', runValidators: true, ...(session ? { session } : {}) }
    );
    return doc ? toPublicProject(doc) : null;
  },
};
