import { isValidObjectId, normalizeSlug } from '@vibeshield/database';
import {
  hasOrganizationPermission,
  OrganizationPermission,
  type OrganizationPermissionType,
} from '../organizations/organization.permissions.js';
import { OrganizationError } from '../organizations/organization.types.js';
import {
  mongooseProjectStore,
  type ProjectStore,
  type ProjectTransactionContext,
} from './project.store.js';
import {
  ProjectError,
  type CreateProjectInput,
  type ListProjectsQuery,
  type PaginatedProjectsResult,
  type PublicProject,
  type UpdateProjectInput,
} from './project.types.js';

export interface ProjectServiceDependencies {
  store?: ProjectStore;
  now?: () => Date;
}

export interface ProjectService {
  createProject(
    actorUserId: string,
    organizationId: string,
    input: CreateProjectInput
  ): Promise<PublicProject>;
  listProjects(organizationId: string, query: ListProjectsQuery): Promise<PaginatedProjectsResult>;
  getProject(organizationId: string, projectId: string): Promise<PublicProject>;
  updateProject(
    actorUserId: string,
    organizationId: string,
    projectId: string,
    input: UpdateProjectInput
  ): Promise<PublicProject>;
  archiveProject(
    actorUserId: string,
    organizationId: string,
    projectId: string
  ): Promise<PublicProject>;
  restoreProject(
    actorUserId: string,
    organizationId: string,
    projectId: string
  ): Promise<PublicProject>;
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

async function acquireLockAndAuthorizeInTx(
  store: ProjectStore,
  actorUserId: string,
  organizationId: string,
  permission: OrganizationPermissionType,
  tx: ProjectTransactionContext
): Promise<void> {
  const locked = await store.acquireOrganizationLock(organizationId, tx);
  if (!locked) {
    throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
  }

  const membership = await store.findActiveMembership(organizationId, actorUserId, tx);
  if (!membership) {
    throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
  }

  if (!hasOrganizationPermission(membership.role, permission)) {
    throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
  }
}

/**
 * Creates the organization-scoped project management service.
 * All project mutations execute inside MongoDB transactions, acquire the shared
 * per-organization mutation lock, and revalidate actor membership/role in-transaction.
 */
export function createProjectService(
  dependencies: ProjectServiceDependencies = {}
): ProjectService {
  const store = dependencies.store ?? mongooseProjectStore;
  const now = dependencies.now ?? (() => new Date());

  return {
    async createProject(
      actorUserId: string,
      organizationId: string,
      input: CreateProjectInput
    ): Promise<PublicProject> {
      const normalizedSlug = normalizeSlug(input.slug);
      const trimmedName = input.name.trim();
      const normalizedDescription =
        input.description === undefined || input.description === null
          ? undefined
          : input.description.trim() || undefined;

      try {
        return await store.withTransaction(async (tx) => {
          await acquireLockAndAuthorizeInTx(
            store,
            actorUserId,
            organizationId,
            OrganizationPermission.PROJECT_CREATE,
            tx
          );

          return await store.createProject(
            {
              organizationId,
              name: trimmedName,
              slug: normalizedSlug,
              ...(normalizedDescription !== undefined
                ? { description: normalizedDescription }
                : {}),
              createdBy: actorUserId,
            },
            tx
          );
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new ProjectError(
            409,
            'PROJECT_SLUG_EXISTS',
            'A project with this slug already exists in this organization'
          );
        }
        throw error;
      }
    },

    async listProjects(
      organizationId: string,
      query: ListProjectsQuery
    ): Promise<PaginatedProjectsResult> {
      const { projects, total } = await store.listProjectsInOrganization(organizationId, query);
      const totalPages = total === 0 ? 0 : Math.ceil(total / query.limit);

      return {
        projects,
        pagination: {
          page: query.page,
          limit: query.limit,
          total,
          totalPages,
        },
      };
    },

    async getProject(organizationId: string, projectId: string): Promise<PublicProject> {
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(400, 'INVALID_PROJECT_ID', 'Invalid project identifier');
      }

      const project = await store.findProjectByIdInOrganization(organizationId, projectId);
      if (!project) {
        throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      }

      return project;
    },

    async updateProject(
      actorUserId: string,
      organizationId: string,
      projectId: string,
      input: UpdateProjectInput
    ): Promise<PublicProject> {
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(400, 'INVALID_PROJECT_ID', 'Invalid project identifier');
      }

      const updates: {
        name?: string;
        slug?: string;
        description?: string | null;
      } = {};

      if (input.name !== undefined) {
        updates.name = input.name.trim();
      }
      if (input.slug !== undefined) {
        updates.slug = normalizeSlug(input.slug);
      }
      if (input.description !== undefined) {
        if (input.description === null) {
          updates.description = null;
        } else {
          const trimmedDesc = input.description.trim();
          updates.description = trimmedDesc.length === 0 ? null : trimmedDesc;
        }
      }

      try {
        return await store.withTransaction(async (tx) => {
          await acquireLockAndAuthorizeInTx(
            store,
            actorUserId,
            organizationId,
            OrganizationPermission.PROJECT_UPDATE,
            tx
          );

          const updated = await store.updateProjectByIdInOrganization(
            organizationId,
            projectId,
            updates,
            tx
          );
          if (!updated) {
            throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
          }
          return updated;
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new ProjectError(
            409,
            'PROJECT_SLUG_EXISTS',
            'A project with this slug already exists in this organization'
          );
        }
        throw error;
      }
    },

    async archiveProject(
      actorUserId: string,
      organizationId: string,
      projectId: string
    ): Promise<PublicProject> {
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(400, 'INVALID_PROJECT_ID', 'Invalid project identifier');
      }

      return store.withTransaction(async (tx) => {
        await acquireLockAndAuthorizeInTx(
          store,
          actorUserId,
          organizationId,
          OrganizationPermission.PROJECT_ARCHIVE,
          tx
        );

        const existing = await store.findProjectByIdInOrganization(organizationId, projectId, tx);
        if (!existing) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }

        // Idempotent archive: preserve existing archivedAt timestamp if already archived
        if (existing.archivedAt !== null) {
          return existing;
        }

        const archived = await store.setProjectArchivedAtInOrganization(
          organizationId,
          projectId,
          now(),
          tx
        );
        if (!archived) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }
        return archived;
      });
    },

    async restoreProject(
      actorUserId: string,
      organizationId: string,
      projectId: string
    ): Promise<PublicProject> {
      if (!isValidObjectId(projectId)) {
        throw new ProjectError(400, 'INVALID_PROJECT_ID', 'Invalid project identifier');
      }

      return store.withTransaction(async (tx) => {
        await acquireLockAndAuthorizeInTx(
          store,
          actorUserId,
          organizationId,
          OrganizationPermission.PROJECT_RESTORE,
          tx
        );

        const existing = await store.findProjectByIdInOrganization(organizationId, projectId, tx);
        if (!existing) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }

        // Idempotent restore
        if (existing.archivedAt === null) {
          return existing;
        }

        const restored = await store.setProjectArchivedAtInOrganization(
          organizationId,
          projectId,
          null,
          tx
        );
        if (!restored) {
          throw new ProjectError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        }
        return restored;
      });
    },
  };
}
