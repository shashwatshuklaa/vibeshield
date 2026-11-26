import { HttpError } from '../../utils/http-error.js';

/**
 * Safe public representation of a project belonging to an organization.
 */
export interface PublicProject {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  description: string | null;
  createdBy: string;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateProjectInput {
  name: string;
  slug: string;
  description?: string | null;
}

export interface UpdateProjectInput {
  name?: string;
  slug?: string;
  description?: string | null;
}

export type ArchivedFilterMode = 'false' | 'true' | 'all';

export interface ListProjectsQuery {
  page: number;
  limit: number;
  search?: string;
  archived: ArchivedFilterMode;
}

export interface PaginationMetadata {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface PaginatedProjectsResult {
  projects: PublicProject[];
  pagination: PaginationMetadata;
}

/**
 * Operational error thrown by project management operations.
 */
export class ProjectError extends HttpError {
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(statusCode, code, message, details);
    this.name = 'ProjectError';
  }
}
