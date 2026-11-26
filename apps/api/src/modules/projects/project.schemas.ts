import { normalizeSlug, SLUG_REGEX } from '@vibeshield/database';
import { z } from '@vibeshield/env';

const projectNameSchema = z
  .string()
  .trim()
  .min(2, 'Project name must be at least 2 characters')
  .max(120, 'Project name cannot exceed 120 characters');

const projectSlugSchema = z
  .string()
  .trim()
  .min(2, 'Project slug must be at least 2 characters')
  .max(64, 'Project slug cannot exceed 64 characters')
  .transform((value) => normalizeSlug(value))
  .refine((value) => SLUG_REGEX.test(value), {
    message: 'Project slug must contain lowercase letters, numbers, and single hyphens',
  });

const projectDescriptionSchema = z
  .string()
  .trim()
  .max(1000, 'Project description cannot exceed 1000 characters')
  .transform((value) => (value.length === 0 ? null : value));

/**
 * Schema for `POST /api/v1/organizations/:organizationId/projects`.
 * Strict mode rejects untrusted fields such as `organizationId`, `createdBy`, or `archivedAt`.
 */
export const createProjectSchema = z
  .object({
    name: projectNameSchema,
    slug: projectSlugSchema,
    description: projectDescriptionSchema.nullable().optional(),
  })
  .strict();

/**
 * Schema for `PATCH /api/v1/organizations/:organizationId/projects/:projectId`.
 */
export const updateProjectSchema = z
  .object({
    name: projectNameSchema.optional(),
    slug: projectSlugSchema.optional(),
    description: projectDescriptionSchema.nullable().optional(),
  })
  .strict()
  .refine(
    (data) => data.name !== undefined || data.slug !== undefined || data.description !== undefined,
    {
      message: 'At least one updatable field (name, slug, or description) must be provided',
    }
  );

/**
 * Query schema for `GET /api/v1/organizations/:organizationId/projects`.
 */
export const listProjectsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).max(10_000).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    search: z
      .string()
      .trim()
      .max(120)
      .optional()
      .transform((value) => (value && value.length > 0 ? value : undefined)),
    archived: z.enum(['false', 'true', 'all']).default('false'),
  })
  .strict();
