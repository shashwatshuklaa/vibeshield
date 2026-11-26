import {
  EMAIL_REGEX,
  isValidObjectId,
  MEMBERSHIP_STATUSES,
  normalizeEmail,
  normalizeSlug,
  ORGANIZATION_ROLES,
  SLUG_REGEX,
} from '@vibeshield/database';
import { z } from '@vibeshield/env';

const slugSchema = z
  .string()
  .trim()
  .min(2, 'Slug must be at least 2 characters')
  .max(64, 'Slug cannot exceed 64 characters')
  .transform((value) => normalizeSlug(value))
  .refine((value) => SLUG_REGEX.test(value), {
    message: 'Slug must contain lowercase letters, numbers, and single hyphens',
  });

const organizationNameSchema = z
  .string()
  .trim()
  .min(2, 'Organization name must be at least 2 characters')
  .max(100, 'Organization name cannot exceed 100 characters');

/**
 * Schema for `POST /api/v1/organizations`.
 * Strict mode prevents clients from submitting trusted fields such as `createdBy`.
 */
export const createOrganizationSchema = z
  .object({
    name: organizationNameSchema,
    slug: slugSchema,
  })
  .strict();

/**
 * Schema for `PATCH /api/v1/organizations/:organizationId`.
 */
export const updateOrganizationSchema = z
  .object({
    name: organizationNameSchema.optional(),
    slug: slugSchema.optional(),
  })
  .strict()
  .refine((data) => data.name !== undefined || data.slug !== undefined, {
    message: 'At least one updatable field (name or slug) must be provided',
  });

/**
 * Schema for `POST /api/v1/organizations/:organizationId/members`.
 */
export const addOrganizationMemberSchema = z
  .object({
    email: z
      .string()
      .trim()
      .min(1, 'Email is required')
      .max(320, 'Email cannot exceed 320 characters')
      .refine((value) => EMAIL_REGEX.test(value), {
        message: 'Must be a valid email address',
      })
      .transform((value) => normalizeEmail(value)),
    role: z.enum(ORGANIZATION_ROLES),
  })
  .strict();

/**
 * Schema for `PATCH /api/v1/organizations/:organizationId/members/:membershipId`.
 */
export const updateOrganizationMemberSchema = z
  .object({
    role: z.enum(ORGANIZATION_ROLES).optional(),
    status: z.enum(MEMBERSHIP_STATUSES).optional(),
  })
  .strict()
  .refine((data) => data.role !== undefined || data.status !== undefined, {
    message: 'At least one updatable field (role or status) must be provided',
  });

/**
 * Schema for `POST /api/v1/organizations/:organizationId/transfer-ownership`.
 */
export const transferOwnershipSchema = z
  .object({
    targetUserId: z
      .string()
      .trim()
      .refine((value) => isValidObjectId(value), {
        message: 'Must be a valid user identifier',
      }),
  })
  .strict();
