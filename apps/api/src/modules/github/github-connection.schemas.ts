import { z } from '@vibeshield/env';

/**
 * Strict payload schema for connecting a GitHub repository to a project.
 * Only identifiers are accepted; repository metadata is fetched authoritatively from GitHub.
 */
export const connectProjectRepositorySchema = z
  .object({
    installationRecordId: z.string().trim().min(1, 'Installation ID is required').max(64),
    githubRepositoryId: z.coerce
      .number()
      .int()
      .min(1, 'GitHub repository ID must be a positive integer')
      .max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

/**
 * Bounded query schema for listing active repository connections across an organization.
 */
export const listOrganizationConnectionsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).max(100).default(1),
    perPage: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();
