import { z } from '@vibeshield/env';

/**
 * Schema for `POST /api/v1/organizations/:organizationId/github/installations/start`.
 */
export const startGitHubInstallationSchema = z
  .object({
    mode: z.enum(['install', 'authorize']).default('install'),
  })
  .strict();

/**
 * Schema for `POST /api/v1/organizations/:organizationId/github/installations/authorize-list`.
 * Used when separating user OAuth discovery of existing installations from linking.
 */
export const discoverUserInstallationsSchema = z
  .object({
    state: z.string().trim().min(16, 'Invalid authorization state').max(256),
    code: z.string().trim().min(1, 'GitHub authorization code is required').max(256),
  })
  .strict();

/**
 * Schema for `POST /api/v1/organizations/:organizationId/github/installations/complete`.
 * Supports combined install+OAuth (`code` + `installationId`), separated setup+OAuth,
 * installation-selection `linkState` completion, OAuth error/cancellation callbacks,
 * and `setupAction: 'request'` pending-approval redirects where `installationId` is absent.
 * Rejects user-supplied `redirectUri` / `callbackUrl` fields via strict mode.
 */
export const completeGitHubInstallationSchema = z
  .object({
    state: z.string().trim().min(16, 'Invalid authorization state').max(256),
    code: z.string().trim().min(1).max(256).optional(),
    installationId: z.coerce
      .number()
      .int()
      .min(1, 'Installation ID must be a positive integer')
      .max(Number.MAX_SAFE_INTEGER)
      .optional(),
    setupAction: z.enum(['install', 'update', 'request']).optional(),
    error: z.string().trim().min(1).max(128).optional(),
    errorDescription: z.string().trim().max(500).optional(),
  })
  .strict();

/**
 * Query schema for `GET /api/v1/organizations/:organizationId/github/repositories`.
 */
export const listGitHubRepositoriesQuerySchema = z
  .object({
    installationRecordId: z.string().trim().min(1).max(64).optional(),
    page: z.coerce.number().int().min(1).max(100).default(1),
    perPage: z.coerce.number().int().min(1).max(100).default(30),
  })
  .strict();
