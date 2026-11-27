import { GITHUB_ACCOUNT_TYPES, GITHUB_REPOSITORY_SELECTIONS } from '@vibeshield/database';
import { z } from '@vibeshield/env';

const DELIVERY_ID_REGEX = /^[A-Za-z0-9._-]{1,128}$/;
const EVENT_NAME_REGEX = /^[a-z][a-z0-9_]{0,63}$/;
const FULL_NAME_REGEX = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

const positiveIntSchema = z
  .number()
  .int()
  .min(1, 'Identifier must be a positive integer')
  .max(Number.MAX_SAFE_INTEGER);

const trimmedNonEmpty = (maxLen: number) => z.string().trim().min(1).max(maxLen);

const grantedPermissionsSchema = z
  .record(trimmedNonEmpty(64), trimmedNonEmpty(32))
  .refine((record) => Object.keys(record).length <= 30, {
    message: 'Permissions map exceeds maximum key count',
  });

const safeHttpUrlSchema = z
  .string()
  .trim()
  .max(500)
  .refine((value) => {
    try {
      const parsed = new URL(value);
      return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch {
      return false;
    }
  }, 'Invalid repository HTML URL');

export const webhookHeadersSchema = z.object({
  deliveryId: z
    .string()
    .trim()
    .regex(DELIVERY_ID_REGEX, 'Missing or malformed X-GitHub-Delivery header'),
  event: z.string().trim().regex(EVENT_NAME_REGEX, 'Missing or malformed X-GitHub-Event header'),
});

export const SUPPORTED_WEBHOOK_EVENTS = [
  'installation',
  'installation_repositories',
  'repository',
] as const;

export const INSTALLATION_SUPPORTED_ACTIONS = [
  'created',
  'deleted',
  'suspend',
  'unsuspend',
  'new_permissions_accepted',
] as const;

export const INSTALLATION_REPOSITORIES_SUPPORTED_ACTIONS = ['added', 'removed'] as const;

export const REPOSITORY_SUPPORTED_ACTIONS = [
  'deleted',
  'renamed',
  'transferred',
  'privatized',
] as const;

export const installationWebhookPayloadSchema = z.object({
  action: trimmedNonEmpty(64),
  installation: z.object({
    id: positiveIntSchema,
    app_id: positiveIntSchema.optional(),
    account: z
      .object({
        id: positiveIntSchema,
        login: trimmedNonEmpty(100),
        type: z.enum(GITHUB_ACCOUNT_TYPES),
      })
      .optional(),
    repository_selection: z.enum(GITHUB_REPOSITORY_SELECTIONS).optional(),
    permissions: grantedPermissionsSchema.optional(),
    suspended_at: z.string().nullable().optional(),
  }),
});

const installationRepoRefSchema = z.object({
  id: positiveIntSchema,
  name: trimmedNonEmpty(100).optional(),
  full_name: trimmedNonEmpty(201).regex(FULL_NAME_REGEX).optional(),
  private: z.boolean().optional(),
});

export const installationRepositoriesWebhookPayloadSchema = z.object({
  action: trimmedNonEmpty(64),
  repository_selection: z.enum(GITHUB_REPOSITORY_SELECTIONS).optional(),
  installation: z.object({
    id: positiveIntSchema,
    app_id: positiveIntSchema.optional(),
    repository_selection: z.enum(GITHUB_REPOSITORY_SELECTIONS).optional(),
  }),
  repositories_added: z.array(installationRepoRefSchema).max(500).optional().default([]),
  repositories_removed: z.array(installationRepoRefSchema).max(500).optional().default([]),
});

export const repositoryWebhookPayloadSchema = z.object({
  action: trimmedNonEmpty(64),
  installation: z
    .object({
      id: positiveIntSchema,
    })
    .optional(),
  repository: z.object({
    id: positiveIntSchema,
    name: trimmedNonEmpty(100),
    full_name: trimmedNonEmpty(201).regex(FULL_NAME_REGEX),
    owner: z.object({
      login: trimmedNonEmpty(100),
    }),
    private: z.boolean(),
    archived: z.boolean().optional(),
    default_branch: trimmedNonEmpty(255).optional(),
    html_url: safeHttpUrlSchema.optional(),
  }),
});

export type InstallationWebhookPayload = z.infer<typeof installationWebhookPayloadSchema>;
export type InstallationRepositoriesWebhookPayload = z.infer<
  typeof installationRepositoriesWebhookPayloadSchema
>;
export type RepositoryWebhookPayload = z.infer<typeof repositoryWebhookPayloadSchema>;
