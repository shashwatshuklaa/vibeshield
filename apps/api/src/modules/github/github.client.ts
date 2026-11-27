import { redactGitHubSecrets } from '@vibeshield/database';
import { z } from '@vibeshield/env';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { createGitHubAppJwt } from './github.jwt.js';
import {
  GitHubError,
  type CreateRepositoryAcquisitionTokenInput,
  type DiscoveredUserGitHubInstallation,
  type PublicGitHubRepository,
  type RepositoryAcquisitionToken,
  type RevokeInstallationTokenResult,
} from './github.types.js';

const OFFICIAL_GITHUB_API_ORIGIN = 'https://api.github.com';
const OFFICIAL_GITHUB_OAUTH_ORIGIN = 'https://github.com';
const GITHUB_API_VERSION = '2026-03-10';
const GITHUB_USER_AGENT = 'VibeShield-API';
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const MAX_TRANSIENT_GET_RETRIES = 1;
const MAX_USER_INSTALLATION_PAGES = 10;
const MAX_INSTALLATION_REPOSITORY_PAGES = 20;

function toPublicGitHubRepository(
  repo: z.infer<typeof gitHubRepositorySchema>
): PublicGitHubRepository {
  return {
    githubRepositoryId: repo.id,
    name: repo.name,
    fullName: repo.full_name,
    ownerLogin: repo.owner.login,
    defaultBranch: repo.default_branch,
    isPrivate: repo.private,
    isArchived: repo.archived,
    htmlUrl: repo.html_url,
  };
}

const positiveIntSchema = z.number().int().min(1);

const httpsOrSafeUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    const protocol = new URL(value).protocol;
    return protocol === 'https:' || protocol === 'http:';
  }, 'Must be a valid HTTP/HTTPS URL');

const oauthAccessTokenResponseSchema = z.object({
  access_token: z.string().min(1).optional(),
  error: z.string().optional(),
  error_description: z.string().optional(),
});

const gitHubAccountSchema = z.object({
  id: positiveIntSchema,
  login: z.string().min(1).max(100),
  type: z.enum(['User', 'Organization']),
});

const userInstallationSchema = z.object({
  id: positiveIntSchema,
  app_id: positiveIntSchema,
  account: gitHubAccountSchema,
  repository_selection: z.enum(['all', 'selected']),
  suspended_at: z.string().nullable().optional(),
});

const listUserInstallationsResponseSchema = z.object({
  total_count: z.number().int().min(0),
  installations: z.array(userInstallationSchema),
});

const appInstallationResponseSchema = z.object({
  id: positiveIntSchema,
  app_id: positiveIntSchema,
  account: gitHubAccountSchema,
  repository_selection: z.enum(['all', 'selected']),
  permissions: z.record(z.string(), z.string()).default({}),
  suspended_at: z.string().nullable().optional(),
});

const installationAccessTokenResponseSchema = z.object({
  token: z.string().trim().min(1),
  expires_at: z.string().trim().min(1),
});

const scopedRepositoryRefSchema = z.object({
  id: positiveIntSchema,
});

const repositoryAcquisitionTokenResponseSchema = z.object({
  token: z.string().trim().min(1),
  expires_at: z.string().trim().min(1),
  repository_selection: z.enum(['all', 'selected']).optional(),
  permissions: z.record(z.string(), z.string()),
  repositories: z.array(scopedRepositoryRefSchema),
});

const gitHubRepositorySchema = z.object({
  id: positiveIntSchema,
  name: z.string().min(1).max(200),
  full_name: z.string().min(3).max(300),
  owner: z.object({
    login: z.string().min(1).max(100),
  }),
  default_branch: z.string().min(1).max(255),
  private: z.boolean(),
  archived: z.boolean().default(false),
  html_url: httpsOrSafeUrlSchema,
});

const listInstallationRepositoriesResponseSchema = z.object({
  total_count: z.number().int().min(0),
  repositories: z.array(gitHubRepositorySchema),
});

const gitHubErrorMessageSchema = z
  .object({
    message: z.string().optional(),
  })
  .passthrough();

export interface AuthoritativeGitHubInstallation {
  githubInstallationId: number;
  githubAppId: number;
  accountId: number;
  accountLogin: string;
  accountType: 'User' | 'Organization';
  repositorySelection: 'all' | 'selected';
  grantedPermissions: Record<string, string>;
  suspendedAt: Date | null;
}

export interface GitHubInstallationRepositoriesPage {
  repositories: PublicGitHubRepository[];
  totalCount: number;
  hasNextPage: boolean;
}

export type GitHubRepositoryProbeResult =
  | { status: 'ACCESSIBLE'; repository: PublicGitHubRepository }
  | { status: 'ACCESS_REVOKED' }
  | { status: 'NOT_FOUND' }
  | { status: 'GONE' };

export interface GitHubClient {
  exchangeOAuthCode(input: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<string>;
  listUserInstallations(userAccessToken: string): Promise<DiscoveredUserGitHubInstallation[]>;
  getAppInstallation(installationId: number): Promise<AuthoritativeGitHubInstallation>;
  /**
   * Mints an installation-scoped discovery token for enumerating accessible repositories and
   * syncing project metadata. Must NEVER be used by future repository acquisition workflows.
   */
  createInstallationAccessToken(installationId: number): Promise<string>;
  /**
   * Mints a strictly bounded, single-repository (`repository_ids: [githubRepositoryId]`),
   * read-only (`permissions: { contents: 'read' }`) installation token in memory for acquisition.
   */
  createRepositoryAcquisitionToken(
    input: CreateRepositoryAcquisitionTokenInput
  ): Promise<RepositoryAcquisitionToken>;
  /**
   * Explicitly revokes an active installation access token via `DELETE /installation/token`.
   */
  revokeInstallationAccessToken(installationToken: string): Promise<RevokeInstallationTokenResult>;
  listInstallationRepositories(
    installationToken: string,
    options: { page: number; perPage: number }
  ): Promise<GitHubInstallationRepositoriesPage>;
  findInstallationRepositoryById(
    installationToken: string,
    githubRepositoryId: number
  ): Promise<PublicGitHubRepository | null>;
  probeRepositoryById(
    installationToken: string,
    githubRepositoryId: number
  ): Promise<GitHubRepositoryProbeResult>;
}

export interface CreateGitHubClientOptions {
  config: GitHubRuntimeConfig;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  timeoutMs?: number;
  retryDelayMs?: number;
  apiBaseUrl?: string;
  oauthBaseUrl?: string;
  allowCustomBaseUrlForTests?: boolean;
}

function resolveControlledBaseUrl(
  rawUrl: string | undefined,
  officialOrigin: string,
  allowCustomForTests: boolean
): string {
  if (!rawUrl) {
    return officialOrigin;
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new GitHubError(500, 'GITHUB_CONFIGURATION_ERROR', 'Invalid GitHub API base URL');
  }

  if (parsed.origin === officialOrigin) {
    return officialOrigin;
  }

  if (!allowCustomForTests) {
    throw new GitHubError(
      500,
      'GITHUB_CONFIGURATION_ERROR',
      'Custom GitHub API base URLs are restricted to controlled test transports'
    );
  }

  return parsed.origin;
}

function parseLinkNextUrl(linkHeader: string | null, expectedOrigin: string): string | null {
  if (!linkHeader) {
    return null;
  }

  const segments = linkHeader.split(',');
  for (const segment of segments) {
    const match = /<([^>]+)>\s*;\s*([^$]+)/.exec(segment.trim());
    if (!match) {
      continue;
    }
    const candidateUrl = match[1];
    const params = match[2];
    if (!candidateUrl || !params || !/\brel=["']?next["']?/i.test(params)) {
      continue;
    }

    try {
      const parsed = new URL(candidateUrl);
      if (parsed.origin === expectedOrigin) {
        return parsed.toString();
      }
    } catch {
      return null;
    }
  }

  return null;
}

function parseRetryAfterSeconds(headers: Headers, nowMs: number): number {
  const retryAfter = headers.get('retry-after');
  if (retryAfter) {
    const numeric = Number(retryAfter);
    if (Number.isFinite(numeric) && numeric >= 1) {
      return Math.min(Math.ceil(numeric), 3600);
    }
  }

  const resetEpoch = headers.get('x-ratelimit-reset');
  if (resetEpoch) {
    const resetSeconds = Number(resetEpoch);
    if (Number.isFinite(resetSeconds)) {
      const delta = Math.ceil(resetSeconds - nowMs / 1000);
      if (delta >= 1) {
        return Math.min(delta, 3600);
      }
    }
  }

  return 60;
}

function isRateLimitResponse(status: number, headers: Headers, bodyMessage: string): boolean {
  if (status === 429) {
    return true;
  }
  if (status !== 403) {
    return false;
  }
  const remaining = headers.get('x-ratelimit-remaining');
  if (remaining === '0' || headers.has('retry-after')) {
    return true;
  }
  return /rate limit/i.test(bodyMessage);
}

function isTimeoutError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const name = (error as { name?: unknown }).name;
  return name === 'TimeoutError' || name === 'AbortError';
}

/**
 * Hardened GitHub App & REST API client using Node.js native fetch and crypto.
 * Rejects unvalidated responses, prevents indefinite retries, enforces timeouts,
 * and scrubs all credentials from error surfaces.
 */
export function createGitHubClient(options: CreateGitHubClientOptions): GitHubClient {
  const {
    config,
    fetchImpl = globalThis.fetch,
    now = () => new Date(),
    timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    retryDelayMs = 50,
    allowCustomBaseUrlForTests = false,
  } = options;

  const apiBaseUrl = resolveControlledBaseUrl(
    options.apiBaseUrl,
    OFFICIAL_GITHUB_API_ORIGIN,
    allowCustomBaseUrlForTests
  );
  const oauthBaseUrl = resolveControlledBaseUrl(
    options.oauthBaseUrl,
    OFFICIAL_GITHUB_OAUTH_ORIGIN,
    allowCustomBaseUrlForTests
  );

  const secretsToRedact = [
    config.privateKeyPem,
    config.clientSecret,
    config.webhookSecret,
    config.previousWebhookSecret,
  ];

  function safeRedact(text: string, runtimeToken?: string): string {
    return redactGitHubSecrets(text, [...secretsToRedact, runtimeToken]);
  }

  async function executeFetch(
    url: string,
    init: RequestInit,
    runtimeToken?: string
  ): Promise<Response> {
    const isIdempotentGet = (init.method ?? 'GET').toUpperCase() === 'GET';
    const maxAttempts = isIdempotentGet ? 1 + MAX_TRANSIENT_GET_RETRIES : 1;

    let lastError: unknown;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await fetchImpl(url, {
          ...init,
          signal: AbortSignal.timeout(timeoutMs),
        });

        if (
          isIdempotentGet &&
          attempt < maxAttempts &&
          (response.status === 502 || response.status === 503 || response.status === 504)
        ) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
          continue;
        }

        return response;
      } catch (error) {
        lastError = error;
        if (isTimeoutError(error)) {
          throw new GitHubError(
            504,
            'GITHUB_API_TIMEOUT',
            'GitHub API request timed out; please try again'
          );
        }
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
          continue;
        }
      }
    }

    const message = lastError instanceof Error ? safeRedact(lastError.message, runtimeToken) : '';
    throw new GitHubError(
      502,
      'GITHUB_API_UNAVAILABLE',
      message ? `Unable to reach GitHub API (${message})` : 'Unable to reach GitHub API'
    );
  }

  async function parseJsonSafely(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new GitHubError(
        502,
        'INVALID_GITHUB_RESPONSE',
        'Received malformed response payload from GitHub'
      );
    }
  }

  async function readSafeErrorMessage(response: Response): Promise<string> {
    try {
      const payload = (await response.json()) as unknown;
      const parsed = gitHubErrorMessageSchema.safeParse(payload);
      return parsed.success && parsed.data.message ? parsed.data.message : '';
    } catch {
      return '';
    }
  }

  async function requestGitHubApi<TSchema extends z.ZodTypeAny>(
    url: string,
    init: RequestInit,
    schema: TSchema,
    optionsMap: {
      bearerToken: string;
      notFoundCode?: string;
      notFoundMessage?: string;
      forbiddenCode?: string;
      forbiddenMessage?: string;
    }
  ): Promise<{ data: z.infer<TSchema>; headers: Headers }> {
    const response = await executeFetch(
      url,
      {
        ...init,
        headers: {
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': GITHUB_API_VERSION,
          'User-Agent': GITHUB_USER_AGENT,
          Authorization: `Bearer ${optionsMap.bearerToken}`,
          ...(init.headers ?? {}),
        },
      },
      optionsMap.bearerToken
    );

    if (!response.ok) {
      const ghMessage = safeRedact(await readSafeErrorMessage(response), optionsMap.bearerToken);

      if (isRateLimitResponse(response.status, response.headers, ghMessage)) {
        const retryAfterSeconds = parseRetryAfterSeconds(response.headers, now().getTime());
        throw new GitHubError(
          429,
          'GITHUB_RATE_LIMITED',
          'GitHub API rate limit exceeded; please retry shortly',
          { retryAfterSeconds }
        );
      }

      if (response.status === 401) {
        throw new GitHubError(
          502,
          'GITHUB_AUTH_FAILED',
          'GitHub authentication failed for this integration request'
        );
      }

      if (response.status === 403) {
        if (/suspend/i.test(ghMessage)) {
          throw new GitHubError(
            409,
            'GITHUB_INSTALLATION_SUSPENDED',
            'GitHub App installation is suspended on GitHub'
          );
        }
        throw new GitHubError(
          403,
          optionsMap.forbiddenCode ?? 'GITHUB_ACCESS_DENIED',
          optionsMap.forbiddenMessage ?? 'GitHub denied access to the requested resource'
        );
      }

      if (response.status === 404) {
        throw new GitHubError(
          404,
          optionsMap.notFoundCode ?? 'GITHUB_RESOURCE_NOT_FOUND',
          optionsMap.notFoundMessage ?? 'Requested resource was not found on GitHub'
        );
      }

      throw new GitHubError(
        502,
        'GITHUB_API_ERROR',
        'Unexpected error response received from GitHub'
      );
    }

    const json = await parseJsonSafely(response);
    const validated = schema.safeParse(json);
    if (!validated.success) {
      throw new GitHubError(
        502,
        'INVALID_GITHUB_RESPONSE',
        'Received unexpected response format from GitHub'
      );
    }

    return {
      data: validated.data,
      headers: response.headers,
    };
  }

  return {
    async exchangeOAuthCode(input: {
      code: string;
      codeVerifier: string;
      redirectUri: string;
    }): Promise<string> {
      const response = await executeFetch(
        `${oauthBaseUrl}/login/oauth/access_token`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': GITHUB_USER_AGENT,
          },
          body: JSON.stringify({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code: input.code,
            redirect_uri: input.redirectUri,
            code_verifier: input.codeVerifier,
          }),
        },
        input.codeVerifier
      );

      if (!response.ok) {
        if (response.status === 429) {
          throw new GitHubError(
            429,
            'GITHUB_RATE_LIMITED',
            'GitHub OAuth rate limit exceeded; please retry shortly'
          );
        }
        throw new GitHubError(
          502,
          'GITHUB_OAUTH_FAILED',
          'Failed to exchange GitHub authorization code'
        );
      }

      const json = await parseJsonSafely(response);
      const parsed = oauthAccessTokenResponseSchema.safeParse(json);
      if (!parsed.success) {
        throw new GitHubError(
          502,
          'INVALID_GITHUB_RESPONSE',
          'Received unexpected OAuth token payload from GitHub'
        );
      }

      if (parsed.data.error || !parsed.data.access_token) {
        if (parsed.data.error === 'redirect_uri_mismatch') {
          throw new GitHubError(
            400,
            'GITHUB_REDIRECT_URI_MISMATCH',
            'GitHub OAuth redirect URI did not match the registered callback URL'
          );
        }
        if (parsed.data.error === 'incorrect_client_credentials') {
          throw new GitHubError(
            502,
            'GITHUB_AUTH_FAILED',
            'GitHub OAuth application credentials failed verification'
          );
        }
        throw new GitHubError(
          400,
          'GITHUB_OAUTH_CODE_INVALID',
          'GitHub authorization code or PKCE verifier is invalid or expired'
        );
      }

      return parsed.data.access_token;
    },

    async listUserInstallations(
      userAccessToken: string
    ): Promise<DiscoveredUserGitHubInstallation[]> {
      const installations: DiscoveredUserGitHubInstallation[] = [];
      let nextUrl: string | null = `${apiBaseUrl}/user/installations?per_page=100&page=1`;

      for (let pageIndex = 0; pageIndex < MAX_USER_INSTALLATION_PAGES && nextUrl; pageIndex += 1) {
        const { data, headers } = await requestGitHubApi(
          nextUrl,
          { method: 'GET' },
          listUserInstallationsResponseSchema,
          {
            bearerToken: userAccessToken,
            forbiddenCode: 'GITHUB_ACCESS_DENIED',
            forbiddenMessage: 'Unable to verify GitHub user installations',
          }
        );

        for (const item of data.installations) {
          if (item.app_id !== config.appId) {
            continue;
          }
          installations.push({
            githubInstallationId: item.id,
            accountLogin: item.account.login,
            accountType: item.account.type,
            repositorySelection: item.repository_selection,
            suspendedAt: item.suspended_at ?? null,
          });
        }

        nextUrl = parseLinkNextUrl(headers.get('link'), apiBaseUrl);
      }

      return installations;
    },

    async getAppInstallation(installationId: number): Promise<AuthoritativeGitHubInstallation> {
      const appJwt = createGitHubAppJwt({
        appId: config.appId,
        privateKeyPem: config.privateKeyPem,
        now,
      });

      const { data } = await requestGitHubApi(
        `${apiBaseUrl}/app/installations/${installationId}`,
        { method: 'GET' },
        appInstallationResponseSchema,
        {
          bearerToken: appJwt,
          notFoundCode: 'GITHUB_INSTALLATION_NOT_FOUND',
          notFoundMessage: 'GitHub App installation was not found on GitHub',
        }
      );

      if (data.id !== installationId || data.app_id !== config.appId) {
        throw new GitHubError(
          502,
          'INVALID_GITHUB_RESPONSE',
          'GitHub installation metadata did not match the configured GitHub App'
        );
      }

      let suspendedAt: Date | null = null;
      if (data.suspended_at) {
        const parsedDate = new Date(data.suspended_at);
        if (Number.isNaN(parsedDate.getTime())) {
          throw new GitHubError(
            502,
            'INVALID_GITHUB_RESPONSE',
            'GitHub returned an invalid installation suspension timestamp'
          );
        }
        suspendedAt = parsedDate;
      }

      return {
        githubInstallationId: data.id,
        githubAppId: data.app_id,
        accountId: data.account.id,
        accountLogin: data.account.login,
        accountType: data.account.type,
        repositorySelection: data.repository_selection,
        grantedPermissions: data.permissions,
        suspendedAt,
      };
    },

    async createInstallationAccessToken(installationId: number): Promise<string> {
      const appJwt = createGitHubAppJwt({
        appId: config.appId,
        privateKeyPem: config.privateKeyPem,
        now,
      });

      const { data } = await requestGitHubApi(
        `${apiBaseUrl}/app/installations/${installationId}/access_tokens`,
        {
          method: 'POST',
          redirect: 'error',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
        },
        installationAccessTokenResponseSchema,
        {
          bearerToken: appJwt,
          notFoundCode: 'GITHUB_INSTALLATION_NOT_FOUND',
          notFoundMessage: 'GitHub App installation was not found or access was revoked',
          forbiddenCode: 'GITHUB_INSTALLATION_ACCESS_DENIED',
          forbiddenMessage: 'GitHub denied creating an installation access token',
        }
      );

      return data.token;
    },

    async createRepositoryAcquisitionToken(
      input: CreateRepositoryAcquisitionTokenInput
    ): Promise<RepositoryAcquisitionToken> {
      if (!Number.isSafeInteger(input.installationId) || input.installationId < 1) {
        throw new GitHubError(
          400,
          'INVALID_INSTALLATION_ID',
          'GitHub installation ID must be a valid positive integer'
        );
      }

      if (!Number.isSafeInteger(input.githubRepositoryId) || input.githubRepositoryId < 1) {
        throw new GitHubError(
          400,
          'INVALID_REPOSITORY_ID',
          'GitHub repository ID must be a valid positive integer'
        );
      }

      const appJwt = createGitHubAppJwt({
        appId: config.appId,
        privateKeyPem: config.privateKeyPem,
        now,
      });

      const { data } = await requestGitHubApi(
        `${apiBaseUrl}/app/installations/${input.installationId}/access_tokens`,
        {
          method: 'POST',
          redirect: 'error',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            repository_ids: [input.githubRepositoryId],
            permissions: {
              contents: 'read',
            },
          }),
        },
        repositoryAcquisitionTokenResponseSchema,
        {
          bearerToken: appJwt,
          notFoundCode: 'GITHUB_INSTALLATION_NOT_FOUND',
          notFoundMessage:
            'GitHub App installation or repository was not found or access was revoked',
          forbiddenCode: 'GITHUB_INSTALLATION_ACCESS_DENIED',
          forbiddenMessage: 'GitHub denied creating a repository-scoped installation access token',
        }
      );

      const expiresAt = new Date(data.expires_at);
      if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= now().getTime()) {
        throw new GitHubError(
          502,
          'INVALID_GITHUB_RESPONSE',
          'GitHub returned an invalid or already-expired installation token timestamp'
        );
      }

      if (data.repository_selection !== undefined && data.repository_selection !== 'selected') {
        throw new GitHubError(
          502,
          'GITHUB_TOKEN_SCOPE_MISMATCH',
          'GitHub returned an installation token with broader repository selection than requested'
        );
      }

      if (data.repositories.length !== 1 || data.repositories[0]?.id !== input.githubRepositoryId) {
        throw new GitHubError(
          502,
          'GITHUB_TOKEN_SCOPE_MISMATCH',
          'GitHub returned an installation token with missing or unexpected repository scope'
        );
      }

      if (data.permissions.contents !== 'read') {
        throw new GitHubError(
          502,
          'GITHUB_TOKEN_SCOPE_MISMATCH',
          'GitHub returned an installation token without read-only contents permission'
        );
      }

      for (const [permissionKey, permissionLevel] of Object.entries(data.permissions)) {
        if (permissionLevel !== 'read') {
          throw new GitHubError(
            502,
            'GITHUB_TOKEN_SCOPE_MISMATCH',
            'GitHub returned an installation token with elevated non-read permissions'
          );
        }
        if (permissionKey !== 'contents' && permissionKey !== 'metadata') {
          throw new GitHubError(
            502,
            'GITHUB_TOKEN_SCOPE_MISMATCH',
            'GitHub returned an installation token with unexpected permission scope'
          );
        }
      }

      return {
        token: data.token,
        expiresAt,
        installationId: input.installationId,
        githubRepositoryId: input.githubRepositoryId,
        permissions: {
          contents: 'read',
          ...(data.permissions.metadata === 'read' ? { metadata: 'read' as const } : {}),
        },
      };
    },

    async revokeInstallationAccessToken(
      installationToken: string
    ): Promise<RevokeInstallationTokenResult> {
      const trimmedToken = typeof installationToken === 'string' ? installationToken.trim() : '';
      if (trimmedToken.length === 0) {
        throw new GitHubError(
          400,
          'INVALID_GITHUB_TOKEN',
          'GitHub installation access token must be a non-empty string'
        );
      }

      const response = await executeFetch(
        `${apiBaseUrl}/installation/token`,
        {
          method: 'DELETE',
          redirect: 'error',
          headers: {
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': GITHUB_API_VERSION,
            'User-Agent': GITHUB_USER_AGENT,
            Authorization: `Bearer ${trimmedToken}`,
          },
        },
        trimmedToken
      );

      if (response.status === 204 || response.ok) {
        return {
          revoked: true,
          alreadyInvalidOrExpired: false,
        };
      }

      if (response.status === 401 || response.status === 404) {
        return {
          revoked: true,
          alreadyInvalidOrExpired: true,
        };
      }

      const ghMessage = safeRedact(await readSafeErrorMessage(response), trimmedToken);
      if (isRateLimitResponse(response.status, response.headers, ghMessage)) {
        const retryAfterSeconds = parseRetryAfterSeconds(response.headers, now().getTime());
        throw new GitHubError(
          429,
          'GITHUB_RATE_LIMITED',
          'GitHub API rate limit exceeded; please retry shortly',
          { retryAfterSeconds }
        );
      }

      if (response.status === 403) {
        throw new GitHubError(
          403,
          'GITHUB_ACCESS_DENIED',
          'GitHub denied revoking the installation access token'
        );
      }

      throw new GitHubError(
        502,
        'GITHUB_API_ERROR',
        'Unexpected error response received from GitHub while revoking token'
      );
    },

    async listInstallationRepositories(
      installationToken: string,
      queryOptions: { page: number; perPage: number }
    ): Promise<GitHubInstallationRepositoriesPage> {
      const { page, perPage } = queryOptions;
      const { data, headers } = await requestGitHubApi(
        `${apiBaseUrl}/installation/repositories?per_page=${perPage}&page=${page}`,
        { method: 'GET' },
        listInstallationRepositoriesResponseSchema,
        {
          bearerToken: installationToken,
          notFoundCode: 'GITHUB_INSTALLATION_NOT_FOUND',
          notFoundMessage: 'GitHub App installation repositories could not be found',
          forbiddenCode: 'GITHUB_ACCESS_DENIED',
          forbiddenMessage: 'GitHub installation lacks permissions to list repositories',
        }
      );

      const linkNext = parseLinkNextUrl(headers.get('link'), apiBaseUrl);
      const hasNextPage = linkNext !== null || page * perPage < data.total_count;

      return {
        totalCount: data.total_count,
        hasNextPage,
        repositories: data.repositories.map(toPublicGitHubRepository),
      };
    },

    async findInstallationRepositoryById(
      installationToken: string,
      githubRepositoryId: number
    ): Promise<PublicGitHubRepository | null> {
      let nextUrl: string | null = `${apiBaseUrl}/installation/repositories?per_page=100&page=1`;

      for (
        let pageIndex = 0;
        pageIndex < MAX_INSTALLATION_REPOSITORY_PAGES && nextUrl;
        pageIndex += 1
      ) {
        const { data, headers } = await requestGitHubApi(
          nextUrl,
          { method: 'GET' },
          listInstallationRepositoriesResponseSchema,
          {
            bearerToken: installationToken,
            notFoundCode: 'GITHUB_INSTALLATION_NOT_FOUND',
            notFoundMessage: 'GitHub App installation repositories could not be found',
            forbiddenCode: 'GITHUB_ACCESS_DENIED',
            forbiddenMessage: 'GitHub installation lacks permissions to list repositories',
          }
        );

        const match = data.repositories.find((repo) => repo.id === githubRepositoryId);
        if (match) {
          return toPublicGitHubRepository(match);
        }

        nextUrl = parseLinkNextUrl(headers.get('link'), apiBaseUrl);
      }

      return null;
    },

    async probeRepositoryById(
      installationToken: string,
      githubRepositoryId: number
    ): Promise<GitHubRepositoryProbeResult> {
      const response = await executeFetch(
        `${apiBaseUrl}/repositories/${githubRepositoryId}`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': GITHUB_API_VERSION,
            'User-Agent': GITHUB_USER_AGENT,
            Authorization: `Bearer ${installationToken}`,
          },
        },
        installationToken
      );

      if (response.ok) {
        const json = await parseJsonSafely(response);
        const validated = gitHubRepositorySchema.safeParse(json);
        if (!validated.success) {
          throw new GitHubError(
            502,
            'INVALID_GITHUB_RESPONSE',
            'Received unexpected repository metadata format from GitHub'
          );
        }
        return {
          status: 'ACCESSIBLE',
          repository: toPublicGitHubRepository(validated.data),
        };
      }

      const ghMessage = safeRedact(await readSafeErrorMessage(response), installationToken);
      if (isRateLimitResponse(response.status, response.headers, ghMessage)) {
        const retryAfterSeconds = parseRetryAfterSeconds(response.headers, now().getTime());
        throw new GitHubError(
          429,
          'GITHUB_RATE_LIMITED',
          'GitHub API rate limit exceeded; please retry shortly',
          { retryAfterSeconds }
        );
      }

      if (response.status === 401) {
        throw new GitHubError(
          502,
          'GITHUB_AUTH_FAILED',
          'GitHub authentication failed while verifying repository state'
        );
      }

      if (response.status === 403) {
        return { status: 'ACCESS_REVOKED' };
      }

      if (response.status === 410) {
        return { status: 'GONE' };
      }

      if (response.status === 404) {
        return { status: 'NOT_FOUND' };
      }

      throw new GitHubError(
        502,
        'GITHUB_API_ERROR',
        'Unexpected error response received from GitHub'
      );
    },
  };
}
