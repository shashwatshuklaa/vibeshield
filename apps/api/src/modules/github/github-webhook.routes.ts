import express, { Router } from 'express';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { createGitHubWebhookController } from './github-webhook.controller.js';
import { createGitHubWebhookService, type GitHubWebhookService } from './github-webhook.service.js';

export const DEFAULT_GITHUB_WEBHOOK_BODY_LIMIT = '1mb';

export interface GitHubWebhookRouterDependencies {
  webhookService?: GitHubWebhookService;
  githubConfig?: GitHubRuntimeConfig | null;
  webhookBodyLimit?: string;
}

/**
 * Creates the unauthenticated (HMAC-authenticated) GitHub webhook router mounted at
 * `${apiPrefix}/webhooks`. Uses `express.raw` scoped strictly to `/github` before global JSON parsing.
 */
export function createGitHubWebhookRouter(
  dependencies: GitHubWebhookRouterDependencies = {}
): Router {
  const router: Router = Router();
  const webhookService =
    dependencies.webhookService ??
    createGitHubWebhookService({ config: dependencies.githubConfig });
  const controller = createGitHubWebhookController(webhookService);
  const bodyLimit = dependencies.webhookBodyLimit ?? DEFAULT_GITHUB_WEBHOOK_BODY_LIMIT;

  router.post('/github', express.raw({ type: () => true, limit: bodyLimit }), controller.receive);

  return router;
}
