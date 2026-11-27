import type { NextFunction, Request, Response } from 'express';
import { GitHubError } from './github.types.js';
import type { GitHubWebhookService } from './github-webhook.service.js';

function resolveRawBodyBuffer(req: Request): Buffer {
  if (Buffer.isBuffer(req.body)) {
    return req.body;
  }

  // Express raw parser leaves `{}` when a POST request has an empty body stream
  const hasContentLength = req.headers['content-length'] !== undefined;
  const hasTransferEncoding = req.headers['transfer-encoding'] !== undefined;
  if (
    (!hasContentLength || req.headers['content-length'] === '0') &&
    !hasTransferEncoding &&
    req.body !== null &&
    typeof req.body === 'object' &&
    !Array.isArray(req.body) &&
    Object.keys(req.body as Record<string, unknown>).length === 0
  ) {
    return Buffer.alloc(0);
  }

  throw new GitHubError(
    500,
    'WEBHOOK_RAW_BODY_UNAVAILABLE',
    'Webhook endpoint requires exact raw request bytes before JSON parsing'
  );
}

/**
 * Creates the HTTP controller for receiving and acknowledging signed GitHub App webhooks.
 */
export function createGitHubWebhookController(webhookService: GitHubWebhookService) {
  return {
    async receive(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const rawBody = resolveRawBodyBuffer(req);
        const result = await webhookService.processWebhook({
          deliveryIdHeader: req.headers['x-github-delivery'],
          eventHeader: req.headers['x-github-event'],
          signatureHeader: req.headers['x-hub-signature-256'],
          rawBody,
        });
        res.status(200).json(result);
      } catch (error) {
        next(error);
      }
    },
  };
}
