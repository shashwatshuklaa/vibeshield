import { createHmac, timingSafeEqual } from 'node:crypto';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { GitHubError } from './github.types.js';

const SIGNATURE_HEADER_REGEX = /^sha256=([a-f0-9]{64})$/i;

function matchesHmacSha256(rawBody: Buffer, providedDigest: Buffer, secret: string): boolean {
  const expectedDigest = createHmac('sha256', secret).update(rawBody).digest();
  if (expectedDigest.length !== providedDigest.length) {
    return false;
  }
  return timingSafeEqual(expectedDigest, providedDigest);
}

/**
 * Verifies a GitHub webhook request's `X-Hub-Signature-256` HMAC-SHA256 signature against the
 * exact raw request bytes using `crypto.timingSafeEqual`. Supports dual-secret validation during
 * secret rotation when `previousWebhookSecret` is configured.
 */
export function verifyGitHubWebhookSignature(input: {
  rawBody: Buffer;
  signatureHeader: string | undefined;
  config: Pick<GitHubRuntimeConfig, 'webhookSecret' | 'previousWebhookSecret'> | null | undefined;
}): { matchedSecret: 'current' | 'previous' } {
  const { rawBody, signatureHeader, config } = input;

  if (!config || !config.webhookSecret) {
    throw new GitHubError(
      503,
      'GITHUB_INTEGRATION_NOT_CONFIGURED',
      'GitHub webhook receiver is not configured on this server'
    );
  }

  if (!Buffer.isBuffer(rawBody)) {
    throw new GitHubError(
      400,
      'INVALID_WEBHOOK_PAYLOAD',
      'Webhook request body must preserve raw request bytes'
    );
  }

  if (typeof signatureHeader !== 'string') {
    throw new GitHubError(
      401,
      'INVALID_WEBHOOK_SIGNATURE',
      'Missing or invalid GitHub webhook signature'
    );
  }

  const trimmed = signatureHeader.trim();
  const match = SIGNATURE_HEADER_REGEX.exec(trimmed);
  if (!match?.[1]) {
    throw new GitHubError(
      401,
      'INVALID_WEBHOOK_SIGNATURE',
      'Malformed GitHub webhook signature format'
    );
  }

  const providedDigest = Buffer.from(match[1], 'hex');
  if (providedDigest.length !== 32) {
    throw new GitHubError(
      401,
      'INVALID_WEBHOOK_SIGNATURE',
      'Invalid GitHub webhook signature length'
    );
  }

  const matchesCurrent = matchesHmacSha256(rawBody, providedDigest, config.webhookSecret);
  const matchesPrevious = config.previousWebhookSecret
    ? matchesHmacSha256(rawBody, providedDigest, config.previousWebhookSecret)
    : false;

  if (matchesCurrent) {
    return { matchedSecret: 'current' };
  }
  if (matchesPrevious) {
    return { matchedSecret: 'previous' };
  }

  throw new GitHubError(401, 'INVALID_WEBHOOK_SIGNATURE', 'GitHub webhook signature mismatch');
}
