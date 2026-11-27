import type { WebhookDeliveryOutcome } from '@vibeshield/database';

export interface ProcessGitHubWebhookInput {
  deliveryIdHeader: unknown;
  eventHeader: unknown;
  signatureHeader: unknown;
  rawBody: Buffer;
}

export interface GitHubWebhookProcessingResult {
  deliveryId: string;
  event: string;
  action: string | null;
  outcome: Extract<WebhookDeliveryOutcome, 'PROCESSED' | 'IGNORED'>;
  duplicate: boolean;
  reason?: string;
}

export interface WebhookDeliveryRecord {
  id: string;
  deliveryId: string;
  event: string;
  action: string | null;
  githubInstallationId: number | null;
  payloadSha256: string;
  outcome: WebhookDeliveryOutcome;
  outcomeReason: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  attemptCount: number;
  processingStartedAt: Date | null;
  processedAt: Date | null;
  failedAt: Date | null;
  receivedAt: Date;
  expiresAt: Date;
}
