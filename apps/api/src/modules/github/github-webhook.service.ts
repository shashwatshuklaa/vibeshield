import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  IntegrationAuditActionValue,
  isInstallationActiveStatus,
  isValidObjectId,
  redactGitHubSecrets,
  RepositoryAccessStateValue,
  WebhookDeliveryOutcomeValue,
} from '@vibeshield/database';
import type { GitHubRuntimeConfig } from '../../config/env.js';
import { GitHubError } from './github.types.js';
import {
  INSTALLATION_REPOSITORIES_SUPPORTED_ACTIONS,
  INSTALLATION_SUPPORTED_ACTIONS,
  installationRepositoriesWebhookPayloadSchema,
  installationWebhookPayloadSchema,
  REPOSITORY_SUPPORTED_ACTIONS,
  repositoryWebhookPayloadSchema,
  SUPPORTED_WEBHOOK_EVENTS,
  webhookHeadersSchema,
  type InstallationRepositoriesWebhookPayload,
  type InstallationWebhookPayload,
  type RepositoryWebhookPayload,
} from './github-webhook.schemas.js';
import {
  mongooseGitHubWebhookStore,
  type GitHubWebhookStore,
  type WebhookTransactionContext,
} from './github-webhook.store.js';
import type {
  GitHubWebhookProcessingResult,
  ProcessGitHubWebhookInput,
  WebhookDeliveryRecord,
} from './github-webhook.types.js';
import { verifyGitHubWebhookSignature } from './github-webhook.verifier.js';

const DEFAULT_DELIVERY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_PROCESSING_LEASE_MS = 60_000;
const DEFAULT_IN_FLIGHT_WAIT_MS = 2_500;
const IN_FLIGHT_POLL_INTERVAL_MS = 25;

export interface GitHubWebhookServiceDependencies {
  config?: Pick<
    GitHubRuntimeConfig,
    'webhookSecret' | 'previousWebhookSecret' | 'clientSecret' | 'privateKeyPem'
  > | null;
  store?: GitHubWebhookStore;
  now?: () => Date;
  deliveryTtlMs?: number;
  processingLeaseMs?: number;
  inFlightWaitMs?: number;
}

export interface GitHubWebhookService {
  processWebhook(input: ProcessGitHubWebhookInput): Promise<GitHubWebhookProcessingResult>;
}

function normalizeHeaderValue(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
}

function parseJsonObjectFromRawBody(rawBody: Buffer): Record<string, unknown> {
  if (rawBody.length === 0) {
    throw new GitHubError(400, 'INVALID_WEBHOOK_PAYLOAD', 'Webhook payload cannot be empty');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new GitHubError(400, 'INVALID_WEBHOOK_PAYLOAD', 'Webhook body is not valid JSON');
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new GitHubError(400, 'INVALID_WEBHOOK_PAYLOAD', 'Webhook payload must be a JSON object');
  }

  return parsed as Record<string, unknown>;
}

function extractSafeAction(rawPayload: Record<string, unknown>): string | null {
  return typeof rawPayload.action === 'string' && rawPayload.action.trim().length > 0
    ? rawPayload.action.trim().slice(0, 64)
    : null;
}

function extractSafeInstallationId(rawPayload: Record<string, unknown>): number | null {
  const inst = rawPayload.installation;
  if (inst && typeof inst === 'object' && !Array.isArray(inst)) {
    const id = (inst as Record<string, unknown>).id;
    if (typeof id === 'number' && Number.isSafeInteger(id) && id >= 1) {
      return id;
    }
  }
  return null;
}

function parseOptionalGitHubTimestamp(raw: string | null | undefined, fallback: Date): Date {
  if (!raw) {
    return fallback;
  }
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

function isSupportedEvent(event: string): event is (typeof SUPPORTED_WEBHOOK_EVENTS)[number] {
  return (SUPPORTED_WEBHOOK_EVENTS as readonly string[]).includes(event);
}

/**
 * Creates the service verifying GitHub webhook signatures, deduplicating deliveries via
 * `WebhookDeliveryModel`, validating strict Zod event schemas, and applying isolated
 * per-organization transactional updates.
 */
export function createGitHubWebhookService(
  dependencies: GitHubWebhookServiceDependencies = {}
): GitHubWebhookService {
  const store = dependencies.store ?? mongooseGitHubWebhookStore;
  const now = dependencies.now ?? (() => new Date());
  const config = dependencies.config ?? null;
  const deliveryTtlMs = dependencies.deliveryTtlMs ?? DEFAULT_DELIVERY_TTL_MS;
  const processingLeaseMs = dependencies.processingLeaseMs ?? DEFAULT_PROCESSING_LEASE_MS;
  const inFlightWaitMs = dependencies.inFlightWaitMs ?? DEFAULT_IN_FLIGHT_WAIT_MS;

  function sanitizeErrorText(raw: string): string {
    return redactGitHubSecrets(raw, [
      config?.webhookSecret,
      config?.previousWebhookSecret,
      config?.clientSecret,
      config?.privateKeyPem,
    ]).slice(0, 500);
  }

  async function completeWithFencingOrAbort(
    input: Parameters<GitHubWebhookStore['completeDelivery']>[0],
    tx?: WebhookTransactionContext
  ): Promise<WebhookDeliveryRecord> {
    const updated = await store.completeDelivery(input, tx);
    if (!updated) {
      throw new GitHubError(
        503,
        'WEBHOOK_DELIVERY_LEASE_LOST',
        'Webhook delivery lease was superseded or is no longer active; please retry'
      );
    }
    return updated;
  }

  async function waitForInFlightDelivery(
    deliveryId: string,
    event: string,
    action: string | null
  ): Promise<GitHubWebhookProcessingResult> {
    const deadline = Date.now() + inFlightWaitMs;
    while (Date.now() < deadline) {
      await delay(IN_FLIGHT_POLL_INTERVAL_MS);
      const latest = await store.getDeliveryByDeliveryId(deliveryId);
      if (!latest) {
        break;
      }
      if (
        latest.outcome === WebhookDeliveryOutcomeValue.PROCESSED ||
        latest.outcome === WebhookDeliveryOutcomeValue.IGNORED
      ) {
        return {
          deliveryId,
          event: latest.event || event,
          action: latest.action ?? action,
          outcome: latest.outcome,
          duplicate: true,
          ...(latest.outcomeReason ? { reason: latest.outcomeReason } : {}),
        };
      }
      if (latest.outcome === WebhookDeliveryOutcomeValue.FAILED) {
        throw new GitHubError(
          503,
          'WEBHOOK_DELIVERY_FAILED',
          'Previous concurrent webhook delivery attempt failed; please retry'
        );
      }
    }

    throw new GitHubError(
      503,
      'WEBHOOK_DELIVERY_IN_PROGRESS',
      'Webhook delivery is currently in progress; please retry'
    );
  }

  async function handleInstallationEvent(
    deliveryId: string,
    attemptCount: number,
    payload: InstallationWebhookPayload,
    eventTime: Date
  ): Promise<{
    outcome: 'PROCESSED' | 'IGNORED';
    reason: string;
  }> {
    const installationId = payload.installation.id;
    const action = payload.action;

    const existing = await store.findActiveInstallationByGitHubId(installationId);
    if (!existing) {
      const reason =
        action === 'created'
          ? 'Installation created event ignored because installation is not yet linked to an organization'
          : `Installation ${action} ignored because no active VibeShield installation exists`;
      await completeWithFencingOrAbort({
        deliveryId,
        attemptCount,
        outcome: WebhookDeliveryOutcomeValue.IGNORED,
        outcomeReason: reason,
        githubInstallationId: installationId,
        now: eventTime,
      });
      return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
    }

    const organizationId = existing.organizationId;

    return store.withTransaction(async (tx) => {
      const locked = await store.acquireOrganizationLock(organizationId, tx);
      if (!locked) {
        const reason = 'Target organization no longer exists';
        await completeWithFencingOrAbort(
          {
            deliveryId,
            attemptCount,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            outcomeReason: reason,
            githubInstallationId: installationId,
            now: eventTime,
          },
          tx
        );
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      const txInstallation = await store.findActiveInstallationByGitHubId(installationId, tx);
      if (
        !txInstallation ||
        txInstallation.organizationId !== organizationId ||
        !isInstallationActiveStatus(txInstallation.status)
      ) {
        const reason = `Installation ${action} ignored because installation is revoked or inactive`;
        await completeWithFencingOrAbort(
          {
            deliveryId,
            attemptCount,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            outcomeReason: reason,
            githubInstallationId: installationId,
            now: eventTime,
          },
          tx
        );
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      if (action === 'created') {
        const nextStatus =
          payload.installation.suspended_at !== null &&
          payload.installation.suspended_at !== undefined
            ? GitHubInstallationStatusValue.SUSPENDED
            : GitHubInstallationStatusValue.ACTIVE;
        const nextSuspendedAt =
          nextStatus === GitHubInstallationStatusValue.SUSPENDED
            ? parseOptionalGitHubTimestamp(payload.installation.suspended_at, eventTime)
            : null;
        const nextAvailability =
          nextStatus === GitHubInstallationStatusValue.SUSPENDED
            ? InstallationAvailabilityValue.SUSPENDED
            : InstallationAvailabilityValue.ACTIVE;

        await store.updateInstallationByIdInOrganization(
          organizationId,
          txInstallation.id,
          {
            ...(payload.installation.account
              ? {
                  accountId: payload.installation.account.id,
                  accountLogin: payload.installation.account.login,
                  accountType: payload.installation.account.type,
                }
              : {}),
            ...(payload.installation.repository_selection
              ? { repositorySelection: payload.installation.repository_selection }
              : {}),
            ...(payload.installation.permissions
              ? { grantedPermissions: payload.installation.permissions }
              : {}),
            status: nextStatus,
            isActive: true,
            suspendedAt: nextSuspendedAt,
            revokedAt: null,
            lastSyncedAt: eventTime,
          },
          tx
        );

        await store.updateConnectionsAvailabilityForInstallation(
          {
            organizationId,
            installationRecordId: txInstallation.id,
            installationAvailability: nextAvailability,
            reasonForConnected:
              nextAvailability === InstallationAvailabilityValue.SUSPENDED
                ? 'GitHub App installation is suspended on GitHub'
                : null,
            now: eventTime,
          },
          tx
        );

        await store.createAuditLog(
          {
            organizationId,
            action:
              nextStatus === GitHubInstallationStatusValue.SUSPENDED
                ? IntegrationAuditActionValue.INSTALLATION_SUSPENDED
                : IntegrationAuditActionValue.INSTALLATION_CONNECTED,
            githubInstallationId: installationId,
            metadata: {
              deliveryId,
              event: 'installation',
              action,
              reconciled: true,
            },
          },
          tx
        );
      } else if (action === 'suspend') {
        const suspendedAt = parseOptionalGitHubTimestamp(
          payload.installation.suspended_at,
          eventTime
        );
        await store.updateInstallationByIdInOrganization(
          organizationId,
          txInstallation.id,
          {
            status: GitHubInstallationStatusValue.SUSPENDED,
            isActive: true,
            suspendedAt,
            revokedAt: null,
            lastSyncedAt: eventTime,
          },
          tx
        );

        const updatedConnections = await store.updateConnectionsAvailabilityForInstallation(
          {
            organizationId,
            installationRecordId: txInstallation.id,
            installationAvailability: InstallationAvailabilityValue.SUSPENDED,
            reasonForConnected: 'GitHub App installation was suspended via webhook',
            now: eventTime,
          },
          tx
        );

        await store.createAuditLog(
          {
            organizationId,
            action: IntegrationAuditActionValue.INSTALLATION_SUSPENDED,
            githubInstallationId: installationId,
            metadata: {
              deliveryId,
              event: 'installation',
              action,
              affectedConnections: updatedConnections.length,
            },
          },
          tx
        );
      } else if (action === 'unsuspend') {
        await store.updateInstallationByIdInOrganization(
          organizationId,
          txInstallation.id,
          {
            status: GitHubInstallationStatusValue.ACTIVE,
            isActive: true,
            suspendedAt: null,
            revokedAt: null,
            lastSyncedAt: eventTime,
          },
          tx
        );

        // Preserve repositoryAccessState independently so ACCESS_REVOKED / REPO_DELETED are never overwritten
        const updatedConnections = await store.updateConnectionsAvailabilityForInstallation(
          {
            organizationId,
            installationRecordId: txInstallation.id,
            installationAvailability: InstallationAvailabilityValue.ACTIVE,
            reasonForConnected: null,
            now: eventTime,
          },
          tx
        );

        await store.createAuditLog(
          {
            organizationId,
            action: IntegrationAuditActionValue.INSTALLATION_UNSUSPENDED,
            githubInstallationId: installationId,
            metadata: {
              deliveryId,
              event: 'installation',
              action,
              affectedConnections: updatedConnections.length,
            },
          },
          tx
        );
      } else if (action === 'deleted') {
        await store.updateInstallationByIdInOrganization(
          organizationId,
          txInstallation.id,
          {
            status: GitHubInstallationStatusValue.REVOKED,
            isActive: false,
            suspendedAt: txInstallation.suspendedAt,
            revokedAt: eventTime,
            lastSyncedAt: eventTime,
          },
          tx
        );

        const updatedConnections = await store.updateConnectionsAvailabilityForInstallation(
          {
            organizationId,
            installationRecordId: txInstallation.id,
            installationAvailability: InstallationAvailabilityValue.REVOKED,
            reasonForConnected: 'GitHub App installation was deleted on GitHub',
            now: eventTime,
          },
          tx
        );

        await store.createAuditLog(
          {
            organizationId,
            action: IntegrationAuditActionValue.INSTALLATION_REVOKED,
            githubInstallationId: installationId,
            metadata: {
              deliveryId,
              event: 'installation',
              action,
              affectedConnections: updatedConnections.length,
            },
          },
          tx
        );
      } else if (action === 'new_permissions_accepted') {
        await store.updateInstallationByIdInOrganization(
          organizationId,
          txInstallation.id,
          {
            ...(payload.installation.repository_selection
              ? { repositorySelection: payload.installation.repository_selection }
              : {}),
            ...(payload.installation.permissions
              ? { grantedPermissions: payload.installation.permissions }
              : {}),
            status: txInstallation.status,
            isActive: true,
            suspendedAt: txInstallation.suspendedAt,
            revokedAt: txInstallation.revokedAt,
            lastSyncedAt: eventTime,
          },
          tx
        );

        await store.createAuditLog(
          {
            organizationId,
            action: IntegrationAuditActionValue.INSTALLATION_CONNECTED,
            githubInstallationId: installationId,
            metadata: {
              deliveryId,
              event: 'installation',
              action,
              permissionsUpdated: payload.installation.permissions !== undefined,
            },
          },
          tx
        );
      }

      const reason = `Processed installation.${action}`;
      await completeWithFencingOrAbort(
        {
          deliveryId,
          attemptCount,
          outcome: WebhookDeliveryOutcomeValue.PROCESSED,
          outcomeReason: reason,
          githubInstallationId: installationId,
          now: eventTime,
        },
        tx
      );
      return { outcome: WebhookDeliveryOutcomeValue.PROCESSED, reason };
    });
  }

  async function handleInstallationRepositoriesEvent(
    deliveryId: string,
    attemptCount: number,
    payload: InstallationRepositoriesWebhookPayload,
    eventTime: Date
  ): Promise<{ outcome: 'PROCESSED' | 'IGNORED'; reason: string }> {
    const installationId = payload.installation.id;
    const action = payload.action;

    const existing = await store.findActiveInstallationByGitHubId(installationId);
    if (!existing) {
      const reason = `installation_repositories.${action} ignored because no active VibeShield installation exists`;
      await completeWithFencingOrAbort({
        deliveryId,
        attemptCount,
        outcome: WebhookDeliveryOutcomeValue.IGNORED,
        outcomeReason: reason,
        githubInstallationId: installationId,
        now: eventTime,
      });
      return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
    }

    const organizationId = existing.organizationId;

    return store.withTransaction(async (tx) => {
      const locked = await store.acquireOrganizationLock(organizationId, tx);
      if (!locked) {
        const reason = 'Target organization no longer exists';
        await completeWithFencingOrAbort(
          {
            deliveryId,
            attemptCount,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            outcomeReason: reason,
            githubInstallationId: installationId,
            now: eventTime,
          },
          tx
        );
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      const txInstallation = await store.findActiveInstallationByGitHubId(installationId, tx);
      if (
        !txInstallation ||
        txInstallation.organizationId !== organizationId ||
        !isInstallationActiveStatus(txInstallation.status)
      ) {
        const reason = `installation_repositories.${action} ignored because installation is inactive`;
        await completeWithFencingOrAbort(
          {
            deliveryId,
            attemptCount,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            outcomeReason: reason,
            githubInstallationId: installationId,
            now: eventTime,
          },
          tx
        );
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      const nextRepoSelection =
        payload.repository_selection ?? payload.installation.repository_selection;

      await store.updateInstallationByIdInOrganization(
        organizationId,
        txInstallation.id,
        {
          ...(nextRepoSelection ? { repositorySelection: nextRepoSelection } : {}),
          status: txInstallation.status,
          isActive: true,
          suspendedAt: txInstallation.suspendedAt,
          revokedAt: txInstallation.revokedAt,
          lastSyncedAt: eventTime,
        },
        tx
      );

      if (action === 'added') {
        const addedById = new Map(payload.repositories_added.map((repo) => [repo.id, repo]));
        const repoIds = Array.from(addedById.keys());
        const connections = await store.listActiveConnectionsByInstallationAndRepoIds(
          organizationId,
          txInstallation.id,
          repoIds,
          tx
        );

        for (const conn of connections) {
          const addedMeta = addedById.get(conn.githubRepositoryId);
          // Never restore permanently deleted repositories via repository-addition events
          const nextAccessState =
            conn.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED
              ? RepositoryAccessStateValue.REPO_DELETED
              : RepositoryAccessStateValue.CONNECTED;
          const nextReason =
            nextAccessState === RepositoryAccessStateValue.CONNECTED ? null : conn.statusReason;

          let ownerLoginUpdate: string | undefined;
          let repoNameUpdate: string | undefined;
          let fullNameUpdate: string | undefined;
          if (addedMeta?.full_name) {
            const parts = addedMeta.full_name.split('/');
            if (parts.length === 2 && parts[0] && parts[1]) {
              ownerLoginUpdate = parts[0];
              repoNameUpdate = parts[1];
              fullNameUpdate = addedMeta.full_name;
            }
          }

          await store.updateConnectionByIdInOrganization(
            organizationId,
            conn.id,
            {
              ...(ownerLoginUpdate ? { ownerLogin: ownerLoginUpdate } : {}),
              ...(repoNameUpdate ? { repoName: repoNameUpdate } : {}),
              ...(fullNameUpdate ? { fullName: fullNameUpdate } : {}),
              ...(addedMeta?.private !== undefined ? { isPrivate: addedMeta.private } : {}),
              repositoryAccessState: nextAccessState,
              installationAvailability: conn.installationAvailability,
              statusReason: nextReason,
              lastSyncedAt: eventTime,
              lastWebhookAt: eventTime,
            },
            tx
          );

          await store.createAuditLog(
            {
              organizationId,
              projectId: conn.projectId,
              action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
              githubInstallationId: installationId,
              githubRepositoryId: conn.githubRepositoryId,
              metadata: {
                deliveryId,
                event: 'installation_repositories',
                action: 'added',
                fullName: fullNameUpdate ?? conn.fullName,
              },
            },
            tx
          );
        }

        if (connections.length === 0) {
          await store.createAuditLog(
            {
              organizationId,
              action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
              githubInstallationId: installationId,
              metadata: {
                deliveryId,
                event: 'installation_repositories',
                action: 'added',
                repositoryCount: repoIds.length,
                affectedConnections: 0,
              },
            },
            tx
          );
        }
      } else if (action === 'removed') {
        const repoIds = Array.from(new Set(payload.repositories_removed.map((repo) => repo.id)));
        const connections = await store.listActiveConnectionsByInstallationAndRepoIds(
          organizationId,
          txInstallation.id,
          repoIds,
          tx
        );

        for (const conn of connections) {
          // Removing access on installation is ACCESS_REVOKED, never permanently REPO_DELETED
          const nextAccessState =
            conn.repositoryAccessState === RepositoryAccessStateValue.REPO_DELETED
              ? RepositoryAccessStateValue.REPO_DELETED
              : RepositoryAccessStateValue.ACCESS_REVOKED;
          const nextReason =
            nextAccessState === RepositoryAccessStateValue.REPO_DELETED
              ? conn.statusReason
              : 'Repository access was removed from GitHub App installation';

          await store.updateConnectionByIdInOrganization(
            organizationId,
            conn.id,
            {
              repositoryAccessState: nextAccessState,
              installationAvailability: conn.installationAvailability,
              statusReason: nextReason,
              lastSyncedAt: eventTime,
              lastWebhookAt: eventTime,
            },
            tx
          );

          await store.createAuditLog(
            {
              organizationId,
              projectId: conn.projectId,
              action:
                nextAccessState === RepositoryAccessStateValue.REPO_DELETED
                  ? IntegrationAuditActionValue.REPOSITORY_DELETED
                  : IntegrationAuditActionValue.REPOSITORY_ACCESS_REVOKED,
              githubInstallationId: installationId,
              githubRepositoryId: conn.githubRepositoryId,
              metadata: {
                deliveryId,
                event: 'installation_repositories',
                action: 'removed',
                fullName: conn.fullName,
              },
            },
            tx
          );
        }

        if (connections.length === 0) {
          await store.createAuditLog(
            {
              organizationId,
              action: IntegrationAuditActionValue.REPOSITORY_ACCESS_REVOKED,
              githubInstallationId: installationId,
              metadata: {
                deliveryId,
                event: 'installation_repositories',
                action: 'removed',
                repositoryCount: repoIds.length,
                affectedConnections: 0,
              },
            },
            tx
          );
        }
      }

      const reason = `Processed installation_repositories.${action}`;
      await completeWithFencingOrAbort(
        {
          deliveryId,
          attemptCount,
          outcome: WebhookDeliveryOutcomeValue.PROCESSED,
          outcomeReason: reason,
          githubInstallationId: installationId,
          now: eventTime,
        },
        tx
      );
      return { outcome: WebhookDeliveryOutcomeValue.PROCESSED, reason };
    });
  }

  async function applyRepositoryUpdateInOrganization(input: {
    organizationId: string;
    installationRecordId: string | null;
    payload: RepositoryWebhookPayload;
    deliveryId: string;
    attemptCount: number;
    eventTime: Date;
    finalizeDeliveryInTx: boolean;
  }): Promise<{
    updatedCount: number;
    finalOutcome?: 'PROCESSED' | 'IGNORED';
    finalReason?: string;
  }> {
    return store.withTransaction(async (tx) => {
      const locked = await store.acquireOrganizationLock(input.organizationId, tx);
      let updatedCount = 0;

      if (locked) {
        const repoConnections = await store.listActiveConnectionsByOrgAndRepoId(
          input.organizationId,
          input.payload.repository.id,
          tx
        );
        const scopedConnections = input.installationRecordId
          ? repoConnections.filter((c) => c.installationRecordId === input.installationRecordId)
          : repoConnections;

        const repo = input.payload.repository;
        const htmlUrl = repo.html_url ?? `https://github.com/${repo.full_name}`;

        for (const conn of scopedConnections) {
          if (input.payload.action === 'deleted') {
            await store.updateConnectionByIdInOrganization(
              input.organizationId,
              conn.id,
              {
                repositoryAccessState: RepositoryAccessStateValue.REPO_DELETED,
                installationAvailability: conn.installationAvailability,
                statusReason: 'Repository was permanently deleted on GitHub',
                lastSyncedAt: input.eventTime,
                lastWebhookAt: input.eventTime,
              },
              tx
            );

            await store.createAuditLog(
              {
                organizationId: input.organizationId,
                projectId: conn.projectId,
                action: IntegrationAuditActionValue.REPOSITORY_DELETED,
                githubInstallationId: conn.githubInstallationId,
                githubRepositoryId: repo.id,
                metadata: {
                  deliveryId: input.deliveryId,
                  event: 'repository',
                  action: 'deleted',
                  fullName: conn.fullName,
                },
              },
              tx
            );
          } else {
            // Preserve organizationId, projectId, REPO_DELETED state, and installationAvailability
            await store.updateConnectionByIdInOrganization(
              input.organizationId,
              conn.id,
              {
                ownerLogin: repo.owner.login,
                repoName: repo.name,
                fullName: repo.full_name,
                htmlUrl,
                ...(repo.default_branch ? { defaultBranch: repo.default_branch } : {}),
                isPrivate: input.payload.action === 'privatized' ? true : repo.private,
                ...(repo.archived !== undefined ? { isArchivedOnGitHub: repo.archived } : {}),
                repositoryAccessState: conn.repositoryAccessState,
                installationAvailability: conn.installationAvailability,
                statusReason: conn.statusReason,
                lastSyncedAt: input.eventTime,
                lastWebhookAt: input.eventTime,
              },
              tx
            );

            await store.createAuditLog(
              {
                organizationId: input.organizationId,
                projectId: conn.projectId,
                action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
                githubInstallationId: conn.githubInstallationId,
                githubRepositoryId: repo.id,
                metadata: {
                  deliveryId: input.deliveryId,
                  event: 'repository',
                  action: input.payload.action,
                  previousFullName: conn.fullName,
                  fullName: repo.full_name,
                  isPrivate: input.payload.action === 'privatized' ? true : repo.private,
                },
              },
              tx
            );
          }
        }

        updatedCount = scopedConnections.length;
      }

      // Atomically persist this organization's completion alongside its state & audit mutations
      const progress = await store.recordOrganizationProgress(
        {
          deliveryId: input.deliveryId,
          attemptCount: input.attemptCount,
          organizationId: input.organizationId,
          processedConnectionsDelta: updatedCount,
        },
        tx
      );
      if (!progress) {
        throw new GitHubError(
          503,
          'WEBHOOK_DELIVERY_LEASE_LOST',
          'Webhook delivery progress update failed due to lost lease or duplicate org execution'
        );
      }

      if (input.finalizeDeliveryInTx) {
        if (progress.targetOrganizationIds.length > 0) {
          const completedSet = new Set(progress.completedOrganizationIds);
          const allTargetsCompleted = progress.targetOrganizationIds.every((id) =>
            completedSet.has(id)
          );
          if (!allTargetsCompleted) {
            throw new GitHubError(
              500,
              'WEBHOOK_PROGRESS_INCOMPLETE',
              'Cannot finalize webhook delivery before all target organizations complete'
            );
          }
        }

        const totalUpdated = progress.processedConnectionCount;
        const outcome =
          totalUpdated > 0
            ? WebhookDeliveryOutcomeValue.PROCESSED
            : WebhookDeliveryOutcomeValue.IGNORED;
        const reason =
          totalUpdated > 0
            ? progress.targetOrganizationIds.length > 1
              ? `Processed repository.${input.payload.action} across ${progress.targetOrganizationIds.length} organizations`
              : `Processed repository.${input.payload.action}`
            : `No active project connections matched repository.${input.payload.action}`;

        await completeWithFencingOrAbort(
          {
            deliveryId: input.deliveryId,
            attemptCount: input.attemptCount,
            outcome,
            outcomeReason: reason,
            githubInstallationId: input.payload.installation?.id ?? null,
            now: input.eventTime,
          },
          tx
        );

        return {
          updatedCount,
          finalOutcome: outcome,
          finalReason: reason,
        };
      }

      return { updatedCount };
    });
  }

  async function handleRepositoryEvent(
    delivery: WebhookDeliveryRecord,
    payload: RepositoryWebhookPayload,
    eventTime: Date
  ): Promise<{ outcome: 'PROCESSED' | 'IGNORED'; reason: string }> {
    const { deliveryId, attemptCount } = delivery;

    if (payload.installation?.id !== undefined) {
      const inst = await store.findActiveInstallationByGitHubId(payload.installation.id);
      if (!inst) {
        const reason = `repository.${payload.action} ignored because no active VibeShield installation exists`;
        await completeWithFencingOrAbort({
          deliveryId,
          attemptCount,
          outcome: WebhookDeliveryOutcomeValue.IGNORED,
          outcomeReason: reason,
          githubInstallationId: payload.installation.id,
          now: eventTime,
        });
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      const result = await applyRepositoryUpdateInOrganization({
        organizationId: inst.organizationId,
        installationRecordId: inst.id,
        payload,
        deliveryId,
        attemptCount,
        eventTime,
        finalizeDeliveryInTx: true,
      });

      return {
        outcome: result.finalOutcome ?? WebhookDeliveryOutcomeValue.IGNORED,
        reason:
          result.finalReason ??
          `No active project connections matched repository.${payload.action}`,
      };
    }

    // Installation omitted: resolve target organizations strictly from DB (never from payload),
    // persist durable target list, skip completed orgs on retry, and finalize only when all finish.
    let targetOrgIds = delivery.targetOrganizationIds.filter(isValidObjectId);
    if (targetOrgIds.length === 0) {
      const discoveredOrgIds = (
        await store.findDistinctOrganizationIdsByActiveRepositoryId(payload.repository.id)
      )
        .filter(isValidObjectId)
        .sort();

      if (discoveredOrgIds.length === 0) {
        const reason = `No active project connections matched repository.${payload.action}`;
        await completeWithFencingOrAbort({
          deliveryId,
          attemptCount,
          outcome: WebhookDeliveryOutcomeValue.IGNORED,
          outcomeReason: reason,
          githubInstallationId: null,
          now: eventTime,
        });
        return { outcome: WebhookDeliveryOutcomeValue.IGNORED, reason };
      }

      if (discoveredOrgIds.length === 1) {
        const singleResult = await applyRepositoryUpdateInOrganization({
          organizationId: discoveredOrgIds[0]!,
          installationRecordId: null,
          payload,
          deliveryId,
          attemptCount,
          eventTime,
          finalizeDeliveryInTx: true,
        });
        return {
          outcome: singleResult.finalOutcome ?? WebhookDeliveryOutcomeValue.IGNORED,
          reason:
            singleResult.finalReason ??
            `No active project connections matched repository.${payload.action}`,
        };
      }

      const updatedDelivery = await store.setDeliveryTargetOrganizations({
        deliveryId,
        attemptCount,
        targetOrganizationIds: discoveredOrgIds,
      });
      if (!updatedDelivery) {
        throw new GitHubError(
          503,
          'WEBHOOK_DELIVERY_LEASE_LOST',
          'Webhook delivery lease was superseded while persisting target organizations; please retry'
        );
      }
      targetOrgIds = updatedDelivery.targetOrganizationIds;
    }

    const completedSet = new Set(delivery.completedOrganizationIds);
    const pendingOrgIds = targetOrgIds.filter((id) => !completedSet.has(id));

    if (pendingOrgIds.length === 0) {
      const recoveredOutcome =
        delivery.processedConnectionCount > 0
          ? WebhookDeliveryOutcomeValue.PROCESSED
          : WebhookDeliveryOutcomeValue.IGNORED;
      const recoveredReason =
        delivery.processedConnectionCount > 0
          ? targetOrgIds.length > 1
            ? `Processed repository.${payload.action} across ${targetOrgIds.length} organizations`
            : `Processed repository.${payload.action}`
          : `No active project connections matched repository.${payload.action}`;

      await completeWithFencingOrAbort({
        deliveryId,
        attemptCount,
        outcome: recoveredOutcome,
        outcomeReason: recoveredReason,
        githubInstallationId: null,
        now: eventTime,
      });
      return { outcome: recoveredOutcome, reason: recoveredReason };
    }

    let finalOutcome: 'PROCESSED' | 'IGNORED' = WebhookDeliveryOutcomeValue.IGNORED;
    let finalReason = `No active project connections matched repository.${payload.action}`;

    for (let idx = 0; idx < pendingOrgIds.length; idx++) {
      const isLastPending = idx === pendingOrgIds.length - 1;
      const stepResult = await applyRepositoryUpdateInOrganization({
        organizationId: pendingOrgIds[idx]!,
        installationRecordId: null,
        payload,
        deliveryId,
        attemptCount,
        eventTime,
        finalizeDeliveryInTx: isLastPending,
      });
      if (isLastPending) {
        finalOutcome = stepResult.finalOutcome ?? WebhookDeliveryOutcomeValue.IGNORED;
        finalReason = stepResult.finalReason ?? finalReason;
      }
    }

    return { outcome: finalOutcome, reason: finalReason };
  }

  return {
    async processWebhook(input: ProcessGitHubWebhookInput): Promise<GitHubWebhookProcessingResult> {
      // 1. Authenticate exact raw bytes BEFORE trusting headers or parsing JSON
      verifyGitHubWebhookSignature({
        rawBody: input.rawBody,
        signatureHeader: normalizeHeaderValue(input.signatureHeader),
        config,
      });

      // 2. Validate required GitHub webhook delivery & event headers
      const headerValidation = webhookHeadersSchema.safeParse({
        deliveryId: normalizeHeaderValue(input.deliveryIdHeader),
        event: normalizeHeaderValue(input.eventHeader),
      });
      if (!headerValidation.success) {
        throw new GitHubError(
          400,
          'INVALID_WEBHOOK_HEADERS',
          'Missing or malformed required GitHub webhook headers'
        );
      }

      const { deliveryId, event } = headerValidation.data;
      const rawObject = parseJsonObjectFromRawBody(input.rawBody);
      const rawAction = extractSafeAction(rawObject);
      const rawInstallationId = extractSafeInstallationId(rawObject);
      const payloadSha256 = createHash('sha256').update(input.rawBody).digest('hex');

      // 3. Validate known event payloads strictly before claiming delivery ID
      let parsedInstallation: InstallationWebhookPayload | null = null;
      let parsedInstallationRepos: InstallationRepositoriesWebhookPayload | null = null;
      let parsedRepository: RepositoryWebhookPayload | null = null;

      if (event === 'installation') {
        const result = installationWebhookPayloadSchema.safeParse(rawObject);
        if (!result.success) {
          throw new GitHubError(
            400,
            'INVALID_WEBHOOK_PAYLOAD',
            'Invalid installation webhook payload'
          );
        }
        parsedInstallation = result.data;
      } else if (event === 'installation_repositories') {
        const result = installationRepositoriesWebhookPayloadSchema.safeParse(rawObject);
        if (!result.success) {
          throw new GitHubError(
            400,
            'INVALID_WEBHOOK_PAYLOAD',
            'Invalid installation_repositories webhook payload'
          );
        }
        parsedInstallationRepos = result.data;
      } else if (event === 'repository') {
        const result = repositoryWebhookPayloadSchema.safeParse(rawObject);
        if (!result.success) {
          throw new GitHubError(
            400,
            'INVALID_WEBHOOK_PAYLOAD',
            'Invalid repository webhook payload'
          );
        }
        parsedRepository = result.data;
      }

      // 4. Atomically claim idempotency slot
      const receivedAt = now();
      const claim = await store.claimDelivery({
        deliveryId,
        event,
        action: rawAction,
        githubInstallationId: rawInstallationId,
        payloadSha256,
        now: receivedAt,
        expiresAt: new Date(receivedAt.getTime() + deliveryTtlMs),
        staleLeaseBefore: new Date(receivedAt.getTime() - processingLeaseMs),
      });

      if (claim.state === 'DUPLICATE_COMPLETED') {
        return {
          deliveryId,
          event: claim.delivery.event,
          action: claim.delivery.action,
          outcome: claim.outcome,
          duplicate: true,
          ...(claim.delivery.outcomeReason ? { reason: claim.delivery.outcomeReason } : {}),
        };
      }

      if (claim.state === 'PAYLOAD_MISMATCH') {
        throw new GitHubError(
          409,
          'WEBHOOK_DELIVERY_PAYLOAD_MISMATCH',
          'Delivery ID was already recorded with a different payload digest'
        );
      }

      if (claim.state === 'IN_FLIGHT') {
        return waitForInFlightDelivery(deliveryId, event, rawAction);
      }

      const attemptCount = claim.delivery.attemptCount;

      try {
        // 5. Handle unsupported event names safely as IGNORED
        if (!isSupportedEvent(event)) {
          const reason = `Unsupported webhook event: ${event}`;
          await completeWithFencingOrAbort({
            deliveryId,
            attemptCount,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            outcomeReason: reason,
            githubInstallationId: rawInstallationId,
            now: now(),
          });
          return {
            deliveryId,
            event,
            action: rawAction,
            outcome: WebhookDeliveryOutcomeValue.IGNORED,
            duplicate: false,
            reason,
          };
        }

        const eventTime = now();

        if (event === 'installation' && parsedInstallation) {
          if (
            !(INSTALLATION_SUPPORTED_ACTIONS as readonly string[]).includes(
              parsedInstallation.action
            )
          ) {
            const reason = `Unsupported action ${parsedInstallation.action} for installation`;
            await completeWithFencingOrAbort({
              deliveryId,
              attemptCount,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              outcomeReason: reason,
              githubInstallationId: parsedInstallation.installation.id,
              now: eventTime,
            });
            return {
              deliveryId,
              event,
              action: parsedInstallation.action,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              duplicate: false,
              reason,
            };
          }

          const outcome = await handleInstallationEvent(
            deliveryId,
            attemptCount,
            parsedInstallation,
            eventTime
          );
          return {
            deliveryId,
            event,
            action: parsedInstallation.action,
            outcome: outcome.outcome,
            duplicate: false,
            reason: outcome.reason,
          };
        }

        if (event === 'installation_repositories' && parsedInstallationRepos) {
          if (
            !(INSTALLATION_REPOSITORIES_SUPPORTED_ACTIONS as readonly string[]).includes(
              parsedInstallationRepos.action
            )
          ) {
            const reason = `Unsupported action ${parsedInstallationRepos.action} for installation_repositories`;
            await completeWithFencingOrAbort({
              deliveryId,
              attemptCount,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              outcomeReason: reason,
              githubInstallationId: parsedInstallationRepos.installation.id,
              now: eventTime,
            });
            return {
              deliveryId,
              event,
              action: parsedInstallationRepos.action,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              duplicate: false,
              reason,
            };
          }

          const outcome = await handleInstallationRepositoriesEvent(
            deliveryId,
            attemptCount,
            parsedInstallationRepos,
            eventTime
          );
          return {
            deliveryId,
            event,
            action: parsedInstallationRepos.action,
            outcome: outcome.outcome,
            duplicate: false,
            reason: outcome.reason,
          };
        }

        if (event === 'repository' && parsedRepository) {
          if (
            !(REPOSITORY_SUPPORTED_ACTIONS as readonly string[]).includes(parsedRepository.action)
          ) {
            const reason = `Unsupported action ${parsedRepository.action} for repository`;
            await completeWithFencingOrAbort({
              deliveryId,
              attemptCount,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              outcomeReason: reason,
              githubInstallationId: parsedRepository.installation?.id ?? null,
              now: eventTime,
            });
            return {
              deliveryId,
              event,
              action: parsedRepository.action,
              outcome: WebhookDeliveryOutcomeValue.IGNORED,
              duplicate: false,
              reason,
            };
          }

          const outcome = await handleRepositoryEvent(claim.delivery, parsedRepository, eventTime);
          return {
            deliveryId,
            event,
            action: parsedRepository.action,
            outcome: outcome.outcome,
            duplicate: false,
            reason: outcome.reason,
          };
        }

        throw new GitHubError(400, 'INVALID_WEBHOOK_PAYLOAD', 'Unsupported webhook payload state');
      } catch (error) {
        const errorCode = error instanceof GitHubError ? error.code : 'WEBHOOK_PROCESSING_ERROR';
        const errorMessage = sanitizeErrorText(
          error instanceof Error ? error.message : 'Unexpected webhook processing failure'
        );

        try {
          await store.failDelivery({
            deliveryId,
            attemptCount,
            errorCode,
            errorMessage,
            now: now(),
          });
        } catch {
          // Best-effort failure recording; original error propagates so GitHub can retry
        }

        throw error;
      }
    },
  };
}
