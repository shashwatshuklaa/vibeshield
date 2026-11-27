import { createHash, createHmac } from 'node:crypto';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import {
  computeConnectionIsActive,
  getEffectiveConnectionStatus,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  IntegrationAuditActorTypeValue,
  isInstallationActiveStatus,
  redactGitHubSecrets,
  RepositoryAccessStateValue,
  WebhookDeliveryOutcomeValue,
  type GitHubAccountType,
  type GitHubInstallationStatus,
  type GitHubRepositorySelection,
  type InstallationAvailability,
  type IntegrationAuditAction,
  type RepositoryAccessState,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import type { GitHubRuntimeConfig } from '../config/env.js';
import type { PublicGitHubInstallation } from '../modules/github/github.types.js';
import type { PublicProjectRepositoryConnection } from '../modules/github/github-connection.types.js';
import { createGitHubWebhookService } from '../modules/github/github-webhook.service.js';
import type {
  ClaimWebhookDeliveryResult,
  GitHubWebhookStore,
} from '../modules/github/github-webhook.store.js';
import type { WebhookDeliveryRecord } from '../modules/github/github-webhook.types.js';
import { verifyGitHubWebhookSignature } from '../modules/github/github-webhook.verifier.js';

const CURRENT_WEBHOOK_SECRET = 'whsec_current_webhook_secret_at_least_32_chars';
const PREVIOUS_WEBHOOK_SECRET = 'whsec_previous_webhook_secret_at_least_32_chars';

const TEST_WEBHOOK_CONFIG: Pick<
  GitHubRuntimeConfig,
  'webhookSecret' | 'previousWebhookSecret' | 'clientSecret' | 'privateKeyPem'
> = {
  webhookSecret: CURRENT_WEBHOOK_SECRET,
  previousWebhookSecret: PREVIOUS_WEBHOOK_SECRET,
  clientSecret: 'gh_client_secret_test_value_1234',
  privateKeyPem: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
};

const FULL_TEST_GITHUB_CONFIG: GitHubRuntimeConfig = {
  appId: 51515,
  appSlug: 'vibeshield-webhook-test',
  privateKeyPem: TEST_WEBHOOK_CONFIG.privateKeyPem,
  clientId: 'Iv1.webhooktest123',
  clientSecret: TEST_WEBHOOK_CONFIG.clientSecret,
  webhookSecret: CURRENT_WEBHOOK_SECRET,
  previousWebhookSecret: PREVIOUS_WEBHOOK_SECRET,
  callbackUrl: 'http://localhost:5173/integrations/github/callback',
};

function makeObjectId(counter: number): string {
  return counter.toString(16).padStart(24, '0');
}

function signPayload(rawBody: Buffer | string, secret: string): string {
  const buf = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody;
  return `sha256=${createHmac('sha256', secret).update(buf).digest('hex')}`;
}

function createInMemoryWebhookHarness(
  options: {
    config?: GitHubRuntimeConfig | null;
    webhookBodyLimit?: string;
    nowRef?: { current: Date };
    failOnAudit?: { enabled: boolean };
  } = {}
) {
  let idCounter = 1;
  const nowRef = options.nowRef ?? { current: new Date('2026-11-27T12:00:00Z') };
  const failOnAudit = options.failOnAudit ?? { enabled: false };

  const orgs = new Set<string>();
  const installations = new Map<string, PublicGitHubInstallation & { isActive: boolean }>();
  const connections = new Map<string, PublicProjectRepositoryConnection>();
  const deliveries = new Map<string, WebhookDeliveryRecord>();
  const auditLogs: Array<{
    organizationId: string;
    projectId: string | null;
    actorType: string;
    actorUserId: string | null;
    action: IntegrationAuditAction;
    githubInstallationId: number | null;
    githubRepositoryId: number | null;
    metadata: Record<string, unknown>;
  }> = [];

  const store: GitHubWebhookStore = {
    async withTransaction(work) {
      // Snapshot rollback simulation for unit tests
      const instSnapshot = new Map(
        Array.from(installations.entries()).map(([k, v]) => [k, { ...v }])
      );
      const connSnapshot = new Map(
        Array.from(connections.entries()).map(([k, v]) => [k, { ...v }])
      );
      const delSnapshot = new Map(
        Array.from(deliveries.entries()).map(([k, v]) => [
          k,
          {
            ...v,
            targetOrganizationIds: [...v.targetOrganizationIds],
            completedOrganizationIds: [...v.completedOrganizationIds],
          },
        ])
      );
      const auditLen = auditLogs.length;

      try {
        return await work({});
      } catch (err) {
        installations.clear();
        for (const [k, v] of instSnapshot.entries()) installations.set(k, v);
        connections.clear();
        for (const [k, v] of connSnapshot.entries()) connections.set(k, v);
        deliveries.clear();
        for (const [k, v] of delSnapshot.entries()) deliveries.set(k, v);
        auditLogs.length = auditLen;
        throw err;
      }
    },
    async acquireOrganizationLock(organizationId) {
      return orgs.has(organizationId);
    },
    async claimDelivery(input): Promise<ClaimWebhookDeliveryResult> {
      const existing = deliveries.get(input.deliveryId);
      if (!existing) {
        const rec: WebhookDeliveryRecord = {
          id: makeObjectId(idCounter++),
          deliveryId: input.deliveryId,
          event: input.event,
          action: input.action,
          githubInstallationId: input.githubInstallationId,
          payloadSha256: input.payloadSha256,
          outcome: WebhookDeliveryOutcomeValue.PROCESSING,
          outcomeReason: null,
          errorCode: null,
          errorMessage: null,
          attemptCount: 1,
          targetOrganizationIds: [],
          completedOrganizationIds: [],
          processedConnectionCount: 0,
          processingStartedAt: input.now,
          processedAt: null,
          failedAt: null,
          receivedAt: input.now,
          expiresAt: input.expiresAt,
        };
        deliveries.set(input.deliveryId, rec);
        return { state: 'CLAIMED', delivery: { ...rec } };
      }

      if (
        existing.outcome === WebhookDeliveryOutcomeValue.PROCESSED ||
        existing.outcome === WebhookDeliveryOutcomeValue.IGNORED
      ) {
        return {
          state: 'DUPLICATE_COMPLETED',
          delivery: { ...existing },
          outcome: existing.outcome,
        };
      }

      if (existing.payloadSha256 !== input.payloadSha256) {
        return { state: 'PAYLOAD_MISMATCH', delivery: { ...existing } };
      }

      const canRetry =
        existing.outcome === WebhookDeliveryOutcomeValue.FAILED ||
        (existing.outcome === WebhookDeliveryOutcomeValue.PROCESSING &&
          existing.processingStartedAt !== null &&
          existing.processingStartedAt.getTime() <= input.staleLeaseBefore.getTime());

      if (canRetry) {
        existing.outcome = WebhookDeliveryOutcomeValue.PROCESSING;
        existing.processingStartedAt = input.now;
        existing.outcomeReason = null;
        existing.attemptCount += 1;
        return {
          state: 'CLAIMED',
          delivery: {
            ...existing,
            targetOrganizationIds: [...existing.targetOrganizationIds],
            completedOrganizationIds: [...existing.completedOrganizationIds],
          },
        };
      }

      return { state: 'IN_FLIGHT', delivery: { ...existing } };
    },
    async getDeliveryByDeliveryId(deliveryId) {
      const d = deliveries.get(deliveryId);
      return d
        ? {
            ...d,
            targetOrganizationIds: [...d.targetOrganizationIds],
            completedOrganizationIds: [...d.completedOrganizationIds],
          }
        : null;
    },
    async setDeliveryTargetOrganizations(input) {
      const d = deliveries.get(input.deliveryId);
      if (
        !d ||
        d.outcome !== WebhookDeliveryOutcomeValue.PROCESSING ||
        d.attemptCount !== input.attemptCount
      ) {
        return null;
      }
      if (d.targetOrganizationIds.length === 0) {
        d.targetOrganizationIds = Array.from(new Set(input.targetOrganizationIds));
      }
      return {
        ...d,
        targetOrganizationIds: [...d.targetOrganizationIds],
        completedOrganizationIds: [...d.completedOrganizationIds],
      };
    },
    async recordOrganizationProgress(input) {
      const d = deliveries.get(input.deliveryId);
      if (
        !d ||
        d.outcome !== WebhookDeliveryOutcomeValue.PROCESSING ||
        d.attemptCount !== input.attemptCount ||
        d.completedOrganizationIds.includes(input.organizationId)
      ) {
        return null;
      }
      d.completedOrganizationIds.push(input.organizationId);
      d.processedConnectionCount += Math.max(0, input.processedConnectionsDelta);
      return {
        ...d,
        targetOrganizationIds: [...d.targetOrganizationIds],
        completedOrganizationIds: [...d.completedOrganizationIds],
      };
    },
    async completeDelivery(input) {
      const d = deliveries.get(input.deliveryId);
      if (
        !d ||
        d.outcome !== WebhookDeliveryOutcomeValue.PROCESSING ||
        d.attemptCount !== input.attemptCount
      ) {
        return null;
      }
      d.outcome = input.outcome;
      d.outcomeReason = input.outcomeReason;
      if (input.githubInstallationId !== undefined) {
        d.githubInstallationId = input.githubInstallationId;
      }
      d.processedAt = input.now;
      d.errorCode = null;
      d.errorMessage = null;
      d.failedAt = null;
      return { ...d };
    },
    async failDelivery(input) {
      const d = deliveries.get(input.deliveryId);
      if (!d || d.attemptCount !== input.attemptCount) {
        return null;
      }
      d.outcome = WebhookDeliveryOutcomeValue.FAILED;
      d.errorCode = input.errorCode;
      d.errorMessage = redactGitHubSecrets(input.errorMessage).slice(0, 500);
      d.failedAt = input.now;
      return { ...d };
    },
    async findActiveInstallationByGitHubId(githubInstallationId) {
      for (const inst of installations.values()) {
        if (inst.githubInstallationId === githubInstallationId && inst.isActive) {
          return { ...inst };
        }
      }
      return null;
    },
    async updateInstallationByIdInOrganization(organizationId, installationRecordId, updates) {
      const inst = installations.get(installationRecordId);
      if (!inst || inst.organizationId !== organizationId) {
        return null;
      }
      if (updates.accountId !== undefined) inst.accountId = updates.accountId;
      if (updates.accountLogin !== undefined) inst.accountLogin = updates.accountLogin;
      if (updates.accountType !== undefined) inst.accountType = updates.accountType;
      if (updates.repositorySelection !== undefined) {
        inst.repositorySelection = updates.repositorySelection;
      }
      if (updates.grantedPermissions !== undefined) {
        inst.grantedPermissions = { ...updates.grantedPermissions };
      }
      inst.status = updates.status;
      inst.isActive = isInstallationActiveStatus(updates.status);
      inst.suspendedAt = updates.suspendedAt;
      inst.revokedAt = updates.revokedAt;
      inst.lastSyncedAt = updates.lastSyncedAt;
      inst.updatedAt = nowRef.current;
      return { ...inst };
    },
    async updateConnectionsAvailabilityForInstallation(input) {
      const updated: PublicProjectRepositoryConnection[] = [];
      for (const conn of connections.values()) {
        if (
          conn.organizationId === input.organizationId &&
          conn.installationRecordId === input.installationRecordId &&
          conn.isActive
        ) {
          conn.installationAvailability = input.installationAvailability;
          if (conn.repositoryAccessState === RepositoryAccessStateValue.CONNECTED) {
            conn.statusReason = input.reasonForConnected;
          }
          conn.isActive = computeConnectionIsActive(
            conn.repositoryAccessState,
            input.installationAvailability
          );
          conn.effectiveStatus = getEffectiveConnectionStatus({
            repositoryAccessState: conn.repositoryAccessState,
            installationAvailability: conn.installationAvailability,
          });
          conn.lastSyncedAt = input.now;
          conn.lastWebhookAt = input.now;
          updated.push({ ...conn });
        }
      }
      return updated;
    },
    async listActiveConnectionsByInstallationAndRepoIds(
      organizationId,
      installationRecordId,
      githubRepositoryIds
    ) {
      const set = new Set(githubRepositoryIds);
      return Array.from(connections.values())
        .filter(
          (c) =>
            c.organizationId === organizationId &&
            c.installationRecordId === installationRecordId &&
            set.has(c.githubRepositoryId) &&
            c.isActive
        )
        .map((c) => ({ ...c }));
    },
    async findDistinctOrganizationIdsByActiveRepositoryId(githubRepositoryId) {
      const set = new Set<string>();
      for (const conn of connections.values()) {
        if (conn.githubRepositoryId === githubRepositoryId && conn.isActive) {
          set.add(conn.organizationId);
        }
      }
      return Array.from(set);
    },
    async listActiveConnectionsByOrgAndRepoId(organizationId, githubRepositoryId) {
      return Array.from(connections.values())
        .filter(
          (c) =>
            c.organizationId === organizationId &&
            c.githubRepositoryId === githubRepositoryId &&
            c.isActive
        )
        .map((c) => ({ ...c }));
    },
    async updateConnectionByIdInOrganization(organizationId, connectionId, updates) {
      const conn = connections.get(connectionId);
      if (!conn || conn.organizationId !== organizationId) {
        return null;
      }
      if (updates.ownerLogin !== undefined) conn.ownerLogin = updates.ownerLogin;
      if (updates.repoName !== undefined) conn.repoName = updates.repoName;
      if (updates.fullName !== undefined) conn.fullName = updates.fullName;
      if (updates.htmlUrl !== undefined) conn.htmlUrl = updates.htmlUrl;
      if (updates.defaultBranch !== undefined) conn.defaultBranch = updates.defaultBranch;
      if (updates.isPrivate !== undefined) conn.isPrivate = updates.isPrivate;
      if (updates.isArchivedOnGitHub !== undefined) {
        conn.isArchivedOnGitHub = updates.isArchivedOnGitHub;
      }
      conn.repositoryAccessState = updates.repositoryAccessState;
      conn.installationAvailability = updates.installationAvailability;
      conn.statusReason = updates.statusReason;
      conn.isActive = computeConnectionIsActive(
        updates.repositoryAccessState,
        updates.installationAvailability
      );
      conn.effectiveStatus = getEffectiveConnectionStatus({
        repositoryAccessState: updates.repositoryAccessState,
        installationAvailability: updates.installationAvailability,
      });
      conn.lastSyncedAt = updates.lastSyncedAt;
      conn.lastWebhookAt = updates.lastWebhookAt;
      return { ...conn };
    },
    async createAuditLog(input) {
      if (failOnAudit.enabled) {
        throw new Error(
          `Audit failed with secret ${CURRENT_WEBHOOK_SECRET} and token ghs_sensitive_token_123456`
        );
      }
      auditLogs.push({
        organizationId: input.organizationId,
        projectId: input.projectId ?? null,
        actorType: IntegrationAuditActorTypeValue.GITHUB_WEBHOOK,
        actorUserId: null,
        action: input.action,
        githubInstallationId: input.githubInstallationId ?? null,
        githubRepositoryId: input.githubRepositoryId ?? null,
        metadata: input.metadata ?? {},
      });
    },
  };

  const resolvedConfig = options.config === undefined ? FULL_TEST_GITHUB_CONFIG : options.config;

  const webhookService = createGitHubWebhookService({
    config: resolvedConfig,
    store,
    now: () => nowRef.current,
  });

  const app = createApp({
    githubConfig: resolvedConfig,
    webhookService,
    webhookBodyLimit: options.webhookBodyLimit,
  });

  function seedInstallation(input: {
    organizationId: string;
    githubInstallationId: number;
    accountLogin?: string;
    accountType?: GitHubAccountType;
    repositorySelection?: GitHubRepositorySelection;
    status?: GitHubInstallationStatus;
    suspendedAt?: Date | null;
    revokedAt?: Date | null;
  }) {
    orgs.add(input.organizationId);
    const id = makeObjectId(idCounter++);
    const status = input.status ?? GitHubInstallationStatusValue.ACTIVE;
    const rec: PublicGitHubInstallation & { isActive: boolean } = {
      id,
      organizationId: input.organizationId,
      githubInstallationId: input.githubInstallationId,
      githubAppId: FULL_TEST_GITHUB_CONFIG.appId,
      accountId: 900 + input.githubInstallationId,
      accountLogin: input.accountLogin ?? 'acme-sec',
      accountType: input.accountType ?? 'Organization',
      repositorySelection: input.repositorySelection ?? 'selected',
      grantedPermissions: { contents: 'read', metadata: 'read' },
      status,
      isActive: isInstallationActiveStatus(status),
      suspendedAt: input.suspendedAt ?? null,
      revokedAt: input.revokedAt ?? null,
      lastSyncedAt: nowRef.current,
      createdAt: nowRef.current,
      updatedAt: nowRef.current,
    };
    installations.set(id, rec);
    return rec;
  }

  function seedConnection(input: {
    organizationId: string;
    projectId: string;
    installationRecordId: string;
    githubInstallationId: number;
    githubRepositoryId: number;
    fullName?: string;
    repositoryAccessState?: RepositoryAccessState;
    installationAvailability?: InstallationAvailability;
    statusReason?: string | null;
  }) {
    orgs.add(input.organizationId);
    const fullName = input.fullName ?? 'acme-sec/core-api';
    const [ownerLogin, repoName] = fullName.split('/');
    const id = makeObjectId(idCounter++);
    const repositoryAccessState =
      input.repositoryAccessState ?? RepositoryAccessStateValue.CONNECTED;
    const installationAvailability =
      input.installationAvailability ?? InstallationAvailabilityValue.ACTIVE;
    const rec: PublicProjectRepositoryConnection = {
      id,
      organizationId: input.organizationId,
      projectId: input.projectId,
      installationRecordId: input.installationRecordId,
      githubInstallationId: input.githubInstallationId,
      githubRepositoryId: input.githubRepositoryId,
      ownerLogin: ownerLogin!,
      repoName: repoName!,
      fullName,
      htmlUrl: `https://github.com/${fullName}`,
      defaultBranch: 'main',
      isPrivate: true,
      isArchivedOnGitHub: false,
      repositoryAccessState,
      installationAvailability,
      effectiveStatus: getEffectiveConnectionStatus({
        repositoryAccessState,
        installationAvailability,
      }),
      statusReason: input.statusReason ?? null,
      isActive: computeConnectionIsActive(repositoryAccessState, installationAvailability),
      connectedByUserId: makeObjectId(8888),
      disconnectedByUserId: null,
      connectedAt: nowRef.current,
      disconnectedAt: null,
      lastSyncedAt: nowRef.current,
      lastWebhookAt: null,
      createdAt: nowRef.current,
      updatedAt: nowRef.current,
    };
    connections.set(id, rec);
    return rec;
  }

  return {
    app,
    orgs,
    installations,
    connections,
    deliveries,
    auditLogs,
    seedInstallation,
    seedConnection,
    failOnAudit,
    store,
  };
}

describe('GitHub Webhook Verification, Idempotency & Event Processing', () => {
  describe('Signature & Raw-Body Verification', () => {
    it('verifies current and previous rotation secrets using timingSafeEqual against exact raw bytes', () => {
      const rawBody = Buffer.from('{\n  "z": 1,\n  "a": "raw-whitespace"\n}', 'utf8');

      expect(
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: signPayload(rawBody, CURRENT_WEBHOOK_SECRET),
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toEqual({ matchedSecret: 'current' });

      expect(
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: signPayload(rawBody, PREVIOUS_WEBHOOK_SECRET),
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toEqual({ matchedSecret: 'previous' });

      // Fails if missing, wrong prefix, wrong length, wrong secret, or modified payload
      expect(() =>
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: undefined,
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toThrow(/signature/i);

      expect(() =>
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: `sha1=${createHash('sha1').update(rawBody).digest('hex')}`,
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toThrow(/signature/i);

      expect(() =>
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: 'sha256=deadbeef',
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toThrow(/signature/i);

      expect(() =>
        verifyGitHubWebhookSignature({
          rawBody: Buffer.from(`${rawBody.toString('utf8')} `, 'utf8'),
          signatureHeader: signPayload(rawBody, CURRENT_WEBHOOK_SECRET),
          config: TEST_WEBHOOK_CONFIG,
        })
      ).toThrow(/mismatch/i);

      expect(() =>
        verifyGitHubWebhookSignature({
          rawBody,
          signatureHeader: signPayload(rawBody, CURRENT_WEBHOOK_SECRET),
          config: null,
        })
      ).toThrow(/not configured/i);
    });

    it('verifies exact raw request bytes over HTTP without re-serializing JSON and preserves standard JSON routes', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgId = makeObjectId(100);
      const inst = harness.seedInstallation({
        organizationId: orgId,
        githubInstallationId: 2001,
      });

      // Exact wire body has extra whitespace & key order distinct from JSON.stringify(JSON.parse(...))
      const wireBody =
        '{  "action": "suspend",   "installation": { "id": 2001, "suspended_at": "2026-11-27T12:00:00Z" } }';
      const reserializedBody = JSON.stringify(JSON.parse(wireBody));
      expect(wireBody).not.toBe(reserializedBody);

      // Valid signature over wire bytes -> 200
      const okRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-raw-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(wireBody, PREVIOUS_WEBHOOK_SECRET))
        .send(wireBody);
      expect(okRes.status).toBe(200);
      expect(harness.installations.get(inst.id)?.status).toBe('SUSPENDED');

      // Signature computed over re-serialized JSON instead of wire bytes -> 401
      const badSigRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-raw-2')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(reserializedBody, CURRENT_WEBHOOK_SECRET))
        .send(wireBody);
      expect(badSigRes.status).toBe(401);
      expect(badSigRes.body.error.code).toBe('INVALID_WEBHOOK_SIGNATURE');

      // Missing headers / malformed JSON return 400
      const pingBody = '{"zen":"keep it awesome"}';
      const missingHeaderRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-Hub-Signature-256', signPayload(pingBody, CURRENT_WEBHOOK_SECRET))
        .send(pingBody);
      expect(missingHeaderRes.status).toBe(400);
      expect(missingHeaderRes.body.error.code).toBe('INVALID_WEBHOOK_HEADERS');

      const badJsonBody = '{not-json';
      const badJsonRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-bad-json')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(badJsonBody, CURRENT_WEBHOOK_SECRET))
        .send(badJsonBody);
      expect(badJsonRes.status).toBe(400);
      expect(badJsonRes.body.error.code).toBe('INVALID_WEBHOOK_PAYLOAD');

      // Standard health/JSON routes continue working untouched
      const healthRes = await request(harness.app).get('/api/v1/health/live');
      expect(healthRes.status).toBe(200);
    });

    it('returns 413 for oversized webhook payloads and 503 when GitHub webhooks are unconfigured', async () => {
      const tinyLimitHarness = createInMemoryWebhookHarness({ webhookBodyLimit: '64b' });
      const oversizedBody = JSON.stringify({ action: 'created', padding: 'A'.repeat(256) });

      const tooBigRes = await request(tinyLimitHarness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-oversized')
        .set('X-GitHub-Event', 'ping')
        .set('X-Hub-Signature-256', signPayload(oversizedBody, CURRENT_WEBHOOK_SECRET))
        .send(oversizedBody);
      expect(tooBigRes.status).toBe(413);

      const unconfiguredHarness = createInMemoryWebhookHarness({ config: null });
      const body = '{"action":"suspend","installation":{"id":1}}';
      const unconfRes = await request(unconfiguredHarness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-unconf')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(body, CURRENT_WEBHOOK_SECRET))
        .send(body);
      expect(unconfRes.status).toBe(503);
      expect(unconfRes.body.error.code).toBe('GITHUB_INTEGRATION_NOT_CONFIGURED');
    });
  });

  describe('Idempotency, Concurrent Duplicates & Failure Retry', () => {
    it('deduplicates sequential and concurrent deliveries, rolls back failed writes without false PROCESSED state, redacts error secrets, and supports retries', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgId = makeObjectId(200);
      const inst = harness.seedInstallation({
        organizationId: orgId,
        githubInstallationId: 3001,
      });

      const payload = JSON.stringify({
        action: 'suspend',
        installation: { id: 3001, suspended_at: '2026-11-27T12:00:00Z' },
      });
      const sig = signPayload(payload, CURRENT_WEBHOOK_SECRET);

      // 1. Concurrent duplicates: both return 200 and mutate/audit exactly once
      const [c1, c2] = await Promise.all([
        request(harness.app)
          .post('/api/v1/webhooks/github')
          .set('Content-Type', 'application/json')
          .set('X-GitHub-Delivery', 'deliv-concurrent-1')
          .set('X-GitHub-Event', 'installation')
          .set('X-Hub-Signature-256', sig)
          .send(payload),
        request(harness.app)
          .post('/api/v1/webhooks/github')
          .set('Content-Type', 'application/json')
          .set('X-GitHub-Delivery', 'deliv-concurrent-1')
          .set('X-GitHub-Event', 'installation')
          .set('X-Hub-Signature-256', sig)
          .send(payload),
      ]);

      expect(c1.status).toBe(200);
      expect(c2.status).toBe(200);
      expect([c1.body.duplicate, c2.body.duplicate].sort()).toEqual([false, true]);
      expect(harness.auditLogs).toHaveLength(1);
      expect(harness.deliveries.get('deliv-concurrent-1')?.outcome).toBe('PROCESSED');

      // 2. Failed delivery rolls back state and redacts secret material, then retry succeeds cleanly
      harness.failOnAudit.enabled = true;
      const unsuspendPayload = JSON.stringify({
        action: 'unsuspend',
        installation: { id: 3001, suspended_at: null },
      });
      const unsuspendSig = signPayload(unsuspendPayload, CURRENT_WEBHOOK_SECRET);

      const failedRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-retry-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', unsuspendSig)
        .send(unsuspendPayload);
      expect(failedRes.status).toBe(500);

      // Rolled back to SUSPENDED (not unsuspended!), delivery marked FAILED with redacted message
      expect(harness.installations.get(inst.id)?.status).toBe('SUSPENDED');
      const failedRecord = harness.deliveries.get('deliv-retry-1');
      expect(failedRecord?.outcome).toBe('FAILED');
      expect(failedRecord?.errorMessage).not.toContain(CURRENT_WEBHOOK_SECRET);
      expect(failedRecord?.errorMessage).not.toContain('ghs_sensitive_token_123456');

      // Retry with different payload for same failed deliveryId is rejected (409)
      const tamperedPayload = JSON.stringify({
        action: 'deleted',
        installation: { id: 3001 },
      });
      const mismatchRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-retry-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(tamperedPayload, CURRENT_WEBHOOK_SECRET))
        .send(tamperedPayload);
      expect(mismatchRes.status).toBe(409);

      // Retry with original payload after recovery succeeds
      harness.failOnAudit.enabled = false;
      const retryOk = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-retry-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', unsuspendSig)
        .send(unsuspendPayload);
      expect(retryOk.status).toBe(200);
      expect(retryOk.body.duplicate).toBe(false);
      expect(harness.installations.get(inst.id)?.status).toBe('ACTIVE');
      expect(harness.deliveries.get('deliv-retry-1')?.attemptCount).toBe(2);
    });
  });

  describe('Event Lifecycle & Multi-Tenant Isolation', () => {
    it('handles installation created/suspend/unsuspend/new_permissions/deleted safely without overwriting ACCESS_REVOKED or REPO_DELETED', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgId = makeObjectId(300);
      const projConnected = makeObjectId(301);
      const projRevoked = makeObjectId(302);
      const projDeleted = makeObjectId(303);

      // Unlinked installation.created ignores safely without fabricating org ownership
      const unlinkedBody = JSON.stringify({
        action: 'created',
        organizationId: makeObjectId(999),
        installation: {
          id: 99999,
          account: { id: 10, login: 'rogue', type: 'Organization' },
          repository_selection: 'all',
        },
      });
      const unlinkedRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-unlinked')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(unlinkedBody, CURRENT_WEBHOOK_SECRET))
        .send(unlinkedBody);
      expect(unlinkedRes.status).toBe(200);
      expect(unlinkedRes.body.outcome).toBe('IGNORED');
      expect(harness.installations.size).toBe(0);

      const inst = harness.seedInstallation({
        organizationId: orgId,
        githubInstallationId: 4001,
      });
      const cConn = harness.seedConnection({
        organizationId: orgId,
        projectId: projConnected,
        installationRecordId: inst.id,
        githubInstallationId: 4001,
        githubRepositoryId: 701,
      });
      const cRevoked = harness.seedConnection({
        organizationId: orgId,
        projectId: projRevoked,
        installationRecordId: inst.id,
        githubInstallationId: 4001,
        githubRepositoryId: 702,
        repositoryAccessState: RepositoryAccessStateValue.ACCESS_REVOKED,
        statusReason: 'Removed earlier',
      });
      const cDeleted = harness.seedConnection({
        organizationId: orgId,
        projectId: projDeleted,
        installationRecordId: inst.id,
        githubInstallationId: 4001,
        githubRepositoryId: 703,
        repositoryAccessState: RepositoryAccessStateValue.REPO_DELETED,
        statusReason: 'Deleted earlier',
      });

      // installation.new_permissions_accepted updates grantedPermissions safely
      const permBody = JSON.stringify({
        action: 'new_permissions_accepted',
        installation: {
          id: 4001,
          permissions: { contents: 'read', metadata: 'read', pull_requests: 'read' },
          repository_selection: 'all',
        },
      });
      const permRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-perm')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(permBody, CURRENT_WEBHOOK_SECRET))
        .send(permBody);
      expect(permRes.status).toBe(200);
      expect(harness.installations.get(inst.id)?.grantedPermissions).toEqual({
        contents: 'read',
        metadata: 'read',
        pull_requests: 'read',
      });

      // Suspend -> only installationAvailability changes; repositoryAccessState stays orthogonal
      const suspendBody = JSON.stringify({
        action: 'suspend',
        installation: { id: 4001, suspended_at: '2026-11-27T12:10:00Z' },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-susp')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(suspendBody, CURRENT_WEBHOOK_SECRET))
        .send(suspendBody);
      expect(harness.connections.get(cConn.id)?.effectiveStatus).toBe('INSTALLATION_SUSPENDED');
      expect(harness.connections.get(cRevoked.id)?.effectiveStatus).toBe('ACCESS_REVOKED');
      expect(harness.connections.get(cDeleted.id)?.effectiveStatus).toBe('REPO_DELETED');

      // Unsuspend -> restores cConn ONLY; cRevoked stays ACCESS_REVOKED and cDeleted stays REPO_DELETED
      const unsuspendBody = JSON.stringify({
        action: 'unsuspend',
        installation: { id: 4001, suspended_at: null },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-unsusp')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(unsuspendBody, CURRENT_WEBHOOK_SECRET))
        .send(unsuspendBody);
      expect(harness.connections.get(cConn.id)?.effectiveStatus).toBe('CONNECTED');
      expect(harness.connections.get(cRevoked.id)?.effectiveStatus).toBe('ACCESS_REVOKED');
      expect(harness.connections.get(cDeleted.id)?.effectiveStatus).toBe('REPO_DELETED');

      // Deleted -> revokes installation, and subsequent unsuspend CANNOT revive REVOKED installation
      const deleteInstBody = JSON.stringify({
        action: 'deleted',
        installation: { id: 4001 },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-del')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(deleteInstBody, CURRENT_WEBHOOK_SECRET))
        .send(deleteInstBody);
      expect(harness.installations.get(inst.id)?.status).toBe('REVOKED');
      expect(harness.installations.get(inst.id)?.isActive).toBe(false);
      expect(harness.connections.get(cConn.id)?.installationAvailability).toBe('REVOKED');
      expect(harness.connections.get(cConn.id)?.effectiveStatus).toBe('ACCESS_REVOKED');
      expect(harness.connections.get(cDeleted.id)?.effectiveStatus).toBe('REPO_DELETED');

      const reviveAttemptBody = JSON.stringify({
        action: 'unsuspend',
        installation: { id: 4001, suspended_at: null },
      });
      const reviveRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-inst-revive-attempt')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signPayload(reviveAttemptBody, CURRENT_WEBHOOK_SECRET))
        .send(reviveAttemptBody);
      expect(reviveRes.status).toBe(200);
      expect(reviveRes.body.outcome).toBe('IGNORED');
      expect(harness.installations.get(inst.id)?.status).toBe('REVOKED');
    });

    it('handles installation_repositories added/removed across multiple repos while preserving tenant isolation and installation availability', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgA = makeObjectId(400);
      const orgB = makeObjectId(401);
      const instA = harness.seedInstallation({
        organizationId: orgA,
        githubInstallationId: 5001,
        status: GitHubInstallationStatusValue.SUSPENDED,
        suspendedAt: new Date('2026-11-27T11:00:00Z'),
      });
      const instB = harness.seedInstallation({
        organizationId: orgB,
        githubInstallationId: 5002,
      });

      const connA1 = harness.seedConnection({
        organizationId: orgA,
        projectId: makeObjectId(410),
        installationRecordId: instA.id,
        githubInstallationId: 5001,
        githubRepositoryId: 801,
        installationAvailability: InstallationAvailabilityValue.SUSPENDED,
      });
      const connA2 = harness.seedConnection({
        organizationId: orgA,
        projectId: makeObjectId(411),
        installationRecordId: instA.id,
        githubInstallationId: 5001,
        githubRepositoryId: 802,
        repositoryAccessState: RepositoryAccessStateValue.ACCESS_REVOKED,
        installationAvailability: InstallationAvailabilityValue.SUSPENDED,
      });
      const connBShared = harness.seedConnection({
        organizationId: orgB,
        projectId: makeObjectId(412),
        installationRecordId: instB.id,
        githubInstallationId: 5002,
        githubRepositoryId: 801,
      });

      // Remove 801 on Org A -> marks ACCESS_REVOKED (not REPO_DELETED!), leaves Org B untouched!
      const removeBody = JSON.stringify({
        action: 'removed',
        repository_selection: 'selected',
        installation: { id: 5001 },
        repositories_removed: [
          { id: 801, name: 'core-api', full_name: 'acme-sec/core-api' },
          { id: 899, name: 'unconnected', full_name: 'acme-sec/unconnected' },
        ],
      });
      const removeRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-instrepo-rem')
        .set('X-GitHub-Event', 'installation_repositories')
        .set('X-Hub-Signature-256', signPayload(removeBody, CURRENT_WEBHOOK_SECRET))
        .send(removeBody);
      expect(removeRes.status).toBe(200);
      expect(harness.connections.get(connA1.id)?.repositoryAccessState).toBe('ACCESS_REVOKED');
      expect(harness.connections.get(connA1.id)?.installationAvailability).toBe('SUSPENDED');
      expect(harness.connections.get(connBShared.id)?.repositoryAccessState).toBe('CONNECTED');

      // Add 802 back on Org A -> restores repositoryAccessState to CONNECTED while keeping SUSPENDED installationAvailability
      const addBody = JSON.stringify({
        action: 'added',
        installation: { id: 5001 },
        repositories_added: [{ id: 802, name: 'web-ui', full_name: 'acme-sec/web-ui' }],
      });
      const addRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-instrepo-add')
        .set('X-GitHub-Event', 'installation_repositories')
        .set('X-Hub-Signature-256', signPayload(addBody, CURRENT_WEBHOOK_SECRET))
        .send(addBody);
      expect(addRes.status).toBe(200);
      expect(harness.connections.get(connA2.id)?.repositoryAccessState).toBe('CONNECTED');
      expect(harness.connections.get(connA2.id)?.installationAvailability).toBe('SUSPENDED');
      expect(harness.connections.get(connA2.id)?.effectiveStatus).toBe('INSTALLATION_SUSPENDED');
    });

    it('handles repository renamed, transferred, privatized, deleted, and unsupported events without letting payload overwrite ownership', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgId = makeObjectId(500);
      const projectId = makeObjectId(501);
      const foreignOrgId = makeObjectId(502);
      const foreignProjectId = makeObjectId(503);

      const inst = harness.seedInstallation({
        organizationId: orgId,
        githubInstallationId: 6001,
      });
      const conn = harness.seedConnection({
        organizationId: orgId,
        projectId,
        installationRecordId: inst.id,
        githubInstallationId: 6001,
        githubRepositoryId: 901,
        fullName: 'acme-sec/old-name',
      });

      // Rename with forged organizationId/projectId in payload -> must ignore forged IDs and preserve ownership
      const renameBody = JSON.stringify({
        action: 'renamed',
        organizationId: foreignOrgId,
        projectId: foreignProjectId,
        installation: { id: 6001 },
        repository: {
          id: 901,
          name: 'new-name',
          full_name: 'acme-sec/new-name',
          owner: { login: 'acme-sec' },
          private: false,
          default_branch: 'main',
        },
      });
      const renameRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-repo-rename')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', signPayload(renameBody, CURRENT_WEBHOOK_SECRET))
        .send(renameBody);
      expect(renameRes.status).toBe(200);
      expect(harness.connections.get(conn.id)).toMatchObject({
        organizationId: orgId,
        projectId,
        fullName: 'acme-sec/new-name',
        repoName: 'new-name',
      });

      // Transferred updates owner/fullName safely without creating cross-org records
      const transferBody = JSON.stringify({
        action: 'transferred',
        installation: { id: 6001 },
        repository: {
          id: 901,
          name: 'new-name',
          full_name: 'new-owner/new-name',
          owner: { login: 'new-owner' },
          private: false,
        },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-repo-transfer')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', signPayload(transferBody, CURRENT_WEBHOOK_SECRET))
        .send(transferBody);
      expect(harness.connections.get(conn.id)).toMatchObject({
        organizationId: orgId,
        projectId,
        ownerLogin: 'new-owner',
        fullName: 'new-owner/new-name',
      });
      expect(harness.connections.size).toBe(1);

      // Privatized sets isPrivate: true
      const privatizedBody = JSON.stringify({
        action: 'privatized',
        installation: { id: 6001 },
        repository: {
          id: 901,
          name: 'new-name',
          full_name: 'new-owner/new-name',
          owner: { login: 'new-owner' },
          private: true,
        },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-repo-priv')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', signPayload(privatizedBody, CURRENT_WEBHOOK_SECRET))
        .send(privatizedBody);
      expect(harness.connections.get(conn.id)?.isPrivate).toBe(true);

      // Deleted permanently sets REPO_DELETED
      const deletedBody = JSON.stringify({
        action: 'deleted',
        installation: { id: 6001 },
        repository: {
          id: 901,
          name: 'new-name',
          full_name: 'new-owner/new-name',
          owner: { login: 'new-owner' },
          private: true,
        },
      });
      await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-repo-del')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', signPayload(deletedBody, CURRENT_WEBHOOK_SECRET))
        .send(deletedBody);
      expect(harness.connections.get(conn.id)?.repositoryAccessState).toBe('REPO_DELETED');
      expect(harness.connections.get(conn.id)?.effectiveStatus).toBe('REPO_DELETED');

      // Unsupported event returns 200 and records IGNORED delivery
      const pushBody = JSON.stringify({ ref: 'refs/heads/main' });
      const pushRes = await request(harness.app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'deliv-unsupported-push')
        .set('X-GitHub-Event', 'push')
        .set('X-Hub-Signature-256', signPayload(pushBody, CURRENT_WEBHOOK_SECRET))
        .send(pushBody);
      expect(pushRes.status).toBe(200);
      expect(pushRes.body.outcome).toBe('IGNORED');
      expect(harness.deliveries.get('deliv-unsupported-push')?.outcome).toBe('IGNORED');
    });

    it('persists per-org progress across partial multi-org failures, preserves prior failure details on retry, and never duplicates completed org audits', async () => {
      const harness = createInMemoryWebhookHarness();
      const orgA = makeObjectId(700);
      const orgB = makeObjectId(701);
      const orgC = makeObjectId(702);

      const instA = harness.seedInstallation({ organizationId: orgA, githubInstallationId: 7101 });
      const instB = harness.seedInstallation({ organizationId: orgB, githubInstallationId: 7102 });
      const instC = harness.seedInstallation({ organizationId: orgC, githubInstallationId: 7103 });

      harness.seedConnection({
        organizationId: orgA,
        projectId: makeObjectId(710),
        installationRecordId: instA.id,
        githubInstallationId: 7101,
        githubRepositoryId: 99001,
        fullName: 'shared-org/original-name',
      });
      harness.seedConnection({
        organizationId: orgB,
        projectId: makeObjectId(711),
        installationRecordId: instB.id,
        githubInstallationId: 7102,
        githubRepositoryId: 99001,
        fullName: 'shared-org/original-name',
      });
      harness.seedConnection({
        organizationId: orgC,
        projectId: makeObjectId(712),
        installationRecordId: instC.id,
        githubInstallationId: 7103,
        githubRepositoryId: 99001,
        fullName: 'shared-org/original-name',
      });

      let shouldFailOrgB = true;
      const baseCreateAudit = harness.store.createAuditLog;
      const partialFailStore: GitHubWebhookStore = {
        ...harness.store,
        async createAuditLog(input, tx) {
          if (shouldFailOrgB && input.organizationId === orgB) {
            throw new Error(`Simulated DB write error on orgB with ${CURRENT_WEBHOOK_SECRET}`);
          }
          return baseCreateAudit(input, tx);
        },
      };

      const partialService = createGitHubWebhookService({
        config: FULL_TEST_GITHUB_CONFIG,
        store: partialFailStore,
      });
      const partialApp = createApp({
        githubConfig: FULL_TEST_GITHUB_CONFIG,
        webhookService: partialService,
      });

      const renameBody = JSON.stringify({
        action: 'renamed',
        repository: {
          id: 99001,
          name: 'renamed-repo',
          full_name: 'shared-org/renamed-repo',
          owner: { login: 'shared-org' },
          private: true,
        },
      });
      const sig = signPayload(renameBody, CURRENT_WEBHOOK_SECRET);

      // Attempt 1: Org A commits, Org B fails & rolls back, Org C not yet run
      const attempt1 = await request(partialApp)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'multi-org-retry-unit-1')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', sig)
        .send(renameBody);
      expect(attempt1.status).toBe(500);

      const recAfterFail = harness.deliveries.get('multi-org-retry-unit-1');
      expect(recAfterFail?.outcome).toBe('FAILED');
      expect(recAfterFail?.completedOrganizationIds).toEqual([orgA]);
      expect(recAfterFail?.targetOrganizationIds).toEqual([orgA, orgB, orgC]);
      expect(recAfterFail?.errorCode).toBe('WEBHOOK_PROCESSING_ERROR');
      expect(recAfterFail?.errorMessage).not.toContain(CURRENT_WEBHOOK_SECRET);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgA)).toHaveLength(1);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgB)).toHaveLength(0);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgC)).toHaveLength(0);

      // Attempt 2: Org B succeeds; Org A is skipped (1 audit total), Org B + C each get 1 audit
      shouldFailOrgB = false;
      const attempt2 = await request(partialApp)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'multi-org-retry-unit-1')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', sig)
        .send(renameBody);
      expect(attempt2.status).toBe(200);
      expect(attempt2.body.outcome).toBe('PROCESSED');
      expect(attempt2.body.duplicate).toBe(false);

      const recAfterSuccess = harness.deliveries.get('multi-org-retry-unit-1');
      expect(recAfterSuccess?.outcome).toBe('PROCESSED');
      expect(recAfterSuccess?.completedOrganizationIds).toEqual([orgA, orgB, orgC]);
      expect(recAfterSuccess?.attemptCount).toBe(2);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgA)).toHaveLength(1);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgB)).toHaveLength(1);
      expect(harness.auditLogs.filter((a) => a.organizationId === orgC)).toHaveLength(1);

      // Attempt 3: completed duplicate returns 200 duplicate without touching any org
      const attempt3 = await request(partialApp)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'multi-org-retry-unit-1')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', sig)
        .send(renameBody);
      expect(attempt3.status).toBe(200);
      expect(attempt3.body.duplicate).toBe(true);
      expect(harness.auditLogs).toHaveLength(3);
    });
  });
});
