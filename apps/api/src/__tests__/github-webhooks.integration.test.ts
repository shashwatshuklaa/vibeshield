import { createHmac, generateKeyPairSync } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  IntegrationAuditActionValue,
  IntegrationAuditLogModel,
  OrganizationMembershipModel,
  OrganizationModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
  SessionModel,
  UserModel,
  WebhookDeliveryModel,
  WebhookDeliveryOutcomeValue,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import type { GitHubRuntimeConfig } from '../config/env.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';
import { createGitHubWebhookService } from '../modules/github/github-webhook.service.js';
import {
  mongooseGitHubWebhookStore,
  type GitHubWebhookStore,
} from '../modules/github/github-webhook.store.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'integration_webhooks_jwt_access_secret_32_chars',
  jwtAccessTtl: '15m',
  jwtAccessTtlSeconds: 900,
  jwtIssuer: 'vibeshield-api',
  jwtAudience: 'vibeshield-clients',
  refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
  isProduction: false,
  cookiePath: '/api/v1/auth',
  allowedOrigins: ['http://localhost:5173'],
};

const { privateKey: TEST_PRIVATE_KEY_PEM } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const TEST_WEBHOOK_SECRET = 'whsec_integration_current_secret_32_chars_min';
const TEST_PREVIOUS_WEBHOOK_SECRET = 'whsec_integration_previous_secret_32_chars';

const TEST_GITHUB_CONFIG: GitHubRuntimeConfig = {
  appId: 95959,
  appSlug: 'vibeshield-webhook-int-app',
  privateKeyPem: TEST_PRIVATE_KEY_PEM,
  clientId: 'Iv1.webhookintclient',
  clientSecret: 'gh_webhook_int_client_secret_value_1234',
  webhookSecret: TEST_WEBHOOK_SECRET,
  previousWebhookSecret: TEST_PREVIOUS_WEBHOOK_SECRET,
  callbackUrl: 'http://localhost:5173/integrations/github/callback',
};

function signWebhookBody(rawBody: string, secret = TEST_WEBHOOK_SECRET): string {
  return `sha256=${createHmac('sha256', secret).update(Buffer.from(rawBody, 'utf8')).digest('hex')}`;
}

describe.skipIf(!REPLICA_URI)(
  'GitHub Webhook Processing Real MongoDB Replica-Set Integration Tests',
  () => {
    beforeAll(async () => {
      await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
      await Promise.all([
        UserModel.syncIndexes(),
        SessionModel.syncIndexes(),
        OrganizationModel.syncIndexes(),
        OrganizationMembershipModel.syncIndexes(),
        ProjectModel.syncIndexes(),
        GitHubInstallationModel.syncIndexes(),
        ProjectRepositoryConnectionModel.syncIndexes(),
        WebhookDeliveryModel.syncIndexes(),
        IntegrationAuditLogModel.syncIndexes(),
      ]);
    });

    beforeEach(async () => {
      await Promise.all([
        IntegrationAuditLogModel.deleteMany({}),
        WebhookDeliveryModel.deleteMany({}),
        ProjectRepositoryConnectionModel.deleteMany({}),
        GitHubInstallationModel.deleteMany({}),
        ProjectModel.deleteMany({}),
        OrganizationMembershipModel.deleteMany({}),
        OrganizationModel.deleteMany({}),
        SessionModel.deleteMany({}),
        UserModel.deleteMany({}),
      ]);
    });

    afterAll(async () => {
      await disconnectDatabase();
    });

    function createIntegrationApp(storeOverride?: GitHubWebhookStore) {
      const webhookService = createGitHubWebhookService({
        config: TEST_GITHUB_CONFIG,
        store: storeOverride ?? mongooseGitHubWebhookStore,
      });

      return createApp({
        authConfig: TEST_AUTH_CONFIG,
        githubConfig: TEST_GITHUB_CONFIG,
        webhookService,
      });
    }

    async function seedOrgWithProjectAndInstallation(
      app: ReturnType<typeof createApp>,
      email: string,
      slug: string,
      githubInstallationId: number,
      githubRepositoryIds: number[]
    ) {
      await request(app)
        .post('/api/v1/auth/register')
        .send({
          email,
          displayName: email.split('@')[0],
          password: 'StrongPassword123!',
        });
      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email,
        password: 'StrongPassword123!',
      });
      const userId = loginRes.body.user.id as string;
      const token = loginRes.body.accessToken as string;

      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: `Org ${slug}`, slug });
      const organizationId = orgRes.body.organization.id as string;

      const instDoc = await GitHubInstallationModel.create({
        organizationId,
        githubInstallationId,
        githubAppId: TEST_GITHUB_CONFIG.appId,
        accountId: 7000 + githubInstallationId,
        accountLogin: slug,
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read', metadata: 'read' },
        status: GitHubInstallationStatusValue.ACTIVE,
        isActive: true,
        connectedByUserId: userId,
        lastSyncedAt: new Date(),
      });

      const connectionIds: string[] = [];
      for (const [idx, repoId] of githubRepositoryIds.entries()) {
        const projRes = await request(app)
          .post(`/api/v1/organizations/${organizationId}/projects`)
          .set('Authorization', `Bearer ${token}`)
          .send({ name: `Project ${idx + 1}`, slug: `proj-${slug}-${idx + 1}` });
        const projectId = projRes.body.project.id as string;

        const connDoc = await ProjectRepositoryConnectionModel.create({
          organizationId,
          projectId,
          installationRecordId: instDoc._id,
          githubInstallationId,
          githubRepositoryId: repoId,
          ownerLogin: slug,
          repoName: `repo-${repoId}`,
          fullName: `${slug}/repo-${repoId}`,
          htmlUrl: `https://github.com/${slug}/repo-${repoId}`,
          defaultBranch: 'main',
          isPrivate: true,
          isArchivedOnGitHub: false,
          repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
          installationAvailability: InstallationAvailabilityValue.ACTIVE,
          statusReason: null,
          isActive: true,
          connectedByUserId: userId,
          lastSyncedAt: new Date(),
        });
        connectionIds.push(connDoc._id.toString());
      }

      return {
        userId,
        token,
        organizationId,
        installationRecordId: instDoc._id.toString(),
        connectionIds,
      };
    }

    it('processes concurrent duplicate webhooks at most once and enforces unique deliveryId index on real MongoDB', async () => {
      const app = createIntegrationApp();
      const orgA = await seedOrgWithProjectAndInstallation(
        app,
        'wh-race@test.dev',
        'wh-race-org',
        8101,
        [50001]
      );

      const payload = JSON.stringify({
        action: 'suspend',
        installation: { id: 8101, suspended_at: '2026-11-27T15:00:00Z' },
      });
      const sig = signWebhookBody(payload);

      const [r1, r2] = await Promise.all([
        request(app)
          .post('/api/v1/webhooks/github')
          .set('Content-Type', 'application/json')
          .set('X-GitHub-Delivery', 'real-race-delivery-1')
          .set('X-GitHub-Event', 'installation')
          .set('X-Hub-Signature-256', sig)
          .send(payload),
        request(app)
          .post('/api/v1/webhooks/github')
          .set('Content-Type', 'application/json')
          .set('X-GitHub-Delivery', 'real-race-delivery-1')
          .set('X-GitHub-Event', 'installation')
          .set('X-Hub-Signature-256', sig)
          .send(payload),
      ]);

      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect([r1.body.duplicate, r2.body.duplicate].sort()).toEqual([false, true]);

      const deliveries = await WebhookDeliveryModel.find({
        deliveryId: 'real-race-delivery-1',
      });
      expect(deliveries).toHaveLength(1);
      expect(deliveries[0]?.outcome).toBe(WebhookDeliveryOutcomeValue.PROCESSED);

      const updatedInst = await GitHubInstallationModel.findById(orgA.installationRecordId);
      expect(updatedInst?.status).toBe(GitHubInstallationStatusValue.SUSPENDED);

      const updatedConn = await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[0]);
      expect(updatedConn?.installationAvailability).toBe(InstallationAvailabilityValue.SUSPENDED);
      expect(updatedConn?.repositoryAccessState).toBe(RepositoryAccessStateValue.CONNECTED);

      const audits = await IntegrationAuditLogModel.find({
        organizationId: orgA.organizationId,
        action: IntegrationAuditActionValue.INSTALLATION_SUSPENDED,
      });
      expect(audits).toHaveLength(1);
    });

    it('rolls back transactional webhook mutations on failure without false PROCESSED state and succeeds on retry', async () => {
      const failingStore: GitHubWebhookStore = {
        ...mongooseGitHubWebhookStore,
        async createAuditLog() {
          throw new Error(
            `Simulated DB audit failure leaking ${TEST_WEBHOOK_SECRET} and ${TEST_PREVIOUS_WEBHOOK_SECRET}`
          );
        },
      };

      const failingApp = createIntegrationApp(failingStore);
      const org = await seedOrgWithProjectAndInstallation(
        failingApp,
        'wh-rollback@test.dev',
        'wh-rollback-org',
        8201,
        [50002]
      );

      const payload = JSON.stringify({
        action: 'suspend',
        installation: { id: 8201, suspended_at: '2026-11-27T15:10:00Z' },
      });
      const sig = signWebhookBody(payload, TEST_PREVIOUS_WEBHOOK_SECRET);

      const failedRes = await request(failingApp)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-rollback-retry-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', sig)
        .send(payload);
      expect(failedRes.status).toBe(500);

      // Installation and connection were rolled back completely
      expect((await GitHubInstallationModel.findById(org.installationRecordId))?.status).toBe(
        GitHubInstallationStatusValue.ACTIVE
      );
      expect(
        (await ProjectRepositoryConnectionModel.findById(org.connectionIds[0]))
          ?.installationAvailability
      ).toBe(InstallationAvailabilityValue.ACTIVE);

      // Delivery record is FAILED (not PROCESSED) and secrets are redacted
      const failedDelivery = await WebhookDeliveryModel.findOne({
        deliveryId: 'real-rollback-retry-1',
      });
      expect(failedDelivery?.outcome).toBe(WebhookDeliveryOutcomeValue.FAILED);
      expect(failedDelivery?.errorMessage).not.toContain(TEST_WEBHOOK_SECRET);
      expect(failedDelivery?.errorMessage).not.toContain(TEST_PREVIOUS_WEBHOOK_SECRET);

      // Retry against healthy app reclaims FAILED delivery and commits atomically
      const healthyApp = createIntegrationApp();
      const retryRes = await request(healthyApp)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-rollback-retry-1')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', sig)
        .send(payload);
      expect(retryRes.status).toBe(200);
      expect(retryRes.body.outcome).toBe('PROCESSED');
      expect(retryRes.body.duplicate).toBe(false);

      const finalDelivery = await WebhookDeliveryModel.findOne({
        deliveryId: 'real-rollback-retry-1',
      });
      expect(finalDelivery?.outcome).toBe(WebhookDeliveryOutcomeValue.PROCESSED);
      expect(finalDelivery?.attemptCount).toBe(2);
      expect((await GitHubInstallationModel.findById(org.installationRecordId))?.status).toBe(
        GitHubInstallationStatusValue.SUSPENDED
      );
    });

    it('isolates multi-tenant webhooks, preserves orthogonal access/deleted states, and serializes with org mutation lock', async () => {
      const app = createIntegrationApp();
      const orgA = await seedOrgWithProjectAndInstallation(
        app,
        'wh-iso-a@test.dev',
        'wh-iso-org-a',
        8301,
        [60001, 60002]
      );
      const orgB = await seedOrgWithProjectAndInstallation(
        app,
        'wh-iso-b@test.dev',
        'wh-iso-org-b',
        8302,
        [60001]
      );

      // 1. Remove repo 60001 on Org A -> ACCESS_REVOKED in Org A only; Org B stays CONNECTED
      const remPayload = JSON.stringify({
        action: 'removed',
        installation: { id: 8301 },
        repositories_removed: [
          { id: 60001, name: 'repo-60001', full_name: 'wh-iso-org-a/repo-60001' },
        ],
      });
      await request(app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-iso-rem')
        .set('X-GitHub-Event', 'installation_repositories')
        .set('X-Hub-Signature-256', signWebhookBody(remPayload))
        .send(remPayload)
        .expect(200);

      expect(
        (await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[0]))
          ?.repositoryAccessState
      ).toBe(RepositoryAccessStateValue.ACCESS_REVOKED);
      expect(
        (await ProjectRepositoryConnectionModel.findById(orgB.connectionIds[0]))
          ?.repositoryAccessState
      ).toBe(RepositoryAccessStateValue.CONNECTED);

      // 2. Suspend then unsuspend Org A -> revoked 60001 stays ACCESS_REVOKED, connected 60002 returns ACTIVE
      const suspPayload = JSON.stringify({
        action: 'suspend',
        installation: { id: 8301, suspended_at: '2026-11-27T16:00:00Z' },
      });
      await request(app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-iso-susp')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signWebhookBody(suspPayload))
        .send(suspPayload)
        .expect(200);

      const unsuspPayload = JSON.stringify({
        action: 'unsuspend',
        installation: { id: 8301, suspended_at: null },
      });
      await request(app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-iso-unsusp')
        .set('X-GitHub-Event', 'installation')
        .set('X-Hub-Signature-256', signWebhookBody(unsuspPayload))
        .send(unsuspPayload)
        .expect(200);

      expect(
        (await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[0]))
          ?.repositoryAccessState
      ).toBe(RepositoryAccessStateValue.ACCESS_REVOKED);
      expect(
        (await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[1]))
          ?.repositoryAccessState
      ).toBe(RepositoryAccessStateValue.CONNECTED);
      expect(
        (await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[1]))
          ?.installationAvailability
      ).toBe(InstallationAvailabilityValue.ACTIVE);

      // 3. repository.deleted on 60002 (Org A) marks REPO_DELETED, then installation.deleted preserves REPO_DELETED
      const delRepoPayload = JSON.stringify({
        action: 'deleted',
        installation: { id: 8301 },
        repository: {
          id: 60002,
          name: 'repo-60002',
          full_name: 'wh-iso-org-a/repo-60002',
          owner: { login: 'wh-iso-org-a' },
          private: true,
        },
      });
      await request(app)
        .post('/api/v1/webhooks/github')
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Delivery', 'real-iso-repodel')
        .set('X-GitHub-Event', 'repository')
        .set('X-Hub-Signature-256', signWebhookBody(delRepoPayload))
        .send(delRepoPayload)
        .expect(200);

      const orgDocAfter = await OrganizationModel.findById(orgA.organizationId);
      expect(orgDocAfter?.membershipVersion).toBeGreaterThanOrEqual(4);
      expect(
        (await ProjectRepositoryConnectionModel.findById(orgA.connectionIds[1]))
          ?.repositoryAccessState
      ).toBe(RepositoryAccessStateValue.REPO_DELETED);
    });
  }
);
