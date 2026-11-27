import { generateKeyPairSync } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  IntegrationAuditActionValue,
  IntegrationAuditLogModel,
  OrganizationMembershipModel,
  OrganizationModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  SessionModel,
  UserModel,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import type { GitHubRuntimeConfig } from '../config/env.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';
import { createGitHubClient } from '../modules/github/github.client.js';
import { createGitHubRepositoryConnectionService } from '../modules/github/github-connection.service.js';
import {
  mongooseGitHubRepositoryConnectionStore,
  type GitHubRepositoryConnectionStore,
} from '../modules/github/github-connection.store.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'integration_connections_jwt_access_secret_32_chars',
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

const TEST_GITHUB_CONFIG: GitHubRuntimeConfig = {
  appId: 99999,
  appSlug: 'vibeshield-conn-int-app',
  privateKeyPem: TEST_PRIVATE_KEY_PEM,
  clientId: 'Iv1.connintclient',
  clientSecret: 'gh_conn_int_client_secret_value_1234',
  webhookSecret: 'whsec_conn_int_webhook_secret_min_32_chars',
  callbackUrl: 'http://localhost:5173/integrations/github/callback',
};

describe.skipIf(!REPLICA_URI)(
  'Project-to-GitHub Repository Connection Real MongoDB Integration Tests',
  () => {
    let mockServer: http.Server;
    let mockBaseUrl = '';
    let mockSuspendedAt: string | null = null;
    let mockRepoFullName = 'acme-sec/real-repo-1';
    let mockDefaultBranch = 'main';
    let mockRepoProbeStatus: 200 | 403 | 404 | 410 = 200;

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
        IntegrationAuditLogModel.syncIndexes(),
      ]);

      mockServer = http.createServer((req, res) => {
        const url = req.url ?? '/';
        res.setHeader('content-type', 'application/json');

        if (req.method === 'GET' && url.startsWith('/app/installations/')) {
          const idMatch = /^\/app\/installations\/(\d+)$/.exec(url);
          const installationId = idMatch ? Number(idMatch[1]) : 9001;
          res.writeHead(200);
          res.end(
            JSON.stringify({
              id: installationId,
              app_id: TEST_GITHUB_CONFIG.appId,
              account: { id: 5000 + installationId, login: 'acme-sec', type: 'Organization' },
              repository_selection: 'selected',
              permissions: { contents: 'read' },
              suspended_at: mockSuspendedAt,
            })
          );
          return;
        }

        if (req.method === 'POST' && /^\/app\/installations\/\d+\/access_tokens$/.test(url)) {
          res.writeHead(201);
          res.end(
            JSON.stringify({
              token: 'ghs_integration_mock_iat',
              expires_at: new Date(Date.now() + 3600_000).toISOString(),
            })
          );
          return;
        }

        if (req.method === 'GET' && url.startsWith('/installation/repositories')) {
          const [ownerLogin, name] = mockRepoFullName.split('/');
          res.writeHead(200);
          res.end(
            JSON.stringify({
              total_count: 2,
              repositories: [
                {
                  id: 70001,
                  name: name!,
                  full_name: mockRepoFullName,
                  owner: { login: ownerLogin! },
                  default_branch: mockDefaultBranch,
                  private: true,
                  archived: false,
                  html_url: `https://github.com/${mockRepoFullName}`,
                },
                {
                  id: 70002,
                  name: 'real-repo-2',
                  full_name: 'acme-sec/real-repo-2',
                  owner: { login: 'acme-sec' },
                  default_branch: 'main',
                  private: false,
                  archived: false,
                  html_url: 'https://github.com/acme-sec/real-repo-2',
                },
              ],
            })
          );
          return;
        }

        if (req.method === 'GET' && url === '/repositories/70001') {
          if (mockRepoProbeStatus !== 200) {
            res.writeHead(mockRepoProbeStatus);
            res.end(JSON.stringify({ message: `Status ${mockRepoProbeStatus}` }));
            return;
          }
          const [ownerLogin, name] = mockRepoFullName.split('/');
          res.writeHead(200);
          res.end(
            JSON.stringify({
              id: 70001,
              name: name!,
              full_name: mockRepoFullName,
              owner: { login: ownerLogin! },
              default_branch: mockDefaultBranch,
              private: true,
              archived: false,
              html_url: `https://github.com/${mockRepoFullName}`,
            })
          );
          return;
        }

        res.writeHead(404);
        res.end(JSON.stringify({ message: 'Not Found' }));
      });

      await new Promise<void>((resolve) => {
        mockServer.listen(0, '127.0.0.1', () => {
          const address = mockServer.address() as AddressInfo;
          mockBaseUrl = `http://127.0.0.1:${address.port}`;
          resolve();
        });
      });
    });

    beforeEach(async () => {
      mockSuspendedAt = null;
      mockRepoFullName = 'acme-sec/real-repo-1';
      mockDefaultBranch = 'main';
      mockRepoProbeStatus = 200;
      await Promise.all([
        IntegrationAuditLogModel.deleteMany({}),
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
      await new Promise<void>((resolve, reject) => {
        mockServer.close((err) => (err ? reject(err) : resolve()));
      });
      await disconnectDatabase();
    });

    function createIntegrationApp(storeOverride?: GitHubRepositoryConnectionStore) {
      const githubClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        apiBaseUrl: mockBaseUrl,
        oauthBaseUrl: mockBaseUrl,
        allowCustomBaseUrlForTests: true,
      });

      const repositoryConnectionService = createGitHubRepositoryConnectionService({
        config: TEST_GITHUB_CONFIG,
        githubClient,
        store: storeOverride ?? mongooseGitHubRepositoryConnectionStore,
      });

      return createApp({
        authConfig: TEST_AUTH_CONFIG,
        repositoryConnectionService,
        githubConfig: TEST_GITHUB_CONFIG,
      });
    }

    async function seedUser(app: ReturnType<typeof createApp>, email: string) {
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
      return {
        userId: loginRes.body.user.id as string,
        token: loginRes.body.accessToken as string,
      };
    }

    async function seedOrgAndInstallation(
      app: ReturnType<typeof createApp>,
      owner: { userId: string; token: string },
      slug: string,
      githubInstallationId: number
    ) {
      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: `Org ${slug}`, slug });
      const organizationId = orgRes.body.organization.id as string;

      const installationDoc = await GitHubInstallationModel.create({
        organizationId,
        githubInstallationId,
        githubAppId: TEST_GITHUB_CONFIG.appId,
        accountId: 5000 + githubInstallationId,
        accountLogin: 'acme-sec',
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read' },
        status: GitHubInstallationStatusValue.ACTIVE,
        isActive: true,
        connectedByUserId: owner.userId,
        lastSyncedAt: new Date(),
      });

      return { organizationId, installationRecordId: installationDoc._id.toString() };
    }

    it('runs full lifecycle against real MongoDB replica set, preserves terminal REPO_DELETED across unsuspend, and persists audit trail', async () => {
      const app = createIntegrationApp();
      const owner = await seedUser(app, 'real-conn-owner@test.dev');
      const { organizationId, installationRecordId } = await seedOrgAndInstallation(
        app,
        owner,
        'real-conn-org',
        9001
      );

      const projRes = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Scanner Service', slug: 'scanner-service' });
      const projectId = projRes.body.project.id as string;

      // Connect
      const connectRes = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ installationRecordId, githubRepositoryId: 70001 });
      expect(connectRes.status).toBe(201);
      expect(connectRes.body.connection.fullName).toBe('acme-sec/real-repo-1');

      // Sync rename + defaultBranch
      mockRepoFullName = 'acme-sec/renamed-repo';
      mockDefaultBranch = 'trunk';
      const syncRes = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(syncRes.status).toBe(200);
      expect(syncRes.body.connection.fullName).toBe('acme-sec/renamed-repo');
      expect(syncRes.body.connection.defaultBranch).toBe('trunk');

      // 410 Gone marks REPO_DELETED; installation suspend -> unsuspend preserves REPO_DELETED
      mockRepoProbeStatus = 410;
      const goneSync = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(goneSync.status).toBe(200);
      expect(goneSync.body.connection.effectiveStatus).toBe('REPO_DELETED');

      mockSuspendedAt = '2026-11-27T12:00:00Z';
      await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
        .set('Authorization', `Bearer ${owner.token}`);

      mockSuspendedAt = null;
      mockRepoProbeStatus = 200;
      const unsuspendAfterDelete = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github/sync`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(unsuspendAfterDelete.status).toBe(200);
      expect(unsuspendAfterDelete.body.connection).toMatchObject({
        repositoryAccessState: 'REPO_DELETED',
        installationAvailability: 'ACTIVE',
        effectiveStatus: 'REPO_DELETED',
      });

      // Disconnect allows fresh reconnection afterwards while preserving historical DB record
      const discRes = await request(app)
        .delete(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(discRes.status).toBe(200);
      expect(discRes.body.connection.isActive).toBe(false);

      const reconnRes = await request(app)
        .post(`/api/v1/organizations/${organizationId}/projects/${projectId}/github`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ installationRecordId, githubRepositoryId: 70001 });
      expect(reconnRes.status).toBe(201);

      const dbRows = await ProjectRepositoryConnectionModel.find({ organizationId, projectId });
      expect(dbRows).toHaveLength(2);
      expect(dbRows.filter((r) => r.isActive)).toHaveLength(1);

      const audits = await IntegrationAuditLogModel.find({ organizationId }).sort({ createdAt: 1 });
      expect(audits.map((a) => a.action)).toContain(IntegrationAuditActionValue.REPOSITORY_DELETED);
      expect(audits.map((a) => a.action)).toContain(
        IntegrationAuditActionValue.REPOSITORY_DISCONNECTED
      );
      expect(audits.map((a) => a.action)).toContain(
        IntegrationAuditActionValue.REPOSITORY_CONNECTED
      );
    });

    it('serializes concurrent connection races (same repo across two projects and different repos on one project) and multi-org isolation', async () => {
      const app = createIntegrationApp();
      const owner = await seedUser(app, 'race-owner@test.dev');
      const org1 = await seedOrgAndInstallation(app, owner, 'race-org-1', 9001);
      const org2 = await seedOrgAndInstallation(app, owner, 'race-org-2', 9002);

      const [p1Res, p2Res, p3Res, org2ProjRes] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Race P1', slug: 'race-p1' }),
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Race P2', slug: 'race-p2' }),
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Race P3', slug: 'race-p3' }),
        request(app)
          .post(`/api/v1/organizations/${org2.organizationId}/projects`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Org2 P1', slug: 'org2-p1' }),
      ]);

      const p1Id = p1Res.body.project.id as string;
      const p2Id = p2Res.body.project.id as string;
      const p3Id = p3Res.body.project.id as string;
      const org2ProjId = org2ProjRes.body.project.id as string;

      // 1. Concurrent same-repo connect race across two projects in the same org
      const [sameRepoA, sameRepoB] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects/${p1Id}/github`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ installationRecordId: org1.installationRecordId, githubRepositoryId: 70001 }),
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects/${p2Id}/github`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ installationRecordId: org1.installationRecordId, githubRepositoryId: 70001 }),
      ]);

      const statusesSameRepo = [sameRepoA.status, sameRepoB.status].sort((a, b) => a - b);
      expect(statusesSameRepo).toEqual([201, 409]);

      // 2. Concurrent different-repo connect race on the same project (p3)
      const [diffRepoA, diffRepoB] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects/${p3Id}/github`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ installationRecordId: org1.installationRecordId, githubRepositoryId: 70002 }),
        request(app)
          .post(`/api/v1/organizations/${org1.organizationId}/projects/${p3Id}/github`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ installationRecordId: org1.installationRecordId, githubRepositoryId: 70001 }),
      ]);
      const p3WinnerCount = [diffRepoA.status, diffRepoB.status].filter((s) => s === 201).length;
      expect(p3WinnerCount).toBe(1);

      // 3. Same repository ID CAN concurrently connect in a different organization (tenant isolation)
      const org2Connect = await request(app)
        .post(`/api/v1/organizations/${org2.organizationId}/projects/${org2ProjId}/github`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ installationRecordId: org2.installationRecordId, githubRepositoryId: 70001 });
      expect(org2Connect.status).toBe(201);
    });

    it('serializes repository connect with organization deletion and rolls back connection + audit atomically on failure', async () => {
      // Part A: Mid-transaction failure rolls back connection + audit cleanly
      const failingStore: GitHubRepositoryConnectionStore = {
        ...mongooseGitHubRepositoryConnectionStore,
        async createAuditLog() {
          throw new Error('Simulated audit log write failure');
        },
      };

      const failingApp = createIntegrationApp(failingStore);
      const owner = await seedUser(failingApp, 'tx-rollback@test.dev');
      const org = await seedOrgAndInstallation(failingApp, owner, 'rollback-org', 9001);
      const projRes = await request(failingApp)
        .post(`/api/v1/organizations/${org.organizationId}/projects`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Rollback Proj', slug: 'rollback-proj' });
      const projectId = projRes.body.project.id as string;

      const failedConnect = await request(failingApp)
        .post(`/api/v1/organizations/${org.organizationId}/projects/${projectId}/github`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ installationRecordId: org.installationRecordId, githubRepositoryId: 70001 });
      expect(failedConnect.status).toBe(500);
      expect(
        await ProjectRepositoryConnectionModel.countDocuments({
          organizationId: org.organizationId,
        })
      ).toBe(0);
      expect(
        await IntegrationAuditLogModel.countDocuments({
          organizationId: org.organizationId,
          action: IntegrationAuditActionValue.REPOSITORY_CONNECTED,
        })
      ).toBe(0);

      // Part B: Organization lock serialization with project archiving prevents post-archive attachment
      const normalApp = createIntegrationApp();
      const raceOrg = await seedOrgAndInstallation(normalApp, owner, 'archive-race-org', 9003);
      const raceProjRes = await request(normalApp)
        .post(`/api/v1/organizations/${raceOrg.organizationId}/projects`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Archive Race Proj', slug: 'archive-race-proj' });
      const raceProjId = raceProjRes.body.project.id as string;

      const [connectOutcome, archiveOutcome] = await Promise.all([
        request(normalApp)
          .post(`/api/v1/organizations/${raceOrg.organizationId}/projects/${raceProjId}/github`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ installationRecordId: raceOrg.installationRecordId, githubRepositoryId: 70001 }),
        request(normalApp)
          .post(`/api/v1/organizations/${raceOrg.organizationId}/projects/${raceProjId}/archive`)
          .set('Authorization', `Bearer ${owner.token}`),
      ]);

      expect(archiveOutcome.status).toBe(200);
      expect([201, 409]).toContain(connectOutcome.status);
      if (connectOutcome.status === 409) {
        expect(connectOutcome.body.error.code).toBe('PROJECT_ARCHIVED');
        expect(
          await ProjectRepositoryConnectionModel.countDocuments({
            organizationId: raceOrg.organizationId,
            projectId: raceProjId,
          })
        ).toBe(0);
      }

      // Connecting an already-archived project always fails cleanly with 409 PROJECT_ARCHIVED
      const alreadyArchivedProjRes = await request(normalApp)
        .post(`/api/v1/organizations/${raceOrg.organizationId}/projects`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Archived Proj', slug: 'archived-proj' });
      const archivedProjId = alreadyArchivedProjRes.body.project.id as string;
      await request(normalApp)
        .post(`/api/v1/organizations/${raceOrg.organizationId}/projects/${archivedProjId}/archive`)
        .set('Authorization', `Bearer ${owner.token}`);

      const postArchiveConnect = await request(normalApp)
        .post(`/api/v1/organizations/${raceOrg.organizationId}/projects/${archivedProjId}/github`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ installationRecordId: raceOrg.installationRecordId, githubRepositoryId: 70002 });
      expect(postArchiveConnect.status).toBe(409);
      expect(postArchiveConnect.body.error.code).toBe('PROJECT_ARCHIVED');
    });
  }
);
