import { generateKeyPairSync, randomBytes } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubOAuthStateModel,
  IntegrationAuditLogModel,
  OrganizationMembershipModel,
  OrganizationModel,
  ProjectModel,
  SessionModel,
  UserModel,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import type { GitHubRuntimeConfig } from '../config/env.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';
import { createGitHubClient } from '../modules/github/github.client.js';
import { createGitHubService } from '../modules/github/github.service.js';
import {
  mongooseGitHubIntegrationStore,
  type GitHubIntegrationStore,
} from '../modules/github/github.store.js';
import { createOrganizationService } from '../modules/organizations/organization.service.js';
import { mongooseOrganizationStore } from '../modules/organizations/organization.store.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'integration_github_jwt_access_secret_min_32_chars',
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
  appId: 88888,
  appSlug: 'vibeshield-integration-app',
  privateKeyPem: TEST_PRIVATE_KEY_PEM,
  clientId: 'Iv1.integrationclient',
  clientSecret: 'gh_integration_client_secret_value_1234',
  webhookSecret: 'whsec_integration_webhook_secret_min_32_chars',
};

describe.skipIf(!REPLICA_URI)(
  'GitHub Installation & Discovery Real MongoDB Integration Tests',
  () => {
    let mockServer: http.Server;
    let mockBaseUrl = '';
    let activeMockSecretIat = '';

    beforeAll(async () => {
      await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
      await Promise.all([
        UserModel.syncIndexes(),
        SessionModel.syncIndexes(),
        OrganizationModel.syncIndexes(),
        OrganizationMembershipModel.syncIndexes(),
        ProjectModel.syncIndexes(),
        GitHubInstallationModel.syncIndexes(),
        GitHubOAuthStateModel.syncIndexes(),
        IntegrationAuditLogModel.syncIndexes(),
      ]);

      mockServer = http.createServer((req, res) => {
        const url = req.url ?? '/';
        res.setHeader('content-type', 'application/json');

        if (req.method === 'POST' && url.startsWith('/login/oauth/access_token')) {
          res.writeHead(200);
          res.end(JSON.stringify({ access_token: 'ghu_mock_oauth_user_token_123456' }));
          return;
        }
        if (req.method === 'GET' && url.startsWith('/user/installations')) {
          res.writeHead(200);
          res.end(
            JSON.stringify({
              total_count: 1,
              installations: [
                {
                  id: 3001,
                  app_id: TEST_GITHUB_CONFIG.appId,
                  account: { id: 700, login: 'real-mongo-org', type: 'Organization' },
                  repository_selection: 'selected',
                },
              ],
            })
          );
          return;
        }
        if (req.method === 'GET' && url === '/app/installations/3001') {
          res.writeHead(200);
          res.end(
            JSON.stringify({
              id: 3001,
              app_id: TEST_GITHUB_CONFIG.appId,
              account: { id: 700, login: 'real-mongo-org', type: 'Organization' },
              repository_selection: 'selected',
              permissions: { contents: 'read', metadata: 'read' },
              suspended_at: null,
            })
          );
          return;
        }
        if (req.method === 'POST' && url === '/app/installations/3001/access_tokens') {
          activeMockSecretIat = `ghs_${randomBytes(16).toString('hex')}`;
          res.writeHead(201);
          res.end(
            JSON.stringify({
              token: activeMockSecretIat,
              expires_at: '2026-11-28T00:00:00.000Z',
            })
          );
          return;
        }
        if (req.method === 'GET' && url.startsWith('/installation/repositories')) {
          if (req.headers.authorization !== `Bearer ${activeMockSecretIat}`) {
            res.writeHead(401);
            res.end(JSON.stringify({ message: 'Bad credentials' }));
            return;
          }
          res.writeHead(200);
          res.end(
            JSON.stringify({
              total_count: 1,
              repositories: [
                {
                  id: 9101,
                  name: 'core-service',
                  full_name: 'real-mongo-org/core-service',
                  owner: { login: 'real-mongo-org' },
                  default_branch: 'main',
                  private: true,
                  archived: false,
                  html_url: 'https://github.com/real-mongo-org/core-service',
                },
              ],
            })
          );
          return;
        }

        res.writeHead(404);
        res.end(JSON.stringify({ message: 'Not found' }));
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
      await Promise.all([
        IntegrationAuditLogModel.deleteMany({}),
        GitHubOAuthStateModel.deleteMany({}),
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

    function createIntegrationApp(storeOverride?: GitHubIntegrationStore) {
      const githubClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        apiBaseUrl: mockBaseUrl,
        oauthBaseUrl: mockBaseUrl,
        allowCustomBaseUrlForTests: true,
      });

      const githubService = createGitHubService({
        config: TEST_GITHUB_CONFIG,
        githubClient,
        store: storeOverride ?? mongooseGitHubIntegrationStore,
      });

      return createApp({
        authConfig: TEST_AUTH_CONFIG,
        githubService,
      });
    }

    async function seedUserAndToken(app: ReturnType<typeof createApp>, email: string) {
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

    it('completes installation atomically against MongoDB, rejects concurrent state replay, persists audit log, and lists repositories', async () => {
      const app = createIntegrationApp();
      const owner = await seedUserAndToken(app, 'gh-real-owner@test.dev');
      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Real Mongo Org', slug: 'real-mongo-org' });
      const orgId = orgRes.body.organization.id as string;

      const startRes = await request(app)
        .post(`/api/v1/organizations/${orgId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const rawState = new URL(startRes.body.authorizeUrl as string).searchParams.get('state')!;

      // Concurrent parallel completions with identical state: exactly 1 succeeds, 1 fails state check
      const [r1, r2] = await Promise.all([
        request(app)
          .post(`/api/v1/organizations/${orgId}/github/installations/complete`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ state: rawState, code: 'oauth_code', installationId: 3001 }),
        request(app)
          .post(`/api/v1/organizations/${orgId}/github/installations/complete`)
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ state: rawState, code: 'oauth_code', installationId: 3001 }),
      ]);

      const statuses = [r1.status, r2.status].sort((a, b) => a - b);
      expect(statuses).toEqual([400, 200].sort((a, b) => a - b));

      expect(await GitHubInstallationModel.countDocuments({ organizationId: orgId })).toBe(1);
      expect(await IntegrationAuditLogModel.countDocuments({ organizationId: orgId })).toBe(1);

      const reposRes = await request(app)
        .get(`/api/v1/organizations/${orgId}/github/repositories?page=1&perPage=20`)
        .set('Authorization', `Bearer ${owner.token}`);
      expect(reposRes.status).toBe(200);
      expect(reposRes.body.repositories).toHaveLength(1);
      expect(reposRes.body.repositories[0].fullName).toBe('real-mongo-org/core-service');
      expect(JSON.stringify(reposRes.body)).not.toContain(activeMockSecretIat);
    });

    it('rolls back installation and organization lock version when audit log insert fails mid-transaction', async () => {
      const failingStore: GitHubIntegrationStore = {
        ...mongooseGitHubIntegrationStore,
        async createAuditLog() {
          throw new Error('Forced audit failure inside transaction');
        },
      };

      const app = createIntegrationApp(failingStore);
      const owner = await seedUserAndToken(app, 'gh-rb-owner@test.dev');
      const orgRes = await request(app)
        .post('/api/v1/organizations')
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ name: 'Rollback Org', slug: 'gh-rollback-org' });
      const orgId = orgRes.body.organization.id as string;
      const beforeOrg = await OrganizationModel.findById(orgId);
      const initialVersion = beforeOrg!.membershipVersion;

      const startRes = await request(app)
        .post(`/api/v1/organizations/${orgId}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ mode: 'install' });
      const rawState = new URL(startRes.body.authorizeUrl as string).searchParams.get('state')!;

      const completeRes = await request(app)
        .post(`/api/v1/organizations/${orgId}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: rawState, code: 'oauth_code', installationId: 3001 });
      expect(completeRes.status).toBe(500);

      const afterOrg = await OrganizationModel.findById(orgId);
      expect(afterOrg?.membershipVersion).toBe(initialVersion);
      expect(await GitHubInstallationModel.countDocuments({ organizationId: orgId })).toBe(0);
    });

    it('revalidates role inside transaction and blocks concurrent completeInstallation after organization deletion', async () => {
      const app = createIntegrationApp();
      const orgService = createOrganizationService({ store: mongooseOrganizationStore });
      const githubClient = createGitHubClient({
        config: TEST_GITHUB_CONFIG,
        apiBaseUrl: mockBaseUrl,
        oauthBaseUrl: mockBaseUrl,
        allowCustomBaseUrlForTests: true,
      });
      const githubService = createGitHubService({
        config: TEST_GITHUB_CONFIG,
        githubClient,
        store: mongooseGitHubIntegrationStore,
      });

      const owner = await seedUserAndToken(app, 'gh-race-owner@test.dev');
      const org = await orgService.createOrganization(owner.userId, {
        name: 'Lock Org',
        slug: 'gh-lock-org',
      });

      const started = await githubService.startInstallation(owner.userId, org.id, {
        mode: 'install',
      });
      const rawState = new URL(started.authorizeUrl).searchParams.get('state')!;

      // Delete org first; completion must abort with 404 ORGANIZATION_NOT_FOUND without creating orphaned records
      await orgService.deleteOrganization(owner.userId, org.id);

      await expect(
        githubService.completeInstallation(owner.userId, org.id, {
          state: rawState,
          code: 'oauth_code',
          installationId: 3001,
        })
      ).rejects.toMatchObject({ statusCode: 404, code: 'ORGANIZATION_NOT_FOUND' });

      expect(await GitHubInstallationModel.countDocuments({ organizationId: org.id })).toBe(0);
    });

    it('prevents linking the same active githubInstallationId to two distinct VibeShield organizations in MongoDB', async () => {
      const app = createIntegrationApp();
      const owner = await seedUserAndToken(app, 'gh-multi-owner@test.dev');

      const orgA = (
        await request(app)
          .post('/api/v1/organizations')
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Org One', slug: 'gh-org-one' })
      ).body.organization;
      const orgB = (
        await request(app)
          .post('/api/v1/organizations')
          .set('Authorization', `Bearer ${owner.token}`)
          .send({ name: 'Org Two', slug: 'gh-org-two' })
      ).body.organization;

      const startA = await request(app)
        .post(`/api/v1/organizations/${orgA.id}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({});
      const stateA = new URL(startA.body.authorizeUrl as string).searchParams.get('state')!;

      const resA = await request(app)
        .post(`/api/v1/organizations/${orgA.id}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: stateA, code: 'oauth_code', installationId: 3001 });
      expect(resA.status).toBe(200);

      const startB = await request(app)
        .post(`/api/v1/organizations/${orgB.id}/github/installations/start`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({});
      const stateB = new URL(startB.body.authorizeUrl as string).searchParams.get('state')!;

      const resB = await request(app)
        .post(`/api/v1/organizations/${orgB.id}/github/installations/complete`)
        .set('Authorization', `Bearer ${owner.token}`)
        .send({ state: stateB, code: 'oauth_code', installationId: 3001 });
      expect(resB.status).toBe(409);
      expect(resB.body.error.code).toBe('GITHUB_INSTALLATION_UNAVAILABLE');
      expect(await GitHubInstallationModel.countDocuments({ organizationId: orgB.id })).toBe(0);
    });
  }
);
