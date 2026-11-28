import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  OrganizationMembershipModel,
  OrganizationModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
  ScanDispatchOutboxModel,
  ScanModel,
  SessionModel,
  UserModel,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import { createScanCreationRateLimiter } from '../middlewares/scan-rate-limit.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

const TEST_AUTH_CONFIG: AuthRuntimeConfig = {
  jwtAccessSecret: 'integration_scans_jwt_access_secret_32_chars_min',
  jwtAccessTtl: '15m',
  jwtAccessTtlSeconds: 900,
  jwtIssuer: 'vibeshield-api',
  jwtAudience: 'vibeshield-clients',
  refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
  isProduction: false,
  cookiePath: '/api/v1/auth',
  cookieSameSite: 'lax',
};

function createAllowAllRateLimiterForMongoTests() {
  return createScanCreationRateLimiter({
    maxRequests: 1000,
    windowMs: 60_000,
    consumeRateLimit: async ({ maxRequests, windowMs }) => ({
      allowed: true,
      limit: maxRequests,
      remaining: maxRequests - 1,
      resetAtMs: Date.now() + windowMs,
      retryAfterSeconds: 60,
    }),
  });
}

describe.skipIf(!REPLICA_URI)('Public Scan API — Real MongoDB Integration Tests', () => {
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
      ScanModel.syncIndexes(),
      ScanDispatchOutboxModel.syncIndexes(),
    ]);
  });

  beforeEach(async () => {
    await Promise.all([
      ScanDispatchOutboxModel.deleteMany({}),
      ScanModel.deleteMany({}),
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

  function buildApp() {
    return createApp({
      authConfig: TEST_AUTH_CONFIG,
      scanCreateRateLimiter: createAllowAllRateLimiterForMongoTests(),
    });
  }

  async function seedOrgProjectAndConnection(app: ReturnType<typeof createApp>, suffix: string) {
    const email = `scan-int-${suffix}-${randomBytes(3).toString('hex')}@test.com`;
    const password = 'scan-integration-password-123!';

    const regRes = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, displayName: `User ${suffix}`, password });
    expect(regRes.status).toBe(201);
    const userId = regRes.body.user.id as string;

    const loginRes = await request(app).post('/api/v1/auth/login').send({ email, password });
    expect(loginRes.status).toBe(200);
    const token = loginRes.body.accessToken as string;

    const orgRes = await request(app)
      .post('/api/v1/organizations')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `Org ${suffix}`, slug: `org-${suffix}-${randomBytes(3).toString('hex')}` });
    expect(orgRes.status).toBe(201);
    const organizationId = orgRes.body.organization.id as string;

    const projectRes = await request(app)
      .post(`/api/v1/organizations/${organizationId}/projects`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: `Project ${suffix}`,
        slug: `proj-${suffix}-${randomBytes(3).toString('hex')}`,
      });
    expect(projectRes.status).toBe(201);
    const projectId = projectRes.body.project.id as string;

    const githubInstallationId = Math.floor(100_000 + Math.random() * 800_000);
    const githubRepositoryId = Math.floor(1_000_000 + Math.random() * 8_000_000);

    const installation = await GitHubInstallationModel.create({
      organizationId,
      githubInstallationId,
      githubAppId: 99999,
      accountId: 50_000 + githubInstallationId,
      accountLogin: `acme-${suffix}`,
      accountType: 'Organization',
      repositorySelection: 'selected',
      grantedPermissions: { contents: 'read', metadata: 'read' },
      status: GitHubInstallationStatusValue.ACTIVE,
      isActive: true,
      connectedByUserId: userId,
      lastSyncedAt: new Date(),
    });

    const connection = await ProjectRepositoryConnectionModel.create({
      organizationId,
      projectId,
      installationRecordId: installation._id,
      githubInstallationId,
      githubRepositoryId,
      ownerLogin: `acme-${suffix}`,
      repoName: `repo-${suffix}`,
      fullName: `acme-${suffix}/repo-${suffix}`,
      htmlUrl: `https://github.com/acme-${suffix}/repo-${suffix}`,
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

    return {
      userId,
      token,
      organizationId,
      projectId,
      installationId: installation._id.toString(),
      connectionId: connection._id.toString(),
      githubInstallationId,
      githubRepositoryId,
    };
  }

  it('atomically creates Scan + ScanDispatchOutbox from trusted DB records and enforces idempotency', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'atomic');

    const createRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({
        requestedRef: 'feature/v1.0.0',
        idempotencyKey: 'deploy-key-001',
        correlationId: 'ci-run-42',
      });

    expect(createRes.status).toBe(201);
    const scan = createRes.body.scan;
    expect(scan.status).toBe('QUEUED');
    expect(scan.isActive).toBe(true);
    expect(scan.triggerSource).toBe('manual');
    expect(scan.requestedRef).toBe('feature/v1.0.0');
    expect(scan.githubInstallationId).toBe(seeded.githubInstallationId);
    expect(scan.githubRepositoryId).toBe(seeded.githubRepositoryId);
    expect(scan.repositoryConnectionId).toBe(seeded.connectionId);
    expect(scan.createdByUserId).toBe(seeded.userId);
    expect(scan).not.toHaveProperty('dispatchRevision');

    const outbox = await ScanDispatchOutboxModel.findOne({ scanId: scan.id }).lean();
    expect(outbox).not.toBeNull();
    expect(outbox?.state).toBe('PENDING');
    expect(outbox?.dispatchGeneration).toBe(1);
    expect(outbox?.organizationId.toString()).toBe(seeded.organizationId);
    expect(outbox?.projectId.toString()).toBe(seeded.projectId);

    // Duplicate idempotencyKey -> 409 SCAN_ALREADY_EXISTS and still only 1 scan
    const dupRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({
        requestedRef: 'feature/v1.0.0',
        idempotencyKey: 'deploy-key-001',
      });

    expect(dupRes.status).toBe(409);
    expect(dupRes.body.error.code).toBe('SCAN_ALREADY_EXISTS');
    expect(await ScanModel.countDocuments({ projectId: seeded.projectId })).toBe(1);
    expect(await ScanDispatchOutboxModel.countDocuments({ projectId: seeded.projectId })).toBe(1);
  });

  it('rejects scan creation when project is archived, repository is disconnected, or installation is suspended', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'guards');

    // 1. Suspended installation -> 409 INSTALLATION_UNAVAILABLE
    await GitHubInstallationModel.updateOne(
      { _id: seeded.installationId },
      { $set: { status: GitHubInstallationStatusValue.SUSPENDED } }
    );
    const suspendedRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(suspendedRes.status).toBe(409);
    expect(suspendedRes.body.error.code).toBe('INSTALLATION_UNAVAILABLE');

    // Restore installation, disconnect repo -> 409 REPOSITORY_NOT_CONNECTED
    await GitHubInstallationModel.updateOne(
      { _id: seeded.installationId },
      { $set: { status: GitHubInstallationStatusValue.ACTIVE } }
    );
    await ProjectRepositoryConnectionModel.updateOne(
      { _id: seeded.connectionId },
      { $set: { isActive: false, status: 'DISCONNECTED' } }
    );
    const disconnectedRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(disconnectedRes.status).toBe(409);
    expect(disconnectedRes.body.error.code).toBe('REPOSITORY_NOT_CONNECTED');

    // Archive project -> 409 PROJECT_ARCHIVED
    await ProjectModel.updateOne({ _id: seeded.projectId }, { $set: { archivedAt: new Date() } });
    const archivedRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(archivedRes.status).toBe(409);
    expect(archivedRes.body.error.code).toBe('PROJECT_ARCHIVED');

    expect(await ScanModel.countDocuments({ projectId: seeded.projectId })).toBe(0);
  });

  it('cancels QUEUED scan atomically (suppresses outbox), handles concurrent cancel race, and handles ALREADY_TERMINAL', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'cancel');

    const createRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(createRes.status).toBe(201);
    const scanId = createRes.body.scan.id as string;

    // Concurrent cancel race: one should succeed (200), one should get 409 SCAN_ALREADY_TERMINAL
    const [c1, c2] = await Promise.all([
      request(app)
        .post(
          `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${scanId}/cancel`
        )
        .set('Authorization', `Bearer ${seeded.token}`)
        .send({ reason: 'Race cancel 1' }),
      request(app)
        .post(
          `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${scanId}/cancel`
        )
        .set('Authorization', `Bearer ${seeded.token}`)
        .send({ reason: 'Race cancel 2' }),
    ]);

    const statuses = [c1.status, c2.status].sort((a, b) => a - b);
    expect(statuses).toEqual([200, 409]);

    const outbox = await ScanDispatchOutboxModel.findOne({ scanId }).lean();
    expect(outbox?.state).toBe('SUPPRESSED');

    const detailRes = await request(app)
      .get(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${scanId}`
      )
      .set('Authorization', `Bearer ${seeded.token}`);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.scan.status).toBe('CANCELLED');
    expect(detailRes.body.scan.isActive).toBe(false);
  });

  it('paginates scans deterministically, supports status/triggerSource filters, and enforces cross-org IDOR isolation', async () => {
    const app = buildApp();
    const orgA = await seedOrgProjectAndConnection(app, 'orga');
    const orgB = await seedOrgProjectAndConnection(app, 'orgb');

    // Seed 15 scans in Org A
    for (let i = 1; i <= 15; i++) {
      const res = await request(app)
        .post(`/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/scans`)
        .set('Authorization', `Bearer ${orgA.token}`)
        .send({ requestedRef: `branch-${String(i).padStart(2, '0')}` });
      expect(res.status).toBe(201);
    }

    // Seed 1 scan in Org B
    const orgBCreate = await request(app)
      .post(`/api/v1/organizations/${orgB.organizationId}/projects/${orgB.projectId}/scans`)
      .set('Authorization', `Bearer ${orgB.token}`)
      .send({ requestedRef: 'orgb-main' });
    expect(orgBCreate.status).toBe(201);
    const orgBScanId = orgBCreate.body.scan.id as string;

    // Page 2, limit 5 -> 5 items, total 15, totalPages 3
    const page2 = await request(app)
      .get(
        `/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/scans?page=2&limit=5&status=QUEUED&triggerSource=manual`
      )
      .set('Authorization', `Bearer ${orgA.token}`);
    expect(page2.status).toBe(200);
    expect(page2.body.scans).toHaveLength(5);
    expect(page2.body.pagination).toEqual({
      page: 2,
      limit: 5,
      total: 15,
      totalPages: 3,
    });

    // Webhook filter should return 0 scans
    const webhookOnly = await request(app)
      .get(
        `/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/scans?triggerSource=webhook`
      )
      .set('Authorization', `Bearer ${orgA.token}`);
    expect(webhookOnly.status).toBe(200);
    expect(webhookOnly.body.scans).toHaveLength(0);
    expect(webhookOnly.body.pagination.total).toBe(0);

    // Cross-org IDOR: Org A user trying to read Org B's scan under Org A's project -> 404 SCAN_NOT_FOUND
    const idorGet = await request(app)
      .get(
        `/api/v1/organizations/${orgA.organizationId}/projects/${orgA.projectId}/scans/${orgBScanId}`
      )
      .set('Authorization', `Bearer ${orgA.token}`);
    expect(idorGet.status).toBe(404);
    expect(idorGet.body.error.code).toBe('SCAN_NOT_FOUND');

    // Cross-org IDOR: Org A user trying to access Org B's orgId -> 404 ORGANIZATION_NOT_FOUND
    const idorOrg = await request(app)
      .get(
        `/api/v1/organizations/${orgB.organizationId}/projects/${orgB.projectId}/scans/${orgBScanId}`
      )
      .set('Authorization', `Bearer ${orgA.token}`);
    expect(idorOrg.status).toBe(404);
    expect(idorOrg.body.error.code).toBe('ORGANIZATION_NOT_FOUND');
  });
});
