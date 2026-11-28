import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  claimQueuedScanForAcquisition,
  completeScanWithLease,
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
  transitionScanToInProgress,
  UserModel,
} from '@vibeshield/database';
import { createApp } from '../app.js';
import { createScanCreationRateLimiter } from '../middlewares/scan-rate-limit.js';
import type { AuthRuntimeConfig } from '../modules/auth/auth.types.js';
import { createScanService } from '../modules/scans/scan.service.js';

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

  it('handles concurrent duplicate idempotencyKey creation and rolls back scan when outbox creation fails', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'conc-idem');

    // 1. Concurrent duplicate idempotencyKey: strictly one 201 and one 409 SCAN_ALREADY_EXISTS
    const [r1, r2] = await Promise.all([
      request(app)
        .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
        .set('Authorization', `Bearer ${seeded.token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'concurrent-idem-1' }),
      request(app)
        .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
        .set('Authorization', `Bearer ${seeded.token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'concurrent-idem-1' }),
    ]);

    const statuses = [r1.status, r2.status].sort((a, b) => a - b);
    expect(statuses).toEqual([201, 409]);
    expect(await ScanModel.countDocuments({ projectId: seeded.projectId })).toBe(1);
    expect(await ScanDispatchOutboxModel.countDocuments({ projectId: seeded.projectId })).toBe(1);

    // 2. Outbox-failure transaction rollback: neither scan nor outbox persists
    const createSpy = vi
      .spyOn(ScanDispatchOutboxModel, 'create')
      .mockRejectedValueOnce(new Error('Simulated outbox failure'));
    try {
      const failRes = await request(app)
        .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
        .set('Authorization', `Bearer ${seeded.token}`)
        .send({ requestedRef: 'main', idempotencyKey: 'rollback-test-key' });
      expect(failRes.status).toBe(500);
    } finally {
      createSpy.mockRestore();
    }

    expect(
      await ScanModel.countDocuments({
        projectId: seeded.projectId,
        idempotencyKey: 'rollback-test-key',
      })
    ).toBe(0);
    expect(await ScanDispatchOutboxModel.countDocuments({ projectId: seeded.projectId })).toBe(1);
  });

  it('rejects scan creation when GitHub repository is archived or installation ID mismatches connection', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'conn-state');

    // 1. Archived on GitHub -> 409 REPOSITORY_ARCHIVED
    await ProjectRepositoryConnectionModel.updateOne(
      { _id: seeded.connectionId },
      { $set: { isArchivedOnGitHub: true } }
    );
    const archivedRepoRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(archivedRepoRes.status).toBe(409);
    expect(archivedRepoRes.body.error.code).toBe('REPOSITORY_ARCHIVED');

    // 2. Mismatched githubInstallationId between connection and installation -> 409 INSTALLATION_UNAVAILABLE
    await ProjectRepositoryConnectionModel.updateOne(
      { _id: seeded.connectionId },
      {
        $set: {
          isArchivedOnGitHub: false,
          githubInstallationId: seeded.githubInstallationId + 999,
        },
      }
    );
    const mismatchRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(mismatchRes.status).toBe(409);
    expect(mismatchRes.body.error.code).toBe('INSTALLATION_UNAVAILABLE');
    expect(await ScanModel.countDocuments({ projectId: seeded.projectId })).toBe(0);
  });

  it('enforces in-transaction membership & role revalidation on cancelScan (TOCTOU protection)', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'toctou-cancel');

    // Register & add a second user as MEMBER
    const memberEmail = `member-toctou-${randomBytes(3).toString('hex')}@test.com`;
    const memberPassword = 'member-secure-password-123!';
    const memberReg = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: memberEmail, displayName: 'Member User', password: memberPassword });
    expect(memberReg.status).toBe(201);
    const memberUserId = memberReg.body.user.id as string;

    const addRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/members`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ email: memberEmail, role: 'MEMBER' });
    expect(addRes.status).toBe(201);
    const membershipId = addRes.body.member.membershipId as string;

    // Create a QUEUED scan
    const createRes = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(createRes.status).toBe(201);
    const scanId = createRes.body.scan.id as string;

    // Demote member to VIEWER, then invoke scanService.cancelScan directly (simulating a request
    // that passed HTTP RBAC middleware right before the role downgrade committed).
    const demoteRes = await request(app)
      .patch(`/api/v1/organizations/${seeded.organizationId}/members/${membershipId}`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ role: 'VIEWER' });
    expect(demoteRes.status).toBe(200);

    const scanService = createScanService();
    await expect(
      scanService.cancelScan(memberUserId, seeded.organizationId, seeded.projectId, scanId, {
        reason: 'Stale middleware auth',
      })
    ).rejects.toMatchObject({
      statusCode: 403,
      code: 'FORBIDDEN',
    });

    // Scan & outbox must remain completely untouched
    const scanDoc = await ScanModel.findById(scanId).lean();
    expect(scanDoc?.status).toBe('QUEUED');
    const outboxDoc = await ScanDispatchOutboxModel.findOne({ scanId }).lean();
    expect(outboxDoc?.state).toBe('PENDING');

    // Concurrent race / post-removal revocation: DELETE member returns 200, in-tx cancelScan rejects 404
    await expect(
      request(app)
        .delete(`/api/v1/organizations/${seeded.organizationId}/members/${membershipId}`)
        .set('Authorization', `Bearer ${seeded.token}`)
    ).resolves.toMatchObject({ status: 200 });

    await expect(
      scanService.cancelScan(memberUserId, seeded.organizationId, seeded.projectId, scanId, {})
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'ORGANIZATION_NOT_FOUND',
    });
    expect((await ScanModel.findById(scanId).lean())?.status).toBe('QUEUED');
  });

  it('prevents same-org cross-project IDOR, suppresses populated lease.token, supports IN_PROGRESS/terminal cancellation, and orders ties by _id desc', async () => {
    const app = buildApp();
    const seeded = await seedOrgProjectAndConnection(app, 'lifecycle-idor');

    // Second project in the same organization
    const proj2Res = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ name: 'Project Two', slug: `proj2-${randomBytes(3).toString('hex')}` });
    expect(proj2Res.status).toBe(201);
    const project2Id = proj2Res.body.project.id as string;

    // 1. Deterministic _id: -1 pagination tiebreaker when timestamps collide
    const fixedTime = new Date('2026-01-01T00:00:00.000Z');
    const s1 = await ScanModel.create({
      organizationId: seeded.organizationId,
      projectId: seeded.projectId,
      repositoryConnectionId: seeded.connectionId,
      githubInstallationId: seeded.githubInstallationId,
      githubRepositoryId: seeded.githubRepositoryId,
      requestedRef: 'tie-first',
      status: 'COMPLETED',
      isActive: false,
      triggerSource: 'manual',
      queuedAt: fixedTime,
      completedAt: fixedTime,
      createdAt: fixedTime,
      updatedAt: fixedTime,
    });
    const s2 = await ScanModel.create({
      organizationId: seeded.organizationId,
      projectId: seeded.projectId,
      repositoryConnectionId: seeded.connectionId,
      githubInstallationId: seeded.githubInstallationId,
      githubRepositoryId: seeded.githubRepositoryId,
      requestedRef: 'tie-second',
      status: 'COMPLETED',
      isActive: false,
      triggerSource: 'manual',
      queuedAt: fixedTime,
      completedAt: fixedTime,
      createdAt: fixedTime,
      updatedAt: fixedTime,
    });

    const page1Res = await request(app)
      .get(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans?page=1&limit=1`
      )
      .set('Authorization', `Bearer ${seeded.token}`);
    expect(page1Res.status).toBe(200);
    expect(page1Res.body.scans[0].id).toBe(s2._id.toString());

    const page2Res = await request(app)
      .get(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans?page=2&limit=1`
      )
      .set('Authorization', `Bearer ${seeded.token}`);
    expect(page2Res.status).toBe(200);
    expect(page2Res.body.scans[0].id).toBe(s1._id.toString());

    // 2. Terminal COMPLETED scan cannot be cancelled -> 409 SCAN_ALREADY_TERMINAL
    const terminalCancel = await request(app)
      .post(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${s1._id.toString()}/cancel`
      )
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({});
    expect(terminalCancel.status).toBe(409);
    expect(terminalCancel.body.error.code).toBe('SCAN_ALREADY_TERMINAL');

    // 3. Create live scan, claim lease (populates lease.token), transition to IN_PROGRESS
    const createLive = await request(app)
      .post(`/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans`)
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ requestedRef: 'main' });
    expect(createLive.status).toBe(201);
    const liveScanId = createLive.body.scan.id as string;

    const claim = await claimQueuedScanForAcquisition({
      scanId: liveScanId,
      organizationId: seeded.organizationId,
      projectId: seeded.projectId,
      workerId: 'worker-audit-1',
    });
    expect(claim.status).toBe('CLAIMED');
    if (claim.status !== 'CLAIMED') throw new Error('Expected CLAIMED');

    const inProg = await transitionScanToInProgress({
      scanId: liveScanId,
      organizationId: seeded.organizationId,
      projectId: seeded.projectId,
      leaseToken: claim.leaseToken,
      acquisition: {
        resolvedCommitSha: 'a'.repeat(40),
        compressedArchiveBytes: 1024,
        extractedBytes: 2048,
        extractedFileCount: 5,
      },
    });
    expect(inProg.status).toBe('UPDATED');

    // Populated lease.token must NEVER leak via GET /:scanId or GET /scans
    const detailWithLease = await request(app)
      .get(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${liveScanId}`
      )
      .set('Authorization', `Bearer ${seeded.token}`);
    expect(detailWithLease.status).toBe(200);
    expect(detailWithLease.body.scan.lease).toBeTruthy();
    expect(detailWithLease.body.scan.lease.workerId).toBe('worker-audit-1');
    expect(detailWithLease.body.scan.lease).not.toHaveProperty('token');
    expect(JSON.stringify(detailWithLease.body)).not.toContain(claim.leaseToken);
    expect(detailWithLease.body.scan).not.toHaveProperty('dispatchRevision');

    // 4. IN_PROGRESS scan cancellation returns 202 CANCELLATION_REQUESTED
    const cancelInProgress = await request(app)
      .post(
        `/api/v1/organizations/${seeded.organizationId}/projects/${seeded.projectId}/scans/${liveScanId}/cancel`
      )
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({ reason: 'Abort live scan' });
    expect(cancelInProgress.status).toBe(202);
    expect(cancelInProgress.body.message).toBe('Cancellation requested');
    expect(cancelInProgress.body.scan.cancellation.requestedAt).toBeTruthy();

    // 5. Same-organization cross-project IDOR: project2 cannot read or cancel project1's scan
    const crossProjGet = await request(app)
      .get(
        `/api/v1/organizations/${seeded.organizationId}/projects/${project2Id}/scans/${liveScanId}`
      )
      .set('Authorization', `Bearer ${seeded.token}`);
    expect(crossProjGet.status).toBe(404);
    expect(crossProjGet.body.error.code).toBe('SCAN_NOT_FOUND');

    const crossProjCancel = await request(app)
      .post(
        `/api/v1/organizations/${seeded.organizationId}/projects/${project2Id}/scans/${liveScanId}/cancel`
      )
      .set('Authorization', `Bearer ${seeded.token}`)
      .send({});
    expect(crossProjCancel.status).toBe(404);
    expect(crossProjCancel.body.error.code).toBe('SCAN_NOT_FOUND');

    // Completing scan sees pending cancellation request cleanly (fencing honored)
    const completed = await completeScanWithLease({
      scanId: liveScanId,
      organizationId: seeded.organizationId,
      projectId: seeded.projectId,
      leaseToken: claim.leaseToken,
    });
    expect(completed.status).toBe('CANCEL_REQUESTED');
  });
});
