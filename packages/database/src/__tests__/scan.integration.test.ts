import mongoose from 'mongoose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  ScanTriggerSourceValue,
} from '@vibeshield/types';
import {
  cancelScanWithLease,
  claimQueuedScanForAcquisition,
  completeScanWithLease,
  connectDatabase,
  createQueuedScan,
  disconnectDatabase,
  failScanWithLease,
  findScanByIdInOrganization,
  listScansByProjectInOrganization,
  OrganizationModel,
  reclaimExpiredScanLease,
  renewScanWorkerLease,
  requestScanCancellation,
  ScanModel,
  transitionScanToInProgress,
} from '../index.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

describe.skipIf(!REPLICA_URI)(
  'ScanModel & Atomic Lease Lifecycle Real MongoDB Replica-Set Integration Tests',
  () => {
    let orgA: string;
    let orgB: string;
    let projectA1: string;
    let projectA2: string;
    let projectB1: string;
    let connA1: string;
    let userA: string;

    beforeAll(async () => {
      await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
      await Promise.all([OrganizationModel.syncIndexes(), ScanModel.syncIndexes()]);
    });

    beforeEach(async () => {
      await Promise.all([OrganizationModel.deleteMany({}), ScanModel.deleteMany({})]);

      const creatorId = new mongoose.Types.ObjectId();
      const [createdOrgA, createdOrgB] = await OrganizationModel.create([
        { name: 'Scan Test Org A', slug: 'scan-test-org-a', createdBy: creatorId },
        { name: 'Scan Test Org B', slug: 'scan-test-org-b', createdBy: creatorId },
      ]);
      orgA = createdOrgA!._id.toString();
      orgB = createdOrgB!._id.toString();
      projectA1 = new mongoose.Types.ObjectId().toString();
      projectA2 = new mongoose.Types.ObjectId().toString();
      projectB1 = new mongoose.Types.ObjectId().toString();
      connA1 = new mongoose.Types.ObjectId().toString();
      userA = creatorId.toString();
    });

    afterAll(async () => {
      await disconnectDatabase();
    });

    it('creates all Scan indexes cleanly and enforces tenant+project idempotency uniqueness', async () => {
      const indexes = await ScanModel.collection.indexes();
      expect(indexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: 'scans_org_project_created_idx' }),
          expect.objectContaining({ name: 'scans_org_project_active_idx' }),
          expect.objectContaining({ name: 'scans_org_status_idx' }),
          expect.objectContaining({ name: 'scans_active_lease_expires_idx' }),
          expect.objectContaining({
            name: 'scans_org_project_idempotency_unique',
            unique: true,
            partialFilterExpression: { idempotencyKey: { $type: 'string' } },
          }),
        ])
      );

      const first = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.WEBHOOK,
        idempotencyKey: 'delivery-123',
      });
      expect(first.status).toBe(ScanLifecycleStatusValue.QUEUED);

      // Duplicate idempotencyKey in same org+project rejected
      await expect(
        createQueuedScan({
          organizationId: orgA,
          projectId: projectA1,
          repositoryConnectionId: connA1,
          githubInstallationId: 1001,
          githubRepositoryId: 2001,
          requestedRef: 'main',
          triggerSource: ScanTriggerSourceValue.WEBHOOK,
          idempotencyKey: 'delivery-123',
        })
      ).rejects.toMatchObject({ code: 11000 });

      // Same idempotencyKey in another project IS allowed, and omitted/null idempotencyKey allows multiple scans
      const otherProjScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA2,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.WEBHOOK,
        idempotencyKey: 'delivery-123',
      });
      expect(otherProjScan.id).not.toBe(first.id);

      const noKey1 = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      const noKey2 = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'develop',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      expect(noKey1.id).not.toBe(noKey2.id);

      // Tenant-scoped lookups isolate cross-org and cross-project reads cleanly
      expect(
        await findScanByIdInOrganization({
          organizationId: orgB,
          projectId: projectA1,
          scanId: first.id,
        })
      ).toBeNull();
      expect(
        await findScanByIdInOrganization({
          organizationId: orgA,
          projectId: projectB1,
          scanId: first.id,
        })
      ).toBeNull();

      const orgAProjectScans = await listScansByProjectInOrganization({
        organizationId: orgA,
        projectId: projectA1,
      });
      expect(orgAProjectScans).toHaveLength(3);
    });

    it('allows only one worker to claim a QUEUED scan under true concurrent contention', async () => {
      const scan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });

      const [claimA, claimB, claimC] = await Promise.all([
        claimQueuedScanForAcquisition({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-alpha',
          leaseDurationMs: 30_000,
        }),
        claimQueuedScanForAcquisition({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-beta',
          leaseDurationMs: 30_000,
        }),
        claimQueuedScanForAcquisition({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-gamma',
          leaseDurationMs: 30_000,
        }),
      ]);

      const outcomes = [claimA, claimB, claimC];
      const winners = outcomes.filter((r) => r.status === 'CLAIMED');
      const losers = outcomes.filter((r) => r.status === 'NOT_CLAIMABLE');

      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(2);
      expect(winners[0]!.scan.attemptCount).toBe(1);
      expect(winners[0]!.scan.status).toBe(ScanLifecycleStatusValue.ACQUIRING);

      // Lease fencing token must NEVER leak in ordinary ScanModel reads
      const rawDoc = await ScanModel.findById(scan.id).lean();
      expect((rawDoc?.lease as Record<string, unknown> | undefined)?.token).toBeUndefined();
    });

    it('enforces full lifecycle transitions, rejects illegal transitions, and fences old workers after lease expiry and reassignment', async () => {
      const t0 = new Date('2026-11-27T12:00:00Z');
      const scan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
        maxAttempts: 2,
        now: t0,
      });

      const claimA = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-old',
        leaseDurationMs: 5_000,
        now: t0,
      });
      expect(claimA.status).toBe('CLAIMED');
      if (claimA.status !== 'CLAIMED') throw new Error('Expected claimed');
      const oldToken = claimA.leaseToken;

      // Illegal skip: ACQUIRING cannot jump directly to COMPLETED
      const illegalSkip = await completeScanWithLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: oldToken,
        now: new Date(t0.getTime() + 1_000),
      });
      expect(illegalSkip.status).toBe('STALE_OR_CONFLICT');

      // Premature reclaim before expiry must fail
      const earlyReclaim = await reclaimExpiredScanLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-new',
        leaseDurationMs: 5_000,
        now: new Date(t0.getTime() + 3_000),
      });
      expect(earlyReclaim.status).toBe('NOT_RECLAIMABLE');

      // Reclaim after lease expiry rotates fencing token and increments attemptCount
      const tExpired = new Date(t0.getTime() + 6_000);
      const reclaimedB = await reclaimExpiredScanLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-new',
        leaseDurationMs: 10_000,
        now: tExpired,
      });
      expect(reclaimedB.status).toBe('RECLAIMED');
      if (reclaimedB.status !== 'RECLAIMED') throw new Error('Expected reclaimed');
      const newToken = reclaimedB.leaseToken;
      expect(newToken).not.toBe(oldToken);
      expect(reclaimedB.scan.attemptCount).toBe(2);
      expect(reclaimedB.scan.lease?.workerId).toBe('worker-new');

      // Old worker holding stale token MUST be fenced on EVERY operation
      const tOldLate = new Date(t0.getTime() + 7_000);
      expect(
        (
          await renewScanWorkerLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: oldToken,
            now: tOldLate,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');

      expect(
        (
          await transitionScanToInProgress({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: oldToken,
            acquisition: {
              resolvedCommitSha: 'c'.repeat(40),
              compressedArchiveBytes: 500,
              extractedBytes: 1500,
              extractedFileCount: 10,
            },
            now: tOldLate,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');

      expect(
        (
          await failScanWithLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: oldToken,
            failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
            failureMessage: 'Old worker failure should be ignored',
            now: tOldLate,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');

      expect(
        (
          await cancelScanWithLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: oldToken,
            now: tOldLate,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');

      // New worker advances cleanly through ACQUIRING -> IN_PROGRESS -> COMPLETED
      const inProgressRes = await transitionScanToInProgress({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: newToken,
        acquisition: {
          resolvedCommitSha: 'd'.repeat(40),
          compressedArchiveBytes: 2048,
          extractedBytes: 8192,
          extractedFileCount: 42,
        },
        now: new Date(tExpired.getTime() + 1_000),
      });
      expect(inProgressRes.status).toBe('UPDATED');
      expect(inProgressRes.scan?.resolvedCommitSha).toBe('d'.repeat(40));
      expect(inProgressRes.scan?.acquisition?.extractedFileCount).toBe(42);

      const completedRes = await completeScanWithLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: newToken,
        now: new Date(tExpired.getTime() + 2_000),
      });
      expect(completedRes.status).toBe('UPDATED');
      expect(completedRes.scan?.status).toBe(ScanLifecycleStatusValue.COMPLETED);
      expect(completedRes.scan?.isActive).toBe(false);
      expect(completedRes.scan?.lease).toBeNull();

      // Terminal scan rejects further cancellation or mutation
      const cancelAfterDone = await requestScanCancellation({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        requestedByUserId: userA,
      });
      expect(cancelAfterDone.status).toBe('ALREADY_TERMINAL');

      // Exhausted lease attempt ceiling fails permanently instead of reclaiming endlessly
      const scanMax = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.SYSTEM,
        maxAttempts: 1,
        now: t0,
      });
      await claimQueuedScanForAcquisition({
        scanId: scanMax.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-crash',
        leaseDurationMs: 2_000,
        now: t0,
      });
      const exhaustedRes = await reclaimExpiredScanLease({
        scanId: scanMax.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-recovery',
        leaseDurationMs: 2_000,
        now: new Date(t0.getTime() + 3_000),
      });
      expect(exhaustedRes.status).toBe('MAX_ATTEMPTS_EXHAUSTED');
      expect(exhaustedRes.scan?.failureCode).toBe(ScanFailureCodeValue.LEASE_EXPIRED);
      expect(exhaustedRes.scan?.isActive).toBe(false);
    });

    it('handles pre-acquisition cancellation and concurrent claim vs cancellation races safely', async () => {
      // 1. Immediate cancellation before claim
      const queuedScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });

      const immediateCancel = await requestScanCancellation({
        scanId: queuedScan.id,
        organizationId: orgA,
        projectId: projectA1,
        requestedByUserId: userA,
        reason: 'Cancelled before worker started',
      });
      expect(immediateCancel.status).toBe('CANCELLED_IMMEDIATELY');

      const claimAfterCancel = await claimQueuedScanForAcquisition({
        scanId: queuedScan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-1',
      });
      expect(claimAfterCancel.status).toBe('CANCELLED');

      // 2. Concurrent race between claim and cancellation
      const raceScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });

      const [claimOutcome, cancelOutcome] = await Promise.all([
        claimQueuedScanForAcquisition({
          scanId: raceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-race',
        }),
        requestScanCancellation({
          scanId: raceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
          reason: 'Concurrent cancel race',
        }),
      ]);

      if (claimOutcome.status === 'CLAIMED') {
        expect(['CANCELLATION_REQUESTED', 'ALREADY_TERMINAL']).toContain(cancelOutcome.status);
        // Active worker MUST NOT be allowed to enter IN_PROGRESS once cancellation was stamped
        const advanceAttempt = await transitionScanToInProgress({
          scanId: raceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimOutcome.leaseToken,
          acquisition: {
            resolvedCommitSha: 'e'.repeat(40),
            compressedArchiveBytes: 100,
            extractedBytes: 200,
            extractedFileCount: 1,
          },
        });
        expect(advanceAttempt.status).toBe('CANCEL_REQUESTED');

        const ackCancel = await cancelScanWithLease({
          scanId: raceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimOutcome.leaseToken,
        });
        expect(ackCancel.status).toBe('UPDATED');
        expect(ackCancel.scan?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
      } else {
        expect(claimOutcome.status).toBe('CANCELLED');
        expect(cancelOutcome.status).toBe('CANCELLED_IMMEDIATELY');
      }
    });
  }
);
