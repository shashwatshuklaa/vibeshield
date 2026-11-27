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
      expect(winners[0]!.scan.isActive).toBe(true);

      // Lease fencing token must NEVER leak in ordinary ScanModel reads
      const rawDoc = await ScanModel.findById(scan.id).lean();
      expect((rawDoc?.lease as Record<string, unknown> | undefined)?.token).toBeUndefined();
    });

    it('rejects expired leases before any replacement worker reclaims and enforces isActive across transitions', async () => {
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
        now: t0,
      });
      expect(scan.status).toBe(ScanLifecycleStatusValue.QUEUED);
      expect(scan.isActive).toBe(true);

      const claimed = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-expire',
        leaseDurationMs: 5_000,
        now: t0,
      });
      expect(claimed.status).toBe('CLAIMED');
      if (claimed.status !== 'CLAIMED') throw new Error('Expected claimed');
      expect(claimed.scan.isActive).toBe(true);

      // Once lease expires (t0 + 6s) BEFORE any replacement worker reclaims, stale owner cannot mutate anything
      const tExpired = new Date(t0.getTime() + 6_000);
      expect(
        (
          await renewScanWorkerLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claimed.leaseToken,
            now: tExpired,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await transitionScanToInProgress({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claimed.leaseToken,
            acquisition: {
              resolvedCommitSha: 'a'.repeat(40),
              compressedArchiveBytes: 100,
              extractedBytes: 200,
              extractedFileCount: 1,
            },
            now: tExpired,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await completeScanWithLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claimed.leaseToken,
            now: tExpired,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await failScanWithLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claimed.leaseToken,
            failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
            failureMessage: 'Should be rejected due to expired lease',
            now: tExpired,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await cancelScanWithLease({
            scanId: scan.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claimed.leaseToken,
            now: tExpired,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
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
      expect(inProgressRes.scan?.isActive).toBe(true);
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
        expect(ackCancel.scan?.isActive).toBe(false);
      } else {
        expect(claimOutcome.status).toBe('CANCELLED');
        expect(claimOutcome.scan.isActive).toBe(false);
        expect(cancelOutcome.status).toBe('CANCELLED_IMMEDIATELY');
        expect(cancelOutcome.scan.isActive).toBe(false);
      }
    });

    it('clears stale acquisition metadata on IN_PROGRESS reclaim and rejects old worker completion', async () => {
      const t0 = new Date('2026-11-27T12:10:00Z');
      const scan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'release/v2',
        requestedCommitHash: '1234567abcdef',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
        maxAttempts: 3,
        now: t0,
      });

      const claimA = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-inprogress-crash',
        leaseDurationMs: 5_000,
        now: t0,
      });
      if (claimA.status !== 'CLAIMED') throw new Error('Expected claimA');

      const started = await transitionScanToInProgress({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claimA.leaseToken,
        acquisition: {
          resolvedCommitSha: 'f'.repeat(40),
          compressedArchiveBytes: 4096,
          extractedBytes: 16_384,
          extractedFileCount: 80,
        },
        now: new Date(t0.getTime() + 1_000),
      });
      expect(started.status).toBe('UPDATED');
      expect(started.scan?.isActive).toBe(true);

      // Simulate worker crash & lease expiration during IN_PROGRESS
      const tReclaim = new Date(t0.getTime() + 6_000);
      const reclaimedB = await reclaimExpiredScanLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-recovery',
        leaseDurationMs: 10_000,
        now: tReclaim,
      });
      expect(reclaimedB.status).toBe('RECLAIMED');
      if (reclaimedB.status !== 'RECLAIMED') throw new Error('Expected reclaimed');

      expect(reclaimedB.scan.status).toBe(ScanLifecycleStatusValue.ACQUIRING);
      expect(reclaimedB.scan.isActive).toBe(true);
      expect(reclaimedB.scan.attemptCount).toBe(2);
      // Stale previous-attempt acquisition fields must be wiped; scan-level metadata preserved
      expect(reclaimedB.scan.resolvedCommitSha).toBeNull();
      expect(reclaimedB.scan.acquisition).toBeNull();
      expect(reclaimedB.scan.inProgressAt).toBeNull();
      expect(reclaimedB.scan.requestedRef).toBe('release/v2');
      expect(reclaimedB.scan.requestedCommitHash).toBe('1234567abcdef');
      expect(reclaimedB.scan.triggerSource).toBe(ScanTriggerSourceValue.MANUAL);
      expect(reclaimedB.scan.createdByUserId).toBe(userA);
      expect(new Date(reclaimedB.scan.queuedAt).getTime()).toBe(t0.getTime());

      // Old worker calling completeScanWithLease after reclaim must be rejected cleanly
      const oldComplete = await completeScanWithLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claimA.leaseToken,
        now: new Date(tReclaim.getTime() + 500),
      });
      expect(oldComplete.status).toBe('STALE_OR_CONFLICT');
    });

    it('prevents cancellation from being overwritten by IN_PROGRESS completion or failure and blocks post-cancel stale updates', async () => {
      // 1. Sequential: IN_PROGRESS cancel blocks both completion and failure, then stale updates rejected after CANCELLED
      const scan1 = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      const claim1 = await claimQueuedScanForAcquisition({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-1',
        leaseDurationMs: 30_000,
      });
      if (claim1.status !== 'CLAIMED') throw new Error('Expected claim1');

      await transitionScanToInProgress({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claim1.leaseToken,
        acquisition: {
          resolvedCommitSha: '1'.repeat(40),
          compressedArchiveBytes: 256,
          extractedBytes: 512,
          extractedFileCount: 4,
        },
      });

      const cancelReq = await requestScanCancellation({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        requestedByUserId: userA,
        reason: 'Stop active IN_PROGRESS scan',
      });
      expect(cancelReq.status).toBe('CANCELLATION_REQUESTED');

      const blockedComplete = await completeScanWithLease({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claim1.leaseToken,
      });
      expect(blockedComplete.status).toBe('CANCEL_REQUESTED');
      expect(blockedComplete.scan?.status).toBe(ScanLifecycleStatusValue.IN_PROGRESS);

      const blockedFail = await failScanWithLease({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claim1.leaseToken,
        failureCode: ScanFailureCodeValue.SCANNER_EXECUTION_FAILED,
        failureMessage: 'Should not become FAILED after cancel request',
      });
      expect(blockedFail.status).toBe('CANCEL_REQUESTED');

      const cancelled = await cancelScanWithLease({
        scanId: scan1.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claim1.leaseToken,
      });
      expect(cancelled.status).toBe('UPDATED');
      expect(cancelled.scan?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
      expect(cancelled.scan?.isActive).toBe(false);
      expect(cancelled.scan?.lease).toBeNull();

      // Any subsequent stale worker attempt after terminal CANCELLED is rejected
      expect(
        (
          await renewScanWorkerLease({
            scanId: scan1.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claim1.leaseToken,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await completeScanWithLease({
            scanId: scan1.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claim1.leaseToken,
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');
      expect(
        (
          await failScanWithLease({
            scanId: scan1.id,
            organizationId: orgA,
            projectId: projectA1,
            leaseToken: claim1.leaseToken,
            failureCode: ScanFailureCodeValue.WORKER_INTERNAL_ERROR,
            failureMessage: 'Late worker error',
          })
        ).status
      ).toBe('STALE_OR_CONFLICT');

      // 2. Concurrent race: requestScanCancellation vs completeScanWithLease
      const scanCompleteRace = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      const claimCR = await claimQueuedScanForAcquisition({
        scanId: scanCompleteRace.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-complete-race',
        leaseDurationMs: 30_000,
      });
      if (claimCR.status !== 'CLAIMED') throw new Error('Expected claimCR');
      await transitionScanToInProgress({
        scanId: scanCompleteRace.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claimCR.leaseToken,
        acquisition: {
          resolvedCommitSha: '2'.repeat(40),
          compressedArchiveBytes: 256,
          extractedBytes: 512,
          extractedFileCount: 4,
        },
      });

      const [cancelResCR, completeResCR] = await Promise.all([
        requestScanCancellation({
          scanId: scanCompleteRace.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
          reason: 'Concurrent cancel vs complete',
        }),
        completeScanWithLease({
          scanId: scanCompleteRace.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimCR.leaseToken,
        }),
      ]);

      if (completeResCR.status === 'UPDATED') {
        expect(completeResCR.scan?.status).toBe(ScanLifecycleStatusValue.COMPLETED);
        expect(completeResCR.scan?.isActive).toBe(false);
        expect(cancelResCR.status).toBe('ALREADY_TERMINAL');
      } else {
        expect(completeResCR.status).toBe('CANCEL_REQUESTED');
        expect(cancelResCR.status).toBe('CANCELLATION_REQUESTED');
        const finalized = await cancelScanWithLease({
          scanId: scanCompleteRace.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimCR.leaseToken,
        });
        expect(finalized.status).toBe('UPDATED');
        expect(finalized.scan?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
        expect(finalized.scan?.isActive).toBe(false);
      }

      // 3. Concurrent race: requestScanCancellation vs failScanWithLease
      const scanFailRace = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      const claimFR = await claimQueuedScanForAcquisition({
        scanId: scanFailRace.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-fail-race',
        leaseDurationMs: 30_000,
      });
      if (claimFR.status !== 'CLAIMED') throw new Error('Expected claimFR');
      await transitionScanToInProgress({
        scanId: scanFailRace.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claimFR.leaseToken,
        acquisition: {
          resolvedCommitSha: '3'.repeat(40),
          compressedArchiveBytes: 256,
          extractedBytes: 512,
          extractedFileCount: 4,
        },
      });

      const [cancelResFR, failResFR] = await Promise.all([
        requestScanCancellation({
          scanId: scanFailRace.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
          reason: 'Concurrent cancel vs fail',
        }),
        failScanWithLease({
          scanId: scanFailRace.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimFR.leaseToken,
          failureCode: ScanFailureCodeValue.SCANNER_EXECUTION_FAILED,
          failureMessage: 'Concurrent scanner error',
        }),
      ]);

      if (failResFR.status === 'UPDATED') {
        expect(failResFR.scan?.status).toBe(ScanLifecycleStatusValue.FAILED);
        expect(failResFR.scan?.isActive).toBe(false);
        expect(cancelResFR.status).toBe('ALREADY_TERMINAL');
      } else {
        expect(failResFR.status).toBe('CANCEL_REQUESTED');
        expect(cancelResFR.status).toBe('CANCELLATION_REQUESTED');
        const finalized = await cancelScanWithLease({
          scanId: scanFailRace.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimFR.leaseToken,
        });
        expect(finalized.status).toBe('UPDATED');
        expect(finalized.scan?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
        expect(finalized.scan?.isActive).toBe(false);
      }
    });

    it('resolves cancellation racing with normal and exhausted lease reclaim deterministically and preserves post-terminal idempotency', async () => {
      const t0 = new Date('2026-11-27T12:20:00Z');
      const tExpired = new Date(t0.getTime() + 10_000);

      // 1. Concurrent race: requestScanCancellation vs reclaimExpiredScanLease (maxAttempts: 3)
      const reclaimRaceScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.SYSTEM,
        maxAttempts: 3,
        now: t0,
      });
      await claimQueuedScanForAcquisition({
        scanId: reclaimRaceScan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-crashed',
        leaseDurationMs: 2_000,
        now: t0,
      });

      const [cancelReclaimRes, reclaimRes] = await Promise.all([
        requestScanCancellation({
          scanId: reclaimRaceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
          reason: 'Cancel racing with reclaim',
          now: tExpired,
        }),
        reclaimExpiredScanLease({
          scanId: reclaimRaceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-new-reclaim',
          leaseDurationMs: 10_000,
          now: tExpired,
        }),
      ]);

      if (reclaimRes.status === 'RECLAIMED') {
        expect(['CANCELLATION_REQUESTED', 'ALREADY_TERMINAL']).toContain(cancelReclaimRes.status);
        const ack = await cancelScanWithLease({
          scanId: reclaimRaceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: reclaimRes.leaseToken,
          now: new Date(tExpired.getTime() + 500),
        });
        expect(ack.status).toBe('UPDATED');
        expect(ack.scan?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
        expect(ack.scan?.isActive).toBe(false);
      } else {
        expect(reclaimRes.status).toBe('CANCELLED');
        expect(reclaimRes.scan.isActive).toBe(false);
      }

      // 2. Concurrent race: requestScanCancellation vs exhausted-attempt reclaim (maxAttempts: 1)
      const exhaustedRaceScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.SYSTEM,
        maxAttempts: 1,
        idempotencyKey: 'exhausted-key-1',
        now: t0,
      });
      await claimQueuedScanForAcquisition({
        scanId: exhaustedRaceScan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'worker-exhausted',
        leaseDurationMs: 2_000,
        now: t0,
      });

      const [cancelExhaustedRes, reclaimExhaustedRes] = await Promise.all([
        requestScanCancellation({
          scanId: exhaustedRaceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
          reason: 'Cancel racing with exhausted reclaim',
          now: tExpired,
        }),
        reclaimExpiredScanLease({
          scanId: exhaustedRaceScan.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'worker-new-exhausted',
          leaseDurationMs: 10_000,
          now: tExpired,
        }),
      ]);

      const reloadedFinal = await findScanByIdInOrganization({
        scanId: exhaustedRaceScan.id,
        organizationId: orgA,
        projectId: projectA1,
      });
      expect(reloadedFinal?.isActive).toBe(false);

      if (reclaimExhaustedRes.status === 'MAX_ATTEMPTS_EXHAUSTED') {
        expect(reloadedFinal?.status).toBe(ScanLifecycleStatusValue.FAILED);
        expect(reloadedFinal?.cancellation.requestedAt).toBeNull();
        expect(cancelExhaustedRes.status).toBe('ALREADY_TERMINAL');
      } else {
        expect(reclaimExhaustedRes.status).toBe('CANCELLED');
        expect(reloadedFinal?.status).toBe(ScanLifecycleStatusValue.CANCELLED);
      }

      // 3. After terminal state: reusing existing idempotencyKey fails with 11000, while new key or null key succeeds
      await expect(
        createQueuedScan({
          organizationId: orgA,
          projectId: projectA1,
          repositoryConnectionId: connA1,
          githubInstallationId: 1001,
          githubRepositoryId: 2001,
          requestedRef: 'main',
          triggerSource: ScanTriggerSourceValue.SYSTEM,
          idempotencyKey: 'exhausted-key-1',
        })
      ).rejects.toMatchObject({ code: 11000 });

      const freshKeyScan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.SYSTEM,
        idempotencyKey: 'exhausted-key-2',
      });
      expect(freshKeyScan.status).toBe(ScanLifecycleStatusValue.QUEUED);
      expect(freshKeyScan.isActive).toBe(true);

      const unkeyedFollowUp = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
      });
      expect(unkeyedFollowUp.status).toBe(ScanLifecycleStatusValue.QUEUED);
      expect(unkeyedFollowUp.isActive).toBe(true);
    });
  }
);
