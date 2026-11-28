import mongoose from 'mongoose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  ScanTriggerSourceValue,
} from '@vibeshield/types';
import {
  cancelScanWithLease,
  claimPendingScanDispatch,
  claimQueuedScanForAcquisition,
  completeAcquisitionPreparedWithLease,
  completeScanWithLease,
  connectDatabase,
  createQueuedScan,
  createQueuedScanWithOutbox,
  disconnectDatabase,
  failScanWithLease,
  findExpiredActiveScanLeaseCandidates,
  findPendingScanDispatchOutboxCandidates,
  findScanByIdInOrganization,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  listScansByProjectInOrganization,
  loadScanExecutionTarget,
  markScanDispatchSucceeded,
  OrganizationModel,
  OutboxDispatchStateValue,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  rearmScanDispatchOutbox,
  reclaimExpiredScanLease,
  recordScanDispatchFailure,
  recoverExpiredScanLeaseCandidate,
  releaseScanLeaseForRetry,
  renewScanWorkerLease,
  RepositoryAccessStateValue,
  requestScanCancellation,
  runInTransaction,
  ScanDispatchOutboxModel,
  ScanModel,
  setScanResolvedCommitWithLease,
  transitionScanToInProgress,
  verifyScanAcquisitionAuthorization,
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
      await Promise.all([
        OrganizationModel.syncIndexes(),
        ScanModel.syncIndexes(),
        ScanDispatchOutboxModel.syncIndexes(),
      ]);
    });

    beforeEach(async () => {
      await Promise.all([
        OrganizationModel.deleteMany({}),
        ScanModel.deleteMany({}),
        ScanDispatchOutboxModel.deleteMany({}),
      ]);

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

    afterEach(() => {
      vi.restoreAllMocks();
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

    it('enforces every scan acquisition authorization invariant against real MongoDB documents', async () => {
      await Promise.all([
        ProjectModel.deleteMany({}),
        ProjectRepositoryConnectionModel.deleteMany({}),
        GitHubInstallationModel.deleteMany({}),
      ]);

      const projectDoc = await ProjectModel.create({
        organizationId: orgA,
        name: 'Authz Project',
        slug: 'authz-project',
        createdBy: userA,
      });

      const installationDoc = await GitHubInstallationModel.create({
        organizationId: orgA,
        githubInstallationId: 5001,
        githubAppId: 9001,
        accountId: 7001,
        accountLogin: 'acme-sec',
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read' },
        status: GitHubInstallationStatusValue.ACTIVE,
        isActive: true,
        connectedByUserId: userA,
        lastSyncedAt: new Date(),
      });

      const connectionDoc = await ProjectRepositoryConnectionModel.create({
        organizationId: orgA,
        projectId: projectDoc._id,
        installationRecordId: installationDoc._id,
        githubInstallationId: 5001,
        githubRepositoryId: 8001,
        ownerLogin: 'acme-sec',
        repoName: 'web-app',
        fullName: 'acme-sec/web-app',
        defaultBranch: 'main',
        isPrivate: true,
        isArchivedOnGitHub: false,
        repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
        installationAvailability: InstallationAvailabilityValue.ACTIVE,
        connectedByUserId: userA,
        connectedAt: new Date(),
        lastSyncedAt: new Date(),
      });

      const t0 = new Date('2026-11-28T01:00:00Z');
      const queued = await createQueuedScan({
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        repositoryConnectionId: connectionDoc._id.toString(),
        githubInstallationId: 5001,
        githubRepositoryId: 8001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
        now: t0,
      });

      // Normal reads must never expose lease.token (`select: false`)
      const defaultRead = await ScanModel.findById(queued.id).lean();
      expect((defaultRead?.lease as { token?: string } | null)?.token).toBeUndefined();

      // Still QUEUED (not ACQUIRING) -> denied
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: 'non_existent_token_123456',
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'SCAN_NOT_ACQUIRING' });

      const claimed = await claimQueuedScanForAcquisition({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        workerId: 'security-worker',
        leaseDurationMs: 30_000,
        now: t0,
      });
      expect(claimed.status).toBe('CLAIMED');
      if (claimed.status !== 'CLAIMED') {
        throw new Error('Expected scan claim to succeed');
      }

      // 1. Valid active authorization passes and returns minimal safe context (no leaseToken)
      const ok = await verifyScanAcquisitionAuthorization({
        scanId: queued.id,
        leaseToken: claimed.leaseToken,
        workerId: 'security-worker',
        now: new Date(t0.getTime() + 1_000),
      });
      expect(ok.status).toBe('AUTHORIZED');
      if (ok.status !== 'AUTHORIZED') {
        throw new Error('Expected authorization to succeed');
      }
      expect(ok.context).toMatchObject({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        repositoryConnectionId: connectionDoc._id.toString(),
        githubInstallationId: 5001,
        githubRepositoryId: 8001,
        repositoryOwner: 'acme-sec',
        repositoryName: 'web-app',
        requestedRef: 'main',
        attemptCount: 1,
        maxAttempts: 3,
        workerId: 'security-worker',
      });
      expect(JSON.stringify(ok.context)).not.toContain(claimed.leaseToken);

      // Fenced resolvedCommitSha persistence works only under active unexpired lease & no cancellation
      const resolvedSha = 'f'.repeat(40);
      const commitPersistOk = await setScanResolvedCommitWithLease({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        leaseToken: claimed.leaseToken,
        resolvedCommitSha: resolvedSha,
        now: new Date(t0.getTime() + 1_500),
      });
      expect(commitPersistOk.status).toBe('UPDATED');
      expect(commitPersistOk.scan?.resolvedCommitSha).toBe(resolvedSha);
      expect(commitPersistOk.scan?.status).toBe(ScanLifecycleStatusValue.ACQUIRING);

      await expect(
        setScanResolvedCommitWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectDoc._id.toString(),
          leaseToken: 'stale_wrong_fencing_token_1234',
          resolvedCommitSha: 'a'.repeat(40),
          now: new Date(t0.getTime() + 1_500),
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // 2. Missing scan -> SCAN_NOT_FOUND
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: new mongoose.Types.ObjectId().toString(),
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'SCAN_NOT_FOUND' });

      // 3. Wrong lease token (different length & same length) -> INVALID_LEASE_TOKEN
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: 'short',
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'INVALID_LEASE_TOKEN' });

      const sameLengthWrongToken = `${claimed.leaseToken.slice(0, -1)}${claimed.leaseToken.endsWith('0') ? '1' : '0'}`;
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: sameLengthWrongToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'INVALID_LEASE_TOKEN' });

      // 4. Wrong workerId -> WORKER_MISMATCH
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'other-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'WORKER_MISMATCH' });

      // 5. Expired lease -> LEASE_EXPIRED
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: new Date(t0.getTime() + 31_000),
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'LEASE_EXPIRED' });

      // 6. Metadata mismatch -> CONNECTION_METADATA_MISMATCH
      await ScanModel.updateOne({ _id: queued.id }, { $set: { githubRepositoryId: 9999 } });
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'CONNECTION_METADATA_MISMATCH' });
      await ScanModel.updateOne({ _id: queued.id }, { $set: { githubRepositoryId: 8001 } });

      // Unsafe repository owner/name path segments are rejected
      await ProjectRepositoryConnectionModel.updateOne(
        { _id: connectionDoc._id },
        { $set: { ownerLogin: '../evil' } }
      );
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'CONNECTION_METADATA_MISMATCH' });
      await ProjectRepositoryConnectionModel.updateOne(
        { _id: connectionDoc._id },
        { $set: { ownerLogin: 'acme-sec' } }
      );

      // 7. Disconnected/revoked connection -> CONNECTION_INACTIVE
      await ProjectRepositoryConnectionModel.updateOne(
        { _id: connectionDoc._id },
        { $set: { repositoryAccessState: RepositoryAccessStateValue.ACCESS_REVOKED } }
      );
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'CONNECTION_INACTIVE' });
      await ProjectRepositoryConnectionModel.updateOne(
        { _id: connectionDoc._id },
        { $set: { repositoryAccessState: RepositoryAccessStateValue.CONNECTED } }
      );

      // 8. Suspended installation -> INSTALLATION_UNAVAILABLE
      await GitHubInstallationModel.updateOne(
        { _id: installationDoc._id },
        {
          $set: {
            status: GitHubInstallationStatusValue.SUSPENDED,
            suspendedAt: t0,
          },
        }
      );
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'INSTALLATION_UNAVAILABLE' });
      await GitHubInstallationModel.updateOne(
        { _id: installationDoc._id },
        {
          $set: {
            status: GitHubInstallationStatusValue.ACTIVE,
            suspendedAt: null,
          },
        }
      );

      // 9. Archived project -> PROJECT_ARCHIVED
      await ProjectModel.updateOne({ _id: projectDoc._id }, { $set: { archivedAt: t0 } });
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'PROJECT_ARCHIVED' });
      await ProjectModel.updateOne({ _id: projectDoc._id }, { $set: { archivedAt: null } });

      // 10. Cross-organization project mismatch -> PROJECT_NOT_FOUND
      await ProjectModel.updateOne({ _id: projectDoc._id }, { $set: { organizationId: orgB } });
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'PROJECT_NOT_FOUND' });
      await ProjectModel.updateOne({ _id: projectDoc._id }, { $set: { organizationId: orgA } });

      // 11. Cancellation requested -> SCAN_CANCELLED
      await requestScanCancellation({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        requestedByUserId: userA,
        reason: 'Stop before download',
        now: t0,
      });
      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: queued.id,
          leaseToken: claimed.leaseToken,
          workerId: 'security-worker',
          now: t0,
        })
      ).resolves.toMatchObject({ status: 'DENIED', reason: 'SCAN_CANCELLED' });

      // Clean up test fixtures cleanly
      await Promise.all([
        ProjectRepositoryConnectionModel.deleteMany({ _id: connectionDoc._id }),
        GitHubInstallationModel.deleteMany({ _id: installationDoc._id }),
        ProjectModel.deleteMany({ _id: projectDoc._id }),
      ]);
    });

    it('transitions ACQUIRING -> PREPARED atomically with DB commit SHA, seals terminal state against cancel/complete/fail/stale races', async () => {
      const t0 = new Date('2026-11-28T12:00:00.000Z');
      const queued = await createQueuedScan({
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

      const claimed = await claimQueuedScanForAcquisition({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'security-worker',
        leaseDurationMs: 30_000,
        now: t0,
      });
      expect(claimed.status).toBe('CLAIMED');
      if (claimed.status !== 'CLAIMED') {
        return;
      }

      const authoritativeSha = 'e'.repeat(40);
      await setScanResolvedCommitWithLease({
        scanId: queued.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: claimed.leaseToken,
        resolvedCommitSha: authoritativeSha,
        now: t0,
      });

      const prepTime = new Date(t0.getTime() + 1_000);
      const [prep1, prep2] = await Promise.all([
        completeAcquisitionPreparedWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimed.leaseToken,
          acquisition: {
            compressedArchiveBytes: 4096,
            extractedBytes: 16384,
            extractedFileCount: 18,
          },
          now: prepTime,
        }),
        completeAcquisitionPreparedWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimed.leaseToken,
          acquisition: {
            compressedArchiveBytes: 9999,
            extractedBytes: 99999,
            extractedFileCount: 99,
          },
          now: prepTime,
        }),
      ]);

      const outcomes = [prep1.status, prep2.status];
      expect(outcomes.filter((s) => s === 'PREPARED')).toHaveLength(1);
      expect(outcomes.filter((s) => s === 'INVALID_TRANSITION')).toHaveLength(1);

      const preparedRecord =
        prep1.status === 'PREPARED' ? prep1.scan : (prep2 as { scan: typeof queued }).scan;
      expect(preparedRecord.status).toBe(ScanLifecycleStatusValue.PREPARED);
      expect(preparedRecord.isActive).toBe(false);
      expect(preparedRecord.preparedAt).toEqual(prepTime);
      expect(preparedRecord.completedAt).toBeNull();
      expect(preparedRecord.lease).toBeNull();
      expect(preparedRecord.acquisition?.resolvedCommitSha).toBe(authoritativeSha);

      // Cannot be cancelled, claimed, reclaimed, completed, or failed once PREPARED
      await expect(
        requestScanCancellation({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          requestedByUserId: userA,
        })
      ).resolves.toMatchObject({ status: 'ALREADY_TERMINAL', scan: { status: 'PREPARED' } });

      await expect(
        claimQueuedScanForAcquisition({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'security-worker',
        })
      ).resolves.toMatchObject({ status: 'NOT_CLAIMABLE', currentStatus: 'PREPARED' });

      await expect(
        reclaimExpiredScanLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'security-worker',
          now: new Date(t0.getTime() + 120_000),
        })
      ).resolves.toMatchObject({ status: 'NOT_RECLAIMABLE' });

      await expect(
        completeScanWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimed.leaseToken,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        failScanWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimed.leaseToken,
          failureCode: ScanFailureCodeValue.WORKER_INTERNAL_ERROR,
          failureMessage: 'Should not overwrite PREPARED',
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        cancelScanWithLease({
          scanId: queued.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: claimed.leaseToken,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });
    });

    it('supports releaseScanLeaseForRetry preserving attemptCount/idempotencyKey and fences stale tokens after reclaim', async () => {
      const t0 = new Date('2026-11-28T12:10:00.000Z');
      const scan = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.WEBHOOK,
        idempotencyKey: 'retry-idem-key-1',
        maxAttempts: 2,
        now: t0,
      });

      const attempt1 = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'security-worker',
        leaseDurationMs: 10_000,
        now: t0,
      });
      expect(attempt1.status).toBe('CLAIMED');
      if (attempt1.status !== 'CLAIMED') {
        return;
      }

      // Persist resolved SHA on attempt 1, then release for retry -> clears transient resolvedCommitSha & lease
      await setScanResolvedCommitWithLease({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: attempt1.leaseToken,
        resolvedCommitSha: 'a'.repeat(40),
        now: t0,
      });

      const released = await releaseScanLeaseForRetry({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        leaseToken: attempt1.leaseToken,
        now: new Date(t0.getTime() + 1_000),
      });
      expect(released.status).toBe('RELEASED');
      if (released.status === 'RELEASED') {
        expect(released.scan.status).toBe(ScanLifecycleStatusValue.QUEUED);
        expect(released.scan.isActive).toBe(true);
        expect(released.scan.attemptCount).toBe(1);
        expect(released.scan.resolvedCommitSha).toBeNull();
        expect(released.scan.lease).toBeNull();
      }

      // Verify idempotencyKey preserved
      const rawReleased = await ScanModel.findById(scan.id).lean();
      expect(rawReleased?.idempotencyKey).toBe('retry-idem-key-1');

      // Attempt 2 claims and advances attemptCount to 2 (= maxAttempts) -> releaseScanLeaseForRetry returns ATTEMPTS_EXHAUSTED
      const attempt2 = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        workerId: 'security-worker',
        leaseDurationMs: 10_000,
        now: new Date(t0.getTime() + 2_000),
      });
      expect(attempt2.status).toBe('CLAIMED');
      if (attempt2.status !== 'CLAIMED') {
        return;
      }

      // Old attempt 1 token cannot release or prepare attempt 2
      await expect(
        releaseScanLeaseForRetry({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: attempt1.leaseToken,
          now: new Date(t0.getTime() + 3_000),
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        completeAcquisitionPreparedWithLease({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: attempt1.leaseToken,
          acquisition: { compressedArchiveBytes: 10, extractedBytes: 20, extractedFileCount: 1 },
          now: new Date(t0.getTime() + 3_000),
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        releaseScanLeaseForRetry({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
          leaseToken: attempt2.leaseToken,
          now: new Date(t0.getTime() + 3_000),
        })
      ).resolves.toMatchObject({ status: 'ATTEMPTS_EXHAUSTED' });
    });

    it('recovers expired active leases safely under concurrent sweepers across recoverable, cancelled, and exhausted states', async () => {
      const t0 = new Date('2026-11-28T12:20:00.000Z');
      const expiredTime = new Date(t0.getTime() + 20_000);

      const sRecoverable = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        maxAttempts: 3,
        now: t0,
      });
      const sCancel = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2002,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        maxAttempts: 3,
        now: t0,
      });
      const sExhausted = await createQueuedScan({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 2003,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        maxAttempts: 1,
        now: t0,
      });

      const [c1, c2, c3] = await Promise.all([
        claimQueuedScanForAcquisition({
          scanId: sRecoverable.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'security-worker',
          leaseDurationMs: 5_000,
          now: t0,
        }),
        claimQueuedScanForAcquisition({
          scanId: sCancel.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'security-worker',
          leaseDurationMs: 5_000,
          now: t0,
        }),
        claimQueuedScanForAcquisition({
          scanId: sExhausted.id,
          organizationId: orgA,
          projectId: projectA1,
          workerId: 'security-worker',
          leaseDurationMs: 5_000,
          now: t0,
        }),
      ]);
      expect(c1.status).toBe('CLAIMED');
      expect(c2.status).toBe('CLAIMED');
      expect(c3.status).toBe('CLAIMED');

      await requestScanCancellation({
        scanId: sCancel.id,
        organizationId: orgA,
        projectId: projectA1,
        requestedByUserId: userA,
        now: t0,
      });

      const candidates = await findExpiredActiveScanLeaseCandidates({ now: expiredTime });
      expect(candidates.map((c) => c.scanId)).toEqual(
        expect.arrayContaining([sRecoverable.id, sCancel.id, sExhausted.id])
      );

      // Two sweepers race simultaneously on each expired scan -> exactly one mutates each scan
      const [rA, rB] = await Promise.all([
        recoverExpiredScanLeaseCandidate({
          scanId: sRecoverable.id,
          organizationId: orgA,
          projectId: projectA1,
          now: expiredTime,
        }),
        recoverExpiredScanLeaseCandidate({
          scanId: sRecoverable.id,
          organizationId: orgA,
          projectId: projectA1,
          now: expiredTime,
        }),
      ]);
      expect([rA.status, rB.status].sort()).toEqual(['ALREADY_HANDLED', 'REQUEUED_FOR_RECOVERY']);

      const cancelRec = await recoverExpiredScanLeaseCandidate({
        scanId: sCancel.id,
        organizationId: orgA,
        projectId: projectA1,
        now: expiredTime,
      });
      expect(cancelRec).toMatchObject({
        status: 'FINALIZED_CANCELLED',
        scan: { status: 'CANCELLED', isActive: false },
      });

      const exhaustRec = await recoverExpiredScanLeaseCandidate({
        scanId: sExhausted.id,
        organizationId: orgA,
        projectId: projectA1,
        now: expiredTime,
      });
      expect(exhaustRec).toMatchObject({
        status: 'FINALIZED_EXHAUSTED',
        scan: {
          status: 'FAILED',
          isActive: false,
          failureCode: ScanFailureCodeValue.LEASE_EXPIRED,
        },
      });
    });

    it('creates scan + outbox atomically, rolls back on failure, fences dispatch generations, and suppresses terminal scans', async () => {
      const t0 = new Date('2026-11-28T12:30:00.000Z');

      // 1. Atomic creation creates both Scan and Outbox gen 1 cleanly
      const { scan, outbox, jobId } = await createQueuedScanWithOutbox({
        organizationId: orgA,
        projectId: projectA1,
        repositoryConnectionId: connA1,
        githubInstallationId: 1001,
        githubRepositoryId: 3001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
        now: t0,
      });
      expect(jobId).toBe(`scan-${scan.id}-1`);
      expect(outbox.state).toBe(OutboxDispatchStateValue.PENDING);
      expect(outbox.organizationId).toBe(orgA);
      expect(outbox.projectId).toBe(projectA1);

      // Unique scanId constraint on outbox
      await expect(
        ScanDispatchOutboxModel.create({
          scanId: scan.id,
          organizationId: orgA,
          projectId: projectA1,
        })
      ).rejects.toMatchObject({ code: 11000 });

      // 2. Rollback proof (both directions):
      // (a) Outbox creation fails after Scan insert -> Scan insert inside createQueuedScanWithOutbox rolls back
      const scansBeforeRollback = await ScanModel.countDocuments({ organizationId: orgA });
      const outboxBeforeRollback = await ScanDispatchOutboxModel.countDocuments({
        organizationId: orgA,
      });
      vi.spyOn(ScanDispatchOutboxModel, 'create').mockRejectedValueOnce(
        new Error('Simulated outbox failure after scan insert')
      );
      await expect(
        createQueuedScanWithOutbox({
          organizationId: orgA,
          projectId: projectA1,
          repositoryConnectionId: connA1,
          githubInstallationId: 1001,
          githubRepositoryId: 3009,
          requestedRef: 'main',
          triggerSource: ScanTriggerSourceValue.MANUAL,
          createdByUserId: userA,
          now: t0,
        })
      ).rejects.toThrow('Simulated outbox failure after scan insert');
      expect(await ScanModel.countDocuments({ organizationId: orgA })).toBe(scansBeforeRollback);
      expect(await ScanDispatchOutboxModel.countDocuments({ organizationId: orgA })).toBe(
        outboxBeforeRollback
      );

      // (b) Subsequent error inside external transaction rolls back both Scan and Outbox created by createQueuedScanWithOutbox
      await expect(
        runInTransaction(async (session) => {
          await createQueuedScanWithOutbox(
            {
              organizationId: orgA,
              projectId: projectA1,
              repositoryConnectionId: connA1,
              githubInstallationId: 1001,
              githubRepositoryId: 3010,
              requestedRef: 'main',
              triggerSource: ScanTriggerSourceValue.MANUAL,
              createdByUserId: userA,
              now: t0,
            },
            session
          );
          throw new Error('Simulated downstream tx abort');
        })
      ).rejects.toThrow('Simulated downstream tx abort');
      expect(await ScanModel.countDocuments({ organizationId: orgA })).toBe(scansBeforeRollback);
      expect(await ScanDispatchOutboxModel.countDocuments({ organizationId: orgA })).toBe(
        outboxBeforeRollback
      );

      // 3. Pending query -> claim -> mark dispatched -> concurrent rearm bumps generation safely & fences old generation!
      const pending = await findPendingScanDispatchOutboxCandidates({ now: t0 });
      expect(pending.some((p) => p.scanId === scan.id)).toBe(true);

      const claimedDispatch = await claimPendingScanDispatch({
        scanId: scan.id,
        dispatchGeneration: 1,
        now: t0,
      });
      expect(claimedDispatch.status).toBe('CLAIMED');

      await expect(
        markScanDispatchSucceeded({ scanId: scan.id, dispatchGeneration: 1, now: t0 })
      ).resolves.toMatchObject({
        status: 'DISPATCHED',
        outbox: { state: 'DISPATCHED', dispatchGeneration: 1 },
      });

      // Concurrent re-arm expecting generation 1 -> only 1 succeeds, incrementing generation to 2
      const [rearm1, rearm2] = await Promise.all([
        rearmScanDispatchOutbox({ scanId: scan.id, expectedGeneration: 1, now: t0 }),
        rearmScanDispatchOutbox({ scanId: scan.id, expectedGeneration: 1, now: t0 }),
      ]);
      const rearmStatuses = [rearm1.status, rearm2.status].sort();
      expect(rearmStatuses).toEqual(['REARMED', 'STALE_OR_CONFLICT']);
      const rearmedOutbox = rearm1.status === 'REARMED' ? rearm1 : (rearm2 as typeof rearm1);
      if (rearmedOutbox.status === 'REARMED') {
        expect(rearmedOutbox.outbox.dispatchGeneration).toBe(2);
        expect(rearmedOutbox.jobId).toBe(`scan-${scan.id}-2`);
      }

      // Old dispatcher (generation 1) CANNOT succeed or record failure over generation 2
      await expect(
        markScanDispatchSucceeded({ scanId: scan.id, dispatchGeneration: 1, now: t0 })
      ).resolves.toEqual({ status: 'STALE_GENERATION' });
      await expect(
        recordScanDispatchFailure({
          scanId: scan.id,
          dispatchGeneration: 1,
          errorMessage: 'Old attempt failure',
          now: t0,
        })
      ).resolves.toEqual({ status: 'STALE_GENERATION' });

      // Cancelling scan causes pending claim & re-arm to suppress outbox cleanly
      await requestScanCancellation({
        scanId: scan.id,
        organizationId: orgA,
        projectId: projectA1,
        requestedByUserId: userA,
        now: t0,
      });
      await expect(
        claimPendingScanDispatch({
          scanId: scan.id,
          dispatchGeneration: 2,
          now: t0,
        })
      ).resolves.toMatchObject({
        status: 'SUPPRESSED',
        outbox: { state: 'SUPPRESSED' },
      });
    });

    it('loads authoritative ScanExecutionTarget without exposing lease.token', async () => {
      const t0 = new Date('2026-11-28T12:40:00.000Z');
      const projectDoc = await ProjectModel.create({
        organizationId: orgA,
        name: 'Target Loader Project',
        slug: 'target-loader-project',
        createdBy: userA,
      });
      const instDoc = await GitHubInstallationModel.create({
        organizationId: orgA,
        githubInstallationId: 9101,
        githubAppId: 9001,
        accountLogin: 'acme-target',
        accountId: 8101,
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read' },
        status: GitHubInstallationStatusValue.ACTIVE,
        isActive: true,
        connectedByUserId: userA,
        lastSyncedAt: t0,
      });
      const connDoc = await ProjectRepositoryConnectionModel.create({
        organizationId: orgA,
        projectId: projectDoc._id,
        installationRecordId: instDoc._id,
        githubInstallationId: 9101,
        githubRepositoryId: 7101,
        ownerLogin: 'acme-target',
        repoName: 'web-app',
        fullName: 'acme-target/web-app',
        defaultBranch: 'main',
        isPrivate: true,
        repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
        installationAvailability: InstallationAvailabilityValue.ACTIVE,
        isActive: true,
        connectedByUserId: userA,
      });
      const created = await createQueuedScan({
        organizationId: orgA,
        projectId: projectDoc._id.toString(),
        repositoryConnectionId: connDoc._id.toString(),
        githubInstallationId: 9101,
        githubRepositoryId: 7101,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userA,
        now: t0,
      });

      const targetRes = await loadScanExecutionTarget(created.id);
      expect(targetRes.status).toBe('EXECUTABLE');
      if (targetRes.status === 'EXECUTABLE') {
        expect(targetRes.target.organizationId).toBe(orgA);
        expect(targetRes.target.projectId).toBe(projectDoc._id.toString());
        expect(targetRes.target.repositoryOwner).toBe('acme-target');
        expect(targetRes.target.repositoryName).toBe('web-app');
        expect((targetRes.target.lease as Record<string, unknown> | null)?.token).toBeUndefined();
      }

      await Promise.all([
        ProjectRepositoryConnectionModel.deleteMany({ _id: connDoc._id }),
        GitHubInstallationModel.deleteMany({ _id: instDoc._id }),
        ProjectModel.deleteMany({ _id: projectDoc._id }),
      ]);
    });
  }
);
