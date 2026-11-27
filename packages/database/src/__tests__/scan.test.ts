import mongoose from 'mongoose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  ScanTriggerSourceValue,
} from '@vibeshield/types';
import {
  cancelScanWithLease,
  claimQueuedScanForAcquisition,
  completeScanWithLease,
  createQueuedScan,
  failScanWithLease,
  isValidScanLifecycleTransition,
  renewScanWorkerLease,
  ScanLifecycleError,
  ScanModel,
  toPublicScanRecord,
  transitionScanToInProgress,
  verifyScanAcquisitionAuthorization,
} from '../index.js';

function makeValidScanInput(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: new mongoose.Types.ObjectId(),
    projectId: new mongoose.Types.ObjectId(),
    repositoryConnectionId: new mongoose.Types.ObjectId(),
    githubInstallationId: 1001,
    githubRepositoryId: 2002,
    requestedRef: 'main',
    requestedCommitHash: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    triggerSource: ScanTriggerSourceValue.MANUAL,
    createdByUserId: new mongoose.Types.ObjectId(),
    status: ScanLifecycleStatusValue.QUEUED,
    isActive: true,
    ...overrides,
  };
}

describe('ScanModel & Scan Lifecycle Unit Tests', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Schema validation, strict fields, and secret redaction', () => {
    it('validates a legitimate scan document and computes active invariant cleanly', () => {
      const doc = new ScanModel(makeValidScanInput());
      expect(doc.validateSync()).toBeUndefined();
      expect(doc.isActive).toBe(true);
      expect(doc.attemptCount).toBe(0);
      expect(doc.lease).toBeNull();
    });

    it('rejects malformed Git refs, invalid SHAs, non-positive GitHub IDs, and active invariant mismatches', async () => {
      const badRef = new ScanModel(makeValidScanInput({ requestedRef: 'feature/../etc/passwd' }));
      expect(badRef.validateSync()?.errors.requestedRef).toBeDefined();

      const badRefLock = new ScanModel(
        makeValidScanInput({ requestedRef: 'refs/heads/main.lock' })
      );
      expect(badRefLock.validateSync()?.errors.requestedRef).toBeDefined();

      const badSha = new ScanModel(makeValidScanInput({ requestedCommitHash: 'not-hex!' }));
      expect(badSha.validateSync()?.errors.requestedCommitHash).toBeDefined();

      const badRepoId = new ScanModel(makeValidScanInput({ githubRepositoryId: 0 }));
      expect(badRepoId.validateSync()?.errors.githubRepositoryId).toBeDefined();

      const mismatchedActive = new ScanModel(
        makeValidScanInput({
          status: ScanLifecycleStatusValue.COMPLETED,
          isActive: true,
        })
      );
      await expect(mismatchedActive.validate()).rejects.toThrow(/isActive/i);
    });

    it('strictly rejects untrusted blob/secret fields and redacts secrets in failure/cancellation text', () => {
      expect(
        () =>
          new ScanModel(
            makeValidScanInput({
              sourceCode: 'should never be persisted',
            })
          )
      ).toThrow(/not in schema/i);

      const doc = new ScanModel(
        makeValidScanInput({
          status: ScanLifecycleStatusValue.FAILED,
          isActive: false,
          failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
          failureMessage:
            'Failed talking to mongodb://admin:MongoPass123!@db.internal:27017 with token ghs_SecretToken123456',
          cancellation: {
            requestedAt: new Date(),
            requestedByUserId: null,
            reason: 'Aborted after error at redis://default:RedisSecret99!@cache:6379',
          },
          lease: {
            workerId: 'worker-1',
            token: 'secret_fencing_token_1234567890',
            acquiredAt: new Date(),
            heartbeatAt: new Date(),
            expiresAt: new Date(Date.now() + 60_000),
          },
        })
      );

      expect(doc.validateSync()).toBeUndefined();
      expect(doc.failureMessage).not.toContain('MongoPass123!');
      expect(doc.failureMessage).not.toContain('ghs_SecretToken123456');
      expect(doc.failureMessage).toContain('[REDACTED_MONGODB_URI]');
      expect(doc.cancellation.reason).not.toContain('RedisSecret99!');
      expect(doc.cancellation.reason).toContain('[REDACTED_REDIS_URL]');

      const serialized = doc.toJSON() as unknown as Record<string, unknown>;
      expect((serialized.lease as Record<string, unknown>).token).toBeUndefined();
      expect((serialized.lease as Record<string, unknown>).workerId).toBe('worker-1');
      expect(serialized.__v).toBeUndefined();

      const publicRecord = toPublicScanRecord(doc);
      expect(publicRecord.lease).toEqual({
        workerId: 'worker-1',
        acquiredAt: doc.lease!.acquiredAt,
        heartbeatAt: doc.lease!.heartbeatAt,
        expiresAt: doc.lease!.expiresAt,
      });
    });
  });

  describe('Lifecycle transition graph & atomic fencing guards', () => {
    it('allows only legal scan lifecycle state transitions and seals terminal states', () => {
      expect(isValidScanLifecycleTransition('QUEUED', 'ACQUIRING')).toBe(true);
      expect(isValidScanLifecycleTransition('QUEUED', 'CANCELLED')).toBe(true);
      expect(isValidScanLifecycleTransition('ACQUIRING', 'IN_PROGRESS')).toBe(true);
      expect(isValidScanLifecycleTransition('IN_PROGRESS', 'COMPLETED')).toBe(true);
      expect(isValidScanLifecycleTransition('IN_PROGRESS', 'ACQUIRING')).toBe(true);

      // Illegal skips and terminal exits
      expect(isValidScanLifecycleTransition('QUEUED', 'COMPLETED')).toBe(false);
      expect(isValidScanLifecycleTransition('QUEUED', 'IN_PROGRESS')).toBe(false);
      expect(isValidScanLifecycleTransition('ACQUIRING', 'COMPLETED')).toBe(false);
      expect(isValidScanLifecycleTransition('COMPLETED', 'IN_PROGRESS')).toBe(false);
      expect(isValidScanLifecycleTransition('FAILED', 'QUEUED')).toBe(false);
      expect(isValidScanLifecycleTransition('CANCELLED', 'ACQUIRING')).toBe(false);
    });

    it('rejects malformed ObjectIds, invalid SHAs, and invalid lease tokens before querying MongoDB', async () => {
      const findOneSpy = vi.spyOn(ScanModel, 'findOneAndUpdate');
      const orgId = new mongoose.Types.ObjectId().toString();
      const projId = new mongoose.Types.ObjectId().toString();
      const scanId = new mongoose.Types.ObjectId().toString();

      await expect(
        createQueuedScan({
          organizationId: 'bad-id',
          projectId: projId,
          repositoryConnectionId: new mongoose.Types.ObjectId().toString(),
          githubInstallationId: 1,
          githubRepositoryId: 2,
          requestedRef: 'main',
          triggerSource: ScanTriggerSourceValue.MANUAL,
        })
      ).rejects.toThrowError(ScanLifecycleError);

      await expect(
        claimQueuedScanForAcquisition({
          scanId,
          organizationId: orgId,
          projectId: projId,
          workerId: 'worker-1',
          leaseDurationMs: 100, // Below minimum 1000ms
        })
      ).rejects.toMatchObject({ code: 'INVALID_LEASE_DURATION' });

      await expect(
        transitionScanToInProgress({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: 'short',
          acquisition: {
            resolvedCommitSha: 'a'.repeat(40),
            compressedArchiveBytes: 100,
            extractedBytes: 200,
            extractedFileCount: 5,
          },
        })
      ).rejects.toMatchObject({ code: 'INVALID_LEASE_TOKEN' });

      await expect(
        transitionScanToInProgress({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: 'valid_fencing_token_1234567890',
          acquisition: {
            resolvedCommitSha: 'too-short',
            compressedArchiveBytes: 100,
            extractedBytes: 200,
            extractedFileCount: 5,
          },
        })
      ).rejects.toMatchObject({ code: 'INVALID_COMMIT_SHA' });

      expect(findOneSpy).not.toHaveBeenCalled();
    });

    it('returns STALE_OR_CONFLICT or CANCEL_REQUESTED when fenced lease updates match zero documents', async () => {
      const orgId = new mongoose.Types.ObjectId().toString();
      const projId = new mongoose.Types.ObjectId().toString();
      const scanId = new mongoose.Types.ObjectId().toString();
      const leaseToken = 'fencing_token_1234567890abcdef';

      vi.spyOn(ScanModel, 'findOneAndUpdate').mockResolvedValue(null);
      const existingAcquiringWithCancel = new ScanModel(
        makeValidScanInput({
          _id: scanId,
          organizationId: orgId,
          projectId: projId,
          status: ScanLifecycleStatusValue.ACQUIRING,
          isActive: true,
          cancellation: {
            requestedAt: new Date(),
            requestedByUserId: null,
            reason: 'User cancelled',
          },
        })
      );
      vi.spyOn(ScanModel, 'findOne').mockResolvedValue(existingAcquiringWithCancel as never);

      const transitionResult = await transitionScanToInProgress({
        scanId,
        organizationId: orgId,
        projectId: projId,
        leaseToken,
        acquisition: {
          resolvedCommitSha: 'b'.repeat(40),
          compressedArchiveBytes: 512,
          extractedBytes: 1024,
          extractedFileCount: 12,
        },
      });
      expect(transitionResult.status).toBe('CANCEL_REQUESTED');

      await expect(
        renewScanWorkerLease({ scanId, organizationId: orgId, projectId: projId, leaseToken })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        completeScanWithLease({ scanId, organizationId: orgId, projectId: projId, leaseToken })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        failScanWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken,
          failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
          failureMessage: 'Failed',
        })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      await expect(
        cancelScanWithLease({ scanId, organizationId: orgId, projectId: projId, leaseToken })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // Active IN_PROGRESS scan with matching valid lease + pending cancellation returns CANCEL_REQUESTED
      const now = new Date();
      const inProgressWithCancel = new ScanModel(
        makeValidScanInput({
          _id: scanId,
          organizationId: orgId,
          projectId: projId,
          status: ScanLifecycleStatusValue.IN_PROGRESS,
          isActive: true,
          lease: {
            workerId: 'worker-1',
            token: leaseToken,
            acquiredAt: now,
            heartbeatAt: now,
            expiresAt: new Date(now.getTime() + 60_000),
          },
          cancellation: {
            requestedAt: now,
            requestedByUserId: null,
            reason: 'User requested cancel',
          },
        })
      );
      vi.spyOn(ScanModel, 'findOne').mockResolvedValue(inProgressWithCancel as never);

      await expect(
        completeScanWithLease({ scanId, organizationId: orgId, projectId: projId, leaseToken, now })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      await expect(
        failScanWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken,
          failureCode: ScanFailureCodeValue.SCANNER_EXECUTION_FAILED,
          failureMessage: 'Tool error',
          now,
        })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      // Stale token on same scan returns STALE_OR_CONFLICT instead of CANCEL_REQUESTED
      await expect(
        completeScanWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: 'wrong_stale_fencing_token_123456',
          now,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });
    });

    it('rejects malformed scanId or invalid workerId before querying authorization models', async () => {
      const findByIdSpy = vi.spyOn(ScanModel, 'findById');

      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: 'not-an-object-id',
          leaseToken: 'valid_token_1234567890',
          workerId: 'security-worker',
        })
      ).rejects.toMatchObject({ code: 'INVALID_SCAN_IDENTIFIER' });

      await expect(
        verifyScanAcquisitionAuthorization({
          scanId: new mongoose.Types.ObjectId().toString(),
          leaseToken: 'valid_token_1234567890',
          workerId: '   ',
        })
      ).rejects.toMatchObject({ code: 'INVALID_WORKER_ID' });

      expect(findByIdSpy).not.toHaveBeenCalled();
    });
  });
});
