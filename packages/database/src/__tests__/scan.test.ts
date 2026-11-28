import mongoose from 'mongoose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  isTerminalScanLifecycleStatus,
  ScanFailureCodeValue,
  ScanLifecycleStatusValue,
  ScanTriggerSourceValue,
} from '@vibeshield/types';
import {
  cancelScanWithLease,
  claimQueuedScanForAcquisition,
  completeAcquisitionPreparedWithLease,
  completeScanWithLease,
  createQueuedScan,
  failScanWithLease,
  findExpiredActiveScanLeaseCandidates,
  formatScanDispatchJobId,
  isValidScanLifecycleTransition,
  loadScanExecutionTarget,
  markScanDispatchSucceeded,
  MAX_OUTBOX_ATTEMPTS,
  OutboxDispatchStateValue,
  ProjectModel,
  rearmScanDispatchOutbox,
  recordScanDispatchFailure,
  releaseScanLeaseForRetry,
  renewScanWorkerLease,
  ScanDispatchOutboxModel,
  ScanLifecycleError,
  ScanModel,
  setScanResolvedCommitWithLease,
  suppressScanDispatchOutbox,
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

function makeMockSession() {
  const session = {
    withTransaction: async (fn: () => Promise<unknown>) => await fn(),
    endSession: async () => undefined,
  };
  return vi.spyOn(mongoose, 'startSession').mockResolvedValue(session as never);
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
      expect(isValidScanLifecycleTransition('ACQUIRING', 'QUEUED')).toBe(true);
      expect(isValidScanLifecycleTransition('ACQUIRING', 'PREPARED')).toBe(true);
      expect(isValidScanLifecycleTransition('ACQUIRING', 'IN_PROGRESS')).toBe(true);
      expect(isValidScanLifecycleTransition('IN_PROGRESS', 'COMPLETED')).toBe(true);
      expect(isValidScanLifecycleTransition('IN_PROGRESS', 'ACQUIRING')).toBe(true);

      expect(isTerminalScanLifecycleStatus('PREPARED')).toBe(true);

      // Illegal skips and terminal exits
      expect(isValidScanLifecycleTransition('QUEUED', 'PREPARED')).toBe(false);
      expect(isValidScanLifecycleTransition('QUEUED', 'COMPLETED')).toBe(false);
      expect(isValidScanLifecycleTransition('QUEUED', 'IN_PROGRESS')).toBe(false);
      expect(isValidScanLifecycleTransition('ACQUIRING', 'COMPLETED')).toBe(false);
      expect(isValidScanLifecycleTransition('PREPARED', 'COMPLETED')).toBe(false);
      expect(isValidScanLifecycleTransition('PREPARED', 'FAILED')).toBe(false);
      expect(isValidScanLifecycleTransition('PREPARED', 'CANCELLED')).toBe(false);
      expect(isValidScanLifecycleTransition('PREPARED', 'QUEUED')).toBe(false);
      expect(isValidScanLifecycleTransition('PREPARED', 'IN_PROGRESS')).toBe(false);
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

    it('returns STALE_OR_CONFLICT or CANCEL_REQUESTED when fenced lease updates match zero documents and requires stored lease token (L3)', async () => {
      makeMockSession();
      const orgId = new mongoose.Types.ObjectId().toString();
      const projId = new mongoose.Types.ObjectId().toString();
      const scanId = new mongoose.Types.ObjectId().toString();
      const leaseToken = 'fencing_token_1234567890abcdef';
      const now = new Date();

      vi.spyOn(ScanModel, 'findOneAndUpdate').mockResolvedValue(null);
      const existingAcquiringMissingLeaseWithCancel = new ScanModel(
        makeValidScanInput({
          _id: scanId,
          organizationId: orgId,
          projectId: projId,
          status: ScanLifecycleStatusValue.ACQUIRING,
          isActive: true,
          lease: null,
          cancellation: {
            requestedAt: now,
            requestedByUserId: null,
            reason: 'User cancelled',
          },
        })
      );
      vi.spyOn(ScanModel, 'findOne').mockResolvedValue(
        existingAcquiringMissingLeaseWithCancel as never
      );

      // L3: Missing/null lease subdocument MUST return STALE_OR_CONFLICT even if cancellation is set
      await expect(
        transitionScanToInProgress({
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
          now,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        failScanWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken,
          failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
          failureMessage: 'Failed',
          now,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // Valid active ACQUIRING lease + pending cancellation -> CANCEL_REQUESTED
      const existingAcquiringWithCancel = new ScanModel(
        makeValidScanInput({
          _id: scanId,
          organizationId: orgId,
          projectId: projId,
          status: ScanLifecycleStatusValue.ACQUIRING,
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
        now,
      });
      expect(transitionResult.status).toBe('CANCEL_REQUESTED');

      await expect(
        renewScanWorkerLease({ scanId, organizationId: orgId, projectId: projId, leaseToken, now })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        completeScanWithLease({ scanId, organizationId: orgId, projectId: projId, leaseToken, now })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      await expect(
        failScanWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken,
          failureCode: ScanFailureCodeValue.ACQUISITION_FAILED,
          failureMessage: 'Failed',
          now,
        })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      await expect(
        cancelScanWithLease({ scanId, organizationId: orgId, projectId: projId, leaseToken, now })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // Active IN_PROGRESS scan with matching valid lease + pending cancellation returns CANCEL_REQUESTED
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

    it('rejects invalid commit SHAs in setScanResolvedCommitWithLease before mutating ScanModel', async () => {
      const updateSpy = vi.spyOn(ScanModel, 'findOneAndUpdate');

      await expect(
        setScanResolvedCommitWithLease({
          scanId: new mongoose.Types.ObjectId().toString(),
          organizationId: new mongoose.Types.ObjectId().toString(),
          projectId: new mongoose.Types.ObjectId().toString(),
          leaseToken: 'valid_lease_token_123456',
          resolvedCommitSha: 'not-a-sha',
        })
      ).rejects.toMatchObject({ code: 'INVALID_COMMIT_SHA' });

      expect(updateSpy).not.toHaveBeenCalled();
    });
  });

  describe('PREPARED lifecycle, retry release, execution target loader, recovery & outbox foundations', () => {
    it('enforces PREPARED terminal schema invariants and preparedAt/completedAt rules', async () => {
      const preparedAt = new Date();
      const sha = 'c'.repeat(40);
      const validPrepared = new ScanModel(
        makeValidScanInput({
          status: ScanLifecycleStatusValue.PREPARED,
          isActive: false,
          resolvedCommitSha: sha,
          preparedAt,
          completedAt: null,
          lease: null,
          acquisition: {
            resolvedCommitSha: sha,
            compressedArchiveBytes: 256,
            extractedBytes: 512,
            extractedFileCount: 4,
            acquisitionCompletedAt: preparedAt,
          },
        })
      );
      expect(validPrepared.validateSync()).toBeUndefined();
      const pub = toPublicScanRecord(validPrepared);
      expect(pub.status).toBe('PREPARED');
      expect(pub.isActive).toBe(false);
      expect(pub.preparedAt).toEqual(preparedAt);
      expect(pub.completedAt).toBeNull();
      expect(pub.lease).toBeNull();

      const invalidActivePrepared = new ScanModel(
        makeValidScanInput({
          status: ScanLifecycleStatusValue.PREPARED,
          isActive: true,
        })
      );
      await expect(invalidActivePrepared.validate()).rejects.toThrow(/isActive/i);
    });

    it('fences completeAcquisitionPreparedWithLease strictly by DB commit SHA, lease token, and cancellation state', async () => {
      makeMockSession();
      const orgId = new mongoose.Types.ObjectId().toString();
      const projId = new mongoose.Types.ObjectId().toString();
      const scanId = new mongoose.Types.ObjectId().toString();
      const validToken = 'valid_lease_token_1234567890';
      const newerToken = 'newer_lease_token_1234567890';
      const now = new Date();
      const sha = 'd'.repeat(40);

      const makeMockSelectQuery = (doc: unknown) => ({
        select: vi.fn(async () => doc),
      });

      // Missing resolvedCommitSha on DB document -> MISSING_RESOLVED_COMMIT
      vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce(
        makeMockSelectQuery(
          new ScanModel(
            makeValidScanInput({
              _id: scanId,
              organizationId: orgId,
              projectId: projId,
              status: ScanLifecycleStatusValue.ACQUIRING,
              isActive: true,
              resolvedCommitSha: null,
              lease: {
                workerId: 'security-worker',
                token: validToken,
                acquiredAt: now,
                heartbeatAt: now,
                expiresAt: new Date(now.getTime() + 60_000),
              },
            })
          )
        ) as never
      );
      await expect(
        completeAcquisitionPreparedWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          acquisition: { compressedArchiveBytes: 100, extractedBytes: 200, extractedFileCount: 2 },
          now,
        })
      ).resolves.toMatchObject({ status: 'MISSING_RESOLVED_COMMIT' });

      // Stale worker cannot see cancellation or prepare
      vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce(
        makeMockSelectQuery(
          new ScanModel(
            makeValidScanInput({
              _id: scanId,
              organizationId: orgId,
              projectId: projId,
              status: ScanLifecycleStatusValue.ACQUIRING,
              isActive: true,
              resolvedCommitSha: sha,
              cancellation: { requestedAt: now, requestedByUserId: null, reason: 'Stop' },
              lease: {
                workerId: 'security-worker',
                token: newerToken,
                acquiredAt: now,
                heartbeatAt: now,
                expiresAt: new Date(now.getTime() + 60_000),
              },
            })
          )
        ) as never
      );
      await expect(
        completeAcquisitionPreparedWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          acquisition: { compressedArchiveBytes: 100, extractedBytes: 200, extractedFileCount: 2 },
          now,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // Active valid lease with cancellation requested -> CANCEL_REQUESTED
      vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce(
        makeMockSelectQuery(
          new ScanModel(
            makeValidScanInput({
              _id: scanId,
              organizationId: orgId,
              projectId: projId,
              status: ScanLifecycleStatusValue.ACQUIRING,
              isActive: true,
              resolvedCommitSha: sha,
              cancellation: { requestedAt: now, requestedByUserId: null, reason: 'Stop' },
              lease: {
                workerId: 'security-worker',
                token: validToken,
                acquiredAt: now,
                heartbeatAt: now,
                expiresAt: new Date(now.getTime() + 60_000),
              },
            })
          )
        ) as never
      );
      await expect(
        completeAcquisitionPreparedWithLease({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          acquisition: { compressedArchiveBytes: 100, extractedBytes: 200, extractedFileCount: 2 },
          now,
        })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      // Valid preparation reads DB commit SHA and leaves completedAt unset
      vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce(
        makeMockSelectQuery(
          new ScanModel(
            makeValidScanInput({
              _id: scanId,
              organizationId: orgId,
              projectId: projId,
              status: ScanLifecycleStatusValue.ACQUIRING,
              isActive: true,
              resolvedCommitSha: sha,
              lease: {
                workerId: 'security-worker',
                token: validToken,
                acquiredAt: now,
                heartbeatAt: now,
                expiresAt: new Date(now.getTime() + 60_000),
              },
            })
          )
        ) as never
      );
      const updateSpy = vi.spyOn(ScanModel, 'findOneAndUpdate').mockResolvedValueOnce(
        new ScanModel(
          makeValidScanInput({
            _id: scanId,
            organizationId: orgId,
            projectId: projId,
            status: ScanLifecycleStatusValue.PREPARED,
            isActive: false,
            resolvedCommitSha: sha,
            preparedAt: now,
            completedAt: null,
            lease: null,
            acquisition: {
              resolvedCommitSha: sha,
              compressedArchiveBytes: 100,
              extractedBytes: 200,
              extractedFileCount: 2,
              acquisitionCompletedAt: now,
            },
          })
        ) as never
      );
      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate').mockResolvedValueOnce(null);
      vi.spyOn(ScanDispatchOutboxModel, 'findOne').mockResolvedValueOnce(null);

      const preparedRes = await completeAcquisitionPreparedWithLease({
        scanId,
        organizationId: orgId,
        projectId: projId,
        leaseToken: validToken,
        acquisition: { compressedArchiveBytes: 100, extractedBytes: 200, extractedFileCount: 2 },
        now,
      });
      expect(preparedRes.status).toBe('PREPARED');
      if (preparedRes.status === 'PREPARED') {
        expect(preparedRes.scan.isActive).toBe(false);
        expect(preparedRes.scan.completedAt).toBeNull();
        expect(preparedRes.scan.preparedAt).toEqual(now);
        expect(preparedRes.scan.lease).toBeNull();
        expect(preparedRes.scan.acquisition?.resolvedCommitSha).toBe(sha);
      }
      expect(updateSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          resolvedCommitSha: sha,
          'lease.token': validToken,
          'cancellation.requestedAt': null,
        }),
        expect.objectContaining({
          $set: expect.objectContaining({
            status: 'PREPARED',
            isActive: false,
            lease: null,
          }),
        }),
        expect.anything()
      );
    });

    it('fences releaseScanLeaseForRetry against stale workers, cancellations, and exhausted attempts', async () => {
      const orgId = new mongoose.Types.ObjectId().toString();
      const projId = new mongoose.Types.ObjectId().toString();
      const scanId = new mongoose.Types.ObjectId().toString();
      const validToken = 'valid_lease_token_1234567890';
      const newerToken = 'newer_lease_token_1234567890';
      const now = new Date();

      vi.spyOn(ScanModel, 'findOneAndUpdate').mockResolvedValue(null);
      const mockSelectDoc = (doc: unknown) =>
        vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce({
          select: vi.fn(async () => doc),
        } as never);

      // Old worker cannot release newer worker's lease
      mockSelectDoc(
        new ScanModel(
          makeValidScanInput({
            _id: scanId,
            organizationId: orgId,
            projectId: projId,
            status: ScanLifecycleStatusValue.ACQUIRING,
            isActive: true,
            lease: {
              workerId: 'security-worker',
              token: newerToken,
              acquiredAt: now,
              heartbeatAt: now,
              expiresAt: new Date(now.getTime() + 60_000),
            },
          })
        )
      );
      await expect(
        releaseScanLeaseForRetry({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          now,
        })
      ).resolves.toMatchObject({ status: 'STALE_OR_CONFLICT' });

      // Pending cancellation -> CANCEL_REQUESTED
      mockSelectDoc(
        new ScanModel(
          makeValidScanInput({
            _id: scanId,
            organizationId: orgId,
            projectId: projId,
            status: ScanLifecycleStatusValue.ACQUIRING,
            isActive: true,
            cancellation: { requestedAt: now, requestedByUserId: null, reason: 'Cancel' },
            lease: {
              workerId: 'security-worker',
              token: validToken,
              acquiredAt: now,
              heartbeatAt: now,
              expiresAt: new Date(now.getTime() + 60_000),
            },
          })
        )
      );
      await expect(
        releaseScanLeaseForRetry({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          now,
        })
      ).resolves.toMatchObject({ status: 'CANCEL_REQUESTED' });

      // Exhausted attempts -> ATTEMPTS_EXHAUSTED
      mockSelectDoc(
        new ScanModel(
          makeValidScanInput({
            _id: scanId,
            organizationId: orgId,
            projectId: projId,
            status: ScanLifecycleStatusValue.ACQUIRING,
            isActive: true,
            attemptCount: 3,
            maxAttempts: 3,
            lease: {
              workerId: 'security-worker',
              token: validToken,
              acquiredAt: now,
              heartbeatAt: now,
              expiresAt: new Date(now.getTime() + 60_000),
            },
          })
        )
      );
      await expect(
        releaseScanLeaseForRetry({
          scanId,
          organizationId: orgId,
          projectId: projId,
          leaseToken: validToken,
          now,
        })
      ).resolves.toMatchObject({ status: 'ATTEMPTS_EXHAUSTED' });
    });

    it('projects execution target safely without +lease.token and detects non-executable states', async () => {
      const scanId = new mongoose.Types.ObjectId().toString();
      const orgId = new mongoose.Types.ObjectId().toString();
      const projectId = new mongoose.Types.ObjectId().toString();
      const connId = new mongoose.Types.ObjectId().toString();

      let selectedFields = '';
      vi.spyOn(ScanModel, 'findById').mockImplementation((() => {
        const chain = {
          select: (fields: string) => {
            selectedFields = fields;
            return chain;
          },
          session: () => chain,
          lean: async () => ({
            _id: scanId,
            organizationId: orgId,
            projectId,
            repositoryConnectionId: connId,
            githubInstallationId: 11,
            githubRepositoryId: 22,
            requestedRef: 'main',
            requestedCommitHash: null,
            resolvedCommitSha: null,
            status: ScanLifecycleStatusValue.QUEUED,
            isActive: true,
            triggerSource: ScanTriggerSourceValue.MANUAL,
            attemptCount: 0,
            maxAttempts: 3,
            cancellation: { requestedAt: null },
            lease: null,
            queuedAt: new Date(),
            startedAt: null,
          }),
        };
        return chain;
      }) as never);

      vi.spyOn(ProjectModel, 'findOne').mockImplementation((() => {
        const chain = {
          session: () => chain,
          lean: async () => ({
            _id: projectId,
            organizationId: orgId,
            archivedAt: new Date(),
          }),
        };
        return chain;
      }) as never);

      const res = await loadScanExecutionTarget(scanId);
      expect(selectedFields).not.toContain('+lease.token');
      expect(selectedFields).not.toContain('lease.token');
      expect(res).toMatchObject({
        status: 'INVALID_BINDING',
        reason: 'PROJECT_ARCHIVED',
        failureCode: ScanFailureCodeValue.PROJECT_ARCHIVED,
      });
    });

    it('queries bounded expired-lease candidates without selecting lease.token', async () => {
      let selectedFields = '';
      let capturedLimit = 0;
      const chain = {
        select: (fields: string) => {
          selectedFields = fields;
          return chain;
        },
        sort: () => chain,
        limit: (n: number) => {
          capturedLimit = n;
          return chain;
        },
        lean: async () => [],
      };
      vi.spyOn(ScanModel, 'find').mockReturnValue(chain as never);

      await findExpiredActiveScanLeaseCandidates({ limit: 500 });
      expect(selectedFields).not.toContain('lease.token');
      expect(capturedLimit).toBe(100);
    });

    it('validates ScanDispatchOutboxModel state invariants, generation + claimToken fencing, exhaustion ceiling, and secret redaction', async () => {
      makeMockSession();
      const base = {
        scanId: new mongoose.Types.ObjectId(),
        organizationId: new mongoose.Types.ObjectId(),
        projectId: new mongoose.Types.ObjectId(),
      };

      const validPending = new ScanDispatchOutboxModel({
        ...base,
        claimToken: 'secret_outbox_claim_token_123456',
      });
      expect(validPending.validateSync()).toBeUndefined();
      expect(validPending.state).toBe(OutboxDispatchStateValue.PENDING);
      expect(validPending.dispatchGeneration).toBe(1);

      // claimToken must never leak via JSON serialization or object conversion
      const jsonOut = validPending.toJSON() as unknown as Record<string, unknown>;
      expect(jsonOut.claimToken).toBeUndefined();
      expect(JSON.stringify(validPending)).not.toContain('secret_outbox_claim_token_123456');

      const invalidPendingWithDispatchedAt = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.PENDING,
        dispatchedAt: new Date(),
      });
      await expect(invalidPendingWithDispatchedAt.validate()).rejects.toThrow(/dispatchedAt/i);

      const invalidDispatchedWithoutTime = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.DISPATCHED,
        dispatchedAt: null,
      });
      await expect(invalidDispatchedWithoutTime.validate()).rejects.toThrow(/dispatchedAt/i);

      const invalidSuppressedWithoutTime = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.SUPPRESSED,
        suppressedAt: null,
      });
      await expect(invalidSuppressedWithoutTime.validate()).rejects.toThrow(/suppressedAt/i);

      const invalidExhaustedWithoutTime = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.EXHAUSTED,
        exhaustedAt: null,
      });
      await expect(invalidExhaustedWithoutTime.validate()).rejects.toThrow(/exhaustedAt/i);

      const validExhausted = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.EXHAUSTED,
        attempts: MAX_OUTBOX_ATTEMPTS,
        exhaustedAt: new Date(),
      });
      expect(validExhausted.validateSync()).toBeUndefined();

      const badGeneration = new ScanDispatchOutboxModel({ ...base, dispatchGeneration: 0 });
      expect(badGeneration.validateSync()?.errors.dispatchGeneration).toBeDefined();

      const badAttempts = new ScanDispatchOutboxModel({ ...base, attempts: -1 });
      expect(badAttempts.validateSync()?.errors.attempts).toBeDefined();

      const overMaxAttempts = new ScanDispatchOutboxModel({
        ...base,
        attempts: MAX_OUTBOX_ATTEMPTS + 1,
      });
      expect(overMaxAttempts.validateSync()?.errors.attempts).toBeDefined();

      const withSecretErr = new ScanDispatchOutboxModel({
        ...base,
        lastError:
          'Failed redis://user:Secret99!@cache:6379 and https://github.com/org/repo?token=secret',
      });
      expect(withSecretErr.lastError).not.toContain('Secret99!');
      expect(withSecretErr.lastError).not.toContain('token=secret');
      expect(withSecretErr.lastError).toContain('[REDACTED_QUERY]');

      const scanIdHex = base.scanId.toString();
      expect(formatScanDispatchJobId(scanIdHex, 3)).toBe(`scan-${scanIdHex}-3`);

      // Rejects invalid/missing claimToken before querying MongoDB
      await expect(
        markScanDispatchSucceeded({
          scanId: scanIdHex,
          dispatchGeneration: 1,
          claimToken: 'short',
        })
      ).rejects.toMatchObject({ code: 'INVALID_OUTBOX_CLAIM_TOKEN' });

      await expect(
        recordScanDispatchFailure({
          scanId: scanIdHex,
          dispatchGeneration: 1,
          claimToken: 'short',
          errorMessage: 'Redis down',
        })
      ).rejects.toMatchObject({ code: 'INVALID_OUTBOX_CLAIM_TOKEN' });

      // Stale claimToken within same PENDING generation -> STALE_CLAIM
      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate').mockResolvedValueOnce(null);
      vi.spyOn(ScanDispatchOutboxModel, 'findOne').mockResolvedValueOnce(validPending as never);
      await expect(
        markScanDispatchSucceeded({
          scanId: scanIdHex,
          dispatchGeneration: 1,
          claimToken: 'old_supplanted_claim_token_123456',
        })
      ).resolves.toEqual({ status: 'STALE_CLAIM' });

      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate')
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      vi.spyOn(ScanDispatchOutboxModel, 'findOne').mockResolvedValueOnce(validPending as never);
      await expect(
        recordScanDispatchFailure({
          scanId: scanIdHex,
          dispatchGeneration: 1,
          claimToken: 'old_supplanted_claim_token_123456',
          errorMessage: 'Redis down',
        })
      ).resolves.toEqual({ status: 'STALE_CLAIM' });

      // Old dispatcher generation mismatch -> STALE_GENERATION
      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate').mockResolvedValueOnce(null);
      vi.spyOn(ScanDispatchOutboxModel, 'findOne').mockResolvedValueOnce(
        new ScanDispatchOutboxModel({
          ...base,
          dispatchGeneration: 2,
          state: OutboxDispatchStateValue.PENDING,
        }) as never
      );
      await expect(
        markScanDispatchSucceeded({
          scanId: scanIdHex,
          dispatchGeneration: 1,
          claimToken: 'any_valid_claim_token_1234567890',
        })
      ).resolves.toEqual({ status: 'STALE_GENERATION' });

      // Suppression of terminal/cancelled scan during rearm
      vi.spyOn(ScanDispatchOutboxModel, 'findOne').mockReturnValueOnce({
        session: vi.fn(async () => validPending),
      } as never);
      vi.spyOn(ScanModel, 'findOneAndUpdate').mockResolvedValueOnce(null);
      vi.spyOn(ScanModel, 'findOne').mockReturnValueOnce({
        select: () => ({
          session: () => ({
            lean: async () => ({
              _id: base.scanId,
              status: ScanLifecycleStatusValue.CANCELLED,
              isActive: false,
              cancellation: { requestedAt: new Date() },
            }),
          }),
        }),
      } as never);
      const suppressedDoc = new ScanDispatchOutboxModel({
        ...base,
        state: OutboxDispatchStateValue.SUPPRESSED,
        suppressedAt: new Date(),
      });
      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate').mockResolvedValueOnce(
        suppressedDoc as never
      );
      const rearmRes = await rearmScanDispatchOutbox({ scanId: scanIdHex });
      expect(rearmRes.status).toBe('SUPPRESSED_TERMINAL');

      vi.spyOn(ScanDispatchOutboxModel, 'findOneAndUpdate').mockResolvedValueOnce(
        suppressedDoc as never
      );
      await expect(suppressScanDispatchOutbox({ scanId: scanIdHex })).resolves.toMatchObject({
        status: 'SUPPRESSED',
      });
    });
  });
});
