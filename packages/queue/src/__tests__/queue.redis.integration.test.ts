import { Worker } from 'bullmq';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { ScanStatus } from '@vibeshield/types';
import {
  buildScanJobId,
  closeQueueResources,
  createScanJobsQueue,
  DEFAULT_QUEUE_POLICY,
  inspectQueueHealth,
  QUEUE_KEY_PREFIX,
  QUEUE_NAMES,
  RedisConnectionManager,
  validateScanQueueJobPayload,
  type ManagedQueueHandle,
  type ScanQueueJobPayload,
} from '../index.js';

const REDIS_URI = process.env.REDIS_INTEGRATION_URI;

describe.skipIf(!REDIS_URI)('@vibeshield/queue Real Redis & BullMQ Integration Tests', () => {
  const activeManagers: RedisConnectionManager[] = [];
  const activeWorkers: Worker[] = [];

  afterEach(async () => {
    for (const worker of activeWorkers.splice(0)) {
      await worker.close().catch(() => undefined);
    }
    for (const mgr of activeManagers.splice(0)) {
      await mgr.disconnect().catch(() => undefined);
    }
  });

  afterAll(async () => {
    for (const worker of activeWorkers.splice(0)) {
      await worker.close().catch(() => undefined);
    }
    for (const mgr of activeManagers.splice(0)) {
      await mgr.disconnect().catch(() => undefined);
    }
  });

  it('connects to authenticated Redis, creates BullMQ queue, deduplicates jobId, retries failed jobs with test worker, and cleans up', async () => {
    const manager = new RedisConnectionManager();
    activeManagers.push(manager);

    await manager.connect({
      url: REDIS_URI!,
      connectTimeoutMs: 5000,
    });

    expect(manager.isConnected()).toBe(true);
    expect(await manager.ping()).toBe(true);

    const handle: ManagedQueueHandle<ScanQueueJobPayload, 'scan'> = createScanJobsQueue(manager, {
      skipWaitingForReady: false,
    });

    // Flush test queue namespace before assertions
    await handle.queue.obliterate({ force: true });

    const payload = validateScanQueueJobPayload({
      scanId: 'scan-real-1',
      organizationId: 'org-real-1',
      projectId: 'proj-real-1',
      installationRecordId: 'inst-real-1',
      githubRepositoryId: 777001,
      commitHash: 'deadbeef1234',
      branch: 'main',
      status: ScanStatus.QUEUED,
      metadata: {
        organizationId: 'org-real-1',
        projectId: 'proj-real-1',
        triggeredByUserId: 'user-real-1',
        triggerSource: 'manual',
        enqueuedAt: new Date().toISOString(),
      },
    });

    const jobId = buildScanJobId({
      organizationId: payload.organizationId,
      projectId: payload.projectId,
      scanId: payload.scanId,
    });

    // Add initial job + duplicate job with same deterministic jobId
    const job1 = await handle.queue.add('scan', payload, {
      jobId,
      attempts: 2,
      backoff: { type: 'fixed', delay: 50 },
    });
    await handle.queue.add('scan', payload, { jobId });

    const countsBeforeWorker = await inspectQueueHealth(handle, manager, true);
    expect(countsBeforeWorker.queueName).toBe(QUEUE_NAMES.SCAN_JOBS);
    expect(countsBeforeWorker.redis.isConnected).toBe(true);
    expect(countsBeforeWorker.counts?.waiting).toBe(1);

    expect(job1.opts.removeOnComplete).toEqual(DEFAULT_QUEUE_POLICY.removeOnComplete);
    expect(job1.opts.removeOnFail).toEqual(DEFAULT_QUEUE_POLICY.removeOnFail);

    // Minimal test-only worker verifying retry attempt 1 fails -> attempt 2 succeeds
    let attemptsSeen = 0;
    const completedPromise = new Promise<string>((resolve, reject) => {
      const worker = new Worker<ScanQueueJobPayload, void, 'scan'>(
        QUEUE_NAMES.SCAN_JOBS,
        async (job) => {
          attemptsSeen += 1;
          if (attemptsSeen === 1) {
            throw new Error('Transient test failure on attempt 1');
          }
          expect(job.data.scanId).toBe('scan-real-1');
        },
        {
          connection: manager.getWorkerConnectionOptions(),
          prefix: QUEUE_KEY_PREFIX,
        }
      );
      activeWorkers.push(worker);

      worker.on('completed', (job) => {
        resolve(job.id ?? '');
      });
      worker.on('failed', (_job, err) => {
        if (attemptsSeen >= 2) {
          reject(err);
        }
      });
    });

    const completedId = await completedPromise;
    expect(completedId).toBe(jobId);
    expect(attemptsSeen).toBe(2);

    // Verify exhausted failure moves job into BullMQ failed state cleanly
    const failingJobId = buildScanJobId({
      organizationId: 'org-real-1',
      projectId: 'proj-real-1',
      scanId: 'scan-real-fail',
    });
    const existingWorker = activeWorkers[0]!;
    const failedPromise = new Promise<string>((resolve) => {
      existingWorker.on('failed', (job) => {
        if (job?.id === failingJobId) {
          resolve(job.id);
        }
      });
    });
    await handle.queue.add(
      'scan',
      { ...payload, scanId: 'scan-real-fail' },
      { jobId: failingJobId, attempts: 1 }
    );
    expect(await failedPromise).toBe(failingJobId);

    await existingWorker.close();
    activeWorkers.length = 0;

    await closeQueueResources([handle], manager);
    expect(manager.getState()).toBe('not_initialized');
  });
});
