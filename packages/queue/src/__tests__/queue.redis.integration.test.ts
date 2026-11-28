import { Worker } from 'bullmq';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import {
  buildScanDispatchJobOptions,
  buildScanJobId,
  closeQueueResources,
  consumeInternalAuthNonce,
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
      scanId: '507f1f77bcf86cd799439011',
    });

    const jobIdGen1 = buildScanJobId({
      scanId: payload.scanId,
      dispatchGeneration: 1,
    });
    const jobIdGen2 = buildScanJobId({
      scanId: payload.scanId,
      dispatchGeneration: 2,
    });
    expect(jobIdGen1).toBe('scan-507f1f77bcf86cd799439011-1');
    expect(jobIdGen2).toBe('scan-507f1f77bcf86cd799439011-2');

    // Add initial job + duplicate job with same deterministic jobId (collapses) + different generation (kept distinct)
    const job1 = await handle.queue.add('scan', payload, {
      jobId: jobIdGen1,
      attempts: 2,
      backoff: { type: 'fixed', delay: 50 },
    });
    await handle.queue.add('scan', payload, { jobId: jobIdGen1 });
    await handle.queue.add('scan', payload, { jobId: jobIdGen2 });

    const countsBeforeWorker = await inspectQueueHealth(handle, manager, true);
    expect(countsBeforeWorker.queueName).toBe(QUEUE_NAMES.SCAN_JOBS);
    expect(countsBeforeWorker.redis.isConnected).toBe(true);
    expect(countsBeforeWorker.counts?.waiting).toBe(2);

    expect(job1.opts.removeOnComplete).toEqual(DEFAULT_QUEUE_POLICY.removeOnComplete);
    expect(job1.opts.removeOnFail).toEqual(DEFAULT_QUEUE_POLICY.removeOnFail);

    // Minimal test-only worker verifying retry attempt 1 fails -> attempt 2 succeeds, and gen 2 runs separately
    let gen1AttemptsSeen = 0;
    const completedIds: string[] = [];
    const completedPromise = new Promise<void>((resolve, reject) => {
      const worker = new Worker<ScanQueueJobPayload, void, 'scan'>(
        QUEUE_NAMES.SCAN_JOBS,
        async (job) => {
          if (job.id === jobIdGen1) {
            gen1AttemptsSeen += 1;
            if (gen1AttemptsSeen === 1) {
              throw new Error('Transient test failure on attempt 1');
            }
          }
          if (job.id === 'scan-507f1f77bcf86cd799439012-1') {
            throw new Error('Intentional generation-1 exhaustion failure');
          }
          if (job.id === 'scan-507f1f77bcf86cd799439012-2') {
            expect(job.data).toEqual({ scanId: '507f1f77bcf86cd799439012' });
            return;
          }
          expect(job.data).toEqual({ scanId: '507f1f77bcf86cd799439011' });
        },
        {
          connection: manager.getWorkerConnectionOptions(),
          prefix: QUEUE_KEY_PREFIX,
        }
      );
      activeWorkers.push(worker);

      worker.on('completed', (job) => {
        if (job.id) {
          completedIds.push(job.id);
        }
        if (completedIds.includes(jobIdGen1) && completedIds.includes(jobIdGen2)) {
          resolve();
        }
      });
      worker.on('failed', (_job, err) => {
        if (gen1AttemptsSeen >= 2) {
          reject(err);
        }
      });
    });

    await completedPromise;
    expect(completedIds).toEqual(expect.arrayContaining([jobIdGen1, jobIdGen2]));
    expect(gen1AttemptsSeen).toBe(2);

    // Verify exhausted failure moves job into BullMQ failed state cleanly AND next dispatchGeneration recovers it
    const failingScanId = '507f1f77bcf86cd799439012';
    const failingJobId = buildScanJobId({
      scanId: failingScanId,
      dispatchGeneration: 1,
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
      { scanId: failingScanId },
      buildScanDispatchJobOptions({
        scanId: failingScanId,
        dispatchGeneration: 1,
        maxAttempts: 1,
      })
    );
    expect(await failedPromise).toBe(failingJobId);

    const gen1Stored = await handle.queue.getJob(failingJobId);
    expect(await gen1Stored?.getState()).toBe('failed');

    // Generation 2 for the same scanId enqueues cleanly without colliding with retained failed gen 1
    const recoveredDone = new Promise<string>((resolve) => {
      existingWorker.on('completed', (job) => {
        if (job.id === buildScanJobId({ scanId: failingScanId, dispatchGeneration: 2 })) {
          resolve(job.id);
        }
      });
    });
    await handle.queue.add(
      'scan',
      { scanId: failingScanId },
      buildScanDispatchJobOptions({
        scanId: failingScanId,
        dispatchGeneration: 2,
        maxAttempts: 2,
        backoffDelayMs: 50,
      })
    );
    expect(await recoveredDone).toBe(
      buildScanJobId({ scanId: failingScanId, dispatchGeneration: 2 })
    );

    await existingWorker.close();
    activeWorkers.length = 0;

    await closeQueueResources([handle], manager);
    expect(manager.getState()).toBe('not_initialized');
  });

  it('enforces atomic Redis SET NX PX replay protection under concurrent requests and expires TTL cleanly', async () => {
    const manager = new RedisConnectionManager();
    activeManagers.push(manager);

    await manager.connect({
      url: REDIS_URI!,
      connectTimeoutMs: 5000,
    });

    const nonce = `int-nonce-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
    const namespace = 'security-worker-int';

    const results = await Promise.all([
      consumeInternalAuthNonce(manager, { nonce, ttlMs: 1_000, namespace }),
      consumeInternalAuthNonce(manager, { nonce, ttlMs: 1_000, namespace }),
      consumeInternalAuthNonce(manager, { nonce, ttlMs: 1_000, namespace }),
    ]);

    expect(results.filter((entry) => entry === 'ACCEPTED')).toHaveLength(1);
    expect(results.filter((entry) => entry === 'REPLAYED')).toHaveLength(2);

    await new Promise((resolve) => setTimeout(resolve, 1_150));

    await expect(
      consumeInternalAuthNonce(manager, { nonce, ttlMs: 1_000, namespace })
    ).resolves.toBe('ACCEPTED');
  });
});
