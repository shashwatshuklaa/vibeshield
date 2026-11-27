import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  buildScanJobId,
  closeQueueResources,
  createScanJobsQueue,
  QUEUE_NAMES,
  RedisConnectionManager,
  validateScanQueueJobPayload,
  type ManagedQueueHandle,
  type ScanQueueJobPayload,
} from '@vibeshield/queue';
import { ScanStatus } from '@vibeshield/types';
import {
  createSecurityWorkerRuntime,
  loadWorkerConfig,
  SecurityWorkerError,
  type SecurityWorkerRuntime,
  type WorkerDatabaseManagerLike,
} from '../index.js';

const REDIS_URI = process.env.REDIS_INTEGRATION_URI;

function createStubDbManager(): WorkerDatabaseManagerLike {
  let connected = false;
  return {
    async connect(): Promise<void> {
      connected = true;
    },
    async disconnect(): Promise<void> {
      connected = false;
    },
    isConnected(): boolean {
      return connected;
    },
    getStatus() {
      return {
        state: connected ? ('connected' as const) : ('disconnected' as const),
        readyState: connected ? 1 : 0,
        isConnected: connected,
      };
    },
  };
}

function makePayload(scanId: string, branch = 'main'): ScanQueueJobPayload {
  return validateScanQueueJobPayload({
    scanId,
    organizationId: 'org-worker-int-1',
    projectId: 'proj-worker-int-1',
    installationRecordId: 'inst-worker-int-1',
    githubRepositoryId: 888001,
    commitHash: 'bead1234feed',
    branch,
    status: ScanStatus.QUEUED,
    metadata: {
      organizationId: 'org-worker-int-1',
      projectId: 'proj-worker-int-1',
      triggeredByUserId: 'user-worker-int-1',
      triggerSource: 'manual',
      enqueuedAt: new Date().toISOString(),
    },
  });
}

describe.skipIf(!REDIS_URI)(
  '@vibeshield/security-worker Real Redis & BullMQ Integration Tests',
  () => {
    const producerManagers: RedisConnectionManager[] = [];
    const producerQueues: Array<ManagedQueueHandle<ScanQueueJobPayload, 'scan'>> = [];
    const runtimes: SecurityWorkerRuntime[] = [];

    async function setupProducer(): Promise<{
      manager: RedisConnectionManager;
      handle: ManagedQueueHandle<ScanQueueJobPayload, 'scan'>;
    }> {
      const manager = new RedisConnectionManager();
      producerManagers.push(manager);
      await manager.connect({
        url: REDIS_URI!,
        connectTimeoutMs: 5000,
      });

      const handle = createScanJobsQueue(manager, {
        skipWaitingForReady: false,
      });
      producerQueues.push(handle);
      await handle.queue.waitUntilReady();
      return { manager, handle };
    }

    beforeEach(async () => {
      const manager = new RedisConnectionManager();
      await manager.connect({ url: REDIS_URI!, connectTimeoutMs: 5000 });
      const handle = createScanJobsQueue(manager, { skipWaitingForReady: false });
      await handle.queue.waitUntilReady();
      await handle.queue.obliterate({ force: true });
      await closeQueueResources([handle], manager);
    });

    afterEach(async () => {
      for (const runtime of runtimes.splice(0)) {
        await runtime.stop().catch(() => undefined);
      }
      for (const handle of producerQueues.splice(0)) {
        await handle.close().catch(() => undefined);
      }
      for (const mgr of producerManagers.splice(0)) {
        await mgr.disconnect().catch(() => undefined);
      }
    });

    afterAll(async () => {
      for (const runtime of runtimes.splice(0)) {
        await runtime.stop().catch(() => undefined);
      }
      for (const handle of producerQueues.splice(0)) {
        await handle.close().catch(() => undefined);
      }
      for (const mgr of producerManagers.splice(0)) {
        await mgr.disconnect().catch(() => undefined);
      }
    });

    it('connects worker independently from producer, consumes validated jobs, and gracefully closes cleanly', async () => {
      const { handle } = await setupProducer();
      const processed: string[] = [];

      let markProcessed!: () => void;
      const processedPromise = new Promise<void>((resolve) => {
        markProcessed = resolve;
      });

      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_redis_test',
        REDIS_URL: REDIS_URI!,
        WORKER_CONCURRENCY: '2',
        WORKER_LOCK_DURATION: '10000',
        WORKER_STALLED_INTERVAL: '10000',
        WORKER_MAX_STALLED_COUNT: '2',
        WORKER_SHUTDOWN_GRACE_MS: '5000',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        databaseManager: createStubDbManager(),
        processor: async (payload) => {
          processed.push(payload.scanId);
          markProcessed();
        },
      });
      runtimes.push(runtime);

      await runtime.start();
      expect(runtime.isReady()).toBe(true);
      expect(runtime.getStatus().queueName).toBe(QUEUE_NAMES.SCAN_JOBS);
      expect(runtime.getStatus().isRunning).toBe(true);

      const payload = makePayload('scan-int-happy-1');
      const jobId = buildScanJobId({
        organizationId: payload.organizationId,
        projectId: payload.projectId,
        scanId: payload.scanId,
      });

      const enqueued = await handle.queue.add('scan', payload, { jobId });
      await processedPromise;

      expect(processed).toEqual(['scan-int-happy-1']);

      // Give BullMQ a moment to finalize state transition to completed in Redis
      await new Promise((resolve) => setTimeout(resolve, 100));
      const fetched = await handle.queue.getJob(enqueued.id!);
      expect(await fetched?.getState()).toBe('completed');

      const shutdownOutcome = await runtime.stop();
      expect(shutdownOutcome).toEqual({ timedOut: false });
      expect(runtime.isReady()).toBe(false);
      expect(runtime.getStatus().state).toBe('stopped');
      expect(runtime.getStatus().isRunning).toBe(false);
    });

    it('retries transient processor errors and terminates malformed payloads immediately without retrying', async () => {
      const { handle } = await setupProducer();
      const attemptLog: Array<{ scanId: string; attempt: number }> = [];

      let markCompleted!: () => void;
      const completedPromise = new Promise<void>((resolve) => {
        markCompleted = resolve;
      });

      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_redis_test',
        REDIS_URL: REDIS_URI!,
        WORKER_CONCURRENCY: '1',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        databaseManager: createStubDbManager(),
        processor: async (payload, job) => {
          attemptLog.push({ scanId: payload.scanId, attempt: job.attemptsMade + 1 });
          if (job.attemptsMade === 0) {
            throw new Error('Simulated transient Redis/network blip');
          }
          markCompleted();
        },
      });
      runtimes.push(runtime);

      await runtime.start();

      // 1. Enqueue permanently invalid payload (missing required fields + leaked token key)
      const poisonJob = await handle.queue.add(
        'scan',
        {
          ...makePayload('scan-int-poison-1'),
          accessToken: 'ghs_leaked_secret_should_unrecoverable',
        } as unknown as ScanQueueJobPayload,
        {
          jobId: 'scan-poison-unrecoverable-1',
          attempts: 3,
          backoff: { type: 'fixed', delay: 50 },
        }
      );

      // 2. Enqueue valid payload that transiently fails once then succeeds on retry
      const retryPayload = makePayload('scan-int-retry-1');
      const retryJob = await handle.queue.add('scan', retryPayload, {
        jobId: buildScanJobId({
          organizationId: retryPayload.organizationId,
          projectId: retryPayload.projectId,
          scanId: retryPayload.scanId,
        }),
        attempts: 3,
        backoff: { type: 'fixed', delay: 50 },
      });

      await completedPromise;
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Poison job must fail immediately on first attempt without consuming remaining retries
      const storedPoison = await handle.queue.getJob(poisonJob.id!);
      expect(await storedPoison?.getState()).toBe('failed');
      expect(storedPoison?.attemptsMade).toBe(1);
      expect(attemptLog.some((entry) => entry.scanId === 'scan-int-poison-1')).toBe(false);

      // Transient error job must have retried and completed on attempt 2
      const storedRetry = await handle.queue.getJob(retryJob.id!);
      expect(await storedRetry?.getState()).toBe('completed');
      expect(attemptLog.filter((entry) => entry.scanId === 'scan-int-retry-1')).toHaveLength(2);
    });

    it('gracefully waits for active jobs within shutdown grace period before closing', async () => {
      const { handle } = await setupProducer();
      let jobStarted!: () => void;
      const startedPromise = new Promise<void>((resolve) => {
        jobStarted = resolve;
      });
      let finishedInsideGrace = false;

      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_redis_test',
        REDIS_URL: REDIS_URI!,
        WORKER_CONCURRENCY: '1',
        WORKER_SHUTDOWN_GRACE_MS: '5000',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        databaseManager: createStubDbManager(),
        processor: async () => {
          jobStarted();
          await new Promise((resolve) => setTimeout(resolve, 250));
          finishedInsideGrace = true;
        },
      });
      runtimes.push(runtime);

      await runtime.start();
      const payload = makePayload('scan-int-grace-1');
      const job = await handle.queue.add('scan', payload, {
        jobId: buildScanJobId({
          organizationId: payload.organizationId,
          projectId: payload.projectId,
          scanId: payload.scanId,
        }),
      });

      await startedPromise;
      const stopResult = await runtime.stop();

      expect(stopResult).toEqual({ timedOut: false });
      expect(finishedInsideGrace).toBe(true);
      const fetched = await handle.queue.getJob(job.id!);
      expect(await fetched?.getState()).toBe('completed');
    });

    it('fails cleanly with credential-redacted error when configured with unreachable Redis', async () => {
      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_redis_test',
        REDIS_URL: 'redis://default:TopSecretRedisPass999!@127.0.0.1:6399/0',
        REDIS_CONNECT_TIMEOUT_MS: '500',
        REDIS_MAX_RECONNECT_ATTEMPTS: '1',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        databaseManager: createStubDbManager(),
        processor: async () => undefined,
      });
      runtimes.push(runtime);

      let err: unknown = null;
      try {
        await runtime.start();
      } catch (caught) {
        err = caught;
      }

      expect(err).toBeInstanceOf(SecurityWorkerError);
      expect((err as SecurityWorkerError).code).toBe('WORKER_STARTUP_FAILED');
      expect((err as Error).message).not.toContain('TopSecretRedisPass999!');
      expect(runtime.isReady()).toBe(false);
    });
  }
);
