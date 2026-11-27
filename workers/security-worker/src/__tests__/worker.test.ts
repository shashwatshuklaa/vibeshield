import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EnvValidationError } from '@vibeshield/env';
import {
  QUEUE_NAMES,
  UnrecoverableError,
  type Job,
  type ManagedWorkerHandle,
  type Processor,
  type ScanQueueJobPayload,
} from '@vibeshield/queue';
import { ScanStatus } from '@vibeshield/types';
import {
  buildValidatedScanProcessor,
  clearSecurityScanProcessor,
  createSecurityWorkerRuntime,
  createWorkerLogger,
  hasSecurityScanProcessor,
  loadWorkerConfig,
  registerSecurityScanProcessor,
  SecurityWorkerError,
  startSecurityWorkerHost,
  type WorkerConfig,
} from '../index.js';

class MockBullWorker extends EventEmitter {
  public running = true;
  public closeCalls: Array<boolean> = [];
  public readyError: Error | null = null;
  public slowGracefulClose = false;

  async waitUntilReady(): Promise<void> {
    if (this.readyError) {
      throw this.readyError;
    }
    this.emit('ready');
  }

  isRunning(): boolean {
    return this.running;
  }

  async close(force = false): Promise<void> {
    this.closeCalls.push(force);
    if (!force && this.slowGracefulClose) {
      return await new Promise<void>(() => {
        // Deliberately simulate an in-flight job outliving shutdownGraceMs
      });
    }
    this.running = false;
    this.emit('closed');
  }
}

function makeConfig(overrides: Partial<WorkerConfig> = {}): WorkerConfig {
  return {
    nodeEnv: 'test',
    logLevel: 'silent',
    redisUrl: 'redis://:SuperSecretRedisPass99!@localhost:6379/0',
    redisConnectTimeoutMs: 5000,
    redisMaxReconnectAttempts: 10,
    concurrency: 2,
    lockDuration: 30_000,
    stalledInterval: 30_000,
    maxStalledCount: 2,
    maxStartedAttempts: 5,
    shutdownGraceMs: 500,
    queuePrefix: 'vibeshield',
    ...overrides,
  };
}

function makeValidPayload(overrides: Partial<ScanQueueJobPayload> = {}): ScanQueueJobPayload {
  return {
    scanId: 'scan-worker-1',
    organizationId: 'org-worker-1',
    projectId: 'proj-worker-1',
    installationRecordId: 'inst-worker-1',
    githubRepositoryId: 90123,
    commitHash: 'a1b2c3d4',
    branch: 'main',
    status: ScanStatus.QUEUED,
    metadata: {
      organizationId: 'org-worker-1',
      projectId: 'proj-worker-1',
      triggeredByUserId: 'user-worker-1',
      triggerSource: 'manual',
      enqueuedAt: '2026-11-27T12:00:00Z',
    },
    ...overrides,
  };
}

function makeFakeJob(
  data: unknown,
  name = 'scan',
  attemptsMade = 1
): Job<ScanQueueJobPayload, unknown, 'scan'> {
  return {
    id: 'job-1',
    name: name as 'scan',
    data: data as ScanQueueJobPayload,
    attemptsMade,
  } as unknown as Job<ScanQueueJobPayload, unknown, 'scan'>;
}

describe('@vibeshield/security-worker Unit Tests', () => {
  afterEach(() => {
    clearSecurityScanProcessor();
    vi.restoreAllMocks();
  });

  describe('Environment validation & credential redaction', () => {
    it('loads valid worker defaults without HTTP PORT and validates bounded settings', () => {
      const cfg = loadWorkerConfig({
        NODE_ENV: 'production',
        REDIS_URL: 'rediss://default:SecretPass!@redis.internal:6380/0',
      });

      expect(cfg).toEqual({
        nodeEnv: 'production',
        logLevel: 'info',
        redisUrl: 'rediss://default:SecretPass!@redis.internal:6380/0',
        redisConnectTimeoutMs: 5000,
        redisMaxReconnectAttempts: 10,
        concurrency: 2,
        lockDuration: 30_000,
        stalledInterval: 30_000,
        maxStalledCount: 2,
        maxStartedAttempts: 5,
        shutdownGraceMs: 10_000,
        queuePrefix: 'vibeshield',
      });
    });

    it('rejects missing REDIS_URL or invalid worker limits without exposing secrets', () => {
      expect(() => loadWorkerConfig({ NODE_ENV: 'test' })).toThrowError(EnvValidationError);

      let caughtMessage = '';
      try {
        loadWorkerConfig({
          REDIS_URL: 'http://admin:SuperSecretUrlPass!@badhost:6379',
          WORKER_CONCURRENCY: '999',
        });
      } catch (err) {
        caughtMessage = err instanceof Error ? err.message : String(err);
      }
      expect(caughtMessage).not.toContain('SuperSecretUrlPass!');
      expect(caughtMessage).toContain('REDIS_URL');
      expect(caughtMessage).toContain('WORKER_CONCURRENCY');

      expect(() =>
        loadWorkerConfig({
          REDIS_URL: 'redis://localhost:6379',
          QUEUE_PREFIX: 'bad:prefix',
        })
      ).toThrowError(EnvValidationError);
    });

    it('redacts Redis URLs and passwords in worker logs and filters below LOG_LEVEL', () => {
      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

      const logger = createWorkerLogger('warn', ['MySecretPwd123!']);
      logger.info('Should be suppressed at warn level');
      logger.error('Connection failed for redis://admin:MySecretPwd123!@cache.internal:6379', {
        reason: new Error('AUTH MySecretPwd123! rejected'),
      });

      expect(logSpy).not.toHaveBeenCalled();
      expect(errSpy).toHaveBeenCalledTimes(1);
      const logged = String(errSpy.mock.calls[0]?.[0] ?? '');
      expect(logged).not.toContain('MySecretPwd123!');
      expect(logged).not.toContain('cache.internal');
      expect(logged).toContain('[REDACTED_REDIS_URL]');
    });
  });

  describe('Processor registration & strict payload validation boundaries', () => {
    it('fails fast with NO_PROCESSOR_REGISTERED before touching Redis if no processor is registered', async () => {
      expect(hasSecurityScanProcessor()).toBe(false);
      const factorySpy = vi.fn();

      const runtime = createSecurityWorkerRuntime({
        config: makeConfig(),
        workerFactory: factorySpy,
      });

      await expect(runtime.start()).rejects.toMatchObject({
        name: 'SecurityWorkerError',
        code: 'NO_PROCESSOR_REGISTERED',
      });
      expect(factorySpy).not.toHaveBeenCalled();
      expect(runtime.isReady()).toBe(false);
      expect(runtime.getStatus().state).toBe('not_initialized');
    });

    it('rejects non-function registrations cleanly', () => {
      expect(() =>
        registerSecurityScanProcessor(null as unknown as () => Promise<void>)
      ).toThrowError(SecurityWorkerError);
    });

    it('wraps permanent payload/name errors in UnrecoverableError while preserving transient errors for retry', async () => {
      const innerSpy = vi.fn(async (payload: ScanQueueJobPayload) => {
        if (payload.branch === 'transient-fail') {
          throw new Error('Temporary upstream timeout');
        }
        if (payload.branch === 'permanent-fail') {
          throw new UnrecoverableError('Repository archived permanently');
        }
        return payload.scanId;
      });

      const wrapped = buildValidatedScanProcessor(innerSpy, ['TopSecretPass!']);

      // Unsupported job name -> UnrecoverableError
      await expect(wrapped(makeFakeJob(makeValidPayload(), 'other-job'))).rejects.toThrowError(
        UnrecoverableError
      );
      expect(innerSpy).not.toHaveBeenCalled();

      // Malformed / credential-bearing payload -> UnrecoverableError (never retried)
      await expect(
        wrapped(
          makeFakeJob({
            ...makeValidPayload(),
            accessToken: 'ghp_secret_never_allowed',
          })
        )
      ).rejects.toThrowError(UnrecoverableError);
      expect(innerSpy).not.toHaveBeenCalled();

      // Valid payload + transient error -> standard Error (retryable by BullMQ)
      const transientErr = await wrapped(
        makeFakeJob(makeValidPayload({ branch: 'transient-fail' }))
      ).catch((e: unknown) => e);
      expect(transientErr).toBeInstanceOf(Error);
      expect(transientErr).not.toBeInstanceOf(UnrecoverableError);

      // Valid payload + explicit UnrecoverableError -> UnrecoverableError
      await expect(
        wrapped(makeFakeJob(makeValidPayload({ branch: 'permanent-fail' })))
      ).rejects.toThrowError(UnrecoverableError);

      // Valid payload -> passes validated payload directly to processor
      await expect(wrapped(makeFakeJob(makeValidPayload()))).resolves.toBe('scan-worker-1');
    });
  });

  describe('Lifecycle, events, duplicate init guard, and bounded graceful shutdown', () => {
    it('tracks readiness transitions, prevents duplicate startup, logs safe job events, and deduplicates shutdown', async () => {
      const mockWorker = new MockBullWorker();
      const recordedEvents: string[] = [];
      const logger = {
        info: (msg: string) => recordedEvents.push(`INFO:${msg}`),
        warn: (msg: string) => recordedEvents.push(`WARN:${msg}`),
        error: (msg: string) => recordedEvents.push(`ERROR:${msg}`),
      };

      const registeredProcessor = vi.fn(async () => undefined);
      registerSecurityScanProcessor(registeredProcessor);

      let capturedProcessor: Processor<ScanQueueJobPayload, unknown, 'scan'> | null = null;
      const runtime = createSecurityWorkerRuntime({
        config: makeConfig(),
        logger,
        workerFactory: (proc, opts) => {
          capturedProcessor = proc;
          expect(opts.concurrency).toBe(2);
          expect(opts.lockDuration).toBe(30_000);
          expect(opts.stalledInterval).toBe(30_000);
          expect(opts.maxStalledCount).toBe(2);
          expect(opts.maxStartedAttempts).toBe(5);
          return {
            name: QUEUE_NAMES.SCAN_JOBS,
            worker: mockWorker as unknown as ManagedWorkerHandle['worker'],
            concurrency: opts.concurrency ?? 2,
            close: (force?: boolean) => mockWorker.close(force),
          };
        },
      });

      await runtime.start();
      expect(runtime.isReady()).toBe(true);
      expect(runtime.getStatus()).toEqual({
        queueName: QUEUE_NAMES.SCAN_JOBS,
        state: 'ready',
        isReady: true,
        isRunning: true,
        concurrency: 2,
      });

      // Duplicate start must fail cleanly
      await expect(runtime.start()).rejects.toMatchObject({
        code: 'WORKER_ALREADY_INITIALIZED',
      });

      // Execute processor and fire lifecycle events
      const validJob = makeFakeJob(makeValidPayload());
      await capturedProcessor!(validJob);
      expect(registeredProcessor).toHaveBeenCalledTimes(1);

      mockWorker.emit('active', validJob);
      mockWorker.emit('completed', validJob);
      mockWorker.emit('stalled', 'job-1');
      mockWorker.emit(
        'failed',
        validJob,
        new Error('redis://admin:SuperSecretRedisPass99!@localhost:6379 failed')
      );

      expect(
        recordedEvents.some((line) => line.includes('Job stalled') || line.includes('stalled'))
      ).toBe(true);
      expect(recordedEvents.join('\n')).not.toContain('SuperSecretRedisPass99!');

      // Concurrent stop calls deduplicate cleanly
      const [stopA, stopB] = await Promise.all([runtime.stop(), runtime.stop()]);
      expect(stopA).toEqual({ timedOut: false });
      expect(stopB).toEqual({ timedOut: false });
      expect(mockWorker.closeCalls).toEqual([false]);
      expect(runtime.isReady()).toBe(false);
      expect(runtime.getStatus().state).toBe('stopped');
    });

    it('forces worker close if graceful shutdown grace period expires and redacts startup failures', async () => {
      const slowWorker = new MockBullWorker();
      slowWorker.slowGracefulClose = true;

      const runtime = createSecurityWorkerRuntime({
        config: makeConfig({ shutdownGraceMs: 25 }),
        processor: async () => undefined,
        workerFactory: (_proc, opts) => ({
          name: QUEUE_NAMES.SCAN_JOBS,
          worker: slowWorker as unknown as ManagedWorkerHandle['worker'],
          concurrency: opts.concurrency ?? 2,
          close: (force?: boolean) => slowWorker.close(force),
        }),
      });

      await runtime.start();
      const outcome = await runtime.stop();
      expect(outcome).toEqual({ timedOut: true });
      expect(slowWorker.closeCalls).toEqual([false, true]);
      expect(runtime.getStatus().state).toBe('stopped');

      // Startup failure cleans up socket handle and strips password from error message
      const failingWorker = new MockBullWorker();
      failingWorker.readyError = new Error(
        'ECONNREFUSED redis://user:SuperSecretRedisPass99!@redis.internal:6379'
      );

      const failedRuntime = createSecurityWorkerRuntime({
        config: makeConfig(),
        processor: async () => undefined,
        workerFactory: (_proc, opts) => ({
          name: QUEUE_NAMES.SCAN_JOBS,
          worker: failingWorker as unknown as ManagedWorkerHandle['worker'],
          concurrency: opts.concurrency ?? 2,
          close: (force?: boolean) => failingWorker.close(force),
        }),
      });

      let startupErr: unknown = null;
      try {
        await failedRuntime.start();
      } catch (err) {
        startupErr = err;
      }
      expect(startupErr).toBeInstanceOf(SecurityWorkerError);
      expect((startupErr as SecurityWorkerError).code).toBe('WORKER_STARTUP_FAILED');
      expect((startupErr as Error).message).not.toContain('SuperSecretRedisPass99!');
      expect(failingWorker.closeCalls).toEqual([true]);
      expect(failedRuntime.getStatus().state).toBe('failed');
    });

    it('aborts startSecurityWorkerHost when invoked without a registered processor', async () => {
      await expect(
        startSecurityWorkerHost({
          rawEnv: {
            NODE_ENV: 'test',
            LOG_LEVEL: 'silent',
            REDIS_URL: 'redis://localhost:6379',
          },
        })
      ).rejects.toMatchObject({
        code: 'NO_PROCESSOR_REGISTERED',
      });
    });
  });
});
