import {
  DatabaseConnectionManager,
  type DatabaseConnectOptions,
  type DatabaseConnectionState,
  type DatabaseConnectionStatus,
} from '@vibeshield/database';
import {
  closeWorkerWithGrace,
  createScanJobsWorker,
  extractRedisUrlPassword,
  QUEUE_NAMES,
  UnrecoverableError,
  validateScanQueueJobPayload,
  type CreateBullWorkerOptions,
  type Job,
  type ManagedWorkerHandle,
  type Processor,
  type ScanQueueJobPayload,
  type WorkerHealthSummary,
  type WorkerLifecycleState,
} from '@vibeshield/queue';
import type { WorkerConfig } from '../config/env.js';
import { createWorkerLogger, formatSafeWorkerMessage, type WorkerLogger } from '../utils/logger.js';

export type SecurityScanJobProcessor<TResult = void> = (
  payload: ScanQueueJobPayload,
  job: Job<ScanQueueJobPayload, TResult, 'scan'>
) => Promise<TResult>;

export type SecurityWorkerErrorCode =
  | 'NO_PROCESSOR_REGISTERED'
  | 'INVALID_PROCESSOR'
  | 'WORKER_ALREADY_INITIALIZED'
  | 'WORKER_STOPPING'
  | 'WORKER_STARTUP_FAILED';

export class SecurityWorkerError extends Error {
  public readonly code: SecurityWorkerErrorCode;

  constructor(message: string, code: SecurityWorkerErrorCode, secretValues: string[] = []) {
    super(formatSafeWorkerMessage(message, secretValues));
    this.name = 'SecurityWorkerError';
    this.code = code;
  }
}

export interface ScanJobsWorkerFactory {
  (
    processor: Processor<ScanQueueJobPayload, unknown, 'scan'>,
    options: CreateBullWorkerOptions
  ): ManagedWorkerHandle<ScanQueueJobPayload, unknown, 'scan'>;
}

export interface WorkerDatabaseManagerLike {
  connect(uri: string, options?: DatabaseConnectOptions): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
  getStatus(): DatabaseConnectionStatus;
}

export interface SecurityWorkerStatus extends WorkerHealthSummary {
  database: {
    state: DatabaseConnectionState;
    isConnected: boolean;
  };
}

export interface SecurityWorkerRuntimeOptions<TResult = unknown> {
  config: WorkerConfig;
  processor?: SecurityScanJobProcessor<TResult>;
  logger?: WorkerLogger;
  workerFactory?: ScanJobsWorkerFactory;
  databaseManager?: WorkerDatabaseManagerLike;
}

export interface SecurityWorkerRuntime {
  readonly queueName: string;
  start(): Promise<void>;
  stop(): Promise<{ timedOut: boolean }>;
  getStatus(): SecurityWorkerStatus;
  isReady(): boolean;
}

let registeredScanProcessor: SecurityScanJobProcessor<unknown> | null = null;

/**
 * Registers the explicit scan job processor for standalone worker bootstrap.
 * Calling bootstrap without registering a processor fails fast rather than dropping jobs.
 */
export function registerSecurityScanProcessor<TResult = void>(
  processor: SecurityScanJobProcessor<TResult>
): void {
  if (typeof processor !== 'function') {
    throw new SecurityWorkerError(
      'Security scan processor must be a valid async function.',
      'INVALID_PROCESSOR'
    );
  }
  registeredScanProcessor = processor as SecurityScanJobProcessor<unknown>;
}

/**
 * Clears the globally registered scan processor (primarily for isolated tests).
 */
export function clearSecurityScanProcessor(): void {
  registeredScanProcessor = null;
}

/**
 * Returns whether a global scan job processor has been registered.
 */
export function hasSecurityScanProcessor(): boolean {
  return typeof registeredScanProcessor === 'function';
}

function extractSafeJobContext(
  job:
    | Pick<Job<ScanQueueJobPayload, unknown, string>, 'id' | 'name' | 'attemptsMade' | 'data'>
    | undefined
): Record<string, unknown> {
  if (!job) {
    return {};
  }

  const rawData =
    typeof job.data === 'object' && job.data !== null
      ? (job.data as unknown as Record<string, unknown>)
      : null;

  return {
    jobId: job.id ?? 'unknown',
    jobName: job.name,
    attemptsMade: job.attemptsMade,
    ...(typeof rawData?.scanId === 'string' ? { scanId: rawData.scanId } : {}),
    ...(typeof rawData?.organizationId === 'string'
      ? { organizationId: rawData.organizationId }
      : {}),
    ...(typeof rawData?.projectId === 'string' ? { projectId: rawData.projectId } : {}),
  };
}

/**
 * Wraps the downstream scan processor with strict schema/credential validation so malformed or
 * unsafe job payloads terminate immediately via `UnrecoverableError` instead of wasting retries.
 */
export function buildValidatedScanProcessor<TResult = unknown>(
  processor: SecurityScanJobProcessor<TResult>,
  extraSecrets: string[] = []
): Processor<ScanQueueJobPayload, TResult, 'scan'> {
  return async (job: Job<ScanQueueJobPayload, TResult, 'scan'>): Promise<TResult> => {
    if (job.name !== 'scan') {
      throw new UnrecoverableError(
        `Unsupported job name "${String(job.name)}" for security worker.`
      );
    }

    let validatedPayload: ScanQueueJobPayload;
    try {
      validatedPayload = validateScanQueueJobPayload(job.data);
    } catch (validationError) {
      const safeMessage = formatSafeWorkerMessage(validationError, extraSecrets);
      throw new UnrecoverableError(`Invalid scan job payload: ${safeMessage}`);
    }

    return await processor(validatedPayload, job);
  };
}

/**
 * Creates a lifecycle-managed worker runtime requiring BOTH MongoDB connectivity and a connected
 * BullMQ Worker bound to `vibeshield-v1-scan-jobs` before reporting ready.
 */
export function createSecurityWorkerRuntime<TResult = unknown>(
  options: SecurityWorkerRuntimeOptions<TResult>
): SecurityWorkerRuntime {
  const { config } = options;
  const secretValues = [extractRedisUrlPassword(config.redisUrl)].filter(
    (secret): secret is string => Boolean(secret)
  );
  const logger = options.logger ?? createWorkerLogger(config.logLevel, secretValues);
  const workerFactory = options.workerFactory ?? createScanJobsWorker;
  const databaseManager: WorkerDatabaseManagerLike =
    options.databaseManager ??
    new DatabaseConnectionManager({
      logger: {
        info: (msg: string) => logger.info(msg),
        warn: (msg: string) => logger.warn(msg),
        error: (msg: string) => logger.error(msg),
      },
    });

  let state: WorkerLifecycleState = 'not_initialized';
  let handle: ManagedWorkerHandle<ScanQueueJobPayload, unknown, 'scan'> | null = null;
  let stopPromise: Promise<{ timedOut: boolean }> | null = null;

  const resolveProcessor = (): SecurityScanJobProcessor<TResult> => {
    const candidate =
      options.processor ?? (registeredScanProcessor as SecurityScanJobProcessor<TResult> | null);
    if (typeof candidate !== 'function') {
      throw new SecurityWorkerError(
        'Refusing to start security worker without an explicitly registered scan job processor.',
        'NO_PROCESSOR_REGISTERED',
        secretValues
      );
    }
    return candidate;
  };

  return {
    queueName: QUEUE_NAMES.SCAN_JOBS,

    async start(): Promise<void> {
      if (state === 'starting' || state === 'ready' || handle !== null) {
        throw new SecurityWorkerError(
          'Security worker runtime has already been started.',
          'WORKER_ALREADY_INITIALIZED',
          secretValues
        );
      }

      if (state === 'stopping') {
        throw new SecurityWorkerError(
          'Security worker runtime cannot start while shutting down.',
          'WORKER_STOPPING',
          secretValues
        );
      }

      const processor = resolveProcessor();
      state = 'starting';

      const wrappedProcessor = buildValidatedScanProcessor(
        processor as SecurityScanJobProcessor<unknown>,
        secretValues
      );

      let createdHandle: ManagedWorkerHandle<ScanQueueJobPayload, unknown, 'scan'> | null = null;
      let dbConnectedByStart = false;

      try {
        await databaseManager.connect(config.mongodbUri, {
          connectTimeoutMS: config.mongodbConnectTimeoutMs,
          serverSelectionTimeoutMS: Math.min(config.mongodbConnectTimeoutMs, 10_000),
        });
        dbConnectedByStart = true;

        if (!databaseManager.isConnected()) {
          throw new Error('MongoDB connection did not reach connected readyState.');
        }

        createdHandle = workerFactory(wrappedProcessor, {
          redis: {
            url: config.redisUrl,
            connectTimeoutMs: config.redisConnectTimeoutMs,
            maxReconnectAttempts: config.redisMaxReconnectAttempts,
          },
          prefix: config.queuePrefix,
          autorun: true,
          concurrency: config.concurrency,
          lockDuration: config.lockDuration,
          stalledInterval: config.stalledInterval,
          maxStalledCount: config.maxStalledCount,
          maxStartedAttempts: config.maxStartedAttempts,
          skipWaitingForReady: false,
          logger: {
            error: (msg: string) => logger.error(msg),
            warn: (msg: string) => logger.warn(msg),
            info: (msg: string) => logger.info(msg),
          },
        });

        handle = createdHandle;
        const { worker } = createdHandle;

        worker.on('ready', () => {
          if (state !== 'stopping' && state !== 'stopped' && databaseManager.isConnected()) {
            state = 'ready';
            logger.info('Worker ready and listening for jobs.', {
              queueName: QUEUE_NAMES.SCAN_JOBS,
              concurrency: config.concurrency,
              databaseConnected: true,
            });
          }
        });

        worker.on('active', (job) => {
          logger.info('Job became active.', extractSafeJobContext(job));
        });

        worker.on('completed', (job) => {
          logger.info('Job completed.', extractSafeJobContext(job));
        });

        worker.on('failed', (job, error) => {
          logger.error('Job failed.', {
            ...extractSafeJobContext(job),
            unrecoverable: error instanceof UnrecoverableError,
            error: formatSafeWorkerMessage(error, secretValues),
          });
        });

        worker.on('stalled', (jobId) => {
          logger.warn('Job detected as stalled and scheduled for recovery checks.', {
            jobId,
          });
        });

        worker.on('closed', () => {
          if (state !== 'failed' && state !== 'stopping') {
            state = 'stopped';
          }
          logger.info('Worker connection closed.', { queueName: QUEUE_NAMES.SCAN_JOBS });
        });

        await worker.waitUntilReady();

        if (!databaseManager.isConnected()) {
          throw new Error('MongoDB connection dropped before worker became ready.');
        }

        if (state === 'starting') {
          state = 'ready';
        }
      } catch (error) {
        state = 'failed';
        handle = null;
        if (createdHandle) {
          await createdHandle.close(true).catch(() => undefined);
        }
        if (dbConnectedByStart || databaseManager.isConnected()) {
          await databaseManager.disconnect().catch(() => undefined);
        }

        if (error instanceof SecurityWorkerError) {
          throw error;
        }

        throw new SecurityWorkerError(
          `Failed to initialize security worker: ${formatSafeWorkerMessage(error, secretValues)}`,
          'WORKER_STARTUP_FAILED',
          secretValues
        );
      }
    },

    async stop(): Promise<{ timedOut: boolean }> {
      if (stopPromise) {
        return await stopPromise;
      }

      if (!handle && !databaseManager.isConnected()) {
        if (state !== 'failed') {
          state = 'stopped';
        }
        return { timedOut: false };
      }

      const activeHandle = handle;
      state = 'stopping';
      logger.info('Shutting down security worker gracefully...', {
        graceMs: config.shutdownGraceMs,
      });

      stopPromise = (async () => {
        let outcome = { timedOut: false };
        let closeError: unknown = null;

        try {
          if (activeHandle) {
            outcome = await closeWorkerWithGrace(activeHandle, config.shutdownGraceMs);
            if (outcome.timedOut) {
              logger.warn('Worker shutdown grace period elapsed; forced active worker closure.');
            }
          }
        } catch (err) {
          closeError = err;
        } finally {
          handle = null;
        }

        try {
          await databaseManager.disconnect();
        } catch (dbErr) {
          if (!closeError) {
            closeError = dbErr;
          }
        }

        if (closeError) {
          state = 'failed';
          stopPromise = null;
          throw new SecurityWorkerError(
            `Worker shutdown encountered an error: ${formatSafeWorkerMessage(closeError, secretValues)}`,
            'WORKER_STARTUP_FAILED',
            secretValues
          );
        }

        state = 'stopped';
        stopPromise = null;
        logger.info('Worker and MongoDB connections closed cleanly.');
        return outcome;
      })();

      return await stopPromise;
    },

    isReady(): boolean {
      return state === 'ready' && handle !== null && databaseManager.isConnected();
    },

    getStatus(): SecurityWorkerStatus {
      const dbStatus = databaseManager.getStatus();
      return {
        queueName: QUEUE_NAMES.SCAN_JOBS,
        state,
        isReady: this.isReady(),
        isRunning: handle ? handle.worker.isRunning() : false,
        concurrency: config.concurrency,
        database: {
          state: dbStatus.state,
          isConnected: dbStatus.isConnected,
        },
      };
    },
  };
}
