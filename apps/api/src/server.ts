import type { Server } from 'node:http';
import type { Express } from 'express';
import { connectDatabase, disconnectDatabase, formatSafeError } from '@vibeshield/database';
import {
  closeQueueResources,
  createScanJobsQueue,
  formatSafeRedisError,
  RedisConnectionManager,
  type ManagedQueueHandle,
  type QueueRuntimeConfig,
  type RedisConnectionStatus,
} from '@vibeshield/queue';
import { createApp, type CreateAppOptions } from './app.js';
import { getApiConfig, toAuthConfig, toGitHubConfig, toQueueConfig } from './config/env.js';

export interface ServerLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

export interface ServerDependencies {
  envSource?: Record<string, string | undefined>;
  connectDb?: (uri: string) => Promise<void>;
  disconnectDb?: () => Promise<void>;
  connectQueue?: (config: QueueRuntimeConfig) => Promise<void>;
  disconnectQueue?: () => Promise<void>;
  getQueueStatus?: () => RedisConnectionStatus & { required?: boolean };
  createAppFn?: (options?: CreateAppOptions) => Express;
  logger?: ServerLogger;
  shutdownTimeoutMs?: number;
}

export interface ShutdownDependencies {
  disconnectDb?: () => Promise<void>;
  disconnectQueue?: () => Promise<void>;
  logger?: ServerLogger;
  shutdownTimeoutMs?: number;
}

const DEFAULT_LOGGER: Required<ServerLogger> = {
  info: (message: string) => console.log(message),
  warn: (message: string) => console.warn(message),
  error: (message: string) => console.error(message),
};

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;

let activeServer: Server | null = null;
let activeDisconnectDb: () => Promise<void> = disconnectDatabase;
let activeDisconnectQueue: () => Promise<void> = async () => undefined;
let shutdownPromise: Promise<void> | null = null;

/**
 * Starts the VibeShield API server following the strict lifecycle sequence:
 * 1. Validate environment configuration.
 * 2. Connect to MongoDB.
 * 3. Initialize optional Redis & BullMQ queue infrastructure if enabled.
 * 4. Start the HTTP server only after required dependencies succeed.
 */
export async function startServer(dependencies: ServerDependencies = {}): Promise<Server> {
  const {
    envSource,
    connectDb = (uri: string) => connectDatabase(uri),
    disconnectDb = () => disconnectDatabase(),
    connectQueue,
    disconnectQueue,
    getQueueStatus,
    createAppFn = createApp,
    logger = DEFAULT_LOGGER,
  } = dependencies;

  // 1. Validate environment configuration before any database or network activity
  const config = getApiConfig(envSource);

  // 2. Establish MongoDB connection before binding HTTP port
  await connectDb(config.MONGODB_URI);

  // 3. Initialize optional Redis & BullMQ foundation explicitly when enabled
  const queueConfig = toQueueConfig(config);
  let ownedRedisManager: RedisConnectionManager | null = null;
  let ownedScanQueue: ManagedQueueHandle | null = null;

  const resolvedDisconnectQueue: () => Promise<void> = disconnectQueue
    ? disconnectQueue
    : async () => {
        if (ownedScanQueue || ownedRedisManager) {
          await closeQueueResources(
            [ownedScanQueue],
            ownedRedisManager ?? new RedisConnectionManager({ logger })
          );
          ownedScanQueue = null;
          ownedRedisManager = null;
        }
      };

  const resolvedGetQueueStatus: () => RedisConnectionStatus & { required?: boolean } =
    getQueueStatus ??
    (() => {
      if (!queueConfig) {
        return { enabled: false, state: 'disabled', isConnected: false, required: false };
      }
      if (!ownedRedisManager) {
        return {
          enabled: true,
          state: 'not_initialized',
          isConnected: false,
          required: queueConfig.required,
        };
      }
      return {
        ...ownedRedisManager.getStatus(true),
        required: queueConfig.required,
      };
    });

  if (queueConfig) {
    try {
      if (connectQueue) {
        await connectQueue(queueConfig);
      } else {
        ownedRedisManager = new RedisConnectionManager({ logger });
        await ownedRedisManager.connect(queueConfig.redis);
        ownedScanQueue = createScanJobsQueue(ownedRedisManager, {
          defaultJobOptions: {
            attempts: queueConfig.defaultAttempts,
            backoff: {
              type: 'exponential',
              delay: queueConfig.backoffDelayMs,
            },
          },
        });
      }
    } catch (queueError) {
      const safeQueueError = formatSafeRedisError(queueError);
      if (queueConfig.required) {
        await resolvedDisconnectQueue().catch(() => undefined);
        await disconnectDb().catch(() => undefined);
        throw queueError;
      }
      logger.warn?.(
        `[VibeShield API] Optional queue initialization unavailable; continuing without queue readiness: ${safeQueueError}`
      );
    }
  }

  // 4. Instantiate Express application
  const authConfig = toAuthConfig(config);
  const githubConfig = toGitHubConfig(config);
  const app = createAppFn({
    apiPrefix: config.API_PREFIX,
    authConfig,
    githubConfig,
    health: {
      getQueueStatus: resolvedGetQueueStatus,
    },
  });

  // 5. Bind and listen on configured host and port
  const port = config.PORT ?? 4000;
  const host = config.HOST;

  try {
    const startedServer = await new Promise<Server>((resolve, reject) => {
      const candidateServer = app.listen(port, host);

      const onError = (error: Error) => {
        candidateServer.off('listening', onListening);
        reject(error);
      };

      const onListening = () => {
        candidateServer.off('error', onError);
        logger.info?.(`[VibeShield API] Server listening on http://${host}:${port}`);
        logger.info?.(
          `[VibeShield API] Liveness endpoint at http://${host}:${port}${config.API_PREFIX}/health/live`
        );
        logger.info?.(
          `[VibeShield API] Readiness endpoint at http://${host}:${port}${config.API_PREFIX}/health/ready`
        );
        resolve(candidateServer);
      };

      candidateServer.once('error', onError);
      candidateServer.once('listening', onListening);
    });

    activeServer = startedServer;
    activeDisconnectDb = disconnectDb;
    activeDisconnectQueue = resolvedDisconnectQueue;
    return startedServer;
  } catch (error) {
    // Ensure queue and database connections are not left dangling if HTTP server fails to bind
    try {
      await resolvedDisconnectQueue();
    } catch (queueDisconnectError) {
      logger.error?.(
        `[VibeShield API] Failed to disconnect Redis/queue after HTTP listen failure: ${formatSafeRedisError(queueDisconnectError)}`
      );
    }
    try {
      await disconnectDb();
    } catch (disconnectError) {
      logger.error?.(
        `[VibeShield API] Failed to disconnect MongoDB after HTTP listen failure: ${formatSafeError(disconnectError)}`
      );
    }
    throw error;
  }
}

/**
 * Gracefully shuts down the HTTP server, queue/Redis connections, and MongoDB.
 * Deduplicates concurrent shutdown calls and enforces a close timeout so the process never hangs.
 */
export function shutdownServer(
  signal: string,
  dependencies: ShutdownDependencies = {}
): Promise<void> {
  if (shutdownPromise) {
    return shutdownPromise;
  }

  const {
    disconnectDb = activeDisconnectDb,
    disconnectQueue = activeDisconnectQueue,
    logger = DEFAULT_LOGGER,
    shutdownTimeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
  } = dependencies;

  const serverToClose = activeServer;

  shutdownPromise = (async () => {
    let shutdownError: Error | null = null;

    logger.info?.(`[VibeShield API] Received ${signal}. Starting graceful shutdown...`);

    if (serverToClose) {
      try {
        await closeHttpServerWithTimeout(serverToClose, shutdownTimeoutMs, logger);
        logger.info?.('[VibeShield API] HTTP server closed gracefully.');
      } catch (error) {
        shutdownError = error instanceof Error ? error : new Error(formatSafeError(error));
        logger.error?.(
          `[VibeShield API] Error while closing HTTP server: ${formatSafeError(error)}`
        );
      }
    }

    try {
      await disconnectQueue();
    } catch (error) {
      if (!shutdownError) {
        shutdownError = error instanceof Error ? error : new Error(formatSafeRedisError(error));
      }
      logger.error?.(
        `[VibeShield API] Error while disconnecting Redis/queue: ${formatSafeRedisError(error)}`
      );
    }

    try {
      await disconnectDb();
      logger.info?.('[VibeShield API] MongoDB connection closed.');
    } catch (error) {
      if (!shutdownError) {
        shutdownError = error instanceof Error ? error : new Error(formatSafeError(error));
      }
      logger.error?.(
        `[VibeShield API] Error while disconnecting MongoDB: ${formatSafeError(error)}`
      );
    } finally {
      activeServer = null;
      activeDisconnectDb = disconnectDatabase;
      activeDisconnectQueue = async () => undefined;
      shutdownPromise = null;
    }

    if (shutdownError) {
      throw shutdownError;
    }
  })();

  return shutdownPromise;
}

async function closeHttpServerWithTimeout(
  serverToClose: Server,
  timeoutMs: number,
  logger: ServerLogger
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      logger.warn?.(
        `[VibeShield API] Graceful HTTP shutdown timed out after ${timeoutMs}ms. Forcing remaining connections closed.`
      );
      if (typeof serverToClose.closeAllConnections === 'function') {
        serverToClose.closeAllConnections();
      }
      resolve();
    }, timeoutMs);

    if (typeof timer.unref === 'function') {
      timer.unref();
    }

    serverToClose.close((error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

/**
 * Resets internal server lifecycle state. Intended for isolated test suites only.
 */
export function resetServerStateForTests(): void {
  activeServer = null;
  activeDisconnectDb = disconnectDatabase;
  activeDisconnectQueue = async () => undefined;
  shutdownPromise = null;
}

/**
 * Bootstraps the API process and exits non-zero if startup fails.
 */
export async function bootstrapServer(
  dependencies: ServerDependencies & { exit?: (code: number) => void } = {}
): Promise<Server | undefined> {
  const { logger = DEFAULT_LOGGER, exit = (code: number) => process.exit(code) } = dependencies;

  try {
    return await startServer(dependencies);
  } catch (error) {
    logger.error?.(`[VibeShield API] Failed to start server: ${formatSafeError(error)}`);
    exit(1);
    return undefined;
  }
}

// Register process signal handlers only when directly executed as the main entrypoint
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('server.ts') || process.argv[1].endsWith('server.js'));

if (isDirectExecution && process.env.NODE_ENV !== 'test') {
  const handleSignal = (signal: string) => {
    shutdownServer(signal)
      .then(() => {
        process.exit(0);
      })
      .catch(() => {
        process.exit(1);
      });
  };

  process.on('SIGINT', () => handleSignal('SIGINT'));
  process.on('SIGTERM', () => handleSignal('SIGTERM'));

  void bootstrapServer();
}
