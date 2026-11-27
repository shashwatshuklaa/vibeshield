import type { Server } from 'node:http';
import type { Express } from 'express';
import { connectDatabase, disconnectDatabase, formatSafeError } from '@vibeshield/database';
import {
  closeQueueResources,
  consumeInternalAuthNonce,
  createScanJobsQueue,
  formatSafeRedisError,
  RedisConnectionManager,
  type ManagedQueueHandle,
  type QueueRuntimeConfig,
  type RedisConnectionStatus,
} from '@vibeshield/queue';
import { createApp, type CreateAppOptions } from './app.js';
import {
  getApiConfig,
  toAuthConfig,
  toGitHubConfig,
  toInternalApiConfig,
  toQueueConfig,
} from './config/env.js';
import { createInternalApp, type CreateInternalAppOptions } from './internal-app.js';
import { createGitHubClient, type GitHubClient } from './modules/github/github.client.js';
import type { InternalScanAcquisitionService } from './modules/scans/internal-acquisition.service.js';
import type { InternalWorkerAuthMiddlewareOptions } from './modules/scans/internal-auth.js';

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
  createInternalAppFn?: (options: CreateInternalAppOptions) => Express;
  consumeInternalAuthNonce?: InternalWorkerAuthMiddlewareOptions['consumeNonce'];
  githubClient?: GitHubClient | null;
  internalAcquisitionService?: InternalScanAcquisitionService;
  verifyScanAuthorization?: CreateInternalAppOptions['verifyAuthorization'];
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
let activeInternalServer: Server | null = null;
let activeDisconnectDb: () => Promise<void> = disconnectDatabase;
let activeDisconnectQueue: () => Promise<void> = async () => undefined;
let shutdownPromise: Promise<void> | null = null;

/**
 * Returns active public and internal HTTP server handles (primarily for integration/lifecycle tests).
 */
export function getActiveServers(): {
  publicServer: Server | null;
  internalServer: Server | null;
} {
  return {
    publicServer: activeServer,
    internalServer: activeInternalServer,
  };
}

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
    createInternalAppFn = createInternalApp,
    consumeInternalAuthNonce: consumeInternalAuthNonceOverride,
    githubClient: githubClientOverride,
    internalAcquisitionService,
    verifyScanAuthorization,
    logger = DEFAULT_LOGGER,
    shutdownTimeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
  } = dependencies;

  // 1. Validate environment configuration before any database or network activity
  const config = getApiConfig(envSource);
  const internalConfig = toInternalApiConfig(config);

  // 2. Establish MongoDB connection before binding HTTP ports
  await connectDb(config.MONGODB_URI);

  // 3. Initialize optional Redis & BullMQ foundation explicitly when enabled
  const queueConfig = toQueueConfig(config);
  let ownedRedisManager: RedisConnectionManager | null = null;
  let ownedScanQueue: ManagedQueueHandle | null = null;
  const fallbackDisconnectedRedisManager = new RedisConnectionManager({ logger });

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
      if (queueConfig.required || (internalConfig !== null && !consumeInternalAuthNonceOverride)) {
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

  // 5. Bind and listen on configured public host and port
  const port = config.PORT ?? 4000;
  const host = config.HOST;

  let startedPublicServer: Server;
  try {
    startedPublicServer = await listenExpressServer(app, host, port, () => {
      logger.info?.(`[VibeShield API] Server listening on http://${host}:${port}`);
      logger.info?.(
        `[VibeShield API] Liveness endpoint at http://${host}:${port}${config.API_PREFIX}/health/live`
      );
      logger.info?.(
        `[VibeShield API] Readiness endpoint at http://${host}:${port}${config.API_PREFIX}/health/ready`
      );
    });
  } catch (error) {
    // Ensure queue and database connections are not left dangling if public HTTP server fails to bind
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

  // 6. Bind and listen on separate loopback/private internal worker listener when enabled
  let startedInternalServer: Server | null = null;
  if (internalConfig) {
    const consumeNonce =
      consumeInternalAuthNonceOverride ??
      ((nonceInput) =>
        consumeInternalAuthNonce(
          ownedRedisManager ?? fallbackDisconnectedRedisManager,
          nonceInput
        ));

    const resolvedGitHubClient =
      githubClientOverride !== undefined
        ? githubClientOverride
        : githubConfig
          ? createGitHubClient({
              config: githubConfig,
              timeoutMs: internalConfig.githubRequestTimeoutMs,
            })
          : null;

    const internalApp = createInternalAppFn({
      auth: {
        workerAuthSecret: internalConfig.workerAuthSecret,
        timestampToleranceMs: internalConfig.timestampToleranceMs,
        nonceTtlMs: internalConfig.nonceTtlMs,
        consumeNonce,
      },
      githubClient: resolvedGitHubClient,
      maxArchiveBytes: internalConfig.maxArchiveBytes,
      githubRequestTimeoutMs: internalConfig.githubRequestTimeoutMs,
      codeloadTimeoutMs: internalConfig.codeloadTimeoutMs,
      totalAcquisitionTimeoutMs: internalConfig.totalAcquisitionTimeoutMs,
      ...(internalAcquisitionService ? { acquisitionService: internalAcquisitionService } : {}),
      ...(verifyScanAuthorization ? { verifyAuthorization: verifyScanAuthorization } : {}),
    });

    try {
      startedInternalServer = await listenExpressServer(
        internalApp,
        internalConfig.host,
        internalConfig.port,
        () => {
          logger.info?.(
            `[VibeShield Internal API] Internal worker listener bound on http://${internalConfig.host}:${internalConfig.port}`
          );
        }
      );
    } catch (error) {
      await closeHttpServerWithTimeout(startedPublicServer, shutdownTimeoutMs, logger).catch(
        (closeError) => {
          logger.error?.(
            `[VibeShield API] Failed to close public HTTP server after internal listener failure: ${formatSafeError(closeError)}`
          );
        }
      );
      await resolvedDisconnectQueue().catch((queueDisconnectError) => {
        logger.error?.(
          `[VibeShield API] Failed to disconnect Redis/queue after internal listener failure: ${formatSafeRedisError(queueDisconnectError)}`
        );
      });
      await disconnectDb().catch((disconnectError) => {
        logger.error?.(
          `[VibeShield API] Failed to disconnect MongoDB after internal listener failure: ${formatSafeError(disconnectError)}`
        );
      });
      throw error;
    }
  }

  activeServer = startedPublicServer;
  activeInternalServer = startedInternalServer;
  activeDisconnectDb = disconnectDb;
  activeDisconnectQueue = resolvedDisconnectQueue;
  return startedPublicServer;
}

function listenExpressServer(
  expressApp: Express,
  host: string,
  port: number,
  onReady: () => void
): Promise<Server> {
  return new Promise<Server>((resolve, reject) => {
    const candidateServer = expressApp.listen(port, host);

    const onError = (error: Error) => {
      candidateServer.off('listening', onListening);
      reject(error);
    };

    const onListening = () => {
      candidateServer.off('error', onError);
      onReady();
      resolve(candidateServer);
    };

    candidateServer.once('error', onError);
    candidateServer.once('listening', onListening);
  });
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
  const internalServerToClose = activeInternalServer;

  shutdownPromise = (async () => {
    let shutdownError: Error | null = null;

    logger.info?.(`[VibeShield API] Received ${signal}. Starting graceful shutdown...`);

    if (internalServerToClose) {
      try {
        await closeHttpServerWithTimeout(internalServerToClose, shutdownTimeoutMs, logger);
        logger.info?.('[VibeShield Internal API] Internal worker listener closed gracefully.');
      } catch (error) {
        shutdownError = error instanceof Error ? error : new Error(formatSafeError(error));
        logger.error?.(
          `[VibeShield Internal API] Error while closing internal worker listener: ${formatSafeError(error)}`
        );
      }
    }

    if (serverToClose) {
      try {
        await closeHttpServerWithTimeout(serverToClose, shutdownTimeoutMs, logger);
        logger.info?.('[VibeShield API] HTTP server closed gracefully.');
      } catch (error) {
        if (!shutdownError) {
          shutdownError = error instanceof Error ? error : new Error(formatSafeError(error));
        }
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
      activeInternalServer = null;
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
  activeInternalServer = null;
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
