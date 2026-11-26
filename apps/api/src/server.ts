import type { Server } from 'node:http';
import type { Express } from 'express';
import { connectDatabase, disconnectDatabase, formatSafeError } from '@vibeshield/database';
import { createApp, type CreateAppOptions } from './app.js';
import { getApiConfig } from './config/env.js';

export interface ServerLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

export interface ServerDependencies {
  envSource?: Record<string, string | undefined>;
  connectDb?: (uri: string) => Promise<void>;
  disconnectDb?: () => Promise<void>;
  createAppFn?: (options?: CreateAppOptions) => Express;
  logger?: ServerLogger;
  shutdownTimeoutMs?: number;
}

export interface ShutdownDependencies {
  disconnectDb?: () => Promise<void>;
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
let shutdownPromise: Promise<void> | null = null;

/**
 * Starts the VibeShield API server following the strict lifecycle sequence:
 * 1. Validate environment configuration.
 * 2. Connect to MongoDB.
 * 3. Start the HTTP server only after database connection succeeds.
 */
export async function startServer(dependencies: ServerDependencies = {}): Promise<Server> {
  const {
    envSource,
    connectDb = (uri: string) => connectDatabase(uri),
    disconnectDb = () => disconnectDatabase(),
    createAppFn = createApp,
    logger = DEFAULT_LOGGER,
  } = dependencies;

  // 1. Validate environment configuration before any database or network activity
  const config = getApiConfig(envSource);

  // 2. Establish MongoDB connection before binding HTTP port
  await connectDb(config.MONGODB_URI);

  // 3. Instantiate Express application
  const app = createAppFn({ apiPrefix: config.API_PREFIX });

  // 4. Bind and listen on configured host and port
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
    return startedServer;
  } catch (error) {
    // Ensure database connection is not left dangling if HTTP server fails to bind
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
 * Gracefully shuts down the HTTP server and disconnects MongoDB.
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
