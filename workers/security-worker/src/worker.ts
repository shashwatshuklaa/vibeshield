import { pathToFileURL } from 'node:url';
import { extractRedisUrlPassword } from '@vibeshield/queue';
import { loadWorkerConfig, type WorkerConfig } from './config/env.js';
import {
  createSecurityWorkerRuntime,
  type SecurityScanJobProcessor,
  type SecurityWorkerRuntime,
  type WorkerDatabaseManagerLike,
} from './runtime/security-worker.js';
import { createWorkerLogger, formatSafeWorkerMessage, type WorkerLogger } from './utils/logger.js';

export interface StartWorkerHostOptions<TResult = unknown> {
  rawEnv?: Record<string, string | undefined>;
  config?: WorkerConfig;
  processor?: SecurityScanJobProcessor<TResult>;
  logger?: WorkerLogger;
  databaseManager?: WorkerDatabaseManagerLike;
}

export interface RunningWorkerHost {
  readonly runtime: SecurityWorkerRuntime;
  shutdown(signal?: string): Promise<{ timedOut: boolean }>;
}

/**
 * Validates worker configuration, connects MongoDB + BullMQ worker runtime cleanly, and
 * returns a deduplicated shutdown handle suitable for process signal handlers or programmatic hosts.
 */
export async function startSecurityWorkerHost<TResult = unknown>(
  options: StartWorkerHostOptions<TResult> = {}
): Promise<RunningWorkerHost> {
  const config = options.config ?? loadWorkerConfig(options.rawEnv);
  const secretValues = [extractRedisUrlPassword(config.redisUrl)].filter(
    (secret): secret is string => Boolean(secret)
  );
  const logger = options.logger ?? createWorkerLogger(config.logLevel, secretValues);

  const runtime = createSecurityWorkerRuntime({
    config,
    processor: options.processor,
    logger,
    databaseManager: options.databaseManager,
  });

  await runtime.start();

  let activeShutdown: Promise<{ timedOut: boolean }> | null = null;

  const shutdown = async (signal?: string): Promise<{ timedOut: boolean }> => {
    if (activeShutdown) {
      return await activeShutdown;
    }

    if (signal) {
      logger.info(`Received ${signal}; stopping security worker...`);
    }

    activeShutdown = runtime.stop();
    return await activeShutdown;
  };

  return {
    runtime,
    shutdown,
  };
}

/**
 * Standalone CLI bootstrap entrypoint for `@vibeshield/security-worker`.
 * Attaches SIGINT/SIGTERM listeners and exits with a non-zero code if configuration or processor
 * registration fails.
 */
export async function main(): Promise<void> {
  let host: RunningWorkerHost | null = null;
  let signalHandled = false;

  const handleSignal = (signal: NodeJS.Signals): void => {
    if (signalHandled) {
      return;
    }
    signalHandled = true;

    if (!host) {
      process.exit(0);
      return;
    }

    void host
      .shutdown(signal)
      .then((outcome) => {
        process.exit(outcome.timedOut ? 1 : 0);
      })
      .catch((error) => {
        console.error(`[SecurityWorker][ERROR] Shutdown failed: ${formatSafeWorkerMessage(error)}`);
        process.exit(1);
      });
  };

  process.once('SIGINT', handleSignal);
  process.once('SIGTERM', handleSignal);

  try {
    host = await startSecurityWorkerHost();
  } catch (error) {
    process.removeListener('SIGINT', handleSignal);
    process.removeListener('SIGTERM', handleSignal);
    console.error(`[SecurityWorker][ERROR] Startup aborted: ${formatSafeWorkerMessage(error)}`);
    process.exit(1);
  }
}

const isDirectExecution =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectExecution) {
  void main();
}
