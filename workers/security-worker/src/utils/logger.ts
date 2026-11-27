import { redactGitHubSecrets, redactMongoUri } from '@vibeshield/database';
import type { BaseEnv } from '@vibeshield/env';
import { formatSafeRedisError } from '@vibeshield/queue';

export type WorkerLogLevel = BaseEnv['LOG_LEVEL'] | 'silent';

export interface WorkerLogger {
  info(message: string, context?: Record<string, unknown>): void;
  warn(message: string, context?: Record<string, unknown>): void;
  error(message: string, context?: Record<string, unknown>): void;
}

const LOG_LEVEL_WEIGHT: Record<WorkerLogLevel, number> = {
  silly: 5,
  debug: 10,
  verbose: 15,
  http: 18,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

/**
 * Redacts MongoDB URIs, Redis URLs, embedded credentials, GitHub tokens, and explicit runtime secrets.
 */
export function formatSafeWorkerMessage(
  input: unknown,
  extraSecrets: readonly string[] = []
): string {
  const redisScrubbed = formatSafeRedisError(input, [...extraSecrets]);
  return redactGitHubSecrets(redactMongoUri(redisScrubbed), extraSecrets);
}

function sanitizeContextValue(value: unknown, extraSecrets: readonly string[]): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return formatSafeWorkerMessage(value, extraSecrets);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (value instanceof Error) {
    return formatSafeWorkerMessage(value, extraSecrets);
  }
  return '[REDACTED_OBJECT]';
}

function formatLine(
  level: 'INFO' | 'WARN' | 'ERROR',
  message: string,
  context: Record<string, unknown> | undefined,
  extraSecrets: readonly string[]
): string {
  const safeMessage = formatSafeWorkerMessage(message, extraSecrets);
  if (!context || Object.keys(context).length === 0) {
    return `[SecurityWorker][${level}] ${safeMessage}`;
  }

  const sanitizedContext: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(context)) {
    sanitizedContext[key] = sanitizeContextValue(val, extraSecrets);
  }
  return `[SecurityWorker][${level}] ${safeMessage} ${JSON.stringify(sanitizedContext)}`;
}

/**
 * Creates a credential-redacting logger bounded to the configured minimum log level.
 */
export function createWorkerLogger(
  level: WorkerLogLevel = 'info',
  extraSecrets: readonly string[] = []
): WorkerLogger {
  const minWeight = LOG_LEVEL_WEIGHT[level] ?? LOG_LEVEL_WEIGHT.info;

  return {
    info(message: string, context?: Record<string, unknown>): void {
      if (minWeight <= LOG_LEVEL_WEIGHT.info) {
        console.log(formatLine('INFO', message, context, extraSecrets));
      }
    },
    warn(message: string, context?: Record<string, unknown>): void {
      if (minWeight <= LOG_LEVEL_WEIGHT.warn) {
        console.warn(formatLine('WARN', message, context, extraSecrets));
      }
    },
    error(message: string, context?: Record<string, unknown>): void {
      if (minWeight <= LOG_LEVEL_WEIGHT.error) {
        console.error(formatLine('ERROR', message, context, extraSecrets));
      }
    },
  };
}
