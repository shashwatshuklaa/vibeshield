import { Redis, type RedisOptions } from 'ioredis';
import { QUEUE_KEY_PREFIX } from './contracts.js';
import {
  extractRedisUrlPassword,
  formatSafeRedisError,
  isTlsRedisUrl,
  isValidRedisUrl,
} from './redaction.js';
import type {
  QueueLogger,
  RedisConfigOptions,
  RedisConnectionRole,
  RedisConnectionState,
  RedisConnectionStatus,
} from './types.js';

export const DEFAULT_REDIS_OPTIONS = Object.freeze({
  connectTimeoutMs: 5000,
  maxRetriesPerRequest: 3,
  maxReconnectAttempts: 10,
  retryDelayBaseMs: 200,
  maxRetryDelayMs: 3000,
});

const DEFAULT_LOGGER: Required<QueueLogger> = {
  info: (message: string) => console.log(message),
  warn: (message: string) => console.warn(message),
  error: (message: string) => console.error(message),
};

export interface RedisClientLike {
  status: string;
  connect(): Promise<unknown>;
  ping(): Promise<string>;
  set?(
    key: string,
    value: string,
    expiryMode: 'PX',
    ttlMs: number,
    condition: 'NX'
  ): Promise<'OK' | null>;
  eval?(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  quit(): Promise<unknown>;
  disconnect(reconnect?: boolean): void;
  duplicate?(override?: Partial<RedisOptions>): RedisClientLike;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export class RedisConnectionError extends Error {
  public readonly code: string;

  constructor(message: string, code = 'REDIS_CONNECTION_ERROR', rawSecrets: string[] = []) {
    super(formatSafeRedisError(message, rawSecrets));
    this.name = 'RedisConnectionError';
    this.code = code;
  }
}

/**
 * Parses a validated `redis://` or `rediss://` URL and constructs ioredis options tailored to
 * the caller's BullMQ lifecycle role:
 * - `'queue'`: bounded `maxRetriesPerRequest`, fast-fail `enableOfflineQueue: false`, optional `commandTimeout`.
 * - `'worker'`: `maxRetriesPerRequest: null` (required by BullMQ blocking commands) and no short `commandTimeout`.
 */
export function buildRedisConnectionOptions(
  config: RedisConfigOptions,
  role: RedisConnectionRole = 'queue'
): RedisOptions {
  if (!isValidRedisUrl(config.url)) {
    throw new RedisConnectionError('Invalid Redis connection URI provided.', 'INVALID_REDIS_URL');
  }

  const parsed = new URL(config.url);
  const password = parsed.password ? decodeURIComponent(parsed.password) : undefined;
  const username = parsed.username ? decodeURIComponent(parsed.username) : undefined;
  const port = parsed.port ? Number(parsed.port) : 6379;
  const db =
    parsed.pathname && parsed.pathname !== '/' ? Number(parsed.pathname.slice(1)) : undefined;

  const connectTimeout = config.connectTimeoutMs ?? DEFAULT_REDIS_OPTIONS.connectTimeoutMs;
  if (!Number.isInteger(connectTimeout) || connectTimeout < 100 || connectTimeout > 60_000) {
    throw new RedisConnectionError(
      'Redis connectTimeoutMs must be between 100ms and 60000ms.',
      'INVALID_REDIS_CONFIG'
    );
  }

  const maxReconnectAttempts =
    config.maxReconnectAttempts ?? DEFAULT_REDIS_OPTIONS.maxReconnectAttempts;
  const retryDelayBaseMs = config.retryDelayBaseMs ?? DEFAULT_REDIS_OPTIONS.retryDelayBaseMs;
  const maxRetryDelayMs = config.maxRetryDelayMs ?? DEFAULT_REDIS_OPTIONS.maxRetryDelayMs;

  const options: RedisOptions = {
    host: parsed.hostname,
    port,
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
    ...(db !== undefined ? { db } : {}),
    connectTimeout,
    lazyConnect: true,
    enableReadyCheck: true,
    ...(role === 'worker'
      ? {
          maxRetriesPerRequest: null,
          enableOfflineQueue: true,
        }
      : {
          maxRetriesPerRequest:
            config.maxRetriesPerRequest ?? DEFAULT_REDIS_OPTIONS.maxRetriesPerRequest,
          enableOfflineQueue: config.enableOfflineQueue ?? false,
          ...(config.commandTimeoutMs !== undefined
            ? { commandTimeout: config.commandTimeoutMs }
            : {}),
        }),
    retryStrategy(times: number): number | null {
      if (times > maxReconnectAttempts) {
        return null;
      }
      return Math.min(times * retryDelayBaseMs, maxRetryDelayMs);
    },
  };

  if (isTlsRedisUrl(config.url)) {
    options.tls =
      config.tlsRejectUnauthorized === false
        ? { rejectUnauthorized: false }
        : { rejectUnauthorized: true };
  }

  return options;
}

export interface RedisConnectionManagerOptions {
  logger?: QueueLogger;
  createClient?: (options: RedisOptions) => RedisClientLike;
}

/**
 * Explicit Redis connection lifecycle manager that never opens network connections on import,
 * deduplicates concurrent connects, redacts credentials from logs/errors, and provides separate
 * role-configured clients for BullMQ queues vs workers.
 */
export class RedisConnectionManager {
  private readonly logger: QueueLogger;
  private readonly createClient: (options: RedisOptions) => RedisClientLike;
  private client: RedisClientLike | null = null;
  private activeUrl: string | null = null;
  private activeConfig: RedisConfigOptions | null = null;
  private state: RedisConnectionState = 'not_initialized';
  private connectingPromise: Promise<void> | null = null;
  private disconnectingPromise: Promise<void> | null = null;

  constructor(options: RedisConnectionManagerOptions = {}) {
    this.logger = options.logger ?? DEFAULT_LOGGER;
    this.createClient =
      options.createClient ?? ((redisOpts) => new Redis(redisOpts) as unknown as RedisClientLike);
  }

  public getState(): RedisConnectionState {
    if (this.client) {
      const rawStatus = this.client.status;
      if (rawStatus === 'ready') {
        return 'connected';
      }
      if (rawStatus === 'reconnecting') {
        return 'reconnecting';
      }
      if (rawStatus === 'connecting' || rawStatus === 'connect') {
        return 'connecting';
      }
    }
    return this.state;
  }

  public isConnected(): boolean {
    return this.getState() === 'connected';
  }

  public getStatus(enabled = true): RedisConnectionStatus {
    if (!enabled) {
      return {
        enabled: false,
        state: 'disabled',
        isConnected: false,
      };
    }

    const currentState = this.getState();
    return {
      enabled: true,
      state: currentState,
      isConnected: currentState === 'connected',
    };
  }

  /**
   * Returns the connected Queue producer Redis client, or throws if not initialized/connected.
   */
  public getQueueClient(): RedisClientLike {
    if (!this.client) {
      throw new RedisConnectionError(
        'Redis queue connection is not initialized.',
        'REDIS_NOT_INITIALIZED'
      );
    }
    return this.client;
  }

  /**
   * Returns connection options configured specifically for a BullMQ `Worker` (`maxRetriesPerRequest: null`)
   * without mutating or sharing the API Queue producer connection.
   */
  public getWorkerConnectionOptions(): RedisOptions {
    if (!this.activeConfig) {
      throw new RedisConnectionError(
        'Redis connection configuration is not initialized.',
        'REDIS_NOT_INITIALIZED'
      );
    }
    return buildRedisConnectionOptions(this.activeConfig, 'worker');
  }

  public async connect(config: RedisConfigOptions): Promise<void> {
    if (!isValidRedisUrl(config.url)) {
      throw new RedisConnectionError('Invalid Redis connection URI provided.', 'INVALID_REDIS_URL');
    }

    const passwordSecret = extractRedisUrlPassword(config.url);
    const secrets = passwordSecret ? [passwordSecret] : [];

    if (this.disconnectingPromise) {
      await this.disconnectingPromise;
    }

    if (this.connectingPromise) {
      if (this.activeUrl === config.url) {
        return this.connectingPromise;
      }
      throw new RedisConnectionError(
        'A Redis connection attempt to a different target is already in progress.',
        'CONNECTION_IN_PROGRESS',
        secrets
      );
    }

    if (this.client && this.isConnected()) {
      if (this.activeUrl === config.url) {
        return;
      }
      throw new RedisConnectionError(
        'Redis is already connected to a different target. Disconnect before reconnecting.',
        'ALREADY_CONNECTED',
        secrets
      );
    }

    const redisOpts = buildRedisConnectionOptions(config, 'queue');
    const candidateClient = this.createClient(redisOpts);
    this.attachListeners(candidateClient, secrets);

    this.client = candidateClient;
    this.activeUrl = config.url;
    this.activeConfig = { ...config };
    this.state = 'connecting';

    this.connectingPromise = (async () => {
      try {
        await candidateClient.connect();
        await candidateClient.ping();
        this.state = 'connected';
        this.logger.info?.('[queue] Redis connection established.');
      } catch (error) {
        this.state = 'unavailable';
        this.client = null;
        this.activeUrl = null;
        this.activeConfig = null;
        try {
          candidateClient.disconnect(false);
        } catch {
          // Best-effort socket cleanup after failed connect
        }
        const safeMessage = formatSafeRedisError(error, secrets);
        this.logger.error?.(`[queue] Failed to connect to Redis: ${safeMessage}`);
        throw new RedisConnectionError(
          `Failed to connect to Redis: ${safeMessage}`,
          'CONNECTION_FAILED',
          secrets
        );
      } finally {
        this.connectingPromise = null;
      }
    })();

    return this.connectingPromise;
  }

  public async ping(): Promise<boolean> {
    if (!this.client) {
      return false;
    }
    try {
      const reply = await this.client.ping();
      return reply === 'PONG';
    } catch {
      return false;
    }
  }

  public async disconnect(): Promise<void> {
    if (this.disconnectingPromise) {
      return this.disconnectingPromise;
    }

    if (this.connectingPromise) {
      await this.connectingPromise.catch(() => undefined);
    }

    const targetClient = this.client;
    if (!targetClient) {
      this.state = 'not_initialized';
      return;
    }

    const secrets = this.activeUrl ? [extractRedisUrlPassword(this.activeUrl) ?? ''] : [];
    this.state = 'disconnecting';

    this.disconnectingPromise = (async () => {
      try {
        await targetClient.quit();
        this.logger.info?.('[queue] Redis connection closed cleanly.');
      } catch (error) {
        try {
          targetClient.disconnect(false);
        } catch {
          // Best-effort force disconnect after quit failure
        }
        const safeMessage = formatSafeRedisError(error, secrets);
        this.logger.warn?.(`[queue] Redis quit returned an error (socket closed): ${safeMessage}`);
      } finally {
        this.client = null;
        this.activeUrl = null;
        this.activeConfig = null;
        this.state = 'not_initialized';
        this.disconnectingPromise = null;
      }
    })();

    return this.disconnectingPromise;
  }

  private attachListeners(client: RedisClientLike, secrets: string[]): void {
    client.on('ready', () => {
      this.state = 'connected';
    });

    client.on('reconnecting', () => {
      this.state = 'reconnecting';
      this.logger.warn?.('[queue] Redis client reconnecting...');
    });

    client.on('error', (error: unknown) => {
      if (this.state === 'connected') {
        this.state = 'unavailable';
      }
      this.logger.error?.(`[queue] Redis error: ${formatSafeRedisError(error, secrets)}`);
    });

    client.on('end', () => {
      if (this.state !== 'disconnecting' && this.state !== 'not_initialized') {
        this.state = 'unavailable';
        this.logger.warn?.('[queue] Redis connection closed.');
      }
    });
  }
}

export const defaultRedisManager = new RedisConnectionManager();

const INTERNAL_AUTH_NONCE_REGEX = /^[A-Za-z0-9._-]{16,128}$/;
const INTERNAL_AUTH_NONCE_NAMESPACE_REGEX = /^[a-z0-9._:-]{1,64}$/;
const MAX_INTERNAL_AUTH_NONCE_TTL_MS = 3_600_000;

export type ConsumeInternalAuthNonceResult = 'ACCEPTED' | 'REPLAYED';

export class InternalAuthReplayProtectionError extends Error {
  public readonly code: string;

  constructor(
    message: string,
    code = 'INTERNAL_AUTH_REPLAY_PROTECTION_UNAVAILABLE',
    rawSecrets: string[] = []
  ) {
    super(formatSafeRedisError(message, rawSecrets));
    this.name = 'InternalAuthReplayProtectionError';
    this.code = code;
  }
}

/**
 * Constructs a canonical, fixed-namespace Redis key for single-use internal worker auth nonces.
 */
export function buildInternalAuthNonceKey(nonce: string, namespace = 'default'): string {
  if (!INTERNAL_AUTH_NONCE_REGEX.test(nonce)) {
    throw new InternalAuthReplayProtectionError(
      'Internal authentication nonce format is invalid.',
      'INVALID_INTERNAL_AUTH_NONCE'
    );
  }
  if (!INTERNAL_AUTH_NONCE_NAMESPACE_REGEX.test(namespace)) {
    throw new InternalAuthReplayProtectionError(
      'Internal authentication nonce namespace format is invalid.',
      'INVALID_INTERNAL_AUTH_NAMESPACE'
    );
  }
  return `${QUEUE_KEY_PREFIX}:internal-auth-nonce:${namespace}:${nonce}`;
}

/**
 * Atomically records a single-use internal authentication nonce in Redis (`SET key 1 PX ttl NX`).
 * Fails closed whenever Redis is disconnected, unavailable, lacks `SET NX PX`, or errors so replay
 * protection can never silently degrade to fail-open.
 */
export async function consumeInternalAuthNonce(
  manager: Pick<RedisConnectionManager, 'isConnected' | 'getQueueClient'>,
  input: {
    nonce: string;
    ttlMs: number;
    namespace?: string;
  }
): Promise<ConsumeInternalAuthNonceResult> {
  const key = buildInternalAuthNonceKey(input.nonce, input.namespace ?? 'default');

  if (
    !Number.isInteger(input.ttlMs) ||
    input.ttlMs < 1_000 ||
    input.ttlMs > MAX_INTERNAL_AUTH_NONCE_TTL_MS
  ) {
    throw new InternalAuthReplayProtectionError(
      `Internal auth nonce TTL must be an integer between 1000 and ${MAX_INTERNAL_AUTH_NONCE_TTL_MS} ms.`,
      'INVALID_INTERNAL_AUTH_TTL'
    );
  }

  if (!manager.isConnected()) {
    throw new InternalAuthReplayProtectionError(
      'Redis replay protection store is not connected.',
      'REDIS_REPLAY_STORE_UNAVAILABLE'
    );
  }

  let client: RedisClientLike;
  try {
    client = manager.getQueueClient();
  } catch (error) {
    throw new InternalAuthReplayProtectionError(
      `Redis replay protection store is unavailable: ${formatSafeRedisError(error)}`,
      'REDIS_REPLAY_STORE_UNAVAILABLE'
    );
  }

  if (typeof client.set !== 'function') {
    throw new InternalAuthReplayProtectionError(
      'Redis client does not support atomic SET NX PX replay protection.',
      'REDIS_REPLAY_STORE_UNSUPPORTED'
    );
  }

  try {
    const reply = await client.set(key, '1', 'PX', input.ttlMs, 'NX');
    return reply === 'OK' ? 'ACCEPTED' : 'REPLAYED';
  } catch (error) {
    throw new InternalAuthReplayProtectionError(
      `Redis replay protection check failed: ${formatSafeRedisError(error)}`,
      'REDIS_REPLAY_STORE_ERROR'
    );
  }
}

const RATE_LIMIT_IDENTIFIER_REGEX = /^[A-Za-z0-9._-]{1,128}$/;
const MAX_RATE_LIMIT_WINDOW_MS = 3_600_000;

const SCAN_CREATE_RATE_LIMIT_LUA = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return { current, ttl }
`;

export interface ScanRateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAtMs: number;
  retryAfterSeconds: number;
}

export class ScanRateLimitBackendError extends Error {
  public readonly code: string;

  constructor(
    message: string,
    code = 'SCAN_RATE_LIMIT_BACKEND_UNAVAILABLE',
    rawSecrets: string[] = []
  ) {
    super(formatSafeRedisError(message, rawSecrets));
    this.name = 'ScanRateLimitBackendError';
    this.code = code;
  }
}

/**
 * Constructs a canonical, fixed-namespace Redis key for per-(organization, user) scan creation rate limits.
 */
export function buildScanCreationRateLimitKey(organizationId: string, userId: string): string {
  if (!RATE_LIMIT_IDENTIFIER_REGEX.test(organizationId)) {
    throw new ScanRateLimitBackendError(
      'Rate-limit organization identifier format is invalid.',
      'INVALID_RATE_LIMIT_IDENTIFIER'
    );
  }
  if (!RATE_LIMIT_IDENTIFIER_REGEX.test(userId)) {
    throw new ScanRateLimitBackendError(
      'Rate-limit user identifier format is invalid.',
      'INVALID_RATE_LIMIT_IDENTIFIER'
    );
  }
  return `${QUEUE_KEY_PREFIX}:rate-limit:scan-create:${organizationId}:${userId}`;
}

/**
 * Atomically increments and evaluates a fixed-window scan-creation rate limit in Redis.
 * Fails closed whenever Redis is disconnected, unavailable, lacks `EVAL`, or errors so
 * rate limiting can never silently degrade to fail-open.
 */
export async function consumeScanCreationRateLimit(
  manager: Pick<RedisConnectionManager, 'isConnected' | 'getQueueClient'>,
  input: {
    organizationId: string;
    userId: string;
    maxRequests: number;
    windowMs: number;
    nowMs?: number;
  }
): Promise<ScanRateLimitDecision> {
  const key = buildScanCreationRateLimitKey(input.organizationId, input.userId);

  if (!Number.isInteger(input.maxRequests) || input.maxRequests < 1 || input.maxRequests > 10_000) {
    throw new ScanRateLimitBackendError(
      'Rate-limit maxRequests must be an integer between 1 and 10000.',
      'INVALID_RATE_LIMIT_CONFIG'
    );
  }

  if (
    !Number.isInteger(input.windowMs) ||
    input.windowMs < 1_000 ||
    input.windowMs > MAX_RATE_LIMIT_WINDOW_MS
  ) {
    throw new ScanRateLimitBackendError(
      `Rate-limit windowMs must be an integer between 1000 and ${MAX_RATE_LIMIT_WINDOW_MS} ms.`,
      'INVALID_RATE_LIMIT_CONFIG'
    );
  }

  if (!manager.isConnected()) {
    throw new ScanRateLimitBackendError(
      'Redis rate-limit store is not connected.',
      'REDIS_RATE_LIMIT_STORE_UNAVAILABLE'
    );
  }

  let client: RedisClientLike;
  try {
    client = manager.getQueueClient();
  } catch (error) {
    throw new ScanRateLimitBackendError(
      `Redis rate-limit store is unavailable: ${formatSafeRedisError(error)}`,
      'REDIS_RATE_LIMIT_STORE_UNAVAILABLE'
    );
  }

  if (typeof client.eval !== 'function') {
    throw new ScanRateLimitBackendError(
      'Redis client does not support atomic Lua rate-limit evaluation.',
      'REDIS_RATE_LIMIT_STORE_UNSUPPORTED'
    );
  }

  try {
    const rawReply = await client.eval(SCAN_CREATE_RATE_LIMIT_LUA, 1, key, input.windowMs);
    if (!Array.isArray(rawReply) || rawReply.length < 2) {
      throw new ScanRateLimitBackendError(
        'Redis rate-limit evaluation returned an invalid response.',
        'REDIS_RATE_LIMIT_STORE_ERROR'
      );
    }

    const current = Number(rawReply[0]);
    const ttlMs = Number(rawReply[1]);
    if (!Number.isFinite(current) || current < 1 || !Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new ScanRateLimitBackendError(
        'Redis rate-limit evaluation returned non-numeric counters.',
        'REDIS_RATE_LIMIT_STORE_ERROR'
      );
    }

    const effectiveTtlMs = ttlMs > 0 ? ttlMs : input.windowMs;
    const nowMs = input.nowMs ?? Date.now();
    const allowed = current <= input.maxRequests;
    const remaining = Math.max(0, input.maxRequests - current);
    const retryAfterSeconds = Math.max(1, Math.ceil(effectiveTtlMs / 1000));

    return {
      allowed,
      limit: input.maxRequests,
      remaining,
      resetAtMs: nowMs + effectiveTtlMs,
      retryAfterSeconds,
    };
  } catch (error) {
    if (error instanceof ScanRateLimitBackendError) {
      throw error;
    }
    throw new ScanRateLimitBackendError(
      `Redis rate-limit check failed: ${formatSafeRedisError(error)}`,
      'REDIS_RATE_LIMIT_STORE_ERROR'
    );
  }
}
