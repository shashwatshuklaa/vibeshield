import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import {
  buildDefaultJobOptions,
  buildInternalAuthNonceKey,
  buildRedisConnectionOptions,
  buildScanJobId,
  buildWorkerPolicyOptions,
  closeQueueResources,
  closeWorkerWithGrace,
  consumeInternalAuthNonce,
  createBullWorker,
  DEFAULT_QUEUE_POLICY,
  DEFAULT_WORKER_POLICY,
  defaultRedisManager,
  formatSafeRedisError,
  inspectQueueHealth,
  InternalAuthReplayProtectionError,
  isTlsRedisUrl,
  isValidQueueName,
  isValidRedisUrl,
  JOB_PRIORITIES,
  MAX_JOB_PAYLOAD_BYTES,
  QUEUE_NAMES,
  redactRedisUrl,
  RedisConnectionError,
  RedisConnectionManager,
  validateScanQueueJobPayload,
  type RedisClientLike,
} from '../index.js';

class MockRedisClient extends EventEmitter implements RedisClientLike {
  public status = 'wait';
  public connectCalls = 0;
  public pingCalls = 0;
  public quitCalls = 0;
  public disconnectCalls = 0;
  public shouldFailConnect: Error | null = null;
  public shouldFailQuit: Error | null = null;
  public shouldFailSet: Error | null = null;
  public readonly nonceKeys = new Map<string, number>();

  async connect(): Promise<void> {
    this.connectCalls += 1;
    if (this.shouldFailConnect) {
      this.status = 'end';
      throw this.shouldFailConnect;
    }
    this.status = 'ready';
    this.emit('ready');
  }

  async ping(): Promise<string> {
    this.pingCalls += 1;
    return 'PONG';
  }

  async set(
    key: string,
    _value: string,
    expiryMode: 'PX',
    ttlMs: number,
    condition: 'NX'
  ): Promise<'OK' | null> {
    if (this.shouldFailSet) {
      throw this.shouldFailSet;
    }
    if (expiryMode !== 'PX' || condition !== 'NX') {
      throw new Error('Unexpected Redis SET arguments in mock client');
    }
    const now = Date.now();
    const existingExpiry = this.nonceKeys.get(key);
    if (existingExpiry !== undefined && existingExpiry > now) {
      return null;
    }
    this.nonceKeys.set(key, now + ttlMs);
    return 'OK';
  }

  async quit(): Promise<string> {
    this.quitCalls += 1;
    if (this.shouldFailQuit) {
      throw this.shouldFailQuit;
    }
    this.status = 'end';
    this.emit('end');
    return 'OK';
  }

  disconnect(): void {
    this.disconnectCalls += 1;
    this.status = 'end';
  }
}

describe('@vibeshield/queue Unit Tests', () => {
  describe('Redis URL validation, TLS, and credential redaction', () => {
    it('validates redis:// and rediss:// URLs and rejects invalid URLs or DB indexes', () => {
      expect(isValidRedisUrl('redis://localhost:6379')).toBe(true);
      expect(isValidRedisUrl('redis://default:s3cr3t@cache.internal:6380/2')).toBe(true);
      expect(isValidRedisUrl('rediss://:tlsSecret@redis.prod.example.com:6380/0')).toBe(true);

      expect(isTlsRedisUrl('rediss://redis.prod.example.com:6380')).toBe(true);
      expect(isTlsRedisUrl('redis://localhost:6379')).toBe(false);

      expect(isValidRedisUrl('')).toBe(false);
      expect(isValidRedisUrl('http://localhost:6379')).toBe(false);
      expect(isValidRedisUrl('mongodb://localhost:27017')).toBe(false);
      expect(isValidRedisUrl('redis://localhost:99999')).toBe(false);
      expect(isValidRedisUrl('redis://localhost:6379/99')).toBe(false);
      expect(isValidRedisUrl('redis://localhost:6379/notadb')).toBe(false);
      expect(isValidRedisUrl('redis://bad host:6379')).toBe(false);
    });

    it('redacts Redis URLs, passwords, and secrets from error formatting', () => {
      const secretUrl = 'rediss://admin:UltraSecretRedisPass99!@cache.prod.internal:6380/1';
      const rawMsg = `ECONNREFUSED connecting to ${secretUrl} password=UltraSecretRedisPass99!`;
      const redacted = redactRedisUrl(rawMsg);

      expect(redacted).not.toContain('UltraSecretRedisPass99!');
      expect(redacted).not.toContain('cache.prod.internal');
      expect(redacted).toContain('[REDACTED_REDIS_URL]');

      const safeErr = formatSafeRedisError(new Error('Auth failed: myPlainSecret42'), [
        'myPlainSecret42',
      ]);
      expect(safeErr).not.toContain('myPlainSecret42');
      expect(safeErr).toContain('[REDACTED_SECRET]');
    });

    it('builds role-separated ioredis options cleanly with strict TLS defaults', () => {
      const queueOpts = buildRedisConnectionOptions(
        {
          url: 'rediss://user:passSecret@redis.internal:6380/3',
          connectTimeoutMs: 2500,
          commandTimeoutMs: 4000,
          maxRetriesPerRequest: 2,
        },
        'queue'
      );

      expect(queueOpts.host).toBe('redis.internal');
      expect(queueOpts.port).toBe(6380);
      expect(queueOpts.db).toBe(3);
      expect(queueOpts.connectTimeout).toBe(2500);
      expect(queueOpts.commandTimeout).toBe(4000);
      expect(queueOpts.maxRetriesPerRequest).toBe(2);
      expect(queueOpts.enableOfflineQueue).toBe(false);
      expect(queueOpts.tls).toEqual({ rejectUnauthorized: true });

      const workerOpts = buildRedisConnectionOptions(
        {
          url: 'redis://localhost:6379/0',
          connectTimeoutMs: 3000,
          commandTimeoutMs: 4000,
        },
        'worker'
      );
      expect(workerOpts.maxRetriesPerRequest).toBeNull();
      expect(workerOpts.enableOfflineQueue).toBe(true);
      expect(workerOpts.commandTimeout).toBeUndefined();
      expect(workerOpts.tls).toBeUndefined();

      expect(() => buildRedisConnectionOptions({ url: 'http://localhost:6379' })).toThrow(
        RedisConnectionError
      );
      expect(() =>
        buildRedisConnectionOptions({ url: 'redis://localhost:6379', connectTimeoutMs: 10 })
      ).toThrow(/connectTimeoutMs/i);
    });
  });

  describe('RedisConnectionManager lifecycle', () => {
    it('does not connect automatically on import and reports disabled/not_initialized states cleanly', () => {
      expect(defaultRedisManager.getState()).toBe('not_initialized');
      expect(defaultRedisManager.getStatus(false)).toEqual({
        enabled: false,
        state: 'disabled',
        isConnected: false,
      });
      expect(defaultRedisManager.getStatus(true)).toEqual({
        enabled: true,
        state: 'not_initialized',
        isConnected: false,
      });
    });

    it('deduplicates concurrent connects, handles reconnection/error events without secret leaks, and closes idempotently', async () => {
      const createdClients: MockRedisClient[] = [];
      const logs: string[] = [];
      const manager = new RedisConnectionManager({
        logger: {
          info: (m) => logs.push(m),
          warn: (m) => logs.push(m),
          error: (m) => logs.push(m),
        },
        createClient: () => {
          const client = new MockRedisClient();
          createdClients.push(client);
          return client;
        },
      });

      const url = 'redis://:SuperSecretPass123@localhost:6379/0';
      await Promise.all([manager.connect({ url }), manager.connect({ url })]);

      expect(createdClients).toHaveLength(1);
      expect(createdClients[0]?.connectCalls).toBe(1);
      expect(manager.isConnected()).toBe(true);
      expect(await manager.ping()).toBe(true);

      // Reconnecting with same URL is a no-op
      await manager.connect({ url });
      expect(createdClients).toHaveLength(1);

      // Reject connecting to a different URL while active
      await expect(manager.connect({ url: 'redis://localhost:6380/0' })).rejects.toThrow(
        /already connected/i
      );

      // Reconnecting, error, & end events preserve safety and state without leaking secrets
      createdClients[0]!.status = 'reconnecting';
      createdClients[0]?.emit('reconnecting');
      expect(manager.getStatus(true).state).toBe('reconnecting');
      createdClients[0]!.status = 'close';
      createdClients[0]?.emit('error', new Error('Failed auth with SuperSecretPass123'));
      createdClients[0]?.emit('end');
      expect(manager.getState()).toBe('unavailable');
      expect(logs.join('\n')).not.toContain('SuperSecretPass123');

      await Promise.all([manager.disconnect(), manager.disconnect()]);
      expect(createdClients[0]?.quitCalls).toBe(1);
      expect(manager.getState()).toBe('not_initialized');
    });

    it('marks state unavailable, closes socket, and redacts password if initial connect fails', async () => {
      const client = new MockRedisClient();
      const secretPass = 'TopSecretPass987!';
      client.shouldFailConnect = new Error(
        `connect ECONNREFUSED redis://:${secretPass}@localhost:6379`
      );
      const errors: string[] = [];

      const manager = new RedisConnectionManager({
        logger: { error: (m) => errors.push(m) },
        createClient: () => client,
      });

      await expect(
        manager.connect({ url: `redis://:${secretPass}@localhost:6379/0` })
      ).rejects.toThrow(RedisConnectionError);

      expect(manager.getState()).toBe('unavailable');
      expect(client.disconnectCalls).toBe(1);
      expect(errors.join('\n')).not.toContain(secretPass);
    });
  });

  describe('Job contracts, defaults, and queue utilities', () => {
    it('enforces colon-free queue names, stable job IDs, and bounded defaults', () => {
      expect(QUEUE_NAMES.SCAN_JOBS).toBe('vibeshield-v1-scan-jobs');
      expect(isValidQueueName(QUEUE_NAMES.SCAN_JOBS)).toBe(true);
      expect(isValidQueueName('vibeshield:scan')).toBe(false);
      expect(isValidQueueName('')).toBe(false);

      expect(
        buildScanJobId({
          scanId: '507F1F77BCF86CD799439011',
          dispatchGeneration: 1,
        })
      ).toBe('scan-507f1f77bcf86cd799439011-1');

      expect(
        buildScanJobId({
          scanId: '507f1f77bcf86cd799439011',
          dispatchGeneration: 2,
        })
      ).toBe('scan-507f1f77bcf86cd799439011-2');

      expect(() =>
        buildScanJobId({
          scanId: 'bad:scan-id',
          dispatchGeneration: 1,
        })
      ).toThrow();
      expect(() =>
        buildScanJobId({
          scanId: '507f1f77bcf86cd799439011',
          dispatchGeneration: 0,
        })
      ).toThrow();

      const defaults = buildDefaultJobOptions();
      expect(defaults.attempts).toBe(DEFAULT_QUEUE_POLICY.attempts);
      expect(defaults.backoff).toEqual({ type: 'exponential', delay: 1000 });
      expect(defaults.removeOnComplete).toEqual(DEFAULT_QUEUE_POLICY.removeOnComplete);
      expect(defaults.removeOnFail).toEqual(DEFAULT_QUEUE_POLICY.removeOnFail);
      expect(defaults.sizeLimit).toBe(MAX_JOB_PAYLOAD_BYTES);

      // Prevents disabling bounded retention or exceeding bounded retries
      const hardened = buildDefaultJobOptions({ attempts: 999, removeOnComplete: false });
      expect(hardened.attempts).toBe(DEFAULT_QUEUE_POLICY.attempts);
      expect(hardened.removeOnComplete).toEqual(DEFAULT_QUEUE_POLICY.removeOnComplete);
      expect(JOB_PRIORITIES.HIGH).toBeLessThan(JOB_PRIORITIES.NORMAL);
    });

    it('validates strict { scanId } payloads and rejects unknown fields, invalid IDs, and credentials', () => {
      const valid = validateScanQueueJobPayload({
        scanId: ' 507F1F77BCF86CD799439011 ',
      });
      expect(valid).toEqual({ scanId: '507f1f77bcf86cd799439011' });

      expect(() =>
        validateScanQueueJobPayload({
          scanId: 'not-an-object-id',
        })
      ).toThrow();

      expect(() =>
        validateScanQueueJobPayload({
          scanId: '507f1f77bcf86cd799439011',
          organizationId: '507f1f77bcf86cd799439012',
          branch: 'main',
        })
      ).toThrow(/unrecognized/i);

      expect(() =>
        validateScanQueueJobPayload({
          scanId: '507f1f77bcf86cd799439011',
          accessToken: 'ghs_should_never_be_queued',
        })
      ).toThrow(/sensitive key/i);

      expect(() =>
        validateScanQueueJobPayload({
          scanId: 'ghp_1234567890abcdef',
        })
      ).toThrow(/credentials/i);
    });

    it('inspects queue health and shuts down owned handles + Redis cleanly', async () => {
      const client = new MockRedisClient();
      const manager = new RedisConnectionManager({ createClient: () => client });
      await manager.connect({ url: 'redis://localhost:6379/0' });

      const closeQueueSpy = vi.fn(async () => undefined);
      const fakeHandle = {
        name: QUEUE_NAMES.SCAN_JOBS,
        queue: {
          getJobCounts: vi.fn(async () => ({
            waiting: 2,
            active: 1,
            delayed: 0,
            failed: 1,
            completed: 5,
          })),
        } as unknown as Parameters<typeof inspectQueueHealth>[0] extends infer H
          ? H extends { queue: infer Q }
            ? Q
            : never
          : never,
        close: closeQueueSpy,
      };

      const health = await inspectQueueHealth(fakeHandle, manager, true);
      expect(health).toEqual({
        queueName: QUEUE_NAMES.SCAN_JOBS,
        redis: { enabled: true, state: 'connected', isConnected: true },
        counts: { waiting: 2, active: 1, delayed: 0, failed: 1, completed: 5 },
      });

      const disabledHealth = await inspectQueueHealth(null, manager, false);
      expect(disabledHealth.redis).toEqual({
        enabled: false,
        state: 'disabled',
        isConnected: false,
      });

      await closeQueueResources([fakeHandle], manager);
      expect(closeQueueSpy).toHaveBeenCalledTimes(1);
      expect(client.quitCalls).toBe(1);
      expect(manager.getState()).toBe('not_initialized');
    });

    it('validates worker policy defaults, bounded overrides, and worker factory guards', async () => {
      expect(buildWorkerPolicyOptions()).toEqual(DEFAULT_WORKER_POLICY);

      expect(
        buildWorkerPolicyOptions({
          concurrency: 5,
          lockDuration: 45_000,
          stalledInterval: 20_000,
          maxStalledCount: 3,
          maxStartedAttempts: 4,
        })
      ).toEqual({
        concurrency: 5,
        lockDuration: 45_000,
        stalledInterval: 20_000,
        maxStalledCount: 3,
        maxStartedAttempts: 4,
      });

      expect(() => buildWorkerPolicyOptions({ concurrency: 0 })).toThrow(/Worker concurrency/);
      expect(() => buildWorkerPolicyOptions({ concurrency: 51 })).toThrow(/Worker concurrency/);
      expect(() => buildWorkerPolicyOptions({ lockDuration: 1000 })).toThrow(/Worker lockDuration/);
      expect(() => buildWorkerPolicyOptions({ maxStalledCount: -1 })).toThrow(
        /Worker maxStalledCount/
      );

      expect(() =>
        createBullWorker('bad:queue', async () => undefined, {
          redis: { url: 'redis://localhost:6379' },
        })
      ).toThrow(/must not contain colons/i);

      expect(() =>
        createBullWorker(
          QUEUE_NAMES.SCAN_JOBS,
          null as unknown as Parameters<typeof createBullWorker>[1],
          {
            redis: { url: 'redis://localhost:6379' },
          }
        )
      ).toThrow(/processor/i);

      expect(() =>
        createBullWorker(QUEUE_NAMES.SCAN_JOBS, async () => undefined, {
          redis: { url: 'http://secret:Pass123!@localhost:6379' },
        })
      ).toThrowError(RedisConnectionError);

      // Graceful close within timeout
      const fastClose = vi.fn(async () => undefined);
      await expect(closeWorkerWithGrace({ close: fastClose }, 500)).resolves.toEqual({
        timedOut: false,
      });
      expect(fastClose).toHaveBeenCalledWith(false);

      // Timed-out close falls back to force=true
      const slowClose = vi.fn((force?: boolean) =>
        force ? Promise.resolve() : new Promise<void>(() => {})
      );
      await expect(closeWorkerWithGrace({ close: slowClose }, 20)).resolves.toEqual({
        timedOut: true,
      });
      expect(slowClose).toHaveBeenNthCalledWith(1, false);
      expect(slowClose).toHaveBeenNthCalledWith(2, true);
    });
  });

  describe('Internal auth replay nonce protection', () => {
    it('atomically accepts first-seen nonces, blocks replays, isolates namespaces, and fails closed when Redis is unavailable', async () => {
      const client = new MockRedisClient();
      const manager = new RedisConnectionManager({
        createClient: () => client,
        logger: {},
      });

      // Fails closed when not connected
      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-1234567890abcdef',
          ttlMs: 30_000,
          namespace: 'security-worker',
        })
      ).rejects.toThrowError(InternalAuthReplayProtectionError);

      await manager.connect({ url: 'redis://localhost:6379' });

      expect(buildInternalAuthNonceKey('nonce-1234567890abcdef', 'security-worker')).toBe(
        'vibeshield:internal-auth-nonce:security-worker:nonce-1234567890abcdef'
      );

      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-1234567890abcdef',
          ttlMs: 30_000,
          namespace: 'security-worker',
        })
      ).resolves.toBe('ACCEPTED');

      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-1234567890abcdef',
          ttlMs: 30_000,
          namespace: 'security-worker',
        })
      ).resolves.toBe('REPLAYED');

      // Different caller namespace does not collide
      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-1234567890abcdef',
          ttlMs: 30_000,
          namespace: 'other-worker',
        })
      ).resolves.toBe('ACCEPTED');

      // Rejects malformed nonces or bad TTLs before Redis call
      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'bad',
          ttlMs: 30_000,
        })
      ).rejects.toThrowError(InternalAuthReplayProtectionError);
      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-1234567890abcdef',
          ttlMs: 100,
        })
      ).rejects.toThrowError(InternalAuthReplayProtectionError);

      // Fails closed if Redis SET errors
      client.shouldFailSet = new Error('READONLY You cannot write against a read only replica');
      await expect(
        consumeInternalAuthNonce(manager, {
          nonce: 'nonce-second-12345678',
          ttlMs: 30_000,
        })
      ).rejects.toThrowError(InternalAuthReplayProtectionError);

      await manager.disconnect();
    });
  });
});
