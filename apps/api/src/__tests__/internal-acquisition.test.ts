import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  InternalAuthReplayProtectionError,
  RedisConnectionManager,
  consumeInternalAuthNonce,
  type RedisClientLike,
} from '@vibeshield/queue';
import { EventEmitter } from 'node:events';
import { createApp } from '../app.js';
import {
  getApiConfig,
  isValidInternalBindHost,
  redactInternalEnvSecrets,
  toInternalApiConfig,
} from '../config/env.js';
import { createInternalApp } from '../internal-app.js';
import {
  INTERNAL_NONCE_HEADER,
  INTERNAL_SERVICE_HEADER,
  INTERNAL_SIGNATURE_HEADER,
  INTERNAL_TIMESTAMP_HEADER,
  signInternalWorkerRequest,
} from '../modules/scans/internal-auth.js';
import {
  getActiveServers,
  resetServerStateForTests,
  shutdownServer,
  startServer,
  type ServerLogger,
} from '../server.js';

const TEST_JWT_SECRET = 'test_jwt_access_secret_minimum_32_characters_long';
const TEST_INTERNAL_SECRET = 'internal_worker_auth_secret_minimum_32_chars_long';
const VALID_SCAN_ID = '507f1f77bcf86cd799439011';
const VALID_LEASE_TOKEN = 'lease_fencing_token_0123456789abcdef';

class InMemoryReplayRedisClient extends EventEmitter implements RedisClientLike {
  public status = 'ready';
  private readonly store = new Map<string, number>();

  async connect(): Promise<void> {
    this.status = 'ready';
    this.emit('ready');
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  async set(
    key: string,
    _value: string,
    expiryMode: 'PX',
    ttlMs: number,
    condition: 'NX'
  ): Promise<'OK' | null> {
    if (expiryMode !== 'PX' || condition !== 'NX') {
      throw new Error('Unexpected SET flags');
    }
    const now = Date.now();
    const exp = this.store.get(key);
    if (exp !== undefined && exp > now) {
      return null;
    }
    this.store.set(key, now + ttlMs);
    return 'OK';
  }

  async quit(): Promise<string> {
    this.status = 'end';
    return 'OK';
  }

  disconnect(): void {
    this.status = 'end';
  }
}

function createMockLogger(): Required<ServerLogger> {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

function makeBaseEnv(overrides: Record<string, string | undefined> = {}) {
  return {
    NODE_ENV: 'test',
    MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
    JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    ...overrides,
  };
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
}

async function sendRawHttpRequest(options: {
  host: string;
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ statusCode: number; bodyText: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: options.host,
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            bodyText: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    req.on('error', reject);
    if (options.body !== undefined) {
      req.write(options.body);
    }
    req.end();
  });
}

describe('Internal Scan Acquisition Authorization & Listener Boundary', () => {
  afterEach(async () => {
    await shutdownServer('TEST_CLEANUP', {
      disconnectDb: async () => undefined,
      disconnectQueue: async () => undefined,
      logger: createMockLogger(),
    }).catch(() => undefined);
    resetServerStateForTests();
  });

  describe('Environment validation & bind-host safety', () => {
    it('keeps internal listener disabled cleanly when INTERNAL_API_ENABLED is omitted', () => {
      const cfg = getApiConfig(makeBaseEnv());
      expect(toInternalApiConfig(cfg)).toBeNull();
    });

    it('accepts loopback/RFC1918 hosts and rejects 0.0.0.0, ::, link-local, or public hosts', () => {
      expect(isValidInternalBindHost('127.0.0.1')).toBe(true);
      expect(isValidInternalBindHost('localhost')).toBe(true);
      expect(isValidInternalBindHost('::1')).toBe(true);
      expect(isValidInternalBindHost('10.24.1.8')).toBe(true);
      expect(isValidInternalBindHost('172.16.0.10')).toBe(true);
      expect(isValidInternalBindHost('192.168.1.25')).toBe(true);
      expect(isValidInternalBindHost('fd12:3456:789a::1')).toBe(true);

      expect(isValidInternalBindHost('0.0.0.0')).toBe(false);
      expect(isValidInternalBindHost('::')).toBe(false);
      expect(isValidInternalBindHost('169.254.169.254')).toBe(false);
      expect(isValidInternalBindHost('8.8.8.8')).toBe(false);
      expect(isValidInternalBindHost('api.vibeshield.io')).toBe(false);
      expect(isValidInternalBindHost('*')).toBe(false);
      expect(isValidInternalBindHost('fe80::1')).toBe(false);
    });

    it('rejects insecure or incomplete internal API configuration cleanly', () => {
      // Missing secret & Redis when enabled
      expect(() =>
        getApiConfig(
          makeBaseEnv({
            INTERNAL_API_ENABLED: 'true',
          })
        )
      ).toThrow(/INTERNAL_WORKER_AUTH_SECRET|QUEUE_ENABLED|REDIS_URL/);

      // Reusing JWT_ACCESS_SECRET fails validation
      expect(() =>
        getApiConfig(
          makeBaseEnv({
            QUEUE_ENABLED: 'true',
            REDIS_URL: 'redis://127.0.0.1:6379',
            INTERNAL_API_ENABLED: 'true',
            INTERNAL_WORKER_AUTH_SECRET: TEST_JWT_SECRET,
          })
        )
      ).toThrow(/distinct from JWT_ACCESS_SECRET/i);

      // Reusing public port fails validation
      expect(() =>
        getApiConfig(
          makeBaseEnv({
            PORT: '4000',
            QUEUE_ENABLED: 'true',
            REDIS_URL: 'redis://127.0.0.1:6379',
            INTERNAL_API_ENABLED: 'true',
            INTERNAL_API_PORT: '4000',
            INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
          })
        )
      ).toThrow(/INTERNAL_API_PORT must be distinct/i);

      // Binding 0.0.0.0 fails validation
      expect(() =>
        getApiConfig(
          makeBaseEnv({
            QUEUE_ENABLED: 'true',
            REDIS_URL: 'redis://127.0.0.1:6379',
            INTERNAL_API_ENABLED: 'true',
            INTERNAL_API_HOST: '0.0.0.0',
            INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
          })
        )
      ).toThrow(/INTERNAL_API_HOST/);

      // Valid configuration resolves defaults cleanly
      const valid = getApiConfig(
        makeBaseEnv({
          PORT: '4000',
          QUEUE_ENABLED: 'true',
          REDIS_URL: 'redis://127.0.0.1:6379',
          INTERNAL_API_ENABLED: 'true',
          INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
        })
      );
      expect(toInternalApiConfig(valid)).toEqual({
        enabled: true,
        host: '127.0.0.1',
        port: 4001,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        timestampToleranceMs: 30_000,
        nonceTtlMs: 65_000,
      });

      const redacted = redactInternalEnvSecrets(
        `auth=${TEST_INTERNAL_SECRET} jwt=${TEST_JWT_SECRET}`,
        {
          INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
          JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        }
      );
      expect(redacted).not.toContain(TEST_INTERNAL_SECRET);
      expect(redacted).not.toContain(TEST_JWT_SECRET);
    });
  });

  describe('HMAC authentication, replay protection, strict request validation, and authorization', () => {
    function buildSignedHeaders(
      rawBody: string,
      overrides: Partial<{
        secret: string;
        method: string;
        path: string;
        serviceId: string;
        timestamp: string;
        nonce: string;
        signature: string;
      }> = {}
    ): Record<string, string> {
      const signed = signInternalWorkerRequest({
        secret: overrides.secret ?? TEST_INTERNAL_SECRET,
        method: overrides.method ?? 'POST',
        path: overrides.path ?? '/internal/v1/scans/acquire',
        serviceId: 'security-worker',
        timestamp: overrides.timestamp ?? String(Date.now()),
        nonce: overrides.nonce ?? `nonce-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`,
        rawBody,
      });

      return {
        'content-type': 'application/json',
        [INTERNAL_SERVICE_HEADER]: overrides.serviceId ?? signed.serviceId,
        [INTERNAL_TIMESTAMP_HEADER]: overrides.timestamp ?? signed.timestamp,
        [INTERNAL_NONCE_HEADER]: overrides.nonce ?? signed.nonce,
        [INTERNAL_SIGNATURE_HEADER]: overrides.signature ?? signed.signature,
      };
    }

    it('authenticates signed worker requests, enforces Redis replay protection, verifies DB context, and returns 501 without exposing secrets', async () => {
      const redisClient = new InMemoryReplayRedisClient();
      const redisManager = new RedisConnectionManager({
        createClient: () => redisClient,
        logger: {},
      });
      await redisManager.connect({ url: 'redis://127.0.0.1:6379' });

      const verifyAuthorization = vi.fn(async (input) => ({
        status: 'AUTHORIZED' as const,
        context: {
          scanId: input.scanId,
          organizationId: '507f1f77bcf86cd799439022',
          projectId: '507f1f77bcf86cd799439033',
          repositoryConnectionId: '507f1f77bcf86cd799439044',
          githubInstallationId: 1001,
          githubRepositoryId: 2002,
          requestedRef: 'main',
          requestedCommitHash: null,
          attemptCount: 1,
          maxAttempts: 3,
          workerId: input.workerId,
          leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      }));

      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce: (input) => consumeInternalAuthNonce(redisManager, input),
        },
        verifyAuthorization,
      });

      const body = JSON.stringify({
        scanId: VALID_SCAN_ID,
        leaseToken: VALID_LEASE_TOKEN,
      });
      const headers = buildSignedHeaders(body, { nonce: 'unique-nonce-000001' });

      const firstRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(headers)
        .send(body);

      expect(firstRes.status).toBe(501);
      expect(firstRes.body.error.code).toBe('ACQUISITION_NOT_IMPLEMENTED');
      expect(firstRes.body.authorization).toMatchObject({
        status: 'AUTHORIZED',
        scanId: VALID_SCAN_ID,
        organizationId: '507f1f77bcf86cd799439022',
        projectId: '507f1f77bcf86cd799439033',
        githubInstallationId: 1001,
        githubRepositoryId: 2002,
        workerId: 'security-worker',
      });
      // Must never echo leaseToken, internal auth secret, or any GitHub credentials
      const serialized = JSON.stringify(firstRes.body);
      expect(serialized).not.toContain(VALID_LEASE_TOKEN);
      expect(serialized).not.toContain(TEST_INTERNAL_SECRET);
      expect(serialized).not.toContain('ghs_');

      expect(verifyAuthorization).toHaveBeenCalledTimes(1);
      expect(verifyAuthorization).toHaveBeenCalledWith({
        scanId: VALID_SCAN_ID,
        leaseToken: VALID_LEASE_TOKEN,
        workerId: 'security-worker',
      });

      // Exact replay with same nonce is blocked before authorization check
      const replayRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(headers)
        .send(body);
      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error.code).toBe('INTERNAL_AUTH_NONCE_REPLAYED');
      expect(verifyAuthorization).toHaveBeenCalledTimes(1);
    });

    it('blocks bad signatures, expired timestamps, path/body tampering before touching Redis, and fails closed when Redis is unavailable', async () => {
      const consumeNonce = vi.fn(async () => 'ACCEPTED' as const);
      const verifyAuthorization = vi.fn();

      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce,
        },
        verifyAuthorization,
      });

      const body = JSON.stringify({ scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN });

      // Missing headers
      const missingRes = await request(internalApp).post('/internal/v1/scans/acquire').send(body);
      expect(missingRes.status).toBe(401);
      expect(missingRes.body.error.code).toBe('INTERNAL_AUTH_MISSING_HEADERS');

      // Bad service caller
      const badServiceRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(buildSignedHeaders(body, { serviceId: 'rogue-worker' }))
        .send(body);
      expect(badServiceRes.status).toBe(401);
      expect(badServiceRes.body.error.code).toBe('INTERNAL_AUTH_INVALID_SERVICE');

      // Expired timestamp
      const expiredRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(buildSignedHeaders(body, { timestamp: String(Date.now() - 120_000) }))
        .send(body);
      expect(expiredRes.status).toBe(401);
      expect(expiredRes.body.error.code).toBe('INTERNAL_AUTH_EXPIRED_TIMESTAMP');

      // Tampered request body after signing
      const signedHeaders = buildSignedHeaders(body);
      const tamperedBodyRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(signedHeaders)
        .send(JSON.stringify({ scanId: VALID_SCAN_ID, leaseToken: 'tampered_lease_token_12345' }));
      expect(tamperedBodyRes.status).toBe(401);
      expect(tamperedBodyRes.body.error.code).toBe('INTERNAL_AUTH_INVALID_SIGNATURE');

      // Query string path mismatch
      const queryRes = await request(internalApp)
        .post('/internal/v1/scans/acquire?override=1')
        .set(buildSignedHeaders(body, { path: '/internal/v1/scans/acquire' }))
        .send(body);
      expect(queryRes.status).toBe(401);
      expect(queryRes.body.error.code).toBe('INTERNAL_AUTH_INVALID_SIGNATURE');

      // Short / non-hex signature format
      const shortSigRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(buildSignedHeaders(body, { signature: 'sha256=deadbeef' }))
        .send(body);
      expect(shortSigRes.status).toBe(401);
      expect(shortSigRes.body.error.code).toBe('INTERNAL_AUTH_INVALID_SIGNATURE');

      // Unauthenticated requests NEVER invoked Redis nonce consumption or DB authorization
      expect(consumeNonce).not.toHaveBeenCalled();
      expect(verifyAuthorization).not.toHaveBeenCalled();

      // Valid signature fails closed with 503 if Redis replay store errors
      consumeNonce.mockRejectedValueOnce(
        new InternalAuthReplayProtectionError('Redis unreachable', 'REDIS_REPLAY_STORE_UNAVAILABLE')
      );
      const redisDownRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(buildSignedHeaders(body))
        .send(body);
      expect(redisDownRes.status).toBe(503);
      expect(redisDownRes.body.error.code).toBe('INTERNAL_AUTH_REPLAY_UNAVAILABLE');
      expect(verifyAuthorization).not.toHaveBeenCalled();
    });

    it('rejects tenant, repository, installation, URL, permission, or token fields via strict schema validation', async () => {
      const consumeNonce = vi.fn(async () => 'ACCEPTED' as const);
      const verifyAuthorization = vi.fn();

      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce,
        },
        verifyAuthorization,
      });

      const forbiddenPayloads = [
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, organizationId: VALID_SCAN_ID },
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, projectId: VALID_SCAN_ID },
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, githubRepositoryId: 9999 },
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, githubInstallationId: 9999 },
        {
          scanId: VALID_SCAN_ID,
          leaseToken: VALID_LEASE_TOKEN,
          url: 'https://codeload.github.com/x',
        },
        {
          scanId: VALID_SCAN_ID,
          leaseToken: VALID_LEASE_TOKEN,
          permissions: { contents: 'write' },
        },
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, token: 'ghs_forbidden' },
        { scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN, workerId: 'spoofed-worker' },
      ];

      for (const payload of forbiddenPayloads) {
        const body = JSON.stringify(payload);
        const res = await request(internalApp)
          .post('/internal/v1/scans/acquire')
          .set(buildSignedHeaders(body))
          .send(body);
        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }

      expect(verifyAuthorization).not.toHaveBeenCalled();
    });

    it('isolates routes completely between createApp() public router and createInternalApp()', async () => {
      const publicApp = createApp({ apiPrefix: '/api/v1' });
      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce: async () => 'ACCEPTED',
        },
      });

      const pubOnInternal = await request(publicApp)
        .post('/internal/v1/scans/acquire')
        .send({ scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN });
      expect(pubOnInternal.status).toBe(404);

      const internalOnPublicHealth = await request(internalApp).get('/api/v1/health/live');
      expect(internalOnPublicHealth.status).toBe(404);
    });
  });

  describe('Dual HTTP listener startup, rollback, and shutdown lifecycle', () => {
    it('starts separate public and internal listeners on distinct ports, blocks internal routes on public port, and shuts down cleanly', async () => {
      const publicPort = await getFreePort();
      const internalPort = await getFreePort();
      const logger = createMockLogger();

      await startServer({
        envSource: makeBaseEnv({
          PORT: String(publicPort),
          HOST: '127.0.0.1',
          QUEUE_ENABLED: 'true',
          REDIS_URL: 'redis://127.0.0.1:6379',
          INTERNAL_API_ENABLED: 'true',
          INTERNAL_API_HOST: '127.0.0.1',
          INTERNAL_API_PORT: String(internalPort),
          INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
        }),
        connectDb: async () => undefined,
        disconnectDb: async () => undefined,
        connectQueue: async () => undefined,
        disconnectQueue: async () => undefined,
        consumeInternalAuthNonce: async () => 'ACCEPTED',
        verifyScanAuthorization: async () => ({
          status: 'DENIED',
          reason: 'SCAN_NOT_FOUND',
          message: 'Scan record was not found.',
        }),
        logger,
      });

      const servers = getActiveServers();
      expect(servers.publicServer?.listening).toBe(true);
      expect(servers.internalServer?.listening).toBe(true);

      // Public port exposes health but NOT /internal/*
      const publicHealth = await sendRawHttpRequest({
        host: '127.0.0.1',
        port: publicPort,
        method: 'GET',
        path: '/api/v1/health/live',
      });
      expect(publicHealth.statusCode).toBe(200);

      const publicInternalAttempt = await sendRawHttpRequest({
        host: '127.0.0.1',
        port: publicPort,
        method: 'POST',
        path: '/internal/v1/scans/acquire',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      expect(publicInternalAttempt.statusCode).toBe(404);

      // Internal port does NOT expose /api/v1/health/live, and authenticates signed /internal/v1/scans/acquire
      const internalPublicHealth = await sendRawHttpRequest({
        host: '127.0.0.1',
        port: internalPort,
        method: 'GET',
        path: '/api/v1/health/live',
      });
      expect(internalPublicHealth.statusCode).toBe(404);

      const payload = JSON.stringify({ scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN });
      const signed = signInternalWorkerRequest({
        secret: TEST_INTERNAL_SECRET,
        method: 'POST',
        path: '/internal/v1/scans/acquire',
        serviceId: 'security-worker',
        timestamp: String(Date.now()),
        nonce: 'dual-listener-nonce-001',
        rawBody: payload,
      });

      const internalAuthAttempt = await sendRawHttpRequest({
        host: '127.0.0.1',
        port: internalPort,
        method: 'POST',
        path: '/internal/v1/scans/acquire',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(payload)),
          [INTERNAL_SERVICE_HEADER]: signed.serviceId,
          [INTERNAL_TIMESTAMP_HEADER]: signed.timestamp,
          [INTERNAL_NONCE_HEADER]: signed.nonce,
          [INTERNAL_SIGNATURE_HEADER]: signed.signature,
        },
        body: payload,
      });
      expect(internalAuthAttempt.statusCode).toBe(404);
      expect(JSON.parse(internalAuthAttempt.bodyText).error.code).toBe('SCAN_NOT_FOUND');

      // Logs never include internal auth secrets or signatures
      const allLogs = [
        ...logger.info.mock.calls.flat(),
        ...logger.warn.mock.calls.flat(),
        ...logger.error.mock.calls.flat(),
      ].join('\n');
      expect(allLogs).not.toContain(TEST_INTERNAL_SECRET);
      expect(allLogs).not.toContain(signed.signature);

      await shutdownServer('SIGINT', {
        disconnectDb: async () => undefined,
        disconnectQueue: async () => undefined,
        logger,
      });

      expect(getActiveServers()).toEqual({ publicServer: null, internalServer: null });
    });

    it('rolls back the public listener, queue, and database cleanly if binding the internal listener fails', async () => {
      const publicPort = await getFreePort();
      const occupiedPort = await getFreePort();

      const occupyingServer = net.createServer();
      await new Promise<void>((resolve) =>
        occupyingServer.listen(occupiedPort, '127.0.0.1', resolve)
      );

      const disconnectDb = vi.fn(async () => undefined);
      const disconnectQueue = vi.fn(async () => undefined);

      try {
        await expect(
          startServer({
            envSource: makeBaseEnv({
              PORT: String(publicPort),
              HOST: '127.0.0.1',
              QUEUE_ENABLED: 'true',
              REDIS_URL: 'redis://127.0.0.1:6379',
              INTERNAL_API_ENABLED: 'true',
              INTERNAL_API_HOST: '127.0.0.1',
              INTERNAL_API_PORT: String(occupiedPort),
              INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
            }),
            connectDb: async () => undefined,
            disconnectDb,
            connectQueue: async () => undefined,
            disconnectQueue,
            consumeInternalAuthNonce: async () => 'ACCEPTED',
            logger: createMockLogger(),
          })
        ).rejects.toThrow();

        expect(disconnectQueue).toHaveBeenCalledTimes(1);
        expect(disconnectDb).toHaveBeenCalledTimes(1);
        expect(getActiveServers()).toEqual({ publicServer: null, internalServer: null });
      } finally {
        await new Promise<void>((resolve) => occupyingServer.close(() => resolve()));
      }
    });
  });
});
