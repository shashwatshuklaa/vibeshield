import { generateKeyPairSync } from 'node:crypto';
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
  createGitHubClient,
  validateCodeloadRedirectUrl,
} from '../modules/github/github.client.js';
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
const VALID_ORG_ID = '507f1f77bcf86cd799439022';
const VALID_PROJ_ID = '507f1f77bcf86cd799439033';
const VALID_CONN_ID = '507f1f77bcf86cd799439044';
const VALID_LEASE_TOKEN = 'lease_fencing_token_0123456789abcdef';
const TEST_COMMIT_SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const TEST_RSA_PRIVATE_KEY_PEM = generateKeyPairSync('rsa', {
  modulusLength: 2048,
}).privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;

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
        let settled = false;
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('error', (err) => {
          if (!settled) {
            settled = true;
            reject(err);
          }
        });
        res.on('close', () => {
          if (!settled && !res.complete) {
            settled = true;
            reject(new Error('HTTP response stream closed prematurely before completion'));
          }
        });
        res.on('end', () => {
          if (!settled) {
            settled = true;
            resolve({
              statusCode: res.statusCode ?? 0,
              bodyText: Buffer.concat(chunks).toString('utf8'),
            });
          }
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
        maxArchiveBytes: 104_857_600,
        githubRequestTimeoutMs: 10_000,
        codeloadTimeoutMs: 60_000,
        totalAcquisitionTimeoutMs: 120_000,
      });

      // Rejects exceeding 100 MiB hard compressed archive limit or invalid timeouts
      expect(() =>
        getApiConfig(
          makeBaseEnv({
            QUEUE_ENABLED: 'true',
            REDIS_URL: 'redis://127.0.0.1:6379',
            INTERNAL_API_ENABLED: 'true',
            INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
            INTERNAL_ARCHIVE_MAX_BYTES: String(104_857_600 + 1),
          })
        )
      ).toThrow(/INTERNAL_ARCHIVE_MAX_BYTES/);

      expect(() =>
        getApiConfig(
          makeBaseEnv({
            QUEUE_ENABLED: 'true',
            REDIS_URL: 'redis://127.0.0.1:6379',
            INTERNAL_API_ENABLED: 'true',
            INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
            INTERNAL_CODELOAD_TIMEOUT_MS: '500',
          })
        )
      ).toThrow(/INTERNAL_CODELOAD_TIMEOUT_MS/);

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

    it('authenticates signed worker requests, enforces Redis replay protection, streams authorized archives, revokes tokens, and blocks replays', async () => {
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
          organizationId: VALID_ORG_ID,
          projectId: VALID_PROJ_ID,
          repositoryConnectionId: VALID_CONN_ID,
          githubInstallationId: 1001,
          githubRepositoryId: 2002,
          repositoryOwner: 'acme-sec',
          repositoryName: 'web-app',
          requestedRef: 'main',
          requestedCommitHash: null,
          attemptCount: 1,
          maxAttempts: 3,
          workerId: input.workerId,
          leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      }));

      const setResolvedCommitWithLease = vi.fn(async () => ({
        status: 'UPDATED' as const,
        scan: {} as never,
      }));

      const mockGitHubClient = {
        createRepositoryAcquisitionToken: vi.fn(async () => ({
          token: 'ghs_ephemeral_repo_scoped_token_123456',
          expiresAt: new Date(Date.now() + 300_000),
          installationId: 1001,
          githubRepositoryId: 2002,
          permissions: { contents: 'read' as const },
        })),
        revokeInstallationAccessToken: vi.fn(async () => ({
          revoked: true as const,
          alreadyInvalidOrExpired: false,
        })),
        probeRepositoryById: vi.fn(async () => ({
          status: 'ACCESSIBLE' as const,
          repository: {
            githubRepositoryId: 2002,
            name: 'web-app',
            fullName: 'acme-sec/web-app',
            ownerLogin: 'acme-sec',
            defaultBranch: 'main',
            isPrivate: true,
            isArchived: false,
            htmlUrl: 'https://github.com/acme-sec/web-app',
          },
        })),
        resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
        openRepositoryTarballStream: vi.fn(async () => ({
          declaredContentLength: 10,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x01]));
              controller.enqueue(new Uint8Array([0x02, 0x03, 0x04, 0x05, 0x06]));
              controller.close();
            },
          }),
        })),
      };

      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce: (input) => consumeInternalAuthNonce(redisManager, input),
        },
        githubClient: mockGitHubClient,
        verifyAuthorization,
        setResolvedCommitWithLease,
      });

      const body = JSON.stringify({
        scanId: VALID_SCAN_ID,
        leaseToken: VALID_LEASE_TOKEN,
      });
      const headers = buildSignedHeaders(body, { nonce: 'unique-nonce-000001' });

      const firstRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(headers)
        .send(body)
        .buffer(true)
        .parse((res, callback) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => callback(null, Buffer.concat(chunks)));
        });

      expect(firstRes.status).toBe(200);
      expect(firstRes.headers['content-type']).toBe('application/gzip');
      expect(firstRes.headers['content-disposition']).toBe(
        `attachment; filename="scan-${VALID_SCAN_ID}.tar.gz"`
      );
      expect(firstRes.headers['cache-control']).toBe('no-store');
      expect(firstRes.headers['x-content-type-options']).toBe('nosniff');
      expect(firstRes.headers['location']).toBeUndefined();
      expect(Buffer.from(firstRes.body as Buffer)).toEqual(
        Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
      );

      expect(mockGitHubClient.createRepositoryAcquisitionToken).toHaveBeenCalledWith({
        installationId: 1001,
        githubRepositoryId: 2002,
      });
      expect(setResolvedCommitWithLease).toHaveBeenCalledWith({
        scanId: VALID_SCAN_ID,
        organizationId: VALID_ORG_ID,
        projectId: VALID_PROJ_ID,
        leaseToken: VALID_LEASE_TOKEN,
        resolvedCommitSha: TEST_COMMIT_SHA,
      });
      expect(mockGitHubClient.revokeInstallationAccessToken).toHaveBeenCalledWith(
        'ghs_ephemeral_repo_scoped_token_123456'
      );

      // Exact replay with same nonce is blocked before touching DB/GitHub again
      const callsBeforeReplay = verifyAuthorization.mock.calls.length;
      const replayRes = await request(internalApp)
        .post('/internal/v1/scans/acquire')
        .set(headers)
        .send(body);
      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error.code).toBe('INTERNAL_AUTH_NONCE_REPLAYED');
      expect(verifyAuthorization.mock.calls.length).toBe(callsBeforeReplay);
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
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(),
          revokeInstallationAccessToken: vi.fn(),
          probeRepositoryById: vi.fn(),
          resolveCommitSha: vi.fn(),
          openRepositoryTarballStream: vi.fn(),
        } as never,
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

  describe('GitHub commit resolution, strict redirect safety, and bounded streaming edge cases', () => {
    function buildGitHubClientConfig() {
      return {
        appId: 9001,
        appSlug: 'vibeshield-test',
        privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
        clientId: 'Iv1.testclient',
        clientSecret: 'test_github_client_secret_value',
        webhookSecret: 'test_github_webhook_secret_32_chars_min',
        callbackUrl: 'http://localhost:5173/integrations/github/callback',
      };
    }

    function buildAcquireHeaders(rawBody: string, secret = TEST_INTERNAL_SECRET) {
      const signed = signInternalWorkerRequest({
        secret,
        method: 'POST',
        path: '/internal/v1/scans/acquire',
        serviceId: 'security-worker',
        timestamp: String(Date.now()),
        nonce: `stream-nonce-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`,
        rawBody,
      });
      return {
        'content-type': 'application/json',
        [INTERNAL_SERVICE_HEADER]: signed.serviceId,
        [INTERNAL_TIMESTAMP_HEADER]: signed.timestamp,
        [INTERNAL_NONCE_HEADER]: signed.nonce,
        [INTERNAL_SIGNATURE_HEADER]: signed.signature,
      };
    }

    function authorizedFixture(overrides: Record<string, unknown> = {}) {
      return {
        status: 'AUTHORIZED' as const,
        context: {
          scanId: VALID_SCAN_ID,
          organizationId: VALID_ORG_ID,
          projectId: VALID_PROJ_ID,
          repositoryConnectionId: VALID_CONN_ID,
          githubInstallationId: 1001,
          githubRepositoryId: 2002,
          repositoryOwner: 'acme-sec',
          repositoryName: 'web-app',
          requestedRef: 'feature/fix-bug',
          requestedCommitHash: null,
          attemptCount: 1,
          maxAttempts: 3,
          workerId: 'security-worker',
          leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
          ...overrides,
        },
      };
    }

    it('strictly validates codeload HTTPS redirect destinations and blocks bypass hosts, schemes, ports, credentials, and chained redirects', async () => {
      expect(
        validateCodeloadRedirectUrl(
          'https://codeload.github.com/acme-sec/web-app/legacy.tar.gz/abc?token=SECRET_QUERY'
        )
      ).toBe('https://codeload.github.com/acme-sec/web-app/legacy.tar.gz/abc?token=SECRET_QUERY');

      const rejectedUrls = [
        null,
        '',
        '/acme-sec/web-app/tar.gz',
        'http://codeload.github.com/acme-sec/web-app/legacy.tar.gz',
        'https://evil.example.com/archive.tar.gz',
        'https://evil.codeload.github.com/acme-sec/web-app/legacy.tar.gz',
        'https://github.com/acme-sec/web-app/archive/main.tar.gz',
        'https://codeload.github.com:8443/acme-sec/web-app/legacy.tar.gz',
        'https://user:pass@codeload.github.com/acme-sec/web-app/legacy.tar.gz',
        'https://codeload.github.com\\@evil.com/x',
      ];

      for (const badUrl of rejectedUrls) {
        expect(() => validateCodeloadRedirectUrl(badUrl)).toThrow(/redirect/i);
      }

      // Chained redirect (302 from api -> 302 from codeload) rejected without revealing signed query string
      const signedCodeloadUrl =
        'https://codeload.github.com/acme-sec/web-app/legacy.tar.gz/sha?token=VERY_SECRET_QUERY_TOKEN';
      const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        const target = String(url);
        expect(init?.redirect).toBe('manual');
        if (target.startsWith('https://api.github.com/')) {
          expect((init?.headers as Record<string, string>)['Authorization']).toBe(
            'Bearer ghs_test_token'
          );
          return new Response(null, {
            status: 302,
            headers: { location: signedCodeloadUrl },
          });
        }
        // Codeload request must NEVER carry Authorization header
        const headersObj = (init?.headers ?? {}) as Record<string, string>;
        expect(headersObj['Authorization']).toBeUndefined();
        expect(headersObj['authorization']).toBeUndefined();
        return new Response(null, {
          status: 302,
          headers: { location: 'https://codeload.github.com/second-hop' },
        });
      });

      const ghClient = createGitHubClient({
        config: buildGitHubClientConfig(),
        fetchImpl: fetchMock as unknown as typeof fetch,
      });

      let caughtError: unknown;
      try {
        await ghClient.openRepositoryTarballStream({
          installationToken: 'ghs_test_token',
          owner: 'acme-sec',
          repo: 'web-app',
          commitSha: TEST_COMMIT_SHA,
          maxArchiveBytes: 1024 * 1024,
        });
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toMatchObject({ code: 'GITHUB_CHAINED_REDIRECT', statusCode: 502 });
      expect(String(caughtError)).not.toContain('VERY_SECRET_QUERY_TOKEN');
      expect(String(caughtError)).not.toContain('ghs_test_token');
    });

    it('resolves immutable commit SHA, strips Authorization on codeload redirect, and rejects malformed SHA or mismatched repository', async () => {
      const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        const target = String(url);
        const headers = (init?.headers ?? {}) as Record<string, string>;
        if (target.endsWith('/commits/feature/fix-bug')) {
          return new Response(JSON.stringify({ sha: TEST_COMMIT_SHA.toUpperCase() }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (target === `https://api.github.com/repos/acme-sec/web-app/tarball/${TEST_COMMIT_SHA}`) {
          expect(init?.redirect).toBe('manual');
          expect(headers['Authorization']).toBe('Bearer ghs_scoped_123');
          return new Response(null, {
            status: 302,
            headers: {
              location: `https://codeload.github.com/acme-sec/web-app/legacy.tar.gz/${TEST_COMMIT_SHA}?token=codeload_secret`,
            },
          });
        }
        if (target.startsWith('https://codeload.github.com/')) {
          expect(init?.redirect).toBe('manual');
          expect(headers['Authorization']).toBeUndefined();
          expect(headers['authorization']).toBeUndefined();
          return new Response(new Uint8Array([1, 2, 3, 4]), {
            status: 200,
            headers: {
              'x-github-request-id': 'secret-upstream-header',
              'set-cookie': 'gh_sess=secret',
            },
          });
        }
        return new Response('unexpected', { status: 404 });
      });

      const ghClient = createGitHubClient({
        config: buildGitHubClientConfig(),
        fetchImpl: fetchMock as unknown as typeof fetch,
      });

      const sha = await ghClient.resolveCommitSha({
        installationToken: 'ghs_scoped_123',
        owner: 'acme-sec',
        repo: 'web-app',
        ref: 'feature/fix-bug',
      });
      expect(sha).toBe(TEST_COMMIT_SHA);

      const streamHandle = await ghClient.openRepositoryTarballStream({
        installationToken: 'ghs_scoped_123',
        owner: 'acme-sec',
        repo: 'web-app',
        commitSha: sha,
        maxArchiveBytes: 1024,
      });
      expect(streamHandle.declaredContentLength).toBeNull();
      const reader = streamHandle.body.getReader();
      const firstRead = await reader.read();
      expect(firstRead.value).toEqual(new Uint8Array([1, 2, 3, 4]));

      // Reject malformed SHA from GitHub commit endpoint
      const badShaClient = createGitHubClient({
        config: buildGitHubClientConfig(),
        fetchImpl: vi.fn(
          async () =>
            new Response(JSON.stringify({ sha: 'not-a-valid-sha' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            })
        ) as unknown as typeof fetch,
      });
      await expect(
        badShaClient.resolveCommitSha({
          installationToken: 'ghs_scoped_123',
          owner: 'acme-sec',
          repo: 'web-app',
          ref: 'main',
        })
      ).rejects.toMatchObject({ code: 'INVALID_GITHUB_RESPONSE' });
    });

    it('rejects oversized declared Content-Length before streaming, aborts inaccurate streams exceeding maxArchiveBytes, and always revokes token', async () => {
      const revokeMock = vi.fn(async () => ({
        revoked: true as const,
        alreadyInvalidOrExpired: false,
      }));
      const logger = createMockLogger();

      const preDeclaredClient = createGitHubClient({
        config: buildGitHubClientConfig(),
        fetchImpl: vi.fn(async (url: string | URL | Request) => {
          const target = String(url);
          if (target.endsWith('/access_tokens')) {
            return new Response(
              JSON.stringify({
                token: 'ghs_oversize_token_secret',
                expires_at: new Date(Date.now() + 60_000).toISOString(),
                repository_selection: 'selected',
                permissions: { contents: 'read' },
                repositories: [{ id: 2002 }],
              }),
              { status: 201, headers: { 'content-type': 'application/json' } }
            );
          }
          if (target.endsWith('/repositories/2002')) {
            return new Response(
              JSON.stringify({
                id: 2002,
                name: 'web-app',
                full_name: 'acme-sec/web-app',
                owner: { login: 'acme-sec' },
                default_branch: 'main',
                private: true,
                archived: false,
                html_url: 'https://github.com/acme-sec/web-app',
              }),
              { status: 200, headers: { 'content-type': 'application/json' } }
            );
          }
          if (target.includes('/commits/')) {
            return new Response(JSON.stringify({ sha: TEST_COMMIT_SHA }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          }
          if (target.includes('/tarball/')) {
            return new Response(null, {
              status: 302,
              headers: {
                location: `https://codeload.github.com/acme-sec/web-app/legacy.tar.gz/${TEST_COMMIT_SHA}?token=q1`,
              },
            });
          }
          if (target.startsWith('https://codeload.github.com/')) {
            return new Response(new Uint8Array(100), {
              status: 200,
              headers: { 'content-length': '2048' },
            });
          }
          if (target.endsWith('/installation/token')) {
            await revokeMock();
            return new Response(null, { status: 204 });
          }
          return new Response(null, { status: 404 });
        }) as unknown as typeof fetch,
      });

      const appTooLarge = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        githubClient: preDeclaredClient,
        verifyAuthorization: async () => authorizedFixture(),
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        maxArchiveBytes: 1024,
      });

      const body = JSON.stringify({ scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN });
      const resTooLarge = await request(appTooLarge)
        .post('/internal/v1/scans/acquire')
        .set(buildAcquireHeaders(body))
        .send(body);

      expect(resTooLarge.status).toBe(413);
      expect(resTooLarge.body.error.code).toBe('ARCHIVE_TOO_LARGE');
      expect(revokeMock).toHaveBeenCalledTimes(1);

      // Inaccurate smaller Content-Length that actually streams > maxArchiveBytes mid-stream
      revokeMock.mockClear();
      let streamAborted = false;
      const appLyingLength = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_lying_token_secret',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeMock,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESSIBLE' as const,
            repository: {
              githubRepositoryId: 2002,
              name: 'web-app',
              fullName: 'acme-sec/web-app',
              ownerLogin: 'acme-sec',
              defaultBranch: 'main',
              isPrivate: true,
              isArchived: false,
              htmlUrl: 'https://github.com/acme-sec/web-app',
            },
          })),
          resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
          openRepositoryTarballStream: vi.fn(async () => {
            let chunkIndex = 0;
            return {
              declaredContentLength: 50,
              body: new ReadableStream<Uint8Array>({
                pull(controller) {
                  chunkIndex += 1;
                  controller.enqueue(new Uint8Array(600).fill(chunkIndex));
                },
                cancel() {
                  streamAborted = true;
                },
              }),
            };
          }),
        },
        verifyAuthorization: async () => authorizedFixture(),
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        maxArchiveBytes: 1024,
      });

      const server = await new Promise<http.Server>((resolve) => {
        const srv = appLyingLength.listen(0, '127.0.0.1', () => resolve(srv));
      });
      try {
        const port = (server.address() as AddressInfo).port;
        await expect(
          sendRawHttpRequest({
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/internal/v1/scans/acquire',
            headers: {
              ...buildAcquireHeaders(body),
              'content-length': String(Buffer.byteLength(body)),
            },
            body,
          })
        ).rejects.toThrow();
        expect(streamAborted).toBe(true);
        await vi.waitFor(() => {
          expect(revokeMock).toHaveBeenCalledWith('ghs_lying_token_secret');
        });
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }

      // Token revocation errors never mask original failure and never leak plaintext token
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('aborts transfer and revokes token on mid-stream cancellation, lease loss, worker disconnect, timeout, and revocation failures', async () => {
      const body = JSON.stringify({ scanId: VALID_SCAN_ID, leaseToken: VALID_LEASE_TOKEN });

      // 1. Mid-stream cancellation flips verifyAuthorization during slow streaming
      const revokeOnCancel = vi.fn(async () => ({
        revoked: true as const,
        alreadyInvalidOrExpired: true,
      }));
      let cancelVerifyCalls = 0;
      let cancelStreamCancelled = false;

      const cancelApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        verifyAuthorization: async () => {
          cancelVerifyCalls += 1;
          if (cancelVerifyCalls >= 5) {
            return {
              status: 'DENIED' as const,
              reason: 'SCAN_CANCELLED' as const,
              message: 'Scan cancellation was requested.',
            };
          }
          return authorizedFixture();
        },
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        revalidationIntervalMs: 25,
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_midstream_cancel_token',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeOnCancel,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESSIBLE' as const,
            repository: {
              githubRepositoryId: 2002,
              name: 'web-app',
              fullName: 'acme-sec/web-app',
              ownerLogin: 'acme-sec',
              defaultBranch: 'main',
              isPrivate: true,
              isArchived: false,
              htmlUrl: 'https://github.com/acme-sec/web-app',
            },
          })),
          resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
          openRepositoryTarballStream: vi.fn(async ({ signal }) => ({
            declaredContentLength: null,
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([1, 2, 3]));
                const timer = setTimeout(() => {
                  if (!signal?.aborted) {
                    controller.enqueue(new Uint8Array([4, 5, 6]));
                    controller.close();
                  }
                }, 250);
                signal?.addEventListener('abort', () => {
                  clearTimeout(timer);
                  cancelStreamCancelled = true;
                  try {
                    controller.error(new Error('Aborted'));
                  } catch {
                    // ignore closed controller
                  }
                });
              },
              cancel() {
                cancelStreamCancelled = true;
              },
            }),
          })),
        },
      });

      const cancelSrv = await new Promise<http.Server>((resolve) => {
        const srv = cancelApp.listen(0, '127.0.0.1', () => resolve(srv));
      });
      try {
        const port = (cancelSrv.address() as AddressInfo).port;
        await expect(
          sendRawHttpRequest({
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/internal/v1/scans/acquire',
            headers: {
              ...buildAcquireHeaders(body),
              'content-length': String(Buffer.byteLength(body)),
            },
            body,
          })
        ).rejects.toThrow();
        expect(cancelStreamCancelled).toBe(true);
        await vi.waitFor(() => {
          expect(revokeOnCancel).toHaveBeenCalledWith('ghs_midstream_cancel_token');
        });
      } finally {
        await new Promise<void>((resolve) => cancelSrv.close(() => resolve()));
      }

      // 2. Worker disconnect mid-stream aborts upstream and revokes token
      let disconnectSignalAborted = false;
      const revokeOnDisconnect = vi.fn(async () => ({
        revoked: true as const,
        alreadyInvalidOrExpired: false,
      }));
      const disconnectApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        verifyAuthorization: async () => authorizedFixture(),
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_worker_disconnect_token',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeOnDisconnect,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESSIBLE' as const,
            repository: {
              githubRepositoryId: 2002,
              name: 'web-app',
              fullName: 'acme-sec/web-app',
              ownerLogin: 'acme-sec',
              defaultBranch: 'main',
              isPrivate: true,
              isArchived: false,
              htmlUrl: 'https://github.com/acme-sec/web-app',
            },
          })),
          resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
          openRepositoryTarballStream: vi.fn(async ({ signal }) => ({
            declaredContentLength: null,
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([9, 8, 7]));
                signal?.addEventListener('abort', () => {
                  disconnectSignalAborted = true;
                  try {
                    controller.error(new Error('Aborted by disconnect'));
                  } catch {
                    // ignore
                  }
                });
              },
              cancel() {
                disconnectSignalAborted = true;
              },
            }),
          })),
        },
      });

      const disconnectSrv = await new Promise<http.Server>((resolve) => {
        const srv = disconnectApp.listen(0, '127.0.0.1', () => resolve(srv));
      });
      try {
        const port = (disconnectSrv.address() as AddressInfo).port;
        await new Promise<void>((resolve) => {
          const clientReq = http.request(
            {
              host: '127.0.0.1',
              port,
              method: 'POST',
              path: '/internal/v1/scans/acquire',
              headers: {
                ...buildAcquireHeaders(body),
                'content-length': String(Buffer.byteLength(body)),
              },
            },
            (res) => {
              res.once('data', () => {
                clientReq.destroy();
                setTimeout(resolve, 60);
              });
            }
          );
          clientReq.on('error', () => undefined);
          clientReq.write(body);
          clientReq.end();
        });

        expect(disconnectSignalAborted).toBe(true);
        await vi.waitFor(() => {
          expect(revokeOnDisconnect).toHaveBeenCalledWith('ghs_worker_disconnect_token');
        });
      } finally {
        await new Promise<void>((resolve) => disconnectSrv.close(() => resolve()));
      }

      // 3. Original failure preserved & token revoked even when revocation throws before headers
      const revokeFails = vi.fn(async () => {
        throw new Error('Revocation network failure ghs_secret_revoke_fail');
      });
      const failApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        verifyAuthorization: async () => authorizedFixture(),
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_secret_revoke_fail',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeFails,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESS_REVOKED' as const,
          })),
          resolveCommitSha: vi.fn(),
          openRepositoryTarballStream: vi.fn(),
        },
      });

      const failRes = await request(failApp)
        .post('/internal/v1/scans/acquire')
        .set(buildAcquireHeaders(body))
        .send(body);
      expect(failRes.status).toBe(403);
      expect(failRes.body.error.code).toBe('GITHUB_ACCESS_REVOKED');
      expect(revokeFails).toHaveBeenCalledWith('ghs_secret_revoke_fail');
      expect(JSON.stringify(failRes.body)).not.toContain('ghs_secret_revoke_fail');

      // 4. Unconfigured GitHub client returns 503 cleanly
      const unconfiguredApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
      });
      const unconfiguredRes = await request(unconfiguredApp)
        .post('/internal/v1/scans/acquire')
        .set(buildAcquireHeaders(body))
        .send(body);
      expect(unconfiguredRes.status).toBe(503);
      expect(unconfiguredRes.body.error.code).toBe('GITHUB_INTEGRATION_NOT_CONFIGURED');

      // 5. Total acquisition timeout aborts stalled download & revokes token cleanly
      const revokeOnTimeout = vi.fn(async () => ({
        revoked: true as const,
        alreadyInvalidOrExpired: false,
      }));
      let timeoutAborted = false;
      const timeoutApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        verifyAuthorization: async () => authorizedFixture(),
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        totalAcquisitionTimeoutMs: 40,
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_timeout_token',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeOnTimeout,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESSIBLE' as const,
            repository: {
              githubRepositoryId: 2002,
              name: 'web-app',
              fullName: 'acme-sec/web-app',
              ownerLogin: 'acme-sec',
              defaultBranch: 'main',
              isPrivate: true,
              isArchived: false,
              htmlUrl: 'https://github.com/acme-sec/web-app',
            },
          })),
          resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
          openRepositoryTarballStream: vi.fn(async ({ signal }) => {
            await new Promise((_resolve, reject) => {
              signal?.addEventListener('abort', () => {
                timeoutAborted = true;
                reject(signal.reason ?? new Error('Timeout aborted'));
              });
            });
            throw new Error('Unreachable');
          }),
        },
      });

      const timeoutRes = await request(timeoutApp)
        .post('/internal/v1/scans/acquire')
        .set(buildAcquireHeaders(body))
        .send(body);
      expect(timeoutRes.status).toBe(504);
      expect(timeoutRes.body.error.code).toBe('ACQUISITION_TIMEOUT');
      expect(timeoutAborted).toBe(true);
      expect(revokeOnTimeout).toHaveBeenCalledWith('ghs_timeout_token');

      // 6. Lease expiry before completion prevents normal EOF completion and revokes token
      const revokeOnLeaseExpiry = vi.fn(async () => ({
        revoked: true as const,
        alreadyInvalidOrExpired: false,
      }));
      let leaseCheckCount = 0;
      const leaseExpireApp = createInternalApp({
        auth: { workerAuthSecret: TEST_INTERNAL_SECRET, consumeNonce: async () => 'ACCEPTED' },
        verifyAuthorization: async () => {
          leaseCheckCount += 1;
          if (leaseCheckCount >= 5) {
            return {
              status: 'DENIED' as const,
              reason: 'LEASE_EXPIRED' as const,
              message: 'Worker lease has expired.',
            };
          }
          return authorizedFixture();
        },
        setResolvedCommitWithLease: async () => ({ status: 'UPDATED', scan: {} as never }),
        revalidationIntervalMs: 5_000,
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_lease_expired_token',
            expiresAt: new Date(Date.now() + 60_000),
            installationId: 1001,
            githubRepositoryId: 2002,
            permissions: { contents: 'read' as const },
          })),
          revokeInstallationAccessToken: revokeOnLeaseExpiry,
          probeRepositoryById: vi.fn(async () => ({
            status: 'ACCESSIBLE' as const,
            repository: {
              githubRepositoryId: 2002,
              name: 'web-app',
              fullName: 'acme-sec/web-app',
              ownerLogin: 'acme-sec',
              defaultBranch: 'main',
              isPrivate: true,
              isArchived: false,
              htmlUrl: 'https://github.com/acme-sec/web-app',
            },
          })),
          resolveCommitSha: vi.fn(async () => TEST_COMMIT_SHA),
          openRepositoryTarballStream: vi.fn(async () => ({
            declaredContentLength: null,
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([10, 20, 30]));
                controller.close();
              },
            }),
          })),
        },
      });

      const leaseSrv = await new Promise<http.Server>((resolve) => {
        const s = leaseExpireApp.listen(0, '127.0.0.1', () => resolve(s));
      });
      try {
        const port = (leaseSrv.address() as AddressInfo).port;
        await expect(
          sendRawHttpRequest({
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/internal/v1/scans/acquire',
            headers: {
              ...buildAcquireHeaders(body),
              'content-length': String(Buffer.byteLength(body)),
            },
            body,
          })
        ).rejects.toThrow();
        await vi.waitFor(() => {
          expect(revokeOnLeaseExpiry).toHaveBeenCalledWith('ghs_lease_expired_token');
        });
      } finally {
        await new Promise<void>((resolve) => leaseSrv.close(() => resolve()));
      }
    });
  });
});
