import { EventEmitter } from 'node:events';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  RedisConnectionManager,
  consumeInternalAuthNonce,
  type RedisClientLike,
} from '@vibeshield/queue';
import { createInternalApp } from '../../../../apps/api/src/internal-app.js';
import {
  buildInternalWorkerCanonicalString as apiBuildCanonical,
  signInternalWorkerRequest as apiSignInternalRequest,
} from '../../../../apps/api/src/modules/scans/internal-auth.js';
import {
  createInternalAcquisitionClient,
  generateInternalAuthNonce,
  HARD_MAX_COMPRESSED_ARCHIVE_BYTES,
  INTERNAL_NONCE_HEADER,
  INTERNAL_SCAN_ACQUIRE_PATH,
  INTERNAL_SERVICE_HEADER,
  INTERNAL_SIGNATURE_HEADER,
  INTERNAL_TIMESTAMP_HEADER,
  INTERNAL_WORKER_SERVICE_ID,
  InternalAcquisitionError,
  loadWorkerConfig,
  requireInternalAcquisitionConfig,
  signInternalWorkerRequest,
  toInternalAcquisitionConfig,
  verifyInternalWorkerSignature,
  type AcquiredRepositoryArchive,
  type WorkerLogger,
} from '../index.js';

const TEST_INTERNAL_SECRET = 'internal_worker_auth_secret_minimum_32_chars_long';
const TEST_JWT_SECRET = 'jwt_access_secret_distinct_minimum_32_chars_long';
const TEST_SCAN_ID = '507f1f77bcf86cd799439011';
const TEST_ORG_ID = '507f1f77bcf86cd799439022';
const TEST_PROJ_ID = '507f1f77bcf86cd799439033';
const TEST_CONN_ID = '507f1f77bcf86cd799439044';
const TEST_LEASE_TOKEN = 'lease_token_fencing_secret_0123456789abcdef';
const TEST_COMMIT_SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';

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

function createCapturingLogger(): {
  logger: WorkerLogger;
  entries: Array<{ level: string; message: string; context?: Record<string, unknown> }>;
} {
  const entries: Array<{ level: string; message: string; context?: Record<string, unknown> }> = [];
  return {
    entries,
    logger: {
      info(message, context) {
        entries.push({ level: 'info', message, context });
      },
      warn(message, context) {
        entries.push({ level: 'warn', message, context });
      },
      error(message, context) {
        entries.push({ level: 'error', message, context });
      },
    },
  };
}

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
}

async function consumeStream(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

describe('Worker Internal Repository Acquisition Client', () => {
  const closers: Array<() => Promise<void>> = [];

  async function startHttpServer(
    handler: http.RequestListener
  ): Promise<{ baseUrl: string; server: http.Server; getOpenConnections: () => number }> {
    const server = http.createServer(handler);
    const sockets = new Set<net.Socket>();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => {
        sockets.delete(socket);
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });

    closers.push(
      () =>
        new Promise<void>((resolve) => {
          for (const sock of sockets) {
            sock.destroy();
          }
          server.close(() => resolve());
        })
    );

    const addr = server.address() as AddressInfo;
    return {
      baseUrl: `http://127.0.0.1:${addr.port}`,
      server,
      getOpenConnections: () => sockets.size,
    };
  }

  async function startRawTcpServer(
    onSocket: (socket: net.Socket) => void
  ): Promise<{ baseUrl: string; httpsBaseUrl: string; server: net.Server }> {
    const server = net.createServer(onSocket);
    const sockets = new Set<net.Socket>();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });

    closers.push(
      () =>
        new Promise<void>((resolve) => {
          for (const sock of sockets) {
            sock.destroy();
          }
          server.close(() => resolve());
        })
    );

    const addr = server.address() as AddressInfo;
    return {
      baseUrl: `http://127.0.0.1:${addr.port}`,
      httpsBaseUrl: `https://127.0.0.1:${addr.port}`,
      server,
    };
  }

  afterEach(async () => {
    while (closers.length > 0) {
      const close = closers.pop()!;
      await close();
    }
    vi.restoreAllMocks();
  });

  describe('Configuration validation & secret isolation', () => {
    it('loads valid internal acquisition configuration without exposing secret during serialization', () => {
      const cfg = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
        INTERNAL_API_BASE_URL: 'http://127.0.0.1:4001/',
        INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
      });

      expect(cfg.internalApiBaseUrl).toBe('http://127.0.0.1:4001');
      expect(cfg.internalWorkerAuthSecret).toBe(TEST_INTERNAL_SECRET);
      expect(JSON.stringify(cfg)).not.toContain(TEST_INTERNAL_SECRET);
      expect(Object.keys(cfg)).not.toContain('internalWorkerAuthSecret');

      const resolved = requireInternalAcquisitionConfig(cfg);
      expect(resolved.baseUrl).toBe('http://127.0.0.1:4001');
      expect(resolved.workerAuthSecret).toBe(TEST_INTERNAL_SECRET);

      const client = createInternalAcquisitionClient({ config: cfg });
      expect(client.getConfigSummary()).toEqual({
        baseUrl: 'http://127.0.0.1:4001',
        endpointPath: INTERNAL_SCAN_ACQUIRE_PATH,
        serviceId: INTERNAL_WORKER_SERVICE_ID,
        maxArchiveBytes: HARD_MAX_COMPRESSED_ARCHIVE_BYTES,
        connectTimeoutMs: 10_000,
        headersTimeoutMs: 90_000,
        streamIdleTimeoutMs: 65_000,
        totalTimeoutMs: 130_000,
      });
      expect(JSON.stringify(client)).not.toContain(TEST_INTERNAL_SECRET);
      expect(inspect(client)).not.toContain(TEST_INTERNAL_SECRET);
    });

    it('rejects missing, partial, malformed, credential-bearing, or secret-colliding configurations cleanly', () => {
      const baseRaw = {
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
      };

      // When both are omitted, toInternalAcquisitionConfig returns null and require throws INVALID_CONFIGURATION
      const unconfigured = loadWorkerConfig(baseRaw);
      expect(toInternalAcquisitionConfig(unconfigured)).toBeNull();
      expect(() => requireInternalAcquisitionConfig(unconfigured)).toThrowError(
        InternalAcquisitionError
      );

      // Partial pairs fail EnvValidationError
      expect(() =>
        loadWorkerConfig({
          ...baseRaw,
          INTERNAL_API_BASE_URL: 'http://127.0.0.1:4001',
        })
      ).toThrow(/INTERNAL_WORKER_AUTH_SECRET/);

      expect(() =>
        loadWorkerConfig({
          ...baseRaw,
          INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
        })
      ).toThrow(/INTERNAL_API_BASE_URL/);

      // Reject malformed/unsupported URLs, credentials, queries, fragments, custom paths without leaking credentials
      const badUrls = [
        'not-a-url',
        'ftp://127.0.0.1:4001',
        'http://worker:EmbeddedUrlSecret!@127.0.0.1:4001',
        'https://127.0.0.1:4001?token=QueryLeak99',
        'https://127.0.0.1:4001#FragmentLeak99',
        'https://127.0.0.1:4001/custom-prefix',
      ];
      for (const badUrl of badUrls) {
        let caughtMsg = '';
        try {
          loadWorkerConfig({
            ...baseRaw,
            INTERNAL_API_BASE_URL: badUrl,
            INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
          });
        } catch (err) {
          caughtMsg = err instanceof Error ? err.message : String(err);
        }
        expect(caughtMsg).toContain('INTERNAL_API_BASE_URL');
        expect(caughtMsg).not.toContain('EmbeddedUrlSecret!');
        expect(caughtMsg).not.toContain('QueryLeak99');
        expect(caughtMsg).not.toContain('FragmentLeak99');
      }

      // Reject short or whitespace-heavy secret and collisions with JWT or GitHub secrets
      expect(() =>
        loadWorkerConfig({
          ...baseRaw,
          INTERNAL_API_BASE_URL: 'http://127.0.0.1:4001',
          INTERNAL_WORKER_AUTH_SECRET: '   short_secret_only   ',
        })
      ).toThrow(/INTERNAL_WORKER_AUTH_SECRET/);

      expect(() =>
        loadWorkerConfig({
          ...baseRaw,
          INTERNAL_API_BASE_URL: 'http://127.0.0.1:4001',
          INTERNAL_WORKER_AUTH_SECRET: TEST_JWT_SECRET,
          JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        })
      ).toThrow(/distinct from JWT_ACCESS_SECRET/);

      expect(() =>
        loadWorkerConfig({
          ...baseRaw,
          INTERNAL_API_BASE_URL: 'http://127.0.0.1:4001',
          INTERNAL_WORKER_AUTH_SECRET: TEST_INTERNAL_SECRET,
          GITHUB_WEBHOOK_SECRET: TEST_INTERNAL_SECRET,
        })
      ).toThrow(/distinct from JWT_ACCESS_SECRET and GitHub secrets/);

      // Reject over-limit maxArchiveBytes or invalid client config
      expect(() =>
        createInternalAcquisitionClient({
          baseUrl: 'http://127.0.0.1:4001',
          workerAuthSecret: TEST_INTERNAL_SECRET,
          maxArchiveBytes: HARD_MAX_COMPRESSED_ARCHIVE_BYTES + 1,
        })
      ).toThrowError(InternalAcquisitionError);

      expect(() =>
        createInternalAcquisitionClient({
          baseUrl: 'http://127.0.0.1:4001?foo=bar',
          workerAuthSecret: TEST_INTERNAL_SECRET,
        })
      ).toThrowError(InternalAcquisitionError);
    });
  });

  describe('HMAC canonical signing & cross-compatibility with API verification', () => {
    it('matches API canonical string and HMAC-SHA256 signatures byte-for-byte with timing-safe verification', () => {
      const payload = JSON.stringify({ scanId: TEST_SCAN_ID, leaseToken: TEST_LEASE_TOKEN });
      const nonce = 'vector_nonce_0123456789_abcdef';
      const timestamp = '1764300000123';

      const workerSigned = signInternalWorkerRequest({
        secret: TEST_INTERNAL_SECRET,
        method: 'POST',
        path: INTERNAL_SCAN_ACQUIRE_PATH,
        serviceId: INTERNAL_WORKER_SERVICE_ID,
        timestamp,
        nonce,
        rawBody: payload,
      });

      const apiSigned = apiSignInternalRequest({
        secret: TEST_INTERNAL_SECRET,
        method: 'POST',
        path: INTERNAL_SCAN_ACQUIRE_PATH,
        serviceId: 'security-worker',
        timestamp,
        nonce,
        rawBody: payload,
      });

      expect(workerSigned).toEqual(apiSigned);
      expect(
        apiBuildCanonical({
          method: 'post',
          path: INTERNAL_SCAN_ACQUIRE_PATH,
          serviceId: 'security-worker',
          timestamp,
          nonce,
          bodySha256Hex: workerSigned.bodySha256Hex,
        })
      ).toContain(workerSigned.bodySha256Hex);

      expect(
        verifyInternalWorkerSignature({
          secret: TEST_INTERNAL_SECRET,
          method: 'POST',
          path: INTERNAL_SCAN_ACQUIRE_PATH,
          serviceId: 'security-worker',
          timestamp,
          nonce,
          rawBody: payload,
          signatureHeader: workerSigned.signature,
        })
      ).toBe(true);

      expect(
        verifyInternalWorkerSignature({
          secret: TEST_INTERNAL_SECRET,
          method: 'POST',
          path: INTERNAL_SCAN_ACQUIRE_PATH,
          serviceId: 'security-worker',
          timestamp,
          nonce,
          rawBody: JSON.stringify({ scanId: TEST_SCAN_ID, leaseToken: `${TEST_LEASE_TOKEN}x` }),
          signatureHeader: workerSigned.signature,
        })
      ).toBe(false);
    });

    it('authenticates directly against the real API internal Express app and fails closed on nonce replay', async () => {
      const redisClient = new InMemoryReplayRedisClient();
      const redisManager = new RedisConnectionManager({
        createClient: () => redisClient,
        logger: {},
      });
      await redisManager.connect({ url: 'redis://127.0.0.1:6379' });

      const archiveFixture = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4, 5, 6]);
      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce: (input) => consumeInternalAuthNonce(redisManager, input),
        },
        verifyAuthorization: vi.fn(async (input) => ({
          status: 'AUTHORIZED' as const,
          context: {
            scanId: input.scanId,
            organizationId: TEST_ORG_ID,
            projectId: TEST_PROJ_ID,
            repositoryConnectionId: TEST_CONN_ID,
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
        })),
        setResolvedCommitWithLease: vi.fn(async () => ({
          status: 'UPDATED' as const,
          scan: {} as never,
        })),
        githubClient: {
          createRepositoryAcquisitionToken: vi.fn(async () => ({
            token: 'ghs_ephemeral_token_0123456789',
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
            declaredContentLength: archiveFixture.byteLength,
            body: new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(archiveFixture);
                controller.close();
              },
            }),
          })),
        },
      });

      const { baseUrl } = await startHttpServer(internalApp);
      const client = createInternalAcquisitionClient({
        baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      // 1. Live end-to-end acquisition succeeds against real internal API middleware & streaming service
      const acquired = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      const received = await consumeStream(acquired.stream);
      expect(received).toEqual(archiveFixture);
      expect(acquired.bytesReceived()).toBe(archiveFixture.byteLength);

      // 2. Fixed-nonce client proves real API Redis replay protection rejects duplicate nonce with 401 -> AUTHENTICATION_FAILED
      const replayNonce = generateInternalAuthNonce();
      const fixedNonceClient = createInternalAcquisitionClient({
        baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        nonceGenerator: () => replayNonce,
      });
      const firstArchive = await fixedNonceClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      expect(await consumeStream(firstArchive.stream)).toEqual(archiveFixture);

      await expect(
        fixedNonceClient.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        name: 'InternalAcquisitionError',
        code: 'AUTHENTICATION_FAILED',
        httpStatus: 401,
      });

      // 3. Invalid scanId or short leaseToken fails fast without calling server or leaking leaseToken
      await expect(
        client.acquireRepositoryArchive({
          scanId: 'invalid-scan-id',
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'INVALID_CONFIGURATION',
      });

      await expect(
        client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: 'too_short_tok',
        })
      ).rejects.toSatisfy(
        (err: unknown) =>
          err instanceof InternalAcquisitionError &&
          err.code === 'INVALID_CONFIGURATION' &&
          !err.message.includes('too_short_tok')
      );

      await redisManager.disconnect();
    });
  });

  describe('Request construction, fresh nonces, failure modes, and zero automatic retries', () => {
    it('sends POST with exact path, strict JSON payload, fresh nonces, and rejects non-retryable failures without retries', async () => {
      const seenRequests: Array<{
        method: string | undefined;
        url: string | undefined;
        headers: http.IncomingHttpHeaders;
        rawBody: string;
      }> = [];

      const { baseUrl } = await startHttpServer((req, res) => {
        const bodyChunks: Buffer[] = [];
        req.on('data', (c: Buffer) => bodyChunks.push(c));
        req.on('end', () => {
          seenRequests.push({
            method: req.method,
            url: req.url,
            headers: req.headers,
            rawBody: Buffer.concat(bodyChunks).toString('utf8'),
          });

          if (seenRequests.length <= 3) {
            res.writeHead(200, {
              'content-type': 'application/gzip',
              'cache-control': 'no-store',
              'x-content-type-options': 'nosniff',
            });
            res.end(Buffer.from([0x1f, 0x8b, 0x08]));
            return;
          }

          res.writeHead(503, { 'content-type': 'application/json' });
          res.end(
            JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE', message: 'raw upstream' } })
          );
        });
      });

      const client = createInternalAcquisitionClient({
        baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      for (let i = 0; i < 3; i += 1) {
        const archive = await client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        });
        expect(await consumeStream(archive.stream)).toEqual(Buffer.from([0x1f, 0x8b, 0x08]));
      }

      const nonces = new Set<string>();
      for (const reqInfo of seenRequests) {
        expect(reqInfo.method).toBe('POST');
        expect(reqInfo.url).toBe(INTERNAL_SCAN_ACQUIRE_PATH);
        expect(reqInfo.headers['content-type']).toBe('application/json');
        expect(reqInfo.headers[INTERNAL_SERVICE_HEADER]).toBe(INTERNAL_WORKER_SERVICE_ID);
        expect(String(reqInfo.headers[INTERNAL_TIMESTAMP_HEADER])).toMatch(/^\d{10,16}$/);
        expect(String(reqInfo.headers[INTERNAL_SIGNATURE_HEADER])).toMatch(/^sha256=[a-f0-9]{64}$/);
        expect(reqInfo.headers['authorization']).toBeUndefined();
        expect(reqInfo.rawBody).toBe(
          JSON.stringify({ scanId: TEST_SCAN_ID, leaseToken: TEST_LEASE_TOKEN })
        );
        nonces.add(String(reqInfo.headers[INTERNAL_NONCE_HEADER]));
      }
      expect(nonces.size).toBe(3);

      // 4th request returns 503 -> must fail immediately with 0 retries (total requests becomes 4, not >4)
      await expect(
        client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'UNEXPECTED_HTTP_STATUS',
        httpStatus: 503,
      });
      expect(seenRequests).toHaveLength(4);
    });

    it('rejects connection refused and connection/headers/total timeouts without retries', async () => {
      const closedPort = await getFreePort();
      const refusedRequestsClient = createInternalAcquisitionClient({
        baseUrl: `http://127.0.0.1:${closedPort}`,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      await expect(
        refusedRequestsClient.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'INTERNAL_API_CONNECTION_FAILED',
      });

      // Connection timeout: real TLS connect attempt against non-responding raw TCP socket stalls before secureConnect
      const { httpsBaseUrl } = await startRawTcpServer(() => {
        // Hold socket silently open without completing TLS handshake
      });
      const connectTimeoutClient = createInternalAcquisitionClient({
        baseUrl: httpsBaseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        connectTimeoutMs: 40,
        headersTimeoutMs: 500,
        totalTimeoutMs: 500,
      });

      await expect(
        connectTimeoutClient.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'ACQUISITION_TIMEOUT',
        timeoutPhase: 'connect',
      });

      // Headers timeout: HTTP server accepts request and stalls before sending headers
      let headerRequestsCount = 0;
      const stalledServer = await startHttpServer((_req, _res) => {
        headerRequestsCount += 1;
      });
      const headersTimeoutClient = createInternalAcquisitionClient({
        baseUrl: stalledServer.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        connectTimeoutMs: 500,
        headersTimeoutMs: 40,
        totalTimeoutMs: 500,
      });

      await expect(
        headersTimeoutClient.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'ACQUISITION_TIMEOUT',
        timeoutPhase: 'headers',
      });
      expect(headerRequestsCount).toBe(1);
    });

    it('rejects 301/302 redirects fail-closed without following Location', async () => {
      const redirectTargetSpy = vi.fn();
      const targetServer = await startHttpServer((_req, res) => {
        redirectTargetSpy();
        res.writeHead(200, { 'content-type': 'application/gzip' });
        res.end(Buffer.from('should-never-be-fetched'));
      });

      let statusToSend = 301;
      const primaryServer = await startHttpServer((_req, res) => {
        res.writeHead(statusToSend, {
          location: `${targetServer.baseUrl}/redirected-evil`,
        });
        res.end();
      });

      const client = createInternalAcquisitionClient({
        baseUrl: primaryServer.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      await expect(
        client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'REDIRECT_REJECTED',
        httpStatus: 301,
      });

      statusToSend = 302;
      await expect(
        client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'REDIRECT_REJECTED',
        httpStatus: 302,
      });

      expect(redirectTargetSpy).not.toHaveBeenCalled();
    });

    it('distinguishes 401/403 authentication failures, 413 oversized, and unexpected HTTP statuses without leaking raw bodies or secrets', async () => {
      const secretBodyLeak = `upstream_body_token=${TEST_LEASE_TOKEN} signing=${TEST_INTERNAL_SECRET}`;
      let nextStatus = 401;

      const server = await startHttpServer((_req, res) => {
        res.writeHead(nextStatus, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 'RAW_CODE', message: secretBodyLeak } }));
      });

      const { entries, logger } = createCapturingLogger();
      const client = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        logger,
      });

      for (const expected of [
        { status: 401, code: 'AUTHENTICATION_FAILED' },
        { status: 403, code: 'AUTHENTICATION_FAILED' },
        { status: 413, code: 'ARCHIVE_SIZE_EXCEEDED' },
        { status: 404, code: 'UNEXPECTED_HTTP_STATUS' },
        { status: 204, code: 'UNEXPECTED_HTTP_STATUS' },
        { status: 500, code: 'UNEXPECTED_HTTP_STATUS' },
      ]) {
        nextStatus = expected.status;
        let caught: unknown = null;
        try {
          await client.acquireRepositoryArchive({
            scanId: TEST_SCAN_ID,
            leaseToken: TEST_LEASE_TOKEN,
          });
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(InternalAcquisitionError);
        expect((caught as InternalAcquisitionError).code).toBe(expected.code);
        expect((caught as InternalAcquisitionError).httpStatus).toBe(expected.status);
        expect((caught as InternalAcquisitionError).message).not.toContain('RAW_CODE');
        expect((caught as InternalAcquisitionError).message).not.toContain(TEST_LEASE_TOKEN);
        expect((caught as InternalAcquisitionError).message).not.toContain(TEST_INTERNAL_SECRET);
        expect(JSON.stringify(caught)).not.toContain(TEST_LEASE_TOKEN);
        expect(JSON.stringify(caught)).not.toContain(TEST_INTERNAL_SECRET);
      }

      const logDump = JSON.stringify(entries);
      expect(logDump).not.toContain(TEST_LEASE_TOKEN);
      expect(logDump).not.toContain(TEST_INTERNAL_SECRET);
      expect(logDump).not.toContain('sha256=');
      expect(logDump).not.toContain('RAW_CODE');
    });

    it('rejects invalid Content-Type, malformed/negative/zero/duplicate Content-Length, and oversized Content-Length', async () => {
      let mode:
        | 'html'
        | 'missing-ct'
        | 'bad-nosniff'
        | 'bad-cache'
        | 'cl-negative'
        | 'cl-nonnumeric'
        | 'cl-zero'
        | 'cl-oversize' = 'html';

      const httpSrv = await startHttpServer((_req, res) => {
        if (mode === 'html') {
          res.writeHead(200, { 'content-type': 'text/html' });
          res.end('<html>error</html>');
        } else if (mode === 'missing-ct') {
          res.writeHead(200, {});
          res.end('abc');
        } else if (mode === 'bad-nosniff') {
          res.writeHead(200, {
            'content-type': 'application/gzip',
            'x-content-type-options': 'invalid',
          });
          res.end('abc');
        } else if (mode === 'bad-cache') {
          res.writeHead(200, {
            'content-type': 'application/gzip',
            'cache-control': 'public, max-age=3600',
          });
          res.end('abc');
        } else if (mode === 'cl-oversize') {
          res.writeHead(200, {
            'content-type': 'application/gzip',
            'content-length': '200',
          });
          res.end(Buffer.alloc(200, 0xaa));
        }
      });

      const client = createInternalAcquisitionClient({
        baseUrl: httpSrv.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        maxArchiveBytes: 100,
      });

      for (const m of ['html', 'missing-ct', 'bad-nosniff', 'bad-cache'] as const) {
        mode = m;
        await expect(
          client.acquireRepositoryArchive({
            scanId: TEST_SCAN_ID,
            leaseToken: TEST_LEASE_TOKEN,
          })
        ).rejects.toMatchObject({
          code: 'INVALID_RESPONSE_HEADERS',
        });
      }

      mode = 'cl-oversize';
      await expect(
        client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'ARCHIVE_SIZE_EXCEEDED',
      });

      // Raw TCP socket tests for malformed/negative/zero/duplicate Content-Length headers
      let rawResponse = '';
      const rawTcp = await startRawTcpServer((socket) => {
        socket.once('data', () => {
          socket.write(rawResponse);
          socket.end();
        });
      });

      const rawClient = createInternalAcquisitionClient({
        baseUrl: rawTcp.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        maxArchiveBytes: 100,
      });

      for (const clHeader of [
        'Content-Length: -5',
        'Content-Length: abc',
        'Content-Length: 0',
        'Content-Length: 10\r\nContent-Length: 20',
      ]) {
        rawResponse =
          `HTTP/1.1 200 OK\r\n` +
          `Content-Type: application/gzip\r\n` +
          `${clHeader}\r\n` +
          `Connection: close\r\n\r\n`;

        await expect(
          rawClient.acquireRepositoryArchive({
            scanId: TEST_SCAN_ID,
            leaseToken: TEST_LEASE_TOKEN,
          })
        ).rejects.toSatisfy(
          (err: unknown) =>
            err instanceof InternalAcquisitionError &&
            (err.code === 'INVALID_RESPONSE_HEADERS' ||
              err.code === 'INTERNAL_API_CONNECTION_FAILED')
        );
      }
    });
  });

  describe('Bounded streaming, backpressure, truncation detection, cancellation, shutdown & cleanup', () => {
    it('succeeds cleanly at exact maxArchiveBytes and aborts immediately across multiple chunks when exceeded (even without Content-Length)', async () => {
      const limit = 100;
      let chunksToSend: Buffer[] = [Buffer.alloc(limit, 0x11)];

      const server = await startHttpServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/gzip',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        });
        for (const chunk of chunksToSend) {
          res.write(chunk);
        }
        res.end();
      });

      const client = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        maxArchiveBytes: limit,
      });

      // Exact limit across multiple chunks (chunked, no Content-Length) -> succeeds
      chunksToSend = [Buffer.alloc(40, 0x22), Buffer.alloc(60, 0x33)];
      const exactArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      const exactPayload = await consumeStream(exactArchive.stream);
      expect(exactPayload.byteLength).toBe(limit);
      expect(exactArchive.bytesReceived()).toBe(limit);
      expect(exactArchive.declaredContentLength).toBeNull();

      // Exceeding limit across multiple chunks (40 + 40 + 30 = 110 > 100) -> fails immediately
      chunksToSend = [Buffer.alloc(40, 0x44), Buffer.alloc(40, 0x55), Buffer.alloc(30, 0x66)];
      const overArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(overArchive.stream)).rejects.toMatchObject({
        code: 'ARCHIVE_SIZE_EXCEEDED',
      });
    });

    it('propagates backpressure cleanly during slow streaming without dropping bytes', async () => {
      const totalChunks = 64;
      const chunkBytes = 4096;
      const expectedTotal = totalChunks * chunkBytes;
      let writeReturnedFalseCount = 0;

      const server = await startHttpServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/gzip',
          'content-length': String(expectedTotal),
        });

        let sent = 0;
        const pump = () => {
          while (sent < totalChunks) {
            const buf = Buffer.alloc(chunkBytes, sent % 256);
            sent += 1;
            const ok = res.write(buf);
            if (!ok) {
              writeReturnedFalseCount += 1;
              res.once('drain', pump);
              return;
            }
          }
          res.end();
        };
        pump();
      });

      const client = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        maxArchiveBytes: expectedTotal + 1024,
        streamHighWaterMark: 1024,
      });

      const archive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });

      let receivedBytes = 0;
      for await (const chunk of archive.stream) {
        receivedBytes += (chunk as Buffer).byteLength;
        await new Promise((resolve) => setTimeout(resolve, 1));
      }

      expect(receivedBytes).toBe(expectedTotal);
      expect(archive.bytesReceived()).toBe(expectedTotal);
      expect(writeReturnedFalseCount).toBeGreaterThan(0);
    });

    it('detects premature socket close after HTTP 200, Content-Length truncation, and empty body responses', async () => {
      let scenario: 'chunked-destroy' | 'cl-truncated' | 'empty-chunked' = 'chunked-destroy';

      const server = await startHttpServer((_req, res) => {
        if (scenario === 'chunked-destroy') {
          res.writeHead(200, { 'content-type': 'application/gzip' });
          res.write(Buffer.from([0x1f, 0x8b, 0x08, 0x00]));
          setTimeout(() => {
            res.destroy();
          }, 15);
          return;
        }

        if (scenario === 'empty-chunked') {
          res.writeHead(200, { 'content-type': 'application/gzip' });
          res.end();
          return;
        }
      });

      const client = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      // 1. Chunked HTTP 200 destroyed mid-stream after partial chunk -> INCOMPLETE_ARCHIVE_RESPONSE
      scenario = 'chunked-destroy';
      const partialArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(partialArchive.stream)).rejects.toMatchObject({
        code: 'INCOMPLETE_ARCHIVE_RESPONSE',
      });

      // 2. Empty HTTP 200 body -> INCOMPLETE_ARCHIVE_RESPONSE
      scenario = 'empty-chunked';
      const emptyArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(emptyArchive.stream)).rejects.toMatchObject({
        code: 'INCOMPLETE_ARCHIVE_RESPONSE',
      });

      // 3. Premature close BEFORE consumer starts iterating archive.stream (deferred error delivery without unhandled error crash)
      scenario = 'chunked-destroy';
      const delayedConsumerArchive: AcquiredRepositoryArchive =
        await client.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        });
      await new Promise((resolve) => setTimeout(resolve, 40));
      await expect(consumeStream(delayedConsumerArchive.stream)).rejects.toMatchObject({
        code: 'INCOMPLETE_ARCHIVE_RESPONSE',
      });

      // 4. Content-Length declared as 100 bytes, raw socket closes after 20 bytes
      const rawTruncated = await startRawTcpServer((socket) => {
        socket.once('data', () => {
          socket.write(
            'HTTP/1.1 200 OK\r\n' +
              'Content-Type: application/gzip\r\n' +
              'Content-Length: 100\r\n' +
              'Connection: close\r\n\r\n'
          );
          socket.write(Buffer.alloc(20, 0xaa));
          socket.end();
        });
      });
      const clClient = createInternalAcquisitionClient({
        baseUrl: rawTruncated.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });
      const clArchive = await clClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(clArchive.stream)).rejects.toMatchObject({
        code: 'INCOMPLETE_ARCHIVE_RESPONSE',
      });
    });

    it('separates explicit cancellation, worker shutdown, and timeouts cleanly and removes all AbortSignal listeners & sockets', async () => {
      let holdResponseOpen: (() => void) | null = null;
      const server = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/gzip' });
        res.write(Buffer.from([0x1f, 0x8b]));
        holdResponseOpen = () => {
          if (!res.destroyed) {
            res.destroy();
          }
        };
      });

      const trackSignal = () => {
        const controller = new AbortController();
        let activeListeners = 0;
        const origAdd = controller.signal.addEventListener.bind(controller.signal);
        const origRemove = controller.signal.removeEventListener.bind(controller.signal);
        controller.signal.addEventListener = ((...args: Parameters<typeof origAdd>) => {
          activeListeners += 1;
          return origAdd(...args);
        }) as typeof controller.signal.addEventListener;
        controller.signal.removeEventListener = ((...args: Parameters<typeof origRemove>) => {
          activeListeners = Math.max(0, activeListeners - 1);
          return origRemove(...args);
        }) as typeof controller.signal.removeEventListener;
        return { controller, getActiveListeners: () => activeListeners };
      };

      // 1. Abort BEFORE headers
      const preHeaderServer = await startHttpServer(() => {
        // Leave pending until client aborts
      });
      const preClient = createInternalAcquisitionClient({
        baseUrl: preHeaderServer.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });
      const preCancel = trackSignal();
      const prePromise = preClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
        signal: preCancel.controller.signal,
      });
      setTimeout(() => preCancel.controller.abort(), 15);
      await expect(prePromise).rejects.toMatchObject({
        code: 'ACQUISITION_CANCELLED',
      });
      expect(preCancel.getActiveListeners()).toBe(0);

      // 2. Abort DURING archive streaming
      const streamClient = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });
      const midCancel = trackSignal();
      const midShutdown = trackSignal();
      const midArchive = await streamClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
        signal: midCancel.controller.signal,
        shutdownSignal: midShutdown.controller.signal,
      });
      setTimeout(() => midCancel.controller.abort(), 20);
      await expect(consumeStream(midArchive.stream)).rejects.toMatchObject({
        code: 'ACQUISITION_CANCELLED',
      });
      expect(midCancel.getActiveListeners()).toBe(0);
      expect(midShutdown.getActiveListeners()).toBe(0);
      holdResponseOpen?.();

      // 3. Worker shutdown DURING archive streaming -> WORKER_SHUTDOWN (distinct from ACQUISITION_CANCELLED)
      const shutdownController = new AbortController();
      const shutdownClient = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        shutdownSignal: shutdownController.signal,
      });
      const shutdownArchive = await shutdownClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      setTimeout(() => shutdownController.abort(), 20);
      await expect(consumeStream(shutdownArchive.stream)).rejects.toMatchObject({
        code: 'WORKER_SHUTDOWN',
      });
      holdResponseOpen?.();

      // Also verify client.shutdown() throws WORKER_SHUTDOWN for future attempts
      shutdownClient.shutdown();
      await expect(
        shutdownClient.acquireRepositoryArchive({
          scanId: TEST_SCAN_ID,
          leaseToken: TEST_LEASE_TOKEN,
        })
      ).rejects.toMatchObject({
        code: 'WORKER_SHUTDOWN',
      });

      // 4. Stream idle timeout during streaming -> ACQUISITION_TIMEOUT (idle)
      const idleClient = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        streamIdleTimeoutMs: 25,
        totalTimeoutMs: 500,
      });
      const idleArchive = await idleClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(idleArchive.stream)).rejects.toMatchObject({
        code: 'ACQUISITION_TIMEOUT',
        timeoutPhase: 'idle',
      });
      holdResponseOpen?.();

      // 5. Overall acquisition timeout during streaming -> ACQUISITION_TIMEOUT (total)
      const totalClient = createInternalAcquisitionClient({
        baseUrl: server.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
        connectTimeoutMs: 200,
        headersTimeoutMs: 200,
        streamIdleTimeoutMs: 200,
        totalTimeoutMs: 25,
      });
      const totalArchive = await totalClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(consumeStream(totalArchive.stream)).rejects.toMatchObject({
        code: 'ACQUISITION_TIMEOUT',
        timeoutPhase: 'total',
      });
      holdResponseOpen?.();

      // 6. Node stream pipeline() integration fails cleanly on truncated/incomplete response
      const truncPipelineServer = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/gzip' });
        res.write(Buffer.from([0x1f, 0x8b, 0x08]));
        setTimeout(() => res.destroy(), 15);
      });
      const pipeClient = createInternalAcquisitionClient({
        baseUrl: truncPipelineServer.baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });
      const pipeArchive = await pipeClient.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      const sinkChunks: Buffer[] = [];
      const sink = new Writable({
        write(chunk, _encoding, callback) {
          sinkChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          callback();
        },
      });
      await expect(pipeline(pipeArchive.stream, sink)).rejects.toMatchObject({
        code: 'INCOMPLETE_ARCHIVE_RESPONSE',
      });

      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(server.getOpenConnections()).toBe(0);
    });
  });
});
