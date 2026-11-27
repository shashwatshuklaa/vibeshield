import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import net from 'node:net';
import http from 'node:http';
import express from 'express';
import { createApp } from '../app.js';
import {
  bootstrapServer,
  resetServerStateForTests,
  shutdownServer,
  startServer,
  type ServerLogger,
} from '../server.js';

const TEST_JWT_SECRET = 'test_jwt_access_secret_minimum_32_characters_long';

function createMockLogger(): Required<ServerLogger> {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const address = srv.address() as AddressInfo;
      srv.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(address.port);
      });
    });
  });
}

describe('API Server Lifecycle Integration', () => {
  afterEach(async () => {
    await shutdownServer('TEST_CLEANUP', {
      disconnectDb: async () => undefined,
      logger: createMockLogger(),
    }).catch(() => undefined);
    resetServerStateForTests();
  });

  it('connects to MongoDB before starting the HTTP server', async () => {
    const events: string[] = [];
    const logger = createMockLogger();
    const port = await getFreePort();

    const connectDb = vi.fn(async () => {
      events.push('db:connect');
    });
    const disconnectDb = vi.fn(async () => {
      events.push('db:disconnect');
    });

    const server = await startServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(port),
        HOST: '127.0.0.1',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_test',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      },
      connectDb,
      disconnectDb,
      createAppFn: (opts) => {
        events.push('app:create');
        const app = createApp(opts);
        const origListen = app.listen.bind(app);
        app.listen = ((...args: Parameters<typeof app.listen>) => {
          events.push('http:listen');
          return origListen(...args);
        }) as typeof app.listen;
        return app;
      },
      logger,
    });

    expect(server.listening).toBe(true);
    expect(connectDb).toHaveBeenCalledTimes(1);
    expect(connectDb).toHaveBeenCalledWith('mongodb://localhost:27017/vibeshield_test');
    expect(events).toEqual(['db:connect', 'app:create', 'http:listen']);

    await shutdownServer('SIGTERM', { disconnectDb, logger });
    expect(server.listening).toBe(false);
    expect(disconnectDb).toHaveBeenCalledTimes(1);
  });

  it('does not start HTTP server when MongoDB connection fails', async () => {
    const logger = createMockLogger();
    const exitSpy = vi.fn();
    const createAppSpy = vi.fn(createApp);
    const port = await getFreePort();

    const secretUri = 'mongodb://apiuser:verySecretPass@db.internal:27017/vibeshield';
    const connectDb = vi.fn(async () => {
      throw new Error(`Connection timed out for ${secretUri}`);
    });
    const disconnectDb = vi.fn(async () => undefined);

    const server = await bootstrapServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(port),
        HOST: '127.0.0.1',
        MONGODB_URI: secretUri,
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      },
      connectDb,
      disconnectDb,
      createAppFn: createAppSpy,
      logger,
      exit: exitSpy,
    });

    expect(server).toBeUndefined();
    expect(connectDb).toHaveBeenCalledTimes(1);
    expect(createAppSpy).not.toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);

    const errorLogs = logger.error.mock.calls.map((c) => String(c[0])).join('\n');
    expect(errorLogs).not.toContain('verySecretPass');
    expect(errorLogs).not.toContain('apiuser');
    expect(errorLogs).toContain('[REDACTED_MONGODB_URI]');
  });

  it('prevents startup when environment configuration is invalid', async () => {
    const logger = createMockLogger();
    const exitSpy = vi.fn();
    const connectDb = vi.fn(async () => undefined);
    const createAppSpy = vi.fn(createApp);

    const server = await bootstrapServer({
      envSource: {
        NODE_ENV: 'test',
        MONGODB_URI: 'invalid-uri-with-secret-token',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      },
      connectDb,
      disconnectDb: vi.fn(async () => undefined),
      createAppFn: createAppSpy,
      logger,
      exit: exitSpy,
    });

    expect(server).toBeUndefined();
    expect(connectDb).not.toHaveBeenCalled();
    expect(createAppSpy).not.toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);

    const errorLogs = logger.error.mock.calls.map((c) => String(c[0])).join('\n');
    expect(errorLogs).not.toContain('invalid-uri-with-secret-token');
  });

  it('closes HTTP server and disconnects MongoDB during shutdown, deduplicating concurrent calls', async () => {
    const logger = createMockLogger();
    const disconnectDb = vi.fn(async () => undefined);
    const port = await getFreePort();

    const server = await startServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(port),
        HOST: '127.0.0.1',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_test',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      },
      connectDb: vi.fn(async () => undefined),
      disconnectDb,
      logger,
    });

    expect(server.listening).toBe(true);

    const p1 = shutdownServer('SIGINT', { disconnectDb, logger });
    const p2 = shutdownServer('SIGTERM', { disconnectDb, logger });

    await Promise.all([p1, p2]);

    expect(server.listening).toBe(false);
    expect(disconnectDb).toHaveBeenCalledTimes(1);
  });

  it('forces hanging connections closed after shutdown timeout and still disconnects MongoDB', async () => {
    const logger = createMockLogger();
    const disconnectDb = vi.fn(async () => undefined);
    const port = await getFreePort();
    let markRequestInFlight!: () => void;
    const requestInFlight = new Promise<void>((resolve) => {
      markRequestInFlight = resolve;
    });

    const server = await startServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(port),
        HOST: '127.0.0.1',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_test',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      },
      connectDb: vi.fn(async () => undefined),
      disconnectDb,
      createAppFn: () => {
        const app = express();
        // Intentionally never end response so an active in-flight request blocks graceful close
        app.get('/slow', (_req, _res) => {
          markRequestInFlight();
        });
        return app;
      },
      logger,
    });

    const address = server.address() as AddressInfo;
    const req = http.get(`http://127.0.0.1:${address.port}/slow`);
    req.on('error', () => {
      // Expected when socket is force-closed after shutdown timeout
    });

    await requestInFlight;

    await shutdownServer('SIGTERM', {
      disconnectDb,
      logger,
      shutdownTimeoutMs: 50,
    });

    req.destroy();

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Graceful HTTP shutdown timed out')
    );
    expect(disconnectDb).toHaveBeenCalledTimes(1);
    expect(server.listening).toBe(false);
  });

  it('initializes optional queue on startup when QUEUE_ENABLED=true, disconnects on shutdown, and fails closed when REDIS_REQUIRED=true', async () => {
    const events: string[] = [];
    const logger = createMockLogger();
    const port = await getFreePort();
    const connectDb = vi.fn(async () => {
      events.push('db:connect');
    });
    const disconnectDb = vi.fn(async () => {
      events.push('db:disconnect');
    });
    const connectQueue = vi.fn(async () => {
      events.push('queue:connect');
    });
    const disconnectQueue = vi.fn(async () => {
      events.push('queue:disconnect');
    });

    const server = await startServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(port),
        HOST: '127.0.0.1',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_test',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        QUEUE_ENABLED: 'true',
        REDIS_URL: 'redis://:secretPass@127.0.0.1:6379/0',
      },
      connectDb,
      disconnectDb,
      connectQueue,
      disconnectQueue,
      getQueueStatus: () => ({
        enabled: true,
        state: 'connected',
        isConnected: true,
        required: false,
      }),
      logger,
    });

    expect(events).toEqual(['db:connect', 'queue:connect']);
    expect(server.listening).toBe(true);

    await shutdownServer('SIGTERM', { disconnectDb, disconnectQueue, logger });
    expect(events).toEqual(['db:connect', 'queue:connect', 'queue:disconnect', 'db:disconnect']);

    // Required Redis outage fails startup and cleans up MongoDB without leaking credentials
    const exitSpy = vi.fn();
    const failingLogger = createMockLogger();
    const dbDisconnectSpy = vi.fn(async () => undefined);
    const failedBoot = await bootstrapServer({
      envSource: {
        NODE_ENV: 'test',
        PORT: String(await getFreePort()),
        HOST: '127.0.0.1',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_test',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        QUEUE_ENABLED: 'true',
        REDIS_REQUIRED: 'true',
        REDIS_URL: 'redis://:SuperSecretRedisPW@127.0.0.1:6379/0',
      },
      connectDb: vi.fn(async () => undefined),
      disconnectDb: dbDisconnectSpy,
      connectQueue: vi.fn(async () => {
        throw new Error('ECONNREFUSED redis://:SuperSecretRedisPW@127.0.0.1:6379/0');
      }),
      disconnectQueue: vi.fn(async () => undefined),
      logger: failingLogger,
      exit: exitSpy,
    });

    expect(failedBoot).toBeUndefined();
    expect(dbDisconnectSpy).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(failingLogger.error.mock.calls.map((c) => String(c[0])).join('\n')).not.toContain(
      'SuperSecretRedisPW'
    );
  });
});
