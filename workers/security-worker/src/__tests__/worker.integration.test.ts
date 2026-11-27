import { EventEmitter } from 'node:events';
import { afterAll, describe, expect, it } from 'vitest';
import { DatabaseConnectionManager } from '@vibeshield/database';
import { QUEUE_NAMES, type ManagedWorkerHandle } from '@vibeshield/queue';
import { createSecurityWorkerRuntime, loadWorkerConfig } from '../index.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

class MockWorkerHandle extends EventEmitter {
  public running = true;
  public readyError: Error | null = null;
  public closeCalls: boolean[] = [];

  async waitUntilReady(): Promise<void> {
    if (this.readyError) {
      throw this.readyError;
    }
    this.emit('ready');
  }

  isRunning(): boolean {
    return this.running;
  }

  async close(force = false): Promise<void> {
    this.closeCalls.push(force);
    this.running = false;
    this.emit('closed');
  }
}

describe.skipIf(!REPLICA_URI)(
  '@vibeshield/security-worker Real MongoDB Lifecycle Integration Tests',
  () => {
    const activeManagers: DatabaseConnectionManager[] = [];

    afterAll(async () => {
      for (const mgr of activeManagers.splice(0)) {
        await mgr.disconnect().catch(() => undefined);
      }
    });

    it('connects real MongoDB before becoming ready and disconnects cleanly on stop()', async () => {
      const dbManager = new DatabaseConnectionManager({ logger: {} });
      activeManagers.push(dbManager);

      const mockWorker = new MockWorkerHandle();
      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: REPLICA_URI!,
        REDIS_URL: 'redis://localhost:6379/0',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        processor: async () => undefined,
        databaseManager: dbManager,
        workerFactory: (_proc, opts) => {
          // MongoDB must already be connected BEFORE BullMQ worker factory runs
          expect(dbManager.isConnected()).toBe(true);
          return {
            name: QUEUE_NAMES.SCAN_JOBS,
            worker: mockWorker as unknown as ManagedWorkerHandle['worker'],
            concurrency: opts.concurrency ?? 2,
            close: (force?: boolean) => mockWorker.close(force),
          };
        },
      });

      expect(dbManager.isConnected()).toBe(false);
      await runtime.start();

      expect(runtime.isReady()).toBe(true);
      expect(runtime.getStatus().database).toEqual({
        state: 'connected',
        isConnected: true,
      });

      const stopOutcome = await runtime.stop();
      expect(stopOutcome).toEqual({ timedOut: false });
      expect(runtime.isReady()).toBe(false);
      expect(dbManager.isConnected()).toBe(false);
      expect(runtime.getStatus().database.state).toBe('disconnected');
    });

    it('rolls back real MongoDB connection if Redis/BullMQ worker initialization fails', async () => {
      const dbManager = new DatabaseConnectionManager({ logger: {} });
      activeManagers.push(dbManager);

      const failingWorker = new MockWorkerHandle();
      failingWorker.readyError = new Error('Redis connection failed after Mongo connected');

      const config = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: REPLICA_URI!,
        REDIS_URL: 'redis://default:SuperSecretRedis99!@localhost:6379/0',
      });

      const runtime = createSecurityWorkerRuntime({
        config,
        processor: async () => undefined,
        databaseManager: dbManager,
        workerFactory: (_proc, opts) => ({
          name: QUEUE_NAMES.SCAN_JOBS,
          worker: failingWorker as unknown as ManagedWorkerHandle['worker'],
          concurrency: opts.concurrency ?? 2,
          close: (force?: boolean) => failingWorker.close(force),
        }),
      });

      await expect(runtime.start()).rejects.toMatchObject({
        code: 'WORKER_STARTUP_FAILED',
      });
      expect(dbManager.isConnected()).toBe(false);
      expect(failingWorker.closeCalls).toEqual([true]);
      expect(runtime.isReady()).toBe(false);
    });
  }
);
