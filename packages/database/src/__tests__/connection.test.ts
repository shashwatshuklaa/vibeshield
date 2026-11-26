import { describe, expect, it, vi } from 'vitest';
import {
  DatabaseConnectionError,
  DatabaseConnectionManager,
  DEFAULT_CONNECT_OPTIONS,
  formatSafeError,
  isValidMongoUri,
  mapReadyStateToConnectionState,
  redactMongoUri,
  runInTransaction,
  type DatabaseLogger,
  type MongooseClientLike,
  type TransactionClientLike,
} from '../index.js';

interface MockConnection extends Record<string, unknown> {
  readyState: number;
  on: (event: string, listener: (...args: unknown[]) => void) => void;
  emit: (event: string, ...args: unknown[]) => void;
}

function createMockClient(initialReadyState = 0): {
  client: MongooseClientLike;
  connection: MockConnection;
  connectSpy: ReturnType<typeof vi.fn>;
  disconnectSpy: ReturnType<typeof vi.fn>;
} {
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();

  const connection: MockConnection = {
    readyState: initialReadyState,
    on: (event: string, listener: (...args: unknown[]) => void) => {
      const existing = listeners.get(event) ?? [];
      existing.push(listener);
      listeners.set(event, existing);
    },
    emit: (event: string, ...args: unknown[]) => {
      const registered = listeners.get(event) ?? [];
      for (const listener of registered) {
        listener(...args);
      }
    },
  };

  const connectSpy = vi.fn(async () => {
    connection.readyState = 1;
    connection.emit('connected');
    return {};
  });

  const disconnectSpy = vi.fn(async () => {
    connection.readyState = 0;
    connection.emit('disconnected');
  });

  const client: MongooseClientLike = {
    connect: connectSpy,
    disconnect: disconnectSpy,
    connection,
  };

  return { client, connection, connectSpy, disconnectSpy };
}

function createMockLogger(): Required<DatabaseLogger> {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

describe('@vibeshield/database', () => {
  describe('no automatic connection on import', () => {
    it('does not connect when imported or instantiated', async () => {
      const dbModule = await import('../index.js');

      expect(dbModule.getDatabaseState()).toBe('disconnected');
      expect(dbModule.isDatabaseConnected()).toBe(false);
      expect(dbModule.getDatabaseStatus()).toEqual({
        state: 'disconnected',
        readyState: 0,
        isConnected: false,
      });
    });
  });

  describe('URI validation and redaction', () => {
    it('accepts valid mongodb:// and mongodb+srv:// URIs', () => {
      expect(isValidMongoUri('mongodb://localhost:27017/vibeshield_dev')).toBe(true);
      expect(
        isValidMongoUri('mongodb://user:pass@localhost:27017/vibeshield?authSource=admin')
      ).toBe(true);
      expect(
        isValidMongoUri('mongodb+srv://app_user:secret123@cluster0.example.mongodb.net/vibeshield')
      ).toBe(true);
      expect(isValidMongoUri('mongodb://host1:27017,host2:27017/vibeshield?replicaSet=rs0')).toBe(
        true
      );
    });

    it('rejects invalid MongoDB URIs', () => {
      expect(isValidMongoUri('')).toBe(false);
      expect(isValidMongoUri('http://localhost:27017')).toBe(false);
      expect(isValidMongoUri('postgres://user:pass@localhost:5432/db')).toBe(false);
      expect(isValidMongoUri('mongodb://')).toBe(false);
      expect(isValidMongoUri('mongodb:///vibeshield')).toBe(false);
      expect(isValidMongoUri('mongodb://@localhost:27017/vibeshield')).toBe(false);
      expect(isValidMongoUri('mongodb://localhost:27017/vibeshield with-space')).toBe(false);
      expect(isValidMongoUri('mongodb://:27017/vibeshield')).toBe(false);
    });

    it('redacts MongoDB URIs and credentials from strings and errors', () => {
      const secretUri = 'mongodb+srv://admin:superSecretPass@cluster0.mongodb.net/prod';
      const redacted = redactMongoUri(`Connection failed for ${secretUri} due to auth error`);

      expect(redacted).not.toContain('superSecretPass');
      expect(redacted).not.toContain('admin');
      expect(redacted).not.toContain('cluster0.mongodb.net');
      expect(redacted).toContain('[REDACTED_MONGODB_URI]');

      const safe = formatSafeError(new Error(`Unable to reach ${secretUri}`));
      expect(safe).not.toContain('superSecretPass');
      expect(safe).toContain('[REDACTED_MONGODB_URI]');
    });
  });

  describe('connection state mapping', () => {
    it('maps Mongoose readyState values to normalized connection states', () => {
      expect(mapReadyStateToConnectionState(0)).toBe('disconnected');
      expect(mapReadyStateToConnectionState(1)).toBe('connected');
      expect(mapReadyStateToConnectionState(2)).toBe('connecting');
      expect(mapReadyStateToConnectionState(3)).toBe('disconnecting');
      expect(mapReadyStateToConnectionState(99)).toBe('disconnected');
    });

    it('reports connection status accurately from client readyState', () => {
      const { client, connection } = createMockClient(0);
      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });

      expect(manager.getStatus()).toEqual({
        state: 'disconnected',
        readyState: 0,
        isConnected: false,
      });

      connection.readyState = 2;
      expect(manager.getState()).toBe('connecting');
      expect(manager.isConnected()).toBe(false);

      connection.readyState = 1;
      expect(manager.getStatus()).toEqual({
        state: 'connected',
        readyState: 1,
        isConnected: true,
      });

      connection.readyState = 3;
      expect(manager.getState()).toBe('disconnecting');
      expect(manager.isConnected()).toBe(false);
    });
  });

  describe('connect lifecycle', () => {
    it('connects cleanly with default options and updates state', async () => {
      const { client, connectSpy } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });
      const uri = 'mongodb://localhost:27017/vibeshield_test';

      await manager.connect(uri);

      expect(connectSpy).toHaveBeenCalledTimes(1);
      expect(connectSpy).toHaveBeenCalledWith(uri, DEFAULT_CONNECT_OPTIONS);
      expect(manager.isConnected()).toBe(true);
      expect(manager.getState()).toBe('connected');
      expect(logger.info).toHaveBeenCalledWith('[database] MongoDB connection established.');
    });

    it('merges custom connection options with defaults', async () => {
      const { client, connectSpy } = createMockClient();
      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });

      await manager.connect('mongodb://localhost:27017/vibeshield_test', {
        serverSelectionTimeoutMS: 2500,
        maxPoolSize: 25,
        dbName: 'custom_db',
      });

      expect(connectSpy).toHaveBeenCalledWith('mongodb://localhost:27017/vibeshield_test', {
        ...DEFAULT_CONNECT_OPTIONS,
        serverSelectionTimeoutMS: 2500,
        maxPoolSize: 25,
        dbName: 'custom_db',
      });
    });

    it('throws DatabaseConnectionError for invalid URIs without leaking the input', async () => {
      const { client, connectSpy } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });
      const badUri = 'http://secretuser:secretpass@bad-host:1234/db';

      await expect(manager.connect(badUri)).rejects.toMatchObject({
        name: 'DatabaseConnectionError',
        code: 'INVALID_MONGODB_URI',
      });

      try {
        await manager.connect(badUri);
      } catch (error) {
        const err = error as DatabaseConnectionError;
        expect(err.message).not.toContain('secretuser');
        expect(err.message).not.toContain('secretpass');
        expect(err.message).not.toContain('bad-host');
      }

      expect(connectSpy).not.toHaveBeenCalled();
    });

    it('handles connection failures predictably and redacts credentials', async () => {
      const { client, connectSpy } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });
      const uri = 'mongodb://dbuser:topSecret123@db.internal:27017/vibeshield';

      connectSpy.mockRejectedValueOnce(new Error(`ECONNREFUSED ${uri}`));

      let caughtError: unknown;
      try {
        await manager.connect(uri);
      } catch (error) {
        caughtError = error;
      }

      expect(caughtError).toBeInstanceOf(DatabaseConnectionError);
      const err = caughtError as DatabaseConnectionError;
      expect(err.code).toBe('CONNECTION_FAILED');
      expect(err.message).not.toContain('topSecret123');
      expect(err.message).not.toContain('dbuser');
      expect(err.message).toContain('[REDACTED_MONGODB_URI]');
      expect(manager.isConnected()).toBe(false);

      const errorLogs = logger.error.mock.calls.map((call) => String(call[0])).join('\n');
      expect(errorLogs).not.toContain('topSecret123');
      expect(errorLogs).not.toContain('dbuser');
    });

    it('avoids duplicate connections when already connected or concurrently connecting with same URI', async () => {
      let resolveConnect!: () => void;
      const { client, connection, connectSpy } = createMockClient();
      connectSpy.mockImplementation(
        () =>
          new Promise((resolve) => {
            connection.readyState = 2;
            resolveConnect = () => {
              connection.readyState = 1;
              resolve({});
            };
          })
      );

      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });
      const uri = 'mongodb://localhost:27017/vibeshield_test';

      const firstPromise = manager.connect(uri);
      const secondPromise = manager.connect(uri);

      expect(connectSpy).toHaveBeenCalledTimes(1);
      resolveConnect();
      await Promise.all([firstPromise, secondPromise]);

      // Subsequent connect call while connected should be a no-op
      await manager.connect(uri);
      expect(connectSpy).toHaveBeenCalledTimes(1);
    });

    it('rejects connecting to a different URI while already connected or connecting', async () => {
      const { client } = createMockClient();
      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });

      await manager.connect('mongodb://localhost:27017/db_one');

      await expect(manager.connect('mongodb://localhost:27017/db_two')).rejects.toMatchObject({
        name: 'DatabaseConnectionError',
        code: 'ALREADY_CONNECTED',
      });
    });
  });

  describe('disconnect lifecycle', () => {
    it('disconnects cleanly and updates state to disconnected', async () => {
      const { client, disconnectSpy } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });

      await manager.connect('mongodb://localhost:27017/vibeshield_test');
      expect(manager.isConnected()).toBe(true);

      await manager.disconnect();
      expect(disconnectSpy).toHaveBeenCalledTimes(1);
      expect(manager.isConnected()).toBe(false);
      expect(manager.getState()).toBe('disconnected');
      expect(logger.info).toHaveBeenCalledWith('[database] MongoDB disconnected cleanly.');
    });

    it('is idempotent when already disconnected', async () => {
      const { client, disconnectSpy } = createMockClient(0);
      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });

      await manager.disconnect();
      expect(disconnectSpy).not.toHaveBeenCalled();
    });

    it('deduplicates concurrent disconnect calls', async () => {
      let resolveDisconnect!: () => void;
      const { client, connection, disconnectSpy } = createMockClient();
      const manager = new DatabaseConnectionManager({ client, logger: createMockLogger() });

      await manager.connect('mongodb://localhost:27017/vibeshield_test');

      disconnectSpy.mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            connection.readyState = 3;
            resolveDisconnect = () => {
              connection.readyState = 0;
              resolve();
            };
          })
      );

      const p1 = manager.disconnect();
      const p2 = manager.disconnect();

      expect(disconnectSpy).toHaveBeenCalledTimes(1);
      resolveDisconnect();
      await Promise.all([p1, p2]);
      expect(manager.getState()).toBe('disconnected');
    });

    it('sanitizes errors thrown during disconnection', async () => {
      const { client, disconnectSpy } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });

      await manager.connect('mongodb://user:secret@localhost:27017/vibeshield_test');
      disconnectSpy.mockRejectedValueOnce(
        new Error('Failed closing mongodb://user:secret@localhost:27017/vibeshield_test')
      );

      await expect(manager.disconnect()).rejects.toMatchObject({
        name: 'DatabaseConnectionError',
        code: 'DISCONNECTION_FAILED',
      });

      const logged = logger.error.mock.calls.map((c) => String(c[0])).join('\n');
      expect(logged).not.toContain('secret');
      expect(logged).toContain('[REDACTED_MONGODB_URI]');
    });

    it('logs sanitized connection runtime events without exposing credentials', async () => {
      const { client, connection } = createMockClient();
      const logger = createMockLogger();
      const manager = new DatabaseConnectionManager({ client, logger });

      await manager.connect('mongodb://user:secret@localhost:27017/vibeshield_test');

      connection.emit(
        'error',
        new Error('Socket error on mongodb://user:secret@localhost:27017/vibeshield_test')
      );
      connection.emit('reconnected');
      connection.emit('disconnected');

      const errorLogs = logger.error.mock.calls.map((c) => String(c[0])).join('\n');
      expect(errorLogs).not.toContain('secret');
      expect(errorLogs).toContain('[REDACTED_MONGODB_URI]');
      expect(logger.info).toHaveBeenCalledWith('[database] MongoDB connection re-established.');
      expect(logger.warn).toHaveBeenCalledWith(
        '[database] MongoDB connection lost or disconnected.'
      );
    });
  });

  describe('runInTransaction', () => {
    it('executes work inside session.withTransaction and always ends the session', async () => {
      const endSession = vi.fn(async () => undefined);
      const withTransaction = vi.fn(async (fn: () => Promise<unknown>) => fn());
      const mockClient: TransactionClientLike = {
        startSession: vi.fn(async () => ({ withTransaction, endSession })),
      };

      const outcome = await runInTransaction(
        async (session) => {
          expect(session).toBeDefined();
          return 'committed';
        },
        { client: mockClient }
      );

      expect(outcome).toBe('committed');
      expect(withTransaction).toHaveBeenCalledTimes(1);
      expect(endSession).toHaveBeenCalledTimes(1);
    });

    it('ends the session and propagates errors without non-transactional fallback', async () => {
      const endSession = vi.fn(async () => undefined);
      const withTransaction = vi.fn(async (fn: () => Promise<unknown>) => fn());
      const mockClient: TransactionClientLike = {
        startSession: vi.fn(async () => ({ withTransaction, endSession })),
      };

      await expect(
        runInTransaction(
          async () => {
            throw new Error('TransactionNumbers are only allowed on a replica set member');
          },
          { client: mockClient }
        )
      ).rejects.toThrow('TransactionNumbers are only allowed on a replica set member');

      expect(endSession).toHaveBeenCalledTimes(1);
    });
  });
});
