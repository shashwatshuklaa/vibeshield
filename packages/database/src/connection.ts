import mongoose, { type ClientSession, type ConnectOptions } from 'mongoose';
import type {
  DatabaseConnectOptions,
  DatabaseConnectionState,
  DatabaseConnectionStatus,
  DatabaseLogger,
  DatabaseManagerOptions,
  MongooseClientLike,
  TransactionClientLike,
  TransactionSessionLike,
} from './types.js';
import { redactGitHubSecrets } from './utils/redaction.js';

/**
 * Sensible default connection timeouts and pooling limits for VibeShield services.
 */
export const DEFAULT_CONNECT_OPTIONS: Readonly<
  Pick<
    DatabaseConnectOptions,
    'serverSelectionTimeoutMS' | 'connectTimeoutMS' | 'socketTimeoutMS' | 'maxPoolSize'
  >
> = Object.freeze({
  serverSelectionTimeoutMS: 5000,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  maxPoolSize: 10,
});

const DEFAULT_LOGGER: Required<DatabaseLogger> = {
  info: (message: string) => console.log(message),
  warn: (message: string) => console.warn(message),
  error: (message: string) => console.error(message),
};

const MONGO_URI_PATTERN = /mongodb(?:\+srv)?:\/\/[^\s'"`]+/gi;
const CREDENTIAL_SEGMENT_PATTERN = /([^\s/:@]+):([^\s/@]+)@/g;

/**
 * Redacts MongoDB URIs and embedded user:password credentials from arbitrary strings
 * so secrets never leak into logs or thrown error messages.
 */
export function redactMongoUri(input: string): string {
  return input
    .replace(MONGO_URI_PATTERN, '[REDACTED_MONGODB_URI]')
    .replace(CREDENTIAL_SEGMENT_PATTERN, '[REDACTED_CREDENTIALS]@');
}

/**
 * Extracts a safe, credential-free message from an unknown error value.
 */
export function formatSafeError(error: unknown): string {
  if (error instanceof Error) {
    return redactGitHubSecrets(redactMongoUri(error.message || error.name));
  }
  if (typeof error === 'string') {
    return redactGitHubSecrets(redactMongoUri(error));
  }
  return 'Unknown database error';
}

/**
 * Validates that a value is a syntactically plausible MongoDB connection URI
 * (`mongodb://` or `mongodb+srv://`) with a non-empty host authority and no whitespace.
 */
export function isValidMongoUri(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length === 0 || /\s/.test(uri)) {
    return false;
  }

  let remainder: string;
  if (uri.startsWith('mongodb+srv://')) {
    remainder = uri.slice('mongodb+srv://'.length);
  } else if (uri.startsWith('mongodb://')) {
    remainder = uri.slice('mongodb://'.length);
  } else {
    return false;
  }

  if (!remainder) {
    return false;
  }

  // Extract the authority section before path (`/`) or query (`?`)
  const authorityEndIndex = remainder.search(/[/?]/);
  const authority = authorityEndIndex === -1 ? remainder : remainder.slice(0, authorityEndIndex);

  if (!authority) {
    return false;
  }

  const atIndex = authority.lastIndexOf('@');
  const hostSection = atIndex === -1 ? authority : authority.slice(atIndex + 1);

  // If credentials separator `@` is present, username must not be empty
  if (atIndex !== -1 && atIndex === 0) {
    return false;
  }

  if (!hostSection) {
    return false;
  }

  // Support single-host and comma-separated replica set hosts
  const hosts = hostSection.split(',');
  return hosts.every((hostEntry) => {
    if (!hostEntry || hostEntry.startsWith(':') || hostEntry.endsWith(':')) {
      return false;
    }
    return true;
  });
}

/**
 * Maps Mongoose numeric readyState values to normalized connection states.
 */
export function mapReadyStateToConnectionState(readyState: number): DatabaseConnectionState {
  switch (readyState) {
    case 1:
      return 'connected';
    case 2:
      return 'connecting';
    case 3:
      return 'disconnecting';
    case 0:
    case 99:
    default:
      return 'disconnected';
  }
}

/**
 * Sanitized error thrown for database connection and disconnection failures.
 */
export class DatabaseConnectionError extends Error {
  public readonly code: string;

  constructor(message: string, code = 'DATABASE_CONNECTION_ERROR', cause?: unknown) {
    super(redactMongoUri(message));
    this.name = 'DatabaseConnectionError';
    this.code = code;

    if (cause instanceof Error) {
      this.cause = new Error(redactMongoUri(cause.message));
    }

    const ErrorWithV8 = Error as unknown as {
      captureStackTrace?: (target: object, constructorOpt?: Function) => void;
    };
    if (typeof ErrorWithV8.captureStackTrace === 'function') {
      ErrorWithV8.captureStackTrace(this, DatabaseConnectionError);
    }
  }
}

/**
 * Manages the MongoDB connection lifecycle cleanly without auto-connecting on import.
 */
export class DatabaseConnectionManager {
  private readonly client: MongooseClientLike;
  private readonly logger: DatabaseLogger;
  private activeUri: string | null = null;
  private connectingPromise: Promise<void> | null = null;
  private disconnectingPromise: Promise<void> | null = null;
  private listenersAttached = false;

  constructor(options: DatabaseManagerOptions = {}) {
    this.client = options.client ?? mongoose;
    this.logger = options.logger ?? DEFAULT_LOGGER;
  }

  /**
   * Returns the normalized connection state (`disconnected`, `connected`, `connecting`, `disconnecting`).
   */
  public getState(): DatabaseConnectionState {
    return mapReadyStateToConnectionState(this.client.connection.readyState);
  }

  /**
   * Returns true only when the underlying Mongoose connection is actively connected (`readyState === 1`).
   */
  public isConnected(): boolean {
    return this.client.connection.readyState === 1;
  }

  /**
   * Returns a complete snapshot of the current database connection status.
   */
  public getStatus(): DatabaseConnectionStatus {
    const readyState = this.client.connection.readyState;
    const state = mapReadyStateToConnectionState(readyState);
    return {
      state,
      readyState,
      isConnected: readyState === 1,
    };
  }

  /**
   * Connects to MongoDB using the provided connection URI and options.
   * Deduplicates concurrent or repeated connection attempts for the same URI.
   */
  public async connect(uri: string, options: DatabaseConnectOptions = {}): Promise<void> {
    if (!isValidMongoUri(uri)) {
      throw new DatabaseConnectionError(
        'Invalid MongoDB connection URI provided.',
        'INVALID_MONGODB_URI'
      );
    }

    if (this.disconnectingPromise) {
      await this.disconnectingPromise;
    }

    if (this.connectingPromise) {
      if (this.activeUri === uri) {
        return this.connectingPromise;
      }
      throw new DatabaseConnectionError(
        'A MongoDB connection attempt to a different target is already in progress.',
        'CONNECTION_IN_PROGRESS'
      );
    }

    if (this.isConnected()) {
      if (this.activeUri === null || this.activeUri === uri) {
        return;
      }
      throw new DatabaseConnectionError(
        'MongoDB is already connected to a different target. Disconnect before reconnecting.',
        'ALREADY_CONNECTED'
      );
    }

    this.attachConnectionListeners();

    const connectOptions = this.buildConnectOptions(options);
    this.activeUri = uri;

    this.connectingPromise = (async () => {
      try {
        await this.client.connect(uri, connectOptions);
        this.logger.info?.('[database] MongoDB connection established.');
      } catch (error) {
        this.activeUri = null;
        const safeMessage = formatSafeError(error);
        this.logger.error?.(`[database] Failed to connect to MongoDB: ${safeMessage}`);
        throw new DatabaseConnectionError(
          `Failed to connect to MongoDB: ${safeMessage}`,
          'CONNECTION_FAILED',
          error
        );
      } finally {
        this.connectingPromise = null;
      }
    })();

    return this.connectingPromise;
  }

  /**
   * Cleanly disconnects from MongoDB. Safe to call multiple times or when already disconnected.
   */
  public async disconnect(): Promise<void> {
    if (this.disconnectingPromise) {
      return this.disconnectingPromise;
    }

    if (this.connectingPromise) {
      await this.connectingPromise.catch(() => undefined);
    }

    if (this.client.connection.readyState === 0 && this.activeUri === null) {
      return;
    }

    this.disconnectingPromise = (async () => {
      try {
        await this.client.disconnect();
        this.logger.info?.('[database] MongoDB disconnected cleanly.');
      } catch (error) {
        const safeMessage = formatSafeError(error);
        this.logger.error?.(`[database] Failed to disconnect from MongoDB: ${safeMessage}`);
        throw new DatabaseConnectionError(
          `Failed to disconnect from MongoDB: ${safeMessage}`,
          'DISCONNECTION_FAILED',
          error
        );
      } finally {
        this.activeUri = null;
        this.disconnectingPromise = null;
      }
    })();

    return this.disconnectingPromise;
  }

  private buildConnectOptions(options: DatabaseConnectOptions): ConnectOptions {
    const merged: DatabaseConnectOptions = {
      ...DEFAULT_CONNECT_OPTIONS,
      ...options,
    };

    const connectOptions: ConnectOptions = {};
    if (merged.serverSelectionTimeoutMS !== undefined) {
      connectOptions.serverSelectionTimeoutMS = merged.serverSelectionTimeoutMS;
    }
    if (merged.connectTimeoutMS !== undefined) {
      connectOptions.connectTimeoutMS = merged.connectTimeoutMS;
    }
    if (merged.socketTimeoutMS !== undefined) {
      connectOptions.socketTimeoutMS = merged.socketTimeoutMS;
    }
    if (merged.maxPoolSize !== undefined) {
      connectOptions.maxPoolSize = merged.maxPoolSize;
    }
    if (merged.minPoolSize !== undefined) {
      connectOptions.minPoolSize = merged.minPoolSize;
    }
    if (merged.dbName !== undefined) {
      connectOptions.dbName = merged.dbName;
    }
    if (merged.autoIndex !== undefined) {
      connectOptions.autoIndex = merged.autoIndex;
    }

    return connectOptions;
  }

  private attachConnectionListeners(): void {
    if (this.listenersAttached || typeof this.client.connection.on !== 'function') {
      return;
    }

    this.listenersAttached = true;

    this.client.connection.on('error', (error: unknown) => {
      this.logger.error?.(`[database] MongoDB connection error: ${formatSafeError(error)}`);
    });

    this.client.connection.on('disconnected', () => {
      this.logger.warn?.('[database] MongoDB connection lost or disconnected.');
    });

    this.client.connection.on('reconnected', () => {
      this.logger.info?.('[database] MongoDB connection re-established.');
    });
  }
}

/**
 * Default shared database connection manager instance.
 * Does not connect automatically on import.
 */
export const databaseManager = new DatabaseConnectionManager();

/**
 * Connects the default database manager to MongoDB.
 */
export function connectDatabase(uri: string, options?: DatabaseConnectOptions): Promise<void> {
  return databaseManager.connect(uri, options);
}

/**
 * Cleanly disconnects the default database manager from MongoDB.
 */
export function disconnectDatabase(): Promise<void> {
  return databaseManager.disconnect();
}

/**
 * Returns the normalized connection state of the default database manager.
 */
export function getDatabaseState(): DatabaseConnectionState {
  return databaseManager.getState();
}

/**
 * Returns whether the default database manager is currently connected.
 */
export function isDatabaseConnected(): boolean {
  return databaseManager.isConnected();
}

/**
 * Returns the full connection status snapshot of the default database manager.
 */
export function getDatabaseStatus(): DatabaseConnectionStatus {
  return databaseManager.getStatus();
}

/**
 * Executes a multi-document database operation inside a MongoDB transaction.
 * Requires a MongoDB replica set or sharded cluster; never falls back to non-transactional writes.
 */
export async function runInTransaction<T>(
  work: (session: ClientSession) => Promise<T>,
  options: { client?: TransactionClientLike } = {}
): Promise<T> {
  const client = options.client ?? (mongoose as unknown as TransactionClientLike);
  const session: TransactionSessionLike = await client.startSession();

  try {
    let result!: T;
    await session.withTransaction(async () => {
      result = await work(session as unknown as ClientSession);
    });
    return result;
  } finally {
    await session.endSession();
  }
}
