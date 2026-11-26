import type { ConnectOptions } from 'mongoose';

/**
 * Normalized MongoDB connection states exposed by @vibeshield/database.
 */
export type DatabaseConnectionState = 'disconnected' | 'connected' | 'connecting' | 'disconnecting';

/**
 * Snapshot of the current database connection status.
 */
export interface DatabaseConnectionStatus {
  state: DatabaseConnectionState;
  readyState: number;
  isConnected: boolean;
}

/**
 * Supported options for establishing a MongoDB connection.
 * Excludes legacy or deprecated Mongoose/driver options.
 */
export interface DatabaseConnectOptions {
  /** Maximum time (ms) to wait for MongoDB server selection before failing. */
  serverSelectionTimeoutMS?: number;
  /** Maximum time (ms) to wait for the initial TCP socket connection. */
  connectTimeoutMS?: number;
  /** Maximum time (ms) of socket inactivity before timing out. */
  socketTimeoutMS?: number;
  /** Maximum number of connections in the MongoDB connection pool. */
  maxPoolSize?: number;
  /** Minimum number of connections maintained in the MongoDB connection pool. */
  minPoolSize?: number;
  /** Explicit database name overriding the one in the connection URI. */
  dbName?: string;
  /** Whether Mongoose should automatically build indexes defined in schemas. */
  autoIndex?: boolean;
}

/**
 * Optional logger interface for database lifecycle events.
 * Implementations must only receive sanitized, credential-free messages.
 */
export interface DatabaseLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

/**
 * Minimal Mongoose connection interface required for status inspection and lifecycle events.
 */
export interface MongooseConnectionLike {
  readyState: number;
  on?: (event: string, listener: (...args: unknown[]) => void) => unknown;
}

/**
 * Minimal Mongoose client interface enabling dependency injection in tests.
 */
export interface MongooseClientLike {
  connect: (uri: string, options?: ConnectOptions) => Promise<unknown>;
  disconnect: () => Promise<void>;
  connection: MongooseConnectionLike;
}

/**
 * Configuration options for constructing a DatabaseConnectionManager.
 */
export interface DatabaseManagerOptions {
  client?: MongooseClientLike;
  logger?: DatabaseLogger;
}
