# `@vibeshield/database`

Shared MongoDB connectivity and connection lifecycle package for VibeShield Node.js services, built on Mongoose and TypeScript.

## Responsibilities

- Establish and manage MongoDB connections via Mongoose (`connectDatabase`, `DatabaseConnectionManager`).
- Expose normalized connection state and readiness status (`getDatabaseState`, `isDatabaseConnected`, `getDatabaseStatus`).
- Deduplicate concurrent or repeated connection and disconnection calls.
- Support graceful shutdown without hanging processes.
- Validate MongoDB connection URI syntax (`isValidMongoUri`).
- Redact MongoDB URIs and credentials from logs and error messages (`redactMongoUri`, `formatSafeError`).

> [!NOTE]
> Importing `@vibeshield/database` never automatically initiates a database connection. Connections are established only when the host application explicitly invokes `connectDatabase()` or `manager.connect()`.

## Non-Responsibilities

This package deliberately excludes:
- Application-specific Mongoose schemas or models.
- Express or HTTP framework dependencies.
- Application environment loading (callers pass the connection URI explicitly).

## Usage

```ts
import {
  connectDatabase,
  disconnectDatabase,
  getDatabaseStatus,
} from '@vibeshield/database';

await connectDatabase(process.env.MONGODB_URI!);

const status = getDatabaseStatus();
// { state: 'connected', readyState: 1, isConnected: true }

await disconnectDatabase();
```

### Dependency Injection & Testing

`DatabaseConnectionManager` accepts an optional Mongoose-compatible client and logger so unit tests can exercise connection lifecycles without requiring a running MongoDB server:

```ts
import { DatabaseConnectionManager } from '@vibeshield/database';

const manager = new DatabaseConnectionManager({
  client: mockMongooseClient,
  logger: mockLogger,
});
```

## Default Connection Options

- `serverSelectionTimeoutMS`: `5000`
- `connectTimeoutMS`: `10000`
- `socketTimeoutMS`: `45000`
- `maxPoolSize`: `10`

All options use Mongoose's modern connection API without deprecated driver flags.

## Running Tests & Checks

```bash
pnpm --filter @vibeshield/database test
pnpm --filter @vibeshield/database typecheck
pnpm --filter @vibeshield/database build
```
