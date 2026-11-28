# `@vibeshield/queue`

Shared Redis connection lifecycle management, BullMQ queue factories, job contracts, and bounded retry/retention defaults for VibeShield asynchronous background processing.

## Why Redis and BullMQ

- **Redis** provides fast, atomic in-memory data structures and pub/sub state coordination needed for distributed background queues across API producers and worker processes.
- **BullMQ** builds reliable job state machines (`waiting`, `active`, `delayed`, `completed`, `failed`), atomic locking/stalled-job recovery, deterministic `jobId` deduplication, priority scheduling, and exponential retry backoff on top of Redis.

## Responsibilities

- **Redis Configuration & Redaction** (`redaction.ts`, `redis.ts`): Validates `redis://` and `rediss://` URLs, enables strict TLS (`rejectUnauthorized: true`) when using `rediss://` without silently downgrading to insecure TCP, and redacts credentials and secrets from logs and thrown errors.
- **Role-Separated Connections**:
  - `queue` role (API producers): bounded `maxRetriesPerRequest` (default `3`), `enableOfflineQueue: false` for fast failure, optional `commandTimeoutMs`.
  - `worker` role (`getWorkerConnectionOptions()`): `maxRetriesPerRequest: null` and no short `commandTimeout` so BullMQ blocking commands never time out prematurely or conflict with API connections.
- **Explicit Lifecycle (`RedisConnectionManager`)**: Never connects upon module import; deduplicates concurrent `connect()` calls, supports `ping()`/`getStatus()` health inspection, and closes owned queue handles before quitting Redis via `closeQueueResources()`.
- **Queue & Worker Factories & Job Contracts** (`contracts.ts`, `factory.ts`):
  - Stable, colon-free queue names (`QUEUE_NAMES.SCAN_JOBS = 'vibeshield-v1-scan-jobs'`, prefix `vibeshield`).
  - Strictly minimal `ScanQueueJobPayload` contract (`{ scanId: string }`) with strict Zod & security runtime validation (`validateScanQueueJobPayload`) rejecting unknown fields, invalid ObjectIds, tokens, private keys, connection URIs, raw archives, or payloads > 16 KB.
  - Deterministic `buildScanJobId()` helpers (`scan-<scanId>-<dispatchGeneration>`, colon-free).
  - Bounded default retry/backoff (`attempts: 3`, `1000ms` exponential backoff) and bounded retention (`removeOnComplete`: 24h / 1000 count, `removeOnFail`: 7d / 2000 count).
  - BullMQ Worker factory (`createBullWorker`, `createScanJobsWorker`, `buildWorkerPolicyOptions`, `closeWorkerWithGrace`) enforcing explicit processor injection, `Worker`-role Redis options (`maxRetriesPerRequest: null`), bounded concurrency/lock/stalled recovery defaults (`DEFAULT_WORKER_POLICY`), and deterministic grace-bounded shutdown.
  - Re-exports `UnrecoverableError`, `Job`, and `Processor` from `bullmq` so downstream workers can classify permanent vs transient failures consistently.
- **Internal Auth Replay Protection (`consumeInternalAuthNonce`, `buildInternalAuthNonceKey`)**:
  - Atomically records single-use internal service authentication nonces via `SET <prefix>:internal-auth-nonce:<service>:<nonce> 1 PX <ttlMs> NX`.
  - Fails closed (`InternalAuthReplayProtectionError`) whenever Redis is disconnected, unavailable, or errors so internal API replay checks never silently pass without Redis backing.

## Environment Variables & Local Setup

Start a local Redis instance (example using Docker):

```bash
docker run -d --name vibeshield-redis -p 6379:6379 redis:7-alpine
```

Configure in `.env` when enabling queue functionality:

```dotenv
QUEUE_ENABLED=true
REDIS_REQUIRED=false
REDIS_URL=redis://localhost:6379
REDIS_CONNECT_TIMEOUT_MS=5000
QUEUE_DEFAULT_ATTEMPTS=3
QUEUE_BACKOFF_DELAY_MS=1000
```

When `QUEUE_ENABLED=false` (the default), the API starts without Redis and unrelated features remain unaffected.

## Testing

- **Unit & API tests** (no Docker or Redis required): `pnpm test`
- **Real Redis & BullMQ integration tests** (ephemeral Docker Redis container): `pnpm run test:integration:redis`

## Worker Integration

Dedicated background workers under `workers/*` (starting with `@vibeshield/security-worker`) instantiate BullMQ `Worker` instances via `createScanJobsWorker()` using `Worker`-role Redis connections (`maxRetriesPerRequest: null`), explicit processor registration, and credential-redacted lifecycle logging without importing Express or `apps/api`.
