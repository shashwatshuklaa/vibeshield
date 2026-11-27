# `@vibeshield/security-worker`

Standalone, independently executable security worker runtime for VibeShield (`workers/security-worker`).

This workspace runs separately from `apps/api`, imports no Express/HTTP server code, connects explicitly to both MongoDB (`@vibeshield/database`) and BullMQ/Redis (`@vibeshield/queue`), and establishes the scan persistence, lease fencing, and worker lifecycle boundaries ahead of repository acquisition and scanner execution.

## Architecture & Safety Guarantees

- **Role-Separated Redis & Explicit MongoDB Startup**:
  - Connects to MongoDB via `DatabaseConnectionManager` (`MONGODB_URI`) **only during explicit `start()`** — never at module import.
  - Initializes BullMQ `Worker` (`maxRetriesPerRequest: null`, `enableOfflineQueue: true`) only after MongoDB connects; worker does not report ready (`isReady()`) unless **both** MongoDB and BullMQ/Redis are connected.
  - Partial startup failures automatically clean up already-opened MongoDB or worker sockets.
- **Explicit Processor Registration Boundary**:
  - Callers must explicitly provide a `SecurityScanJobProcessor` or invoke `registerSecurityScanProcessor()` before `start()`.
  - Refuses to boot (`NO_PROCESSOR_REGISTERED`) when no processor is registered so queued jobs are never silently dropped.
- **Persistent Scan Lifecycle, Fencing & Cancellation** (`@vibeshield/database`):
  - **Three Separate Lifecycles**: Persistent scan state (`QUEUED` -> `ACQUIRING` -> `IN_PROGRESS` -> `COMPLETED` / `FAILED` / `CANCELLED`), BullMQ dispatch status (`ScanStatus`), and worker host state (`WorkerLifecycleState`).
  - **Fenced Leases & Recovery**: `claimQueuedScanForAcquisition()` atomically transitions `QUEUED` -> `ACQUIRING`, mints an opaque random `lease.token` (hidden via `select: false` + serialization stripping), and sets `lease.expiresAt`. After crash/timeout (`expiresAt <= now`), `reclaimExpiredScanLease()` rotates `lease.token` and increments `attemptCount` (up to `maxAttempts`, then fails with `LEASE_EXPIRED`). Any prior stalled worker holding an older `lease.token` is atomically rejected (`STALE_OR_CONFLICT`).
  - **Cancellation Semantics**: Cancelling a `QUEUED` scan transitions it directly to `CANCELLED`; cancelling an `ACQUIRING` or `IN_PROGRESS` scan stamps `cancellation.requestedAt`, blocks advancement to `IN_PROGRESS`, and lets the fenced worker finalize `CANCELLED`.
- **Credential-Safe Logging & Secret Isolation**:
  - Intentionally excludes GitHub App private keys (`GITHUB_APP_PRIVATE_KEY`), OAuth secrets, and webhook secrets, and will never receive raw GitHub installation tokens.
  - Scrubs MongoDB URIs, Redis URLs, and inline credentials from all logs and thrown errors.
- **Trust Boundaries & Future Hardening**:
  - In this phase, `@vibeshield/security-worker` acts as a **trusted control-plane orchestrator** connecting directly to MongoDB and Redis to claim/renew/complete scan leases. Future hardening will narrow or replace direct worker database access with narrowly scoped DB roles or API-mediated state RPCs.
  - Repository acquisition streams compressed repository archives directly from `POST /internal/v1/scans/acquire` on the API's dedicated private/loopback listener (`INTERNAL_WORKER_AUTH_SECRET`, upgradeable to mTLS/workload identity in production), while actual static analyzers (`Semgrep`, `Gitleaks`, `Trivy`) and tar extraction will execute later inside restricted, networkless non-root scanner sandboxes holding zero DB, Redis, or GitHub credentials.
- **Deterministic Idempotent Shutdown**:
  - `SIGINT` / `SIGTERM` and concurrent `stop()` calls deduplicate cleanly, closing BullMQ worker first within `WORKER_SHUTDOWN_GRACE_MS` (falling back to force-close on expiry) and then disconnecting MongoDB.

## Environment Variables

| Variable | Required | Default | Bounds / Notes |
| --- | --- | --- | --- |
| `MONGODB_URI` | Yes | — | Valid `mongodb://` or `mongodb+srv://` URI |
| `MONGODB_CONNECT_TIMEOUT_MS` | No | `10000` | `100..60000` ms |
| `REDIS_URL` | Yes | — | Valid `redis://` or `rediss://` URL |
| `REDIS_CONNECT_TIMEOUT_MS` | No | `5000` | `100..60000` ms |
| `REDIS_MAX_RECONNECT_ATTEMPTS` | No | `10` | `0..100` attempts |
| `WORKER_CONCURRENCY` | No | `2` | `1..50` concurrent jobs |
| `WORKER_LOCK_DURATION` | No | `30000` | `5000..600000` ms |
| `WORKER_STALLED_INTERVAL` | No | `30000` | `5000..600000` ms |
| `WORKER_MAX_STALLED_COUNT` | No | `2` | `0..10` recoveries |
| `WORKER_MAX_STARTED_ATTEMPTS` | No | `5` | `1..20` starts |
| `WORKER_LEASE_DURATION_MS` | No | `60000` | `5000..600000` ms |
| `WORKER_SHUTDOWN_GRACE_MS` | No | `10000` | `500..120000` ms |
| `QUEUE_PREFIX` | No | `vibeshield` | Lowercase/digits/`._-`, no colons |
| `NODE_ENV` | No | `development` | `development \| production \| test` |
| `LOG_LEVEL` | No | `info` | `error \| warn \| info \| http \| verbose \| debug \| silly \| silent` |

## Commands

```bash
# Build & typecheck
pnpm --filter @vibeshield/security-worker build
pnpm --filter @vibeshield/security-worker typecheck

# Unit tests (no Docker required)
pnpm --filter @vibeshield/security-worker test

# Real Docker MongoDB replica-set integration tests (from repo root)
pnpm run test:integration

# Real Docker Redis integration tests (from repo root)
pnpm run test:integration:redis
```

## Scope Note

Task 1.7.3.1 establishes the persistent `ScanModel`, atomic worker lease/fencing operations, and worker MongoDB connectivity. GitHub credential brokering, repository tarball downloading, defensive archive extraction, security scanner containers (`Semgrep`, `Gitleaks`, `Trivy`), webhook scan triggers, and AI remediation remain intentionally unimplemented for upcoming tasks.
