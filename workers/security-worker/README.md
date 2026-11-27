# `@vibeshield/security-worker`

Standalone, independently executable security worker runtime for VibeShield (`workers/security-worker`).

This workspace runs separately from `apps/api`, imports no Express/HTTP server code, and establishes the BullMQ worker lifecycle and safety boundaries ahead of future repository scanning and security tool execution phases.

## Architecture & Safety Guarantees

- **Dedicated BullMQ Worker Connections**: Connects directly to Redis via `@vibeshield/queue`'s `'worker'` role (`maxRetriesPerRequest: null`, `enableOfflineQueue: true`, TLS verification preserved for `rediss://`) completely isolated from `apps/api`'s queue producer connections.
- **Explicit Processor Registration Boundary**:
  - Callers must explicitly provide a `SecurityScanJobProcessor` or invoke `registerSecurityScanProcessor()` before `start()` / `bootstrap`.
  - Refuses to boot (`NO_PROCESSOR_REGISTERED`) when no processor is registered so queued jobs are never silently marked complete or dropped.
- **Strict Payload Validation & Retry Classification**:
  - Wraps every executed job with `validateScanQueueJobPayload()` before invoking the registered processor.
  - Malformed, oversized, or secret-bearing payloads (and unsupported job names) throw `UnrecoverableError` so BullMQ moves them directly to `failed` instead of retrying endlessly.
  - Transient processor exceptions propagate untouched so BullMQ retries with exponential backoff (`DEFAULT_QUEUE_POLICY`).
- **Bounded Execution & Deterministic Shutdown**:
  - Enforces bounded defaults for concurrency (`WORKER_CONCURRENCY=2`), lock duration (`WORKER_LOCK_DURATION=30000`), stalled checks (`WORKER_STALLED_INTERVAL=30000`, `WORKER_MAX_STALLED_COUNT=2`), and shutdown grace (`WORKER_SHUTDOWN_GRACE_MS=10000`).
  - Handles `SIGINT` / `SIGTERM` idempotently and falls back to forced `worker.close(true)` if an active job outlives `WORKER_SHUTDOWN_GRACE_MS`.
- **Credential-Safe Logging**: Redacts Redis URLs, passwords, and secrets via `@vibeshield/queue` and never logs full raw `job.data` payloads.

## Environment Variables

| Variable | Required | Default | Bounds / Notes |
| --- | --- | --- | --- |
| `REDIS_URL` | Yes | — | Valid `redis://` or `rediss://` URL |
| `REDIS_CONNECT_TIMEOUT_MS` | No | `5000` | `100..60000` ms |
| `REDIS_MAX_RECONNECT_ATTEMPTS` | No | `10` | `0..100` attempts |
| `WORKER_CONCURRENCY` | No | `2` | `1..50` concurrent jobs |
| `WORKER_LOCK_DURATION` | No | `30000` | `5000..600000` ms |
| `WORKER_STALLED_INTERVAL` | No | `30000` | `5000..600000` ms |
| `WORKER_MAX_STALLED_COUNT` | No | `2` | `0..10` recoveries |
| `WORKER_MAX_STARTED_ATTEMPTS` | No | `5` | `1..20` starts |
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

# Real Docker Redis integration tests (from repo root)
pnpm run test:integration:redis

# Run standalone compiled worker entrypoint (requires a registered processor)
pnpm --filter @vibeshield/security-worker start
```

## Scope Note

Task 1.7.2 establishes the dedicated worker runtime, lifecycle management, processor contract, and tests. Repository cloning, containerized execution, Semgrep/Gitleaks/Trivy scanners, webhook-triggered enqueueing, and AI remediation will be implemented in subsequent tasks.
