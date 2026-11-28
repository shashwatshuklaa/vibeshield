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
  - Repository acquisition streams compressed repository archives directly from `POST /internal/v1/scans/acquire` on the API's dedicated private/loopback listener (`INTERNAL_WORKER_AUTH_SECRET`, upgradeable to mTLS/workload identity in production). Under this shared-HMAC service identity model, workers claiming scans must set `lease.workerId = 'security-worker'` so internal authorization aligns with `x-vibeshield-service: security-worker`. Actual static analyzers (`Semgrep`, `Gitleaks`, `Trivy`) and tar extraction will execute later inside restricted, networkless non-root scanner sandboxes holding zero DB, Redis, or GitHub credentials.
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
| `WORKER_WORKSPACE_DIR` | No | OS temp (`vibeshield-workspaces`) | Non-root absolute directory without NUL bytes; must not be a symlink |
| `INTERNAL_API_BASE_URL` | Conditional | — | HTTP/HTTPS origin (`http://host[:port]`); required when `INTERNAL_WORKER_AUTH_SECRET` is set |
| `INTERNAL_WORKER_AUTH_SECRET` | Conditional | — | >= 32 non-whitespace chars, distinct from JWT/GitHub secrets; required when `INTERNAL_API_BASE_URL` is set |
| `NODE_ENV` | No | `development` | `development \| production \| test` |
| `LOG_LEVEL` | No | `info` | `error \| warn \| info \| http \| verbose \| debug \| silly \| silent` |

## Internal Repository Acquisition & Defensive Extraction

`createInternalAcquisitionClient()` exposes a bounded, non-buffering HTTP client pinned strictly to `POST /internal/v1/scans/acquire` with `x-vibeshield-service: security-worker`:

- Signs exact raw UTF-8 JSON `{ scanId, leaseToken }` bytes with HMAC-SHA256, millisecond timestamp, and CSPRNG nonce (`generateInternalAuthNonce()`).
- Rejects redirects (`3xx`) fail-closed, validates `Content-Type` (`application/gzip` / `application/x-gzip`) and `Content-Length`, caps compressed transfers at `100 MiB` (`104857600` bytes), propagates socket/stream backpressure via `Readable`, and rejects truncated/incomplete HTTP responses or premature closes.
- Separates timeouts (`ACQUISITION_TIMEOUT`), explicit cancellation (`ACQUISITION_CANCELLED`), and worker shutdown (`WORKER_SHUTDOWN`) cleanly without leaking lease tokens, HMAC secrets, signatures, or upstream response bodies.

`extractRepositoryArchive()` consumes `AcquiredRepositoryArchive` using streaming gzip decompression (`zlib.createGunzip()`), a pre-parser 512-byte tar metadata guard (`createTarMetadataGuardTransform`), and `tar-stream` (`allowUnknownFormat: false`) into an isolated `0700` temporary workspace:

- Enforces hard limits: compressed stream `<= 100 MiB`, decompressed stream `<= 512 MiB`, regular files `<= 25 MiB`, total entries `<= 25,000`, entry path length `<= 240` (characters and UTF-8 bytes) and component UTF-8 bytes `<= 255`, entry depth `<= 24`, per-entry metadata `<= 64 KiB`, total extended metadata `<= 4 MiB`, extended headers `<= 25,000` (with at most 8 consecutive extended headers and 4 global PAX headers).
- Rejects ill-formed Unicode surrogates, empty PAX `path` overrides, malformed/signed base-256 sizes (`0x81`), GNU long link paths (`K`), unsupported PAX keys, and Unicode NFD/NFC or case-insensitive path collisions after NFC canonicalization.
- Validates workspace parent directory trust (`workerUid`-owned or `uid === 0` with sticky bit such as `/tmp`, rejecting group/world-writable non-sticky directories on both initialization and cleanup) and removes partial `mkdtemp` directories if post-creation checks fail.
- Accepts strictly regular files and directories under a single consistent top-level root directory (stripped deterministically), extracting files exclusively (`O_CREAT | O_EXCL | O_NOFOLLOW`, `0600`) and directories (`0700`) without preserving executable bits, ownership, ACLs, links, devices, FIFOs, or sparse files.
- Guarantees idempotent containment-validated `cleanup()` on explicit release as well as on parser, limit, truncation, cancellation, or shutdown failure.

### Extraction Threat Model & Residual Risks

- Extraction executes sequentially on the worker host under the worker OS UID and does not execute repository contents.
- Standard Node.js `fs/promises` path-based operations (`lstat`, `realpath`, `mkdir`, `open`, `rm`) cannot achieve kernel `openat2`/`RESOLVE_BENEATH` atomicity, leaving narrow TOCTOU windows if an untrusted local process shares write access to the workspace hierarchy. Production deployments must isolate workspaces on dedicated worker-owned (`0700`) non-shared storage (or OS sticky `/tmp` only in trusted single-tenant sandboxes) ahead of dedicated scanner sandboxes.

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

This workspace currently implements worker runtime/lifecycle coordination, MongoDB lease fencing, BullMQ job consumption, the internal API HTTP archive acquisition client (`createInternalAcquisitionClient()`), and defensive archive extraction into isolated worker workspaces (`extractRepositoryArchive()`). Static security scanner execution (`Semgrep`, `Gitleaks`, `Trivy`), restricted scanner container sandboxes, scan orchestration wiring, webhook triggers, and AI remediation remain unimplemented for upcoming tasks.
