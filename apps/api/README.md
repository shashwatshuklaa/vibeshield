# VibeShield API Service (`@vibeshield/api`)

The foundational HTTP backend service for the VibeShield application security engineering platform.

## Overview

The API service provides versioned REST endpoints for user authentication, session management, security project administration, vulnerability scan coordination, and platform health monitoring. It is designed as a modular monolith in TypeScript with robust input validation, Argon2id password hashing, HS256 JWT access tokens, rotating HttpOnly refresh cookies, MongoDB connectivity via `@vibeshield/database`, centralized error handling, and defense-in-depth HTTP security headers via Helmet.

## Getting Started

### 1. Install Dependencies
From the repository root:
```bash
pnpm install
```

### 2. Configure Environment
The API extends the foundational environment schema from `@vibeshield/env`. Copy the root `.env.example` to `.env` and configure required variables:
- `MONGODB_URI` (**required**): MongoDB connection URI (`mongodb://...` or `mongodb+srv://...`). Never commit real credentials to Git.
- `JWT_ACCESS_SECRET` (**required**): Cryptographically random secret (minimum 32 characters) used to sign HS256 JWT access tokens. No default fallback is provided.
- `CORS_ORIGIN`: Comma-separated allowed HTTP/HTTPS frontend origin(s) for browser Origin/Referer CSRF checks on cookie-authenticated auth routes (default: `http://localhost:5173`)
- `JWT_ACCESS_TTL`: Access token expiration duration (default: `15m`)
- `JWT_ISSUER`: JWT `iss` claim (default: `vibeshield-api`)
- `JWT_AUDIENCE`: JWT `aud` claim (default: `vibeshield-clients`)
- `AUTH_REFRESH_TOKEN_TTL`: Refresh session lifetime duration (default: `7d`)
- `PORT`: HTTP port to bind (default: `4000`)
- `HOST`: Bind host address (default: `0.0.0.0`)
- `NODE_ENV`: Execution environment (`development`, `production`, `test`)
- `LOG_LEVEL`: Logging verbosity level (default: `info`)
- `API_PREFIX`: Route namespace prefix (default: `/api/v1`)
- **GitHub App Integration (Optional; all-or-none when enabled; routes/webhooks deferred to upcoming tasks)**:
  - `GITHUB_APP_ID`: Numeric GitHub App identifier.
  - `GITHUB_APP_SLUG`: Hyphenated lowercase GitHub App URL slug.
  - `GITHUB_APP_PRIVATE_KEY`: Valid RSA PEM private key (supports escaped `\n` newlines).
  - `GITHUB_CLIENT_ID`: GitHub App OAuth Client ID.
  - `GITHUB_CLIENT_SECRET`: GitHub App OAuth Client Secret (min 20 characters).
  - `GITHUB_WEBHOOK_SECRET`: Primary GitHub webhook HMAC secret (min 32 characters).
  - `GITHUB_WEBHOOK_SECRET_PREVIOUS`: Optional previous webhook secret for zero-downtime secret rotation (requires core GitHub settings when set).
  - `GITHUB_CALLBACK_URL`: Exact registered GitHub App OAuth Callback URL without wildcards, query parameters, or fragments (HTTPS required in production).

#### Local MongoDB Example
```env
MONGODB_URI=mongodb://localhost:27017/vibeshield_dev
```

#### MongoDB Atlas Example
```env
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster-host>/vibeshield_dev?retryWrites=true&w=majority
```

### 3. Startup & Shutdown Lifecycle
When started via `dev` or `start`, the server follows a strict startup sequence:
1. Validate environment variables (fails fast with sanitized errors if `MONGODB_URI` or `JWT_ACCESS_SECRET` is missing or invalid).
2. Connect to MongoDB via `@vibeshield/database`.
3. Start listening for HTTP requests only after MongoDB connects successfully.

If database connection fails, the API does not open the HTTP port, logs a credential-free error, and exits with status `1`.

On `SIGINT` or `SIGTERM`, the API stops accepting new HTTP connections, waits for active requests to finish (forcing open keep-alive connections closed after timeout), disconnects MongoDB, and exits cleanly.

### 4. Development Mode
Run the API with hot reloading using native Node.js TypeScript execution:
```bash
pnpm --filter @vibeshield/api dev
```

### 5. Build and Production Run
Compile TypeScript to JavaScript and start the production server:
```bash
pnpm --filter @vibeshield/api build
pnpm --filter @vibeshield/api start
```

### 6. Running Tests
Run the fast Vitest unit and in-memory integration suites (no running MongoDB instance required):
```bash
pnpm --filter @vibeshield/api test
```

Run the **real MongoDB replica-set integration tests** (from the repository root, requires Docker or `MONGODB_INTEGRATION_URI` + `MONGODB_STANDALONE_URI`):
```bash
pnpm run test:integration
```

`scripts/run-mongo-integration.mjs` automatically starts ephemeral single-node MongoDB replica-set (`--replSet rs0`) and standalone containers on free localhost ports, runs `vitest.integration.config.mts`, and removes the containers afterward. In GitHub Actions CI, `test:integration` runs with `MONGO_IMAGE_TAG=7`.

#### Test Coverage Distinction
- **Real MongoDB replica-set integration tests** ([organizations.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/organizations.integration.test.ts), [transaction.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/packages/database/src/__tests__/transaction.integration.test.ts)): Exercise actual Mongoose `ClientSession` transactions, WiredTiger `WriteConflict` serialization, rollbacks, unique index `E11000` enforcement, and standalone MongoDB transaction rejection.
- **In-memory snapshot-simulator & store tests** ([organizations.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/organizations.test.ts), [auth.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/auth.test.ts)): Exercise HTTP routing, Zod schemas, RBAC matrix, CSRF/Origin checks, and simulated snapshot isolation without requiring a database process.
- **Unit tests** (`auth-crypto.test.ts`, `env.test.ts`, `health.test.ts`, `server.test.ts`, `app.test.ts`): Test cryptography, JWT validation, env parsing, health probes, and HTTP lifecycle.

## Authentication Architecture

- **Password Security**: Passwords (12–128 characters, no arbitrary composition rules) are hashed with **Argon2id** (`memoryCost: 65536`, `timeCost: 3`, `parallelism: 1`). Plaintext passwords and hashes are never logged or returned in API responses.
- **Access Tokens**: Short-lived (`15m` default) JWTs signed with explicit **HS256**, containing `sub` (user ID), `sid` (session ID), `iss`, `aud`, `iat`, and `exp`. No passwords or PII are included in claims.
- **Refresh Tokens & Sessions**: Opaque 256-bit CSPRNG refresh tokens are hashed with **SHA-256** and persisted in `SessionModel`. Each `/auth/refresh` call atomically rotates the refresh token (`findOneAndUpdate`), stores `previousRefreshTokenHash` on the session (catching concurrent `N-1` races atomically), and records the rotated hash in `RotatedRefreshTokenModel` (bounded by a MongoDB TTL index) so replay of **any** previously rotated token (`N-1`, `N-2`, ...) revokes the entire session.
- **Cookie & CSRF Protection**:
  - Refresh tokens are issued exclusively via an `HttpOnly`, `SameSite=Lax` cookie (`vs_refresh_token`) scoped to `${API_PREFIX}/auth`, with `Secure` enabled when `NODE_ENV=production`.
  - Refresh tokens are never returned in JSON bodies.
  - Because `SameSite=Lax` alone permits same-site `POST` requests from sibling subdomains (e.g. `other.vibeshield.io` -> `api.vibeshield.io`), `POST /auth/refresh` and `POST /auth/logout` also enforce strict `Origin` / `Referer` / `Sec-Fetch-Site` validation against `CORS_ORIGIN` and the request's own host origin.
  - **Client Implications**: Browser clients must send credentials (`credentials: 'include'` / `withCredentials: true`) when calling `/auth/refresh` and `/auth/logout`. Frontend apps must **serialize concurrent `/auth/refresh` calls** across requests and browser tabs (e.g., via a shared in-flight promise and `navigator.locks` / `BroadcastChannel`), because strict replay detection treats simultaneous parallel refresh requests with the same token as potential replay and revokes the session. If frontend and API are deployed on separate sites (`eTLD+1`), `SameSite=None; Secure` and CORS credentials middleware will be required alongside `Origin` checks.
- **Middleware Protection**: `authenticate` validates the `Authorization: Bearer <token>` JWT, checks that session `sid` exists and is neither revoked nor expired, and verifies that the user is `ACTIVE`.
- **Current Limitations**:
  - **Authentication rate limiting is not implemented yet**: `/auth/register`, `/auth/login`, and `/auth/refresh` currently lack brute-force and credential-stuffing protection. A dedicated distributed **Redis-backed** rate limiter (per-IP and per-normalized-account/email) will be added in the Redis/rate-limiting task rather than introducing a misleading single-instance in-memory limiter.
  - Email verification and password reset/recovery flows are **not** implemented yet and will be introduced in dedicated future workflows.
  - Registration does not automatically create an `Organization` or `OrganizationMembership`.

## API Endpoints

- **`GET /`**: Service identity and documentation pointer.
- **`GET /api/v1/health/live`**: Liveness probe indicating the Node.js API process is operational. Independent of MongoDB availability.
- **`GET /api/v1/health/ready`**: Readiness probe checking MongoDB connectivity and reporting queue status (`disabled`, `connected`, `not_initialized`, or `unavailable` under `checks.queue`). Returns HTTP `200` when MongoDB is connected (and any required Redis queue is connected), or HTTP `503` when MongoDB or a required Redis connection is down. Optional disabled/unavailable queues do not fail API readiness.
- **`GET /api/v1/health`**: Backward-compatible process health endpoint (behaves identically to `/api/v1/health/live`).
- **`POST /api/v1/auth/register`**: Register a new user (`email`, `displayName`, `password`), handling concurrent duplicate emails via MongoDB unique index (`409`).
- **`POST /api/v1/auth/login`**: Authenticate user, create a hashed session, set `vs_refresh_token` HttpOnly cookie, and return `{ user, accessToken, expiresIn }`.
- **`POST /api/v1/auth/refresh`**: Atomically rotate refresh cookie, detect reuse, and return `{ accessToken, expiresIn }`.
- **`GET /api/v1/auth/me`**: Return the authenticated user's safe profile (requires Bearer token + active session).
- **`POST /api/v1/auth/logout`**: Revoke the current session, clear `vs_refresh_token` cookie, and invalidate the session's access tokens.
- **`POST /api/v1/organizations`**: Create an organization and initial `ACTIVE` `OWNER` membership inside a MongoDB transaction.
- **`GET /api/v1/organizations`**: List organizations where the authenticated user holds an `ACTIVE` membership (with user role).
- **`GET /api/v1/organizations/:organizationId`**: Retrieve organization details (requires `ACTIVE` membership).
- **`PATCH /api/v1/organizations/:organizationId`**: Update organization `name`/`slug` (`OWNER` or `ADMIN`).
- **`DELETE /api/v1/organizations/:organizationId`**: Delete an organization and its memberships transactionally (`OWNER` only; blocked if projects exist).
- **`GET /api/v1/organizations/:organizationId/members`**: List organization members safely (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`).
- **`POST /api/v1/organizations/:organizationId/members`**: Add an existing registered user by email (`OWNER` assigns `ADMIN`/`MEMBER`/`VIEWER`; `ADMIN` assigns `MEMBER`/`VIEWER`).
- **`PATCH /api/v1/organizations/:organizationId/members/:membershipId`**: Update member role/status according to the permission matrix and last-`OWNER` invariant.
- **`DELETE /api/v1/organizations/:organizationId/members/:membershipId`**: Remove a member or leave the organization (last `ACTIVE` `OWNER` protected).
- **`POST /api/v1/organizations/:organizationId/transfer-ownership`**: Atomically transfer `OWNER` to another `ACTIVE` member inside a MongoDB transaction (`OWNER` only).
- **`POST /api/v1/organizations/:organizationId/projects`**: Create an organization-scoped project inside a MongoDB transaction (`OWNER`, `ADMIN`, `MEMBER`).
- **`GET /api/v1/organizations/:organizationId/projects`**: List organization projects with pagination (`page`, `limit`), safe `search` (case-insensitive substring on `name`), `archived` filter (`exclude` | `only` | `include`), and deterministic sort (`createdAt` desc, `_id` desc) (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`).
- **`GET /api/v1/organizations/:organizationId/projects/:projectId`**: Retrieve a single organization-scoped project (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`).
- **`PATCH /api/v1/organizations/:organizationId/projects/:projectId`**: Update project `name`, `slug`, and/or `description` (`OWNER`, `ADMIN`, `MEMBER`).
- **`POST /api/v1/organizations/:organizationId/projects/:projectId/archive`**: Idempotently archive a project (`OWNER`, `ADMIN` only).
- **`POST /api/v1/organizations/:organizationId/projects/:projectId/restore`**: Idempotently restore an archived project (`OWNER`, `ADMIN` only).
- **`POST /api/v1/organizations/:organizationId/github/installations/start`**: Create a single-use SHA-256-hashed OAuth state bound to user + org and return a GitHub App installation or OAuth URL (`OWNER`, `ADMIN` only).
- **`POST /api/v1/organizations/:organizationId/github/installations/authorize-list`**: Consume state, exchange user OAuth code, and list installations accessible to the authenticating GitHub user for separated setup flows (`OWNER`, `ADMIN` only).
- **`POST /api/v1/organizations/:organizationId/github/installations/complete`**: Consume state atomically, verify GitHub installation ownership and authoritative App metadata, and transactionally link the installation (`200 CONNECTED`, or `202 APPROVAL_REQUESTED` for `setupAction=request`) (`OWNER`, `ADMIN` only).
- **`GET /api/v1/organizations/:organizationId/github/installations`**: List linked non-disconnected GitHub App installations for the organization (`OWNER`, `ADMIN` only).
- **`GET /api/v1/organizations/:organizationId/github/repositories`**: Mint an ephemeral installation access token in memory and return paginated safe repository metadata (`OWNER`, `ADMIN` only).
- **`GET /api/v1/organizations/:organizationId/github/connections`**: List paginated active repository connections across the organization (`OWNER`, `ADMIN` only).
- **`POST /api/v1/organizations/:organizationId/projects/:projectId/github`**: Connect an organization's project to a repository verified via `GET /installation/repositories` (`201 Created`, or idempotent `200 OK` metadata refresh; `OWNER`, `ADMIN` only). Blocks archived projects (`409 PROJECT_ARCHIVED`), cross-org resources (`404`), and duplicate active project/repo bindings (`409`).
- **`GET /api/v1/organizations/:organizationId/projects/:projectId/github`**: Retrieve a project's active GitHub repository connection (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`).
- **`POST /api/v1/organizations/:organizationId/projects/:projectId/github/sync`**: Refresh installation suspension/revocation status and authoritative GitHub repository metadata without letting installation unsuspend overwrite `REPO_DELETED` or restore `ACCESS_REVOKED` (`OWNER`, `ADMIN` only).
- **`DELETE /api/v1/organizations/:organizationId/projects/:projectId/github`**: Safely disconnect a project's GitHub repository (`repositoryAccessState: DISCONNECTED`, `isActive: false`) while preserving historical connection and installation records (`OWNER`, `ADMIN` only).
- **`POST /api/v1/webhooks/github`**: Unauthenticated GitHub App webhook receiver verified via `X-Hub-Signature-256` HMAC-SHA256 against exact raw request bytes (`GITHUB_WEBHOOK_SECRET` and optional `GITHUB_WEBHOOK_SECRET_PREVIOUS` during rotation), deduplicated via `X-GitHub-Delivery`, and processing `installation`, `installation_repositories`, and `repository` lifecycle events inside per-organization transactions.

## Organization & RBAC Architecture

- **Centralized Permission Matrix** ([organization.permissions.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/organizations/organization.permissions.ts)):
  - Roles: `OWNER`, `ADMIN`, `MEMBER`, `VIEWER`.
  - `OWNER`: Full organization control, `DELETE`, `ADMIN` assignment, member management, ownership transfer, and full project management (read, create, update, archive, restore).
  - `ADMIN`: View/update organization, view members, add/manage/remove `MEMBER` and `VIEWER` roles, and full project management (read, create, update, archive, restore); cannot manage `OWNER` or `ADMIN` memberships, assign `ADMIN`/`OWNER`, delete the organization, or transfer ownership.
  - `MEMBER`: Read-only access to organization details and member lists (and self-removal/leave); full non-destructive project participation (read, create, update projects, cannot archive or restore).
  - `VIEWER`: Read-only access across organization details, member lists, and projects (and self-removal/leave); cannot create, update, archive, or restore projects.
  - Anti-escalation rules: No user may modify their own role/status via `PATCH`, assign `OWNER` outside `/transfer-ownership`, or access another organization or foreign project via ID guessing (non-members, `INVITED`, `SUSPENDED` memberships, and cross-organization project IDs receive `404`).
- **Reusable Authorization Middleware** ([authorize-organization.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/middlewares/authorize-organization.ts)):
  - `createRequireOrganizationMembershipMiddleware` resolves `ACTIVE` membership once per request and caches `req.organizationAuth` (avoiding duplicate DB queries).
  - `requireOrganizationPermission` and `requireOrganizationRoles` enforce route-level authorization against the cached context across both `/organizations/:organizationId` and `/organizations/:organizationId/projects`.
- **Project Module & Query Isolation** ([project.service.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/projects/project.service.ts), [project.store.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/projects/project.store.ts)):
  - Every project query explicitly filters by `{ _id: projectId, organizationId }` (or `{ organizationId }` for listings) derived solely from verified `req.organizationAuth.organizationId`, returning `404 PROJECT_NOT_FOUND` on cross-organization access attempts.
  - `createProject`, `updateProject`, `archiveProject`, and `restoreProject` run inside MongoDB transactions, acquire `acquireOrganizationMutationLock(organizationId, session)` first, and revalidate active membership + permission inside the transaction before mutating project state.
  - Organization-scoped slug uniqueness (`E11000` on `{ organizationId, slug }`) maps deterministically to HTTP `409 PROJECT_SLUG_EXISTS`, while distinct organizations can reuse the same project slug independently.
  - `listProjects` validates bounded pagination (`page >= 1`, `1 <= limit <= 100`), escapes regex metacharacters on `search`, supports `archived=exclude|only|include`, and runs a single `find` + `countDocuments` query with deterministic sorting (`createdAt: -1, _id: -1`).
- **Transaction & Isolation Requirements**:
  - **Per-Organization Mutation Lock (Write-Skew Prevention)**: Because MongoDB multi-document transactions run under WiredTiger Snapshot Isolation (not Serializable isolation), checking active `OWNER` counts or project existence and modifying separate membership/project documents without a shared write would allow write skew. Therefore, `OrganizationModel` maintains an internal `membershipVersion` counter, and **every** organization-level or project-level mutation starts a MongoDB transaction, acquires the shared lock first via `acquireOrganizationMutationLock` (`$inc: { membershipVersion: 1 }`), and revalidates the actor's `ACTIVE` membership and role inside the transaction before checking invariants or writing.
  - **Project Creation vs. Organization Deletion Serialization**: `createProject` acquires `acquireOrganizationMutationLock(organizationId, session)` inside its MongoDB transaction before inserting the `Project` document, preventing concurrent `createProject` and `deleteOrganization` calls from committing disjoint writes and leaving orphaned projects.
  - **Replica-Set Requirement**: `runInTransaction` relies on MongoDB multi-document transactions, which require a **MongoDB replica set or sharded cluster** (no fallback to non-transactional writes; transient `WriteConflict` retries are handled by MongoDB's bounded `session.withTransaction`).
  - Future scan, finding, and repository services must always resolve `OrganizationAuthContext` first and scope every database query by `organizationId`.
  - **Known Limitations**: Email invitation delivery, automatic scan job queueing (Redis/BullMQ), and repository security scanning (Task 1.7+) are **not implemented yet**. Because GitHub returns `404` for unauthorized private repositories to avoid leaking existence, REST sync (`/github/sync`) conservatively marks ambiguous `404` responses as `ACCESS_REVOKED` (with an explanatory `statusReason`) and reserves `REPO_DELETED` for explicit `410 Gone`, while `repository.deleted` webhook deliveries mark `REPO_DELETED` authoritatively. Automated unit and integration tests exercise mocked HTTP transports, signed local Supertest payloads, and an in-process mock HTTP server rather than hitting live GitHub endpoints. Single-node replica-set integration tests ([organizations.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/organizations.integration.test.ts), [projects.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/projects.integration.test.ts), [github.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/github.integration.test.ts), [github-connections.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/github-connections.integration.test.ts), [github-webhooks.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/__tests__/github-webhooks.integration.test.ts), and [github-models.integration.test.ts](file:///home/krishna/Coding/Projects/Vibeshield/packages/database/src/__tests__/github-models.integration.test.ts)) verify real MongoDB transactions, rollbacks, `WriteConflict` locking, TTL indexes, and partial unique indexes, while multi-node replica-set failover and network-partition behavior are outside single-node integration scope.

## GitHub App Integration Architecture

- **Module Components** (`apps/api/src/modules/github/`):
  - [github.jwt.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github.jwt.ts): Signs short-lived RS256 GitHub App JWTs via Node.js `node:crypto` with a `60s` clock-skew `iat` offset and `540s` `exp` (`<= 600s` total lifetime).
  - [github.pkce.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github.pkce.ts): Generates 256-bit CSPRNG PKCE `code_verifier` + `S256` `code_challenge` pairs and encrypts verifiers at rest with AES-256-GCM (HKDF-SHA256 derived key + AAD bound to `userId:organizationId:stateHash`).
  - [github.client.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github.client.ts): Native `fetch` client enforcing official `https://api.github.com` / `https://github.com` origins (custom origins restricted to explicit test injection), `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2026-03-10`, `User-Agent: VibeShield-API`, strict `redirect_uri` & `code_verifier` exchange, timeouts, bounded single transient `GET` retry, rate-limit mapping (`429`/`Retry-After`/`X-RateLimit-Reset`), strict Zod validation of untrusted GitHub payloads, installation-membership repository checks (`findInstallationRepositoryById`, `probeRepositoryById`), and credential redaction.
  - [github.service.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github.service.ts) & [github.store.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github.store.ts): Implements installation start (`install` and `authorize` modes with `S256` PKCE + fixed callback URL), separated user OAuth discovery (`authorize-list`, consuming `OAUTH_AUTHORIZE` state + PKCE verifier atomically and issuing a single-use `INSTALLATION_SELECTION` `linkState`), atomic `GitHubOAuthStateModel` consumption (wiping `encryptedCodeVerifier` to `null` atomically), OAuth cancel/error handling, `setupAction=request` pending-approval (`202`) handling, GitHub user-to-installation ownership verification (`GET /user/installations`), authoritative installation inspection (`GET /app/installations/{id}`), transactional linking under `acquireOrganizationMutationLock`, append-only `IntegrationAuditLog` writes, and ephemeral in-memory IAT repository discovery (`GET /github/repositories`).
  - [github-connection.service.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-connection.service.ts) & [github-connection.store.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-connection.store.ts): Implements project-to-repository linking, inspection, synchronization, detachment, and org-wide listing with external GitHub checks performed outside MongoDB transactions, orthogonal state transitions (`repositoryAccessState` vs `installationAvailability`), transactional `acquireOrganizationMutationLock` serialization, partial unique index conflict mapping, and append-only audit logs.
  - [github-webhook.verifier.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-webhook.verifier.ts), [github-webhook.routes.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-webhook.routes.ts), [github-webhook.service.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-webhook.service.ts), & [github-webhook.store.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/modules/github/github-webhook.store.ts):
    - **Middleware Ordering & Raw Body**: In [app.ts](file:///home/krishna/Coding/Projects/Vibeshield/apps/api/src/app.ts), `/api/v1/webhooks/github` is mounted **before** global `express.json()` using route-scoped `express.raw({ type: () => true, limit: '1mb' })` so `X-Hub-Signature-256` is always verified with `crypto.timingSafeEqual()` against exact raw request bytes without JSON re-serialization or altering JSON parsing on unrelated routes. Oversized payloads return HTTP `413`.
    - **Secret Rotation**: Validates `GITHUB_WEBHOOK_SECRET` first and optionally accepts valid HMAC-SHA256 signatures from `GITHUB_WEBHOOK_SECRET_PREVIOUS` for zero-downtime secret rotation.
    - **Delivery Idempotency & Retries**: Uses `WebhookDeliveryModel` (`deliveryId` unique index + TTL index) with `PROCESSING -> PROCESSED | IGNORED | FAILED` state transitions coordinated transactionally with domain writes and `attemptCount` fencing. Multi-organization `repository` events persist bounded per-organization progress (`targetOrganizationIds`, `completedOrganizationIds`, `processedConnectionCount`) atomically inside each organization's transaction so retries skip already-completed organizations without duplicating audit logs and finalize `PROCESSED` only once all targets finish. Concurrent duplicates wait briefly or receive HTTP `200`/`503` without re-applying mutations; failed deliveries preserve prior progress plus redacted safe error metadata for HTTP `5xx` retries.
    - **Supported Events**: `installation` (`created`, `deleted`, `suspend`, `unsuspend`, `new_permissions_accepted`), `installation_repositories` (`added`, `removed`), and `repository` (`deleted`, `renamed`, `transferred`, `privatized`), resolving ownership strictly from existing DB records under `acquireOrganizationMutationLock` and logging sanitized `GITHUB_WEBHOOK` audit events.
- **GitHub App Setup Prerequisites (Local Manual E2E Testing)**:
  1. Create a GitHub App under GitHub Developer Settings (`User` or `Organization`).
  2. Configure **Repository permissions**: `Contents: Read-only` and `Metadata: Read-only`, and subscribe to **Events**: `Installation target` / `Repository` / `Meta` (or `Installation`, `Installation repositories`, `Repository`).
  3. Enable **"Request user authorization (OAuth) during installation"** and set the **Callback URL** strictly to the exact URL configured in `GITHUB_CALLBACK_URL` (e.g., `http://localhost:5173/integrations/github/callback`). **Disable wildcard callback matching** unless explicitly required, and never register shared wildcard domains. Configure **Webhook URL** to point at `POST <public-tunnel-or-domain>/api/v1/webhooks/github` and generate a 32+ character **Webhook secret** (`GITHUB_WEBHOOK_SECRET`; use `GITHUB_WEBHOOK_SECRET_PREVIOUS` temporarily during secret rotation).
  4. Generate a private key `.pem`, copy the App ID, App slug, Client ID, Client Secret, Callback URL, and Webhook secret into local `.env` (never committed to Git). To test webhooks locally, deliver signed JSON payloads to `http://localhost:4000/api/v1/webhooks/github` using `X-Hub-Signature-256`, `X-GitHub-Delivery`, and `X-GitHub-Event` headers (e.g., via `smee.io`, `gh webhook forward`, or Supertest).
  5. When `GITHUB_*` variables are omitted, the API starts normally and returns `503 GITHUB_INTEGRATION_NOT_CONFIGURED` on `/github/*` and `/webhooks/github` endpoints.
