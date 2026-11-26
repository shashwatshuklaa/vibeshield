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
- `JWT_ACCESS_TTL`: Access token expiration duration (default: `15m`)
- `JWT_ISSUER`: JWT `iss` claim (default: `vibeshield-api`)
- `JWT_AUDIENCE`: JWT `aud` claim (default: `vibeshield-clients`)
- `AUTH_REFRESH_TOKEN_TTL`: Refresh session lifetime duration (default: `7d`)
- `PORT`: HTTP port to bind (default: `4000`)
- `HOST`: Bind host address (default: `0.0.0.0`)
- `NODE_ENV`: Execution environment (`development`, `production`, `test`)
- `LOG_LEVEL`: Logging verbosity level (default: `info`)
- `API_PREFIX`: Route namespace prefix (default: `/api/v1`)

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
Run the Vitest unit and integration suite (mocked/in-memory stores, no running MongoDB instance required):
```bash
pnpm --filter @vibeshield/api test
```

## Authentication Architecture

- **Password Security**: Passwords (12–128 characters, no arbitrary composition rules) are hashed with **Argon2id** (`memoryCost: 65536`, `timeCost: 3`, `parallelism: 1`). Plaintext passwords and hashes are never logged or returned in API responses.
- **Access Tokens**: Short-lived (`15m` default) JWTs signed with explicit **HS256**, containing `sub` (user ID), `sid` (session ID), `iss`, `aud`, `iat`, and `exp`. No passwords or PII are included in claims.
- **Refresh Tokens & Sessions**: Opaque 256-bit CSPRNG refresh tokens are hashed with **SHA-256** and persisted in `SessionModel`. Each `/auth/refresh` call atomically rotates the refresh token (`findOneAndUpdate`) and stores `previousRefreshTokenHash`. Presenting a previously rotated token triggers reuse detection and revokes the entire session.
- **Cookie Behavior**:
  - Refresh tokens are issued exclusively via an `HttpOnly`, `SameSite=Lax` cookie (`vs_refresh_token`) scoped to `${API_PREFIX}/auth`, with `Secure` enabled when `NODE_ENV=production`.
  - Refresh tokens are never returned in JSON bodies.
  - **Client Implications**: Browser clients must send credentials (`credentials: 'include'` / `withCredentials: true`) when calling `/auth/refresh` and `/auth/logout`. Non-browser API clients must retain and replay the `vs_refresh_token` cookie jar for refresh operations, and should serialize concurrent `/auth/refresh` calls in-flight since parallel replay of a rotated token triggers strict reuse revocation.
- **Middleware Protection**: `authenticate` validates the `Authorization: Bearer <token>` JWT, checks that session `sid` exists and is neither revoked nor expired, and verifies that the user is `ACTIVE`.
- **Current Limitations**:
  - Email verification and password reset/recovery flows are **not** implemented yet and will be introduced in dedicated future workflows.
  - Registration does not automatically create an `Organization` or `OrganizationMembership`.
  - Rate limiting / brute-force throttling and Redis-backed revocation caching are pending later phases.

## API Endpoints

- **`GET /`**: Service identity and documentation pointer.
- **`GET /api/v1/health/live`**: Liveness probe indicating the Node.js API process is operational. Independent of MongoDB availability.
- **`GET /api/v1/health/ready`**: Readiness probe checking MongoDB connection status. Returns HTTP `200` when connected and HTTP `503` when unavailable or disconnected.
- **`GET /api/v1/health`**: Backward-compatible process health endpoint (behaves identically to `/api/v1/health/live`).
- **`POST /api/v1/auth/register`**: Register a new user (`email`, `displayName`, `password`), handling concurrent duplicate emails via MongoDB unique index (`409`).
- **`POST /api/v1/auth/login`**: Authenticate user, create a hashed session, set `vs_refresh_token` HttpOnly cookie, and return `{ user, accessToken, expiresIn }`.
- **`POST /api/v1/auth/refresh`**: Atomically rotate refresh cookie, detect reuse, and return `{ accessToken, expiresIn }`.
- **`GET /api/v1/auth/me`**: Return the authenticated user's safe profile (requires Bearer token + active session).
- **`POST /api/v1/auth/logout`**: Revoke the current session, clear `vs_refresh_token` cookie, and invalidate the session's access tokens.
