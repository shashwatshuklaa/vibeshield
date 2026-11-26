# VibeShield API Service (`@vibeshield/api`)

The foundational HTTP backend service for the VibeShield application security engineering platform.

## Overview

The API service provides versioned REST endpoints for security project administration, vulnerability scan coordination, and platform health monitoring. It is designed as a modular monolith in TypeScript with robust input validation, MongoDB connectivity via `@vibeshield/database`, centralized error handling, and defense-in-depth HTTP security headers via Helmet.

## Getting Started

### 1. Install Dependencies
From the repository root:
```bash
pnpm install
```

### 2. Configure Environment
The API extends the foundational environment schema from `@vibeshield/env`. Copy the root `.env.example` to `.env` and configure required variables:
- `MONGODB_URI` (**required**): MongoDB connection URI (`mongodb://...` or `mongodb+srv://...`). Never commit real credentials to Git.
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
1. Validate environment variables (fails fast with sanitized errors if `MONGODB_URI` is missing or malformed).
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
Run the Vitest unit and integration suite (mocked database dependencies, no running MongoDB instance required):
```bash
pnpm --filter @vibeshield/api test
```

## API Endpoints

- **`GET /`**: Service identity and documentation pointer.
- **`GET /api/v1/health/live`**: Liveness probe indicating the Node.js API process is operational. Independent of MongoDB availability.
- **`GET /api/v1/health/ready`**: Readiness probe checking MongoDB connection status. Returns HTTP `200` when connected and HTTP `503` when unavailable or disconnected.
- **`GET /api/v1/health`**: Backward-compatible process health endpoint (behaves identically to `/api/v1/health/live`).
