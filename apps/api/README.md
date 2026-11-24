# VibeShield API Service (`@vibeshield/api`)

The foundational HTTP backend service for the VibeShield application security engineering platform.

## Overview

The API service provides versioned REST endpoints for security project administration, vulnerability scan coordination, and platform health monitoring. It is designed as a modular monolith in TypeScript with robust input validation, centralized error handling, and defense-in-depth HTTP security headers via Helmet.

## Getting Started

### 1. Install Dependencies
From the repository root:
```bash
pnpm install
```

### 2. Configure Environment
The API extends the foundational environment schema from `@vibeshield/env`. Copy the root `.env.example` to `.env` if you wish to override default variables:
- `PORT`: HTTP port to bind (default: `4000`)
- `HOST`: Bind host address (default: `0.0.0.0`)
- `NODE_ENV`: Execution environment (`development`, `production`, `test`)
- `LOG_LEVEL`: Logging verbosity level (default: `info`)
- `API_PREFIX`: Route namespace prefix (default: `/api/v1`)

### 3. Development Mode
Run the API with hot reloading using native Node.js TypeScript execution:
```bash
pnpm --filter @vibeshield/api dev
```

### 4. Build and Production Run
Compile TypeScript to JavaScript and start the production server:
```bash
pnpm --filter @vibeshield/api build
pnpm --filter @vibeshield/api start
```

### 5. Running Tests
Run the Vitest integration suite:
```bash
pnpm --filter @vibeshield/api test
```

## Initial API Endpoints

- **`GET /`**: Service identity and documentation pointer.
- **`GET /api/v1/health`**: Process health check returning operational status, uptime, and timestamp.
