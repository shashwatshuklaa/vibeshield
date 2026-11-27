# VibeShield

> AI-Powered Application Security Engineering Platform.

## Mission

VibeShield aims to empower software engineering and security teams with intelligent, proactive, and automated application security capabilities. By integrating context-aware AI analysis with modern security engineering workflows, VibeShield helps teams identify, assess, and remediate vulnerabilities early and effectively across the software development lifecycle.

## Workspace Architecture

VibeShield is structured as a **pnpm workspace monorepo** to maintain code modularity, enable efficient code sharing, and provide reproducible builds across all platform components.

### Workspace Layout

- **`apps/*`**: User-facing applications and core services.
  - **`apps/api`** (`@vibeshield/api`): Modular monolith backend API (Express + Helmet). *(Implemented)*
  - **`apps/web`**: Security dashboard frontend (React + Vite). *(Planned)*
- **`workers/*`**: Asynchronous background workers, security analysis jobs, and event consumers. *(Planned)*
- **`packages/*`**: Shared internal libraries, type definitions, security rules, and utility packages.
  - **`packages/types`** (`@vibeshield/types`): Shared domain contracts, enums, and entities. *(Implemented)*
  - **`packages/config`** (`@vibeshield/config`): Shared TypeScript presets (`node.json`, `react.json`). *(Implemented)*
  - **`packages/env`** (`@vibeshield/env`): Secure environment validation and schema utilities with secret redaction. *(Implemented)*
  - **`packages/database`** (`@vibeshield/database`): Reusable MongoDB connectivity and connection lifecycle management built on Mongoose. *(Implemented)*
  - Other shared packages (`queue`): *(Planned)*

> [!NOTE]
> `@vibeshield/api`, `@vibeshield/types`, `@vibeshield/config`, `@vibeshield/env`, and `@vibeshield/database` are active workspaces. Web UI and background workers are planned architecture components.

## Prerequisites

- **Node.js**: >= 20.0.0 (Tested on Node.js 22.x)
- **pnpm**: 12.23.0 (Managed via Corepack)

## Getting Started

1. **Enable pnpm via Corepack** (if not already enabled):
   ```bash
   corepack enable pnpm
   ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` (or configure your deployment environment):
   ```bash
   cp .env.example .env
   ```

3. **Install Workspace Dependencies**:
   ```bash
   pnpm install
   ```

4. **Build Workspace Packages**:
   ```bash
   pnpm run build
   ```

5. **Start the API Service (Development)**:
   ```bash
   pnpm --filter @vibeshield/api dev
   ```

## Development Status

- **Status**: Redis & BullMQ queue infrastructure foundation established (Task 1.7.1 completed; security workers and scanner orchestration pending next tasks).
- Foundational pnpm monorepo structure, shared domain contracts (`@vibeshield/types`), shared TypeScript presets (`@vibeshield/config`), secure environment configuration (`@vibeshield/env`), MongoDB connection lifecycle, transactions, and core/GitHub foundation models (`@vibeshield/database`: `User`, `Organization`, `OrganizationMembership`, `Project`, `Session`, `RotatedRefreshToken`, `GitHubInstallation`, `GitHubOAuthState`, `ProjectRepositoryConnection`, `WebhookDelivery`, `IntegrationAuditLog`), shared Redis/BullMQ queue infrastructure (`@vibeshield/queue`: redacted `redis://`/`rediss://` lifecycle, role-separated Queue/Worker options, `vibeshield-v1-scan-jobs` factory, bounded retry/retention defaults, and strict credential-free payload validation), and Express backend service (`@vibeshield/api` with Argon2id auth, HS256 JWT access tokens, rotating HttpOnly refresh sessions, multi-tenant organization CRUD, RBAC permission matrix, transactional ownership transfer, organization-scoped project CRUD with pagination/search/archive/restore, hardened GitHub App installation flow, repository discovery, project-to-repository connection/sync/disconnect lifecycle, HMAC-verified GitHub webhook receiver with idempotent delivery tracking, and liveness/readiness probes including optional queue readiness) are active. Production scan workers, security scanner integrations, frontend UI, and AI analysis/remediation are pending next phases.
