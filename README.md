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
- **`workers/*`**: Asynchronous background workers and job consumers.
  - **`workers/security-worker`** (`@vibeshield/security-worker`): Dedicated standalone BullMQ security worker runtime consuming `vibeshield-v1-scan-jobs` independently of `apps/api`. *(Runtime Foundation Implemented; security scanners pending)*
- **`packages/*`**: Shared internal libraries, type definitions, security rules, and utility packages.
  - **`packages/types`** (`@vibeshield/types`): Shared domain contracts, enums, and entities. *(Implemented)*
  - **`packages/config`** (`@vibeshield/config`): Shared TypeScript presets (`node.json`, `react.json`). *(Implemented)*
  - **`packages/env`** (`@vibeshield/env`): Secure environment validation and schema utilities with secret redaction. *(Implemented)*
  - **`packages/database`** (`@vibeshield/database`): Reusable MongoDB connectivity and connection lifecycle management built on Mongoose. *(Implemented)*
  - **`packages/queue`** (`@vibeshield/queue`): Shared Redis lifecycle management, BullMQ queue & worker factories, job contracts, and secret redaction. *(Implemented)*

> [!NOTE]
> `@vibeshield/api`, `@vibeshield/security-worker`, `@vibeshield/types`, `@vibeshield/config`, `@vibeshield/env`, `@vibeshield/database`, and `@vibeshield/queue` are active workspaces. Web UI, scanner execution, and AI analysis/remediation are pending next phases.

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

6. **Run Worker Tests or Worker Entrypoint** (standalone worker runtime):
   ```bash
   pnpm --filter @vibeshield/security-worker test
   ```

## Development Status

- **Status**: Scan persistence model & worker MongoDB lifecycle foundation established (Task 1.7.3.1 completed; GitHub credential broker, repository acquisition, and scanner execution pending next tasks).
- Foundational pnpm monorepo structure, shared domain contracts (`@vibeshield/types` including `ScanLifecycleStatus`, failure codes, and acquisition metrics), shared TypeScript presets (`@vibeshield/config`), secure environment configuration (`@vibeshield/env`), MongoDB connection lifecycle, transactions, and core/GitHub/scan foundation models (`@vibeshield/database`: `User`, `Organization`, `OrganizationMembership`, `Project`, `Session`, `RotatedRefreshToken`, `GitHubInstallation`, `GitHubOAuthState`, `ProjectRepositoryConnection`, `WebhookDelivery`, `IntegrationAuditLog`, `Scan` with fenced worker lease and atomic cancellation operations), shared Redis/BullMQ queue infrastructure (`@vibeshield/queue`: redacted `redis://`/`rediss://` lifecycle, role-separated Queue/Worker options, `vibeshield-v1-scan-jobs` queue & worker factories, bounded retry/retention defaults, and strict credential-free payload validation), standalone security worker runtime (`workers/security-worker`: explicit MongoDB + Redis startup/cleanup, fail-fast processor boundary, bounded concurrency/lock/stalled settings, `UnrecoverableError` payload guarding, and grace-bounded shutdown), and Express backend service (`@vibeshield/api` with Argon2id auth, HS256 JWT access tokens, rotating HttpOnly refresh sessions, multi-tenant organization CRUD, RBAC permission matrix, transactional ownership transfer, organization-scoped project CRUD with pagination/search/archive/restore, hardened GitHub App installation flow, repository discovery, project-to-repository connection/sync/disconnect lifecycle, HMAC-verified GitHub webhook receiver with idempotent delivery tracking, and liveness/readiness probes including optional queue readiness) are active. GitHub credential brokering, archive acquisition, scan engines, frontend UI, and AI analysis/remediation are pending next phases.
