# VibeShield

> AI-Powered Application Security Engineering Platform.

## Mission

VibeShield aims to empower software engineering and security teams with intelligent, proactive, and automated application security capabilities. By integrating context-aware AI analysis with modern security engineering workflows, VibeShield helps teams identify, assess, and remediate vulnerabilities early and effectively across the software development lifecycle.

## Workspace Architecture

VibeShield is structured as a **pnpm workspace monorepo** to maintain code modularity, enable efficient code sharing, and provide reproducible builds across all platform components.

### Workspace Layout

- **`apps/*`**: User-facing applications and core services (e.g., Web dashboard, API gateway). *(Planned)*
- **`workers/*`**: Asynchronous background workers, security analysis jobs, and event consumers. *(Planned)*
- **`packages/*`**: Shared internal libraries, type definitions, security rules, and utility packages.
  - **`packages/types`** (`@vibeshield/types`): Shared domain contracts, enums, and entities. *(Implemented)*
  - **`packages/config`** (`@vibeshield/config`): Shared TypeScript presets (`node.json`, `react.json`). *(Implemented)*
  - Other shared packages (`database`, `queue`): *(Planned)*

> [!NOTE]
> `@vibeshield/types` and `@vibeshield/config` are foundational shared packages. All deployable applications (`apps/*`), background workers (`workers/*`), and other shared packages (`packages/*`) are planned architecture components.

## Prerequisites

- **Node.js**: >= 20.0.0 (Tested on Node.js 22.x)
- **pnpm**: 12.23.0 (Managed via Corepack)

## Getting Started

1. **Enable pnpm via Corepack** (if not already enabled):
   ```bash
   corepack enable pnpm
   ```

2. **Install Workspace Dependencies**:
   ```bash
   pnpm install
   ```

3. **Build Workspace Packages**:
   ```bash
   pnpm run build
   ```

## Development Status

- **Status**: Shared TypeScript configuration presets established (Task 0.5 completed).
- Foundational pnpm monorepo structure, shared domain contracts (`@vibeshield/types`), and shared TypeScript presets (`@vibeshield/config`) are active. Application and worker implementations are pending next phases.
