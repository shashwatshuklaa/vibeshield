# VibeShield

> AI-Powered Application Security Engineering Platform.

## Mission

VibeShield aims to empower software engineering and security teams with intelligent, proactive, and automated application security capabilities. By integrating context-aware AI analysis with modern security engineering workflows, VibeShield helps teams identify, assess, and remediate vulnerabilities early and effectively across the software development lifecycle.

## Workspace Architecture

VibeShield is structured as a **pnpm workspace monorepo** to maintain code modularity, enable efficient code sharing, and provide reproducible builds across all platform components.

### Planned Directory Layout

- **`apps/*`**: User-facing applications and core services (e.g., Web dashboard, API gateway). *(Planned)*
- **`workers/*`**: Asynchronous background workers, security analysis jobs, and event consumers. *(Planned)*
- **`packages/*`**: Shared internal libraries, type definitions, security rules, and utility packages. *(Planned)*

> [!NOTE]
> All applications, background workers, and shared packages listed above are planned architecture components. No application code has been implemented yet.

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

## Development Status

- **Status**: Workspace initialization phase (Task 0.2 completed).
- Foundational pnpm monorepo structure, TypeScript base configuration, and root workspace controls are established. Application implementation has not yet started.
