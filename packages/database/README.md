# `@vibeshield/database`

Shared MongoDB connectivity, connection lifecycle management, and core Mongoose domain models for VibeShield Node.js services.

## Responsibilities

### 1. Connection Lifecycle Management
- Establish and manage MongoDB connections via Mongoose (`connectDatabase`, `DatabaseConnectionManager`).
- Expose normalized connection state and readiness status (`getDatabaseState`, `isDatabaseConnected`, `getDatabaseStatus`).
- Deduplicate concurrent or repeated connection and disconnection calls.
- Support graceful shutdown without hanging processes.
- Validate MongoDB connection URI syntax (`isValidMongoUri`).
- Redact MongoDB URIs and credentials from logs and error messages (`redactMongoUri`, `formatSafeError`).

### 2. Core Multi-Tenant Domain Models
- **`UserModel`** (`users` collection): Platform user identity, normalized email, credential hash storage (`select: false` + serialization redaction), and account status (`ACTIVE`, `INACTIVE`, `SUSPENDED`).
- **`OrganizationModel`** (`organizations` collection): Top-level tenant boundary with globally unique normalized slug and creator reference.
- **`OrganizationMembershipModel`** (`organization_memberships` collection): Explicit many-to-many join model linking users to organizations with controlled roles (`OWNER`, `ADMIN`, `MEMBER`, `VIEWER`) and membership status (`ACTIVE`, `INVITED`, `SUSPENDED`).
- **`ProjectModel`** (`projects` collection): Tenant-owned project record scoped to an `Organization`, with organization-scoped unique slug, creator reference, and non-destructive `archivedAt` timestamp.
- **`SessionModel`** (`sessions` collection): Refresh-token session store tracking `userId`, SHA-256 `refreshTokenHash` (`select: false`), `previousRefreshTokenHash` (`select: false`) for atomic `N-1` rotation reuse detection, `expiresAt` (with TTL index), `revokedAt`, and `lastUsedAt`.
- **`RotatedRefreshTokenModel`** (`rotated_refresh_tokens` collection): Bounded TTL-indexed token-family store recording older rotated `tokenHash` values per `sessionId` so replays from `N-2` or earlier revoke the session without unbounded growth on `Session` documents.

> [!NOTE]
> Importing `@vibeshield/database` or its models never automatically initiates a database connection. Connections are established only when the host application explicitly invokes `connectDatabase()` or `manager.connect()`.

## Non-Responsibilities

This package deliberately excludes:
- Authentication, password hashing, or JWT issuance logic.
- Express or HTTP framework dependencies and authorization middleware.
- Application environment loading (callers pass the connection URI explicitly).
- Premature repository, scan execution, or vulnerability finding models.

## Data Model Relationships

```mermaid
erDiagram
  USER ||--o{ ORGANIZATION_MEMBERSHIP : "belongs to orgs via"
  ORGANIZATION ||--o{ ORGANIZATION_MEMBERSHIP : "has members via"
  USER ||--o{ ORGANIZATION : "createdBy"
  ORGANIZATION ||--o{ PROJECT : "owns"
  USER ||--o{ PROJECT : "createdBy"
  USER ||--o{ SESSION : "owns sessions"

  USER {
    ObjectId _id PK
    string email UK "normalized lowercase"
    string displayName
    string passwordHash "select: false, redacted on JSON"
    string status "ACTIVE | INACTIVE | SUSPENDED"
    Date createdAt
    Date updatedAt
  }

  ORGANIZATION {
    ObjectId _id PK
    string name
    string slug UK "normalized lowercase"
    ObjectId createdBy FK "ref: User"
    Date createdAt
    Date updatedAt
  }

  ORGANIZATION_MEMBERSHIP {
    ObjectId _id PK
    ObjectId userId FK "ref: User"
    ObjectId organizationId FK "ref: Organization"
    string role "OWNER | ADMIN | MEMBER | VIEWER"
    string status "ACTIVE | INVITED | SUSPENDED"
    Date createdAt
    Date updatedAt
  }

  PROJECT {
    ObjectId _id PK
    ObjectId organizationId FK "ref: Organization"
    string name
    string slug "unique per organizationId"
    string description
    ObjectId createdBy FK "ref: User"
    Date archivedAt "nullable soft archive"
    Date createdAt
    Date updatedAt
  }

  SESSION {
    ObjectId _id PK
    ObjectId userId FK "ref: User"
    string refreshTokenHash UK "SHA-256, select: false"
    string previousRefreshTokenHash "SHA-256, select: false"
    Date expiresAt "TTL index"
    Date revokedAt "nullable revocation timestamp"
    Date lastUsedAt "nullable"
    Date createdAt
    Date updatedAt
  }
```

## Indexes and Uniqueness Constraints

| Model | Index Keys | Unique | Index Name | Purpose |
| --- | --- | --- | --- | --- |
| `User` | `{ email: 1 }` | Yes | `users_email_unique` | Enforce unique normalized email & fast account lookup |
| `User` | `{ status: 1 }` | No | `users_status_idx` | Operational queries by user status |
| `Organization` | `{ slug: 1 }` | Yes | `organizations_slug_unique` | Global tenant slug uniqueness & routing lookup |
| `Organization` | `{ createdBy: 1 }` | No | `organizations_created_by_idx` | Lookup organizations created by a user |
| `OrganizationMembership` | `{ organizationId: 1, userId: 1 }` | Yes | `org_memberships_org_user_unique` | Prevent duplicate memberships & check user access in org |
| `OrganizationMembership` | `{ userId: 1, status: 1 }` | No | `org_memberships_user_status_idx` | List active organizations for a user |
| `OrganizationMembership` | `{ organizationId: 1, role: 1, status: 1 }` | No | `org_memberships_org_role_status_idx` | Query active roles (e.g., active `OWNER` count) in an org |
| `Project` | `{ organizationId: 1, slug: 1 }` | Yes | `projects_org_slug_unique` | Organization-scoped project slug uniqueness & lookup |
| `Project` | `{ organizationId: 1, archivedAt: 1, createdAt: -1 }` | No | `projects_org_archived_created_idx` | Paginated listing of active/archived projects per org |
| `Project` | `{ createdBy: 1 }` | No | `projects_created_by_idx` | Audit lookup of projects by creator |
| `Session` | `{ refreshTokenHash: 1 }` | Yes | `sessions_refresh_token_hash_unique` | Unique hashed refresh token lookup |
| `Session` | `{ previousRefreshTokenHash: 1 }` | No (Partial) | `sessions_prev_refresh_token_hash_idx` | Detect reuse of rotated refresh tokens |
| `Session` | `{ userId: 1, revokedAt: 1, expiresAt: 1 }` | No | `sessions_user_active_idx` | Query active sessions for a user |
| `Session` | `{ expiresAt: 1 }` | No (TTL `0s`) | `sessions_expires_at_ttl_idx` | Background cleanup of expired session documents |
| `RotatedRefreshToken` | `{ tokenHash: 1 }` | Yes | `rotated_tokens_hash_unique` | Unique lookup of previously rotated refresh token hashes |
| `RotatedRefreshToken` | `{ sessionId: 1 }` | No | `rotated_tokens_session_idx` | Link rotated token hashes back to parent session |
| `RotatedRefreshToken` | `{ expiresAt: 1 }` | No (TTL `0s`) | `rotated_tokens_expires_at_ttl_idx` | Automatic TTL cleanup bounding token-family storage |

## Multi-Tenancy & Service-Layer Guidance

- **Tenant isolation**: Every `Project` strictly requires `organizationId`. API services must always scope project queries and mutations by `organizationId` after verifying an `ACTIVE` `OrganizationMembership` for the authenticated `userId`.
- **Creator membership boundary**: Storing `organizationId` and `createdBy` on `Project` does **not** prove at the schema level that the creator belongs to that organization. Service-layer handlers must verify active `OrganizationMembership` in `organizationId` before creating or modifying a project.
- **Multi-org users**: Membership lives in `OrganizationMembershipModel` rather than embedding org lists on `User` or member arrays on `Organization`, allowing users to hold distinct roles across any number of organizations.
- **Ownership consistency**: `Organization.createdBy` is creator provenance, not a substitute for an active `OWNER` membership. Future service operations must create the `Organization` and its initial `OWNER` `OrganizationMembership` together (preferably inside a MongoDB transaction) and prevent removing or demoting the last `ACTIVE` `OWNER` of an organization.
- **Update & `.lean()` precautions**: Mongoose runs schema setters (`normalizeEmail`, `normalizeSlug`, `trim`, `lowercase`) during standard update casting, but update queries (`updateOne`, `findOneAndUpdate`, `updateMany`) do **not** run schema validators by default unless `{ runValidators: true }` is passed. Likewise, `.lean()` queries bypass Mongoose `toJSON`/`toObject` transforms—never serialize `.lean()` documents that explicitly selected `+passwordHash`.
- **Transaction support**: `runInTransaction(work)` executes multi-document operations inside `session.withTransaction()` and always closes the session. MongoDB transactions require a **replica set or sharded cluster** and never silently fall back to non-transactional writes.
- **No model recompilation errors**: Models are registered via `getOrCreateModel()` to safely handle repeated imports or watch-mode reloads.

## Usage

```ts
import {
  connectDatabase,
  disconnectDatabase,
  UserModel,
  OrganizationModel,
  OrganizationMembershipModel,
  OrganizationRoleValue,
  ProjectModel,
} from '@vibeshield/database';

await connectDatabase(process.env.MONGODB_URI!);
// Use UserModel, OrganizationModel, OrganizationMembershipModel, ProjectModel
await disconnectDatabase();
```

## Known Limitations

- Schema-level unit tests verify Mongoose schema definitions, validators, normalizers, serialization transforms, and index metadata in memory without a running MongoDB server.
- Actual unique index creation (`E11000` duplicate key enforcement), multi-document transactions, and query plan execution require a live MongoDB replica set instance.
- `ProjectModel` currently omits repository integration fields (`repositoryUrl`, `defaultBranch`) intentionally; future repository integration tasks will extend `ProjectSchema` without breaking existing tenant isolation.

## Running Tests & Checks

```bash
pnpm --filter @vibeshield/database test
pnpm --filter @vibeshield/database typecheck
pnpm --filter @vibeshield/database build
```
