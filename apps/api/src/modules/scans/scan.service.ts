import {
  acquireOrganizationMutationLock,
  createQueuedScanWithOutbox,
  findScanByIdInOrganization,
  getEffectiveConnectionStatus,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  isValidObjectId,
  listScansPagedByProjectInOrganization,
  OrganizationMembershipModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  requestScanCancellation,
  runInTransaction,
} from '@vibeshield/database';

type TransactionSession = Parameters<Parameters<typeof runInTransaction>[0]>[0];
import {
  hasOrganizationPermission,
  OrganizationPermission,
  type OrganizationPermissionType,
} from '../organizations/organization.permissions.js';
import { OrganizationError } from '../organizations/organization.types.js';
import type { PublicScanRecord } from '@vibeshield/types';
import { ScanError } from './scan.types.js';
import type {
  CreateScanInput,
  ListScansQuery,
  PaginatedScansResult,
  CancelScanInput,
} from './scan.types.js';

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

function assertValidProjectIdentifier(projectId: string): void {
  if (!isValidObjectId(projectId)) {
    throw new ScanError(400, 'VALIDATION_ERROR', 'Invalid project identifier', [
      { field: 'projectId', message: 'Project ID must be a valid ObjectId' },
    ]);
  }
}

function assertValidScanIdentifier(scanId: string): void {
  if (!isValidObjectId(scanId)) {
    throw new ScanError(400, 'VALIDATION_ERROR', 'Invalid scan identifier', [
      { field: 'scanId', message: 'Scan ID must be a valid ObjectId' },
    ]);
  }
}

/**
 * Acquires the per-organization mutation lock and re-validates actor membership + permission
 * inside the active MongoDB transaction so concurrent membership removal or role demotion
 * cannot be bypassed via middleware TOCTOU.
 */
async function assertActorPermissionInOrganizationTx(
  actorUserId: string,
  organizationId: string,
  permission: OrganizationPermissionType,
  session: TransactionSession
): Promise<void> {
  const locked = await acquireOrganizationMutationLock(organizationId, session);
  if (!locked) {
    throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
  }

  const membership = await OrganizationMembershipModel.findOne({
    organizationId,
    userId: actorUserId,
    status: 'ACTIVE',
  })
    .session(session)
    .lean();

  if (!membership) {
    throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
  }

  if (
    !hasOrganizationPermission(
      membership.role as Parameters<typeof hasOrganizationPermission>[0],
      permission
    )
  ) {
    throw new OrganizationError(403, 'FORBIDDEN', 'Insufficient organization permissions');
  }
}

export interface ScanServiceDependencies {
  now?: () => Date;
}

export interface ScanService {
  createScan(
    actorUserId: string,
    organizationId: string,
    projectId: string,
    input: CreateScanInput
  ): Promise<PublicScanRecord>;

  listScans(
    organizationId: string,
    projectId: string,
    query: ListScansQuery
  ): Promise<PaginatedScansResult>;

  getScan(organizationId: string, projectId: string, scanId: string): Promise<PublicScanRecord>;

  cancelScan(
    actorUserId: string,
    organizationId: string,
    projectId: string,
    scanId: string,
    input: CancelScanInput
  ): Promise<{
    result: 'CANCELLED_IMMEDIATELY' | 'CANCELLATION_REQUESTED';
    scan: PublicScanRecord;
  }>;
}

/**
 * Creates the public scan management service.
 *
 * Security model:
 * - Both `createScan` and `cancelScan` acquire the organization mutation lock inside a
 *   MongoDB transaction and re-validate actor membership + permission before mutating state.
 * - `createScan` verifies the project, active non-archived GitHub repository connection, and
 *   matching active parent GitHub installation before atomically creating the scan + outbox.
 *   Repository identifiers are NEVER accepted from the request body.
 * - `cancelScan` delegates cancellation transitions & outbox suppression to
 *   `requestScanCancellation` within the same authorized transaction.
 * - `listScans` and `getScan` are tenant-scoped reads validating identifiers at the boundary.
 */
export function createScanService(dependencies: ScanServiceDependencies = {}): ScanService {
  const getNow = dependencies.now ?? (() => new Date());

  return {
    async createScan(
      actorUserId: string,
      organizationId: string,
      projectId: string,
      input: CreateScanInput
    ): Promise<PublicScanRecord> {
      if (!isValidObjectId(organizationId) || !isValidObjectId(actorUserId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      assertValidProjectIdentifier(projectId);

      const now = getNow();

      let scan: PublicScanRecord;

      try {
        scan = await runInTransaction(async (session) => {
          // 1. Acquire organization mutation lock and re-validate membership + permission inside tx
          await assertActorPermissionInOrganizationTx(
            actorUserId,
            organizationId,
            OrganizationPermission.SCAN_CREATE,
            session
          );

          // 2. Verify project belongs to org and is not archived
          const project = await ProjectModel.findOne({
            _id: projectId,
            organizationId,
          })
            .session(session)
            .lean();

          if (!project) {
            throw new ScanError(404, 'PROJECT_NOT_FOUND', 'Project not found');
          }
          if (project.archivedAt !== null && project.archivedAt !== undefined) {
            throw new ScanError(
              409,
              'PROJECT_ARCHIVED',
              'Project is archived and cannot accept new scans'
            );
          }

          // 3. Resolve the active repository connection — never trust client-supplied IDs
          const connection = await ProjectRepositoryConnectionModel.findOne({
            organizationId,
            projectId,
            isActive: true,
          })
            .session(session)
            .lean();

          if (!connection) {
            throw new ScanError(
              409,
              'REPOSITORY_NOT_CONNECTED',
              'Project does not have an active GitHub repository connection'
            );
          }

          if (getEffectiveConnectionStatus(connection) !== 'CONNECTED') {
            throw new ScanError(
              409,
              'REPOSITORY_NOT_CONNECTED',
              'Project repository connection is not active'
            );
          }

          if (connection.isArchivedOnGitHub === true) {
            throw new ScanError(
              409,
              'REPOSITORY_ARCHIVED',
              'Connected GitHub repository is archived and cannot accept new scans'
            );
          }

          // 4. Verify parent GitHub installation is active and matches connection metadata
          const installation = await GitHubInstallationModel.findOne({
            _id: connection.installationRecordId,
            organizationId,
          })
            .session(session)
            .lean();

          if (!installation) {
            throw new ScanError(409, 'INSTALLATION_UNAVAILABLE', 'GitHub installation not found');
          }

          if (
            installation.status !== GitHubInstallationStatusValue.ACTIVE ||
            installation.isActive !== true ||
            installation.githubInstallationId !== connection.githubInstallationId
          ) {
            throw new ScanError(
              409,
              'INSTALLATION_UNAVAILABLE',
              'GitHub installation is suspended, revoked, or mismatched'
            );
          }

          // 5. Atomically create scan + outbox record
          const result = await createQueuedScanWithOutbox(
            {
              organizationId,
              projectId,
              repositoryConnectionId: connection._id.toString(),
              githubInstallationId: connection.githubInstallationId,
              githubRepositoryId: connection.githubRepositoryId,
              requestedRef: input.requestedRef,
              triggerSource: 'manual',
              createdByUserId: actorUserId,
              idempotencyKey: input.idempotencyKey ?? null,
              correlationId: input.correlationId ?? null,
              now,
            },
            session
          );

          return result.scan;
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new ScanError(
            409,
            'SCAN_ALREADY_EXISTS',
            'A scan with this idempotency key already exists for this project'
          );
        }
        throw error;
      }

      return scan;
    },

    async listScans(
      organizationId: string,
      projectId: string,
      query: ListScansQuery
    ): Promise<PaginatedScansResult> {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      assertValidProjectIdentifier(projectId);

      const { scans, total } = await listScansPagedByProjectInOrganization({
        organizationId,
        projectId,
        status: query.status as Parameters<
          typeof listScansPagedByProjectInOrganization
        >[0]['status'],
        triggerSource: query.triggerSource as Parameters<
          typeof listScansPagedByProjectInOrganization
        >[0]['triggerSource'],
        page: query.page,
        limit: query.limit,
      });

      const totalPages = total === 0 ? 0 : Math.ceil(total / query.limit);
      return {
        scans,
        pagination: {
          page: query.page,
          limit: query.limit,
          total,
          totalPages,
        },
      };
    },

    async getScan(
      organizationId: string,
      projectId: string,
      scanId: string
    ): Promise<PublicScanRecord> {
      if (!isValidObjectId(organizationId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      assertValidProjectIdentifier(projectId);
      assertValidScanIdentifier(scanId);

      const scan = await findScanByIdInOrganization({ organizationId, projectId, scanId });
      if (!scan) {
        throw new ScanError(404, 'SCAN_NOT_FOUND', 'Scan not found');
      }
      return scan;
    },

    async cancelScan(
      actorUserId: string,
      organizationId: string,
      projectId: string,
      scanId: string,
      input: CancelScanInput
    ): Promise<{
      result: 'CANCELLED_IMMEDIATELY' | 'CANCELLATION_REQUESTED';
      scan: PublicScanRecord;
    }> {
      if (!isValidObjectId(organizationId) || !isValidObjectId(actorUserId)) {
        throw new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found');
      }
      assertValidProjectIdentifier(projectId);
      assertValidScanIdentifier(scanId);

      const now = getNow();
      const outcome = await runInTransaction(async (session) => {
        await assertActorPermissionInOrganizationTx(
          actorUserId,
          organizationId,
          OrganizationPermission.SCAN_CANCEL,
          session
        );

        return await requestScanCancellation(
          {
            scanId,
            organizationId,
            projectId,
            requestedByUserId: actorUserId,
            reason: input.reason ?? null,
            now,
          },
          session
        );
      });

      if (outcome.status === 'NOT_FOUND') {
        throw new ScanError(404, 'SCAN_NOT_FOUND', 'Scan not found');
      }

      if (outcome.status === 'ALREADY_TERMINAL') {
        throw new ScanError(
          409,
          'SCAN_ALREADY_TERMINAL',
          'Scan is already in a terminal state and cannot be cancelled'
        );
      }

      if (outcome.status === 'CANCELLED_IMMEDIATELY') {
        return { result: 'CANCELLED_IMMEDIATELY', scan: outcome.scan };
      }

      return { result: 'CANCELLATION_REQUESTED', scan: outcome.scan };
    },
  };
}
