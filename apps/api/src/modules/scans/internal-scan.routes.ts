import { Router, type NextFunction, type Response } from 'express';
import {
  verifyScanAcquisitionAuthorization,
  type ScanAcquisitionDenialReason,
  type VerifyScanAcquisitionAuthorizationInput,
  type VerifyScanAcquisitionAuthorizationResult,
} from '@vibeshield/database';
import { HttpError } from '../../utils/http-error.js';
import {
  createRequireInternalWorkerAuthMiddleware,
  type InternalAuthenticatedRequest,
  type InternalWorkerAuthMiddlewareOptions,
} from './internal-auth.js';
import { internalScanAcquireRequestSchema } from './internal-scan.schemas.js';

export interface InternalScanRouterDependencies {
  auth: InternalWorkerAuthMiddlewareOptions;
  verifyAuthorization?: (
    input: VerifyScanAcquisitionAuthorizationInput
  ) => Promise<VerifyScanAcquisitionAuthorizationResult>;
}

const DENIAL_STATUS_MAP: Record<ScanAcquisitionDenialReason, { status: number; code: string }> = {
  SCAN_NOT_FOUND: { status: 404, code: 'SCAN_NOT_FOUND' },
  PROJECT_NOT_FOUND: { status: 404, code: 'PROJECT_NOT_FOUND' },
  CONNECTION_NOT_FOUND: { status: 404, code: 'REPOSITORY_CONNECTION_NOT_FOUND' },
  INSTALLATION_NOT_FOUND: { status: 404, code: 'GITHUB_INSTALLATION_NOT_FOUND' },
  WORKER_MISMATCH: { status: 403, code: 'SCAN_WORKER_MISMATCH' },
  INVALID_LEASE_TOKEN: { status: 403, code: 'INVALID_SCAN_LEASE_TOKEN' },
  PROJECT_ARCHIVED: { status: 403, code: 'PROJECT_ARCHIVED' },
  CONNECTION_INACTIVE: { status: 403, code: 'REPOSITORY_CONNECTION_INACTIVE' },
  CONNECTION_METADATA_MISMATCH: { status: 403, code: 'REPOSITORY_BINDING_MISMATCH' },
  INSTALLATION_UNAVAILABLE: { status: 403, code: 'GITHUB_INSTALLATION_UNAVAILABLE' },
  INSTALLATION_MISMATCH: { status: 403, code: 'GITHUB_INSTALLATION_MISMATCH' },
  SCAN_NOT_ACQUIRING: { status: 409, code: 'SCAN_NOT_ACQUIRING' },
  SCAN_INACTIVE: { status: 409, code: 'SCAN_INACTIVE' },
  SCAN_CANCELLED: { status: 409, code: 'SCAN_CANCELLED' },
  INVALID_ATTEMPT_STATE: { status: 409, code: 'SCAN_ATTEMPT_INVALID' },
  LEASE_MISSING: { status: 409, code: 'SCAN_LEASE_MISSING' },
  LEASE_EXPIRED: { status: 409, code: 'SCAN_LEASE_EXPIRED' },
};

function parseStrictJsonBody(req: InternalAuthenticatedRequest): unknown {
  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.');
  }

  const rawBuf = Buffer.isBuffer(req.body)
    ? req.body
    : Buffer.isBuffer(req.rawBody)
      ? req.rawBody
      : Buffer.alloc(0);

  if (rawBuf.length === 0) {
    throw new HttpError(400, 'INVALID_JSON', 'Request body must be a non-empty JSON object.');
  }

  try {
    return JSON.parse(rawBuf.toString('utf8'));
  } catch {
    throw new HttpError(400, 'INVALID_JSON', 'Malformed JSON request payload.');
  }
}

/**
 * Creates the internal scan lifecycle router mounted exclusively on `createInternalApp()`.
 */
export function createInternalScanRouter(deps: InternalScanRouterDependencies): Router {
  const router = Router();
  const requireInternalAuth = createRequireInternalWorkerAuthMiddleware(deps.auth);
  const verifyAuthorization = deps.verifyAuthorization ?? verifyScanAcquisitionAuthorization;

  router.post(
    '/acquire',
    requireInternalAuth,
    async (req: InternalAuthenticatedRequest, res: Response, next: NextFunction) => {
      try {
        if (!req.internalAuth) {
          throw new HttpError(
            401,
            'INTERNAL_AUTH_REQUIRED',
            'Authenticated internal service caller context is missing.'
          );
        }

        const rawJson = parseStrictJsonBody(req);
        const parsedBody = internalScanAcquireRequestSchema.safeParse(rawJson);
        if (!parsedBody.success) {
          next(parsedBody.error);
          return;
        }

        const authResult = await verifyAuthorization({
          scanId: parsedBody.data.scanId,
          leaseToken: parsedBody.data.leaseToken,
          workerId: req.internalAuth.serviceId,
        });

        if (authResult.status === 'DENIED') {
          const mapped = DENIAL_STATUS_MAP[authResult.reason];
          next(new HttpError(mapped.status, mapped.code, authResult.message));
          return;
        }

        // Task 1.7.3.3.1 boundary: authorization verified without minting GitHub tokens
        // or proxying repository archives yet. Never echo secrets, leaseToken, or credentials.
        res.status(501).json({
          error: {
            code: 'ACQUISITION_NOT_IMPLEMENTED',
            message:
              'Scan acquisition authorization succeeded, but repository archive streaming is not yet enabled.',
          },
          authorization: {
            status: 'AUTHORIZED',
            scanId: authResult.context.scanId,
            organizationId: authResult.context.organizationId,
            projectId: authResult.context.projectId,
            repositoryConnectionId: authResult.context.repositoryConnectionId,
            githubInstallationId: authResult.context.githubInstallationId,
            githubRepositoryId: authResult.context.githubRepositoryId,
            requestedRef: authResult.context.requestedRef,
            attemptCount: authResult.context.attemptCount,
            workerId: authResult.context.workerId,
          },
        });
      } catch (error) {
        next(error);
      }
    }
  );

  return router;
}
