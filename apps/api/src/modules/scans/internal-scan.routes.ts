import { Router, type NextFunction, type Response } from 'express';
import { HttpError } from '../../utils/http-error.js';
import {
  createInternalScanAcquisitionService,
  type CreateInternalScanAcquisitionServiceOptions,
  type InternalScanAcquisitionService,
} from './internal-acquisition.service.js';
import {
  createRequireInternalWorkerAuthMiddleware,
  type InternalAuthenticatedRequest,
  type InternalWorkerAuthMiddlewareOptions,
} from './internal-auth.js';
import { internalScanAcquireRequestSchema } from './internal-scan.schemas.js';

export interface InternalScanRouterDependencies {
  auth: InternalWorkerAuthMiddlewareOptions;
  acquisitionService?: InternalScanAcquisitionService;
  githubClient?: CreateInternalScanAcquisitionServiceOptions['githubClient'];
  verifyAuthorization?: CreateInternalScanAcquisitionServiceOptions['verifyAuthorization'];
  setResolvedCommitWithLease?: CreateInternalScanAcquisitionServiceOptions['setResolvedCommitWithLease'];
  maxArchiveBytes?: number;
  githubRequestTimeoutMs?: number;
  codeloadTimeoutMs?: number;
  totalAcquisitionTimeoutMs?: number;
  revalidationIntervalMs?: number;
}

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
  const acquisitionService =
    deps.acquisitionService ??
    createInternalScanAcquisitionService({
      githubClient: deps.githubClient ?? null,
      verifyAuthorization: deps.verifyAuthorization,
      setResolvedCommitWithLease: deps.setResolvedCommitWithLease,
      maxArchiveBytes: deps.maxArchiveBytes,
      githubRequestTimeoutMs: deps.githubRequestTimeoutMs,
      codeloadTimeoutMs: deps.codeloadTimeoutMs,
      totalAcquisitionTimeoutMs: deps.totalAcquisitionTimeoutMs,
      revalidationIntervalMs: deps.revalidationIntervalMs,
    });

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

        await acquisitionService.acquireAndStreamArchive({
          req,
          res,
          scanId: parsedBody.data.scanId,
          leaseToken: parsedBody.data.leaseToken,
          workerId: req.internalAuth.serviceId,
        });
      } catch (error) {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        next(error);
      }
    }
  );

  return router;
}
