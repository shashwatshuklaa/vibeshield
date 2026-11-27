import express, { type Express } from 'express';
import helmet from 'helmet';
import { errorHandler } from './middlewares/error-handler.js';
import { notFoundHandler } from './middlewares/not-found.js';
import type {
  CreateInternalScanAcquisitionServiceOptions,
  InternalScanAcquisitionService,
} from './modules/scans/internal-acquisition.service.js';
import type { InternalWorkerAuthMiddlewareOptions } from './modules/scans/internal-auth.js';
import { createInternalScanRouter } from './modules/scans/internal-scan.routes.js';

export interface CreateInternalAppOptions {
  auth: InternalWorkerAuthMiddlewareOptions;
  bodyLimit?: string;
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

/**
 * Creates and configures the isolated internal-only Express application for trusted worker calls.
 *
 * Isolation guarantees:
 * - Mounted ONLY on a dedicated loopback/private HTTP server (`INTERNAL_API_HOST:INTERNAL_API_PORT`),
 *   never onto the public API router or `createApp()`.
 * - Exposes no public auth, org, project, webhook, or health routes.
 * - Captures raw request bytes before JSON parsing so HMAC-SHA256 verification and Redis replay
 *   protection execute prior to any JSON deserialization or schema validation.
 */
export function createInternalApp(options: CreateInternalAppOptions): Express {
  const { auth, bodyLimit = '16kb', ...scanRouterOptions } = options;

  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());

  app.use(
    express.raw({
      type: '*/*',
      limit: bodyLimit,
    })
  );

  app.use(
    '/internal/v1/scans',
    createInternalScanRouter({
      auth,
      ...scanRouterOptions,
    })
  );

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
