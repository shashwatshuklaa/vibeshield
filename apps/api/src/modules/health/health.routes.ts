import { Router } from 'express';
import {
  createReadinessHandler,
  getHealthStatus,
  getLivenessStatus,
  type HealthDependencies,
} from './health.controller.js';

/**
 * Creates the health router with liveness and readiness endpoints.
 * Supports dependency injection for testing readiness states without a live database.
 */
export function createHealthRouter(dependencies: HealthDependencies = {}): Router {
  const router: Router = Router();

  router.get('/health', getHealthStatus);
  router.get('/health/live', getLivenessStatus);
  router.get('/health/ready', createReadinessHandler(dependencies));

  return router;
}

export const healthRouter: Router = createHealthRouter();
