import { Router } from 'express';
import type { HealthDependencies } from '../modules/health/health.controller.js';
import { createHealthRouter } from '../modules/health/health.routes.js';

export interface ApiRouterDependencies {
  health?: HealthDependencies;
}

/**
 * Creates the versioned API router with optional dependency overrides for testing.
 */
export function createApiRouter(dependencies: ApiRouterDependencies = {}): Router {
  const router: Router = Router();

  // Mount module routes
  router.use(createHealthRouter(dependencies.health));

  return router;
}

export const apiRouter: Router = createApiRouter();
