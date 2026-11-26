import { Router } from 'express';
import { createAuthRouter, type AuthRouterDependencies } from '../modules/auth/auth.routes.js';
import type { HealthDependencies } from '../modules/health/health.controller.js';
import { createHealthRouter } from '../modules/health/health.routes.js';

export interface ApiRouterDependencies {
  health?: HealthDependencies;
  auth?: AuthRouterDependencies;
}

/**
 * Creates the versioned API router with optional dependency overrides for testing.
 */
export function createApiRouter(dependencies: ApiRouterDependencies = {}): Router {
  const router: Router = Router();

  // Mount module routes
  router.use(createHealthRouter(dependencies.health));
  router.use('/auth', createAuthRouter(dependencies.auth));

  return router;
}

export const apiRouter: Router = createApiRouter();
