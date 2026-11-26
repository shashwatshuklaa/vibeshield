import { Router } from 'express';
import { createAuthenticateMiddleware } from '../../middlewares/authenticate.js';
import { createVerifyOriginMiddleware } from '../../middlewares/verify-origin.js';
import { createAuthController } from './auth.controller.js';
import { createAuthService, type AuthService } from './auth.service.js';
import type { AuthRuntimeConfig } from './auth.types.js';

export interface AuthRouterDependencies {
  authService?: AuthService;
  config?: AuthRuntimeConfig;
}

/**
 * Creates the authentication router (`/auth/*`) with injectable service/config for testing.
 */
export function createAuthRouter(dependencies: AuthRouterDependencies = {}): Router {
  const router: Router = Router();
  const authService =
    dependencies.authService ?? createAuthService({ config: dependencies.config });
  const controller = createAuthController(authService, dependencies.config);
  const authenticate = createAuthenticateMiddleware(authService);
  const verifyOrigin = createVerifyOriginMiddleware(dependencies.config?.allowedOrigins ?? []);

  router.post('/register', controller.register);
  router.post('/login', controller.login);
  router.post('/refresh', verifyOrigin, controller.refresh);
  router.get('/me', authenticate, controller.me);
  router.post('/logout', verifyOrigin, controller.logout);

  return router;
}
