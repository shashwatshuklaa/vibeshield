import { Router } from 'express';
import { healthRouter } from '../modules/health/health.routes.js';

export const apiRouter: Router = Router();

// Mount module routes
apiRouter.use(healthRouter);
