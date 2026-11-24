import express, { type Express } from 'express';
import helmet from 'helmet';
import { apiRouter } from './routes/index.js';
import { notFoundHandler } from './middlewares/not-found.js';
import { errorHandler } from './middlewares/error-handler.js';

export interface CreateAppOptions {
  apiPrefix?: string;
  bodyLimit?: string;
}

/**
 * Creates and configures the Express application instance.
 * Decoupled from network port listening for easy, fast integration testing.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const { apiPrefix = '/api/v1', bodyLimit = '1mb' } = options;
  const app = express();

  // 1. Security Headers via Helmet
  app.use(helmet());

  // 2. Request body parsing with strict payload limit
  app.use(express.json({ limit: bodyLimit }));

  // 3. Root service info endpoint
  app.get('/', (_req, res) => {
    res.status(200).json({
      name: 'VibeShield API',
      status: 'operational',
      version: '0.1.0',
      docs: `${apiPrefix}/health`,
    });
  });

  // 4. API v1 routes
  app.use(apiPrefix, apiRouter);

  // 5. 404 Handler for unmatched routes
  app.use(notFoundHandler);

  // 6. Centralized Error Handler (must be registered last with 4 arguments)
  app.use(errorHandler);

  return app;
}
