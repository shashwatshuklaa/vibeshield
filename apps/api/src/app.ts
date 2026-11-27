import express, { type Express } from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import type { GitHubRuntimeConfig } from './config/env.js';
import type { AuthRouterDependencies } from './modules/auth/auth.routes.js';
import type { AuthRuntimeConfig } from './modules/auth/auth.types.js';
import type { GitHubService } from './modules/github/github.service.js';
import type { HealthDependencies } from './modules/health/health.controller.js';
import type { OrganizationRouterDependencies } from './modules/organizations/organization.routes.js';
import type { ProjectService } from './modules/projects/project.service.js';
import { createApiRouter } from './routes/index.js';
import { notFoundHandler } from './middlewares/not-found.js';
import { errorHandler } from './middlewares/error-handler.js';

export interface CreateAppOptions {
  apiPrefix?: string;
  bodyLimit?: string;
  health?: HealthDependencies;
  auth?: AuthRouterDependencies;
  authConfig?: AuthRuntimeConfig;
  organizations?: OrganizationRouterDependencies;
  projectService?: ProjectService;
  githubService?: GitHubService;
  githubConfig?: GitHubRuntimeConfig | null;
}

/**
 * Creates and configures the Express application instance.
 * Decoupled from network port listening and database connection for fast integration testing.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const {
    apiPrefix = '/api/v1',
    bodyLimit = '1mb',
    health,
    auth,
    authConfig,
    organizations,
    projectService,
    githubService,
    githubConfig,
  } = options;
  const app = express();

  // 1. Security Headers via Helmet
  app.use(helmet());

  // 2. Request body and cookie parsing with strict payload limit
  app.use(express.json({ limit: bodyLimit }));
  app.use(cookieParser());

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
  const resolvedAuthDeps = auth ?? (authConfig ? { config: authConfig } : undefined);
  const resolvedOrgDeps: OrganizationRouterDependencies | undefined = organizations
    ? {
        ...organizations,
        ...(projectService && !organizations.projectService ? { projectService } : {}),
        ...(githubService && !organizations.githubService ? { githubService } : {}),
        ...(githubConfig !== undefined && organizations.githubConfig === undefined
          ? { githubConfig }
          : {}),
      }
    : resolvedAuthDeps || projectService || githubService || githubConfig !== undefined
      ? {
          authService: resolvedAuthDeps?.authService,
          authConfig: resolvedAuthDeps?.config,
          projectService,
          githubService,
          githubConfig,
        }
      : undefined;

  app.use(
    apiPrefix,
    createApiRouter({
      health,
      auth: resolvedAuthDeps,
      organizations: resolvedOrgDeps,
    })
  );

  // 5. 404 Handler for unmatched routes
  app.use(notFoundHandler);

  // 6. Centralized Error Handler (must be registered last with 4 arguments)
  app.use(errorHandler);

  return app;
}
