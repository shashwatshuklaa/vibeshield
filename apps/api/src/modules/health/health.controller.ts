import type { Request, Response } from 'express';
import {
  getDatabaseStatus,
  type DatabaseConnectionState,
  type DatabaseConnectionStatus,
} from '@vibeshield/database';

export interface HealthCheckResponse {
  status: 'ok';
  service: 'vibeshield-api';
  timestamp: string;
  uptime: number;
  environment: string;
  version: string;
}

export interface ReadinessCheckResponse {
  status: 'ready' | 'not_ready';
  service: 'vibeshield-api';
  timestamp: string;
  checks: {
    database: {
      status: 'up' | 'down';
      state: DatabaseConnectionState;
    };
  };
}

export interface HealthDependencies {
  getDatabaseStatus?: () => DatabaseConnectionStatus;
}

/**
 * Liveness handler indicating process operability.
 * Explicitly independent of MongoDB availability.
 */
export function getLivenessStatus(_req: Request, res: Response): void {
  const response: HealthCheckResponse = {
    status: 'ok',
    service: 'vibeshield-api',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    version: '0.1.0',
  };

  res.status(200).json(response);
}

/**
 * Backward-compatible alias for the root `/health` endpoint.
 */
export const getHealthStatus = getLivenessStatus;

/**
 * Creates a readiness check handler verifying MongoDB connectivity.
 * Returns HTTP 200 when connected and HTTP 503 when unavailable or disconnected.
 */
export function createReadinessHandler(
  dependencies: HealthDependencies = {}
): (_req: Request, res: Response) => void {
  const resolveDatabaseStatus = dependencies.getDatabaseStatus ?? getDatabaseStatus;

  return (_req: Request, res: Response): void => {
    let dbState: DatabaseConnectionState = 'disconnected';
    let isDbConnected = false;

    try {
      const dbStatus = resolveDatabaseStatus();
      dbState = dbStatus.state;
      isDbConnected = dbStatus.isConnected;
    } catch {
      dbState = 'disconnected';
      isDbConnected = false;
    }

    const response: ReadinessCheckResponse = {
      status: isDbConnected ? 'ready' : 'not_ready',
      service: 'vibeshield-api',
      timestamp: new Date().toISOString(),
      checks: {
        database: {
          status: isDbConnected ? 'up' : 'down',
          state: dbState,
        },
      },
    };

    res.status(isDbConnected ? 200 : 503).json(response);
  };
}
