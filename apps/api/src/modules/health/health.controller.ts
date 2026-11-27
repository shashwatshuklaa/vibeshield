import type { Request, Response } from 'express';
import {
  getDatabaseStatus,
  type DatabaseConnectionState,
  type DatabaseConnectionStatus,
} from '@vibeshield/database';
import type { RedisConnectionState, RedisConnectionStatus } from '@vibeshield/queue';

export interface HealthCheckResponse {
  status: 'ok';
  service: 'vibeshield-api';
  timestamp: string;
  uptime: number;
  environment: string;
  version: string;
}

export type QueueReadinessStatus = 'disabled' | 'connected' | 'unavailable' | 'not_initialized';

export interface ReadinessCheckResponse {
  status: 'ready' | 'not_ready';
  service: 'vibeshield-api';
  timestamp: string;
  checks: {
    database: {
      status: 'up' | 'down';
      state: DatabaseConnectionState;
    };
    queue: {
      status: QueueReadinessStatus;
      state: RedisConnectionState;
      required: boolean;
    };
  };
}

export interface HealthDependencies {
  getDatabaseStatus?: () => DatabaseConnectionStatus;
  getQueueStatus?: () => RedisConnectionStatus & { required?: boolean };
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
  const resolveQueueStatus = dependencies.getQueueStatus;

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

    let queueCheckStatus: QueueReadinessStatus = 'disabled';
    let queueConnectionState: RedisConnectionState = 'disabled';
    let queueRequired = false;

    if (resolveQueueStatus) {
      try {
        const qStatus = resolveQueueStatus();
        queueRequired = Boolean(qStatus.required);
        if (!qStatus.enabled) {
          queueCheckStatus = 'disabled';
          queueConnectionState = 'disabled';
        } else if (qStatus.isConnected) {
          queueCheckStatus = 'connected';
          queueConnectionState = qStatus.state;
        } else if (qStatus.state === 'not_initialized') {
          queueCheckStatus = 'not_initialized';
          queueConnectionState = 'not_initialized';
        } else {
          queueCheckStatus = 'unavailable';
          queueConnectionState = qStatus.state;
        }
      } catch {
        queueCheckStatus = 'unavailable';
        queueConnectionState = 'unavailable';
      }
    }

    const queueBlocksReadiness = queueRequired && queueCheckStatus !== 'connected';
    const isOverallReady = isDbConnected && !queueBlocksReadiness;

    const response: ReadinessCheckResponse = {
      status: isOverallReady ? 'ready' : 'not_ready',
      service: 'vibeshield-api',
      timestamp: new Date().toISOString(),
      checks: {
        database: {
          status: isDbConnected ? 'up' : 'down',
          state: dbState,
        },
        queue: {
          status: queueCheckStatus,
          state: queueConnectionState,
          required: queueRequired,
        },
      },
    };

    res.status(isOverallReady ? 200 : 503).json(response);
  };
}
