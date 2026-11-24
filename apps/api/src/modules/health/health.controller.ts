import type { Request, Response } from 'express';

export interface HealthCheckResponse {
  status: 'ok';
  service: 'vibeshield-api';
  timestamp: string;
  uptime: number;
  environment: string;
  version: string;
}

/**
 * Health check handler indicating process operability.
 * Explicitly decoupled from external dependencies (DB/Redis) which are not yet integrated.
 */
export function getHealthStatus(_req: Request, res: Response): void {
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
