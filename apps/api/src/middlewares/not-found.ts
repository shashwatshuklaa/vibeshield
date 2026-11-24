import type { Request, Response } from 'express';

/**
 * Fallback 404 handler for unmatched routes.
 * Returns a standardized JSON error response.
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `Cannot ${req.method} ${req.originalUrl || req.url}`,
    },
  });
}
