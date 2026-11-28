import type { NextFunction, Request, RequestHandler, Response } from 'express';
import {
  consumeScanCreationRateLimit,
  type RedisConnectionManager,
  type ScanRateLimitDecision,
} from '@vibeshield/queue';
import { AuthError } from '../modules/auth/auth.types.js';
import { OrganizationError } from '../modules/organizations/organization.types.js';
import { HttpError } from '../utils/http-error.js';

export const DEFAULT_SCAN_CREATE_RATE_LIMIT_MAX_REQUESTS = 10;
export const DEFAULT_SCAN_CREATE_RATE_LIMIT_WINDOW_MS = 60_000;

export type ScanCreationRateLimitConsumer = (input: {
  organizationId: string;
  userId: string;
  maxRequests: number;
  windowMs: number;
}) => Promise<ScanRateLimitDecision>;

export interface ScanCreationRateLimiterOptions {
  maxRequests?: number;
  windowMs?: number;
  consumeRateLimit?: ScanCreationRateLimitConsumer;
}

/**
 * Creates a fail-closed rate-limiting middleware for public scan creation,
 * scoped per authenticated `(organizationId, userId)` pair.
 *
 * Security invariants:
 * - Must run AFTER `authenticate`, `requireOrgMembership`, and `requireOrganizationPermission(SCAN_CREATE)`
 *   so unauthenticated/unauthorized callers are rejected before touching rate-limit state.
 * - Fails closed (`503 RATE_LIMIT_UNAVAILABLE`) whenever no rate-limit backend is configured
 *   or when the backend throws / is unavailable.
 */
export function createScanCreationRateLimiter(
  options: ScanCreationRateLimiterOptions = {}
): RequestHandler {
  const maxRequests = options.maxRequests ?? DEFAULT_SCAN_CREATE_RATE_LIMIT_MAX_REQUESTS;
  const windowMs = options.windowMs ?? DEFAULT_SCAN_CREATE_RATE_LIMIT_WINDOW_MS;
  const consumeRateLimit = options.consumeRateLimit;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const userId = req.auth?.user.id;
    if (!userId) {
      next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
      return;
    }

    const organizationId = req.organizationAuth?.organization.id;
    if (!organizationId) {
      next(new OrganizationError(404, 'ORGANIZATION_NOT_FOUND', 'Organization not found'));
      return;
    }

    if (!consumeRateLimit) {
      next(
        new HttpError(
          503,
          'RATE_LIMIT_UNAVAILABLE',
          'Scan creation rate limiting is temporarily unavailable'
        )
      );
      return;
    }

    let decision: ScanRateLimitDecision;
    try {
      decision = await consumeRateLimit({
        organizationId,
        userId,
        maxRequests,
        windowMs,
      });
    } catch {
      next(
        new HttpError(
          503,
          'RATE_LIMIT_UNAVAILABLE',
          'Scan creation rate limiting is temporarily unavailable'
        )
      );
      return;
    }

    res.setHeader('X-RateLimit-Limit', String(decision.limit));
    res.setHeader('X-RateLimit-Remaining', String(decision.remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(decision.resetAtMs / 1000)));

    if (!decision.allowed) {
      res.setHeader('Retry-After', String(decision.retryAfterSeconds));
      next(
        new HttpError(
          429,
          'RATE_LIMIT_EXCEEDED',
          'Too many scan creation requests. Please try again later.'
        )
      );
      return;
    }

    next();
  };
}

/**
 * Convenience factory binding `createScanCreationRateLimiter` to a `RedisConnectionManager`.
 * Fails closed with `503 RATE_LIMIT_UNAVAILABLE` whenever Redis is disconnected or errors.
 */
export function createRedisScanCreationRateLimiter(
  redisManager: Pick<RedisConnectionManager, 'isConnected' | 'getQueueClient'>,
  options: Omit<ScanCreationRateLimiterOptions, 'consumeRateLimit'> = {}
): RequestHandler {
  return createScanCreationRateLimiter({
    ...options,
    consumeRateLimit: (input) => consumeScanCreationRateLimit(redisManager, input),
  });
}
