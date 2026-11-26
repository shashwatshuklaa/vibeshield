import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { AuthError } from '../modules/auth/auth.types.js';

function normalizeHttpOrigin(raw: string): string | null {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

function getRequestSelfOrigin(req: Request): string | null {
  const host = req.get('host');
  if (!host) {
    return null;
  }
  return normalizeHttpOrigin(`${req.protocol}://${host}`);
}

/**
 * Verifies Origin / Referer / Sec-Fetch-Site headers on cookie-authenticated
 * state-changing endpoints to prevent cross-site and sibling-subdomain CSRF attacks.
 */
export function createVerifyOriginMiddleware(allowedOrigins: string[] = []): RequestHandler {
  const allowedSet = new Set(
    allowedOrigins
      .map((origin) => normalizeHttpOrigin(origin))
      .filter((origin): origin is string => origin !== null)
  );

  return (req: Request, _res: Response, next: NextFunction): void => {
    const secFetchSite = req.headers['sec-fetch-site'];
    if (secFetchSite === 'cross-site') {
      next(new AuthError(403, 'FORBIDDEN_ORIGIN', 'Invalid request origin'));
      return;
    }

    const originHeader = req.headers.origin;
    const refererHeader = req.headers.referer;
    const selfOrigin = getRequestSelfOrigin(req);

    const isAllowedOrigin = (candidate: string | null): boolean => {
      if (!candidate) {
        return false;
      }
      return allowedSet.has(candidate) || (selfOrigin !== null && candidate === selfOrigin);
    };

    if (originHeader !== undefined) {
      const normalized =
        typeof originHeader === 'string' ? normalizeHttpOrigin(originHeader) : null;
      if (!isAllowedOrigin(normalized)) {
        next(new AuthError(403, 'FORBIDDEN_ORIGIN', 'Invalid request origin'));
        return;
      }
      next();
      return;
    }

    if (refererHeader !== undefined) {
      const normalized =
        typeof refererHeader === 'string' ? normalizeHttpOrigin(refererHeader) : null;
      if (!isAllowedOrigin(normalized)) {
        next(new AuthError(403, 'FORBIDDEN_ORIGIN', 'Invalid request origin'));
        return;
      }
      next();
      return;
    }

    if (secFetchSite === 'same-site') {
      next(new AuthError(403, 'FORBIDDEN_ORIGIN', 'Invalid request origin'));
      return;
    }

    next();
  };
}
