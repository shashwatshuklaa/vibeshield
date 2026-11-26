import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AuthService } from '../modules/auth/auth.service.js';
import { AuthError } from '../modules/auth/auth.types.js';

/**
 * Extracts a Bearer token from an Authorization header if properly formatted.
 */
export function extractBearerToken(authorizationHeader?: string): string | null {
  if (typeof authorizationHeader !== 'string') {
    return null;
  }

  const trimmed = authorizationHeader.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) {
    return null;
  }

  const token = trimmed.slice(7).trim();
  if (token.length === 0 || /\s/.test(token)) {
    return null;
  }

  return token;
}

/**
 * Creates Express middleware enforcing Bearer JWT + active session + active user checks.
 */
export function createAuthenticateMiddleware(
  authService: Pick<AuthService, 'authenticateAccessToken'>
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = extractBearerToken(req.headers.authorization);
      if (!token) {
        next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
        return;
      }

      req.auth = await authService.authenticateAccessToken(token);
      next();
    } catch (error) {
      if (error instanceof AuthError) {
        next(error);
        return;
      }
      next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
    }
  };
}
