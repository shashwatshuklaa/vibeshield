import type { CookieOptions, NextFunction, Request, Response } from 'express';
import { extractBearerToken } from '../../middlewares/authenticate.js';
import { loginSchema, registerSchema } from './auth.schemas.js';
import type { AuthService } from './auth.service.js';
import { AuthError, REFRESH_TOKEN_COOKIE_NAME, type AuthRuntimeConfig } from './auth.types.js';

function getRefreshCookieOptions(config?: AuthRuntimeConfig): CookieOptions {
  return {
    httpOnly: true,
    secure: config?.isProduction ?? process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: config?.cookiePath ?? '/api/v1/auth',
  };
}

function readRefreshTokenCookie(req: Request): string | undefined {
  const cookies = req.cookies as Record<string, unknown> | undefined;
  const rawToken = cookies?.[REFRESH_TOKEN_COOKIE_NAME];
  return typeof rawToken === 'string' && rawToken.length > 0 ? rawToken : undefined;
}

/**
 * Creates thin HTTP controllers for authentication endpoints.
 */
export function createAuthController(authService: AuthService, config?: AuthRuntimeConfig) {
  const baseCookieOptions = getRefreshCookieOptions(config);

  const setRefreshCookie = (res: Response, refreshToken: string, expiresAt: Date): void => {
    res.cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken, {
      ...baseCookieOptions,
      expires: expiresAt,
      maxAge: Math.max(0, expiresAt.getTime() - Date.now()),
    });
  };

  const clearRefreshCookie = (res: Response): void => {
    res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, baseCookieOptions);
  };

  return {
    async register(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const parsed = registerSchema.parse(req.body);
        const user = await authService.register(parsed);
        res.status(201).json({ user });
      } catch (error) {
        next(error);
      }
    },

    async login(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const parsed = loginSchema.parse(req.body);
        const result = await authService.login(parsed);

        setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);

        res.status(200).json({
          user: result.user,
          accessToken: result.accessToken,
          expiresIn: result.expiresIn,
        });
      } catch (error) {
        next(error);
      }
    },

    async refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const refreshToken = readRefreshTokenCookie(req);
        if (!refreshToken) {
          clearRefreshCookie(res);
          next(new AuthError(401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired session'));
          return;
        }

        const result = await authService.refresh(refreshToken);
        setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);

        res.status(200).json({
          accessToken: result.accessToken,
          expiresIn: result.expiresIn,
        });
      } catch (error) {
        clearRefreshCookie(res);
        next(error);
      }
    },

    me(req: Request, res: Response, next: NextFunction): void {
      if (!req.auth) {
        next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
        return;
      }

      res.status(200).json({
        user: req.auth.user,
      });
    },

    async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const rawAuthHeader = req.headers.authorization;
        const accessToken = extractBearerToken(rawAuthHeader);

        if (rawAuthHeader !== undefined && accessToken === null) {
          clearRefreshCookie(res);
          next(new AuthError(401, 'UNAUTHORIZED', 'Authentication required'));
          return;
        }

        const refreshToken = readRefreshTokenCookie(req);
        await authService.logout({
          accessToken: accessToken ?? undefined,
          refreshToken,
        });

        clearRefreshCookie(res);
        res.status(200).json({
          message: 'Logged out successfully',
        });
      } catch (error) {
        clearRefreshCookie(res);
        next(error);
      }
    },
  };
}
