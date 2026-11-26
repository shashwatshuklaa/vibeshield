import type {} from 'express';
import type { UserStatus } from '@vibeshield/database';
import { HttpError } from '../../utils/http-error.js';

export const REFRESH_TOKEN_COOKIE_NAME = 'vs_refresh_token';

/**
 * Safe public representation of an authenticated user.
 */
export interface PublicUser {
  id: string;
  email: string;
  displayName: string;
  status: UserStatus;
  createdAt: Date;
}

/**
 * Authenticated request context attached by the authentication middleware.
 */
export interface AuthContext {
  user: PublicUser;
  sessionId: string;
}

/**
 * Validated runtime configuration for JWT issuance and refresh cookies.
 */
export interface AuthRuntimeConfig {
  jwtAccessSecret: string;
  jwtAccessTtl: string;
  jwtAccessTtlSeconds: number;
  jwtIssuer: string;
  jwtAudience: string;
  refreshTokenTtlSeconds: number;
  isProduction: boolean;
  cookiePath: string;
  allowedOrigins?: string[];
}

export interface RegisterInput {
  email: string;
  displayName: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface LoginResult {
  user: PublicUser;
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: Date;
}

export interface RefreshResult {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: Date;
}

export interface LogoutInput {
  accessToken?: string;
  refreshToken?: string;
}

/**
 * Operational error thrown by authentication and authorization components.
 * Guarantees safe client-facing error messages without stack or secret leakage.
 */
export class AuthError extends HttpError {
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(statusCode, code, message, details);
    this.name = 'AuthError';
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}
