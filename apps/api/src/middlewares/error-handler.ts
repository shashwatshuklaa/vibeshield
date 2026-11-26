import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { HttpError } from '../utils/http-error.js';

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
    stack?: string;
  };
}

/**
 * Centralized error-handling middleware.
 * Formats errors into a predictable JSON shape and prevents leaking internal details in production.
 */
export function errorHandler(
  err: Error & { status?: number; statusCode?: number; code?: string },
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  if (err instanceof HttpError) {
    const body: ApiErrorResponse = {
      error: {
        code: err.code,
        message: err.message,
      },
    };
    if (err.details !== undefined) {
      body.error.details = err.details;
    }
    res.status(err.statusCode).json(body);
    return;
  }

  if (err instanceof ZodError) {
    const fieldErrors = err.issues.map((issue) => ({
      field: issue.path.join('.') || 'body',
      message: issue.message,
    }));

    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: fieldErrors,
      },
    });
    return;
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const statusCode = err.status || err.statusCode || 500;
  const isClientError = statusCode >= 400 && statusCode < 500;

  // In production, mask unexpected 5xx internal server errors
  const message =
    isProduction && !isClientError
      ? 'Internal Server Error'
      : err.message || 'An unexpected error occurred';

  const code = err.code || (isClientError ? 'CLIENT_ERROR' : 'INTERNAL_SERVER_ERROR');

  const responseBody: ApiErrorResponse = {
    error: {
      code,
      message,
    },
  };

  // Stack traces are strictly excluded in production
  if (!isProduction && err.stack) {
    responseBody.error.stack = err.stack;
  }

  res.status(statusCode).json(responseBody);
}
