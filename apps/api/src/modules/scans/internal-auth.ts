import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import {
  InternalAuthReplayProtectionError,
  type ConsumeInternalAuthNonceResult,
} from '@vibeshield/queue';
import { HttpError } from '../../utils/http-error.js';

export const INTERNAL_SERVICE_IDS = ['security-worker'] as const;
export type InternalServiceId = (typeof INTERNAL_SERVICE_IDS)[number];

export const INTERNAL_SERVICE_HEADER = 'x-vibeshield-service';
export const INTERNAL_TIMESTAMP_HEADER = 'x-vibeshield-timestamp';
export const INTERNAL_NONCE_HEADER = 'x-vibeshield-nonce';
export const INTERNAL_SIGNATURE_HEADER = 'x-vibeshield-signature';
export const INTERNAL_AUTH_SIGNATURE_PREFIX = 'sha256=';

const TIMESTAMP_MS_REGEX = /^\d{10,16}$/;
const NONCE_FORMAT_REGEX = /^[A-Za-z0-9._-]{16,128}$/;
const SIGNATURE_HEX_REGEX = /^sha256=([a-f0-9]{64})$/;
const MIN_INTERNAL_SECRET_LENGTH = 32;

export interface AuthenticatedInternalCaller {
  serviceId: InternalServiceId;
  timestampMs: number;
  nonce: string;
}

export interface InternalAuthenticatedRequest extends Request {
  internalAuth?: AuthenticatedInternalCaller;
  rawBody?: Buffer;
}

export interface BuildInternalCanonicalRequestInput {
  method: string;
  path: string;
  serviceId: string;
  timestamp: string;
  nonce: string;
  bodySha256Hex: string;
}

export interface SignInternalWorkerRequestInput {
  secret: string;
  method: string;
  path: string;
  serviceId?: InternalServiceId;
  timestamp: number | string;
  nonce: string;
  rawBody: Buffer | string;
}

export interface InternalWorkerAuthMiddlewareOptions {
  workerAuthSecret: string;
  timestampToleranceMs?: number;
  nonceTtlMs?: number;
  allowedServices?: readonly InternalServiceId[];
  consumeNonce: (input: {
    nonce: string;
    ttlMs: number;
    namespace: string;
  }) => Promise<ConsumeInternalAuthNonceResult>;
  now?: () => number;
}

/**
 * Computes lowercase hex SHA-256 over the exact HTTP request body bytes.
 */
export function computeInternalBodySha256Hex(rawBody: Buffer | string): string {
  const buf = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody;
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Builds the canonical signing string binding HTTP method, exact path, caller service identity,
 * millisecond timestamp, single-use nonce, and raw body SHA-256 digest.
 */
export function buildInternalWorkerCanonicalString(
  input: BuildInternalCanonicalRequestInput
): string {
  return [
    input.method.toUpperCase(),
    input.path,
    input.serviceId,
    input.timestamp,
    input.nonce,
    input.bodySha256Hex,
  ].join('\n');
}

/**
 * Signs an internal worker-to-API request using HMAC-SHA256 over the canonical request string.
 */
export function signInternalWorkerRequest(input: SignInternalWorkerRequestInput): {
  serviceId: InternalServiceId;
  timestamp: string;
  nonce: string;
  signature: string;
  bodySha256Hex: string;
} {
  if (typeof input.secret !== 'string' || input.secret.trim().length < MIN_INTERNAL_SECRET_LENGTH) {
    throw new Error(
      'Internal worker signing secret must be at least 32 non-whitespace characters.'
    );
  }

  const serviceId = input.serviceId ?? 'security-worker';
  const timestamp = String(input.timestamp);
  const bodySha256Hex = computeInternalBodySha256Hex(input.rawBody);
  const canonical = buildInternalWorkerCanonicalString({
    method: input.method,
    path: input.path,
    serviceId,
    timestamp,
    nonce: input.nonce,
    bodySha256Hex,
  });
  const hmacHex = createHmac('sha256', input.secret).update(canonical, 'utf8').digest('hex');

  return {
    serviceId,
    timestamp,
    nonce: input.nonce,
    signature: `${INTERNAL_AUTH_SIGNATURE_PREFIX}${hmacHex}`,
    bodySha256Hex,
  };
}

function readSingleHeader(req: Request, headerName: string): string | null {
  const value = req.headers[headerName];
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function resolveRawRequestBody(req: InternalAuthenticatedRequest): Buffer {
  if (Buffer.isBuffer(req.rawBody)) {
    return req.rawBody;
  }
  if (Buffer.isBuffer(req.body)) {
    return req.body;
  }
  return Buffer.alloc(0);
}

/**
 * Express middleware enforcing mutual service HMAC-SHA256 authentication and Redis-backed
 * fail-closed replay protection on all internal worker endpoints.
 *
 * Authentication order ensures unauthenticated callers cannot pollute Redis nonce storage:
 * 1. Validate required auth headers and known service identity.
 * 2. Validate timestamp freshness within clock-skew tolerance.
 * 3. Verify HMAC-SHA256 over method, exact path, service, timestamp, nonce, and body SHA-256
 *    with constant-time digest comparison.
 * 4. Consume the single-use nonce atomically in Redis (`SET NX PX`), failing closed (`503`)
 *    if Redis is unavailable and rejecting replays (`401`).
 */
export function createRequireInternalWorkerAuthMiddleware(
  options: InternalWorkerAuthMiddlewareOptions
): RequestHandler {
  if (
    typeof options.workerAuthSecret !== 'string' ||
    options.workerAuthSecret.trim().length < MIN_INTERNAL_SECRET_LENGTH
  ) {
    throw new Error(
      'INTERNAL_WORKER_AUTH_SECRET must be configured with at least 32 non-whitespace characters.'
    );
  }

  const timestampToleranceMs = options.timestampToleranceMs ?? 30_000;
  const nonceTtlMs = options.nonceTtlMs ?? timestampToleranceMs * 2 + 5_000;
  const allowedServices = new Set<string>(options.allowedServices ?? INTERNAL_SERVICE_IDS);
  const now = options.now ?? (() => Date.now());

  return async (req: InternalAuthenticatedRequest, _res: Response, next: NextFunction) => {
    const serviceId = readSingleHeader(req, INTERNAL_SERVICE_HEADER);
    const timestampRaw = readSingleHeader(req, INTERNAL_TIMESTAMP_HEADER);
    const nonce = readSingleHeader(req, INTERNAL_NONCE_HEADER);
    const signatureHeader = readSingleHeader(req, INTERNAL_SIGNATURE_HEADER);

    if (!serviceId || !timestampRaw || !nonce || !signatureHeader) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_MISSING_HEADERS',
          'Missing required internal service authentication headers.'
        )
      );
      return;
    }

    if (!allowedServices.has(serviceId)) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_INVALID_SERVICE',
          'Unrecognized internal service caller identity.'
        )
      );
      return;
    }

    if (!TIMESTAMP_MS_REGEX.test(timestampRaw)) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_INVALID_TIMESTAMP',
          'Internal authentication timestamp format is invalid.'
        )
      );
      return;
    }

    const timestampMs = Number(timestampRaw);
    const currentNowMs = now();
    if (
      !Number.isSafeInteger(timestampMs) ||
      Math.abs(currentNowMs - timestampMs) > timestampToleranceMs
    ) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_EXPIRED_TIMESTAMP',
          'Internal request timestamp is outside the allowed clock-skew window.'
        )
      );
      return;
    }

    if (!NONCE_FORMAT_REGEX.test(nonce)) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_INVALID_NONCE',
          'Internal authentication nonce format is invalid.'
        )
      );
      return;
    }

    const signatureMatch = SIGNATURE_HEX_REGEX.exec(signatureHeader);
    if (!signatureMatch?.[1]) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_INVALID_SIGNATURE',
          'Internal request signature format is invalid.'
        )
      );
      return;
    }

    const providedDigest = Buffer.from(signatureMatch[1], 'hex');
    const rawBody = resolveRawRequestBody(req);
    const bodySha256Hex = computeInternalBodySha256Hex(rawBody);
    const canonical = buildInternalWorkerCanonicalString({
      method: req.method,
      path: req.originalUrl,
      serviceId,
      timestamp: timestampRaw,
      nonce,
      bodySha256Hex,
    });
    const expectedDigest = createHmac('sha256', options.workerAuthSecret)
      .update(canonical, 'utf8')
      .digest();

    if (
      expectedDigest.length !== providedDigest.length ||
      !timingSafeEqual(expectedDigest, providedDigest)
    ) {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_INVALID_SIGNATURE',
          'Internal request signature verification failed.'
        )
      );
      return;
    }

    let replayResult: ConsumeInternalAuthNonceResult;
    try {
      replayResult = await options.consumeNonce({
        nonce,
        ttlMs: nonceTtlMs,
        namespace: serviceId,
      });
    } catch (error) {
      if (error instanceof InternalAuthReplayProtectionError) {
        next(
          new HttpError(
            503,
            'INTERNAL_AUTH_REPLAY_UNAVAILABLE',
            'Internal authentication replay protection store is unavailable.'
          )
        );
        return;
      }
      next(
        new HttpError(
          503,
          'INTERNAL_AUTH_REPLAY_UNAVAILABLE',
          'Internal authentication replay protection check failed.'
        )
      );
      return;
    }

    if (replayResult === 'REPLAYED') {
      next(
        new HttpError(
          401,
          'INTERNAL_AUTH_NONCE_REPLAYED',
          'Internal authentication nonce has already been used.'
        )
      );
      return;
    }

    req.internalAuth = {
      serviceId: serviceId as InternalServiceId,
      timestampMs,
      nonce,
    };

    next();
  };
}
