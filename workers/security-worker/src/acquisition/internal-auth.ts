import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isValidObjectId } from '@vibeshield/database';

export const INTERNAL_WORKER_SERVICE_ID = 'security-worker' as const;
export const INTERNAL_SCAN_ACQUIRE_PATH = '/internal/v1/scans/acquire' as const;

export const INTERNAL_SERVICE_HEADER = 'x-vibeshield-service' as const;
export const INTERNAL_TIMESTAMP_HEADER = 'x-vibeshield-timestamp' as const;
export const INTERNAL_NONCE_HEADER = 'x-vibeshield-nonce' as const;
export const INTERNAL_SIGNATURE_HEADER = 'x-vibeshield-signature' as const;
export const INTERNAL_AUTH_SIGNATURE_PREFIX = 'sha256=' as const;

export const MIN_INTERNAL_AUTH_SECRET_LENGTH = 32;
export const MIN_LEASE_TOKEN_LENGTH = 16;
export const MAX_LEASE_TOKEN_LENGTH = 256;

const NONCE_BYTES = 24;
const NONCE_FORMAT_REGEX = /^[A-Za-z0-9._-]{16,128}$/;
const SIGNATURE_HEX_REGEX = /^sha256=([a-f0-9]{64})$/;
const TIMESTAMP_MS_REGEX = /^\d{10,16}$/;

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
  serviceId?: typeof INTERNAL_WORKER_SERVICE_ID;
  timestamp: number | string;
  nonce: string;
  rawBody: Buffer | string;
}

export interface SignedInternalWorkerRequest {
  serviceId: typeof INTERNAL_WORKER_SERVICE_ID;
  timestamp: string;
  nonce: string;
  signature: string;
  bodySha256Hex: string;
}

export interface SignedAcquireRequestArtifacts {
  rawBodyBuffer: Buffer;
  headers: Record<string, string>;
  serviceId: typeof INTERNAL_WORKER_SERVICE_ID;
  timestamp: string;
  nonce: string;
  signature: string;
  bodySha256Hex: string;
}

/**
 * Generates a cryptographically random URL-safe nonce accepted by the API internal auth middleware.
 */
export function generateInternalAuthNonce(): string {
  return randomBytes(NONCE_BYTES).toString('base64url');
}

/**
 * Computes lowercase hex SHA-256 over the exact HTTP request body bytes.
 */
export function computeInternalBodySha256Hex(rawBody: Buffer | string): string {
  const buf = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody;
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Builds the canonical signing string matching the API middleware byte-for-byte:
 * `METHOD\nPATH\nSERVICE_ID\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX`.
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
 * Computes an internal HMAC-SHA256 signature over canonical request metadata and exact raw bytes.
 * Never embeds or returns the signing secret in the returned structure.
 */
export function signInternalWorkerRequest(
  input: SignInternalWorkerRequestInput
): SignedInternalWorkerRequest {
  if (
    typeof input.secret !== 'string' ||
    input.secret.trim().length < MIN_INTERNAL_AUTH_SECRET_LENGTH
  ) {
    throw new Error(
      `Internal worker signing secret must be at least ${MIN_INTERNAL_AUTH_SECRET_LENGTH} non-whitespace characters.`
    );
  }

  const timestamp = String(input.timestamp);
  if (!TIMESTAMP_MS_REGEX.test(timestamp)) {
    throw new Error('Internal authentication timestamp must be a 10-16 digit epoch value.');
  }

  if (!NONCE_FORMAT_REGEX.test(input.nonce)) {
    throw new Error('Internal authentication nonce format is invalid.');
  }

  const serviceId = input.serviceId ?? INTERNAL_WORKER_SERVICE_ID;
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

/**
 * Verifies an internal worker HMAC-SHA256 signature using constant-time digest comparison.
 */
export function verifyInternalWorkerSignature(input: {
  secret: string;
  method: string;
  path: string;
  serviceId: string;
  timestamp: string;
  nonce: string;
  rawBody: Buffer | string;
  signatureHeader: string;
}): boolean {
  if (
    typeof input.secret !== 'string' ||
    input.secret.trim().length < MIN_INTERNAL_AUTH_SECRET_LENGTH
  ) {
    return false;
  }

  if (
    !TIMESTAMP_MS_REGEX.test(input.timestamp) ||
    !NONCE_FORMAT_REGEX.test(input.nonce) ||
    input.serviceId !== INTERNAL_WORKER_SERVICE_ID
  ) {
    return false;
  }

  const signatureMatch = SIGNATURE_HEX_REGEX.exec(input.signatureHeader);
  if (!signatureMatch?.[1]) {
    return false;
  }

  const providedDigest = Buffer.from(signatureMatch[1], 'hex');
  const bodySha256Hex = computeInternalBodySha256Hex(input.rawBody);
  const canonical = buildInternalWorkerCanonicalString({
    method: input.method,
    path: input.path,
    serviceId: input.serviceId,
    timestamp: input.timestamp,
    nonce: input.nonce,
    bodySha256Hex,
  });
  const expectedDigest = createHmac('sha256', input.secret).update(canonical, 'utf8').digest();

  return (
    expectedDigest.length === providedDigest.length &&
    timingSafeEqual(expectedDigest, providedDigest)
  );
}

/**
 * Serializes `{ scanId, leaseToken }` once to exact UTF-8 JSON bytes and signs those exact bytes
 * for `POST /internal/v1/scans/acquire`.
 */
export function buildSignedAcquireRequest(input: {
  scanId: string;
  leaseToken: string;
  workerAuthSecret: string;
  now?: () => number;
  nonceGenerator?: () => string;
}): SignedAcquireRequestArtifacts {
  if (
    typeof input.scanId !== 'string' ||
    input.scanId.trim() !== input.scanId ||
    !isValidObjectId(input.scanId)
  ) {
    throw new Error('scanId must be a valid 24-character ObjectId string.');
  }

  if (
    typeof input.leaseToken !== 'string' ||
    input.leaseToken.length < MIN_LEASE_TOKEN_LENGTH ||
    input.leaseToken.length > MAX_LEASE_TOKEN_LENGTH
  ) {
    throw new Error(
      `leaseToken must be between ${MIN_LEASE_TOKEN_LENGTH} and ${MAX_LEASE_TOKEN_LENGTH} characters.`
    );
  }

  const now = input.now ?? (() => Date.now());
  const nonceGenerator = input.nonceGenerator ?? generateInternalAuthNonce;

  // Serialize once so the exact transmitted payload buffer is hashed and signed.
  const rawBodyBuffer = Buffer.from(
    JSON.stringify({
      scanId: input.scanId,
      leaseToken: input.leaseToken,
    }),
    'utf8'
  );

  const signed = signInternalWorkerRequest({
    secret: input.workerAuthSecret,
    method: 'POST',
    path: INTERNAL_SCAN_ACQUIRE_PATH,
    serviceId: INTERNAL_WORKER_SERVICE_ID,
    timestamp: String(now()),
    nonce: nonceGenerator(),
    rawBody: rawBodyBuffer,
  });

  return {
    rawBodyBuffer,
    headers: {
      'content-type': 'application/json',
      'content-length': String(rawBodyBuffer.byteLength),
      [INTERNAL_SERVICE_HEADER]: signed.serviceId,
      [INTERNAL_TIMESTAMP_HEADER]: signed.timestamp,
      [INTERNAL_NONCE_HEADER]: signed.nonce,
      [INTERNAL_SIGNATURE_HEADER]: signed.signature,
    },
    serviceId: signed.serviceId,
    timestamp: signed.timestamp,
    nonce: signed.nonce,
    signature: signed.signature,
    bodySha256Hex: signed.bodySha256Hex,
  };
}
