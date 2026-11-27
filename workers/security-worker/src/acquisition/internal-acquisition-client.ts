import http, { type IncomingMessage } from 'node:http';
import https from 'node:https';
import type { Duplex } from 'node:stream';
import { Readable } from 'node:stream';
import { isValidObjectId } from '@vibeshield/database';
import {
  isValidInternalApiBaseUrl,
  isValidInternalWorkerAuthSecret,
  normalizeInternalApiBaseUrl,
  type WorkerConfig,
} from '../config/env.js';
import { createWorkerLogger, formatSafeWorkerMessage, type WorkerLogger } from '../utils/logger.js';
import {
  buildSignedAcquireRequest,
  INTERNAL_SCAN_ACQUIRE_PATH,
  INTERNAL_WORKER_SERVICE_ID,
  MAX_LEASE_TOKEN_LENGTH,
  MIN_LEASE_TOKEN_LENGTH,
} from './internal-auth.js';

export const HARD_MAX_COMPRESSED_ARCHIVE_BYTES = 100 * 1024 * 1024; // 100 MiB (104,857,600)
export const DEFAULT_INTERNAL_ACQUISITION_CONNECT_TIMEOUT_MS = 10_000;
export const DEFAULT_INTERNAL_ACQUISITION_HEADERS_TIMEOUT_MS = 90_000;
export const DEFAULT_INTERNAL_ACQUISITION_STREAM_IDLE_TIMEOUT_MS = 65_000;
export const DEFAULT_INTERNAL_ACQUISITION_TOTAL_TIMEOUT_MS = 130_000;
export const DEFAULT_INTERNAL_ACQUISITION_STREAM_HIGH_WATER_MARK = 64 * 1024;

export type InternalAcquisitionErrorCode =
  | 'INVALID_CONFIGURATION'
  | 'INTERNAL_API_CONNECTION_FAILED'
  | 'AUTHENTICATION_FAILED'
  | 'REDIRECT_REJECTED'
  | 'UNEXPECTED_HTTP_STATUS'
  | 'INVALID_RESPONSE_HEADERS'
  | 'ARCHIVE_SIZE_EXCEEDED'
  | 'INCOMPLETE_ARCHIVE_RESPONSE'
  | 'ACQUISITION_TIMEOUT'
  | 'ACQUISITION_CANCELLED'
  | 'WORKER_SHUTDOWN';

export type InternalAcquisitionTimeoutPhase = 'connect' | 'headers' | 'idle' | 'total';

export interface InternalAcquisitionErrorOptions {
  httpStatus?: number;
  timeoutPhase?: InternalAcquisitionTimeoutPhase;
  secretsToRedact?: readonly (string | undefined)[];
}

function sanitizeSafeErrorText(
  message: string,
  secretsToRedact: readonly (string | undefined)[] = []
): string {
  const urlSanitized = message.replace(/https?:\/\/[^\s"'<>()]+/gi, (matchedUrl) => {
    try {
      const parsed = new URL(matchedUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return '[REDACTED_URL]';
      }
      const hadQuery = parsed.search.length > 0 || matchedUrl.includes('?');
      const hadFragment = parsed.hash.length > 0 || matchedUrl.includes('#');
      return `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}${
        hadQuery ? '?[REDACTED_QUERY]' : ''
      }${hadFragment ? '#[REDACTED_FRAGMENT]' : ''}`;
    } catch {
      return '[REDACTED_URL]';
    }
  });

  const nonEmptySecrets = secretsToRedact.filter(
    (value): value is string => typeof value === 'string' && value.length > 0
  );
  return formatSafeWorkerMessage(urlSanitized, nonEmptySecrets);
}

/**
 * Operational error raised by the internal repository acquisition client.
 * Guarantees safe static/redacted messages with zero credential, signature, lease-token, or raw body leakage.
 */
export class InternalAcquisitionError extends Error {
  public readonly code: InternalAcquisitionErrorCode;
  public readonly httpStatus?: number;
  public readonly timeoutPhase?: InternalAcquisitionTimeoutPhase;

  constructor(
    code: InternalAcquisitionErrorCode,
    message: string,
    options: InternalAcquisitionErrorOptions = {}
  ) {
    super(sanitizeSafeErrorText(message, options.secretsToRedact));
    this.name = 'InternalAcquisitionError';
    this.code = code;
    if (options.httpStatus !== undefined) {
      this.httpStatus = options.httpStatus;
    }
    if (options.timeoutPhase !== undefined) {
      this.timeoutPhase = options.timeoutPhase;
    }
  }

  public toJSON(): {
    name: string;
    code: InternalAcquisitionErrorCode;
    message: string;
    httpStatus?: number;
    timeoutPhase?: InternalAcquisitionTimeoutPhase;
  } {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      ...(this.httpStatus !== undefined ? { httpStatus: this.httpStatus } : {}),
      ...(this.timeoutPhase !== undefined ? { timeoutPhase: this.timeoutPhase } : {}),
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `[${this.name} (${this.code})]: ${this.message}`;
  }
}

export interface InternalAcquisitionClientConfig {
  readonly baseUrl: string;
  readonly workerAuthSecret: string;
}

/**
 * Extracts validated internal acquisition configuration from `WorkerConfig`, or returns `null` when
 * internal acquisition is unconfigured. Throws `InternalAcquisitionError('INVALID_CONFIGURATION')`
 * if partially or improperly configured.
 */
export function toInternalAcquisitionConfig(
  config: Pick<WorkerConfig, 'internalApiBaseUrl' | 'internalWorkerAuthSecret'>
): InternalAcquisitionClientConfig | null {
  const hasBaseUrl = config.internalApiBaseUrl !== undefined;
  const hasSecret = config.internalWorkerAuthSecret !== undefined;

  if (!hasBaseUrl && !hasSecret) {
    return null;
  }

  if (!hasBaseUrl || !isValidInternalApiBaseUrl(config.internalApiBaseUrl!)) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      'INTERNAL_API_BASE_URL must be configured as a valid HTTP/HTTPS origin without credentials or query strings.',
      { secretsToRedact: [config.internalWorkerAuthSecret] }
    );
  }

  if (!hasSecret || !isValidInternalWorkerAuthSecret(config.internalWorkerAuthSecret!)) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      'INTERNAL_WORKER_AUTH_SECRET must be configured with at least 32 non-whitespace characters.',
      { secretsToRedact: [config.internalWorkerAuthSecret] }
    );
  }

  const resolved: InternalAcquisitionClientConfig = {
    baseUrl: normalizeInternalApiBaseUrl(config.internalApiBaseUrl!),
    workerAuthSecret: config.internalWorkerAuthSecret!,
  };

  return resolved;
}

/**
 * Requires complete, valid internal acquisition configuration from `WorkerConfig`.
 */
export function requireInternalAcquisitionConfig(
  config: Pick<WorkerConfig, 'internalApiBaseUrl' | 'internalWorkerAuthSecret'>
): InternalAcquisitionClientConfig {
  const resolved = toInternalAcquisitionConfig(config);
  if (!resolved) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      'Internal API acquisition configuration (INTERNAL_API_BASE_URL and INTERNAL_WORKER_AUTH_SECRET) is missing.'
    );
  }
  return resolved;
}

export interface InternalAcquisitionClientConfigSummary {
  readonly baseUrl: string;
  readonly endpointPath: typeof INTERNAL_SCAN_ACQUIRE_PATH;
  readonly serviceId: typeof INTERNAL_WORKER_SERVICE_ID;
  readonly maxArchiveBytes: number;
  readonly connectTimeoutMs: number;
  readonly headersTimeoutMs: number;
  readonly streamIdleTimeoutMs: number;
  readonly totalTimeoutMs: number;
}

export interface CreateInternalAcquisitionClientOptions {
  config?: Pick<WorkerConfig, 'internalApiBaseUrl' | 'internalWorkerAuthSecret'>;
  baseUrl?: string;
  workerAuthSecret?: string;
  maxArchiveBytes?: number;
  connectTimeoutMs?: number;
  headersTimeoutMs?: number;
  streamIdleTimeoutMs?: number;
  totalTimeoutMs?: number;
  streamHighWaterMark?: number;
  logger?: WorkerLogger;
  shutdownSignal?: AbortSignal;
  now?: () => number;
  nonceGenerator?: () => string;
  /**
   * Optional custom TCP/TLS socket connector (used in deterministic unit tests for connect timeouts).
   * Host and port are still strictly governed by the validated `baseUrl`.
   */
  createConnection?: http.ClientRequestArgs['createConnection'];
}

export interface AcquireRepositoryArchiveInput {
  scanId: string;
  leaseToken: string;
  signal?: AbortSignal;
  shutdownSignal?: AbortSignal;
}

export interface AcquiredRepositoryArchive {
  readonly scanId: string;
  readonly contentType: string;
  readonly declaredContentLength: number | null;
  readonly maxArchiveBytes: number;
  readonly stream: Readable;
  bytesReceived(): number;
  abort(reason?: 'cancelled' | 'shutdown'): void;
}

export interface InternalAcquisitionClient {
  acquireRepositoryArchive(
    input: AcquireRepositoryArchiveInput
  ): Promise<AcquiredRepositoryArchive>;
  shutdown(): void;
  getConfigSummary(): InternalAcquisitionClientConfigSummary;
  toJSON(): InternalAcquisitionClientConfigSummary;
}

function validatePositiveInt(value: number, fieldName: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      `${fieldName} must be a positive integer.`
    );
  }
  return value;
}

function readSingleResponseHeader(
  rawHeaders: string[],
  headers: IncomingMessage['headers'],
  headerName: string
): { present: boolean; value: string | null; conflict: boolean } {
  const targetLower = headerName.toLowerCase();
  const rawValues: string[] = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const key = rawHeaders[i];
    const val = rawHeaders[i + 1];
    if (typeof key === 'string' && key.toLowerCase() === targetLower && typeof val === 'string') {
      rawValues.push(val);
    }
  }

  if (rawValues.length > 1) {
    return { present: true, value: null, conflict: true };
  }

  const parsedValue = headers[targetLower];
  if (Array.isArray(parsedValue)) {
    return { present: true, value: null, conflict: true };
  }

  if (rawValues.length === 1) {
    return { present: true, value: rawValues[0]!, conflict: false };
  }

  if (typeof parsedValue === 'string') {
    return { present: true, value: parsedValue, conflict: false };
  }

  return { present: false, value: null, conflict: false };
}

interface ValidatedArchiveHeaders {
  contentType: string;
  declaredContentLength: number | null;
}

function validateArchiveResponseHeaders(
  res: IncomingMessage,
  maxArchiveBytes: number
): ValidatedArchiveHeaders {
  // 1. Content-Type must be present, single-valued, and gzip.
  const contentTypeHeader = readSingleResponseHeader(res.rawHeaders, res.headers, 'content-type');
  if (!contentTypeHeader.present || contentTypeHeader.conflict || !contentTypeHeader.value) {
    throw new InternalAcquisitionError(
      'INVALID_RESPONSE_HEADERS',
      'Internal API archive response is missing a valid Content-Type header.',
      { httpStatus: 200 }
    );
  }

  const mediaType = (contentTypeHeader.value.split(';')[0] ?? '').trim().toLowerCase();
  if (mediaType !== 'application/gzip' && mediaType !== 'application/x-gzip') {
    throw new InternalAcquisitionError(
      'INVALID_RESPONSE_HEADERS',
      'Internal API archive response returned an unexpected Content-Type.',
      { httpStatus: 200 }
    );
  }

  // 2. Optional X-Content-Type-Options, Cache-Control, and Content-Disposition integrity checks.
  const xContentTypeOptions = readSingleResponseHeader(
    res.rawHeaders,
    res.headers,
    'x-content-type-options'
  );
  if (xContentTypeOptions.present) {
    if (
      xContentTypeOptions.conflict ||
      xContentTypeOptions.value?.trim().toLowerCase() !== 'nosniff'
    ) {
      throw new InternalAcquisitionError(
        'INVALID_RESPONSE_HEADERS',
        'Internal API archive response has an invalid X-Content-Type-Options header.',
        { httpStatus: 200 }
      );
    }
  }

  const cacheControl = readSingleResponseHeader(res.rawHeaders, res.headers, 'cache-control');
  if (cacheControl.present) {
    if (cacheControl.conflict || !cacheControl.value?.toLowerCase().includes('no-store')) {
      throw new InternalAcquisitionError(
        'INVALID_RESPONSE_HEADERS',
        'Internal API archive response has an invalid Cache-Control header.',
        { httpStatus: 200 }
      );
    }
  }

  // 3. Content-Length (optional in chunked mode; strictly validated when present).
  const contentLengthHeader = readSingleResponseHeader(
    res.rawHeaders,
    res.headers,
    'content-length'
  );
  let declaredContentLength: number | null = null;

  if (contentLengthHeader.present) {
    if (contentLengthHeader.conflict || contentLengthHeader.value === null) {
      throw new InternalAcquisitionError(
        'INVALID_RESPONSE_HEADERS',
        'Internal API archive response returned conflicting Content-Length headers.',
        { httpStatus: 200 }
      );
    }

    const trimmedLength = contentLengthHeader.value.trim();
    if (!/^\d+$/.test(trimmedLength)) {
      throw new InternalAcquisitionError(
        'INVALID_RESPONSE_HEADERS',
        'Internal API archive response returned a malformed Content-Length header.',
        { httpStatus: 200 }
      );
    }

    const parsedLength = Number(trimmedLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength <= 0) {
      throw new InternalAcquisitionError(
        'INVALID_RESPONSE_HEADERS',
        'Internal API archive response returned an invalid zero or out-of-range Content-Length.',
        { httpStatus: 200 }
      );
    }

    if (parsedLength > maxArchiveBytes) {
      throw new InternalAcquisitionError(
        'ARCHIVE_SIZE_EXCEEDED',
        'Repository archive Content-Length exceeds maximum allowed compressed size limit.',
        { httpStatus: 200 }
      );
    }

    declaredContentLength = parsedLength;
  }

  return {
    contentType: mediaType,
    declaredContentLength,
  };
}

function mapNonSuccessHttpStatus(statusCode: number): InternalAcquisitionError {
  if (statusCode >= 300 && statusCode < 400) {
    return new InternalAcquisitionError(
      'REDIRECT_REJECTED',
      'Internal API acquisition endpoint attempted an unauthorized HTTP redirect.',
      { httpStatus: statusCode }
    );
  }

  if (statusCode === 401 || statusCode === 403) {
    return new InternalAcquisitionError(
      'AUTHENTICATION_FAILED',
      'Internal API rejected worker authentication or scan lease authorization.',
      { httpStatus: statusCode }
    );
  }

  if (statusCode === 413) {
    return new InternalAcquisitionError(
      'ARCHIVE_SIZE_EXCEEDED',
      'Repository archive exceeds maximum allowed compressed size limit.',
      { httpStatus: statusCode }
    );
  }

  return new InternalAcquisitionError(
    'UNEXPECTED_HTTP_STATUS',
    `Internal API acquisition endpoint returned unexpected HTTP status ${statusCode}.`,
    { httpStatus: statusCode }
  );
}

/**
 * Creates a reusable, non-buffering HTTP client bound to the fixed internal acquisition endpoint
 * (`POST /internal/v1/scans/acquire`) with strict HMAC signing, fail-closed redirect rejection,
 * bounded timeouts, byte counting, backpressure propagation, and truncation detection.
 */
export function createInternalAcquisitionClient(
  options: CreateInternalAcquisitionClientOptions
): InternalAcquisitionClient {
  const rawBaseUrl = options.baseUrl ?? options.config?.internalApiBaseUrl;
  const rawSecret = options.workerAuthSecret ?? options.config?.internalWorkerAuthSecret;

  if (!rawBaseUrl || !isValidInternalApiBaseUrl(rawBaseUrl)) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      'Internal acquisition client requires a valid HTTP/HTTPS baseUrl without credentials, queries, or fragments.',
      { secretsToRedact: [rawSecret] }
    );
  }

  if (!rawSecret || !isValidInternalWorkerAuthSecret(rawSecret)) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      'Internal acquisition client requires a workerAuthSecret of at least 32 non-whitespace characters.',
      { secretsToRedact: [rawSecret] }
    );
  }

  const normalizedBaseUrl = normalizeInternalApiBaseUrl(rawBaseUrl);
  const parsedBaseUrl = new URL(normalizedBaseUrl);
  // Keep secret solely inside closure scope; never assign onto returned objects.
  const workerAuthSecret = rawSecret;

  const maxArchiveBytes = options.maxArchiveBytes ?? HARD_MAX_COMPRESSED_ARCHIVE_BYTES;
  if (
    !Number.isSafeInteger(maxArchiveBytes) ||
    maxArchiveBytes < 1 ||
    maxArchiveBytes > HARD_MAX_COMPRESSED_ARCHIVE_BYTES
  ) {
    throw new InternalAcquisitionError(
      'INVALID_CONFIGURATION',
      `maxArchiveBytes must be an integer between 1 and ${HARD_MAX_COMPRESSED_ARCHIVE_BYTES} bytes.`
    );
  }

  const connectTimeoutMs = validatePositiveInt(
    options.connectTimeoutMs ?? DEFAULT_INTERNAL_ACQUISITION_CONNECT_TIMEOUT_MS,
    'connectTimeoutMs'
  );
  const headersTimeoutMs = validatePositiveInt(
    options.headersTimeoutMs ?? DEFAULT_INTERNAL_ACQUISITION_HEADERS_TIMEOUT_MS,
    'headersTimeoutMs'
  );
  const streamIdleTimeoutMs = validatePositiveInt(
    options.streamIdleTimeoutMs ?? DEFAULT_INTERNAL_ACQUISITION_STREAM_IDLE_TIMEOUT_MS,
    'streamIdleTimeoutMs'
  );
  const totalTimeoutMs = validatePositiveInt(
    options.totalTimeoutMs ?? DEFAULT_INTERNAL_ACQUISITION_TOTAL_TIMEOUT_MS,
    'totalTimeoutMs'
  );
  const streamHighWaterMark = validatePositiveInt(
    options.streamHighWaterMark ?? DEFAULT_INTERNAL_ACQUISITION_STREAM_HIGH_WATER_MARK,
    'streamHighWaterMark'
  );

  const logger = options.logger ?? createWorkerLogger('warn', [workerAuthSecret]);
  const clientShutdownController = new AbortController();
  const targetUrl = new URL(INTERNAL_SCAN_ACQUIRE_PATH, parsedBaseUrl);

  const configSummary: InternalAcquisitionClientConfigSummary = Object.freeze({
    baseUrl: normalizedBaseUrl,
    endpointPath: INTERNAL_SCAN_ACQUIRE_PATH,
    serviceId: INTERNAL_WORKER_SERVICE_ID,
    maxArchiveBytes,
    connectTimeoutMs,
    headersTimeoutMs,
    streamIdleTimeoutMs,
    totalTimeoutMs,
  });

  const client: InternalAcquisitionClient = {
    getConfigSummary(): InternalAcquisitionClientConfigSummary {
      return configSummary;
    },

    toJSON(): InternalAcquisitionClientConfigSummary {
      return configSummary;
    },

    shutdown(): void {
      if (!clientShutdownController.signal.aborted) {
        clientShutdownController.abort();
      }
    },

    async acquireRepositoryArchive(
      input: AcquireRepositoryArchiveInput
    ): Promise<AcquiredRepositoryArchive> {
      const secretsForAttempt = [workerAuthSecret, input.leaseToken];

      if (
        clientShutdownController.signal.aborted ||
        options.shutdownSignal?.aborted ||
        input.shutdownSignal?.aborted
      ) {
        throw new InternalAcquisitionError(
          'WORKER_SHUTDOWN',
          'Worker shutdown prevented internal repository archive acquisition.',
          { secretsToRedact: secretsForAttempt }
        );
      }

      if (input.signal?.aborted) {
        throw new InternalAcquisitionError(
          'ACQUISITION_CANCELLED',
          'Repository archive acquisition was explicitly cancelled before sending request.',
          { secretsToRedact: secretsForAttempt }
        );
      }

      if (
        typeof input.scanId !== 'string' ||
        input.scanId.trim() !== input.scanId ||
        !isValidObjectId(input.scanId)
      ) {
        throw new InternalAcquisitionError(
          'INVALID_CONFIGURATION',
          'scanId must be a valid 24-character ObjectId.',
          { secretsToRedact: secretsForAttempt }
        );
      }

      if (
        typeof input.leaseToken !== 'string' ||
        input.leaseToken.length < MIN_LEASE_TOKEN_LENGTH ||
        input.leaseToken.length > MAX_LEASE_TOKEN_LENGTH
      ) {
        throw new InternalAcquisitionError(
          'INVALID_CONFIGURATION',
          `leaseToken must be between ${MIN_LEASE_TOKEN_LENGTH} and ${MAX_LEASE_TOKEN_LENGTH} characters.`,
          { secretsToRedact: secretsForAttempt }
        );
      }

      const signed = buildSignedAcquireRequest({
        scanId: input.scanId,
        leaseToken: input.leaseToken,
        workerAuthSecret,
        now: options.now,
        nonceGenerator: options.nonceGenerator,
      });
      const attemptSecrets = [...secretsForAttempt, signed.signature];

      logger.info('Starting internal repository archive acquisition.', {
        scanId: input.scanId,
        endpointPath: INTERNAL_SCAN_ACQUIRE_PATH,
        serviceId: INTERNAL_WORKER_SERVICE_ID,
      });

      return await new Promise<AcquiredRepositoryArchive>((resolveAttempt, rejectAttempt) => {
        let initialSettled = false;
        let streamFinished = false;
        let streamFailed = false;
        let pendingStreamError: InternalAcquisitionError | null = null;
        let totalBytesReceived = 0;
        let declaredContentLength: number | null = null;
        let socketConnected = false;

        let activeReq: http.ClientRequest | null = null;
        let activeSocket: Duplex | null = null;
        let activeRes: IncomingMessage | null = null;
        let outputStream: Readable | null = null;

        let connectTimer: ReturnType<typeof setTimeout> | null = null;
        let headersTimer: ReturnType<typeof setTimeout> | null = null;
        let streamIdleTimer: ReturnType<typeof setTimeout> | null = null;
        let totalTimer: ReturnType<typeof setTimeout> | null = null;

        const clearAllTimers = () => {
          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          if (headersTimer) {
            clearTimeout(headersTimer);
            headersTimer = null;
          }
          if (streamIdleTimer) {
            clearTimeout(streamIdleTimer);
            streamIdleTimer = null;
          }
          if (totalTimer) {
            clearTimeout(totalTimer);
            totalTimer = null;
          }
        };

        const detachSocketListeners = () => {
          if (!activeSocket) {
            return;
          }
          activeSocket.off('connect', onSocketConnected);
          activeSocket.off('secureConnect', onSocketConnected);
          activeSocket = null;
        };

        const detachResponseListeners = () => {
          if (!activeRes) {
            return;
          }
          activeRes.off('data', onResData);
          activeRes.off('end', onResEnd);
          activeRes.off('aborted', onResAborted);
          activeRes.off('close', onResClose);
          activeRes.off('error', onResError);
        };

        const detachRequestListeners = () => {
          if (!activeReq) {
            return;
          }
          activeReq.off('socket', onReqSocket);
          activeReq.off('response', onReqResponse);
          activeReq.off('error', onReqError);
        };

        const detachSignalListeners = () => {
          input.signal?.removeEventListener('abort', onExplicitCancel);
          options.shutdownSignal?.removeEventListener('abort', onWorkerShutdown);
          input.shutdownSignal?.removeEventListener('abort', onWorkerShutdown);
          clientShutdownController.signal.removeEventListener('abort', onWorkerShutdown);
        };

        const cleanupAllResources = (destroyTransport: boolean) => {
          const socketToClose = activeSocket;
          clearAllTimers();
          detachSignalListeners();
          detachSocketListeners();
          detachResponseListeners();
          detachRequestListeners();

          if (destroyTransport) {
            const noopError = () => undefined;
            const resToClose = activeRes;
            const reqToClose = activeReq;
            activeRes = null;
            activeReq = null;
            if (resToClose) {
              resToClose.on('error', noopError);
              if (!resToClose.destroyed) {
                resToClose.destroy();
              }
            }
            if (reqToClose) {
              reqToClose.on('error', noopError);
              if (!reqToClose.destroyed) {
                reqToClose.destroy();
              }
            }
            if (socketToClose && !socketToClose.destroyed) {
              socketToClose.on('error', noopError);
              socketToClose.destroy();
            }
          } else {
            activeRes = null;
            activeReq = null;
          }
        };

        const failAcquisition = (err: InternalAcquisitionError) => {
          if (streamFinished || streamFailed) {
            return;
          }

          cleanupAllResources(true);

          if (!initialSettled) {
            initialSettled = true;
            streamFailed = true;
            logger.warn('Internal repository archive acquisition failed before stream start.', {
              scanId: input.scanId,
              code: err.code,
              ...(err.httpStatus !== undefined ? { httpStatus: err.httpStatus } : {}),
              ...(err.timeoutPhase !== undefined ? { timeoutPhase: err.timeoutPhase } : {}),
            });
            rejectAttempt(err);
            return;
          }

          streamFailed = true;
          logger.warn('Internal repository archive acquisition stream terminated with error.', {
            scanId: input.scanId,
            code: err.code,
            bytesReceived: totalBytesReceived,
            ...(err.timeoutPhase !== undefined ? { timeoutPhase: err.timeoutPhase } : {}),
          });

          if (outputStream && !outputStream.destroyed) {
            if (outputStream.listenerCount('error') > 0) {
              outputStream.destroy(err);
            } else {
              pendingStreamError = err;
            }
          }
        };

        const resetStreamIdleTimer = () => {
          if (streamIdleTimer) {
            clearTimeout(streamIdleTimer);
          }
          streamIdleTimer = setTimeout(() => {
            failAcquisition(
              new InternalAcquisitionError(
                'ACQUISITION_TIMEOUT',
                'Repository archive stream stalled waiting for data from the internal API.',
                { timeoutPhase: 'idle', secretsToRedact: attemptSecrets }
              )
            );
          }, streamIdleTimeoutMs);
          streamIdleTimer.unref?.();
        };

        const onExplicitCancel = () => {
          failAcquisition(
            new InternalAcquisitionError(
              'ACQUISITION_CANCELLED',
              'Repository archive acquisition was explicitly cancelled.',
              { secretsToRedact: attemptSecrets }
            )
          );
        };

        const onWorkerShutdown = () => {
          failAcquisition(
            new InternalAcquisitionError(
              'WORKER_SHUTDOWN',
              'Worker shutdown interrupted repository archive acquisition.',
              { secretsToRedact: attemptSecrets }
            )
          );
        };

        const onSocketConnected = () => {
          socketConnected = true;
          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          detachSocketListeners();
        };

        const onReqSocket = (socket: Duplex) => {
          activeSocket = socket;
          const isConnecting =
            'connecting' in socket && Boolean((socket as { connecting?: boolean }).connecting);
          if (!isConnecting && parsedBaseUrl.protocol === 'http:') {
            onSocketConnected();
            return;
          }

          if (parsedBaseUrl.protocol === 'https:') {
            socket.once('secureConnect', onSocketConnected);
          } else {
            socket.once('connect', onSocketConnected);
          }
        };

        const onResData = (rawChunk: Buffer | string) => {
          if (streamFinished || streamFailed) {
            return;
          }

          const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
          if (chunk.byteLength === 0) {
            return;
          }

          resetStreamIdleTimer();
          totalBytesReceived += chunk.byteLength;

          if (totalBytesReceived > maxArchiveBytes) {
            failAcquisition(
              new InternalAcquisitionError(
                'ARCHIVE_SIZE_EXCEEDED',
                'Repository archive stream exceeded maximum allowed compressed size limit.',
                { secretsToRedact: attemptSecrets }
              )
            );
            return;
          }

          if (declaredContentLength !== null && totalBytesReceived > declaredContentLength) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive stream exceeded its declared Content-Length.',
                { secretsToRedact: attemptSecrets }
              )
            );
            return;
          }

          if (outputStream && !outputStream.destroyed) {
            const canAcceptMore = outputStream.push(chunk);
            if (!canAcceptMore && activeRes && !activeRes.destroyed) {
              activeRes.pause();
            }
          }
        };

        const onResEnd = () => {
          if (streamFinished || streamFailed) {
            return;
          }

          if (
            clientShutdownController.signal.aborted ||
            options.shutdownSignal?.aborted ||
            input.shutdownSignal?.aborted
          ) {
            onWorkerShutdown();
            return;
          }

          if (input.signal?.aborted) {
            onExplicitCancel();
            return;
          }

          const resRef = activeRes;
          if (!resRef?.complete) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive HTTP response ended before full framing completed.',
                { secretsToRedact: attemptSecrets }
              )
            );
            return;
          }

          if (totalBytesReceived === 0) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive HTTP response was empty.',
                { secretsToRedact: attemptSecrets }
              )
            );
            return;
          }

          if (declaredContentLength !== null && totalBytesReceived !== declaredContentLength) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive HTTP response terminated before matching declared Content-Length.',
                { secretsToRedact: attemptSecrets }
              )
            );
            return;
          }

          streamFinished = true;
          cleanupAllResources(false);
          logger.info('Completed internal repository archive acquisition stream.', {
            scanId: input.scanId,
            bytesReceived: totalBytesReceived,
          });
          outputStream?.push(null);
        };

        const onResAborted = () => {
          if (!streamFinished && !streamFailed) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive HTTP response was aborted before completion.',
                { secretsToRedact: attemptSecrets }
              )
            );
          }
        };

        const onResClose = () => {
          if (!streamFinished && !streamFailed) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive connection closed prematurely before completion.',
                { secretsToRedact: attemptSecrets }
              )
            );
          }
        };

        const onResError = () => {
          if (!streamFinished && !streamFailed) {
            failAcquisition(
              new InternalAcquisitionError(
                'INCOMPLETE_ARCHIVE_RESPONSE',
                'Repository archive stream failed due to an underlying transport error.',
                { secretsToRedact: attemptSecrets }
              )
            );
          }
        };

        const onReqError = (error: Error) => {
          if (streamFinished || streamFailed) {
            return;
          }

          if (!initialSettled) {
            const safeReason = socketConnected
              ? 'Internal API request failed while awaiting response.'
              : `Unable to connect to internal API endpoint (${formatSafeWorkerMessage(
                  error.message,
                  attemptSecrets
                )}).`;
            failAcquisition(
              new InternalAcquisitionError('INTERNAL_API_CONNECTION_FAILED', safeReason, {
                secretsToRedact: attemptSecrets,
              })
            );
            return;
          }

          failAcquisition(
            new InternalAcquisitionError(
              'INCOMPLETE_ARCHIVE_RESPONSE',
              'Internal API transport error interrupted active repository archive transfer.',
              { secretsToRedact: attemptSecrets }
            )
          );
        };

        const onReqResponse = (res: IncomingMessage) => {
          if (streamFinished || streamFailed || initialSettled) {
            res.destroy();
            return;
          }

          activeRes = res;

          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          if (headersTimer) {
            clearTimeout(headersTimer);
            headersTimer = null;
          }
          socketConnected = true;
          detachSocketListeners();

          const statusCode = res.statusCode ?? 0;
          if (statusCode !== 200) {
            failAcquisition(mapNonSuccessHttpStatus(statusCode));
            return;
          }

          let validatedHeaders: ValidatedArchiveHeaders;
          try {
            validatedHeaders = validateArchiveResponseHeaders(res, maxArchiveBytes);
          } catch (headerError) {
            if (headerError instanceof InternalAcquisitionError) {
              failAcquisition(headerError);
            } else {
              failAcquisition(
                new InternalAcquisitionError(
                  'INVALID_RESPONSE_HEADERS',
                  'Internal API returned invalid archive response headers.',
                  { httpStatus: statusCode, secretsToRedact: attemptSecrets }
                )
              );
            }
            return;
          }

          declaredContentLength = validatedHeaders.declaredContentLength;

          const boundedReadable = new Readable({
            highWaterMark: streamHighWaterMark,
            read() {
              if (!streamFinished && !streamFailed && activeRes && !activeRes.destroyed) {
                activeRes.resume();
              }
            },
            destroy(err, callback) {
              if (!streamFinished && !streamFailed) {
                streamFailed = true;
                cleanupAllResources(true);
              }
              callback(err);
            },
          });

          // Deliver any deferred premature-truncation/size-limit error as soon as consumer attaches error handling.
          boundedReadable.on('newListener', (eventName: string | symbol) => {
            if (eventName === 'error' && pendingStreamError && !boundedReadable.destroyed) {
              const deferredError = pendingStreamError;
              pendingStreamError = null;
              queueMicrotask(() => {
                if (!boundedReadable.destroyed) {
                  boundedReadable.destroy(deferredError);
                }
              });
            }
          });

          outputStream = boundedReadable;

          res.on('data', onResData);
          res.on('end', onResEnd);
          res.on('aborted', onResAborted);
          res.on('close', onResClose);
          res.on('error', onResError);

          resetStreamIdleTimer();

          initialSettled = true;
          resolveAttempt({
            scanId: input.scanId,
            contentType: validatedHeaders.contentType,
            declaredContentLength,
            maxArchiveBytes,
            stream: boundedReadable,
            bytesReceived(): number {
              return totalBytesReceived;
            },
            abort(reason: 'cancelled' | 'shutdown' = 'cancelled'): void {
              if (reason === 'shutdown') {
                onWorkerShutdown();
              } else {
                onExplicitCancel();
              }
            },
          });
        };

        input.signal?.addEventListener('abort', onExplicitCancel, { once: true });
        options.shutdownSignal?.addEventListener('abort', onWorkerShutdown, { once: true });
        input.shutdownSignal?.addEventListener('abort', onWorkerShutdown, { once: true });
        clientShutdownController.signal.addEventListener('abort', onWorkerShutdown, {
          once: true,
        });

        connectTimer = setTimeout(() => {
          if (!socketConnected) {
            failAcquisition(
              new InternalAcquisitionError(
                'ACQUISITION_TIMEOUT',
                'Timed out establishing connection to internal API endpoint.',
                { timeoutPhase: 'connect', secretsToRedact: attemptSecrets }
              )
            );
          }
        }, connectTimeoutMs);
        connectTimer.unref?.();

        headersTimer = setTimeout(() => {
          if (!initialSettled) {
            failAcquisition(
              new InternalAcquisitionError(
                'ACQUISITION_TIMEOUT',
                'Timed out awaiting response headers from internal API endpoint.',
                { timeoutPhase: 'headers', secretsToRedact: attemptSecrets }
              )
            );
          }
        }, headersTimeoutMs);
        headersTimer.unref?.();

        totalTimer = setTimeout(() => {
          failAcquisition(
            new InternalAcquisitionError(
              'ACQUISITION_TIMEOUT',
              'Repository archive acquisition exceeded the overall allowed timeout.',
              { timeoutPhase: 'total', secretsToRedact: attemptSecrets }
            )
          );
        }, totalTimeoutMs);
        totalTimer.unref?.();

        const portNumber = parsedBaseUrl.port
          ? Number(parsedBaseUrl.port)
          : parsedBaseUrl.protocol === 'https:'
            ? 443
            : 80;

        const requestOptions: http.RequestOptions = {
          protocol: parsedBaseUrl.protocol,
          hostname: parsedBaseUrl.hostname,
          port: portNumber,
          path: targetUrl.pathname,
          method: 'POST',
          headers: signed.headers,
          agent: false,
          ...(options.createConnection ? { createConnection: options.createConnection } : {}),
        };

        activeReq =
          parsedBaseUrl.protocol === 'https:'
            ? https.request(requestOptions)
            : http.request(requestOptions);

        activeReq.on('socket', onReqSocket);
        activeReq.on('response', onReqResponse);
        activeReq.on('error', onReqError);

        activeReq.write(signed.rawBodyBuffer);
        activeReq.end();
      });
    },
  };

  Object.defineProperty(client, Symbol.for('nodejs.util.inspect.custom'), {
    value: () =>
      `[InternalAcquisitionClient ${configSummary.baseUrl}${configSummary.endpointPath} service=${configSummary.serviceId}]`,
    enumerable: false,
  });

  return client;
}
