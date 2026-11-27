import type { Request, Response } from 'express';
import {
  redactGitHubSecrets,
  redactMongoUri,
  setScanResolvedCommitWithLease,
  verifyScanAcquisitionAuthorization,
  type ScanAcquisitionDenialReason,
} from '@vibeshield/database';
import { HttpError } from '../../utils/http-error.js';
import type { GitHubClient } from '../github/github.client.js';
import { GitHubError, type RepositoryAcquisitionToken } from '../github/github.types.js';

export const HARD_MAX_COMPRESSED_ARCHIVE_BYTES = 100 * 1024 * 1024; // 100 MiB
export const DEFAULT_GITHUB_REQUEST_TIMEOUT_MS = 10_000;
export const DEFAULT_CODELOAD_TIMEOUT_MS = 60_000;
export const DEFAULT_ACQUISITION_TOTAL_TIMEOUT_MS = 120_000;
export const DEFAULT_TRANSFER_REVALIDATION_INTERVAL_MS = 5_000;

export interface InternalAcquisitionLogger {
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

export interface CreateInternalScanAcquisitionServiceOptions {
  githubClient: Pick<
    GitHubClient,
    | 'createRepositoryAcquisitionToken'
    | 'revokeInstallationAccessToken'
    | 'probeRepositoryById'
    | 'resolveCommitSha'
    | 'openRepositoryTarballStream'
  > | null;
  verifyAuthorization?: typeof verifyScanAcquisitionAuthorization;
  setResolvedCommitWithLease?: typeof setScanResolvedCommitWithLease;
  maxArchiveBytes?: number;
  githubRequestTimeoutMs?: number;
  codeloadTimeoutMs?: number;
  totalAcquisitionTimeoutMs?: number;
  revalidationIntervalMs?: number;
  logger?: InternalAcquisitionLogger;
}

export interface AcquireAndStreamInput {
  req: Request;
  res: Response;
  scanId: string;
  leaseToken: string;
  workerId: string;
}

export interface InternalScanAcquisitionService {
  acquireAndStreamArchive(input: AcquireAndStreamInput): Promise<void>;
}

const DENIAL_STATUS_MAP: Record<ScanAcquisitionDenialReason, { status: number; code: string }> = {
  SCAN_NOT_FOUND: { status: 404, code: 'SCAN_NOT_FOUND' },
  PROJECT_NOT_FOUND: { status: 404, code: 'PROJECT_NOT_FOUND' },
  CONNECTION_NOT_FOUND: { status: 404, code: 'REPOSITORY_CONNECTION_NOT_FOUND' },
  INSTALLATION_NOT_FOUND: { status: 404, code: 'GITHUB_INSTALLATION_NOT_FOUND' },
  WORKER_MISMATCH: { status: 403, code: 'SCAN_WORKER_MISMATCH' },
  INVALID_LEASE_TOKEN: { status: 403, code: 'INVALID_SCAN_LEASE_TOKEN' },
  PROJECT_ARCHIVED: { status: 403, code: 'PROJECT_ARCHIVED' },
  CONNECTION_INACTIVE: { status: 403, code: 'REPOSITORY_CONNECTION_INACTIVE' },
  CONNECTION_METADATA_MISMATCH: { status: 403, code: 'REPOSITORY_BINDING_MISMATCH' },
  INSTALLATION_UNAVAILABLE: { status: 403, code: 'GITHUB_INSTALLATION_UNAVAILABLE' },
  INSTALLATION_MISMATCH: { status: 403, code: 'GITHUB_INSTALLATION_MISMATCH' },
  SCAN_NOT_ACQUIRING: { status: 409, code: 'SCAN_NOT_ACQUIRING' },
  SCAN_INACTIVE: { status: 409, code: 'SCAN_INACTIVE' },
  SCAN_CANCELLED: { status: 409, code: 'SCAN_CANCELLED' },
  INVALID_ATTEMPT_STATE: { status: 409, code: 'SCAN_ATTEMPT_INVALID' },
  LEASE_MISSING: { status: 409, code: 'SCAN_LEASE_MISSING' },
  LEASE_EXPIRED: { status: 409, code: 'SCAN_LEASE_EXPIRED' },
};

const DEFAULT_LOGGER: Required<InternalAcquisitionLogger> = {
  warn: (message: string) => console.warn(message),
  error: (message: string) => console.error(message),
};

type ChunkReadResult = Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>['read']>>;

async function readChunkWithAbort(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal
): Promise<ChunkReadResult> {
  if (signal.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error('Transfer aborted');
  }

  return new Promise<ChunkReadResult>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(signal.reason instanceof Error ? signal.reason : new Error('Transfer aborted'));
    };

    const cleanup = () => {
      signal.removeEventListener('abort', onAbort);
    };

    signal.addEventListener('abort', onAbort, { once: true });

    reader.read().then(
      (result) => {
        cleanup();
        resolve(result);
      },
      (err) => {
        cleanup();
        reject(err);
      }
    );
  });
}

async function waitForDrainOrAbort(res: Response, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error('Transfer aborted');
  }

  return new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      res.off('drain', onDrain);
      res.off('close', onClose);
      res.off('error', onError);
      signal.removeEventListener('abort', onAbort);
    };

    const onDrain = () => {
      cleanup();
      resolve();
    };

    const onClose = () => {
      cleanup();
      reject(new HttpError(499, 'WORKER_DISCONNECTED', 'Worker disconnected during stream drain'));
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const onAbort = () => {
      cleanup();
      reject(signal.reason instanceof Error ? signal.reason : new Error('Transfer aborted'));
    };

    res.once('drain', onDrain);
    res.once('close', onClose);
    res.once('error', onError);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function finalizeWritableResponse(res: Response, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(
      signal.reason instanceof Error
        ? signal.reason
        : new HttpError(499, 'ACQUISITION_ABORTED', 'Archive acquisition was aborted.')
    );
  }

  if (res.writableFinished) {
    return Promise.resolve();
  }

  if (res.destroyed) {
    return Promise.reject(
      new HttpError(
        499,
        'WORKER_DISCONNECTED',
        'Worker connection closed before final archive flush completed.'
      )
    );
  }

  return new Promise<void>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      res.off('finish', onFinish);
      res.off('close', onClose);
      res.off('error', onError);
      signal.removeEventListener('abort', onAbort);
    };

    const settleResolve = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };

    const settleReject = (err: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(err);
    };

    const onFinish = () => {
      settleResolve();
    };

    const onClose = () => {
      if (res.writableFinished) {
        settleResolve();
        return;
      }
      settleReject(
        new HttpError(
          499,
          'WORKER_DISCONNECTED',
          'Worker connection closed before final archive flush completed.'
        )
      );
    };

    const onError = (err: Error) => {
      settleReject(err);
    };

    const onAbort = () => {
      settleReject(
        signal.reason instanceof Error
          ? signal.reason
          : new HttpError(499, 'ACQUISITION_ABORTED', 'Archive acquisition was aborted.')
      );
    };

    res.once('finish', onFinish);
    res.once('close', onClose);
    res.once('error', onError);
    signal.addEventListener('abort', onAbort, { once: true });

    res.end();
  });
}

export function sanitizeDiagnosticUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '[REDACTED_URL]';
    }
    const hadQuery = parsed.search.length > 0 || rawUrl.includes('?');
    const hadFragment = parsed.hash.length > 0 || rawUrl.includes('#');
    const safeOrigin = `${parsed.protocol}//${parsed.host}`;
    const safePath = parsed.pathname || '/';
    return `${safeOrigin}${safePath}${hadQuery ? '?[REDACTED_QUERY]' : ''}${hadFragment ? '#[REDACTED_FRAGMENT]' : ''}`;
  } catch {
    return '[REDACTED_URL]';
  }
}

export function toSafeDiagnostic(error: unknown, extraSecrets: Array<string | undefined>): string {
  const raw = error instanceof Error ? error.message : String(error);
  const urlSanitized = raw.replace(/https?:\/\/[^\s"'<>()]+/gi, (matchedUrl) =>
    sanitizeDiagnosticUrl(matchedUrl)
  );
  return redactGitHubSecrets(redactMongoUri(urlSanitized), extraSecrets);
}

/**
 * Orchestrates authorized, least-privilege, bounded GitHub repository archive acquisition
 * and streaming to an authenticated security worker without persisting archives or leaking tokens.
 */
export function createInternalScanAcquisitionService(
  options: CreateInternalScanAcquisitionServiceOptions
): InternalScanAcquisitionService {
  const verifyAuthorization = options.verifyAuthorization ?? verifyScanAcquisitionAuthorization;
  const persistResolvedCommit =
    options.setResolvedCommitWithLease ?? setScanResolvedCommitWithLease;
  const maxArchiveBytes = options.maxArchiveBytes ?? HARD_MAX_COMPRESSED_ARCHIVE_BYTES;
  const githubRequestTimeoutMs =
    options.githubRequestTimeoutMs ?? DEFAULT_GITHUB_REQUEST_TIMEOUT_MS;
  const codeloadTimeoutMs = options.codeloadTimeoutMs ?? DEFAULT_CODELOAD_TIMEOUT_MS;
  const totalAcquisitionTimeoutMs =
    options.totalAcquisitionTimeoutMs ?? DEFAULT_ACQUISITION_TOTAL_TIMEOUT_MS;
  const revalidationIntervalMs =
    options.revalidationIntervalMs ?? DEFAULT_TRANSFER_REVALIDATION_INTERVAL_MS;
  const logger = options.logger ?? DEFAULT_LOGGER;

  if (
    !Number.isInteger(maxArchiveBytes) ||
    maxArchiveBytes < 1 ||
    maxArchiveBytes > HARD_MAX_COMPRESSED_ARCHIVE_BYTES
  ) {
    throw new Error(
      `Internal archive max bytes must be between 1 and ${HARD_MAX_COMPRESSED_ARCHIVE_BYTES} bytes.`
    );
  }

  return {
    async acquireAndStreamArchive(input: AcquireAndStreamInput): Promise<void> {
      const { req, res, scanId, leaseToken, workerId } = input;
      const githubClient = options.githubClient;

      if (!githubClient) {
        throw new HttpError(
          503,
          'GITHUB_INTEGRATION_NOT_CONFIGURED',
          'GitHub App credentials are not configured for repository archive acquisition.'
        );
      }

      const abortController = new AbortController();
      let transferCompleted = false;
      let acquisitionToken: RepositoryAcquisitionToken | null = null;
      let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
      let revalidationTimer: ReturnType<typeof setInterval> | null = null;
      let revalidationInFlight = false;

      const abortTransfer = (status: number, code: string, message: string) => {
        if (!abortController.signal.aborted && !transferCompleted) {
          abortController.abort(new HttpError(status, code, message));
        }
      };

      const totalTimer = setTimeout(() => {
        abortTransfer(
          504,
          'ACQUISITION_TIMEOUT',
          'Repository archive acquisition exceeded the total allowed duration.'
        );
      }, totalAcquisitionTimeoutMs);
      totalTimer.unref?.();

      const onReqAborted = () => {
        abortTransfer(
          499,
          'WORKER_DISCONNECTED',
          'Worker request aborted before acquisition completed.'
        );
      };

      const onResClose = () => {
        if (!transferCompleted && !res.writableFinished) {
          abortTransfer(
            499,
            'WORKER_DISCONNECTED',
            'Worker connection closed before archive transfer completed.'
          );
        }
      };

      const onResError = () => {
        if (!transferCompleted) {
          abortTransfer(
            499,
            'WORKER_DISCONNECTED',
            'Worker response stream encountered an error before transfer completed.'
          );
        }
      };

      req.once('aborted', onReqAborted);
      res.once('close', onResClose);
      res.once('error', onResError);

      const assertAuthorized = async () => {
        if (abortController.signal.aborted) {
          throw abortController.signal.reason instanceof Error
            ? abortController.signal.reason
            : new HttpError(499, 'ACQUISITION_ABORTED', 'Archive acquisition was aborted.');
        }

        const authResult = await verifyAuthorization({
          scanId,
          leaseToken,
          workerId,
        });

        if (authResult.status === 'DENIED') {
          const mapped = DENIAL_STATUS_MAP[authResult.reason];
          throw new HttpError(mapped.status, mapped.code, authResult.message);
        }

        if (abortController.signal.aborted) {
          throw abortController.signal.reason instanceof Error
            ? abortController.signal.reason
            : new HttpError(499, 'ACQUISITION_ABORTED', 'Archive acquisition was aborted.');
        }

        return authResult.context;
      };

      try {
        // 1. Authoritative scan, lease, cancellation, project, connection & installation verification
        await assertAuthorized();

        // 2. Revalidate immediately before minting short-lived single-repository token
        const preTokenAuth = await assertAuthorized();
        acquisitionToken = await githubClient.createRepositoryAcquisitionToken({
          installationId: preTokenAuth.githubInstallationId,
          githubRepositoryId: preTokenAuth.githubRepositoryId,
        });

        // 3. Confirm live GitHub repository numeric ID & owner/name match DB binding
        const probeResult = await githubClient.probeRepositoryById(
          acquisitionToken.token,
          preTokenAuth.githubRepositoryId,
          { signal: abortController.signal }
        );

        if (probeResult.status !== 'ACCESSIBLE') {
          if (probeResult.status === 'ACCESS_REVOKED') {
            throw new HttpError(
              403,
              'GITHUB_ACCESS_REVOKED',
              'GitHub denied access to the connected repository.'
            );
          }
          throw new HttpError(
            404,
            'GITHUB_REPOSITORY_NOT_FOUND',
            'Connected GitHub repository could not be found.'
          );
        }

        if (
          probeResult.repository.githubRepositoryId !== preTokenAuth.githubRepositoryId ||
          probeResult.repository.ownerLogin.toLowerCase() !==
            preTokenAuth.repositoryOwner.toLowerCase() ||
          probeResult.repository.name.toLowerCase() !== preTokenAuth.repositoryName.toLowerCase()
        ) {
          throw new HttpError(
            409,
            'REPOSITORY_IDENTITY_MISMATCH',
            'GitHub repository identity does not match the authorized project binding.'
          );
        }

        // 4. Resolve requested ref or commit hash to full immutable commit SHA
        const targetRef = preTokenAuth.requestedCommitHash ?? preTokenAuth.requestedRef;
        const resolvedSha = await githubClient.resolveCommitSha({
          installationToken: acquisitionToken.token,
          owner: preTokenAuth.repositoryOwner,
          repo: preTokenAuth.repositoryName,
          ref: targetRef,
          signal: abortController.signal,
        });

        // 5. Persist resolved commit SHA under fenced active lease & no-cancellation precondition
        const commitPersist = await persistResolvedCommit({
          scanId: preTokenAuth.scanId,
          organizationId: preTokenAuth.organizationId,
          projectId: preTokenAuth.projectId,
          leaseToken,
          resolvedCommitSha: resolvedSha,
        });

        if (commitPersist.status === 'CANCEL_REQUESTED') {
          throw new HttpError(
            409,
            'SCAN_CANCELLED',
            'Scan cancellation was requested before archive streaming began.'
          );
        }
        if (commitPersist.status !== 'UPDATED') {
          throw new HttpError(
            409,
            'SCAN_LEASE_CONFLICT',
            'Scan lease became invalid or expired while resolving commit SHA.'
          );
        }

        // 6. Revalidate immediately before calling /repos/{owner}/{repo}/tarball/{sha}
        await assertAuthorized();

        const streamHandle = await githubClient.openRepositoryTarballStream({
          installationToken: acquisitionToken.token,
          owner: preTokenAuth.repositoryOwner,
          repo: preTokenAuth.repositoryName,
          commitSha: resolvedSha,
          maxArchiveBytes,
          timeoutMs: githubRequestTimeoutMs,
          codeloadTimeoutMs,
          signal: abortController.signal,
        });

        // 7. Revalidate right before flushing HTTP response headers to worker
        await assertAuthorized();

        reader = streamHandle.body.getReader();

        revalidationTimer = setInterval(() => {
          if (revalidationInFlight || abortController.signal.aborted || transferCompleted) {
            return;
          }
          revalidationInFlight = true;
          void verifyAuthorization({ scanId, leaseToken, workerId })
            .then((check) => {
              if (check.status === 'DENIED') {
                const mapped = DENIAL_STATUS_MAP[check.reason];
                abortTransfer(mapped.status, mapped.code, check.message);
                void reader?.cancel().catch(() => undefined);
              }
            })
            .catch(() => {
              abortTransfer(
                503,
                'SCAN_REVALIDATION_FAILED',
                'Unable to verify scan lease and cancellation state during archive transfer.'
              );
              void reader?.cancel().catch(() => undefined);
            })
            .finally(() => {
              revalidationInFlight = false;
            });
        }, revalidationIntervalMs);
        revalidationTimer.unref?.();

        let totalBytes = 0;
        let headersSentForArchive = false;

        while (true) {
          const { done, value } = await readChunkWithAbort(reader, abortController.signal);
          if (done) {
            break;
          }
          if (!value || value.byteLength === 0) {
            continue;
          }

          totalBytes += value.byteLength;
          if (totalBytes > maxArchiveBytes) {
            abortTransfer(
              413,
              'ARCHIVE_TOO_LARGE',
              'Repository archive exceeds maximum allowed compressed size limit.'
            );
            throw new HttpError(
              413,
              'ARCHIVE_TOO_LARGE',
              'Repository archive exceeds maximum allowed compressed size limit.'
            );
          }

          if (!headersSentForArchive) {
            res.status(200);
            res.setHeader('Content-Type', 'application/gzip');
            res.setHeader(
              'Content-Disposition',
              `attachment; filename="scan-${preTokenAuth.scanId}.tar.gz"`
            );
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            headersSentForArchive = true;
          }

          const canContinue = res.write(value);
          if (!canContinue) {
            await waitForDrainOrAbort(res, abortController.signal);
          }
        }

        if (revalidationTimer) {
          clearInterval(revalidationTimer);
          revalidationTimer = null;
        }

        if (totalBytes === 0) {
          throw new HttpError(
            502,
            'EMPTY_ARCHIVE_RESPONSE',
            'Upstream repository archive stream was empty.'
          );
        }

        // Final fence/cancellation verification before emitting normal EOF to worker
        await assertAuthorized();

        await finalizeWritableResponse(res, abortController.signal);
        transferCompleted = true;
      } catch (error) {
        if (revalidationTimer) {
          clearInterval(revalidationTimer);
          revalidationTimer = null;
        }

        if (res.headersSent && !transferCompleted) {
          if (reader) {
            await reader.cancel().catch(() => undefined);
            reader = null;
          }
          res.destroy();
          logger.warn?.(
            `[VibeShield Internal API] Terminated active archive stream for scan ${scanId}: ${toSafeDiagnostic(
              error,
              [leaseToken, acquisitionToken?.token]
            )}`
          );
          return;
        }

        if (error instanceof HttpError) {
          throw error;
        }
        if (error instanceof GitHubError) {
          throw new HttpError(error.statusCode, error.code, error.message);
        }
        if (
          error &&
          typeof error === 'object' &&
          'name' in error &&
          (error as { name?: unknown }).name === 'TimeoutError'
        ) {
          throw new HttpError(
            504,
            'ARCHIVE_DOWNLOAD_TIMEOUT',
            'Repository archive download timed out before receiving archive data.'
          );
        }
        throw new HttpError(
          502,
          'ARCHIVE_ACQUISITION_FAILED',
          'Repository archive acquisition failed before streaming started.'
        );
      } finally {
        clearTimeout(totalTimer);
        if (revalidationTimer) {
          clearInterval(revalidationTimer);
          revalidationTimer = null;
        }
        req.off('aborted', onReqAborted);
        res.off('close', onResClose);
        res.off('error', onResError);

        if (reader) {
          await reader.cancel().catch(() => undefined);
        }

        if (acquisitionToken) {
          const tokenToRevoke = acquisitionToken.token;
          acquisitionToken = null;
          try {
            await githubClient.revokeInstallationAccessToken(tokenToRevoke);
          } catch (revokeError) {
            logger.warn?.(
              `[VibeShield Internal API] Failed to revoke temporary GitHub acquisition token: ${toSafeDiagnostic(
                revokeError,
                [tokenToRevoke, leaseToken]
              )}`
            );
          }
        }
      }
    },
  };
}
