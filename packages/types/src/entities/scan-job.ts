import {
  type ScanFailureCode,
  type ScanLifecycleStatus,
  ScanStatus,
  type ScanTriggerSource,
} from '../enums/scan-status.js';

/**
 * Contract for a security scan job dispatched to background workers.
 * Independent of specific queue infrastructure (e.g., BullMQ).
 */
export interface ScanJob {
  /**
   * Unique identifier of the scan job dispatch.
   */
  jobId: string;

  /**
   * Associated security scan execution record ID.
   */
  scanId: string;

  /**
   * Associated project identifier.
   */
  projectId: string;

  /**
   * Target Git commit hash to analyze.
   */
  commitHash: string;

  /**
   * Git branch being analyzed.
   */
  branch: string;

  /**
   * Current execution status of the scan job.
   */
  status: ScanStatus;

  /**
   * User ID or trigger mechanism (e.g. 'webhook', 'scheduled', 'manual').
   */
  triggeredBy: string;

  /**
   * Timestamp when the job was enqueued.
   */
  createdAt: Date | string;

  /**
   * Optional timestamp when execution started.
   */
  startedAt?: Date | string;

  /**
   * Optional timestamp when execution completed or failed.
   */
  completedAt?: Date | string;

  /**
   * Optional error message if the scan job failed.
   */
  errorMessage?: string;
}

/**
 * Safe summary of verified repository archive acquisition metrics recorded on a Scan.
 * Contains metrics and resolved immutable commit SHA only (never source code or archive blobs).
 */
export interface ScanAcquisitionMetadata {
  resolvedCommitSha: string;
  compressedArchiveBytes: number;
  extractedBytes: number;
  extractedFileCount: number;
  acquisitionCompletedAt: Date | string;
}

/**
 * Public, token-free worker lease snapshot attached to an active scan execution.
 */
export interface PublicScanWorkerLease {
  workerId: string;
  acquiredAt: Date | string;
  heartbeatAt: Date | string;
  expiresAt: Date | string;
}

/**
 * Public cancellation request state on a Scan record.
 */
export interface ScanCancellationState {
  requestedAt: Date | string | null;
  requestedByUserId: string | null;
  reason: string | null;
}

/**
 * Safe public representation of a persistent VibeShield Scan record (never includes secrets,
 * worker lease fencing tokens, or source archives).
 */
export interface PublicScanRecord {
  id: string;
  organizationId: string;
  projectId: string;
  repositoryConnectionId: string;
  githubInstallationId: number;
  githubRepositoryId: number;
  requestedRef: string;
  requestedCommitHash: string | null;
  resolvedCommitSha: string | null;
  status: ScanLifecycleStatus;
  isActive: boolean;
  triggerSource: ScanTriggerSource;
  createdByUserId: string | null;
  correlationId: string | null;
  attemptCount: number;
  maxAttempts: number;
  lease: PublicScanWorkerLease | null;
  cancellation: ScanCancellationState;
  acquisition: ScanAcquisitionMetadata | null;
  failureCode: ScanFailureCode | null;
  failureMessage: string | null;
  queuedAt: Date | string;
  startedAt: Date | string | null;
  acquiringAt: Date | string | null;
  preparedAt: Date | string | null;
  inProgressAt: Date | string | null;
  completedAt: Date | string | null;
  failedAt: Date | string | null;
  cancelledAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

/**
 * Minimal, server-authorized acquisition context resolved solely by the API database layer
 * after verifying scan ownership, active lease fencing, cancellation state, project state,
 * repository connection state, and GitHub installation status.
 *
 * Never contains worker lease fencing tokens, GitHub installation tokens, private keys, or user PII.
 */
export interface AuthorizedScanAcquisitionContext {
  scanId: string;
  organizationId: string;
  projectId: string;
  repositoryConnectionId: string;
  githubInstallationId: number;
  githubRepositoryId: number;
  repositoryOwner: string;
  repositoryName: string;
  requestedRef: string;
  requestedCommitHash: string | null;
  attemptCount: number;
  maxAttempts: number;
  workerId: string;
  leaseExpiresAt: Date | string;
}
