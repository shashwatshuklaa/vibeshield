import { ScanStatus } from '../enums/scan-status.js';

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
