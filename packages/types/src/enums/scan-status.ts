/**
 * Lifecycle states of an application security scan job.
 */
export enum ScanStatus {
  QUEUED = 'QUEUED',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

/**
 * Type-level union representing valid scan statuses.
 */
export type ScanStatusType = `${ScanStatus}`;
