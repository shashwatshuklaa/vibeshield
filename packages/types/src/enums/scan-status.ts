/**
 * Existing BullMQ queue-payload status values (kept untouched for backward queue compatibility).
 */
export enum ScanStatus {
  QUEUED = 'QUEUED',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

/**
 * Type-level union representing valid queue-payload scan statuses.
 */
export type ScanStatusType = `${ScanStatus}`;

/**
 * Authoritative persistent scan lifecycle states stored in MongoDB (`ScanModel`).
 * Distinct from queue dispatch status (`ScanStatus`) and worker host readiness (`WorkerLifecycleState`).
 */
export const SCAN_LIFECYCLE_STATUSES = [
  'QUEUED',
  'ACQUIRING',
  'IN_PROGRESS',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;

export type ScanLifecycleStatus = (typeof SCAN_LIFECYCLE_STATUSES)[number];

export const ScanLifecycleStatusValue = {
  QUEUED: 'QUEUED',
  ACQUIRING: 'ACQUIRING',
  IN_PROGRESS: 'IN_PROGRESS',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
} as const satisfies Record<ScanLifecycleStatus, ScanLifecycleStatus>;

export const TERMINAL_SCAN_LIFECYCLE_STATUSES: ReadonlySet<ScanLifecycleStatus> = new Set([
  ScanLifecycleStatusValue.COMPLETED,
  ScanLifecycleStatusValue.FAILED,
  ScanLifecycleStatusValue.CANCELLED,
]);

export function isTerminalScanLifecycleStatus(status: unknown): boolean {
  return (
    typeof status === 'string' &&
    TERMINAL_SCAN_LIFECYCLE_STATUSES.has(status as ScanLifecycleStatus)
  );
}

/**
 * Origin trigger classifying how a scan job was created.
 */
export const SCAN_TRIGGER_SOURCES = ['manual', 'webhook', 'scheduled', 'system'] as const;
export type ScanTriggerSource = (typeof SCAN_TRIGGER_SOURCES)[number];

export const ScanTriggerSourceValue = {
  MANUAL: 'manual',
  WEBHOOK: 'webhook',
  SCHEDULED: 'scheduled',
  SYSTEM: 'system',
} as const satisfies Record<Uppercase<ScanTriggerSource>, ScanTriggerSource>;

/**
 * Canonical non-secret failure classification codes recorded on persistent Scan records.
 */
export const SCAN_FAILURE_CODES = [
  'INVALID_JOB_PAYLOAD',
  'PROJECT_NOT_FOUND',
  'PROJECT_ARCHIVED',
  'REPOSITORY_DISCONNECTED',
  'REPOSITORY_ACCESS_REVOKED',
  'REPOSITORY_DELETED',
  'INSTALLATION_NOT_FOUND',
  'INSTALLATION_SUSPENDED',
  'INSTALLATION_REVOKED',
  'BROKER_UNAVAILABLE',
  'GITHUB_AUTH_FAILED',
  'GITHUB_RATE_LIMITED',
  'GITHUB_UNAVAILABLE',
  'ARCHIVE_TOO_LARGE',
  'ARCHIVE_SECURITY_VIOLATION',
  'ACQUISITION_FAILED',
  'LEASE_EXPIRED',
  'SCANNER_EXECUTION_FAILED',
  'WORKER_INTERNAL_ERROR',
] as const;

export type ScanFailureCode = (typeof SCAN_FAILURE_CODES)[number];

export const ScanFailureCodeValue = {
  INVALID_JOB_PAYLOAD: 'INVALID_JOB_PAYLOAD',
  PROJECT_NOT_FOUND: 'PROJECT_NOT_FOUND',
  PROJECT_ARCHIVED: 'PROJECT_ARCHIVED',
  REPOSITORY_DISCONNECTED: 'REPOSITORY_DISCONNECTED',
  REPOSITORY_ACCESS_REVOKED: 'REPOSITORY_ACCESS_REVOKED',
  REPOSITORY_DELETED: 'REPOSITORY_DELETED',
  INSTALLATION_NOT_FOUND: 'INSTALLATION_NOT_FOUND',
  INSTALLATION_SUSPENDED: 'INSTALLATION_SUSPENDED',
  INSTALLATION_REVOKED: 'INSTALLATION_REVOKED',
  BROKER_UNAVAILABLE: 'BROKER_UNAVAILABLE',
  GITHUB_AUTH_FAILED: 'GITHUB_AUTH_FAILED',
  GITHUB_RATE_LIMITED: 'GITHUB_RATE_LIMITED',
  GITHUB_UNAVAILABLE: 'GITHUB_UNAVAILABLE',
  ARCHIVE_TOO_LARGE: 'ARCHIVE_TOO_LARGE',
  ARCHIVE_SECURITY_VIOLATION: 'ARCHIVE_SECURITY_VIOLATION',
  ACQUISITION_FAILED: 'ACQUISITION_FAILED',
  LEASE_EXPIRED: 'LEASE_EXPIRED',
  SCANNER_EXECUTION_FAILED: 'SCANNER_EXECUTION_FAILED',
  WORKER_INTERNAL_ERROR: 'WORKER_INTERNAL_ERROR',
} as const satisfies Record<ScanFailureCode, ScanFailureCode>;
