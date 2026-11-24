/**
 * Standard vulnerability severity ratings across VibeShield analyzers and reports.
 * Follows industry-standard risk prioritization.
 */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

/**
 * Type-level union representing valid severity levels.
 */
export type SeverityLevel = `${Severity}`;
