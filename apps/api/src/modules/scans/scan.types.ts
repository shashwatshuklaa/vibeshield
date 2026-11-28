import { HttpError } from '../../utils/http-error.js';
import type { PublicScanRecord } from '@vibeshield/types';

/**
 * Operational error thrown by public scan API operations.
 * Extends HttpError for seamless integration with the existing error handler.
 */
export class ScanError extends HttpError {
  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(statusCode, code, message, details);
    this.name = 'ScanError';
  }
}

export interface PaginationMetadata {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface PaginatedScansResult {
  scans: PublicScanRecord[];
  pagination: PaginationMetadata;
}

export interface CreateScanInput {
  requestedRef: string;
  idempotencyKey?: string | null;
  correlationId?: string | null;
}

export interface ListScansQuery {
  page: number;
  limit: number;
  status?: string;
  triggerSource?: string;
}

export interface CancelScanInput {
  reason?: string | null;
}
