import { isValidObjectId } from '@vibeshield/database';
import { z } from 'zod';

/**
 * Strict request body accepted by `POST /internal/v1/scans/acquire`.
 *
 * Only `scanId` and `leaseToken` are permitted. Tenant, repository, installation, URL,
 * permission, and credential override fields are strictly rejected so authorization is derived
 * solely from authoritative server database state and authenticated worker headers.
 */
export const internalScanAcquireRequestSchema = z
  .object({
    scanId: z
      .string()
      .trim()
      .refine((value) => isValidObjectId(value), {
        message: 'scanId must be a valid ObjectId',
      }),
    leaseToken: z
      .string()
      .min(16, 'leaseToken must be at least 16 characters')
      .max(256, 'leaseToken must not exceed 256 characters'),
  })
  .strict();

export type InternalScanAcquireRequest = z.infer<typeof internalScanAcquireRequestSchema>;
