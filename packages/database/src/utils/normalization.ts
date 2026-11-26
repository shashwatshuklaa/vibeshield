import mongoose, { type Model, type Schema } from 'mongoose';

/**
 * Pragmatic email format pattern rejecting whitespace and requiring a domain with TLD.
 */
export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * URL-safe lowercase slug pattern (alphanumeric segments separated by single hyphens).
 */
export const SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Normalizes an email address for canonical storage and uniqueness matching.
 * Non-string inputs are returned unchanged so Mongoose validation/casting handles them cleanly.
 */
export function normalizeEmail(value: string): string;
export function normalizeEmail(value: unknown): unknown;
export function normalizeEmail(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value;
  }
  return value.trim().toLowerCase();
}

/**
 * Normalizes a slug for canonical storage and uniqueness matching.
 * Non-string inputs are returned unchanged so Mongoose validation/casting handles them cleanly.
 */
export function normalizeSlug(value: string): string;
export function normalizeSlug(value: unknown): unknown;
export function normalizeSlug(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value;
  }
  return value.trim().toLowerCase();
}

/**
 * Retrieves an existing compiled Mongoose model or registers a new one,
 * preventing OverwriteModelError during repeated imports or watch-mode reloads.
 */
export function getOrCreateModel<T>(name: string, schema: Schema<T>): Model<T> {
  const existing = mongoose.models[name] as Model<T> | undefined;
  return existing ?? mongoose.model<T>(name, schema);
}
