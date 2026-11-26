import { describe, expect, it } from 'vitest';
import { Error as MongooseError, Schema, Types, type Document } from 'mongoose';
import { getOrCreateModel, SessionModel, sessionSchema } from '../index.js';

async function getValidationError(
  doc: Document
): Promise<MongooseError.ValidationError | undefined> {
  try {
    await doc.validate();
    return undefined;
  } catch (error) {
    if (error instanceof MongooseError.ValidationError) {
      return error;
    }
    throw error;
  }
}

describe('SessionModel (schema-level tests)', () => {
  it('exports SessionModel with expected name, collection, and idempotent registration', () => {
    expect(SessionModel.modelName).toBe('Session');
    expect(SessionModel.collection.name).toBe('sessions');
    expect(getOrCreateModel('Session', sessionSchema)).toBe(SessionModel);
  });

  it('validates required fields and applies default null lifecycle timestamps', async () => {
    const missing = new SessionModel({});
    const missingError = await getValidationError(missing);
    expect(missingError?.errors.userId?.kind).toBe('required');
    expect(missingError?.errors.refreshTokenHash?.kind).toBe('required');
    expect(missingError?.errors.expiresAt?.kind).toBe('required');

    const userId = new Types.ObjectId();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const session = new SessionModel({
      userId,
      refreshTokenHash: 'a'.repeat(64),
      expiresAt,
    });

    expect(await getValidationError(session)).toBeUndefined();
    expect(session.userId.equals(userId)).toBe(true);
    expect(session.previousRefreshTokenHash).toBeNull();
    expect(session.revokedAt).toBeNull();
    expect(session.lastUsedAt).toBeNull();
  });

  it('references User via ObjectId and excludes token hashes from selection and serialization', () => {
    const userPath = sessionSchema.path('userId');
    expect(userPath).toBeInstanceOf(Schema.Types.ObjectId);
    expect(userPath.options.ref).toBe('User');

    expect(sessionSchema.path('refreshTokenHash').options.select).toBe(false);
    expect(sessionSchema.path('previousRefreshTokenHash').options.select).toBe(false);

    const session = new SessionModel({
      userId: new Types.ObjectId(),
      refreshTokenHash: 'secret_hash_current_123',
      previousRefreshTokenHash: 'secret_hash_previous_456',
      expiresAt: new Date(Date.now() + 60_000),
    });

    const jsonObj = session.toJSON() as unknown as Record<string, unknown>;
    const plainObj = session.toObject() as unknown as Record<string, unknown>;
    const serialized = JSON.stringify(session);

    expect(jsonObj.refreshTokenHash).toBeUndefined();
    expect(jsonObj.previousRefreshTokenHash).toBeUndefined();
    expect(jsonObj.__v).toBeUndefined();
    expect(plainObj.refreshTokenHash).toBeUndefined();
    expect(plainObj.previousRefreshTokenHash).toBeUndefined();
    expect(serialized).not.toContain('secret_hash_current_123');
    expect(serialized).not.toContain('secret_hash_previous_456');
  });

  it('defines unique refreshTokenHash index, previousRefreshTokenHash partial index, active lookup index, and TTL index', () => {
    const indexes = sessionSchema.indexes();

    expect(indexes).toContainEqual([
      { refreshTokenHash: 1 },
      expect.objectContaining({ unique: true, name: 'sessions_refresh_token_hash_unique' }),
    ]);
    expect(indexes).toContainEqual([
      { previousRefreshTokenHash: 1 },
      expect.objectContaining({
        name: 'sessions_prev_refresh_token_hash_idx',
        partialFilterExpression: { previousRefreshTokenHash: { $type: 'string' } },
      }),
    ]);
    expect(indexes).toContainEqual([
      { userId: 1, revokedAt: 1, expiresAt: 1 },
      expect.objectContaining({ name: 'sessions_user_active_idx' }),
    ]);
    expect(indexes).toContainEqual([
      { expiresAt: 1 },
      expect.objectContaining({ expireAfterSeconds: 0, name: 'sessions_expires_at_ttl_idx' }),
    ]);
  });
});
