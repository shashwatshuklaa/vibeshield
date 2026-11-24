import { describe, expect, it } from 'vitest';
import { z, ZodError } from 'zod';
import { EnvValidationError } from '../error.js';

describe('EnvValidationError & sanitization', () => {
  it('creates an EnvValidationError with sanitized issues and immutable issue array', () => {
    const issues = [
      { variable: 'AUTH_SECRET', message: 'Missing required environment variable' },
      { variable: 'PORT', message: 'Expected number, received string' },
    ];

    const error = new EnvValidationError(issues);

    expect(error.name).toBe('EnvValidationError');
    expect(error.issues).toHaveLength(2);
    expect(error.issues[0]).toEqual(issues[0]);
    expect(error.issues[1]).toEqual(issues[1]);
    expect(Object.isFrozen(error.issues)).toBe(true);
    expect(error.message).toContain('AUTH_SECRET: Missing required environment variable');
    expect(error.message).toContain('PORT: Expected number, received string');
  });

  describe('sanitization prevents secret leakage', () => {
    it('does not expose sensitive values when length constraints fail', () => {
      const SECRET_API_KEY = 'short_secret_value_123';

      const schema = z.object({
        SECRET_API_KEY: z.string().min(50),
        PASSWORD: z.string().max(5),
      });

      let caughtError: EnvValidationError | null = null;
      try {
        schema.parse({
          SECRET_API_KEY: SECRET_API_KEY,
          PASSWORD: 'super_secret_master_password_456',
        });
      } catch (err) {
        if (err instanceof ZodError) {
          caughtError = EnvValidationError.fromZodError(err);
        }
      }

      expect(caughtError).not.toBeNull();
      const serialized = `${caughtError?.message} ${JSON.stringify(caughtError?.issues)}`;

      // Must never contain sensitive inputs
      expect(serialized).not.toContain(SECRET_API_KEY);
      expect(serialized).not.toContain('super_secret_master_password_456');

      // Instead, contains safe generic descriptions
      expect(caughtError?.issues[0].message).toBe(
        'Value is too short (minimum 50 characters required)'
      );
      expect(caughtError?.issues[1].message).toBe(
        'Value is too long (maximum 5 characters allowed)'
      );
    });

    it('does not expose sensitive values when enum constraints fail', () => {
      const INVALID_SECRET_TYPE = 'extremely_secret_custom_token_type';

      const schema = z.object({
        TOKEN_TYPE: z.enum(['bearer', 'basic', 'api_key']),
      });

      let caughtError: EnvValidationError | null = null;
      try {
        schema.parse({ TOKEN_TYPE: INVALID_SECRET_TYPE });
      } catch (err) {
        if (err instanceof ZodError) {
          caughtError = EnvValidationError.fromZodError(err);
        }
      }

      expect(caughtError).not.toBeNull();
      const serialized = `${caughtError?.message} ${JSON.stringify(caughtError?.issues)}`;

      expect(serialized).not.toContain(INVALID_SECRET_TYPE);
      expect(caughtError?.issues[0].message).toBe(
        "Invalid value. Expected one of: 'bearer', 'basic', 'api_key'"
      );
    });

    it('does not expose malformed sensitive URLs or emails', () => {
      const schema = z.object({
        DATABASE_URL: z.string().url(),
        SECURITY_ALERT_EMAIL: z.string().email(),
      });

      let caughtError: EnvValidationError | null = null;
      try {
        schema.parse({
          DATABASE_URL: 'not a valid url password123',
          SECURITY_ALERT_EMAIL: 'not-an-email-with-secret:token999',
        });
      } catch (err) {
        if (err instanceof ZodError) {
          caughtError = EnvValidationError.fromZodError(err);
        }
      }

      expect(caughtError).not.toBeNull();
      const serialized = `${caughtError?.message} ${JSON.stringify(caughtError?.issues)}`;

      expect(serialized).not.toContain('password123');
      expect(serialized).not.toContain('token999');

      const dbIssue = caughtError?.issues.find((i) => i.variable === 'DATABASE_URL');
      const emailIssue = caughtError?.issues.find((i) => i.variable === 'SECURITY_ALERT_EMAIL');

      expect(dbIssue?.message).toBe('Must be a valid URL');
      expect(emailIssue?.message).toBe('Must be a valid email address');
    });

    it('redacts received values in unexpected fallback error messages', () => {
      const customZodIssue = {
        code: 'custom' as const,
        path: ['SPECIAL_CREDENTIAL'],
        message: "Invalid configuration: received 'my-secret-token-key-777'",
      };

      const syntheticZodError = new ZodError([customZodIssue]);
      const envError = EnvValidationError.fromZodError(syntheticZodError);

      expect(envError.message).not.toContain('my-secret-token-key-777');
      expect(envError.issues[0].message).toBe('Invalid configuration: received [REDACTED]');
    });
  });
});
