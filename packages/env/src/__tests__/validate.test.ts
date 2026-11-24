import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { baseEnvSchema } from '../base.js';
import { EnvValidationError } from '../error.js';
import { validateEnv } from '../validate.js';

describe('validateEnv', () => {
  it('successfully validates and returns typed environment with base schema', () => {
    const customSource = {
      NODE_ENV: 'production',
      PORT: '8080',
      LOG_LEVEL: 'warn',
    };

    const env = validateEnv(baseEnvSchema, customSource);

    expect(env).toEqual({
      NODE_ENV: 'production',
      PORT: 8080,
      LOG_LEVEL: 'warn',
    });
  });

  it('successfully validates schema extensions', () => {
    const extendedSchema = baseEnvSchema.extend({
      SERVICE_NAME: z.string().min(1),
      API_TIMEOUT_MS: z.string().regex(/^\d+$/).transform(Number),
      ENABLE_FEATURE: z.enum(['true', 'false']).transform((v) => v === 'true'),
    });

    const customSource = {
      SERVICE_NAME: 'security-scanner',
      API_TIMEOUT_MS: '5000',
      ENABLE_FEATURE: 'true',
    };

    const env = validateEnv(extendedSchema, customSource);

    expect(env.SERVICE_NAME).toBe('security-scanner');
    expect(env.API_TIMEOUT_MS).toBe(5000);
    expect(env.ENABLE_FEATURE).toBe(true);
    expect(env.NODE_ENV).toBe('development'); // default from base schema
  });

  it('throws EnvValidationError when required variable is missing', () => {
    const schemaWithRequired = z.object({
      REQUIRED_KEY: z.string(),
    });

    expect(() => validateEnv(schemaWithRequired, {})).toThrow(EnvValidationError);

    try {
      validateEnv(schemaWithRequired, {});
    } catch (error) {
      expect(error).toBeInstanceOf(EnvValidationError);
      const envError = error as EnvValidationError;
      expect(envError.issues).toHaveLength(1);
      expect(envError.issues[0].variable).toBe('REQUIRED_KEY');
      expect(envError.issues[0].message).toBe('Missing required environment variable');
    }
  });

  it('throws EnvValidationError when variable format is invalid', () => {
    const schema = z.object({
      DATABASE_URL: z.string().url(),
      WORKER_COUNT: z.string().regex(/^\d+$/),
    });

    expect(() =>
      validateEnv(schema, {
        DATABASE_URL: 'invalid-url-format',
        WORKER_COUNT: 'abc',
      })
    ).toThrow(EnvValidationError);

    try {
      validateEnv(schema, {
        DATABASE_URL: 'invalid-url-format',
        WORKER_COUNT: 'abc',
      });
    } catch (error) {
      const envError = error as EnvValidationError;
      expect(envError.issues).toHaveLength(2);
      expect(envError.issues[0].variable).toBe('DATABASE_URL');
      expect(envError.issues[0].message).toBe('Must be a valid URL');
      expect(envError.issues[1].variable).toBe('WORKER_COUNT');
      expect(envError.issues[1].message).toBe('Invalid string format (expected regex)');
    }
  });

  it('formats overall error message with clean bulleted list', () => {
    const schema = z.object({
      VAR_A: z.string(),
      VAR_B: z.string(),
    });

    try {
      validateEnv(schema, {});
      expect.unreachable('Should have thrown an EnvValidationError');
    } catch (error) {
      const envError = error as EnvValidationError;
      expect(envError.message).toContain('Environment configuration validation failed:');
      expect(envError.message).toContain('- VAR_A: Missing required environment variable');
      expect(envError.message).toContain('- VAR_B: Missing required environment variable');
      expect(envError.message).toContain(
        'Please check your environment configuration or .env file.'
      );
    }
  });
});
