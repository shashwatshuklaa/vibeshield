import { describe, expect, it } from 'vitest';
import { EnvValidationError } from '@vibeshield/env';
import { getApiConfig } from '../config/env.js';

describe('API Environment Configuration', () => {
  it('validates a complete API environment with mongodb:// URI', () => {
    const config = getApiConfig({
      NODE_ENV: 'development',
      PORT: '4000',
      HOST: '127.0.0.1',
      API_PREFIX: '/api/v1',
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
    });

    expect(config).toEqual({
      NODE_ENV: 'development',
      PORT: 4000,
      LOG_LEVEL: 'info',
      HOST: '127.0.0.1',
      API_PREFIX: '/api/v1',
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
    });
  });

  it('validates mongodb+srv:// Atlas URIs', () => {
    const config = getApiConfig({
      MONGODB_URI: 'mongodb+srv://appuser:apppass@cluster0.example.mongodb.net/vibeshield',
    });

    expect(config.MONGODB_URI).toBe(
      'mongodb+srv://appuser:apppass@cluster0.example.mongodb.net/vibeshield'
    );
  });

  it('throws EnvValidationError when MONGODB_URI is missing', () => {
    expect(() => getApiConfig({ NODE_ENV: 'test' })).toThrow(EnvValidationError);

    try {
      getApiConfig({ NODE_ENV: 'test' });
    } catch (error) {
      const err = error as EnvValidationError;
      expect(err.issues).toEqual([
        {
          variable: 'MONGODB_URI',
          message: 'Missing required environment variable',
        },
      ]);
    }
  });

  it('throws EnvValidationError when MONGODB_URI is invalid and never leaks credentials or URI value', () => {
    const sensitiveInvalidUri = 'postgres://admin:superSecretPassword@prod-db.internal:5432/app';

    let caught: unknown;
    try {
      getApiConfig({
        MONGODB_URI: sensitiveInvalidUri,
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(EnvValidationError);
    const err = caught as EnvValidationError;
    expect(err.issues[0]?.variable).toBe('MONGODB_URI');
    expect(err.message).not.toContain('superSecretPassword');
    expect(err.message).not.toContain('prod-db.internal');
    expect(err.message).not.toContain(sensitiveInvalidUri);
  });
});
