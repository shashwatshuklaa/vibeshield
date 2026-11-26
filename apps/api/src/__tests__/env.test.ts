import { describe, expect, it } from 'vitest';
import { EnvValidationError } from '@vibeshield/env';
import { getApiConfig, toAuthConfig } from '../config/env.js';

const TEST_JWT_SECRET = 'test_jwt_access_secret_minimum_32_characters_long';

describe('API Environment Configuration', () => {
  it('validates a complete API environment with mongodb:// URI and auth defaults', () => {
    const config = getApiConfig({
      NODE_ENV: 'development',
      PORT: '4000',
      HOST: '127.0.0.1',
      API_PREFIX: '/api/v1',
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    });

    expect(config).toEqual({
      NODE_ENV: 'development',
      PORT: 4000,
      LOG_LEVEL: 'info',
      HOST: '127.0.0.1',
      API_PREFIX: '/api/v1',
      CORS_ORIGIN: 'http://localhost:5173',
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      JWT_ACCESS_TTL: '15m',
      JWT_ISSUER: 'vibeshield-api',
      JWT_AUDIENCE: 'vibeshield-clients',
      AUTH_REFRESH_TOKEN_TTL: '7d',
    });

    expect(toAuthConfig(config)).toEqual({
      jwtAccessSecret: TEST_JWT_SECRET,
      jwtAccessTtl: '15m',
      jwtAccessTtlSeconds: 900,
      jwtIssuer: 'vibeshield-api',
      jwtAudience: 'vibeshield-clients',
      refreshTokenTtlSeconds: 604800,
      isProduction: false,
      cookiePath: '/api/v1/auth',
      allowedOrigins: ['http://localhost:5173'],
    });
  });

  it('validates mongodb+srv:// Atlas URIs', () => {
    const config = getApiConfig({
      MONGODB_URI: 'mongodb+srv://appuser:apppass@cluster0.example.mongodb.net/vibeshield',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    });

    expect(config.MONGODB_URI).toBe(
      'mongodb+srv://appuser:apppass@cluster0.example.mongodb.net/vibeshield'
    );
  });

  it('throws EnvValidationError when MONGODB_URI or JWT_ACCESS_SECRET is missing', () => {
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
        {
          variable: 'JWT_ACCESS_SECRET',
          message: 'Missing required environment variable',
        },
      ]);
    }
  });

  it('rejects short JWT_ACCESS_SECRET without leaking the secret value', () => {
    const shortSecret = 'too_short_secret_value';

    try {
      getApiConfig({
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
        JWT_ACCESS_SECRET: shortSecret,
      });
      expect.unreachable('Should have thrown EnvValidationError');
    } catch (error) {
      const err = error as EnvValidationError;
      expect(err.issues[0]?.variable).toBe('JWT_ACCESS_SECRET');
      expect(err.message).not.toContain(shortSecret);
    }
  });

  it('throws EnvValidationError when MONGODB_URI is invalid and never leaks credentials or URI value', () => {
    const sensitiveInvalidUri = 'postgres://admin:superSecretPassword@prod-db.internal:5432/app';

    let caught: unknown;
    try {
      getApiConfig({
        MONGODB_URI: sensitiveInvalidUri,
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
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

  it('parses comma-separated CORS_ORIGIN values and rejects invalid origins', () => {
    const config = getApiConfig({
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      CORS_ORIGIN: 'https://app.vibeshield.io/, http://localhost:5173',
    });

    expect(toAuthConfig(config).allowedOrigins).toEqual([
      'https://app.vibeshield.io',
      'http://localhost:5173',
    ]);

    expect(() =>
      getApiConfig({
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        CORS_ORIGIN: 'not-a-valid-origin',
      })
    ).toThrow(EnvValidationError);
  });
});
