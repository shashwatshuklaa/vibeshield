import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EnvValidationError } from '@vibeshield/env';
import {
  getApiConfig,
  redactGitHubEnvSecrets,
  toAuthConfig,
  toGitHubConfig,
} from '../config/env.js';

const TEST_JWT_SECRET = 'test_jwt_access_secret_minimum_32_characters_long';
const TEST_WEBHOOK_SECRET = 'whsec_test_webhook_secret_at_least_32_chars';
const TEST_WEBHOOK_SECRET_PREVIOUS = 'whsec_prev_webhook_secret_at_least_32_chars';
const TEST_CLIENT_SECRET = 'gh_client_secret_value_min_20';

function generateEphemeralTestRsaPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return privateKey;
}

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

  it('returns null from toGitHubConfig when GitHub integration is omitted', () => {
    const config = getApiConfig({
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    });

    expect(toGitHubConfig(config)).toBeNull();
  });

  it('validates complete GitHub App configuration and normalizes escaped newlines in PEM keys', () => {
    const testPem = generateEphemeralTestRsaPem();
    const escapedPem = testPem.replace(/\n/g, '\\n');

    const config = getApiConfig({
      MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
      JWT_ACCESS_SECRET: TEST_JWT_SECRET,
      GITHUB_APP_ID: '123456',
      GITHUB_APP_SLUG: '  VibeShield-App  ',
      GITHUB_APP_PRIVATE_KEY: escapedPem,
      GITHUB_CLIENT_ID: 'Iv1.testclientid12',
      GITHUB_CLIENT_SECRET: TEST_CLIENT_SECRET,
      GITHUB_WEBHOOK_SECRET: TEST_WEBHOOK_SECRET,
      GITHUB_WEBHOOK_SECRET_PREVIOUS: TEST_WEBHOOK_SECRET_PREVIOUS,
      GITHUB_CALLBACK_URL: 'https://app.vibeshield.io/integrations/github/callback',
    });

    const ghConfig = toGitHubConfig(config);
    expect(ghConfig).toEqual({
      appId: 123456,
      appSlug: 'vibeshield-app',
      privateKeyPem: testPem.trim(),
      clientId: 'Iv1.testclientid12',
      clientSecret: TEST_CLIENT_SECRET,
      webhookSecret: TEST_WEBHOOK_SECRET,
      previousWebhookSecret: TEST_WEBHOOK_SECRET_PREVIOUS,
      callbackUrl: 'https://app.vibeshield.io/integrations/github/callback',
    });

    const leakedText = `Failed with secret ${TEST_CLIENT_SECRET}, ${TEST_WEBHOOK_SECRET}, and ${escapedPem}`;
    const redacted = redactGitHubEnvSecrets(leakedText, config);
    expect(redacted).not.toContain(TEST_CLIENT_SECRET);
    expect(redacted).not.toContain(TEST_WEBHOOK_SECRET);
    expect(redacted).not.toContain('BEGIN PRIVATE KEY');
  });

  it('rejects partial GitHub configuration via all-or-none validation', () => {
    let caught: unknown;
    try {
      getApiConfig({
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        GITHUB_APP_ID: '123456',
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(EnvValidationError);
    const err = caught as EnvValidationError;
    const variables = err.issues.map((issue) => issue.variable);
    expect(variables).toEqual([
      'GITHUB_APP_SLUG',
      'GITHUB_APP_PRIVATE_KEY',
      'GITHUB_CLIENT_ID',
      'GITHUB_CLIENT_SECRET',
      'GITHUB_WEBHOOK_SECRET',
      'GITHUB_CALLBACK_URL',
    ]);
  });

  it('rejects invalid PEM keys, wildcard or non-HTTPS production callback URLs, and malformed GitHub settings without leaking secrets', () => {
    const malformedPem =
      '-----BEGIN PRIVATE KEY-----\nSECRET_BODY_DO_NOT_LEAK\n-----END PRIVATE KEY-----';
    const shortWebhook = 'too_short_webhook_secret_leak';
    const shortClientSecret = 'short_client_leak';

    let caught: unknown;
    try {
      getApiConfig({
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_dev',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        GITHUB_APP_ID: '0',
        GITHUB_APP_SLUG: 'Invalid Slug!',
        GITHUB_APP_PRIVATE_KEY: malformedPem,
        GITHUB_CLIENT_ID: 'short',
        GITHUB_CLIENT_SECRET: shortClientSecret,
        GITHUB_WEBHOOK_SECRET: shortWebhook,
        GITHUB_CALLBACK_URL: 'https://*.vibeshield.io/callback?open=1',
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(EnvValidationError);
    const err = caught as EnvValidationError;
    expect(err.issues.map((issue) => issue.variable)).toEqual([
      'GITHUB_APP_ID',
      'GITHUB_APP_SLUG',
      'GITHUB_APP_PRIVATE_KEY',
      'GITHUB_CLIENT_ID',
      'GITHUB_CLIENT_SECRET',
      'GITHUB_WEBHOOK_SECRET',
      'GITHUB_CALLBACK_URL',
    ]);
    expect(err.message).not.toContain('SECRET_BODY_DO_NOT_LEAK');
    expect(err.message).not.toContain(shortWebhook);
    expect(err.message).not.toContain(shortClientSecret);

    // Reject plain HTTP callback URL in production
    expect(() =>
      getApiConfig({
        NODE_ENV: 'production',
        MONGODB_URI: 'mongodb://localhost:27017/vibeshield_prod',
        JWT_ACCESS_SECRET: TEST_JWT_SECRET,
        GITHUB_APP_ID: '123456',
        GITHUB_APP_SLUG: 'vibeshield-prod',
        GITHUB_APP_PRIVATE_KEY: generateEphemeralTestRsaPem(),
        GITHUB_CLIENT_ID: 'Iv1.prodclientid12',
        GITHUB_CLIENT_SECRET: TEST_CLIENT_SECRET,
        GITHUB_WEBHOOK_SECRET: TEST_WEBHOOK_SECRET,
        GITHUB_CALLBACK_URL: 'http://app.vibeshield.io/integrations/github/callback',
      })
    ).toThrow(EnvValidationError);
  });
});
