import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';
import { GitHubError } from './github.types.js';

export interface GitHubAppJwtOptions {
  appId: number;
  privateKeyPem: string;
  now?: () => Date;
  clockSkewSeconds?: number;
  ttlSeconds?: number;
}

const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_APP_JWT_TTL_SECONDS = 540; // 9 minutes; together with 60s iat skew, exp - iat = 600s max
const MAX_GITHUB_APP_JWT_LIFETIME_SECONDS = 600;

function encodeBase64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function parseRsaPrivateKey(privateKeyPem: string): KeyObject {
  try {
    const keyObject = createPrivateKey({ key: privateKeyPem, format: 'pem' });
    if (keyObject.type !== 'private' || keyObject.asymmetricKeyType !== 'rsa') {
      throw new Error('Not an RSA private key');
    }
    return keyObject;
  } catch {
    throw new GitHubError(
      500,
      'GITHUB_CONFIGURATION_ERROR',
      'GitHub App private key configuration is invalid'
    );
  }
}

/**
 * Generates an RS256-signed GitHub App JWT bounded to GitHub's 10-minute lifetime limit,
 * accounting for clock skew without ever exposing the private key or JWT in errors.
 */
export function createGitHubAppJwt(options: GitHubAppJwtOptions): string {
  const {
    appId,
    privateKeyPem,
    now = () => new Date(),
    clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
    ttlSeconds = DEFAULT_APP_JWT_TTL_SECONDS,
  } = options;

  if (!Number.isSafeInteger(appId) || appId < 1) {
    throw new GitHubError(
      500,
      'GITHUB_CONFIGURATION_ERROR',
      'GitHub App identifier configuration is invalid'
    );
  }

  if (
    !Number.isInteger(clockSkewSeconds) ||
    clockSkewSeconds < 0 ||
    !Number.isInteger(ttlSeconds) ||
    ttlSeconds < 1 ||
    ttlSeconds + clockSkewSeconds > MAX_GITHUB_APP_JWT_LIFETIME_SECONDS
  ) {
    throw new GitHubError(
      500,
      'GITHUB_CONFIGURATION_ERROR',
      'GitHub App JWT lifetime configuration exceeds allowed bounds'
    );
  }

  const keyObject = parseRsaPrivateKey(privateKeyPem);
  const nowSeconds = Math.floor(now().getTime() / 1000);
  const iat = nowSeconds - clockSkewSeconds;
  const exp = nowSeconds + ttlSeconds;

  const headerSegment = encodeBase64UrlJson({ alg: 'RS256', typ: 'JWT' });
  const payloadSegment = encodeBase64UrlJson({
    iat,
    exp,
    iss: String(appId),
  });
  const signingInput = `${headerSegment}.${payloadSegment}`;

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput, 'utf8');
  signer.end();

  const signature = signer.sign(keyObject).toString('base64url');
  return `${signingInput}.${signature}`;
}
