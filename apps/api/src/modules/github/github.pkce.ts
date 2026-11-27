import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { GitHubError } from './github.types.js';

const PKCE_VERIFIER_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;
const PKCE_ENCRYPTION_INFO = Buffer.from('vibeshield:github:pkce:v1', 'utf8');
const PKCE_ENVELOPE_VERSION = 'v1';

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

/**
 * Computes the S256 Base64URL SHA-256 code challenge for an RFC 7636 PKCE verifier.
 */
export function derivePkceS256Challenge(codeVerifier: string): string {
  if (!PKCE_VERIFIER_REGEX.test(codeVerifier)) {
    throw new GitHubError(
      400,
      'INVALID_PKCE_VERIFIER',
      'PKCE code verifier does not meet RFC 7636 entropy and character requirements'
    );
  }
  return createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
}

/**
 * Generates a 256-bit CSPRNG PKCE code verifier and its S256 challenge.
 */
export function generatePkcePair(): PkcePair {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = derivePkceS256Challenge(codeVerifier);
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}

function derivePkceEncryptionKey(secretKeyMaterial: string, stateHash: string): Buffer {
  if (!secretKeyMaterial || secretKeyMaterial.length < 16) {
    throw new GitHubError(
      500,
      'GITHUB_CONFIGURATION_ERROR',
      'GitHub client secret is insufficient for PKCE verifier protection'
    );
  }

  const derived = hkdfSync(
    'sha256',
    Buffer.from(secretKeyMaterial, 'utf8'),
    Buffer.from(stateHash, 'hex'),
    PKCE_ENCRYPTION_INFO,
    32
  );
  return Buffer.from(derived);
}

function buildPkceAad(userId: string, organizationId: string, stateHash: string): Buffer {
  return Buffer.from(`${userId}:${organizationId}:${stateHash}`, 'utf8');
}

/**
 * Encrypts a PKCE code verifier using AES-256-GCM bound via AAD to the user,
 * organization, and SHA-256 state hash so raw verifiers are never persisted in MongoDB.
 */
export function encryptPkceVerifier(input: {
  codeVerifier: string;
  secretKeyMaterial: string;
  stateHash: string;
  userId: string;
  organizationId: string;
}): string {
  if (!PKCE_VERIFIER_REGEX.test(input.codeVerifier)) {
    throw new GitHubError(500, 'PKCE_INTERNAL_ERROR', 'Invalid PKCE verifier generated');
  }

  const key = derivePkceEncryptionKey(input.secretKeyMaterial, input.stateHash);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(buildPkceAad(input.userId, input.organizationId, input.stateHash));

  const ciphertext = Buffer.concat([cipher.update(input.codeVerifier, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${PKCE_ENVELOPE_VERSION}.${iv.toString('base64url')}.${authTag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

/**
 * Decrypts and verifies a stored PKCE code verifier envelope against its bound context.
 */
export function decryptPkceVerifier(input: {
  envelope: string;
  secretKeyMaterial: string;
  stateHash: string;
  userId: string;
  organizationId: string;
}): string {
  const parts = input.envelope.split('.');
  if (parts.length !== 4 || parts[0] !== PKCE_ENVELOPE_VERSION) {
    throw new GitHubError(
      400,
      'INVALID_OAUTH_STATE',
      'GitHub authorization state or PKCE binding is invalid'
    );
  }

  const [, ivB64, tagB64, cipherB64] = parts as [string, string, string, string];

  try {
    const key = derivePkceEncryptionKey(input.secretKeyMaterial, input.stateHash);
    const iv = Buffer.from(ivB64, 'base64url');
    const authTag = Buffer.from(tagB64, 'base64url');
    const ciphertext = Buffer.from(cipherB64, 'base64url');

    if (iv.length !== 12 || authTag.length !== 16 || ciphertext.length === 0) {
      throw new Error('Malformed AES-GCM envelope');
    }

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    decipher.setAAD(buildPkceAad(input.userId, input.organizationId, input.stateHash));

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
      'utf8'
    );
    if (!PKCE_VERIFIER_REGEX.test(plaintext)) {
      throw new Error('Decrypted PKCE verifier failed format check');
    }
    return plaintext;
  } catch (error) {
    if (error instanceof GitHubError) {
      throw error;
    }
    throw new GitHubError(
      400,
      'INVALID_OAUTH_STATE',
      'GitHub authorization state or PKCE binding is invalid'
    );
  }
}
