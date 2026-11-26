import { SignJWT, jwtVerify } from 'jose';
import { AuthError } from './auth.types.js';

export interface JwtTokenConfig {
  secret: string;
  issuer: string;
  audience: string;
  accessTtl: string;
  accessTtlSeconds: number;
}

export interface AccessTokenPayload {
  userId: string;
  sessionId: string;
}

export interface SignedAccessToken {
  token: string;
  expiresIn: number;
}

export interface JwtService {
  signAccessToken(payload: AccessTokenPayload, config: JwtTokenConfig): Promise<SignedAccessToken>;
  verifyAccessToken(token: string, config: JwtTokenConfig): Promise<AccessTokenPayload>;
}

const JWT_ALGORITHM = 'HS256';
const MIN_SECRET_LENGTH = 32;
const textEncoder = new TextEncoder();

function encodeSecret(secret: string): Uint8Array {
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    throw new AuthError(500, 'AUTH_CONFIGURATION_ERROR', 'Authentication service is misconfigured');
  }
  return textEncoder.encode(secret);
}

/**
 * Dedicated JWT issuance and verification service using explicit HS256 signing
 * and strict issuer, audience, expiration, and subject/session claim checks.
 */
export function createJwtService(): JwtService {
  return {
    async signAccessToken(
      payload: AccessTokenPayload,
      config: JwtTokenConfig
    ): Promise<SignedAccessToken> {
      const secretKey = encodeSecret(config.secret);

      const token = await new SignJWT({ sid: payload.sessionId })
        .setProtectedHeader({ alg: JWT_ALGORITHM, typ: 'JWT' })
        .setSubject(payload.userId)
        .setIssuer(config.issuer)
        .setAudience(config.audience)
        .setIssuedAt()
        .setExpirationTime(config.accessTtl)
        .sign(secretKey);

      return {
        token,
        expiresIn: config.accessTtlSeconds,
      };
    },

    async verifyAccessToken(token: string, config: JwtTokenConfig): Promise<AccessTokenPayload> {
      if (typeof token !== 'string' || token.trim().length === 0) {
        throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
      }

      const secretKey = encodeSecret(config.secret);

      try {
        const { payload } = await jwtVerify(token, secretKey, {
          algorithms: [JWT_ALGORITHM],
          issuer: config.issuer,
          audience: config.audience,
          requiredClaims: ['sub', 'sid', 'exp', 'iat', 'iss', 'aud'],
        });

        const userId = payload.sub;
        const sessionId = payload.sid;

        if (
          typeof userId !== 'string' ||
          userId.length === 0 ||
          typeof sessionId !== 'string' ||
          sessionId.length === 0
        ) {
          throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
        }

        return { userId, sessionId };
      } catch (error) {
        if (error instanceof AuthError) {
          throw error;
        }
        throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
      }
    },
  };
}

export const jwtService = createJwtService();
