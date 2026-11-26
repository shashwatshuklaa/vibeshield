import { describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';
import { createJwtService, type JwtTokenConfig } from '../modules/auth/jwt.service.js';
import { createPasswordService } from '../modules/auth/password.service.js';
import { AuthError } from '../modules/auth/auth.types.js';

describe('Password Security (Argon2id)', () => {
  const passwordService = createPasswordService();

  it('creates an Argon2id hash and never returns plaintext', async () => {
    const plaintext = 'correct horse battery staple';
    const hash = await passwordService.hashPassword(plaintext);

    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(hash).not.toContain(plaintext);
  });

  it('verifies matching and non-matching passwords accurately', async () => {
    const plaintext = 'vibe-shield-passphrase-123';
    const hash = await passwordService.hashPassword(plaintext);

    expect(await passwordService.verifyPassword(hash, plaintext)).toBe(true);
    expect(await passwordService.verifyPassword(hash, 'wrong-passphrase-123')).toBe(false);
  });

  it('handles malformed or non-argon2id password hashes safely without throwing', async () => {
    expect(await passwordService.verifyPassword('', 'password123456')).toBe(false);
    expect(await passwordService.verifyPassword('not-a-valid-hash', 'password123456')).toBe(false);
    expect(await passwordService.verifyPassword('$2b$12$legacybcrypt', 'password123456')).toBe(
      false
    );
    expect(
      await passwordService.verifyPassword('$argon2id$corrupt$payload', 'password123456')
    ).toBe(false);
  });
});

describe('JWT Access Token Service (HS256)', () => {
  const jwtService = createJwtService();
  const jwtConfig: JwtTokenConfig = {
    secret: 'super_secure_test_jwt_secret_at_least_32_bytes',
    issuer: 'vibeshield-api',
    audience: 'vibeshield-clients',
    accessTtl: '15m',
    accessTtlSeconds: 900,
  };

  it('signs and verifies a valid access token with sub, sid, iss, and aud', async () => {
    const signed = await jwtService.signAccessToken(
      { userId: '507f1f77bcf86cd799439011', sessionId: '507f1f77bcf86cd799439022' },
      jwtConfig
    );

    expect(signed.expiresIn).toBe(900);
    const claims = await jwtService.verifyAccessToken(signed.token, jwtConfig);
    expect(claims).toEqual({
      userId: '507f1f77bcf86cd799439011',
      sessionId: '507f1f77bcf86cd799439022',
    });

    // Ensure no sensitive PII or password claims are embedded in JWT payload
    const payloadPart = signed.token.split('.')[1]!;
    const decodedPayload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
    expect(decodedPayload.sub).toBe('507f1f77bcf86cd799439011');
    expect(decodedPayload.sid).toBe('507f1f77bcf86cd799439022');
    expect(decodedPayload.password).toBeUndefined();
    expect(decodedPayload.passwordHash).toBeUndefined();
    expect(decodedPayload.email).toBeUndefined();
  });

  it('rejects tokens signed with an invalid signature', async () => {
    const signed = await jwtService.signAccessToken(
      { userId: '507f1f77bcf86cd799439011', sessionId: '507f1f77bcf86cd799439022' },
      jwtConfig
    );

    await expect(
      jwtService.verifyAccessToken(signed.token, {
        ...jwtConfig,
        secret: 'another_completely_different_secret_over_32_chars',
      })
    ).rejects.toMatchObject({
      statusCode: 401,
      code: 'UNAUTHORIZED',
    });
  });

  it('rejects expired tokens', async () => {
    const expiredToken = await new SignJWT({ sid: '507f1f77bcf86cd799439022' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject('507f1f77bcf86cd799439011')
      .setIssuer(jwtConfig.issuer)
      .setAudience(jwtConfig.audience)
      .setIssuedAt(Math.floor(Date.now() / 1000) - 120)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(new TextEncoder().encode(jwtConfig.secret));

    await expect(jwtService.verifyAccessToken(expiredToken, jwtConfig)).rejects.toMatchObject({
      statusCode: 401,
      code: 'UNAUTHORIZED',
    });
  });

  it('rejects tokens with incorrect issuer or audience', async () => {
    const signed = await jwtService.signAccessToken(
      { userId: '507f1f77bcf86cd799439011', sessionId: '507f1f77bcf86cd799439022' },
      jwtConfig
    );

    await expect(
      jwtService.verifyAccessToken(signed.token, { ...jwtConfig, issuer: 'wrong-issuer' })
    ).rejects.toBeInstanceOf(AuthError);

    await expect(
      jwtService.verifyAccessToken(signed.token, { ...jwtConfig, audience: 'wrong-audience' })
    ).rejects.toBeInstanceOf(AuthError);
  });

  it('rejects tokens with missing sid or sub claims or disallowed algorithms', async () => {
    const secretKey = new TextEncoder().encode(jwtConfig.secret);

    const missingSid = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject('507f1f77bcf86cd799439011')
      .setIssuer(jwtConfig.issuer)
      .setAudience(jwtConfig.audience)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(secretKey);

    await expect(jwtService.verifyAccessToken(missingSid, jwtConfig)).rejects.toMatchObject({
      statusCode: 401,
    });

    const wrongAlg = await new SignJWT({ sid: '507f1f77bcf86cd799439022' })
      .setProtectedHeader({ alg: 'HS384', typ: 'JWT' })
      .setSubject('507f1f77bcf86cd799439011')
      .setIssuer(jwtConfig.issuer)
      .setAudience(jwtConfig.audience)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(secretKey);

    await expect(jwtService.verifyAccessToken(wrongAlg, jwtConfig)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('refuses weak secrets under 32 characters', async () => {
    await expect(
      jwtService.signAccessToken(
        { userId: '507f1f77bcf86cd799439011', sessionId: '507f1f77bcf86cd799439022' },
        { ...jwtConfig, secret: 'short' }
      )
    ).rejects.toMatchObject({
      statusCode: 500,
      code: 'AUTH_CONFIGURATION_ERROR',
    });
  });
});
