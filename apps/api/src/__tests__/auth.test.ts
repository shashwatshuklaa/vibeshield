import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import type { UserStatus } from '@vibeshield/database';
import { createApp } from '../app.js';
import {
  createAuthService,
  hashRefreshToken,
  type AuthStore,
  type StoredSessionRef,
  type StoredUserWithPassword,
} from '../modules/auth/auth.service.js';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  type AuthRuntimeConfig,
  type PublicUser,
} from '../modules/auth/auth.types.js';

interface InMemorySessionRecord {
  id: string;
  userId: string;
  refreshTokenHash: string;
  previousRefreshTokenHash: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
}

class InMemoryAuthStore implements AuthStore {
  public readonly users = new Map<string, StoredUserWithPassword>();
  public readonly sessions = new Map<string, InMemorySessionRecord>();
  public readonly rotatedTokens = new Map<string, { sessionId: string; expiresAt: Date }>();

  async createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: UserStatus;
  }): Promise<PublicUser> {
    for (const existing of this.users.values()) {
      if (existing.email === input.email) {
        const duplicateError = new Error('E11000 duplicate key error') as Error & { code: number };
        duplicateError.code = 11000;
        throw duplicateError;
      }
    }

    const id = randomBytes(12).toString('hex');
    const record: StoredUserWithPassword = {
      id,
      email: input.email,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      status: input.status,
      createdAt: new Date(),
    };
    this.users.set(id, record);

    return {
      id: record.id,
      email: record.email,
      displayName: record.displayName,
      status: record.status,
      createdAt: record.createdAt,
    };
  }

  async findUserWithPasswordByEmail(email: string): Promise<StoredUserWithPassword | null> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return { ...user };
      }
    }
    return null;
  }

  async findActiveUserById(userId: string): Promise<PublicUser | null> {
    const user = this.users.get(userId);
    if (!user || user.status !== 'ACTIVE') {
      return null;
    }
    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      status: user.status,
      createdAt: user.createdAt,
    };
  }

  async createSession(input: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }): Promise<StoredSessionRef> {
    const id = randomBytes(12).toString('hex');
    this.sessions.set(id, {
      id,
      userId: input.userId,
      refreshTokenHash: input.refreshTokenHash,
      previousRefreshTokenHash: null,
      expiresAt: input.expiresAt,
      revokedAt: null,
      lastUsedAt: input.lastUsedAt,
    });
    return { id, userId: input.userId };
  }

  async rotateSession(input: {
    presentedHash: string;
    nextRefreshTokenHash: string;
    now: Date;
    nextExpiresAt: Date;
  }): Promise<StoredSessionRef | null> {
    for (const session of this.sessions.values()) {
      if (
        session.refreshTokenHash === input.presentedHash &&
        session.revokedAt === null &&
        session.expiresAt > input.now
      ) {
        session.previousRefreshTokenHash = input.presentedHash;
        session.refreshTokenHash = input.nextRefreshTokenHash;
        session.lastUsedAt = input.now;
        session.expiresAt = input.nextExpiresAt;
        return { id: session.id, userId: session.userId };
      }
    }
    return null;
  }

  async recordRotatedToken(input: {
    sessionId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<void> {
    if (!this.rotatedTokens.has(input.tokenHash)) {
      this.rotatedTokens.set(input.tokenHash, {
        sessionId: input.sessionId,
        expiresAt: input.expiresAt,
      });
    }
  }

  async revokeSessionByPreviousTokenHash(previousHash: string, now: Date): Promise<boolean> {
    for (const session of this.sessions.values()) {
      if (session.previousRefreshTokenHash === previousHash && session.revokedAt === null) {
        session.revokedAt = now;
        return true;
      }
    }
    return false;
  }

  async revokeSessionByRotatedTokenHash(tokenHash: string, now: Date): Promise<boolean> {
    const rotated = this.rotatedTokens.get(tokenHash);
    if (!rotated) {
      return false;
    }
    const session = this.sessions.get(rotated.sessionId);
    if (session && session.revokedAt === null) {
      session.revokedAt = now;
      return true;
    }
    return false;
  }

  async findActiveSessionByIdAndUserId(
    sessionId: string,
    userId: string,
    now: Date
  ): Promise<StoredSessionRef | null> {
    const session = this.sessions.get(sessionId);
    if (
      !session ||
      session.userId !== userId ||
      session.revokedAt !== null ||
      session.expiresAt <= now
    ) {
      return null;
    }
    return { id: session.id, userId: session.userId };
  }

  async revokeSessionById(sessionId: string, now: Date): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session && session.revokedAt === null) {
      session.revokedAt = now;
    }
  }

  async revokeSessionByIdAndUserId(sessionId: string, userId: string, now: Date): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session && session.userId === userId && session.revokedAt === null) {
      session.revokedAt = now;
    }
  }

  async revokeSessionByTokenHash(tokenHash: string, now: Date): Promise<void> {
    for (const session of this.sessions.values()) {
      if (
        (session.refreshTokenHash === tokenHash ||
          session.previousRefreshTokenHash === tokenHash) &&
        session.revokedAt === null
      ) {
        session.revokedAt = now;
      }
    }
  }
}

function createAuthTestHarness(overrides: { isProduction?: boolean; now?: () => Date } = {}) {
  const store = new InMemoryAuthStore();
  const config: AuthRuntimeConfig = {
    jwtAccessSecret: 'test_auth_access_secret_minimum_32_characters_long',
    jwtAccessTtl: '15m',
    jwtAccessTtlSeconds: 900,
    jwtIssuer: 'vibeshield-api',
    jwtAudience: 'vibeshield-clients',
    refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
    isProduction: overrides.isProduction ?? false,
    cookiePath: '/api/v1/auth',
    allowedOrigins: ['http://localhost:5173', 'https://app.vibeshield.io'],
  };

  const authService = createAuthService({
    config,
    store,
    now: overrides.now,
  });

  const app = createApp({
    auth: {
      authService,
      config,
    },
  });

  return { app, store, authService, config };
}

function extractCookieValue(setCookieHeader: string[] | undefined, cookieName: string): string {
  const cookieLine = setCookieHeader?.find((entry) => entry.startsWith(`${cookieName}=`));
  if (!cookieLine) {
    throw new Error(`Expected cookie ${cookieName} in Set-Cookie header`);
  }
  return cookieLine.split(';')[0]!.slice(`${cookieName}=`.length);
}

describe('Authentication Endpoints and Session Lifecycle', () => {
  describe('POST /api/v1/auth/register', () => {
    it('registers a user with normalized email, hashes password with Argon2id, and omits passwordHash', async () => {
      const { app, store } = createAuthTestHarness();

      const res = await request(app).post('/api/v1/auth/register').send({
        email: '  Alice.Security@Example.COM  ',
        displayName: '  Alice Security  ',
        password: 'correct horse battery staple',
      });

      expect(res.status).toBe(201);
      expect(res.body.user).toMatchObject({
        email: 'alice.security@example.com',
        displayName: 'Alice Security',
        status: 'ACTIVE',
      });
      expect(typeof res.body.user.id).toBe('string');
      expect(res.body.user.passwordHash).toBeUndefined();
      expect(res.body.user.password).toBeUndefined();

      const storedUser = store.users.get(res.body.user.id);
      expect(storedUser?.passwordHash.startsWith('$argon2id$')).toBe(true);
      expect(storedUser?.passwordHash).not.toContain('correct horse battery staple');
    });

    it('rejects invalid inputs with 400 and never leaks passwords', async () => {
      const { app } = createAuthTestHarness();
      const shortPassword = 'short_pwd';

      const res = await request(app).post('/api/v1/auth/register').send({
        email: 'invalid-email',
        displayName: '',
        password: shortPassword,
      });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(JSON.stringify(res.body)).not.toContain(shortPassword);
    });

    it('returns 409 on duplicate email and handles concurrent registration races via unique store error', async () => {
      const { app } = createAuthTestHarness();

      const payload = {
        email: 'race.user@example.com',
        displayName: 'Race User',
        password: 'very-strong-passphrase-123',
      };

      const [r1, r2] = await Promise.all([
        request(app).post('/api/v1/auth/register').send(payload),
        request(app)
          .post('/api/v1/auth/register')
          .send({ ...payload, email: '  RACE.USER@EXAMPLE.COM  ' }),
      ]);

      const statuses = [r1.status, r2.status].sort();
      expect(statuses).toEqual([201, 409]);

      const conflictRes = r1.status === 409 ? r1 : r2;
      expect(conflictRes.body).toEqual({
        error: {
          code: 'EMAIL_ALREADY_EXISTS',
          message: 'An account with this email already exists',
        },
      });
    });
  });

  describe('POST /api/v1/auth/login', () => {
    it('logs in an active user, sets HttpOnly refresh cookie, stores only token hash, and returns access token', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'bob@example.com',
        displayName: 'Bob',
        password: 'bob-strong-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: '  BOB@EXAMPLE.COM ',
        password: 'bob-strong-passphrase-123',
      });

      expect(loginRes.status).toBe(200);
      expect(typeof loginRes.body.accessToken).toBe('string');
      expect(loginRes.body.expiresIn).toBe(900);
      expect(loginRes.body.refreshToken).toBeUndefined();
      expect(loginRes.body.user).toMatchObject({
        email: 'bob@example.com',
        displayName: 'Bob',
        status: 'ACTIVE',
      });
      expect(loginRes.body.user.passwordHash).toBeUndefined();

      const setCookie = loginRes.headers['set-cookie'] as unknown as string[];
      const cookieHeader = setCookie.find((c) => c.startsWith(`${REFRESH_TOKEN_COOKIE_NAME}=`))!;
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('SameSite=Lax');
      expect(cookieHeader).toContain('Path=/api/v1/auth');

      const rawRefreshToken = extractCookieValue(setCookie, REFRESH_TOKEN_COOKIE_NAME);
      const expectedHash = hashRefreshToken(rawRefreshToken);

      expect(store.sessions.size).toBe(1);
      const [session] = [...store.sessions.values()];
      expect(session?.refreshTokenHash).toBe(expectedHash);
      expect(session?.refreshTokenHash).not.toBe(rawRefreshToken);
    });

    it('sets Secure flag on refresh cookie in production', async () => {
      const { app } = createAuthTestHarness({ isProduction: true });

      await request(app).post('/api/v1/auth/register').send({
        email: 'prod@example.com',
        displayName: 'Prod User',
        password: 'prod-strong-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'prod@example.com',
        password: 'prod-strong-passphrase-123',
      });

      const setCookie = loginRes.headers['set-cookie'] as unknown as string[];
      const cookieHeader = setCookie.find((c) => c.startsWith(`${REFRESH_TOKEN_COOKIE_NAME}=`))!;
      expect(cookieHeader).toContain('Secure');
    });

    it('prevents account enumeration across wrong password, unknown email, inactive, and suspended accounts', async () => {
      const { app, store } = createAuthTestHarness();

      const regInactive = await request(app).post('/api/v1/auth/register').send({
        email: 'inactive@example.com',
        displayName: 'Inactive',
        password: 'inactive-passphrase-123',
      });
      store.users.get(regInactive.body.user.id)!.status = 'INACTIVE';

      const regSuspended = await request(app).post('/api/v1/auth/register').send({
        email: 'suspended@example.com',
        displayName: 'Suspended',
        password: 'suspended-passphrase-123',
      });
      store.users.get(regSuspended.body.user.id)!.status = 'SUSPENDED';

      const wrongPwd = await request(app).post('/api/v1/auth/login').send({
        email: 'inactive@example.com',
        password: 'completely-wrong-password',
      });
      const unknownEmail = await request(app).post('/api/v1/auth/login').send({
        email: 'nobody@example.com',
        password: 'completely-wrong-password',
      });
      const inactiveUser = await request(app).post('/api/v1/auth/login').send({
        email: 'inactive@example.com',
        password: 'inactive-passphrase-123',
      });
      const suspendedUser = await request(app).post('/api/v1/auth/login').send({
        email: 'suspended@example.com',
        password: 'suspended-passphrase-123',
      });

      for (const res of [wrongPwd, unknownEmail, inactiveUser, suspendedUser]) {
        expect(res.status).toBe(401);
        expect(res.body).toEqual({
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
          },
        });
        expect(res.headers['set-cookie']).toBeUndefined();
      }
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    it('rotates refresh token, issues new access token, and sets replacement cookie', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'rotator@example.com',
        displayName: 'Rotator',
        password: 'rotator-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'rotator@example.com',
        password: 'rotator-passphrase-123',
      });

      const firstCookie = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const refreshRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${firstCookie}`);

      expect(refreshRes.status).toBe(200);
      expect(typeof refreshRes.body.accessToken).toBe('string');
      expect(refreshRes.body.expiresIn).toBe(900);
      expect(refreshRes.body.refreshToken).toBeUndefined();

      const secondCookie = extractCookieValue(
        refreshRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );
      expect(secondCookie).not.toBe(firstCookie);

      const [session] = [...store.sessions.values()];
      expect(session?.previousRefreshTokenHash).toBe(hashRefreshToken(firstCookie));
      expect(session?.refreshTokenHash).toBe(hashRefreshToken(secondCookie));
      expect(session?.revokedAt).toBeNull();
    });

    it('detects reuse of a previously rotated refresh token and revokes the entire session', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'reuse@example.com',
        displayName: 'Reuse Test',
        password: 'reuse-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'reuse@example.com',
        password: 'reuse-passphrase-123',
      });

      const token1 = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const refresh1 = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token1}`);
      expect(refresh1.status).toBe(200);

      const token2 = extractCookieValue(
        refresh1.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      // Attacker replays old token1 after rotation
      const replayRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token1}`);
      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error.code).toBe('INVALID_REFRESH_TOKEN');

      // Session must now be revoked, so legitimate token2 is also rejected
      const [session] = [...store.sessions.values()];
      expect(session?.revokedAt).toBeInstanceOf(Date);

      const subsequentRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token2}`);
      expect(subsequentRes.status).toBe(401);
    });

    it('allows only one concurrent refresh request to succeed and rejects the racing request', async () => {
      const { app } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'concurrent@example.com',
        displayName: 'Concurrent',
        password: 'concurrent-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'concurrent@example.com',
        password: 'concurrent-passphrase-123',
      });

      const token = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const [res1, res2] = await Promise.all([
        request(app)
          .post('/api/v1/auth/refresh')
          .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token}`),
        request(app)
          .post('/api/v1/auth/refresh')
          .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token}`),
      ]);

      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toEqual([200, 401]);

      // Because strict replay detection revoked the session on the losing concurrent request,
      // the winning request's newly issued tokens are also invalidated.
      const winnerRes = res1.status === 200 ? res1 : res2;
      const winningAccessToken = winnerRes.body.accessToken as string;
      const winningRefreshCookie = extractCookieValue(
        winnerRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const meWithWinnerToken = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${winningAccessToken}`);
      expect(meWithWinnerToken.status).toBe(401);

      const refreshWithWinnerCookie = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${winningRefreshCookie}`);
      expect(refreshWithWinnerCookie.status).toBe(401);
    });

    it('detects reuse of an older (N-2+) rotated token and revokes the active session', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'deepreuse@example.com',
        displayName: 'Deep Reuse',
        password: 'deep-reuse-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'deepreuse@example.com',
        password: 'deep-reuse-passphrase-123',
      });

      const token1 = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      // Rotate twice: T1 -> T2 -> T3
      const refresh1 = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token1}`);
      expect(refresh1.status).toBe(200);
      const token2 = extractCookieValue(
        refresh1.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const refresh2 = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token2}`);
      expect(refresh2.status).toBe(200);
      const token3 = extractCookieValue(
        refresh2.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      // Replaying T1 (from 2 rotations ago) must revoke the entire session
      const replayOlder = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token1}`);
      expect(replayOlder.status).toBe(401);

      const [session] = [...store.sessions.values()];
      expect(session?.revokedAt).toBeInstanceOf(Date);

      // Current active token3 must now be rejected
      const refreshWithCurrent = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token3}`);
      expect(refreshWithCurrent.status).toBe(401);
    });

    it('rejects expired or revoked sessions on refresh and clears cookie', async () => {
      let currentTime = new Date('2026-01-01T00:00:00.000Z');
      const { app, store } = createAuthTestHarness({ now: () => currentTime });

      await request(app).post('/api/v1/auth/register').send({
        email: 'expired@example.com',
        displayName: 'Expired',
        password: 'expired-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'expired@example.com',
        password: 'expired-passphrase-123',
      });

      const token = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      // Advance past 7-day refresh TTL
      currentTime = new Date('2026-01-09T00:00:00.000Z');
      const expiredRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token}`);

      expect(expiredRes.status).toBe(401);
      const clearedCookie = (expiredRes.headers['set-cookie'] as unknown as string[])[0];
      expect(clearedCookie).toContain(`${REFRESH_TOKEN_COOKIE_NAME}=;`);

      // Reset clock, explicitly mark session revoked
      currentTime = new Date('2026-01-01T01:00:00.000Z');
      const [session] = [...store.sessions.values()];
      session!.revokedAt = new Date('2026-01-01T00:30:00.000Z');

      const revokedRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${token}`);
      expect(revokedRes.status).toBe(401);
    });
  });

  describe('Authentication Middleware, GET /api/v1/auth/me, and POST /api/v1/auth/logout', () => {
    it('returns 200 with safe user profile on /me when authenticated', async () => {
      const { app } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'me@example.com',
        displayName: 'Me User',
        password: 'me-strong-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'me@example.com',
        password: 'me-strong-passphrase-123',
      });

      const meRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${loginRes.body.accessToken}`);

      expect(meRes.status).toBe(200);
      expect(meRes.body.user).toMatchObject({
        id: loginRes.body.user.id,
        email: 'me@example.com',
        displayName: 'Me User',
        status: 'ACTIVE',
      });
      expect(meRes.body.user.passwordHash).toBeUndefined();
      expect(meRes.body.user.__v).toBeUndefined();
    });

    it('rejects missing or invalid Bearer tokens with 401 without leaking details', async () => {
      const { app } = createAuthTestHarness();

      const missingHeader = await request(app).get('/api/v1/auth/me');
      expect(missingHeader.status).toBe(401);
      expect(missingHeader.body).toEqual({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
        },
      });

      const invalidToken = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer not.a.valid.jwt');
      expect(invalidToken.status).toBe(401);
      expect(invalidToken.body).toEqual({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
        },
      });
    });

    it('rejects /me when user becomes inactive or session is revoked', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'statuscheck@example.com',
        displayName: 'Status Check',
        password: 'statuscheck-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'statuscheck@example.com',
        password: 'statuscheck-passphrase-123',
      });

      const token = loginRes.body.accessToken as string;

      // Deactivate user
      store.users.get(loginRes.body.user.id)!.status = 'SUSPENDED';
      const inactiveRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${token}`);
      expect(inactiveRes.status).toBe(401);

      // Re-activate user, revoke session
      store.users.get(loginRes.body.user.id)!.status = 'ACTIVE';
      const [session] = [...store.sessions.values()];
      session!.revokedAt = new Date();
      const revokedRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${token}`);
      expect(revokedRes.status).toBe(401);
    });

    it('revokes session, invalidates access token, clears cookie, and handles repeated logout safely', async () => {
      const { app, store } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'logout@example.com',
        displayName: 'Logout User',
        password: 'logout-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'logout@example.com',
        password: 'logout-passphrase-123',
      });

      const accessToken = loginRes.body.accessToken as string;
      const refreshCookie = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      const logoutRes1 = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);

      expect(logoutRes1.status).toBe(200);
      expect(logoutRes1.body).toEqual({ message: 'Logged out successfully' });
      const clearedCookie = (logoutRes1.headers['set-cookie'] as unknown as string[])[0];
      expect(clearedCookie).toContain(`${REFRESH_TOKEN_COOKIE_NAME}=;`);
      expect(clearedCookie).toContain('Path=/api/v1/auth');

      const [session] = [...store.sessions.values()];
      expect(session?.revokedAt).toBeInstanceOf(Date);

      // Access token is now unusable because session is revoked
      const meAfterLogout = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(meAfterLogout.status).toBe(401);

      // Refresh cookie is also unusable
      const refreshAfterLogout = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(refreshAfterLogout.status).toBe(401);

      // Repeated logout requests succeed safely
      const logoutRes2 = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(logoutRes2.status).toBe(200);
    });
  });

  describe('Cookie CSRF and Origin Protection on /refresh and /logout', () => {
    it('blocks cross-site, untrusted sibling-subdomain, and null origins with 403 while allowing configured origins', async () => {
      const { app } = createAuthTestHarness();

      await request(app).post('/api/v1/auth/register').send({
        email: 'csrf@example.com',
        displayName: 'CSRF Test',
        password: 'csrf-strong-passphrase-123',
      });

      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: 'csrf@example.com',
        password: 'csrf-strong-passphrase-123',
      });

      const refreshCookie = extractCookieValue(
        loginRes.headers['set-cookie'] as unknown as string[],
        REFRESH_TOKEN_COOKIE_NAME
      );

      // Untrusted external origin
      const externalRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Origin', 'https://evil.example.com')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(externalRes.status).toBe(403);
      expect(externalRes.body.error.code).toBe('FORBIDDEN_ORIGIN');

      // Untrusted sibling subdomain (same-site for SameSite=Lax cookies, must still be blocked)
      const siblingRefreshRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Origin', 'https://untrusted.vibeshield.io')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(siblingRefreshRes.status).toBe(403);

      const siblingLogoutRes = await request(app)
        .post('/api/v1/auth/logout')
        .set('Referer', 'https://untrusted.vibeshield.io/attack')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(siblingLogoutRes.status).toBe(403);

      // Sandboxed iframe / null origin and Sec-Fetch-Site: cross-site
      const nullOriginRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Origin', 'null')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(nullOriginRes.status).toBe(403);

      const crossSiteHeaderRes = await request(app)
        .post('/api/v1/auth/logout')
        .set('Sec-Fetch-Site', 'cross-site')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(crossSiteHeaderRes.status).toBe(403);

      // Configured frontend origin is allowed and cookie remains valid because blocked requests did not rotate/revoke it
      const allowedRes = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Origin', 'https://app.vibeshield.io')
        .set('Cookie', `${REFRESH_TOKEN_COOKIE_NAME}=${refreshCookie}`);
      expect(allowedRes.status).toBe(200);
    });
  });
});
