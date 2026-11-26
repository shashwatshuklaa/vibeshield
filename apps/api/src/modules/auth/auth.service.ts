import { createHash, randomBytes } from 'node:crypto';
import {
  isValidObjectId,
  normalizeEmail,
  SessionModel,
  UserModel,
  UserStatusValue,
  type UserStatus,
} from '@vibeshield/database';
import {
  AuthError,
  type AuthContext,
  type AuthRuntimeConfig,
  type LoginInput,
  type LoginResult,
  type LogoutInput,
  type PublicUser,
  type RefreshResult,
  type RegisterInput,
} from './auth.types.js';
import {
  jwtService as defaultJwtService,
  type JwtService,
  type JwtTokenConfig,
} from './jwt.service.js';
import {
  passwordService as defaultPasswordService,
  type PasswordService,
} from './password.service.js';

export interface StoredUserWithPassword extends PublicUser {
  passwordHash: string;
}

export interface StoredSessionRef {
  id: string;
  userId: string;
}

export interface AuthStore {
  createUser(input: {
    email: string;
    displayName: string;
    passwordHash: string;
    status: UserStatus;
  }): Promise<PublicUser>;
  findUserWithPasswordByEmail(email: string): Promise<StoredUserWithPassword | null>;
  findActiveUserById(userId: string): Promise<PublicUser | null>;
  createSession(input: {
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    lastUsedAt: Date;
  }): Promise<StoredSessionRef>;
  rotateSession(input: {
    presentedHash: string;
    nextRefreshTokenHash: string;
    now: Date;
    nextExpiresAt: Date;
  }): Promise<StoredSessionRef | null>;
  revokeSessionByPreviousTokenHash(previousHash: string, now: Date): Promise<boolean>;
  findActiveSessionByIdAndUserId(
    sessionId: string,
    userId: string,
    now: Date
  ): Promise<StoredSessionRef | null>;
  revokeSessionById(sessionId: string, now: Date): Promise<void>;
  revokeSessionByIdAndUserId(sessionId: string, userId: string, now: Date): Promise<void>;
  revokeSessionByTokenHash(tokenHash: string, now: Date): Promise<void>;
}

export interface AuthServiceDependencies {
  config?: AuthRuntimeConfig;
  store?: AuthStore;
  passwordService?: PasswordService;
  jwtService?: JwtService;
  now?: () => Date;
}

export interface AuthService {
  register(input: RegisterInput): Promise<PublicUser>;
  login(input: LoginInput): Promise<LoginResult>;
  refresh(refreshToken: string): Promise<RefreshResult>;
  authenticateAccessToken(token: string): Promise<AuthContext>;
  logout(input: LogoutInput): Promise<void>;
}

/**
 * Generates a 256-bit cryptographically random opaque refresh token.
 */
export function generateRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Computes the SHA-256 hex digest of a refresh token for database storage and lookup.
 */
export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function isMongoDuplicateKeyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const err = error as { code?: unknown; cause?: { code?: unknown } };
  return err.code === 11000 || err.cause?.code === 11000;
}

function toPublicUser(doc: {
  _id: { toString(): string } | string;
  email: string;
  displayName: string;
  status: UserStatus;
  createdAt: Date;
}): PublicUser {
  return {
    id: typeof doc._id === 'string' ? doc._id : doc._id.toString(),
    email: doc.email,
    displayName: doc.displayName,
    status: doc.status,
    createdAt: doc.createdAt,
  };
}

export const mongooseAuthStore: AuthStore = {
  async createUser(input) {
    const doc = await UserModel.create({
      email: input.email,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      status: input.status,
    });
    return toPublicUser(doc);
  },

  async findUserWithPasswordByEmail(email) {
    const doc = await UserModel.findOne({ email }).select('+passwordHash');
    if (!doc) {
      return null;
    }
    return {
      ...toPublicUser(doc),
      passwordHash: doc.passwordHash,
    };
  },

  async findActiveUserById(userId) {
    if (!isValidObjectId(userId)) {
      return null;
    }
    const doc = await UserModel.findOne({ _id: userId, status: UserStatusValue.ACTIVE });
    return doc ? toPublicUser(doc) : null;
  },

  async createSession(input) {
    const doc = await SessionModel.create({
      userId: input.userId,
      refreshTokenHash: input.refreshTokenHash,
      previousRefreshTokenHash: null,
      expiresAt: input.expiresAt,
      revokedAt: null,
      lastUsedAt: input.lastUsedAt,
    });
    return {
      id: doc._id.toString(),
      userId: doc.userId.toString(),
    };
  },

  async rotateSession(input) {
    const doc = await SessionModel.findOneAndUpdate(
      {
        refreshTokenHash: input.presentedHash,
        revokedAt: null,
        expiresAt: { $gt: input.now },
      },
      {
        $set: {
          previousRefreshTokenHash: input.presentedHash,
          refreshTokenHash: input.nextRefreshTokenHash,
          lastUsedAt: input.now,
          expiresAt: input.nextExpiresAt,
        },
      },
      { new: true }
    );
    return doc
      ? {
          id: doc._id.toString(),
          userId: doc.userId.toString(),
        }
      : null;
  },

  async revokeSessionByPreviousTokenHash(previousHash, now) {
    const doc = await SessionModel.findOneAndUpdate(
      {
        previousRefreshTokenHash: previousHash,
        revokedAt: null,
      },
      {
        $set: { revokedAt: now },
      },
      { new: true }
    );
    return Boolean(doc);
  },

  async findActiveSessionByIdAndUserId(sessionId, userId, now) {
    if (!isValidObjectId(sessionId) || !isValidObjectId(userId)) {
      return null;
    }
    const doc = await SessionModel.findOne({
      _id: sessionId,
      userId,
      revokedAt: null,
      expiresAt: { $gt: now },
    });
    return doc
      ? {
          id: doc._id.toString(),
          userId: doc.userId.toString(),
        }
      : null;
  },

  async revokeSessionById(sessionId, now) {
    if (!isValidObjectId(sessionId)) {
      return;
    }
    await SessionModel.updateOne({ _id: sessionId, revokedAt: null }, { $set: { revokedAt: now } });
  },

  async revokeSessionByIdAndUserId(sessionId, userId, now) {
    if (!isValidObjectId(sessionId) || !isValidObjectId(userId)) {
      return;
    }
    await SessionModel.updateOne(
      { _id: sessionId, userId, revokedAt: null },
      { $set: { revokedAt: now } }
    );
  },

  async revokeSessionByTokenHash(tokenHash, now) {
    await SessionModel.updateOne(
      {
        $or: [{ refreshTokenHash: tokenHash }, { previousRefreshTokenHash: tokenHash }],
        revokedAt: null,
      },
      { $set: { revokedAt: now } }
    );
  },
};

function toJwtConfig(config: AuthRuntimeConfig): JwtTokenConfig {
  return {
    secret: config.jwtAccessSecret,
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    accessTtl: config.jwtAccessTtl,
    accessTtlSeconds: config.jwtAccessTtlSeconds,
  };
}

function requireConfig(config?: AuthRuntimeConfig): AuthRuntimeConfig {
  if (!config) {
    throw new AuthError(500, 'AUTH_CONFIGURATION_ERROR', 'Authentication service is misconfigured');
  }
  return config;
}

/**
 * Creates the core authentication service handling registration, login,
 * token refresh rotation with reuse detection, access-token verification, and logout.
 */
export function createAuthService(dependencies: AuthServiceDependencies = {}): AuthService {
  const {
    config,
    store = mongooseAuthStore,
    passwordService = defaultPasswordService,
    jwtService = defaultJwtService,
    now = () => new Date(),
  } = dependencies;

  return {
    async register(input: RegisterInput): Promise<PublicUser> {
      const normalizedEmail = normalizeEmail(input.email);
      const passwordHash = await passwordService.hashPassword(input.password);

      try {
        return await store.createUser({
          email: normalizedEmail,
          displayName: input.displayName.trim(),
          passwordHash,
          status: UserStatusValue.ACTIVE,
        });
      } catch (error) {
        if (isMongoDuplicateKeyError(error)) {
          throw new AuthError(
            409,
            'EMAIL_ALREADY_EXISTS',
            'An account with this email already exists'
          );
        }
        throw error;
      }
    },

    async login(input: LoginInput): Promise<LoginResult> {
      const runtimeConfig = requireConfig(config);
      const normalizedEmail = normalizeEmail(input.email);
      const user = await store.findUserWithPasswordByEmail(normalizedEmail);

      if (!user) {
        await passwordService.verifyDummy(input.password);
        throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
      }

      const passwordMatches = await passwordService.verifyPassword(
        user.passwordHash,
        input.password
      );

      if (!passwordMatches || user.status !== UserStatusValue.ACTIVE) {
        throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
      }

      const currentTime = now();
      const refreshToken = generateRefreshToken();
      const refreshTokenHash = hashRefreshToken(refreshToken);
      const refreshExpiresAt = new Date(
        currentTime.getTime() + runtimeConfig.refreshTokenTtlSeconds * 1000
      );

      const session = await store.createSession({
        userId: user.id,
        refreshTokenHash,
        expiresAt: refreshExpiresAt,
        lastUsedAt: currentTime,
      });

      const signedToken = await jwtService.signAccessToken(
        { userId: user.id, sessionId: session.id },
        toJwtConfig(runtimeConfig)
      );

      const publicUser: PublicUser = {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        status: user.status,
        createdAt: user.createdAt,
      };

      return {
        user: publicUser,
        accessToken: signedToken.token,
        expiresIn: signedToken.expiresIn,
        refreshToken,
        refreshExpiresAt,
      };
    },

    async refresh(refreshToken: string): Promise<RefreshResult> {
      const runtimeConfig = requireConfig(config);

      if (typeof refreshToken !== 'string' || refreshToken.trim().length === 0) {
        throw new AuthError(401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired session');
      }

      const currentTime = now();
      const presentedHash = hashRefreshToken(refreshToken);
      const nextRefreshToken = generateRefreshToken();
      const nextRefreshTokenHash = hashRefreshToken(nextRefreshToken);
      const nextExpiresAt = new Date(
        currentTime.getTime() + runtimeConfig.refreshTokenTtlSeconds * 1000
      );

      const rotatedSession = await store.rotateSession({
        presentedHash,
        nextRefreshTokenHash,
        now: currentTime,
        nextExpiresAt,
      });

      if (!rotatedSession) {
        await store.revokeSessionByPreviousTokenHash(presentedHash, currentTime);
        throw new AuthError(401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired session');
      }

      const user = await store.findActiveUserById(rotatedSession.userId);
      if (!user) {
        await store.revokeSessionById(rotatedSession.id, currentTime);
        throw new AuthError(401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired session');
      }

      const signedToken = await jwtService.signAccessToken(
        { userId: user.id, sessionId: rotatedSession.id },
        toJwtConfig(runtimeConfig)
      );

      return {
        accessToken: signedToken.token,
        expiresIn: signedToken.expiresIn,
        refreshToken: nextRefreshToken,
        refreshExpiresAt: nextExpiresAt,
      };
    },

    async authenticateAccessToken(token: string): Promise<AuthContext> {
      const runtimeConfig = requireConfig(config);
      const claims = await jwtService.verifyAccessToken(token, toJwtConfig(runtimeConfig));

      const session = await store.findActiveSessionByIdAndUserId(
        claims.sessionId,
        claims.userId,
        now()
      );
      if (!session) {
        throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
      }

      const user = await store.findActiveUserById(claims.userId);
      if (!user) {
        throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
      }

      return {
        user,
        sessionId: session.id,
      };
    },

    async logout(input: LogoutInput): Promise<void> {
      const runtimeConfig = requireConfig(config);
      const currentTime = now();

      if (input.accessToken) {
        try {
          const claims = await jwtService.verifyAccessToken(
            input.accessToken,
            toJwtConfig(runtimeConfig)
          );
          await store.revokeSessionByIdAndUserId(claims.sessionId, claims.userId, currentTime);
          return;
        } catch {
          if (!input.refreshToken) {
            throw new AuthError(401, 'UNAUTHORIZED', 'Authentication required');
          }
        }
      }

      if (input.refreshToken) {
        const tokenHash = hashRefreshToken(input.refreshToken);
        await store.revokeSessionByTokenHash(tokenHash, currentTime);
      }
    },
  };
}
