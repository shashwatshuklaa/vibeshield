import argon2 from 'argon2';

export interface PasswordService {
  hashPassword(password: string): Promise<string>;
  verifyPassword(passwordHash: string, password: string): Promise<boolean>;
  verifyDummy(password: string): Promise<void>;
}

const ARGON2ID_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
} as const;

/**
 * Dedicated Argon2id password hashing and verification service.
 * Handles invalid hashes safely without throwing or exposing sensitive values.
 */
export function createPasswordService(): PasswordService {
  let dummyHashPromise: Promise<string> | null = null;

  const getDummyHash = (): Promise<string> => {
    if (!dummyHashPromise) {
      dummyHashPromise = argon2.hash('vibeshield-timing-equalization-dummy', ARGON2ID_OPTIONS);
    }
    return dummyHashPromise;
  };

  return {
    async hashPassword(password: string): Promise<string> {
      return argon2.hash(password, ARGON2ID_OPTIONS);
    },

    async verifyPassword(passwordHash: string, password: string): Promise<boolean> {
      if (
        typeof passwordHash !== 'string' ||
        typeof password !== 'string' ||
        password.length === 0 ||
        !passwordHash.startsWith('$argon2id$')
      ) {
        return false;
      }

      try {
        return await argon2.verify(passwordHash, password);
      } catch {
        return false;
      }
    },

    async verifyDummy(password: string): Promise<void> {
      try {
        const dummyHash = await getDummyHash();
        await argon2.verify(dummyHash, password);
      } catch {
        // Ignore errors during timing-equalization dummy check
      }
    },
  };
}

export const passwordService = createPasswordService();
