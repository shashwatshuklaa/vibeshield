import { describe, expect, it } from 'vitest';
import { baseEnvSchema, NodeEnvEnum } from '../base.js';

describe('baseEnvSchema', () => {
  describe('default values', () => {
    it('populates default NODE_ENV and LOG_LEVEL when empty object is provided', () => {
      const result = baseEnvSchema.parse({});

      expect(result.NODE_ENV).toBe('development');
      expect(result.LOG_LEVEL).toBe('info');
      expect(result.PORT).toBeUndefined();
    });
  });

  describe('NODE_ENV validation', () => {
    it('accepts valid NODE_ENV values', () => {
      expect(baseEnvSchema.parse({ NODE_ENV: 'development' }).NODE_ENV).toBe('development');
      expect(baseEnvSchema.parse({ NODE_ENV: 'production' }).NODE_ENV).toBe('production');
      expect(baseEnvSchema.parse({ NODE_ENV: 'test' }).NODE_ENV).toBe('test');
    });

    it('rejects invalid NODE_ENV values', () => {
      expect(() => baseEnvSchema.parse({ NODE_ENV: 'staging' })).toThrow();
      expect(() => baseEnvSchema.parse({ NODE_ENV: 'local' })).toThrow();
      expect(() => baseEnvSchema.parse({ NODE_ENV: '' })).toThrow();
    });

    it('exports NodeEnvEnum matching allowed environments', () => {
      expect(NodeEnvEnum.options).toEqual(['development', 'production', 'test']);
    });
  });

  describe('PORT validation and coercion', () => {
    it('coerces valid numeric string ports to numbers', () => {
      expect(baseEnvSchema.parse({ PORT: '3000' }).PORT).toBe(3000);
      expect(baseEnvSchema.parse({ PORT: '80' }).PORT).toBe(80);
      expect(baseEnvSchema.parse({ PORT: '443' }).PORT).toBe(443);
      expect(baseEnvSchema.parse({ PORT: '65535' }).PORT).toBe(65535);
    });

    it('rejects non-numeric port strings', () => {
      expect(() => baseEnvSchema.parse({ PORT: 'abc' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '3000a' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '30.5' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '-3000' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '' })).toThrow();
    });

    it('rejects port numbers out of valid range (1-65535)', () => {
      expect(() => baseEnvSchema.parse({ PORT: '0' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '65536' })).toThrow();
      expect(() => baseEnvSchema.parse({ PORT: '99999' })).toThrow();
    });
  });

  describe('LOG_LEVEL validation', () => {
    it('accepts all supported log levels', () => {
      const validLevels = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'] as const;

      for (const level of validLevels) {
        expect(baseEnvSchema.parse({ LOG_LEVEL: level }).LOG_LEVEL).toBe(level);
      }
    });

    it('rejects unsupported log levels', () => {
      expect(() => baseEnvSchema.parse({ LOG_LEVEL: 'trace' })).toThrow();
      expect(() => baseEnvSchema.parse({ LOG_LEVEL: 'fatal' })).toThrow();
      expect(() => baseEnvSchema.parse({ LOG_LEVEL: 'silent' })).toThrow();
      expect(() => baseEnvSchema.parse({ LOG_LEVEL: 'unknown' })).toThrow();
    });
  });
});
