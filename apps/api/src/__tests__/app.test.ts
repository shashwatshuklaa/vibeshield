import { afterEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createApp } from '../app.js';
import { errorHandler } from '../middlewares/error-handler.js';

describe('VibeShield API Foundation', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  describe('GET /api/v1/health', () => {
    it('returns 200 with operational health metadata', async () => {
      const app = createApp();
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toMatchObject({
        status: 'ok',
        service: 'vibeshield-api',
        version: '0.1.0',
      });
      expect(typeof res.body.timestamp).toBe('string');
      expect(typeof res.body.uptime).toBe('number');
    });
  });

  describe('GET / (Root endpoint)', () => {
    it('returns service summary information', async () => {
      const app = createApp();
      const res = await request(app).get('/');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        name: 'VibeShield API',
        status: 'operational',
        version: '0.1.0',
        docs: '/api/v1/health',
      });
    });
  });

  describe('Unmatched routes (404 Handler)', () => {
    it('returns formatted JSON 404 for unknown API paths', async () => {
      const app = createApp();
      const res = await request(app).get('/api/v1/nonexistent');

      expect(res.status).toBe(404);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'Cannot GET /api/v1/nonexistent',
        },
      });
    });

    it('returns formatted JSON 404 for unknown root paths', async () => {
      const app = createApp();
      const res = await request(app).post('/random-endpoint');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'Cannot POST /random-endpoint',
        },
      });
    });
  });

  describe('Security Headers via Helmet', () => {
    it('sets standard defensive HTTP security headers', async () => {
      const app = createApp();
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-dns-prefetch-control']).toBe('off');
      expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    });
  });

  describe('Payload Size Limit', () => {
    it('rejects payloads that exceed configured limit with 413 Payload Too Large', async () => {
      const app = createApp({ bodyLimit: '50b' });

      // Mount an echo endpoint to test body parsing
      app.post('/test-echo', (req, res) => {
        res.status(200).json({ received: req.body });
      });
      // Ensure error handler is at the end of the chain
      app.use(errorHandler);

      const largePayload = { data: 'A'.repeat(200) };
      const res = await request(app)
        .post('/test-echo')
        .send(largePayload)
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(413);
    });
  });

  describe('Centralized Error Handling', () => {
    it('exposes error message in development/test environment', async () => {
      process.env.NODE_ENV = 'test';
      const app = express();
      app.get('/crash', () => {
        throw new Error('Database connection failed internally');
      });
      app.use(errorHandler);

      const res = await request(app).get('/crash');

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('INTERNAL_SERVER_ERROR');
      expect(res.body.error.message).toBe('Database connection failed internally');
      expect(res.body.error.stack).toBeDefined();
    });

    it('masks internal server error details and redacts stack trace in production', async () => {
      process.env.NODE_ENV = 'production';
      const app = express();
      app.get('/crash', () => {
        throw new Error('Sensitive database credentials leak');
      });
      app.use(errorHandler);

      const res = await request(app).get('/crash');

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('INTERNAL_SERVER_ERROR');
      expect(res.body.error.message).toBe('Internal Server Error');
      expect(res.body.error.stack).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toContain('Sensitive database credentials leak');
    });
  });
});
