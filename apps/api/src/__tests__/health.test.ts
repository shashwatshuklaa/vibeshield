import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../app.js';

describe('Health and Readiness Endpoints', () => {
  describe('Liveness (GET /api/v1/health/live & GET /api/v1/health)', () => {
    it('returns 200 on /api/v1/health/live independently of MongoDB availability', async () => {
      const app = createApp({
        health: {
          getDatabaseStatus: () => ({
            state: 'disconnected',
            readyState: 0,
            isConnected: false,
          }),
        },
      });

      const res = await request(app).get('/api/v1/health/live');

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

    it('keeps /api/v1/health returning 200 even when MongoDB is disconnected', async () => {
      const app = createApp({
        health: {
          getDatabaseStatus: () => ({
            state: 'disconnected',
            readyState: 0,
            isConnected: false,
          }),
        },
      });

      const res = await request(app).get('/api/v1/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  describe('Readiness (GET /api/v1/health/ready)', () => {
    it('returns 200 when MongoDB is connected', async () => {
      const app = createApp({
        health: {
          getDatabaseStatus: () => ({
            state: 'connected',
            readyState: 1,
            isConnected: true,
          }),
        },
      });

      const res = await request(app).get('/api/v1/health/ready');

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toMatchObject({
        status: 'ready',
        service: 'vibeshield-api',
        checks: {
          database: {
            status: 'up',
            state: 'connected',
          },
        },
      });
      expect(typeof res.body.timestamp).toBe('string');
    });

    it('returns 503 when MongoDB is disconnected', async () => {
      const app = createApp({
        health: {
          getDatabaseStatus: () => ({
            state: 'disconnected',
            readyState: 0,
            isConnected: false,
          }),
        },
      });

      const res = await request(app).get('/api/v1/health/ready');

      expect(res.status).toBe(503);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toMatchObject({
        status: 'not_ready',
        service: 'vibeshield-api',
        checks: {
          database: {
            status: 'down',
            state: 'disconnected',
          },
        },
      });
    });

    it('returns 503 when MongoDB is connecting or disconnecting', async () => {
      const connectingApp = createApp({
        health: {
          getDatabaseStatus: () => ({
            state: 'connecting',
            readyState: 2,
            isConnected: false,
          }),
        },
      });

      const res = await request(connectingApp).get('/api/v1/health/ready');
      expect(res.status).toBe(503);
      expect(res.body.checks.database).toEqual({
        status: 'down',
        state: 'connecting',
      });
    });

    it('returns 503 without exposing internal errors if status check throws', async () => {
      const app = createApp({
        health: {
          getDatabaseStatus: () => {
            throw new Error('mongodb://secret:pass@internal:27017/db');
          },
        },
      });

      const res = await request(app).get('/api/v1/health/ready');
      expect(res.status).toBe(503);
      expect(res.body.status).toBe('not_ready');
      expect(JSON.stringify(res.body)).not.toContain('secret');
      expect(JSON.stringify(res.body)).not.toContain('internal:27017');
    });

    it('distinguishes disabled, connected, not_initialized, and unavailable queue readiness without failing unrelated API readiness when optional', async () => {
      const baseDbUp = () => ({
        state: 'connected' as const,
        readyState: 1,
        isConnected: true,
      });

      const disabledRes = await request(
        createApp({
          health: {
            getDatabaseStatus: baseDbUp,
            getQueueStatus: () => ({
              enabled: false,
              state: 'disabled',
              isConnected: false,
              required: false,
            }),
          },
        })
      ).get('/api/v1/health/ready');
      expect(disabledRes.status).toBe(200);
      expect(disabledRes.body.checks.queue).toEqual({
        status: 'disabled',
        state: 'disabled',
        required: false,
      });

      const connectedRes = await request(
        createApp({
          health: {
            getDatabaseStatus: baseDbUp,
            getQueueStatus: () => ({
              enabled: true,
              state: 'connected',
              isConnected: true,
              required: true,
            }),
          },
        })
      ).get('/api/v1/health/ready');
      expect(connectedRes.status).toBe(200);
      expect(connectedRes.body.checks.queue).toEqual({
        status: 'connected',
        state: 'connected',
        required: true,
      });

      const optionalUnavailableRes = await request(
        createApp({
          health: {
            getDatabaseStatus: baseDbUp,
            getQueueStatus: () => ({
              enabled: true,
              state: 'unavailable',
              isConnected: false,
              required: false,
            }),
          },
        })
      ).get('/api/v1/health/ready');
      expect(optionalUnavailableRes.status).toBe(200);
      expect(optionalUnavailableRes.body.checks.queue.status).toBe('unavailable');

      const requiredUnavailableRes = await request(
        createApp({
          health: {
            getDatabaseStatus: baseDbUp,
            getQueueStatus: () => ({
              enabled: true,
              state: 'not_initialized',
              isConnected: false,
              required: true,
            }),
          },
        })
      ).get('/api/v1/health/ready');
      expect(requiredUnavailableRes.status).toBe(503);
      expect(requiredUnavailableRes.body.status).toBe('not_ready');
      expect(requiredUnavailableRes.body.checks.queue.status).toBe('not_initialized');
    });
  });
});
