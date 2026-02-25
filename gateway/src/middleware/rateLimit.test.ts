import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { rateLimit } from './rateLimit.js';

function createTestApp(maxRequests: number = 5, windowMs: number = 60000) {
  const app = express();
  app.use(rateLimit({ maxRequests, windowMs }));
  app.get('/test', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('rateLimit middleware', () => {
  it('should allow requests under the limit', async () => {
    const app = createTestApp(5);
    const res = await request(app).get('/test');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('should set rate limit headers', async () => {
    const app = createTestApp(10);
    const res = await request(app).get('/test');
    expect(res.headers['x-ratelimit-limit']).toBe('10');
    expect(res.headers['x-ratelimit-remaining']).toBeDefined();
    expect(res.headers['x-ratelimit-reset']).toBeDefined();
  });

  it('should decrement remaining count with each request', async () => {
    const app = createTestApp(5);
    const agent = request(app);

    const res1 = await agent.get('/test');
    const remaining1 = parseInt(res1.headers['x-ratelimit-remaining']);

    const res2 = await agent.get('/test');
    const remaining2 = parseInt(res2.headers['x-ratelimit-remaining']);

    expect(remaining2).toBeLessThan(remaining1);
  });

  it('should return 429 when limit is exceeded', async () => {
    const app = createTestApp(2);
    const agent = request(app);

    await agent.get('/test'); // 1
    await agent.get('/test'); // 2
    const res = await agent.get('/test'); // 3 -> over limit

    expect(res.status).toBe(429);
    expect(res.body.error).toBe('rate_limited');
    expect(res.body.retry_after).toBeTypeOf('number');
    expect(res.headers['retry-after']).toBeDefined();
  });

  it('should extract IP from X-Forwarded-For header', async () => {
    const app = createTestApp(2);

    // Different IPs should have independent counters
    const res1 = await request(app).get('/test').set('X-Forwarded-For', '1.2.3.4');
    const res2 = await request(app).get('/test').set('X-Forwarded-For', '5.6.7.8');

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });

  it('should use first IP from X-Forwarded-For with multiple IPs', async () => {
    const app = createTestApp(2);

    // Both requests have same first IP, so they share the same counter
    await request(app).get('/test').set('X-Forwarded-For', '1.2.3.4, 10.0.0.1');
    await request(app).get('/test').set('X-Forwarded-For', '1.2.3.4, 10.0.0.2');
    const res = await request(app).get('/test').set('X-Forwarded-For', '1.2.3.4, 10.0.0.3');

    expect(res.status).toBe(429);
  });

  it('should set remaining to 0 (not negative) when over limit', async () => {
    const app = createTestApp(1);
    const agent = request(app);

    await agent.get('/test'); // uses the 1 allowed request
    const res = await agent.get('/test'); // over limit

    expect(res.status).toBe(429);
    expect(res.headers['x-ratelimit-remaining']).toBe('0');
  });
});
