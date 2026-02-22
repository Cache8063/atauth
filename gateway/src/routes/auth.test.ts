/**
 * Auth Routes Tests
 *
 * Integration tests for /auth/init redirect_uri handling.
 * Verifies that downstream app callback URLs are NOT passed as the
 * OAuth redirect_uri to @atproto/oauth-client (RCA-2026-02-22).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createAuthRoutes } from './auth.js';
import { DatabaseService } from '../services/database.js';

function createTestApp(db: DatabaseService, mockOAuth: any) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createAuthRoutes(db, mockOAuth);
  app.use('/auth', router);

  // Error handler matching Express 5 pattern
  app.use((err: any, _req: any, res: any, _next: any) => {
    const status = err.status || err.statusCode || 500;
    res.status(status).json({
      error: err.code || 'server_error',
      message: err.message,
    });
  });

  return app;
}

function registerTestApp(db: DatabaseService, id = 'test-app', callbackUrl = 'https://app.example.com/callback') {
  db.upsertApp({
    id,
    name: 'Test App',
    hmac_secret: crypto.randomBytes(32).toString('hex'),
    token_ttl_seconds: 3600,
    callback_url: callbackUrl,
  });
}

describe('POST /auth/init', () => {
  let db: DatabaseService;
  let mockOAuth: any;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    mockOAuth = {
      generateAuthUrl: vi.fn().mockResolvedValue({
        url: 'https://bsky.social/oauth/authorize?state=mock-state',
        state: 'mock-state',
      }),
      handleCallback: vi.fn(),
    };
    app = createTestApp(db, mockOAuth);
  });

  afterEach(() => {
    db.close();
  });

  it('should not pass app callback as OAuth redirect_uri', async () => {
    registerTestApp(db);

    const res = await request(app)
      .post('/auth/init')
      .send({
        app_id: 'test-app',
        handle: 'user.bsky.social',
      });

    expect(res.status).toBe(200);
    expect(res.body.auth_url).toContain('bsky.social');

    // Verify generateAuthUrl was called with:
    // arg 1: app_id
    // arg 2: handle
    // arg 3: customRedirect = undefined (NOT the app's callback)
    // arg 4: appRedirectUri = the app's callback (stored in state, not sent to PDS)
    expect(mockOAuth.generateAuthUrl).toHaveBeenCalledOnce();
    const [appId, handle, customRedirect, appRedirectUri] = mockOAuth.generateAuthUrl.mock.calls[0];
    expect(appId).toBe('test-app');
    expect(handle).toBe('user.bsky.social');
    expect(customRedirect).toBeUndefined();
    expect(appRedirectUri).toBe('https://app.example.com/callback');
  });

  it('should not pass explicit redirect_uri as OAuth redirect_uri', async () => {
    registerTestApp(db);

    const res = await request(app)
      .post('/auth/init')
      .send({
        app_id: 'test-app',
        handle: 'user.bsky.social',
        redirect_uri: 'https://app.example.com/callback/alt',
      });

    expect(res.status).toBe(200);

    const [, , customRedirect, appRedirectUri] = mockOAuth.generateAuthUrl.mock.calls[0];
    expect(customRedirect).toBeUndefined();
    expect(appRedirectUri).toBe('https://app.example.com/callback/alt');
  });

  it('should store app callback in appRedirectUri even without explicit redirect_uri', async () => {
    registerTestApp(db, 'myapp', 'https://myapp.example.com/auth');

    await request(app)
      .post('/auth/init')
      .send({
        app_id: 'myapp',
        handle: 'test.bsky.social',
      });

    const [, , customRedirect, appRedirectUri] = mockOAuth.generateAuthUrl.mock.calls[0];
    expect(customRedirect).toBeUndefined();
    expect(appRedirectUri).toBe('https://myapp.example.com/auth');
  });

  it('should reject redirect_uri that does not match app callback', async () => {
    registerTestApp(db);

    const res = await request(app)
      .post('/auth/init')
      .send({
        app_id: 'test-app',
        handle: 'user.bsky.social',
        redirect_uri: 'https://evil.example.com/steal',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
    expect(mockOAuth.generateAuthUrl).not.toHaveBeenCalled();
  });

  it('should require app_id', async () => {
    const res = await request(app)
      .post('/auth/init')
      .send({ handle: 'user.bsky.social' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_app_id');
  });

  it('should require handle', async () => {
    const res = await request(app)
      .post('/auth/init')
      .send({ app_id: 'test-app' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_handle');
  });

  it('should return 404 for unregistered app', async () => {
    const res = await request(app)
      .post('/auth/init')
      .send({ app_id: 'nonexistent', handle: 'user.bsky.social' });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('app_not_found');
  });

  it('should return auth_url and state on success', async () => {
    registerTestApp(db);

    const res = await request(app)
      .post('/auth/init')
      .send({
        app_id: 'test-app',
        handle: 'user.bsky.social',
      });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      auth_url: expect.stringContaining('bsky.social'),
      state: 'mock-state',
      app_id: 'test-app',
    });
  });
});

