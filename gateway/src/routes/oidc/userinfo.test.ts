import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createUserInfoRouter } from './userinfo.js';
import { DatabaseService } from '../../services/database.js';

function createMockOIDCService(accessTokenClaims: any = null) {
  return {
    tokenService: {
      verifyAccessToken: vi.fn().mockReturnValue(accessTokenClaims),
      verifyIdToken: vi.fn(),
      createTokenResponse: vi.fn(),
    },
    keyService: { getPublicKeySet: vi.fn() },
  } as any;
}

function createTestApp(db: DatabaseService, oidcService: any) {
  const app = express();
  app.use(express.json());

  const router = createUserInfoRouter(db, oidcService);
  app.use('/oauth', router);

  return app;
}

describe('/oauth/userinfo', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    // Mock the global fetch for AT Protocol API calls
    vi.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ handle: 'test.bsky.social' }),
    } as Response);
  });

  afterEach(() => {
    db.close();
    vi.restoreAllMocks();
  });

  it('should return 401 for missing Authorization header', async () => {
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app).get('/oauth/userinfo');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });

  it('should return 401 for non-Bearer auth', async () => {
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Basic abc123');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });

  it('should return 401 for invalid access token', async () => {
    const oidcService = createMockOIDCService(null); // null = invalid token
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer invalid-token');

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
    expect(res.body.error_description).toContain('expired');
  });

  it('should return user info for valid token with openid scope', async () => {
    const oidcService = createMockOIDCService({
      sub: 'did:plc:testuser',
      scope: 'openid',
      client_id: 'test-client',
    });
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('did:plc:testuser');
  });

  it('should return profile claims for profile scope', async () => {
    const oidcService = createMockOIDCService({
      sub: 'did:plc:testuser',
      scope: 'openid profile',
      client_id: 'test-client',
    });
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('did:plc:testuser');
    expect(res.body.preferred_username).toBe('test.bsky.social');
  });

  it('should support POST method', async () => {
    const oidcService = createMockOIDCService({
      sub: 'did:plc:testuser',
      scope: 'openid',
      client_id: 'test-client',
    });
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .post('/oauth/userinfo')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('did:plc:testuser');
  });

  it('should use user mapping handle when available', async () => {
    const oidcService = createMockOIDCService({
      sub: 'did:plc:testuser',
      scope: 'openid profile',
      client_id: 'test-app',
    });

    // Register app and create user mapping
    db.upsertApp({
      id: 'test-app',
      name: 'Test',
      hmac_secret: 'a'.repeat(64),
      token_ttl_seconds: 3600,
    });
    db.setUserMapping({
      did: 'did:plc:testuser',
      app_id: 'test-app',
      user_id: 1,
      handle: 'mapped.handle.social',
    });

    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.preferred_username).toBe('mapped.handle.social');
    // Should NOT have called fetch since mapping was found
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should fall back to DID when API call fails', async () => {
    vi.spyOn(global, 'fetch').mockRejectedValue(new Error('network error'));

    const oidcService = createMockOIDCService({
      sub: 'did:plc:testuser',
      scope: 'openid profile',
      client_id: 'test-client',
    });
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/userinfo')
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.preferred_username).toBe('did:plc:testuser');
  });
});
