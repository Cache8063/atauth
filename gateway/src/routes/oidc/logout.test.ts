import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createLogoutRouter } from './logout.js';
import { DatabaseService } from '../../services/database.js';

function createMockOIDCService(verifyResult: any = null) {
  return {
    tokenService: {
      verifyIdToken: vi.fn().mockReturnValue(verifyResult),
      verifyAccessToken: vi.fn(),
      createTokenResponse: vi.fn(),
    },
    keyService: { getPublicKeySet: vi.fn() },
  } as any;
}

function createTestApp(db: DatabaseService, oidcService: any) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createLogoutRouter(db, oidcService);
  app.use('/oauth', router);

  return app;
}

function registerOIDCClient(db: DatabaseService, id = 'test-client') {
  db.upsertOIDCClient({
    id,
    name: 'Test App',
    client_type: 'oidc',
    hmac_secret: crypto.randomBytes(32).toString('hex'),
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code'],
    allowed_scopes: ['openid', 'profile'],
    token_ttl_seconds: 3600,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 86400,
    require_pkce: false,
    token_endpoint_auth_method: 'client_secret_basic',
  });
}

describe('GET /oauth/end_session', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  afterEach(() => db.close());

  it('should render logged out page when no redirect URI', async () => {
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app).get('/oauth/end_session');

    expect(res.status).toBe(200);
    expect(res.text).toContain('Logged Out');
    expect(res.text).toContain('successfully logged out');
  });

  it('should redirect to post_logout_redirect_uri when valid', async () => {
    registerOIDCClient(db);
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/end_session')
      .query({
        client_id: 'test-client',
        post_logout_redirect_uri: 'https://app.example.com/callback',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('app.example.com/callback');
  });

  it('should append state to redirect', async () => {
    registerOIDCClient(db);
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/end_session')
      .query({
        client_id: 'test-client',
        post_logout_redirect_uri: 'https://app.example.com/callback',
        state: 'my-state-123',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('state=my-state-123');
  });

  it('should reject invalid post_logout_redirect_uri', async () => {
    registerOIDCClient(db);
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/end_session')
      .query({
        client_id: 'test-client',
        post_logout_redirect_uri: 'https://evil.example.com/steal',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toContain('Invalid post_logout_redirect_uri');
  });

  it('should reject unknown client_id', async () => {
    const oidcService = createMockOIDCService();
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/end_session')
      .query({
        client_id: 'nonexistent',
        post_logout_redirect_uri: 'https://app.example.com',
      });

    expect(res.status).toBe(400);
    expect(res.body.error_description).toContain('Unknown client');
  });

  it('should extract client_id from id_token_hint', async () => {
    registerOIDCClient(db);
    const oidcService = createMockOIDCService({ sub: 'did:plc:test', aud: 'test-client' });
    const app = createTestApp(db, oidcService);

    const res = await request(app)
      .get('/oauth/end_session')
      .query({
        id_token_hint: 'mock-id-token',
        post_logout_redirect_uri: 'https://app.example.com/callback',
      });

    expect(res.status).toBe(302);
    expect(oidcService.tokenService.verifyIdToken).toHaveBeenCalledWith('mock-id-token');
  });

  it('should revoke refresh tokens on logout with id_token_hint', async () => {
    registerOIDCClient(db);
    const oidcService = createMockOIDCService({ sub: 'did:plc:test', aud: 'test-client' });
    const app = createTestApp(db, oidcService);

    const revokeSpy = vi.spyOn(db, 'revokeAllRefreshTokensForUser');

    await request(app)
      .get('/oauth/end_session')
      .query({
        id_token_hint: 'mock-id-token',
      });

    expect(revokeSpy).toHaveBeenCalledWith('did:plc:test', 'test-client');
  });
});
