/**
 * OIDC Authorize Passkey Tests
 *
 * Tests for passkey authentication on the OIDC authorize page.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createAuthorizeRouter } from './authorize.js';
import { DatabaseService } from '../../services/database.js';

function createTestApp(db: DatabaseService, mockOidc: any, mockOAuth: any, mockPasskey?: any) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createAuthorizeRouter(db, mockOidc, mockOAuth, mockPasskey);
  app.use('/oauth', router);

  app.use((err: any, _req: any, res: any, _next: any) => {
    const status = err.status || err.statusCode || 500;
    res.status(status).json({
      error: err.code || 'server_error',
      message: err.message,
    });
  });

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

function createPendingAuthCode(db: DatabaseService, code = 'test-auth-code') {
  db.saveAuthorizationCode({
    code,
    client_id: 'test-client',
    redirect_uri: 'https://app.example.com/callback',
    scope: 'openid profile',
    state: 'test-state-123',
    did: '',
    handle: '',
    created_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 600,
    used: false,
  });
}

const mockCredential = {
  id: 'credential-id-123',
  rawId: 'credential-id-123',
  response: {
    clientDataJSON: 'mock-client-data',
    authenticatorData: 'mock-auth-data',
    signature: 'mock-signature',
  },
  type: 'public-key',
};

describe('POST /oauth/authorize/passkey', () => {
  let db: DatabaseService;
  let mockOidc: any;
  let mockOAuth: any;
  let mockPasskey: any;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    mockOidc = {
      issuer: 'https://auth.example.com',
    };
    mockOAuth = {
      generateAuthUrl: vi.fn(),
      handleCallback: vi.fn(),
    };
    mockPasskey = {
      verifyAuthentication: vi.fn(),
      generateAuthenticationOptions: vi.fn(),
    };
    registerOIDCClient(db);
    app = createTestApp(db, mockOidc, mockOAuth, mockPasskey);
  });

  afterEach(() => {
    db.close();
  });

  it('should complete OIDC flow via passkey authentication', async () => {
    createPendingAuthCode(db);
    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: true,
      did: 'did:plc:test123',
      handle: 'user.bsky.social',
    });

    const res = await request(app)
      .post('/oauth/authorize/passkey')
      .send({
        auth_code: 'test-auth-code',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(200);
    expect(res.body.redirect_url).toContain('https://app.example.com/callback');
    expect(res.body.redirect_url).toContain('code=test-auth-code');
    expect(res.body.redirect_url).toContain('state=test-state-123');

    // Verify the auth code was updated with user identity
    const authData = db.getAuthorizationCode('test-auth-code');
    expect(authData?.did).toBe('did:plc:test123');
    expect(authData?.handle).toBe('user.bsky.social');
  });

  it('should return 400 for missing parameters', async () => {
    const res = await request(app)
      .post('/oauth/authorize/passkey')
      .send({ auth_code: 'test' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('should return 400 for invalid auth code', async () => {
    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: true,
      did: 'did:plc:test123',
      handle: 'user.bsky.social',
    });

    const res = await request(app)
      .post('/oauth/authorize/passkey')
      .send({
        auth_code: 'nonexistent-code',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toContain('expired or invalid');
  });

  it('should return 400 for already-used auth code', async () => {
    createPendingAuthCode(db, 'used-code');
    // Mark it as used via raw SQL since there's no direct method
    db.updateAuthorizationCodeUser('used-code', 'did:plc:old', 'old.bsky.social');
    db['db'].prepare('UPDATE authorization_codes SET used = 1 WHERE code = ?').run('used-code');

    const res = await request(app)
      .post('/oauth/authorize/passkey')
      .send({
        auth_code: 'used-code',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toContain('already used');
  });

  it('should return 401 for failed passkey verification', async () => {
    createPendingAuthCode(db);
    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: false,
      error: 'Unknown credential',
    });

    const res = await request(app)
      .post('/oauth/authorize/passkey')
      .send({
        auth_code: 'test-auth-code',
        credential: mockCredential,
        challenge: 'bad-challenge',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('authentication_failed');
    expect(res.body.error_description).toContain('Unknown credential');
  });

  it('should return 404 when passkey service is not enabled', async () => {
    const appNoPasskey = createTestApp(db, mockOidc, mockOAuth, null);
    createPendingAuthCode(db);

    const res = await request(appNoPasskey)
      .post('/oauth/authorize/passkey')
      .send({
        auth_code: 'test-auth-code',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('not_found');
  });
});

describe('GET /oauth/authorize - login page', () => {
  let db: DatabaseService;
  let mockOidc: any;
  let mockOAuth: any;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    mockOidc = { issuer: 'https://auth.example.com' };
    mockOAuth = { generateAuthUrl: vi.fn(), handleCallback: vi.fn() };
    registerOIDCClient(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render passkey button when passkey service is enabled', async () => {
    const mockPasskey = { verifyAuthentication: vi.fn() };
    const app = createTestApp(db, mockOidc, mockOAuth, mockPasskey);

    const res = await request(app)
      .get('/oauth/authorize')
      .query({
        response_type: 'code',
        client_id: 'test-client',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile',
        state: 'test-state',
      });

    expect(res.status).toBe(200);
    expect(res.text).toContain('passkeyBtn');
    expect(res.text).toContain('Sign in with passkey');
    expect(res.text).toContain('b64urlToBuffer');
  });

  it('should not render passkey button when passkey service is disabled', async () => {
    const app = createTestApp(db, mockOidc, mockOAuth, null);

    const res = await request(app)
      .get('/oauth/authorize')
      .query({
        response_type: 'code',
        client_id: 'test-client',
        redirect_uri: 'https://app.example.com/callback',
        scope: 'openid profile',
        state: 'test-state',
      });

    expect(res.status).toBe(200);
    expect(res.text).not.toContain('passkeyBtn');
    expect(res.text).not.toContain('Sign in with passkey');
    // Handle form should still be present
    expect(res.text).toContain('loginForm');
    expect(res.text).toContain('you.bsky.social');
  });
});
