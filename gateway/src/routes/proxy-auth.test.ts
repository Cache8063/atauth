/**
 * Forward-Auth Proxy Routes Tests
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createProxyAuthRoutes } from './proxy-auth.js';
import { DatabaseService } from '../services/database.js';
import {
  createSessionCookie,
  createProxyCookie,
  createAuthTicket,
  SESSION_COOKIE_NAME,
  PROXY_COOKIE_NAME,
} from '../utils/proxy-auth.js';
import type { ForwardAuthConfig } from '../types/proxy.js';

const TEST_SECRET = 'test-forward-auth-secret-32bytes!';
const TEST_ISSUER = 'https://auth.example.com';

const forwardAuthConfig: ForwardAuthConfig = {
  enabled: true,
  sessionSecret: TEST_SECRET,
  sessionTtl: 604800,
  proxyCookieTtl: 86400,
};

function createTestApp(db: DatabaseService, mockPasskey?: any) {
  const app = express();
  app.use((_req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
  });
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Mock OAuth service (we can't do real AT Proto OAuth in tests)
  const mockOAuth = {
    generateAuthUrl: vi.fn(),
    handleCallback: vi.fn(),
  } as any;

  const router = createProxyAuthRoutes(db, mockOAuth, forwardAuthConfig, TEST_ISSUER, mockPasskey || null);
  app.use('/auth', router);
  return { app, mockOAuth };
}

function createTestSession(db: DatabaseService, overrides: Partial<{
  id: string; did: string; handle: string; expires_at: number;
}> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    id: overrides.id || crypto.randomBytes(16).toString('base64url'),
    did: overrides.did || 'did:plc:test123',
    handle: overrides.handle || 'test.bsky.social',
    created_at: now,
    expires_at: overrides.expires_at || now + 604800,
    last_activity: now,
  };
  db.createProxySession(session);
  return session;
}

describe('GET /auth/verify', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    ({ app } = createTestApp(db));
  });

  afterEach(() => {
    db.close();
  });

  it('should return 401 with no cookie', async () => {
    const res = await request(app).get('/auth/verify');
    expect(res.status).toBe(401);
  });

  it('should return 200 with valid proxy cookie', async () => {
    const session = createTestSession(db);
    const cookie = createProxyCookie(session.id, TEST_SECRET, 86400);

    const res = await request(app)
      .get('/auth/verify')
      .set('Cookie', `${PROXY_COOKIE_NAME}=${cookie}`);

    expect(res.status).toBe(200);
    expect(res.headers['x-auth-did']).toBe(session.did);
    expect(res.headers['x-auth-handle']).toBe(session.handle);
    expect(res.headers['x-auth-user']).toBe(session.handle);
  });

  it('should return 401 with expired proxy cookie', async () => {
    const now = Math.floor(Date.now() / 1000);
    const session = createTestSession(db, { expires_at: now - 100 });
    const cookie = createProxyCookie(session.id, TEST_SECRET, 86400);

    const res = await request(app)
      .get('/auth/verify')
      .set('Cookie', `${PROXY_COOKIE_NAME}=${cookie}`);

    expect(res.status).toBe(401);
  });

  it('should return 401 with invalid proxy cookie', async () => {
    const res = await request(app)
      .get('/auth/verify')
      .set('Cookie', `${PROXY_COOKIE_NAME}=invalid.cookie`);

    expect(res.status).toBe(401);
  });

  it('should return 200 with valid ticket in X-Original-URL', async () => {
    const session = createTestSession(db);
    const ticket = createAuthTicket(
      session.id, session.did, session.handle,
      'https://search.example.com', TEST_SECRET,
    );

    const res = await request(app)
      .get('/auth/verify')
      .set('X-Original-URL', `https://search.example.com/path?_atauth_ticket=${ticket}`)
      .set('X-Forwarded-Proto', 'https')
      .set('X-Forwarded-Host', 'search.example.com');

    expect(res.status).toBe(200);
    expect(res.headers['x-auth-did']).toBe(session.did);
    expect(res.headers['x-auth-handle']).toBe(session.handle);
    // Should set a proxy cookie for the domain
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain(PROXY_COOKIE_NAME);
  });
});

describe('GET /auth/proxy/login', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    ({ app } = createTestApp(db));
  });

  afterEach(() => {
    db.close();
  });

  it('should return 400 without redirect parameter', async () => {
    const res = await request(app).get('/auth/proxy/login');
    expect(res.status).toBe(400);
  });

  it('should return 403 for disallowed origin', async () => {
    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://evil.example.com/page' });

    expect(res.status).toBe(403);
    expect(res.text).toContain('Access Denied');
  });

  it('should redirect with ticket for existing session (silent SSO)', async () => {
    // Add allowed origin
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    // Create session and cookie
    const session = createTestSession(db);
    const sessionCookie = createSessionCookie(session.id, TEST_SECRET, 604800);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/path' })
      .set('Cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('search.example.com');
    expect(res.headers.location).toContain('_atauth_ticket=');
  });

  it('should deny silent SSO when access rules block user', async () => {
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    // Only allow example.com handles
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.example.com',
      description: null,
    });

    const session = createTestSession(db, { handle: 'outsider.bsky.social' });
    const sessionCookie = createSessionCookie(session.id, TEST_SECRET, 604800);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/path' })
      .set('Cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`);

    expect(res.status).toBe(403);
    expect(res.text).toContain('Not Authorized');
  });

  it('should allow silent SSO when no access rules exist (open mode)', async () => {
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    const session = createTestSession(db);
    const sessionCookie = createSessionCookie(session.id, TEST_SECRET, 604800);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/path' })
      .set('Cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('_atauth_ticket=');
  });

  it('should render login page when no session exists', async () => {
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/path' });

    expect(res.status).toBe(200);
    expect(res.text).toContain('Sign in to continue');
    expect(res.text).toContain('auth_request_id');
  });
});

describe('GET /auth/proxy/logout', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    ({ app } = createTestApp(db));
  });

  afterEach(() => {
    db.close();
  });

  it('should clear session cookie and render logged out page', async () => {
    const session = createTestSession(db);
    const sessionCookie = createSessionCookie(session.id, TEST_SECRET, 604800);

    const res = await request(app)
      .get('/auth/proxy/logout')
      .set('Cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`);

    expect(res.status).toBe(200);
    expect(res.text).toContain('Signed Out');
    // Cookie should be cleared
    expect(res.headers['set-cookie'][0]).toContain('Max-Age=0');

    // Session should be deleted from DB
    expect(db.getProxySession(session.id)).toBeNull();
  });

  it('should redirect to rd param after logout when origin is allowed', async () => {
    db.addProxyAllowedOrigin('https://example.com', 'Example');
    const res = await request(app)
      .get('/auth/proxy/logout')
      .query({ rd: 'https://example.com/page' });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('https://example.com/page');
  });

  it('should not redirect to disallowed rd param after logout', async () => {
    const res = await request(app)
      .get('/auth/proxy/logout')
      .query({ rd: 'https://evil.example.com' });

    expect(res.status).toBe(200);
    expect(res.text).toContain('Signed Out');
  });
});

describe('POST /auth/proxy/login', () => {
  let db: DatabaseService;
  let app: express.Application;
  let mockOAuth: { generateAuthUrl: ReturnType<typeof vi.fn>; handleCallback: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    ({ app, mockOAuth } = createTestApp(db));
  });

  afterEach(() => {
    db.close();
  });

  it('should return 400 if auth_request_id or handle is missing', async () => {
    const res = await request(app)
      .post('/auth/proxy/login')
      .send({ handle: 'test.bsky.social' });

    expect(res.status).toBe(400);
  });

  it('should return 400 if auth request does not exist', async () => {
    const res = await request(app)
      .post('/auth/proxy/login')
      .send({ auth_request_id: 'nonexistent', handle: 'test.bsky.social' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('expired or invalid');
  });

  it('should return 400 if auth request is expired', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'expired-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now - 700,
      expires_at: now - 100,
    });

    const res = await request(app)
      .post('/auth/proxy/login')
      .send({ auth_request_id: 'expired-req', handle: 'test.bsky.social' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('expired');
  });

  it('should redirect to AT Proto OAuth URL on success', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'valid-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockOAuth.generateAuthUrl.mockResolvedValue({
      url: 'https://bsky.social/oauth/authorize?state=abc123',
      state: 'abc123',
    });

    const res = await request(app)
      .post('/auth/proxy/login')
      .type('form')
      .send({ auth_request_id: 'valid-req', handle: 'test.bsky.social' });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('bsky.social/oauth/authorize');
    expect(mockOAuth.generateAuthUrl).toHaveBeenCalledWith(
      'proxy-auth',
      'test.bsky.social',
      `${TEST_ISSUER}/auth/proxy/callback`,
    );
  });

  it('should sanitize handle - strip @ prefix', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'req1',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockOAuth.generateAuthUrl.mockResolvedValue({
      url: 'https://bsky.social/oauth/authorize',
      state: 'st1',
    });

    await request(app)
      .post('/auth/proxy/login')
      .send({ auth_request_id: 'req1', handle: '@user.bsky.social' });

    expect(mockOAuth.generateAuthUrl).toHaveBeenCalledWith(
      'proxy-auth',
      'user.bsky.social',
      expect.any(String),
    );
  });

  it('should append .bsky.social for handles without dots', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'req2',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockOAuth.generateAuthUrl.mockResolvedValue({
      url: 'https://bsky.social/oauth/authorize',
      state: 'st2',
    });

    await request(app)
      .post('/auth/proxy/login')
      .send({ auth_request_id: 'req2', handle: 'username' });

    expect(mockOAuth.generateAuthUrl).toHaveBeenCalledWith(
      'proxy-auth',
      'username.bsky.social',
      expect.any(String),
    );
  });

  it('should show error page on OAuth failure', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'req3',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockOAuth.generateAuthUrl.mockRejectedValue(new Error('resolve identity failed'));

    const res = await request(app)
      .post('/auth/proxy/login')
      .send({ auth_request_id: 'req3', handle: 'nonexistent.handle' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('Could not find that handle');
  });

  it('should return JSON error when request is JSON', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'req4',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockOAuth.generateAuthUrl.mockRejectedValue(new Error('resolve identity failed'));

    const res = await request(app)
      .post('/auth/proxy/login')
      .set('Content-Type', 'application/json')
      .send({ auth_request_id: 'req4', handle: 'nonexistent' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Could not find that handle');
  });
});

describe('GET /auth/proxy/callback', () => {
  let db: DatabaseService;
  let app: express.Application;
  let mockOAuth: { generateAuthUrl: ReturnType<typeof vi.fn>; handleCallback: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    ({ app, mockOAuth } = createTestApp(db));
  });

  afterEach(() => {
    db.close();
  });

  it('should return 400 if AT Proto returns an error', async () => {
    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ error: 'access_denied', error_description: 'User denied' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('User denied');
  });

  it('should return 400 if code or state is missing', async () => {
    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ code: 'abc' });

    expect(res.status).toBe(400);
  });

  it('should return 400 for invalid state', async () => {
    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ code: 'abc', state: 'nonexistent' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('Invalid or expired state');
  });

  it('should complete full callback flow', async () => {
    const now = Math.floor(Date.now() / 1000);

    // Register the allowed origin (required for access check)
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    // Set up proxy auth request
    db.saveProxyAuthRequest({
      id: 'auth-req-1',
      redirect_uri: 'https://search.example.com/path?q=test',
      created_at: now,
      expires_at: now + 600,
    });

    // Set up OAuth state linking to proxy auth request
    db.saveOAuthState({
      state: 'oauth-state-1',
      code_verifier: 'auth-req-1',
      app_id: 'proxy-auth',
      redirect_uri: 'https://search.example.com/path?q=test',
      created_at: now,
    });

    mockOAuth.handleCallback.mockResolvedValue({
      did: 'did:plc:testuser',
      handle: 'testuser.bsky.social',
    });

    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ code: 'auth-code', state: 'oauth-state-1', iss: 'https://bsky.social' });

    // Should redirect back to original URL with ticket
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('search.example.com');
    expect(res.headers.location).toContain('_atauth_ticket=');

    // Should set session cookie on ATAuth domain
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain(SESSION_COOKIE_NAME);

    // Should pass redirect_uri to handleCallback
    expect(mockOAuth.handleCallback).toHaveBeenCalledWith(
      expect.any(URLSearchParams),
      `${TEST_ISSUER}/auth/proxy/callback`,
    );

    // OAuth state should be cleaned up
    expect(db.getOAuthState('oauth-state-1')).toBeNull();

    // Auth request should be cleaned up
    expect(db.getProxyAuthRequest('auth-req-1')).toBeNull();

    // Proxy session should exist
    const sessions = db.getAllProxySessions('did:plc:testuser');
    expect(sessions).toHaveLength(1);
    expect(sessions[0].handle).toBe('testuser.bsky.social');
  });

  it('should return 400 if auth request expired', async () => {
    const now = Math.floor(Date.now() / 1000);

    // State exists but auth request was deleted/expired
    db.saveOAuthState({
      state: 'orphan-state',
      code_verifier: 'missing-auth-req',
      app_id: 'proxy-auth',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
    });

    mockOAuth.handleCallback.mockResolvedValue({
      did: 'did:plc:testuser',
      handle: 'testuser.bsky.social',
    });

    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ code: 'auth-code', state: 'orphan-state' });

    expect(res.status).toBe(400);
    expect(res.text).toContain('Login request expired');
  });

  it('should return 500 page if handleCallback throws', async () => {
    const now = Math.floor(Date.now() / 1000);

    db.saveProxyAuthRequest({
      id: 'auth-req-err',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    db.saveOAuthState({
      state: 'error-state',
      code_verifier: 'auth-req-err',
      app_id: 'proxy-auth',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
    });

    mockOAuth.handleCallback.mockRejectedValue(new Error('Token exchange failed'));

    const res = await request(app)
      .get('/auth/proxy/callback')
      .query({ code: 'bad-code', state: 'error-state' });

    expect(res.status).toBe(500);
    expect(res.text).toContain('unexpected error');
  });
});

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

describe('POST /auth/proxy/passkey', () => {
  let db: DatabaseService;
  let app: express.Application;
  let mockPasskey: { verifyAuthentication: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    mockPasskey = {
      verifyAuthentication: vi.fn(),
    };
    ({ app } = createTestApp(db, mockPasskey));
  });

  afterEach(() => {
    db.close();
  });

  it('should complete proxy flow via passkey authentication', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');
    db.saveProxyAuthRequest({
      id: 'passkey-req-1',
      redirect_uri: 'https://search.example.com/path',
      created_at: now,
      expires_at: now + 600,
    });

    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: true,
      did: 'did:plc:test123',
      handle: 'user.bsky.social',
    });

    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'passkey-req-1',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(200);
    expect(res.body.redirect_url).toContain('search.example.com');
    expect(res.body.redirect_url).toContain('_atauth_ticket=');

    // Session cookie should be set
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain(SESSION_COOKIE_NAME);

    // Auth request should be cleaned up
    expect(db.getProxyAuthRequest('passkey-req-1')).toBeNull();

    // Proxy session should exist
    const sessions = db.getAllProxySessions('did:plc:test123');
    expect(sessions).toHaveLength(1);
    expect(sessions[0].handle).toBe('user.bsky.social');
  });

  it('should return 400 for missing parameters', async () => {
    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({ auth_request_id: 'test' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('should return 400 for invalid auth request', async () => {
    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'nonexistent',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toContain('expired or invalid');
  });

  it('should return 400 for expired auth request', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'expired-passkey-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now - 700,
      expires_at: now - 100,
    });

    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'expired-passkey-req',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(400);
    expect(res.body.error_description).toContain('expired');
  });

  it('should return 401 for failed passkey verification', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'fail-passkey-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: false,
      error: 'Unknown credential',
    });

    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'fail-passkey-req',
        credential: mockCredential,
        challenge: 'bad-challenge',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('authentication_failed');
    expect(res.body.error_description).toContain('Unknown credential');
  });

  it('should return 403 when access rules deny the user', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');
    db.saveProxyAuthRequest({
      id: 'denied-passkey-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    // Only allow *.example.com handles
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.example.com',
      description: null,
    });

    mockPasskey.verifyAuthentication.mockResolvedValue({
      success: true,
      did: 'did:plc:outsider',
      handle: 'outsider.bsky.social',
    });

    const res = await request(app)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'denied-passkey-req',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('access_denied');
  });

  it('should return 404 when passkey service is not enabled', async () => {
    const { app: appNoPasskey } = createTestApp(db);
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'no-passkey-req',
      redirect_uri: 'https://search.example.com/',
      created_at: now,
      expires_at: now + 600,
    });

    const res = await request(appNoPasskey)
      .post('/auth/proxy/passkey')
      .send({
        auth_request_id: 'no-passkey-req',
        credential: mockCredential,
        challenge: 'test-challenge',
      });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('not_found');
  });
});

describe('Proxy login page passkey rendering', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');
  });

  afterEach(() => {
    db.close();
  });

  it('should render passkey button when passkey service is enabled', async () => {
    const mockPasskey = { verifyAuthentication: vi.fn() };
    const { app } = createTestApp(db, mockPasskey);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/page' });

    expect(res.status).toBe(200);
    expect(res.text).toContain('passkeyBtn');
    expect(res.text).toContain('Sign in with passkey');
    expect(res.text).toContain('b64urlToBuffer');
    expect(res.text).toContain('/auth/proxy/passkey');
  });

  it('should not render passkey button when passkey service is disabled', async () => {
    const { app } = createTestApp(db);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.example.com/page' });

    expect(res.status).toBe(200);
    expect(res.text).not.toContain('passkeyBtn');
    expect(res.text).not.toContain('Sign in with passkey');
    // Handle form should still be present
    expect(res.text).toContain('loginForm');
    expect(res.text).toContain('you.bsky.social');
  });
});
