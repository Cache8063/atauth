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

function createTestApp(db: DatabaseService) {
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

  const router = createProxyAuthRoutes(db, mockOAuth, forwardAuthConfig, TEST_ISSUER);
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
    const cookie = createSessionCookie(session.id, TEST_SECRET, 86400);

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
    const cookie = createSessionCookie(session.id, TEST_SECRET, 86400);

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
      'https://search.arcnode.xyz', TEST_SECRET,
    );

    const res = await request(app)
      .get('/auth/verify')
      .set('X-Original-URL', `https://search.arcnode.xyz/path?_atauth_ticket=${ticket}`)
      .set('X-Forwarded-Proto', 'https')
      .set('X-Forwarded-Host', 'search.arcnode.xyz');

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
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    // Create session and cookie
    const session = createTestSession(db);
    const sessionCookie = createSessionCookie(session.id, TEST_SECRET, 604800);

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.arcnode.xyz/path' })
      .set('Cookie', `${SESSION_COOKIE_NAME}=${sessionCookie}`);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('search.arcnode.xyz');
    expect(res.headers.location).toContain('_atauth_ticket=');
  });

  it('should render login page when no session exists', async () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    const res = await request(app)
      .get('/auth/proxy/login')
      .query({ rd: 'https://search.arcnode.xyz/path' });

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

  it('should redirect to rd param after logout', async () => {
    const res = await request(app)
      .get('/auth/proxy/logout')
      .query({ rd: 'https://example.com' });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('https://example.com');
  });
});
