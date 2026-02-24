/**
 * Admin Proxy API Tests
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createAdminRoutes } from './admin.js';
import { DatabaseService } from '../services/database.js';

import { createAdminCookie, ADMIN_COOKIE_NAME } from '../utils/proxy-auth.js';

const ADMIN_TOKEN = 'test-admin-token-secret';
const SESSION_SECRET = 'test-session-secret-for-admin-32!';

function createTestApp(db: DatabaseService, sessionSecret?: string) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createAdminRoutes(db, ADMIN_TOKEN, null, null, null, sessionSecret);
  app.use('/admin', router);
  return app;
}

function authHeader() {
  return { Authorization: `Bearer ${ADMIN_TOKEN}` };
}

describe('Admin Proxy Origins', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should require admin auth', async () => {
    const res = await request(app).get('/admin/proxy/origins');
    expect(res.status).toBe(401);
  });

  it('should reject invalid admin token', async () => {
    const res = await request(app)
      .get('/admin/proxy/origins')
      .set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(403);
  });

  it('should list empty origins initially', async () => {
    const res = await request(app)
      .get('/admin/proxy/origins')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.origins).toEqual([]);
  });

  it('should add an allowed origin', async () => {
    const res = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    expect(res.status).toBe(201);
    expect(res.body.origin).toBe('https://search.example.com');
    expect(res.body.name).toBe('SearXNG');
    expect(res.body.id).toBeGreaterThan(0);
  });

  it('should reject origin without name', async () => {
    const res = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://test.example.com' });

    expect(res.status).toBe(400);
  });

  it('should reject invalid origin format', async () => {
    const res = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'not-a-url', name: 'Bad' });

    expect(res.status).toBe(400);
  });

  it('should reject origin with trailing path', async () => {
    const res = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com/path', name: 'Bad' });

    expect(res.status).toBe(400);
  });

  it('should reject duplicate origin', async () => {
    await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    const res = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'Duplicate' });

    expect(res.status).toBe(409);
  });

  it('should list origins after adding', async () => {
    await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });
    await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://element.example.com', name: 'Element' });

    const res = await request(app)
      .get('/admin/proxy/origins')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.origins).toHaveLength(2);
  });

  it('should delete an origin', async () => {
    const created = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    const res = await request(app)
      .delete(`/admin/proxy/origins/${created.body.id}`)
      .set(authHeader());

    expect(res.status).toBe(200);

    const list = await request(app)
      .get('/admin/proxy/origins')
      .set(authHeader());
    expect(list.body.origins).toHaveLength(0);
  });
});

describe('Admin Proxy Sessions', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  function createSession(overrides: Partial<{ id: string; did: string; handle: string }> = {}) {
    const now = Math.floor(Date.now() / 1000);
    const session = {
      id: overrides.id || crypto.randomBytes(16).toString('base64url'),
      did: overrides.did || 'did:plc:test123',
      handle: overrides.handle || 'test.bsky.social',
      created_at: now,
      expires_at: now + 604800,
      last_activity: now,
    };
    db.createProxySession(session);
    return session;
  }

  it('should list proxy sessions', async () => {
    createSession({ id: 's1', did: 'did:plc:a' });
    createSession({ id: 's2', did: 'did:plc:b' });

    const res = await request(app)
      .get('/admin/proxy/sessions')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(2);
  });

  it('should filter sessions by DID', async () => {
    createSession({ id: 's1', did: 'did:plc:a' });
    createSession({ id: 's2', did: 'did:plc:b' });

    const res = await request(app)
      .get('/admin/proxy/sessions')
      .query({ did: 'did:plc:a' })
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(1);
    expect(res.body.sessions[0].did).toBe('did:plc:a');
  });

  it('should delete a proxy session', async () => {
    const session = createSession();

    const res = await request(app)
      .delete(`/admin/proxy/sessions/${session.id}`)
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(db.getProxySession(session.id)).toBeNull();
  });
});

describe('Admin Access Rules API', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should list empty rules', async () => {
    const res = await request(app)
      .get('/admin/proxy/access')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.rules).toEqual([]);
  });

  it('should create an allow rule', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: null,
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*.example.com',
        description: 'PDS users',
      });

    expect(res.status).toBe(201);
    expect(res.body.rule_type).toBe('allow');
    expect(res.body.subject_value).toBe('*.example.com');
  });

  it('should create a deny rule', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: null,
        rule_type: 'deny',
        subject_type: 'did',
        subject_value: 'did:plc:banned',
      });

    expect(res.status).toBe(201);
    expect(res.body.rule_type).toBe('deny');
  });

  it('should reject invalid rule_type', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        rule_type: 'invalid',
        subject_type: 'did',
        subject_value: 'did:plc:test',
      });

    expect(res.status).toBe(400);
  });

  it('should reject invalid subject_type', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'email',
        subject_value: 'test@test.com',
      });

    expect(res.status).toBe(400);
  });

  it('should reject DID without did: prefix', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'did',
        subject_value: 'plc:test123',
      });

    expect(res.status).toBe(400);
  });

  it('should reject invalid handle pattern', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '***',
      });

    expect(res.status).toBe(400);
  });

  it('should reject non-existent origin_id', async () => {
    const res = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: 9999,
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*',
      });

    expect(res.status).toBe(404);
  });

  it('should delete a rule', async () => {
    const created = await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*',
      });

    const res = await request(app)
      .delete(`/admin/proxy/access/${created.body.id}`)
      .set(authHeader());

    expect(res.status).toBe(200);

    const list = await request(app)
      .get('/admin/proxy/access')
      .set(authHeader());
    expect(list.body.rules).toHaveLength(0);
  });

  it('should filter rules by origin_id', async () => {
    const origin = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: origin.body.id,
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*',
      });
    await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: null,
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*.example.com',
      });

    const res = await request(app)
      .get('/admin/proxy/access')
      .query({ origin_id: origin.body.id })
      .set(authHeader());

    expect(res.status).toBe(200);
    // Should include origin-specific + global (NULL) rules
    expect(res.body.rules).toHaveLength(2);
  });

  it('should run a dry-run access check', async () => {
    const origin = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    await request(app)
      .post('/admin/proxy/access')
      .set(authHeader())
      .send({
        origin_id: null,
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*.example.com',
      });

    const allowed = await request(app)
      .post('/admin/proxy/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:test', handle: 'user.example.com', origin_id: origin.body.id });

    expect(allowed.status).toBe(200);
    expect(allowed.body.allowed).toBe(true);

    const denied = await request(app)
      .post('/admin/proxy/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:test', handle: 'random.bsky.social', origin_id: origin.body.id });

    expect(denied.status).toBe(200);
    expect(denied.body.allowed).toBe(false);
  });

  it('should return open access when no rules exist', async () => {
    const origin = await request(app)
      .post('/admin/proxy/origins')
      .set(authHeader())
      .send({ origin: 'https://search.example.com', name: 'SearXNG' });

    const res = await request(app)
      .post('/admin/proxy/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:anyone', handle: 'anyone.bsky.social', origin_id: origin.body.id });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(true);
    expect(res.body.reason).toContain('open access');
  });
});

describe('Admin Cookie Auth', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db, SESSION_SECRET);
  });

  afterEach(() => {
    db.close();
  });

  it('should render login page', async () => {
    const res = await request(app).get('/admin/login');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Admin Token');
    expect(res.text).toContain('form');
  });

  it('should reject invalid login token', async () => {
    const res = await request(app)
      .post('/admin/login')
      .type('form')
      .send({ token: 'wrong-token' });

    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid admin token');
  });

  it('should set cookie on valid login', async () => {
    const res = await request(app)
      .post('/admin/login')
      .type('form')
      .send({ token: ADMIN_TOKEN });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/admin/dashboard');
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain(ADMIN_COOKIE_NAME);
    expect(res.headers['set-cookie'][0]).toContain('HttpOnly');
    expect(res.headers['set-cookie'][0]).toContain('SameSite=Strict');
  });

  it('should clear cookie on logout', async () => {
    const res = await request(app).get('/admin/logout');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/admin/login');
    expect(res.headers['set-cookie'][0]).toContain('Max-Age=0');
  });

  it('should accept admin cookie for protected endpoints', async () => {
    const cookie = createAdminCookie(SESSION_SECRET, 86400);

    const res = await request(app)
      .get('/admin/proxy/origins')
      .set('Cookie', `${ADMIN_COOKIE_NAME}=${cookie}`);

    expect(res.status).toBe(200);
  });

  it('should reject invalid admin cookie', async () => {
    const res = await request(app)
      .get('/admin/proxy/origins')
      .set('Cookie', `${ADMIN_COOKIE_NAME}=invalid.cookie`)
      .set('Accept', 'application/json');

    expect(res.status).toBe(401);
  });

  it('should reject expired admin cookie', async () => {
    // Create cookie with 0s TTL (already expired)
    const cookie = createAdminCookie(SESSION_SECRET, -1);

    const res = await request(app)
      .get('/admin/proxy/origins')
      .set('Cookie', `${ADMIN_COOKIE_NAME}=${cookie}`)
      .set('Accept', 'application/json');

    expect(res.status).toBe(401);
  });
});
