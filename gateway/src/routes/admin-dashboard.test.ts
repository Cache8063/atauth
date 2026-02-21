/**
 * Admin Dashboard Routes Tests
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

function createTestApp(db: DatabaseService) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createAdminRoutes(db, ADMIN_TOKEN, null, null, null, SESSION_SECRET);
  app.use('/admin', router);
  return app;
}

function adminCookie(): string {
  return `${ADMIN_COOKIE_NAME}=${createAdminCookie(SESSION_SECRET, 86400)}`;
}

describe('Dashboard Overview', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render overview page with stats', async () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    const res = await request(app)
      .get('/admin/dashboard')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Overview');
    expect(res.text).toContain('Protected Origins');
    expect(res.text).toContain('Access Rules');
    expect(res.text).toContain('Active Sessions');
  });

  it('should redirect to login without cookie', async () => {
    const res = await request(app)
      .get('/admin/dashboard')
      .set('Accept', 'text/html');

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/admin/login');
  });
});

describe('Dashboard Origins', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render origins page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/origins')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Protected Origins');
    expect(res.text).toContain('Add Origin');
  });

  it('should list existing origins', async () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    const res = await request(app)
      .get('/admin/dashboard/origins')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('SearXNG');
    expect(res.text).toContain('search.arcnode.xyz');
  });

  it('should add an origin via form POST', async () => {
    // First get the page to extract CSRF token
    const page = await request(app)
      .get('/admin/dashboard/origins')
      .set('Cookie', adminCookie());

    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    expect(csrfMatch).not.toBeNull();
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post('/admin/dashboard/origins')
      .set('Cookie', adminCookie())
      .type('form')
      .send({ _csrf: csrf, origin: 'https://test.example.com', name: 'Test' });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/admin/dashboard/origins');

    // Verify it was added
    const origins = db.listProxyAllowedOrigins();
    expect(origins).toHaveLength(1);
    expect(origins[0].origin).toBe('https://test.example.com');
  });

  it('should reject form without CSRF token', async () => {
    const res = await request(app)
      .post('/admin/dashboard/origins')
      .set('Cookie', adminCookie())
      .type('form')
      .send({ origin: 'https://test.example.com', name: 'Test' });

    expect(res.status).toBe(403);
    expect(res.text).toContain('Invalid or expired form submission');
  });

  it('should delete an origin via form POST', async () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    const page = await request(app)
      .get('/admin/dashboard/origins')
      .set('Cookie', adminCookie());
    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post(`/admin/dashboard/origins/${origin.id}/delete`)
      .set('Cookie', adminCookie())
      .type('form')
      .send({ _csrf: csrf });

    expect(res.status).toBe(302);
    expect(db.listProxyAllowedOrigins()).toHaveLength(0);
  });
});

describe('Dashboard Access Rules', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render access rules page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/access')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Access Rules');
    expect(res.text).toContain('Add Rule');
  });

  it('should add a rule via form POST', async () => {
    const page = await request(app)
      .get('/admin/dashboard/access')
      .set('Cookie', adminCookie());
    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post('/admin/dashboard/access')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        origin_id: '',
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*.arcnode.xyz',
        description: 'PDS users',
      });

    expect(res.status).toBe(302);
    const rules = db.listProxyAccessRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].subject_value).toBe('*.arcnode.xyz');
  });

  it('should display existing rules', async () => {
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: 'PDS users',
    });

    const res = await request(app)
      .get('/admin/dashboard/access')
      .set('Cookie', adminCookie());

    expect(res.text).toContain('*.arcnode.xyz');
    expect(res.text).toContain('PDS users');
    expect(res.text).toContain('allow');
  });
});

describe('Dashboard Sessions', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render sessions page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/sessions')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Proxy Sessions');
  });

  it('should list active sessions', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.createProxySession({
      id: 'sess-1',
      did: 'did:plc:test123',
      handle: 'user.bsky.social',
      created_at: now,
      expires_at: now + 604800,
      last_activity: now,
    });

    const res = await request(app)
      .get('/admin/dashboard/sessions')
      .set('Cookie', adminCookie());

    expect(res.text).toContain('user.bsky.social');
  });

  it('should revoke a session via form POST', async () => {
    const now = Math.floor(Date.now() / 1000);
    db.createProxySession({
      id: 'sess-del',
      did: 'did:plc:test123',
      handle: 'user.bsky.social',
      created_at: now,
      expires_at: now + 604800,
      last_activity: now,
    });

    const page = await request(app)
      .get('/admin/dashboard/sessions')
      .set('Cookie', adminCookie());
    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post('/admin/dashboard/sessions/sess-del/delete')
      .set('Cookie', adminCookie())
      .type('form')
      .send({ _csrf: csrf });

    expect(res.status).toBe(302);
    expect(db.getProxySession('sess-del')).toBeNull();
  });
});

describe('Dashboard Access Check', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render access check page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/check')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Access Check Tool');
  });

  it('should show access check result', async () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: null,
    });

    const page = await request(app)
      .get('/admin/dashboard/check')
      .set('Cookie', adminCookie());
    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post('/admin/dashboard/check')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        did: 'did:plc:test123',
        handle: 'bkb.arcnode.xyz',
        origin_id: origin.id.toString(),
      });

    expect(res.status).toBe(200);
    expect(res.text).toContain('ACCESS ALLOWED');
  });

  it('should show denied result', async () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: null,
    });

    const page = await request(app)
      .get('/admin/dashboard/check')
      .set('Cookie', adminCookie());
    const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
    const csrf = csrfMatch![1];

    const res = await request(app)
      .post('/admin/dashboard/check')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        did: 'did:plc:outsider',
        handle: 'user.bsky.social',
        origin_id: origin.id.toString(),
      });

    expect(res.status).toBe(200);
    expect(res.text).toContain('ACCESS DENIED');
  });
});
