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
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

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
    db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

    const res = await request(app)
      .get('/admin/dashboard/origins')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('SearXNG');
    expect(res.text).toContain('search.example.com');
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
    const origin = db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');

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
        subject_value: '*.example.com',
        description: 'PDS users',
      });

    expect(res.status).toBe(302);
    const rules = db.listProxyAccessRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].subject_value).toBe('*.example.com');
  });

  it('should display existing rules', async () => {
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.example.com',
      description: 'PDS users',
    });

    const res = await request(app)
      .get('/admin/dashboard/access')
      .set('Cookie', adminCookie());

    expect(res.text).toContain('*.example.com');
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
    const origin = db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.example.com',
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
        handle: 'user.example.com',
        origin_id: origin.id.toString(),
      });

    expect(res.status).toBe(200);
    expect(res.text).toContain('ACCESS ALLOWED');
  });

  it('should show denied result', async () => {
    const origin = db.addProxyAllowedOrigin('https://search.example.com', 'SearXNG');
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.example.com',
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

// ===== Helper to create an OIDC client via DB =====

function createTestOIDCClient(db: DatabaseService, id = 'test-app', name = 'Test App') {
  db.upsertApp({
    id,
    name,
    hmac_secret: crypto.randomBytes(32).toString('hex'),
    token_ttl_seconds: 3600,
    callback_url: 'https://app.example.com/callback',
  });
  db.updateOIDCClient(id, {
    client_type: 'oidc',
    client_secret: crypto.createHash('sha256').update('test-secret').digest('hex'),
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email'],
    require_pkce: true,
    token_endpoint_auth_method: 'client_secret_basic',
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
  });
}

async function getCsrf(app: express.Application, path: string): Promise<string> {
  const page = await request(app)
    .get(path)
    .set('Cookie', adminCookie());
  const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
  if (!csrfMatch) throw new Error(`No CSRF token found on ${path}`);
  return csrfMatch[1];
}

// ===== OIDC Client Management =====

describe('Dashboard OIDC Clients', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render client list page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('OIDC Clients');
    expect(res.text).toContain('New Client');
  });

  it('should list existing clients in table', async () => {
    createTestOIDCClient(db);

    const res = await request(app)
      .get('/admin/dashboard/clients')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('test-app');
    expect(res.text).toContain('Test App');
    expect(res.text).toContain('app.example.com');
  });

  it('should render new client form', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/new')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('New OIDC Client');
    expect(res.text).toContain('Client ID');
    expect(res.text).toContain('Redirect URIs');
    expect(res.text).toContain('Grant Types');
  });

  it('should create client and redirect to secret page', async () => {
    const csrf = await getCsrf(app, '/admin/dashboard/clients/new');

    const res = await request(app)
      .post('/admin/dashboard/clients/new')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        id: 'myapp',
        name: 'My App',
        redirect_uris_text: 'https://myapp.example.com/callback',
        grant_types: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile'],
        auth_method: 'client_secret_basic',
        require_pkce: 'on',
        id_token_ttl: '3600',
        access_token_ttl: '3600',
        refresh_token_ttl: '604800',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/admin/dashboard/clients/created');
    expect(res.headers.location).toContain('id=myapp');
    expect(res.headers.location).toContain('secret=');

    // Verify in DB
    const client = db.getOIDCClient('myapp');
    expect(client).not.toBeNull();
    expect(client!.name).toBe('My App');
    expect(client!.redirect_uris).toEqual(['https://myapp.example.com/callback']);
    expect(client!.require_pkce).toBe(true);
  });

  it('should display secret on created page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/created?id=test&secret=abc123hex')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Client Created');
    expect(res.text).toContain('abc123hex');
    expect(res.text).toContain('This secret will not be shown again');
    expect(res.text).toContain('Discovery URL');
  });

  it('should reject duplicate client ID', async () => {
    createTestOIDCClient(db);
    const csrf = await getCsrf(app, '/admin/dashboard/clients/new');

    const res = await request(app)
      .post('/admin/dashboard/clients/new')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        id: 'test-app',
        name: 'Duplicate',
        redirect_uris_text: 'https://dup.example.com/callback',
        grant_types: 'authorization_code',
        scopes: 'openid',
        auth_method: 'client_secret_basic',
        require_pkce: 'on',
        id_token_ttl: '3600',
        access_token_ttl: '3600',
        refresh_token_ttl: '604800',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=');
    expect(res.headers.location).toContain('already%20exists');
  });

  it('should reject missing required fields', async () => {
    const csrf = await getCsrf(app, '/admin/dashboard/clients/new');

    const res = await request(app)
      .post('/admin/dashboard/clients/new')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        id: '',
        name: '',
        redirect_uris_text: '',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=');
  });

  it('should render edit form with pre-filled values', async () => {
    createTestOIDCClient(db);

    const res = await request(app)
      .get('/admin/dashboard/clients/test-app/edit')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Edit Client');
    expect(res.text).toContain('test-app');
    expect(res.text).toContain('Test App');
    expect(res.text).toContain('app.example.com/callback');
    expect(res.text).toContain('Rotate Client Secret');
  });

  it('should update client via edit form', async () => {
    createTestOIDCClient(db);
    const csrf = await getCsrf(app, '/admin/dashboard/clients/test-app/edit');

    const res = await request(app)
      .post('/admin/dashboard/clients/test-app/edit')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        name: 'Updated App',
        redirect_uris_text: 'https://updated.example.com/callback',
        grant_types: 'authorization_code',
        scopes: ['openid', 'profile'],
        auth_method: 'client_secret_post',
        require_pkce: 'on',
        id_token_ttl: '7200',
        access_token_ttl: '7200',
        refresh_token_ttl: '1209600',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('Client+updated');

    const updated = db.getOIDCClient('test-app');
    expect(updated!.redirect_uris).toEqual(['https://updated.example.com/callback']);
    expect(updated!.token_endpoint_auth_method).toBe('client_secret_post');
    expect(updated!.id_token_ttl_seconds).toBe(7200);
  });

  it('should rotate secret and show new secret', async () => {
    createTestOIDCClient(db);
    const oldClient = db.getOIDCClient('test-app');
    const csrf = await getCsrf(app, '/admin/dashboard/clients/test-app/edit');

    const res = await request(app)
      .post('/admin/dashboard/clients/test-app/rotate-secret')
      .set('Cookie', adminCookie())
      .type('form')
      .send({ _csrf: csrf });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/admin/dashboard/clients/created');
    expect(res.headers.location).toContain('rotated=1');
    expect(res.headers.location).toContain('secret=');

    // Verify secret changed
    const newClient = db.getOIDCClient('test-app');
    expect(newClient!.client_secret).not.toBe(oldClient!.client_secret);
  });

  it('should delete client', async () => {
    createTestOIDCClient(db);
    const csrf = await getCsrf(app, '/admin/dashboard/clients');

    const res = await request(app)
      .post('/admin/dashboard/clients/test-app/delete')
      .set('Cookie', adminCookie())
      .type('form')
      .send({ _csrf: csrf });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('Client+deleted');
    expect(db.getOIDCClient('test-app')).toBeNull();
  });

  it('should reject POST without CSRF', async () => {
    const res = await request(app)
      .post('/admin/dashboard/clients/new')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        id: 'nope',
        name: 'Nope',
        redirect_uris_text: 'https://nope.com/cb',
        grant_types: 'authorization_code',
        scopes: 'openid',
      });

    expect(res.status).toBe(403);
    expect(res.text).toContain('Invalid or expired form submission');
  });
});

// ===== Setup Wizard =====

describe('Dashboard Setup Wizard', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render app selection grid', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/wizard')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Setup Wizard');
    expect(res.text).toContain('Audiobookshelf');
    expect(res.text).toContain('Jellyfin');
    expect(res.text).toContain('Nextcloud');
    expect(res.text).toContain('Gitea');
    expect(res.text).toContain('Custom');
  });

  it('should render preset form with pre-filled values', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/wizard/audiobookshelf')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Setup Audiobookshelf');
    expect(res.text).toContain('audiobookshelf');
    expect(res.text).toContain('/auth/openid/callback');
    expect(res.text).toContain('Your Domain');
  });

  it('should create client from wizard preset', async () => {
    const csrf = await getCsrf(app, '/admin/dashboard/clients/wizard/audiobookshelf');

    const res = await request(app)
      .post('/admin/dashboard/clients/wizard/audiobookshelf')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        preset: 'audiobookshelf',
        domain: 'abs.example.com',
        id: 'audiobookshelf',
        name: 'Audiobookshelf',
        grant_types: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email'],
        auth_method: 'client_secret_basic',
        require_pkce: 'on',
        id_token_ttl: '3600',
        access_token_ttl: '3600',
        refresh_token_ttl: '604800',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/admin/dashboard/clients/created');
    expect(res.headers.location).toContain('preset=audiobookshelf');

    const client = db.getOIDCClient('audiobookshelf');
    expect(client).not.toBeNull();
    expect(client!.redirect_uris).toEqual(['https://abs.example.com/auth/openid/callback']);
  });

  it('should strip protocol prefix from domain in wizard', async () => {
    const csrf = await getCsrf(app, '/admin/dashboard/clients/wizard/audiobookshelf');

    const res = await request(app)
      .post('/admin/dashboard/clients/wizard/audiobookshelf')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        preset: 'audiobookshelf',
        domain: 'https://abs.example.com',
        id: 'abs-protocol-test',
        name: 'ABS Protocol Test',
        grant_types: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email'],
        auth_method: 'client_secret_basic',
        require_pkce: 'on',
        id_token_ttl: '3600',
        access_token_ttl: '3600',
        refresh_token_ttl: '604800',
      });

    expect(res.status).toBe(302);
    const client = db.getOIDCClient('abs-protocol-test');
    expect(client).not.toBeNull();
    expect(client!.redirect_uris).toEqual(['https://abs.example.com/auth/openid/callback']);
  });

  it('should show setup notes on created page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/created?id=abs&secret=abc123&preset=audiobookshelf')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Setup Instructions');
    expect(res.text).toContain('Audiobookshelf');
    expect(res.text).toContain('Issuer URL');
  });

  it('should 404 for unknown preset', async () => {
    const res = await request(app)
      .get('/admin/dashboard/clients/wizard/nonexistent')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(404);
    expect(res.text).toContain('Preset not found');
  });
});

// ===== Proxy Wizard =====

describe('Dashboard Proxy Wizard', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should render proxy setup form', async () => {
    const res = await request(app)
      .get('/admin/dashboard/proxy-wizard')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('Forward-Auth Proxy Setup');
    expect(res.text).toContain('Service Name');
    expect(res.text).toContain('Origin URL');
  });

  it('should create origin and show config snippets', async () => {
    const csrf = await getCsrf(app, '/admin/dashboard/proxy-wizard');

    const res = await request(app)
      .post('/admin/dashboard/proxy-wizard')
      .set('Cookie', adminCookie())
      .type('form')
      .send({
        _csrf: csrf,
        name: 'SearXNG',
        origin: 'https://search.example.com',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/admin/dashboard/proxy-wizard/result');

    // Verify origin was created
    const origins = db.listProxyAllowedOrigins();
    expect(origins).toHaveLength(1);
    expect(origins[0].name).toBe('SearXNG');
  });

  it('should display config snippets on result page', async () => {
    const res = await request(app)
      .get('/admin/dashboard/proxy-wizard/result?origin=https://search.example.com&name=SearXNG&origin_id=1')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('nginx Configuration');
    expect(res.text).toContain('auth_request');
    expect(res.text).toContain('Kubernetes Ingress');
    expect(res.text).toContain('auth-url');
    expect(res.text).toContain('Add Access Rules');
  });
});

// ===== Overview with OIDC Stats =====

describe('Dashboard Overview OIDC Stats', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
  });

  afterEach(() => {
    db.close();
  });

  it('should show OIDC client count on overview', async () => {
    createTestOIDCClient(db, 'app1', 'App One');
    createTestOIDCClient(db, 'app2', 'App Two');

    const res = await request(app)
      .get('/admin/dashboard')
      .set('Cookie', adminCookie());

    expect(res.status).toBe(200);
    expect(res.text).toContain('OIDC Clients');
    expect(res.text).toContain('>2<');
    expect(res.text).toContain('Setup Wizard');
    expect(res.text).toContain('Add OIDC Client');
  });
});
