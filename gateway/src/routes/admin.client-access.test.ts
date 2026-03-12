/**
 * Admin Client Access Rules API Tests
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAdminRoutes } from './admin.js';
import { DatabaseService } from '../services/database.js';

const ADMIN_TOKEN = 'test-admin-token-secret';

function createTestApp(db: DatabaseService) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createAdminRoutes(db, ADMIN_TOKEN, null, null, null);
  app.use('/admin', router);
  return app;
}

function authHeader() {
  return { Authorization: `Bearer ${ADMIN_TOKEN}` };
}

function createTestClient(db: DatabaseService, clientId = 'test-app', requireAccessCheck = false) {
  db.upsertOIDCClient({
    id: clientId,
    name: 'Test App',
    client_type: 'oidc',
    hmac_secret: 'test-secret-min-32-characters-long!!',
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code'],
    allowed_scopes: ['openid'],
    token_ttl_seconds: 3600,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    require_pkce: true,
    require_access_check: requireAccessCheck,
    token_endpoint_auth_method: 'client_secret_basic',
  });
}

describe('Admin Client Access Rules', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
    createTestClient(db);
  });

  afterEach(() => {
    db.close();
  });

  // List rules

  it('should return empty rules initially', async () => {
    const res = await request(app)
      .get('/admin/clients/test-app/access')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.rules).toEqual([]);
    expect(res.body.require_access_check).toBe(false);
  });

  it('should return 404 for unknown client', async () => {
    const res = await request(app)
      .get('/admin/clients/nonexistent/access')
      .set(authHeader());

    expect(res.status).toBe(404);
  });

  // Create rules

  it('should create an allow rule by DID', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'did',
        subject_value: 'did:plc:testuser123',
        description: 'Test user',
      });

    expect(res.status).toBe(201);
    expect(res.body.client_id).toBe('test-app');
    expect(res.body.rule_type).toBe('allow');
    expect(res.body.subject_type).toBe('did');
    expect(res.body.subject_value).toBe('did:plc:testuser123');
  });

  it('should create an allow rule by handle pattern', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '*.bsky.social',
      });

    expect(res.status).toBe(201);
    expect(res.body.subject_type).toBe('handle_pattern');
    expect(res.body.subject_value).toBe('*.bsky.social');
  });

  it('should create a deny rule', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'deny',
        subject_type: 'handle_pattern',
        subject_value: 'bad.actor.bsky.social',
      });

    expect(res.status).toBe(201);
    expect(res.body.rule_type).toBe('deny');
  });

  it('should reject invalid rule_type', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'invalid',
        subject_type: 'did',
        subject_value: 'did:plc:test',
      });

    expect(res.status).toBe(400);
  });

  it('should reject invalid DID format', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'did',
        subject_value: 'not-a-did',
      });

    expect(res.status).toBe(400);
  });

  it('should reject invalid handle pattern', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'handle_pattern',
        subject_value: '..invalid',
      });

    expect(res.status).toBe(400);
  });

  // Delete rules

  it('should delete a rule', async () => {
    // Create a rule first
    const createRes = await request(app)
      .post('/admin/clients/test-app/access')
      .set(authHeader())
      .send({
        rule_type: 'allow',
        subject_type: 'did',
        subject_value: 'did:plc:testuser123',
      });

    const ruleId = createRes.body.id;

    const deleteRes = await request(app)
      .delete(`/admin/clients/test-app/access/${ruleId}`)
      .set(authHeader());

    expect(deleteRes.status).toBe(200);

    // Verify it's gone
    const listRes = await request(app)
      .get('/admin/clients/test-app/access')
      .set(authHeader());

    expect(listRes.body.rules).toEqual([]);
  });

  // Toggle access check

  it('should enable access check', async () => {
    const res = await request(app)
      .patch('/admin/clients/test-app/access-check')
      .set(authHeader())
      .send({ enabled: true });

    expect(res.status).toBe(200);
    expect(res.body.require_access_check).toBe(true);

    // Verify in list
    const listRes = await request(app)
      .get('/admin/clients/test-app/access')
      .set(authHeader());

    expect(listRes.body.require_access_check).toBe(true);
  });

  it('should disable access check', async () => {
    // Enable first
    await request(app)
      .patch('/admin/clients/test-app/access-check')
      .set(authHeader())
      .send({ enabled: true });

    // Then disable
    const res = await request(app)
      .patch('/admin/clients/test-app/access-check')
      .set(authHeader())
      .send({ enabled: false });

    expect(res.status).toBe(200);
    expect(res.body.require_access_check).toBe(false);
  });

  it('should reject non-boolean enabled', async () => {
    const res = await request(app)
      .patch('/admin/clients/test-app/access-check')
      .set(authHeader())
      .send({ enabled: 'yes' });

    expect(res.status).toBe(400);
  });

  // Access check dry-run

  it('should allow when access check is disabled', async () => {
    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:anyone', handle: 'anyone.bsky.social' });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(true);
    expect(res.body.reason).toContain('not enabled');
  });

  it('should deny when access check is enabled but no rules', async () => {
    db.setClientAccessCheck('test-app', true);

    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:anyone', handle: 'anyone.bsky.social' });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(false);
    expect(res.body.reason).toContain('no rules');
  });

  it('should allow matching DID when access check is enabled', async () => {
    db.setClientAccessCheck('test-app', true);
    db.createClientAccessRule({
      client_id: 'test-app',
      rule_type: 'allow',
      subject_type: 'did',
      subject_value: 'did:plc:allowed',
      description: 'Allowed user',
    });

    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:allowed', handle: 'allowed.bsky.social' });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(true);
  });

  it('should deny non-matching DID when access check is enabled', async () => {
    db.setClientAccessCheck('test-app', true);
    db.createClientAccessRule({
      client_id: 'test-app',
      rule_type: 'allow',
      subject_type: 'did',
      subject_value: 'did:plc:allowed',
      description: 'Allowed user',
    });

    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:blocked', handle: 'blocked.bsky.social' });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(false);
  });

  it('should deny trumps allow', async () => {
    db.setClientAccessCheck('test-app', true);
    db.createClientAccessRule({
      client_id: 'test-app',
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: 'Allow all',
    });
    db.createClientAccessRule({
      client_id: 'test-app',
      rule_type: 'deny',
      subject_type: 'did',
      subject_value: 'did:plc:baduser',
      description: 'Block bad user',
    });

    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:baduser', handle: 'bad.bsky.social' });

    expect(res.status).toBe(200);
    expect(res.body.allowed).toBe(false);
  });

  it('should allow handle pattern matching', async () => {
    db.setClientAccessCheck('test-app', true);
    db.createClientAccessRule({
      client_id: 'test-app',
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: 'Arcnode users',
    });

    // Should allow matching handle
    const allowRes = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:arcuser', handle: 'bkb.arcnode.xyz' });
    expect(allowRes.body.allowed).toBe(true);

    // Should deny non-matching handle
    const denyRes = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:other', handle: 'other.bsky.social' });
    expect(denyRes.body.allowed).toBe(false);
  });

  // Rules don't leak between clients

  it('should not apply rules from one client to another', async () => {
    createTestClient(db, 'other-app', true);
    db.setClientAccessCheck('test-app', true);

    db.createClientAccessRule({
      client_id: 'other-app',
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: 'Allow all on other-app',
    });

    // test-app has access check on but no rules — should deny
    const res = await request(app)
      .post('/admin/clients/test-app/access/check')
      .set(authHeader())
      .send({ did: 'did:plc:anyone', handle: 'anyone.bsky.social' });

    expect(res.body.allowed).toBe(false);
  });
});
