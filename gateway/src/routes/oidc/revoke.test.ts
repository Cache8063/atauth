import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createRevokeRouter } from './revoke.js';
import { DatabaseService } from '../../services/database.js';

function createTestApp(db: DatabaseService) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createRevokeRouter(db);
  app.use('/oauth', router);

  return app;
}

function registerOIDCClient(db: DatabaseService, id = 'test-client', secret = 'my-secret') {
  const secretHash = crypto.createHash('sha256').update(secret).digest('hex');
  db.upsertOIDCClient({
    id,
    name: 'Test App',
    client_type: 'oidc',
    hmac_secret: crypto.randomBytes(32).toString('hex'),
    client_secret: secretHash,
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile'],
    token_ttl_seconds: 3600,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 86400,
    require_pkce: false,
    token_endpoint_auth_method: 'client_secret_basic',
  });
}

function createRefreshToken(db: DatabaseService, token: string, clientId = 'test-client') {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  db.saveRefreshToken({
    token_hash: tokenHash,
    client_id: clientId,
    did: 'did:plc:testuser',
    handle: 'test.bsky.social',
    scope: 'openid profile',
    expires_at: new Date(Date.now() + 86400 * 1000),
    family_id: `family-${Date.now()}`,
  });
  return tokenHash;
}

describe('POST /oauth/revoke', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
    registerOIDCClient(db);
  });

  afterEach(() => db.close());

  it('should return 200 for missing token (per RFC 7009)', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({});

    expect(res.status).toBe(200);
  });

  it('should revoke a refresh token', async () => {
    const rawToken = 'test-refresh-token-123';
    const tokenHash = createRefreshToken(db, rawToken);

    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: rawToken, client_id: 'test-client', client_secret: 'my-secret' });

    expect(res.status).toBe(200);

    // Token should be revoked in DB
    const stored = db.getRefreshToken(tokenHash);
    expect(stored?.revoked).toBe(true);
  });

  it('should accept client credentials via Basic auth', async () => {
    const rawToken = 'test-refresh-token-basic';
    createRefreshToken(db, rawToken);

    const credentials = Buffer.from('test-client:my-secret').toString('base64');
    const res = await request(app)
      .post('/oauth/revoke')
      .set('Authorization', `Basic ${credentials}`)
      .send({ token: rawToken });

    expect(res.status).toBe(200);
  });

  it('should return 401 for unknown client', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: 'some-token', client_id: 'nonexistent' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  it('should return 401 for wrong client secret', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: 'some-token', client_id: 'test-client', client_secret: 'wrong-secret' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
  });

  it('should return 401 for missing client secret when required', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: 'some-token', client_id: 'test-client' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_client');
    expect(res.body.error_description).toContain('Client authentication required');
  });

  it('should return 200 for unknown token (per RFC 7009)', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: 'nonexistent-token', client_id: 'test-client', client_secret: 'my-secret' });

    expect(res.status).toBe(200);
  });

  it('should return 200 for token belonging to different client', async () => {
    // Register a second client so FK constraint is satisfied
    registerOIDCClient(db, 'other-client', 'other-secret');

    const rawToken = 'other-client-token';
    createRefreshToken(db, rawToken, 'other-client');

    const res = await request(app)
      .post('/oauth/revoke')
      .send({ token: rawToken, client_id: 'test-client', client_secret: 'my-secret' });

    // Per RFC 7009, still returns 200
    expect(res.status).toBe(200);
  });

  it('should handle access token revocation (returns 200)', async () => {
    const res = await request(app)
      .post('/oauth/revoke')
      .send({
        token: 'some-access-token',
        token_type_hint: 'access_token',
        client_id: 'test-client',
        client_secret: 'my-secret',
      });

    // Access tokens can't be truly revoked (JWT), returns 200 per RFC
    expect(res.status).toBe(200);
  });
});
