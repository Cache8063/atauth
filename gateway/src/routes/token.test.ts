import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createTokenRoutes } from './token.js';
import { DatabaseService } from '../services/database.js';
import { createGatewayToken } from '../utils/hmac.js';

const TEST_SECRET = crypto.randomBytes(32).toString('hex');

function createTestApp(db: DatabaseService) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const router = createTokenRoutes(db);
  app.use('/token', router);

  app.use((err: any, _req: any, res: any, _next: any) => {
    const status = err.status || err.statusCode || 500;
    res.status(status).json({
      error: err.code || 'server_error',
      message: err.message,
    });
  });

  return app;
}

function registerApp(db: DatabaseService, id = 'test-app') {
  db.upsertApp({
    id,
    name: 'Test App',
    hmac_secret: TEST_SECRET,
    token_ttl_seconds: 3600,
    callback_url: 'https://app.example.com/callback',
  });
}

describe('POST /token/verify', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
    registerApp(db);
  });

  afterEach(() => db.close());

  it('should return valid: true for a valid token', async () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'test.bsky.social', user_id: 1, app_id: 'test-app' },
      TEST_SECRET,
    );

    const res = await request(app)
      .post('/token/verify')
      .send({ token, app_id: 'test-app' });

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.payload.did).toBe('did:plc:test');
    expect(res.body.payload.handle).toBe('test.bsky.social');
    expect(res.body.payload.user_id).toBe(1);
    expect(res.body.payload.app_id).toBe('test-app');
  });

  it('should return 400 for missing token', async () => {
    const res = await request(app)
      .post('/token/verify')
      .send({ app_id: 'test-app' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_params');
  });

  it('should return 400 for missing app_id', async () => {
    const res = await request(app)
      .post('/token/verify')
      .send({ token: 'some-token' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_params');
  });

  it('should return 404 for unregistered app', async () => {
    const res = await request(app)
      .post('/token/verify')
      .send({ token: 'some-token', app_id: 'nonexistent' });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('app_not_found');
  });

  it('should return 401 for an invalid token', async () => {
    const res = await request(app)
      .post('/token/verify')
      .send({ token: 'garbage.token', app_id: 'test-app' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });

  it('should return 401 for token issued for a different app', async () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'other-app' },
      TEST_SECRET,
    );

    const res = await request(app)
      .post('/token/verify')
      .send({ token, app_id: 'test-app' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('app_mismatch');
  });
});

describe('GET /token/info', () => {
  let db: DatabaseService;
  let app: express.Application;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    app = createTestApp(db);
    registerApp(db);
  });

  afterEach(() => db.close());

  it('should return token info with remaining_seconds', async () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'test.bsky.social', user_id: 5, app_id: 'test-app' },
      TEST_SECRET,
      3600,
    );

    const res = await request(app)
      .get('/token/info')
      .query({ token, app_id: 'test-app' });

    expect(res.status).toBe(200);
    expect(res.body.did).toBe('did:plc:test');
    expect(res.body.handle).toBe('test.bsky.social');
    expect(res.body.user_id).toBe(5);
    expect(res.body.app_id).toBe('test-app');
    expect(res.body.issued_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(res.body.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(res.body.remaining_seconds).toBeGreaterThan(3500);
  });

  it('should return 400 for missing query params', async () => {
    const res = await request(app).get('/token/info');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing_params');
  });

  it('should return 404 for unregistered app', async () => {
    const res = await request(app)
      .get('/token/info')
      .query({ token: 'x', app_id: 'nonexistent' });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('app_not_found');
  });

  it('should return 401 for an invalid token', async () => {
    const res = await request(app)
      .get('/token/info')
      .query({ token: 'invalid.token', app_id: 'test-app' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });
});
