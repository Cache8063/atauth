/**
 * OIDC Flow E2E Tests
 *
 * Tests the complete OIDC authorization code flow
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { DatabaseService } from '../src/services/database.js';
import { OIDCService } from '../src/services/oidc/index.js';
import { createOIDCRouter } from '../src/routes/oidc/index.js';
import { generateCodeVerifier, generateCodeChallenge } from '../src/services/oidc/pkce.js';
import type { OAuthService } from '../src/services/oauth.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

// Test configuration
const TEST_ISSUER = 'https://auth.test.example.com';
const TEST_CLIENT_ID = 'test-oidc-client';
const TEST_REDIRECT_URI = 'https://app.test.example.com/callback';
const TEST_DB_PATH = path.join(process.cwd(), 'test-oidc.db');

describe('OIDC Flow E2E', () => {
  let app: express.Application;
  let db: DatabaseService;
  let oidcService: OIDCService;
  let mockOAuthService: OAuthService;

  beforeAll(async () => {
    // Clean up any existing test database
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }

    // Initialize database
    db = new DatabaseService(TEST_DB_PATH);

    // Create mock OAuth service
    mockOAuthService = {
      generateAuthUrl: async () => ({
        url: 'https://pds.example.com/oauth/authorize?...',
        state: 'atproto-state-123',
      }),
      handleCallback: async () => ({
        did: 'did:plc:testuser123',
        handle: 'testuser.bsky.social',
      }),
    } as unknown as OAuthService;

    // Initialize OIDC service
    oidcService = new OIDCService(db, {
      issuer: TEST_ISSUER,
      keySecret: crypto.randomBytes(32).toString('hex'),
    });

    // Ensure signing key exists
    await oidcService.initialize();

    // Register test OIDC client
    db.upsertOIDCClient({
      id: TEST_CLIENT_ID,
      name: 'Test OIDC App',
      client_type: 'oidc',
      hmac_secret: crypto.randomBytes(32).toString('hex'),
      redirect_uris: [TEST_REDIRECT_URI],
      allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
      grant_types: ['authorization_code', 'refresh_token'],
      require_pkce: true,
      token_endpoint_auth_method: 'none',
      token_ttl_seconds: 3600,
      id_token_ttl_seconds: 3600,
      access_token_ttl_seconds: 3600,
      refresh_token_ttl_seconds: 604800,
    });

    // Create Express app
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Mount OIDC routes
    const { wellKnownRouter, oauthRouter } = createOIDCRouter(db, oidcService, mockOAuthService);
    app.use('/.well-known', wellKnownRouter);
    app.use('/oauth', oauthRouter);
  });

  afterAll(() => {
    // Clean up test database
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.unlinkSync(TEST_DB_PATH);
    }
  });

  describe('Discovery Endpoints', () => {
    it('should return valid OpenID configuration', async () => {
      const response = await request(app)
        .get('/.well-known/openid-configuration')
        .expect(200);

      expect(response.body.issuer).toBe(TEST_ISSUER);
      expect(response.body.authorization_endpoint).toBe(`${TEST_ISSUER}/oauth/authorize`);
      expect(response.body.token_endpoint).toBe(`${TEST_ISSUER}/oauth/token`);
      expect(response.body.userinfo_endpoint).toBe(`${TEST_ISSUER}/oauth/userinfo`);
      expect(response.body.jwks_uri).toBe(`${TEST_ISSUER}/.well-known/jwks.json`);
      expect(response.body.scopes_supported).toContain('openid');
      expect(response.body.response_types_supported).toContain('code');
      expect(response.body.grant_types_supported).toContain('authorization_code');
      expect(response.body.id_token_signing_alg_values_supported).toContain('ES256');
      expect(response.body.code_challenge_methods_supported).toContain('S256');
    });

    it('should return valid JWKS', async () => {
      const response = await request(app)
        .get('/.well-known/jwks.json')
        .expect(200);

      expect(response.body.keys).toBeDefined();
      expect(Array.isArray(response.body.keys)).toBe(true);
      expect(response.body.keys.length).toBeGreaterThan(0);

      const key = response.body.keys[0];
      expect(key.kty).toBeDefined();
      expect(key.alg).toBeDefined();
      expect(key.kid).toBeDefined();
      expect(key.use).toBe('sig');
    });
  });

  describe('Authorization Endpoint', () => {
    it('should require all mandatory parameters', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .expect(400);

      expect(response.body.error).toBe('invalid_request');
      expect(response.body.error_description).toContain('Missing required parameters');
    });

    it('should reject unsupported response_type', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'token',
          client_id: TEST_CLIENT_ID,
          redirect_uri: TEST_REDIRECT_URI,
          scope: 'openid',
          state: 'test-state',
        })
        .expect(400);

      expect(response.body.error).toBe('unsupported_response_type');
    });

    it('should reject unknown client_id', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'code',
          client_id: 'unknown-client',
          redirect_uri: TEST_REDIRECT_URI,
          scope: 'openid',
          state: 'test-state',
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_client');
    });

    it('should reject invalid redirect_uri', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'code',
          client_id: TEST_CLIENT_ID,
          redirect_uri: 'https://malicious.example.com/callback',
          scope: 'openid',
          state: 'test-state',
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_request');
      expect(response.body.error_description).toContain('redirect_uri');
    });

    it('should require PKCE code_challenge when client requires it', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'code',
          client_id: TEST_CLIENT_ID,
          redirect_uri: TEST_REDIRECT_URI,
          scope: 'openid',
          state: 'test-state',
        });

      // Should redirect with error
      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('error=invalid_request');
      expect(response.headers.location).toContain('code_challenge');
    });

    it('should return login page with valid parameters', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'code',
          client_id: TEST_CLIENT_ID,
          redirect_uri: TEST_REDIRECT_URI,
          scope: 'openid profile',
          state: 'test-state-123',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        })
        .expect(200);

      expect(response.type).toBe('text/html');
      expect(response.text).toContain('Sign in');
      expect(response.text).toContain('handle');
    });

    it('should redirect with error for missing openid scope', async () => {
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          response_type: 'code',
          client_id: TEST_CLIENT_ID,
          redirect_uri: TEST_REDIRECT_URI,
          scope: 'profile',
          state: 'test-state',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        });

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('error=invalid_scope');
      expect(response.headers.location).toContain('openid');
    });
  });

  describe('Token Endpoint', () => {
    let authorizationCode: string;
    let codeVerifier: string;

    beforeAll(async () => {
      // Create an authorization code for testing
      codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      authorizationCode = crypto.randomBytes(32).toString('base64url');

      db.saveAuthorizationCode({
        code: authorizationCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid profile',
        state: 'test-state',
        nonce: 'test-nonce',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:testuser123',
        handle: 'testuser.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });
    });

    it('should reject missing grant_type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          code: authorizationCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_request');
    });

    it('should reject unsupported grant_type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'password',
          code: authorizationCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
        })
        .expect(400);

      expect(response.body.error).toBe('unsupported_grant_type');
    });

    it('should reject invalid authorization code', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: 'invalid-code',
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: codeVerifier,
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_grant');
    });

    it('should reject invalid PKCE verifier', async () => {
      // Create a fresh auth code
      const freshCode = crypto.randomBytes(32).toString('base64url');
      const freshVerifier = generateCodeVerifier();
      const freshChallenge = generateCodeChallenge(freshVerifier);

      db.saveAuthorizationCode({
        code: freshCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:testuser123',
        handle: 'testuser.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });

      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: 'wrong-verifier-that-is-at-least-43-chars-long-for-validity',
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_grant');
      expect(response.body.error_description).toContain('code_verifier');
    });

    it('should exchange valid code for tokens', async () => {
      // Create a fresh auth code
      const freshCode = crypto.randomBytes(32).toString('base64url');
      const freshVerifier = generateCodeVerifier();
      const freshChallenge = generateCodeChallenge(freshVerifier);

      db.saveAuthorizationCode({
        code: freshCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid profile',
        nonce: 'test-nonce',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:testuser123',
        handle: 'testuser.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });

      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: freshVerifier,
        })
        .expect(200);

      expect(response.body.access_token).toBeDefined();
      expect(response.body.token_type).toBe('Bearer');
      expect(response.body.expires_in).toBeDefined();
      expect(response.body.id_token).toBeDefined();

      // Verify tokens are valid JWTs
      expect(response.body.access_token.split('.')).toHaveLength(3);
      expect(response.body.id_token.split('.')).toHaveLength(3);
    });

    it('should not allow code reuse', async () => {
      // Create a fresh auth code
      const freshCode = crypto.randomBytes(32).toString('base64url');
      const freshVerifier = generateCodeVerifier();
      const freshChallenge = generateCodeChallenge(freshVerifier);

      db.saveAuthorizationCode({
        code: freshCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:testuser123',
        handle: 'testuser.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });

      // First request should succeed
      await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: freshVerifier,
        })
        .expect(200);

      // Second request should fail
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: freshVerifier,
        })
        .expect(400);

      expect(response.body.error).toBe('invalid_grant');
    });
  });

  describe('UserInfo Endpoint', () => {
    let accessToken: string;

    beforeAll(async () => {
      // Get a valid access token
      const freshCode = crypto.randomBytes(32).toString('base64url');
      const freshVerifier = generateCodeVerifier();
      const freshChallenge = generateCodeChallenge(freshVerifier);

      db.saveAuthorizationCode({
        code: freshCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid profile',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:userinfotest',
        handle: 'userinfotest.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });

      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: freshVerifier,
        });

      accessToken = response.body.access_token;
    });

    it('should require authorization', async () => {
      const response = await request(app)
        .get('/oauth/userinfo')
        .expect(401);

      expect(response.body.error).toBe('invalid_token');
    });

    it('should reject invalid tokens', async () => {
      const response = await request(app)
        .get('/oauth/userinfo')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.error).toBe('invalid_token');
    });

    it('should return user info with valid token', async () => {
      const response = await request(app)
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      // sub is always returned
      expect(response.body.sub).toBe('did:plc:userinfotest');
      // Note: handle/preferred_username require user mapping which isn't set up in this test
    });

    it('should support POST method', async () => {
      const response = await request(app)
        .post('/oauth/userinfo')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body.sub).toBe('did:plc:userinfotest');
    });
  });

  describe('Token Revocation', () => {
    let accessToken: string;

    beforeAll(async () => {
      const freshCode = crypto.randomBytes(32).toString('base64url');
      const freshVerifier = generateCodeVerifier();
      const freshChallenge = generateCodeChallenge(freshVerifier);

      db.saveAuthorizationCode({
        code: freshCode,
        client_id: TEST_CLIENT_ID,
        redirect_uri: TEST_REDIRECT_URI,
        scope: 'openid',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256',
        did: 'did:plc:revoketest',
        handle: 'revoketest.bsky.social',
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600,
        used: false,
      });

      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshCode,
          redirect_uri: TEST_REDIRECT_URI,
          client_id: TEST_CLIENT_ID,
          code_verifier: freshVerifier,
        });

      accessToken = response.body.access_token;
    });

    it('should accept revocation request', async () => {
      await request(app)
        .post('/oauth/revoke')
        .send({
          token: accessToken,
          client_id: TEST_CLIENT_ID,
        })
        .expect(200);
    });

    it('should accept revocation of already revoked/invalid token', async () => {
      // Per RFC 7009, revocation endpoint should always return 200
      await request(app)
        .post('/oauth/revoke')
        .send({
          token: 'already-revoked-or-invalid',
          client_id: TEST_CLIENT_ID,
        })
        .expect(200);
    });
  });

  describe('End Session / Logout', () => {
    it('should handle logout request', async () => {
      const response = await request(app)
        .get('/oauth/end_session')
        .query({
          post_logout_redirect_uri: TEST_REDIRECT_URI,
          state: 'logout-state',
        });

      // Should redirect or return success
      expect([200, 302]).toContain(response.status);
    });
  });
});
