/**
 * User Profile Tests
 */
import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import crypto from 'crypto';
import { createUserProfileRoutes } from './user-profile.js';
import { DatabaseService } from '../services/database.js';
import { createSessionCookie, SESSION_COOKIE_NAME } from '../utils/proxy-auth.js';

const SESSION_SECRET = 'test-session-secret-for-profile-32chars';

function createTestApp(db: DatabaseService, passkeyService: any = null) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use((_req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
  });
  const router = createUserProfileRoutes(db, passkeyService, SESSION_SECRET);
  app.use('/auth/profile', router);
  return app;
}

function createProxySession(db: DatabaseService, did = 'did:plc:test123', handle = 'test.bsky.social') {
  const sessionId = crypto.randomBytes(16).toString('hex');
  db.createProxySession({
    id: sessionId,
    did,
    handle,
    created_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 604800,
    last_activity: Math.floor(Date.now() / 1000),
    user_agent: 'Mozilla/5.0 Chrome/120',
    ip_address: '127.0.0.1',
  });
  return sessionId;
}

function sessionCookie(sessionId: string): string {
  return `${SESSION_COOKIE_NAME}=${createSessionCookie(sessionId, SESSION_SECRET, 604800)}`;
}

describe('User Profile Routes', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  describe('GET /auth/profile', () => {
    it('redirects to login when no session cookie', async () => {
      const app = createTestApp(db);
      const res = await request(app).get('/auth/profile');
      expect(res.status).toBe(302);
      expect(res.headers.location).toContain('/auth/proxy/login');
    });

    it('redirects to login when session cookie is invalid', async () => {
      const app = createTestApp(db);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', `${SESSION_COOKIE_NAME}=invalid-cookie`);
      expect(res.status).toBe(302);
      expect(res.headers.location).toContain('/auth/proxy/login');
    });

    it('renders profile page when authenticated', async () => {
      const sessionId = createProxySession(db);
      const app = createTestApp(db);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).toContain('test.bsky.social');
      expect(res.text).toContain('did:plc:test123');
      expect(res.text).toContain('Active Sessions');
    });

    it('shows passkey section when passkeyService is provided', async () => {
      const sessionId = createProxySession(db);
      const mockPasskey = {
        listPasskeys: () => [],
      };
      const app = createTestApp(db, mockPasskey);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).toContain('Passkeys');
      expect(res.text).toContain('registerPasskeyBtn');
    });

    it('hides passkey section when passkeyService is null', async () => {
      const sessionId = createProxySession(db);
      const app = createTestApp(db, null);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).not.toContain('registerPasskeyBtn');
    });

    it('shows flash message from query param', async () => {
      const sessionId = createProxySession(db);
      const app = createTestApp(db);
      const res = await request(app)
        .get('/auth/profile?msg=Passkey+deleted')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).toContain('Passkey deleted');
    });

    it('shows registered passkeys', async () => {
      const sessionId = createProxySession(db);
      const mockPasskey = {
        listPasskeys: () => [
          { id: 'pk-1', name: 'My Yubikey', device_type: 'cross-platform', backed_up: false, last_used_at: null, created_at: '2026-01-01T00:00:00Z' },
        ],
      };
      const app = createTestApp(db, mockPasskey);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).toContain('My Yubikey');
      expect(res.text).toContain('cross-platform');
    });

    it('marks current session in session list', async () => {
      const sessionId = createProxySession(db);
      const app = createTestApp(db);
      const res = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      expect(res.status).toBe(200);
      expect(res.text).toContain('current-session');
      expect(res.text).toContain('current');
    });
  });

  describe('POST /auth/profile/passkey/delete', () => {
    it('rejects without CSRF token', async () => {
      const sessionId = createProxySession(db);
      const mockPasskey = { deletePasskey: () => true };
      const app = createTestApp(db, mockPasskey);
      const res = await request(app)
        .post('/auth/profile/passkey/delete')
        .set('Cookie', sessionCookie(sessionId))
        .send({ passkey_id: 'pk-1' });
      expect(res.status).toBe(403);
    });

    it('redirects to login without session', async () => {
      const app = createTestApp(db);
      const res = await request(app)
        .post('/auth/profile/passkey/delete')
        .send({ passkey_id: 'pk-1', _csrf: 'invalid' });
      expect(res.status).toBe(302);
      expect(res.headers.location).toBe('/auth/profile');
    });
  });

  describe('POST /auth/profile/session/revoke', () => {
    it('prevents revoking current session', async () => {
      const sessionId = createProxySession(db);
      // Need a second session so the page has at least one revoke form with a CSRF token
      createProxySession(db);

      const app = createTestApp(db);
      const page = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);
      expect(csrfMatch).toBeTruthy();

      const res = await request(app)
        .post('/auth/profile/session/revoke')
        .set('Cookie', sessionCookie(sessionId))
        .type('form')
        .send({ session_id: sessionId, _csrf: csrfMatch![1] });
      expect(res.status).toBe(302);
      expect(res.headers.location).toContain('Cannot+revoke+current+session');
    });

    it('revokes other session successfully', async () => {
      const sessionId = createProxySession(db);
      const otherSessionId = createProxySession(db);

      const app = createTestApp(db);
      const page = await request(app)
        .get('/auth/profile')
        .set('Cookie', sessionCookie(sessionId));
      const csrfMatch = page.text.match(/name="_csrf" value="([^"]+)"/);

      const res = await request(app)
        .post('/auth/profile/session/revoke')
        .set('Cookie', sessionCookie(sessionId))
        .type('form')
        .send({ session_id: otherSessionId, _csrf: csrfMatch![1] });
      expect(res.status).toBe(302);
      expect(res.headers.location).toContain('Session+revoked');

      // Verify it was actually deleted
      const deletedSession = db.getProxySession(otherSessionId);
      expect(deletedSession).toBeNull();
    });
  });
});
