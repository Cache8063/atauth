/**
 * Admin Routes
 *
 * Application registration and management endpoints.
 * Now includes OIDC client, session, and key management.
 * Express 5 automatically forwards async errors to the error handler.
 */

import crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import { DatabaseService } from '../services/database.js';
import { generateHmacSecret } from '../utils/hmac.js';
import { httpError } from '../utils/errors.js';
import { checkAccess } from '../utils/access-check.js';
import { parseCookies, ADMIN_COOKIE_NAME, createAdminCookie, verifyAdminCookie } from '../utils/proxy-auth.js';
import { createAdminDashboardRoutes } from './admin-dashboard.js';
import type { OIDCService } from '../services/oidc/index.js';
import type { PasskeyService } from '../services/passkey.js';
import type { MFAService } from '../services/mfa.js';

/**
 * Constant-time string comparison to prevent timing attacks.
 */
function secureCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  // Prevent length-based timing attacks by always comparing fixed-length hashes
  const hashA = crypto.createHash('sha256').update(bufA).digest();
  const hashB = crypto.createHash('sha256').update(bufB).digest();

  return crypto.timingSafeEqual(hashA, hashB);
}

export function createAdminRoutes(
  db: DatabaseService,
  adminToken?: string,
  oidcService?: OIDCService | null,
  passkeyService?: PasskeyService | null,
  mfaService?: MFAService | null,
  sessionSecret?: string,
): Router {
  const router = Router();

  const ADMIN_COOKIE_TTL = 86400; // 24 hours

  /**
   * Admin authentication middleware.
   * Accepts EITHER a Bearer token in the Authorization header
   * OR a valid _atauth_admin cookie (for dashboard sessions).
   */
  const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
    if (!adminToken) {
      throw httpError.forbidden('admin_disabled', 'Admin endpoints are disabled (set ADMIN_TOKEN)');
    }

    // Check Bearer token first
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      if (!secureCompare(token, adminToken)) {
        throw httpError.forbidden('invalid_token', 'Invalid admin token');
      }
      return next();
    }

    // Check admin cookie
    if (sessionSecret) {
      const cookies = parseCookies(req.headers.cookie);
      const adminCookieValue = cookies[ADMIN_COOKIE_NAME];
      if (adminCookieValue && verifyAdminCookie(adminCookieValue, sessionSecret)) {
        return next();
      }
    }

    // If this looks like a browser request (Accept: text/html), redirect to login
    if (req.accepts('html') && !req.accepts('json')) {
      return res.redirect('/admin/login');
    }

    throw httpError.unauthorized('missing_auth', 'Authorization required');
  };

  // ===== Admin Login/Logout (no auth required) =====

  /**
   * GET /admin/login
   * Render the admin login page.
   */
  router.get('/login', (_req: Request, res: Response) => {
    if (!adminToken) {
      return res.status(403).send('Admin endpoints are disabled');
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderLoginPage());
  });

  /**
   * POST /admin/login
   * Validate admin token and set session cookie.
   */
  router.post('/login', (req: Request, res: Response) => {
    if (!adminToken) {
      throw httpError.forbidden('admin_disabled', 'Admin endpoints are disabled');
    }

    const { token } = req.body;
    if (!token || !secureCompare(token, adminToken)) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(401).send(renderLoginPage('Invalid admin token'));
    }

    if (!sessionSecret) {
      throw httpError.internalServerError('config_error', 'Session secret not configured');
    }

    const cookieValue = createAdminCookie(sessionSecret, ADMIN_COOKIE_TTL);
    res.setHeader('Set-Cookie', `${ADMIN_COOKIE_NAME}=${cookieValue}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${ADMIN_COOKIE_TTL}`);
    res.redirect('/admin/dashboard');
  });

  /**
   * GET /admin/logout
   * Clear admin session cookie and redirect to login.
   */
  router.get('/logout', (_req: Request, res: Response) => {
    res.setHeader('Set-Cookie', `${ADMIN_COOKIE_NAME}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    res.redirect('/admin/login');
  });

  // ===== Dashboard (server-rendered HTML) =====
  if (sessionSecret) {
    const dashboardRouter = createAdminDashboardRoutes(db, sessionSecret);
    router.use('/dashboard', requireAdmin, dashboardRouter);
  }

  /**
   * POST /admin/apps
   * Register a new application
   *
   * Body:
   * - id: Unique app identifier
   * - name: Display name
   * - token_ttl_seconds: Token lifetime (default 3600)
   * - callback_url: OAuth callback URL
   */
  router.post('/apps', requireAdmin, async (req: Request, res: Response) => {
    const { id, name, token_ttl_seconds, callback_url } = req.body;

    if (!id || !name) {
      throw httpError.badRequest('missing_params', 'id and name are required');
    }

    const existing = db.getApp(id);
    if (existing) {
      throw httpError.conflict('app_exists', `Application '${id}' already exists`);
    }

    const hmac_secret = generateHmacSecret();

    db.upsertApp({
      id,
      name,
      hmac_secret,
      token_ttl_seconds: token_ttl_seconds || 3600,
      callback_url,
    });

    res.status(201).json({
      id,
      name,
      hmac_secret,
      token_ttl_seconds: token_ttl_seconds || 3600,
      callback_url,
      message: 'Application registered. Store the hmac_secret securely!',
    });
  });

  /**
   * GET /admin/apps/:id
   * Get application configuration (without secret)
   */
  router.get('/apps/:id', requireAdmin, async (req: Request, res: Response) => {
    const app = db.getApp(req.params.id);
    if (!app) {
      throw httpError.notFound('app_not_found', `Application '${req.params.id}' not found`);
    }

    res.json({
      id: app.id,
      name: app.name,
      token_ttl_seconds: app.token_ttl_seconds,
      callback_url: app.callback_url,
    });
  });

  /**
   * PUT /admin/apps/:id
   * Update application configuration
   */
  router.put('/apps/:id', requireAdmin, async (req: Request, res: Response) => {
    const existing = db.getApp(req.params.id);
    if (!existing) {
      throw httpError.notFound('app_not_found', `Application '${req.params.id}' not found`);
    }

    const { name, token_ttl_seconds, callback_url, rotate_secret } = req.body;

    const updated = {
      id: req.params.id,
      name: name || existing.name,
      hmac_secret: rotate_secret ? generateHmacSecret() : existing.hmac_secret,
      token_ttl_seconds: token_ttl_seconds || existing.token_ttl_seconds,
      callback_url: callback_url !== undefined ? callback_url : existing.callback_url,
    };

    db.upsertApp(updated);

    const response: Record<string, unknown> = {
      id: updated.id,
      name: updated.name,
      token_ttl_seconds: updated.token_ttl_seconds,
      callback_url: updated.callback_url,
    };

    if (rotate_secret) {
      response.hmac_secret = updated.hmac_secret;
      response.message = 'Secret rotated. Update your backend configuration!';
    }

    res.json(response);
  });

  /**
   * POST /admin/cleanup
   * Clean up expired sessions and OAuth states
   */
  router.post('/cleanup', requireAdmin, async (_req: Request, res: Response) => {
    const statesDeleted = db.cleanupOldOAuthStates();
    const sessionsDeleted = db.cleanupExpiredSessions();
    const authCodesDeleted = db.cleanupExpiredAuthorizationCodes();
    const refreshTokensDeleted = db.cleanupExpiredRefreshTokens();
    const emailCodesDeleted = db.cleanupExpiredEmailVerificationCodes();

    res.json({
      oauth_states_deleted: statesDeleted,
      sessions_deleted: sessionsDeleted,
      authorization_codes_deleted: authCodesDeleted,
      refresh_tokens_deleted: refreshTokensDeleted,
      email_codes_deleted: emailCodesDeleted,
    });
  });

  // ===== OIDC Client Management =====

  /**
   * GET /admin/oidc/clients
   * List all OIDC clients
   */
  router.get('/oidc/clients', requireAdmin, async (_req: Request, res: Response) => {
    const clients = db.getAllOIDCClients();
    res.json({
      clients: clients.map(c => ({
        id: c.id,
        name: c.name,
        client_type: c.client_type,
        redirect_uris: c.redirect_uris,
        grant_types: c.grant_types,
        allowed_scopes: c.allowed_scopes,
        require_pkce: c.require_pkce,
        token_endpoint_auth_method: c.token_endpoint_auth_method,
        created_at: c.created_at.toISOString(),
      })),
    });
  });

  /**
   * POST /admin/oidc/clients
   * Create a new OIDC client
   */
  router.post('/oidc/clients', requireAdmin, async (req: Request, res: Response) => {
    const {
      id,
      name,
      redirect_uris,
      grant_types,
      allowed_scopes,
      require_pkce,
      token_endpoint_auth_method,
      id_token_ttl_seconds,
      access_token_ttl_seconds,
      refresh_token_ttl_seconds,
    } = req.body;

    if (!id || !name) {
      throw httpError.badRequest('missing_params', 'id and name are required');
    }

    const existing = db.getOIDCClient(id);
    if (existing) {
      throw httpError.conflict('client_exists', `OIDC client '${id}' already exists`);
    }

    // Generate client secret
    const clientSecret = crypto.randomBytes(32).toString('hex');
    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    // Create app entry with OIDC configuration
    db.upsertApp({
      id,
      name,
      hmac_secret: generateHmacSecret(),
      token_ttl_seconds: access_token_ttl_seconds || 3600,
      callback_url: redirect_uris?.[0],
    });

    // Update with OIDC-specific fields
    db.updateOIDCClient(id, {
      client_type: 'oidc',
      client_secret: clientSecretHash,
      redirect_uris: redirect_uris || [],
      grant_types: grant_types || ['authorization_code'],
      allowed_scopes: allowed_scopes || ['openid'],
      require_pkce: require_pkce ?? true,
      token_endpoint_auth_method: token_endpoint_auth_method || 'client_secret_basic',
      id_token_ttl_seconds: id_token_ttl_seconds || 3600,
      access_token_ttl_seconds: access_token_ttl_seconds || 3600,
      refresh_token_ttl_seconds: refresh_token_ttl_seconds || 604800,
    });

    res.status(201).json({
      id,
      name,
      client_secret: clientSecret, // Only shown once!
      redirect_uris: redirect_uris || [],
      grant_types: grant_types || ['authorization_code'],
      allowed_scopes: allowed_scopes || ['openid'],
      require_pkce: require_pkce ?? true,
      message: 'OIDC client created. Store the client_secret securely!',
    });
  });

  /**
   * GET /admin/oidc/clients/:id
   * Get OIDC client details
   */
  router.get('/oidc/clients/:id', requireAdmin, async (req: Request, res: Response) => {
    const client = db.getOIDCClient(req.params.id);
    if (!client) {
      throw httpError.notFound('client_not_found', `OIDC client '${req.params.id}' not found`);
    }

    res.json({
      id: client.id,
      name: client.name,
      client_type: client.client_type,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      allowed_scopes: client.allowed_scopes,
      require_pkce: client.require_pkce,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      id_token_ttl_seconds: client.id_token_ttl_seconds,
      access_token_ttl_seconds: client.access_token_ttl_seconds,
      refresh_token_ttl_seconds: client.refresh_token_ttl_seconds,
      created_at: client.created_at.toISOString(),
    });
  });

  /**
   * PUT /admin/oidc/clients/:id
   * Update OIDC client
   */
  router.put('/oidc/clients/:id', requireAdmin, async (req: Request, res: Response) => {
    const existing = db.getOIDCClient(req.params.id);
    if (!existing) {
      throw httpError.notFound('client_not_found', `OIDC client '${req.params.id}' not found`);
    }

    const {
      name,
      redirect_uris,
      grant_types,
      allowed_scopes,
      require_pkce,
      token_endpoint_auth_method,
      id_token_ttl_seconds,
      access_token_ttl_seconds,
      refresh_token_ttl_seconds,
    } = req.body;

    db.updateOIDCClient(req.params.id, {
      redirect_uris: redirect_uris ?? existing.redirect_uris,
      grant_types: grant_types ?? existing.grant_types,
      allowed_scopes: allowed_scopes ?? existing.allowed_scopes,
      require_pkce: require_pkce ?? existing.require_pkce,
      token_endpoint_auth_method: token_endpoint_auth_method ?? existing.token_endpoint_auth_method,
      id_token_ttl_seconds: id_token_ttl_seconds ?? existing.id_token_ttl_seconds,
      access_token_ttl_seconds: access_token_ttl_seconds ?? existing.access_token_ttl_seconds,
      refresh_token_ttl_seconds: refresh_token_ttl_seconds ?? existing.refresh_token_ttl_seconds,
    });

    // Update app name if provided
    if (name) {
      const app = db.getApp(req.params.id);
      if (app) {
        db.upsertApp({ ...app, name });
      }
    }

    res.json({
      id: req.params.id,
      message: 'OIDC client updated',
    });
  });

  /**
   * DELETE /admin/oidc/clients/:id
   * Delete OIDC client
   */
  router.delete('/oidc/clients/:id', requireAdmin, async (req: Request, res: Response) => {
    const existing = db.getOIDCClient(req.params.id);
    if (!existing) {
      throw httpError.notFound('client_not_found', `OIDC client '${req.params.id}' not found`);
    }

    db.deleteApp(req.params.id);

    res.json({
      message: 'OIDC client deleted',
    });
  });

  /**
   * POST /admin/oidc/clients/:id/rotate-secret
   * Rotate OIDC client secret
   */
  router.post('/oidc/clients/:id/rotate-secret', requireAdmin, async (req: Request, res: Response) => {
    const existing = db.getOIDCClient(req.params.id);
    if (!existing) {
      throw httpError.notFound('client_not_found', `OIDC client '${req.params.id}' not found`);
    }

    const clientSecret = crypto.randomBytes(32).toString('hex');
    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    db.updateOIDCClientSecret(req.params.id, clientSecretHash);

    res.json({
      id: req.params.id,
      client_secret: clientSecret,
      message: 'Client secret rotated. Update your application configuration!',
    });
  });

  // ===== Session Management =====

  /**
   * GET /admin/sessions
   * List active sessions with optional filters
   */
  router.get('/sessions', requireAdmin, async (req: Request, res: Response) => {
    const { app_id, did, limit } = req.query;
    const sessions = db.getAllActiveSessions(
      app_id as string | undefined,
      did as string | undefined,
      limit ? parseInt(limit as string, 10) : 100
    );

    res.json({
      sessions: sessions.map(s => ({
        id: s.id,
        did: s.did,
        handle: s.handle,
        app_id: s.app_id,
        created_at: s.created_at.toISOString(),
        expires_at: s.expires_at.toISOString(),
        connection_state: s.connection_state,
        last_activity: s.last_activity?.toISOString(),
      })),
    });
  });

  /**
   * DELETE /admin/sessions/:id
   * Revoke a specific session
   */
  router.delete('/sessions/:id', requireAdmin, async (req: Request, res: Response) => {
    db.deleteSession(req.params.id);
    res.json({ message: 'Session revoked' });
  });

  /**
   * POST /admin/sessions/revoke-all
   * Revoke all sessions for a user/app combination
   */
  router.post('/sessions/revoke-all', requireAdmin, async (req: Request, res: Response) => {
    const { did, app_id } = req.body;
    if (!did) {
      throw httpError.badRequest('missing_params', 'did is required');
    }

    const count = db.revokeAllSessionsForUser(did, app_id);
    res.json({
      sessions_revoked: count,
    });
  });

  // ===== Key Management =====

  /**
   * GET /admin/keys
   * List signing keys (if OIDC service is available)
   */
  router.get('/keys', requireAdmin, async (_req: Request, res: Response) => {
    if (!oidcService) {
      throw httpError.badRequest('oidc_disabled', 'OIDC is not enabled');
    }

    const keys = db.getActiveOIDCKeys();
    res.json({
      keys: keys.map(k => ({
        kid: k.kid,
        algorithm: k.algorithm,
        is_active: k.is_active,
        use_for_signing: k.use_for_signing,
        created_at: k.created_at.toISOString(),
        expires_at: k.expires_at?.toISOString(),
      })),
    });
  });

  /**
   * POST /admin/keys/rotate
   * Rotate signing keys
   */
  router.post('/keys/rotate', requireAdmin, async (req: Request, res: Response) => {
    if (!oidcService) {
      throw httpError.badRequest('oidc_disabled', 'OIDC is not enabled');
    }

    const { algorithm } = req.body;
    await oidcService.keyManager.rotateKeys(algorithm || 'ES256');

    res.json({
      message: 'Signing key rotated',
    });
  });

  // ===== User Management =====

  /**
   * GET /admin/users/:did
   * Get user details including MFA status and passkeys
   */
  router.get('/users/:did', requireAdmin, async (req: Request, res: Response) => {
    const { did } = req.params;

    const passkeys = passkeyService?.listPasskeys(did) || [];
    const mfaStatus = mfaService?.getMFAStatus(did, passkeys.length) || {
      totp_enabled: false,
      passkey_count: passkeys.length,
      backup_codes_remaining: 0,
    };
    const emails = db.getUserEmails(did);

    res.json({
      did,
      mfa: mfaStatus,
      passkeys: passkeys.map(p => ({
        id: p.id,
        name: p.name,
        device_type: p.device_type,
        backed_up: p.backed_up,
        created_at: p.created_at,
        last_used_at: p.last_used_at,
      })),
      emails: emails.map(e => ({
        email: e.email,
        verified: e.verified,
        is_primary: e.is_primary,
        created_at: e.created_at.toISOString(),
      })),
    });
  });

  /**
   * DELETE /admin/users/:did/mfa
   * Reset MFA for a user (admin override)
   */
  router.delete('/users/:did/mfa', requireAdmin, async (req: Request, res: Response) => {
    const { did } = req.params;

    if (mfaService) {
      mfaService.disableTOTP(did);
    }

    res.json({
      message: 'MFA disabled for user',
    });
  });

  /**
   * DELETE /admin/users/:did/passkeys/:passkeyId
   * Delete a passkey for a user (admin override)
   */
  router.delete('/users/:did/passkeys/:passkeyId', requireAdmin, async (req: Request, res: Response) => {
    const { did, passkeyId } = req.params;

    if (passkeyService) {
      const success = passkeyService.deletePasskey(did, passkeyId);
      if (!success) {
        throw httpError.notFound('passkey_not_found', 'Passkey not found');
      }
    }

    res.json({
      message: 'Passkey deleted',
    });
  });

  // ===== Forward-Auth Proxy Management =====

  /**
   * GET /admin/proxy/origins
   * List allowed origins for forward-auth
   */
  router.get('/proxy/origins', requireAdmin, async (_req: Request, res: Response) => {
    const origins = db.listProxyAllowedOrigins();
    res.json({ origins });
  });

  /**
   * POST /admin/proxy/origins
   * Add an allowed origin for forward-auth
   *
   * Body:
   * - origin: Full origin URL (e.g. "https://search.example.com")
   * - name: Display name (e.g. "SearXNG")
   */
  router.post('/proxy/origins', requireAdmin, async (req: Request, res: Response) => {
    const { origin, name } = req.body;

    if (!origin || !name) {
      throw httpError.badRequest('missing_params', 'origin and name are required');
    }

    // Validate origin format
    try {
      const parsed = new URL(origin);
      if (parsed.origin !== origin) {
        throw httpError.badRequest('invalid_origin', 'origin must be a valid URL origin (scheme://host[:port])');
      }
    } catch (e) {
      if (e instanceof Error && 'statusCode' in e) throw e;
      throw httpError.badRequest('invalid_origin', 'origin must be a valid URL');
    }

    try {
      const created = db.addProxyAllowedOrigin(origin, name);
      res.status(201).json(created);
    } catch (e) {
      const msg = e instanceof Error ? e.message : '';
      if (msg.includes('UNIQUE constraint')) {
        throw httpError.conflict('origin_exists', `Origin '${origin}' already exists`);
      }
      throw e;
    }
  });

  /**
   * DELETE /admin/proxy/origins/:id
   * Remove an allowed origin
   */
  router.delete('/proxy/origins/:id', requireAdmin, async (req: Request, res: Response) => {
    db.removeProxyAllowedOrigin(parseInt(req.params.id, 10));
    res.json({ message: 'Origin removed' });
  });

  /**
   * GET /admin/proxy/sessions
   * List active proxy sessions
   */
  router.get('/proxy/sessions', requireAdmin, async (req: Request, res: Response) => {
    const { did, limit } = req.query;
    const sessions = db.getAllProxySessions(
      did as string | undefined,
      limit ? parseInt(limit as string, 10) : 100,
    );
    res.json({ sessions });
  });

  /**
   * DELETE /admin/proxy/sessions/:id
   * Revoke a proxy session
   */
  router.delete('/proxy/sessions/:id', requireAdmin, async (req: Request, res: Response) => {
    db.deleteProxySession(req.params.id);
    res.json({ message: 'Proxy session revoked' });
  });

  // ===== Forward-Auth Access Rules =====

  /**
   * GET /admin/proxy/access
   * List access rules. Optional ?origin_id=N filter.
   */
  router.get('/proxy/access', requireAdmin, async (req: Request, res: Response) => {
    const originIdParam = req.query.origin_id;
    let rules;
    if (originIdParam !== undefined) {
      const originId = parseInt(originIdParam as string, 10);
      rules = db.listProxyAccessRules(originId);
    } else {
      rules = db.listProxyAccessRules();
    }
    res.json({ rules });
  });

  /**
   * POST /admin/proxy/access
   * Create an access rule.
   *
   * Body:
   * - origin_id: number | null (null = global rule)
   * - rule_type: "allow" | "deny"
   * - subject_type: "did" | "handle_pattern"
   * - subject_value: string (DID or pattern like "*.example.com")
   * - description: string (optional label)
   */
  router.post('/proxy/access', requireAdmin, async (req: Request, res: Response) => {
    const { origin_id, rule_type, subject_type, subject_value, description } = req.body;

    if (!rule_type || !subject_type || !subject_value) {
      throw httpError.badRequest('missing_params', 'rule_type, subject_type, and subject_value are required');
    }

    if (!['allow', 'deny'].includes(rule_type)) {
      throw httpError.badRequest('invalid_rule_type', 'rule_type must be "allow" or "deny"');
    }

    if (!['did', 'handle_pattern'].includes(subject_type)) {
      throw httpError.badRequest('invalid_subject_type', 'subject_type must be "did" or "handle_pattern"');
    }

    if (subject_type === 'did' && !subject_value.startsWith('did:')) {
      throw httpError.badRequest('invalid_did', 'DID must start with "did:"');
    }

    if (subject_type === 'handle_pattern') {
      if (subject_value !== '*' && !subject_value.match(/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/)) {
        throw httpError.badRequest('invalid_pattern', 'Handle pattern must be "*", "*.domain", or an exact handle');
      }
    }

    if (origin_id !== null && origin_id !== undefined) {
      const origins = db.listProxyAllowedOrigins();
      if (!origins.some(o => o.id === origin_id)) {
        throw httpError.notFound('origin_not_found', `Origin with id ${origin_id} not found`);
      }
    }

    const rule = db.createProxyAccessRule({
      origin_id: origin_id ?? null,
      rule_type,
      subject_type,
      subject_value,
      description: description || null,
    });

    res.status(201).json(rule);
  });

  /**
   * DELETE /admin/proxy/access/:id
   * Delete an access rule.
   */
  router.delete('/proxy/access/:id', requireAdmin, async (req: Request, res: Response) => {
    db.deleteProxyAccessRule(parseInt(req.params.id, 10));
    res.json({ message: 'Access rule deleted' });
  });

  /**
   * POST /admin/proxy/access/check
   * Test if a DID/handle would be allowed for an origin.
   * Admin debugging tool -- does not modify state.
   */
  router.post('/proxy/access/check', requireAdmin, async (req: Request, res: Response) => {
    const { did, handle, origin_id } = req.body;

    if (!did || !handle || origin_id === undefined) {
      throw httpError.badRequest('missing_params', 'did, handle, and origin_id are required');
    }

    const rules = db.getProxyAccessRulesForCheck(origin_id);
    const totalRules = rules.denyRules.length + rules.originAllowRules.length + rules.globalAllowRules.length;

    if (totalRules === 0) {
      return res.json({
        allowed: true,
        matched_rule_id: null,
        reason: 'No access rules configured (open access)',
      });
    }

    const result = checkAccess(did, handle, rules);
    res.json(result);
  });

  // ===== Stats =====

  /**
   * GET /admin/stats
   * Get system statistics
   */
  router.get('/stats', requireAdmin, async (_req: Request, res: Response) => {
    const stats = db.getStats();
    res.json(stats);
  });

  return router;
}

// ===== Admin Login Page Template =====

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderLoginPage(error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ATAuth Admin Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #e2e8f0;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
      color: #f1f5f9;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 0.875rem;
      margin-bottom: 1.5rem;
    }
    .error {
      background: #451a22;
      border: 1px solid #7f1d2f;
      color: #fca5a5;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      font-size: 0.875rem;
      margin-bottom: 1rem;
    }
    label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 0.5rem;
    }
    input[type="password"] {
      width: 100%;
      padding: 0.625rem 0.75rem;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus {
      border-color: #3b82f6;
    }
    button {
      width: 100%;
      margin-top: 1rem;
      padding: 0.625rem;
      background: #3b82f6;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ATAuth Admin</h1>
    <p class="subtitle">Enter your admin token to continue</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    <form method="POST" action="/admin/login">
      <label for="token">Admin Token</label>
      <input type="password" id="token" name="token" required autocomplete="current-password" autofocus>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`;
}
