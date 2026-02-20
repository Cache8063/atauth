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
  mfaService?: MFAService | null
): Router {
  const router = Router();

  const requireAdmin = (req: Request, _res: Response, next: NextFunction) => {
    if (!adminToken) {
      throw httpError.forbidden('admin_disabled', 'Admin endpoints are disabled (set ADMIN_TOKEN)');
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw httpError.unauthorized('missing_auth', 'Authorization header required');
    }

    const token = authHeader.substring(7);
    if (!secureCompare(token, adminToken)) {
      throw httpError.forbidden('invalid_token', 'Invalid admin token');
    }

    next();
  };

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
   * - origin: Full origin URL (e.g. "https://search.arcnode.xyz")
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
