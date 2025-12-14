/**
 * Auth Routes
 *
 * OAuth flow endpoints for AT Protocol authentication
 */

import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { OAuthService } from '../services/oauth.js';
import { DatabaseService } from '../services/database.js';
import { createGatewayToken } from '../utils/hmac.js';
import { internalError } from '../utils/errors.js';

/**
 * Validate a redirect URI against an app's allowed callback URL.
 *
 * SECURITY: Prevents open redirect attacks by ensuring the redirect_uri
 * matches the app's registered callback_url origin (or starts with it).
 *
 * @param redirectUri - The redirect URI from the request
 * @param allowedUrl - The app's registered callback_url
 * @returns true if valid, false otherwise
 */
function isValidRedirectUri(redirectUri: string, allowedUrl: string | undefined): boolean {
  if (!redirectUri) return false;

  try {
    const redirect = new URL(redirectUri);
    const protocol = redirect.protocol;

    // Only allow HTTPS in production (or HTTP for localhost dev)
    const isLocalhost = redirect.hostname === 'localhost' || redirect.hostname === '127.0.0.1';
    if (protocol !== 'https:' && !(protocol === 'http:' && isLocalhost)) {
      return false;
    }

    // If app has no registered callback, reject external redirects
    if (!allowedUrl) {
      return false;
    }

    const allowed = new URL(allowedUrl);

    // Must match origin (scheme + host + port)
    if (redirect.origin !== allowed.origin) {
      return false;
    }

    // Redirect path must start with allowed path (for path restrictions)
    // This allows callback_url="https://app.com/auth" to accept
    // redirects to "https://app.com/auth/callback" but not "https://app.com/admin"
    if (allowed.pathname !== '/' && !redirect.pathname.startsWith(allowed.pathname)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export function createAuthRoutes(
  db: DatabaseService,
  oauth: OAuthService
): Router {
  const router = Router();

  /**
   * POST /auth/init
   * Start OAuth flow for an application
   *
   * Body:
   * - app_id: The application identifier (required)
   * - handle: The user's AT Protocol handle (required)
   * - redirect_uri: Where to redirect after auth (optional)
   */
  router.post('/init', async (req: Request, res: Response) => {
    try {
      const { app_id, handle, redirect_uri } = req.body;

      if (!app_id || typeof app_id !== 'string') {
        return res.status(400).json({
          error: 'missing_app_id',
          message: 'app_id is required',
        });
      }

      if (!handle || typeof handle !== 'string') {
        return res.status(400).json({
          error: 'missing_handle',
          message: 'handle is required (e.g., yourname.bsky.social)',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: `Application '${app_id}' is not registered`,
        });
      }

      // Validate redirect_uri if provided
      let validatedRedirectUri: string | undefined;
      if (typeof redirect_uri === 'string') {
        if (!isValidRedirectUri(redirect_uri, app.callback_url)) {
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            message: 'redirect_uri does not match the registered callback URL for this application',
          });
        }
        validatedRedirectUri = redirect_uri;
      } else if (app.callback_url) {
        // Use the registered callback URL as default
        validatedRedirectUri = app.callback_url;
      }

      const { url, state } = await oauth.generateAuthUrl(
        app_id,
        handle,
        validatedRedirectUri
      );

      res.json({
        auth_url: url,
        state,
        app_id,
      });
    } catch (error) {
      res.status(500).json(internalError('auth_init_failed', error, 'Auth init'));
    }
  });

  /**
   * GET /auth/callback
   * OAuth callback handler
   */
  router.get('/callback', async (req: Request, res: Response) => {
    try {
      const params = new URLSearchParams(req.url.split('?')[1] || '');

      const state = params.get('state');
      if (!state) {
        return res.status(400).json({
          error: 'missing_state',
          message: 'OAuth state parameter is missing',
        });
      }

      const savedState = db.getOAuthState(state);
      if (!savedState) {
        return res.status(400).json({
          error: 'invalid_state',
          message: 'OAuth state not found or expired',
        });
      }

      db.deleteOAuthState(state);

      const app = db.getApp(savedState.app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: 'Application configuration not found',
        });
      }

      const result = await oauth.handleCallback(params);

      const existingMapping = db.getUserMapping(result.did, savedState.app_id);
      const userId = existingMapping?.user_id ?? null;

      const token = createGatewayToken(
        {
          did: result.did,
          handle: result.handle,
          user_id: userId,
          app_id: savedState.app_id,
        },
        app.hmac_secret,
        app.token_ttl_seconds
      );

      const sessionId = uuidv4();
      const expiresAt = new Date(Date.now() + app.token_ttl_seconds * 1000);

      db.createSession({
        id: sessionId,
        did: result.did,
        handle: result.handle,
        user_id: userId,
        app_id: savedState.app_id,
        expires_at: expiresAt,
      });

      if (savedState.redirect_uri) {
        // Defense in depth: re-validate redirect URI before redirecting
        if (!isValidRedirectUri(savedState.redirect_uri, app.callback_url)) {
          console.error(`[SECURITY] Invalid redirect_uri in saved state: ${savedState.redirect_uri}`);
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            message: 'Redirect URI validation failed',
          });
        }

        const redirectUrl = new URL(savedState.redirect_uri);
        // Use URL fragment (hash) for sensitive data to prevent logging in:
        // - Server access logs
        // - Browser history
        // - Referrer headers
        // Fragments are only available client-side and never sent to servers
        const fragmentParams = new URLSearchParams();
        fragmentParams.set('token', token);
        fragmentParams.set('session_id', sessionId);
        if (userId === null) {
          fragmentParams.set('needs_linking', 'true');
        }
        redirectUrl.hash = fragmentParams.toString();
        return res.redirect(redirectUrl.toString());
      }

      res.json({
        token,
        session_id: sessionId,
        did: result.did,
        handle: result.handle,
        user_id: userId,
        needs_linking: userId === null,
        expires_at: expiresAt.toISOString(),
      });
    } catch (error) {
      res.status(500).json(internalError('auth_callback_failed', error, 'Auth callback'));
    }
  });

  /**
   * POST /auth/link
   * Link an AT Protocol identity to an application user account
   */
  router.post('/link', async (req: Request, res: Response) => {
    try {
      const { session_id, user_id, app_id } = req.body;

      if (!session_id || !user_id || !app_id) {
        return res.status(400).json({
          error: 'missing_params',
          message: 'session_id, user_id, and app_id are required',
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or expired',
        });
      }

      if (session.app_id !== app_id) {
        return res.status(400).json({
          error: 'app_mismatch',
          message: 'Session app_id does not match',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: 'Application not found',
        });
      }

      db.setUserMapping({
        did: session.did,
        app_id,
        user_id: parseInt(user_id, 10),
        handle: session.handle,
      });

      const token = createGatewayToken(
        {
          did: session.did,
          handle: session.handle,
          user_id: parseInt(user_id, 10),
          app_id,
        },
        app.hmac_secret,
        app.token_ttl_seconds
      );

      res.json({
        success: true,
        token,
        did: session.did,
        handle: session.handle,
        user_id: parseInt(user_id, 10),
      });
    } catch (error) {
      res.status(500).json(internalError('link_failed', error, 'Link'));
    }
  });

  /**
   * POST /auth/refresh
   * Refresh an expired gateway token
   */
  router.post('/refresh', async (req: Request, res: Response) => {
    try {
      const { session_id, app_id } = req.body;

      if (!session_id || !app_id) {
        return res.status(400).json({
          error: 'missing_params',
          message: 'session_id and app_id are required',
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or expired',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: 'Application not found',
        });
      }

      const mapping = db.getUserMapping(session.did, app_id);
      const userId = mapping?.user_id ?? session.user_id;

      const token = createGatewayToken(
        {
          did: session.did,
          handle: session.handle,
          user_id: userId,
          app_id,
        },
        app.hmac_secret,
        app.token_ttl_seconds
      );

      res.json({
        token,
        expires_in: app.token_ttl_seconds,
      });
    } catch (error) {
      res.status(500).json(internalError('refresh_failed', error, 'Refresh'));
    }
  });

  /**
   * POST /auth/logout
   * Invalidate a session
   */
  router.post('/logout', async (req: Request, res: Response) => {
    try {
      const { session_id } = req.body;

      if (!session_id) {
        return res.status(400).json({
          error: 'missing_session_id',
          message: 'session_id is required',
        });
      }

      db.deleteSession(session_id);

      res.json({ success: true });
    } catch (error) {
      res.status(500).json(internalError('logout_failed', error, 'Logout'));
    }
  });

  return router;
}
