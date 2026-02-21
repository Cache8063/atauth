/**
 * Forward-Auth Proxy Routes
 *
 * Implements nginx auth_request compatible endpoints for protecting
 * arbitrary services behind ATAuth SSO.
 *
 * Flow:
 * 1. User hits protected service -> nginx auth_request -> GET /auth/verify -> 401
 * 2. nginx redirects to GET /auth/proxy/login?rd=<original_url>
 * 3. If ATAuth session exists: silent SSO redirect with ticket
 *    If not: render login page, user does AT Proto OAuth
 * 4. After auth: redirect back to original URL with _atauth_ticket param
 * 5. nginx auth_request fires again -> GET /auth/verify validates ticket,
 *    returns 200 + Set-Cookie for the protected domain
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../services/database.js';
import type { OAuthService } from '../services/oauth.js';
import type { ForwardAuthConfig, AccessCheckResult } from '../types/proxy.js';
import { checkAccess } from '../utils/access-check.js';
import {
  SESSION_COOKIE_NAME,
  PROXY_COOKIE_NAME,
  createSessionCookie,
  verifySessionCookie,
  createProxyCookie,
  verifyProxyCookie,
  createAuthTicket,
  verifyAuthTicket,
  parseCookies,
  isAllowedRedirect,
  extractOrigin,
} from '../utils/proxy-auth.js';

export function createProxyAuthRoutes(
  db: DatabaseService,
  oauthService: OAuthService,
  forwardAuthConfig: ForwardAuthConfig,
  oidcIssuer: string,
): Router {
  const router = Router();
  const secret = forwardAuthConfig.sessionSecret;

  /**
   * Check access rules for a user attempting to access a protected origin.
   * Returns allowed if no rules are configured (backward compat).
   */
  function enforceAccess(did: string, handle: string, redirectUri: string): AccessCheckResult {
    const targetOrigin = extractOrigin(redirectUri);
    if (!targetOrigin) {
      return { allowed: false, matched_rule_id: null, reason: 'Invalid redirect URI' };
    }

    const originId = db.getOriginIdByOrigin(targetOrigin);
    if (originId === null) {
      return { allowed: false, matched_rule_id: null, reason: 'Origin not registered' };
    }

    const rules = db.getProxyAccessRulesForCheck(originId);
    const totalRules = rules.denyRules.length + rules.originAllowRules.length + rules.globalAllowRules.length;
    if (totalRules === 0) {
      return { allowed: true, matched_rule_id: null, reason: 'No access rules configured (open access)' };
    }

    const result = checkAccess(did, handle, rules);
    if (!result.allowed) {
      console.log(`[Proxy ACL] Access denied for ${handle} (${did}) to ${targetOrigin}: ${result.reason}`);
    }
    return result;
  }

  // ===== GET /auth/verify =====
  // Called by nginx auth_request on every request to a protected service.
  router.get('/verify', async (req: Request, res: Response) => {
    const cookieHeader = req.headers.cookie as string | undefined;
    const originalUrl = req.headers['x-original-url'] as string | undefined;
    const cookies = parseCookies(cookieHeader);

    // 1. Check for per-domain _atauth_proxy cookie
    const proxyCookie = cookies[PROXY_COOKIE_NAME];
    if (proxyCookie) {
      const sessionId = verifyProxyCookie(proxyCookie, secret);
      if (sessionId) {
        const session = db.getProxySession(sessionId);
        if (session && session.expires_at > Math.floor(Date.now() / 1000)) {
          db.updateProxySessionActivity(sessionId);
          res.setHeader('X-Auth-User', session.handle);
          res.setHeader('X-Auth-DID', session.did);
          res.setHeader('X-Auth-Handle', session.handle);
          return res.sendStatus(200);
        }
      }
    }

    // 2. Check for _atauth_ticket in the original URL (redirect-back flow)
    if (originalUrl) {
      try {
        // X-Original-URL may be a full URL or just a path+query
        const url = originalUrl.startsWith('http')
          ? new URL(originalUrl)
          : new URL(originalUrl, 'http://placeholder');
        const ticket = url.searchParams.get('_atauth_ticket');
        if (ticket) {
          // Determine origin from X-Forwarded headers or the URL itself
          const forwardedProto = req.headers['x-forwarded-proto'] as string || 'https';
          const forwardedHost = req.headers['x-forwarded-host'] as string || url.host;
          const requestOrigin = `${forwardedProto}://${forwardedHost}`;

          const verified = verifyAuthTicket(ticket, secret, requestOrigin);
          if (verified) {
            const session = db.getProxySession(verified.sid);
            if (session && session.expires_at > Math.floor(Date.now() / 1000)) {
              // Set per-domain cookie via Set-Cookie header
              // nginx configuration-snippet passes this to the browser
              const cookieValue = createProxyCookie(
                verified.sid, secret, forwardAuthConfig.proxyCookieTtl,
              );
              res.setHeader('Set-Cookie',
                `${PROXY_COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${forwardAuthConfig.proxyCookieTtl}`,
              );
              res.setHeader('X-Auth-User', session.handle);
              res.setHeader('X-Auth-DID', session.did);
              res.setHeader('X-Auth-Handle', session.handle);
              return res.sendStatus(200);
            }
          }
        }
      } catch {
        // Ignore URL parse errors
      }
    }

    // 3. Not authenticated
    return res.sendStatus(401);
  });

  // ===== GET /auth/proxy/login =====
  // Browser lands here after nginx redirects on 401.
  router.get('/proxy/login', async (req: Request, res: Response) => {
    const rd = req.query.rd as string;

    if (!rd) {
      return res.status(400).send('Missing redirect parameter');
    }

    // Validate redirect URL against allowed origins
    const allowedOrigins = db.listProxyAllowedOrigins().map(o => o.origin);
    if (!isAllowedRedirect(rd, allowedOrigins)) {
      return res.status(403).type('html').send(renderForbiddenPage(res.locals.cspNonce));
    }

    // Check for existing ATAuth session cookie
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies[SESSION_COOKIE_NAME];

    if (sessionCookie) {
      const sessionId = verifySessionCookie(sessionCookie, secret);
      if (sessionId) {
        const session = db.getProxySession(sessionId);
        if (session && session.expires_at > Math.floor(Date.now() / 1000)) {
          // Check access rules before issuing silent SSO ticket
          const accessResult = enforceAccess(session.did, session.handle, rd);
          if (!accessResult.allowed) {
            return res.status(403).type('html').send(renderAccessDeniedPage(res.locals.cspNonce));
          }

          // Silent SSO -- generate ticket and redirect back
          const targetOrigin = extractOrigin(rd);
          if (targetOrigin) {
            const ticket = createAuthTicket(session.id, session.did, session.handle, targetOrigin, secret);
            const redirectUrl = new URL(rd);
            redirectUrl.searchParams.set('_atauth_ticket', ticket);
            return res.redirect(redirectUrl.toString());
          }
        }
      }
    }

    // No valid session -- show login page
    const now = Math.floor(Date.now() / 1000);
    const authRequestId = crypto.randomBytes(32).toString('base64url');
    db.saveProxyAuthRequest({
      id: authRequestId,
      redirect_uri: rd,
      created_at: now,
      expires_at: now + 600, // 10 minutes
    });

    res.type('html').send(renderProxyLoginPage(authRequestId, res.locals.cspNonce));
  });

  // ===== POST /auth/proxy/login =====
  // Handle the login form submission with user's handle.
  router.post('/proxy/login', async (req: Request, res: Response) => {
    const { auth_request_id, handle } = req.body;

    if (!auth_request_id || !handle) {
      return res.status(400).send('Missing required parameters');
    }

    // Sanitize handle (same logic as authorize.ts)
    let sanitizedHandle = handle.trim().replace(/^@/, '');
    sanitizedHandle = sanitizedHandle.replace(/:/g, '.');
    sanitizedHandle = sanitizedHandle.replace(/@/, '.');
    if (!sanitizedHandle.includes('.')) {
      sanitizedHandle = sanitizedHandle + '.bsky.social';
    }

    // Look up the pending auth request
    const authRequest = db.getProxyAuthRequest(auth_request_id);
    if (!authRequest) {
      return res.status(400).send('Login request expired or invalid');
    }

    if (authRequest.expires_at < Math.floor(Date.now() / 1000)) {
      db.deleteProxyAuthRequest(auth_request_id);
      return res.status(400).send('Login request expired');
    }

    try {
      // Start AT Protocol OAuth
      let atprotoAuth;
      try {
        atprotoAuth = await oauthService.generateAuthUrl(
          'proxy-auth', // internal client ID for state tracking
          sanitizedHandle,
          `${oidcIssuer}/auth/proxy/callback`,
        );
      } catch (firstErr) {
        const msg = firstErr instanceof Error ? firstErr.message : '';
        if (msg.includes('invalid_client_metadata')) {
          console.log('[Proxy Auth] Retrying after transient client_metadata error...');
          await new Promise(r => setTimeout(r, 1000));
          atprotoAuth = await oauthService.generateAuthUrl(
            'proxy-auth',
            sanitizedHandle,
            `${oidcIssuer}/auth/proxy/callback`,
          );
        } else {
          throw firstErr;
        }
      }

      if (!atprotoAuth) {
        return res.status(500).send('Failed to start authentication');
      }

      // Store mapping: AT Proto state -> proxy auth request ID
      db.saveOAuthState({
        state: atprotoAuth.state,
        code_verifier: auth_request_id, // Store auth request ID for the callback
        app_id: 'proxy-auth',
        redirect_uri: authRequest.redirect_uri,
        created_at: Math.floor(Date.now() / 1000),
      });

      // Redirect to AT Protocol OAuth
      const isJsonRequest = req.is('json');
      if (isJsonRequest) {
        res.json({ redirect_url: atprotoAuth.url });
      } else {
        res.redirect(atprotoAuth.url);
      }
    } catch (error) {
      console.error('[Proxy Auth] Login error:', error);
      let userMessage = 'Authentication failed. Please try again.';
      const errMsg = error instanceof Error ? error.message : '';
      if (errMsg.includes('resolve identity') || errMsg.includes('Invalid handle')) {
        userMessage = 'Could not find that handle. Enter your full handle (e.g. yourname.bsky.social or your.custom.domain).';
      } else if (errMsg.includes('invalid_client_metadata')) {
        userMessage = 'Bluesky login is temporarily unavailable. Please wait a moment and try again.';
      }
      const isJsonRequest = req.is('json');
      if (isJsonRequest) {
        res.status(400).json({ error: userMessage });
      } else {
        res.status(400).type('html').send(renderProxyLoginPage(auth_request_id, res.locals.cspNonce, userMessage));
      }
    }
  });

  // ===== GET /auth/proxy/callback =====
  // AT Protocol OAuth callback for the forward-auth flow.
  router.get('/proxy/callback', async (req: Request, res: Response) => {
    try {
      const { code, state, error, error_description, iss } = req.query as {
        code?: string;
        state?: string;
        error?: string;
        error_description?: string;
        iss?: string;
      };

      if (error) {
        console.error(`[Proxy Callback] AT Protocol error: ${error} - ${error_description}`);
        return res.status(400).type('html').send(renderErrorPage(
          'Authentication failed',
          error_description || 'The identity provider returned an error.',
          res.locals.cspNonce,
        ));
      }

      if (!code || !state) {
        return res.status(400).send('Missing code or state');
      }

      // Get the saved state
      const savedState = db.getOAuthState(state);
      if (!savedState || savedState.app_id !== 'proxy-auth') {
        return res.status(400).send('Invalid or expired state');
      }

      // Exchange the AT Protocol code for tokens
      const callbackParams = new URLSearchParams();
      callbackParams.set('code', code);
      callbackParams.set('state', state);
      if (iss) callbackParams.set('iss', iss);

      const callbackResult = await oauthService.handleCallback(
        callbackParams,
        `${oidcIssuer}/auth/proxy/callback`,
      );
      if (!callbackResult) {
        return res.status(500).send('Failed to complete authentication');
      }

      const { did, handle } = callbackResult;
      console.log(`[Proxy Callback] Authenticated user: ${handle} (${did})`);

      // Get the original redirect URI from the proxy auth request
      const authRequestId = savedState.code_verifier;
      const authRequest = db.getProxyAuthRequest(authRequestId);
      if (!authRequest) {
        return res.status(400).send('Login request expired');
      }

      // Check access rules before creating session
      const accessResult = enforceAccess(did, handle, authRequest.redirect_uri);
      if (!accessResult.allowed) {
        db.deleteOAuthState(state);
        db.deleteProxyAuthRequest(authRequestId);
        return res.status(403).type('html').send(renderAccessDeniedPage(res.locals.cspNonce));
      }

      // Create a proxy session
      const now = Math.floor(Date.now() / 1000);
      const sessionId = crypto.randomBytes(32).toString('base64url');
      db.createProxySession({
        id: sessionId,
        did,
        handle,
        created_at: now,
        expires_at: now + forwardAuthConfig.sessionTtl,
        last_activity: now,
        user_agent: req.headers['user-agent'],
        ip_address: req.headers['x-forwarded-for'] as string || req.ip,
      });

      // Set the ATAuth session cookie (on ATAuth domain)
      const sessionCookieValue = createSessionCookie(sessionId, secret, forwardAuthConfig.sessionTtl);
      res.setHeader('Set-Cookie',
        `${SESSION_COOKIE_NAME}=${sessionCookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${forwardAuthConfig.sessionTtl}`,
      );

      // Generate auth ticket for the redirect target
      const targetOrigin = extractOrigin(authRequest.redirect_uri);
      if (!targetOrigin) {
        return res.status(400).send('Invalid redirect URI');
      }

      const ticket = createAuthTicket(sessionId, did, handle, targetOrigin, secret);

      // Clean up
      db.deleteOAuthState(state);
      db.deleteProxyAuthRequest(authRequestId);

      // Redirect back to the original URL with ticket
      const redirectUrl = new URL(authRequest.redirect_uri);
      redirectUrl.searchParams.set('_atauth_ticket', ticket);
      res.redirect(redirectUrl.toString());
    } catch (error) {
      console.error('[Proxy Callback] Error:', error);
      res.status(500).type('html').send(renderErrorPage(
        'Authentication error',
        'An unexpected error occurred. Please try again.',
        res.locals.cspNonce,
      ));
    }
  });

  // ===== GET /auth/proxy/logout =====
  // Centralized logout.
  router.get('/proxy/logout', async (req: Request, res: Response) => {
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies[SESSION_COOKIE_NAME];

    if (sessionCookie) {
      const sessionId = verifySessionCookie(sessionCookie, secret);
      if (sessionId) {
        db.deleteProxySession(sessionId);
      }
    }

    // Clear the session cookie
    res.setHeader('Set-Cookie',
      `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );

    const rd = req.query.rd as string;
    if (rd) {
      // Validate redirect against allowed origins to prevent open redirect
      const allowedOrigins = db.listProxyAllowedOrigins().map(o => o.origin);
      if (isAllowedRedirect(rd, allowedOrigins)) {
        return res.redirect(rd);
      }
      // If not allowed, fall through to the logged-out page
    }

    res.type('html').send(renderLoggedOutPage(res.locals.cspNonce));
  });

  return router;
}

// ===== HTML Templates =====

/**
 * Escape HTML special characters to prevent XSS.
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderProxyLoginPage(authRequestId: string, nonce?: string, errorMessage?: string): string {
  const errorHtml = errorMessage
    ? `<div class="error" style="display:block">${escapeHtml(errorMessage)}</div>`
    : '<div class="error" id="error"></div>';
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in - ATAuth</title>
  ${sharedStyles()}
</head>
<body>
  <div class="container">
    <h1>Sign in to continue</h1>
    <p class="subtitle">Authenticate with your Bluesky account to access this service</p>
    ${errorHtml}
    <form id="loginForm" action="/auth/proxy/login" method="POST">
      <input type="hidden" name="auth_request_id" value="${escapeHtml(authRequestId)}">
      <label for="handle">Your Handle</label>
      <input type="text" id="handle" name="handle" placeholder="you.bsky.social" autocomplete="username" autocapitalize="none" spellcheck="false" required>
      <p class="hint">Enter your Bluesky handle or custom domain</p>
      <button type="submit" id="submitBtn">Continue</button>
    </form>
    <p class="privacy">Bluesky will ask to authorize broad access -- this is a limitation of the AT&nbsp;Protocol OAuth standard. This gateway only reads your identity (handle). It will never post, follow, or access your data.</p>
  </div>
  <script${nonce ? ` nonce="${nonce}"` : ''}>
    var form = document.getElementById('loginForm');
    var submitBtn = document.getElementById('submitBtn');
    var errorDiv = document.getElementById('error');
    var submitted = false;
    form.addEventListener('submit', function(e) {
      if (submitted) { e.preventDefault(); return; }
      submitted = true;
      submitBtn.disabled = true;
      submitBtn.textContent = 'Redirecting...';
      if (errorDiv) errorDiv.style.display = 'none';
    });
  </script>
</body>
</html>`;
}

function renderForbiddenPage(nonce?: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied - ATAuth</title>
  ${sharedStyles()}
</head>
<body>
  <div class="container">
    <h1>Access Denied</h1>
    <p class="subtitle">This service is not configured for SSO access. Contact your administrator.</p>
  </div>
</body>
</html>`;
}

function renderAccessDeniedPage(nonce?: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Not Authorized - ATAuth</title>
  ${sharedStyles()}
</head>
<body>
  <div class="container">
    <h1>Not Authorized</h1>
    <p class="subtitle">Your account does not have access to this service. Contact your administrator if you believe this is an error.</p>
  </div>
</body>
</html>`;
}

function renderErrorPage(title: string, message: string, nonce?: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - ATAuth</title>
  ${sharedStyles()}
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>
    <p class="subtitle">${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

function renderLoggedOutPage(nonce?: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Signed Out - ATAuth</title>
  ${sharedStyles()}
</head>
<body>
  <div class="container">
    <h1>Signed Out</h1>
    <p class="subtitle">You have been signed out of ATAuth SSO.</p>
  </div>
</body>
</html>`;
}

function sharedStyles(): string {
  return `<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    h1 { font-size: 24px; margin-bottom: 8px; color: #1a1a2e; }
    .subtitle { color: #666; margin-bottom: 32px; font-size: 14px; }
    label { display: block; font-weight: 500; margin-bottom: 8px; color: #333; }
    input[type="text"] {
      width: 100%;
      padding: 14px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus { outline: none; border-color: #667eea; }
    .hint { font-size: 12px; color: #888; margin-top: 8px; }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 24px;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
    button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    .error {
      background: #fee;
      color: #c00;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      font-size: 14px;
      display: none;
    }
    .privacy { font-size: 12px; color: #888; margin-top: 20px; line-height: 1.5; text-align: center; }
    .privacy strong { color: #555; }
  </style>`;
}
