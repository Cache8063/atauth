/**
 * OIDC Authorization Endpoint
 *
 * Handles /oauth/authorize - the entry point for OIDC authentication
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../../services/database.js';
import type { OIDCService } from '../../services/oidc/index.js';
import type { OAuthService } from '../../services/oauth.js';
import type { PasskeyService } from '../../services/passkey.js';
import { parseScopes, hasOpenIdScope, validateScopes } from '../../services/oidc/claims.js';
import { isValidCodeChallengeMethod } from '../../services/oidc/pkce.js';

export function createAuthorizeRouter(
  db: DatabaseService,
  oidcService: OIDCService,
  oauthService: OAuthService,
  passkeyService?: PasskeyService | null
): Router {
  const router = Router();

  function esc(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderLoginPage(clientName: string, authCode: string, state: string, errorMessage?: string, nonce?: string, passkeyEnabled?: boolean): string {
    const errorHtml = errorMessage
      ? `<div class="error" style="display:block">${esc(errorMessage)}</div>`
      : '<div class="error" id="error"></div>';
    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in - ATAuth</title>
  <style>
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
    .client-info {
      background: #f5f5f5;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 24px;
      font-size: 13px;
      color: #444;
    }
    .client-info strong { color: #1a1a2e; }
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
    .logo { text-align: center; margin-bottom: 24px; font-size: 32px; }
    .divider { display: flex; align-items: center; margin: 24px 0; gap: 12px; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #e0e0e0; }
    .divider span { color: #999; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
    .passkey-btn {
      width: 100%;
      padding: 14px;
      background: white;
      color: #333;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: border-color 0.2s, transform 0.2s, box-shadow 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .passkey-btn:hover { border-color: #667eea; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2); }
    .passkey-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    .passkey-icon { font-size: 20px; line-height: 1; }
    .privacy { font-size: 12px; color: #888; margin-top: 20px; line-height: 1.5; text-align: center; }
    .privacy strong { color: #555; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">&#128274;</div>
    <h1>Sign in with ATAuth</h1>
    <p class="subtitle">Use your Bluesky or AT Protocol identity</p>
    <div class="client-info">Signing in to <strong>${esc(clientName)}</strong></div>
    ${errorHtml}
    <form id="loginForm" action="/oauth/authorize/login" method="POST">
      <input type="hidden" name="auth_code" value="${esc(authCode)}">
      <input type="hidden" name="state" value="${esc(state)}">
      <label for="handle">Your Handle</label>
      <input type="text" id="handle" name="handle" placeholder="you.bsky.social" autocomplete="username" autocapitalize="none" spellcheck="false" required>
      <p class="hint">Enter your Bluesky handle or custom domain</p>
      <button type="submit" id="submitBtn">Continue</button>
    </form>${passkeyEnabled ? `
    <div class="divider"><span>or</span></div>
    <button type="button" class="passkey-btn" id="passkeyBtn" style="display:none">
      <span class="passkey-icon">&#128273;</span> Sign in with a passkey
    </button>` : ''}
    <p class="privacy">Bluesky will ask to authorize broad access — this is a limitation of the AT&nbsp;Protocol OAuth standard. <strong>${esc(clientName)}</strong> only reads your identity (handle). It will never post, follow, or access your data.</p>
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
    });${passkeyEnabled ? `
    function b64urlToBuffer(s) {
      var b = s.replace(/-/g, '+').replace(/_/g, '/');
      var pad = b.length % 4 === 0 ? '' : '='.repeat(4 - (b.length % 4));
      var bin = atob(b + pad);
      var arr = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr.buffer;
    }
    function bufferToB64url(buf) {
      var bytes = new Uint8Array(buf);
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    }
    function showError(msg) {
      var e = document.getElementById('error');
      if (e) { e.textContent = msg; e.style.display = 'block'; }
    }
    var passkeyBtn = document.getElementById('passkeyBtn');
    if (passkeyBtn && window.PublicKeyCredential) {
      passkeyBtn.style.display = 'flex';
      passkeyBtn.addEventListener('click', function() {
        passkeyBtn.disabled = true;
        passkeyBtn.innerHTML = '<span class="passkey-icon">&#128273;</span> Authenticating...';
        if (errorDiv) errorDiv.style.display = 'none';
        fetch('/auth/passkey/authenticate/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        })
        .then(function(r) { return r.json(); })
        .then(function(opts) {
          var pubKeyOpts = {
            challenge: b64urlToBuffer(opts.challenge),
            timeout: opts.timeout,
            rpId: opts.rpId,
            userVerification: opts.userVerification
          };
          if (opts.allowCredentials && opts.allowCredentials.length > 0) {
            pubKeyOpts.allowCredentials = opts.allowCredentials.map(function(c) {
              return { id: b64urlToBuffer(c.id), type: c.type, transports: c.transports };
            });
          }
          return navigator.credentials.get({ publicKey: pubKeyOpts }).then(function(cred) {
            return { cred: cred, challenge: opts.challenge };
          });
        })
        .then(function(res) {
          var cred = res.cred;
          return fetch('/oauth/authorize/passkey', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              auth_code: document.querySelector('input[name="auth_code"]').value,
              challenge: res.challenge,
              credential: {
                id: cred.id,
                rawId: bufferToB64url(cred.rawId),
                response: {
                  clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
                  authenticatorData: bufferToB64url(cred.response.authenticatorData),
                  signature: bufferToB64url(cred.response.signature),
                  userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : undefined
                },
                type: cred.type,
                authenticatorAttachment: cred.authenticatorAttachment
              }
            })
          });
        })
        .then(function(r) { return r.json(); })
        .then(function(result) {
          if (result.redirect_url) {
            window.location.href = result.redirect_url;
          } else {
            showError(result.error_description || 'Passkey authentication failed');
            passkeyBtn.disabled = false;
            passkeyBtn.innerHTML = '<span class="passkey-icon">&#128273;</span> Sign in with a passkey';
          }
        })
        .catch(function(err) {
          if (err.name !== 'NotAllowedError') {
            showError('Passkey authentication failed. Try signing in with your handle.');
          }
          passkeyBtn.disabled = false;
          passkeyBtn.innerHTML = '<span class="passkey-icon">&#128273;</span> Sign in with a passkey';
        });
      });
    }` : ''}
  </script>
</body>
</html>`;
  }

  /**
   * GET/POST /oauth/authorize
   * Start the authorization flow
   */
  router.all('/authorize', async (req: Request, res: Response) => {
    try {
      // Extract parameters from query or body
      const params = req.method === 'POST' ? req.body : req.query;

      const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
      } = params as {
        response_type?: string;
        client_id?: string;
        redirect_uri?: string;
        scope?: string;
        state?: string;
        nonce?: string;
        code_challenge?: string;
        code_challenge_method?: string;
      };

      // Validate required parameters
      if (!response_type || !client_id || !redirect_uri || !scope || !state) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: response_type, client_id, redirect_uri, scope, state',
        });
      }

      // Only support authorization code flow
      if (response_type !== 'code') {
        return res.status(400).json({
          error: 'unsupported_response_type',
          error_description: 'Only response_type=code is supported',
        });
      }

      // Get client configuration
      const client = db.getOIDCClient(client_id);
      if (!client) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Unknown client_id',
        });
      }

      // Verify client is OIDC type
      if (client.client_type !== 'oidc') {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client is not configured for OIDC',
        });
      }

      // Validate redirect_uri
      console.log(`[OIDC] Validating redirect_uri: "${redirect_uri}"`);
      console.log(`[OIDC] Allowed redirect_uris: ${JSON.stringify(client.redirect_uris)}`);
      if (!client.redirect_uris.includes(redirect_uri)) {
        console.log(`[OIDC] redirect_uri mismatch!`);
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid redirect_uri',
        });
      }

      // Validate scopes
      const requestedScopes = parseScopes(scope);
      if (!hasOpenIdScope(requestedScopes)) {
        return redirectWithError(res, redirect_uri, state, 'invalid_scope', 'openid scope is required');
      }

      const scopeValidation = validateScopes(requestedScopes, client.allowed_scopes);
      if (!scopeValidation.valid) {
        return redirectWithError(res, redirect_uri, state, 'invalid_scope', scopeValidation.error || 'Invalid scope');
      }

      // Check PKCE requirements
      if (client.require_pkce && !code_challenge) {
        return redirectWithError(res, redirect_uri, state, 'invalid_request', 'PKCE code_challenge is required');
      }

      // Validate code_challenge_method
      if (code_challenge && code_challenge_method && !isValidCodeChallengeMethod(code_challenge_method)) {
        return redirectWithError(res, redirect_uri, state, 'invalid_request', 'Invalid code_challenge_method');
      }

      // Generate authorization code
      const authCode = crypto.randomBytes(32).toString('base64url');

      // Store the authorization request
      // We'll complete this after AT Protocol OAuth returns
      const authState = {
        code: authCode,
        client_id,
        redirect_uri,
        scope: scopeValidation.scopes.join(' '),
        nonce,
        code_challenge,
        code_challenge_method: code_challenge_method as 'S256' | 'plain' | undefined,
        state,
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 600, // 10 minutes
      };

      // Store the OIDC authorization request and show login page
      // We need the user's handle before we can start AT Protocol OAuth

      // Save the pending authorization request
      db.saveAuthorizationCode({
        code: authCode,
        client_id,
        redirect_uri,
        scope: scopeValidation.scopes.join(' '),
        state,
        nonce,
        code_challenge,
        code_challenge_method: code_challenge_method as 'S256' | 'plain' | undefined,
        did: '', // Will be filled on callback
        handle: '', // Will be filled on callback
        created_at: authState.created_at,
        expires_at: authState.expires_at,
        used: false,
      });

      // Show login page asking for handle
      res.type('html').send(renderLoginPage(client.name || client_id, authCode, state || '', undefined, res.locals.cspNonce, !!passkeyService));
    } catch (error) {
      console.error('[OIDC Authorize] Error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  /**
   * POST /oauth/authorize/login
   * Handle the login form submission with user's handle
   */
  router.post('/authorize/login', async (req: Request, res: Response) => {
    try {
      const { auth_code, handle } = req.body;

      if (!auth_code || !handle) {
        return res.status(400).send('Missing required parameters');
      }

      // Sanitize handle: strip @, fix common typos, add .bsky.social if no domain
      let sanitizedHandle = handle.trim().replace(/^@/, '');
      // Replace colons with dots (common keyboard typo: "user:bsky.social")
      sanitizedHandle = sanitizedHandle.replace(/:/g, '.');
      // Strip email-style @domain (e.g. "user@bsky.social" → "user.bsky.social")
      sanitizedHandle = sanitizedHandle.replace(/@/, '.');
      // If no dots, assume .bsky.social
      if (!sanitizedHandle.includes('.')) {
        sanitizedHandle = sanitizedHandle + '.bsky.social';
      }

      // Get the pending authorization
      const authData = db.getAuthorizationCode(auth_code);
      if (!authData) {
        return res.status(400).send('Authorization request expired or invalid');
      }

      if (authData.used) {
        return res.status(400).send('Authorization code already used');
      }

      // Start AT Protocol OAuth with the user's handle
      // Retry once on transient errors (bsky.social intermittently fails to fetch client metadata)
      let atprotoAuth;
      try {
        atprotoAuth = await oauthService.generateAuthUrl(
          authData.client_id,
          sanitizedHandle,
          `${oidcService.issuer}/oauth/callback`
        );
      } catch (firstErr) {
        const msg = firstErr instanceof Error ? firstErr.message : '';
        if (msg.includes('invalid_client_metadata')) {
          console.log('[OIDC Login] Retrying after transient client_metadata error...');
          await new Promise(r => setTimeout(r, 1000));
          atprotoAuth = await oauthService.generateAuthUrl(
            authData.client_id,
            sanitizedHandle,
            `${oidcService.issuer}/oauth/callback`
          );
        } else {
          throw firstErr;
        }
      }

      if (!atprotoAuth) {
        return res.status(500).send('Failed to start authentication');
      }

      // Store mapping from AT Protocol state to our auth code
      db.saveOAuthState({
        state: atprotoAuth.state,
        code_verifier: auth_code, // Store our auth code here for the callback
        app_id: authData.client_id,
        redirect_uri: authData.redirect_uri,
        created_at: Math.floor(Date.now() / 1000),
      });

      // Return redirect URL — JSON for fetch clients, 302 for native form fallback
      const isJsonRequest = req.is('json');
      if (isJsonRequest) {
        res.json({ redirect_url: atprotoAuth.url });
      } else {
        res.redirect(atprotoAuth.url);
      }
    } catch (error) {
      console.error('[OIDC Login] Error:', error);
      // Provide a user-friendly error for common handle issues
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
        // Re-render login page with error for native form submissions
        const { auth_code: errAuthCode } = req.body;
        const errAuthData = errAuthCode ? db.getAuthorizationCode(errAuthCode) : null;
        const errClient = errAuthData ? db.getApp(errAuthData.client_id) : null;
        const errClientName = errClient?.name || errAuthData?.client_id || 'Unknown';
        res.status(400).type('html').send(renderLoginPage(errClientName, errAuthCode || '', errAuthData?.state || '', userMessage, res.locals.cspNonce, !!passkeyService));
      }
    }
  });

  /**
   * POST /oauth/authorize/passkey
   * Authenticate via passkey and complete the OIDC authorization flow
   */
  router.post('/authorize/passkey', async (req: Request, res: Response) => {
    try {
      if (!passkeyService) {
        return res.status(404).json({
          error: 'not_found',
          error_description: 'Passkey authentication is not enabled',
        });
      }

      const { auth_code, credential, challenge } = req.body;

      if (!auth_code || !credential || !challenge) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters: auth_code, credential, challenge',
        });
      }

      // Validate the pending authorization code
      const authData = db.getAuthorizationCode(auth_code);
      if (!authData) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Authorization request expired or invalid',
        });
      }

      if (authData.used) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Authorization code already used',
        });
      }

      // Verify the passkey
      const result = await passkeyService.verifyAuthentication(credential, challenge);

      if (!result.success || !result.did || !result.handle) {
        return res.status(401).json({
          error: 'authentication_failed',
          error_description: result.error || 'Passkey authentication failed',
        });
      }

      console.log(`[OIDC Passkey] Authenticated user: ${result.handle} (${result.did})`);

      // Update the authorization code with the user's identity
      db.updateAuthorizationCodeUser(auth_code, result.did, result.handle);

      // Build the redirect URL back to the original client
      const clientRedirectUrl = new URL(authData.redirect_uri);
      clientRedirectUrl.searchParams.set('code', auth_code);
      if (authData.state) {
        clientRedirectUrl.searchParams.set('state', authData.state);
      }

      res.json({ redirect_url: clientRedirectUrl.toString() });
    } catch (error) {
      console.error('[OIDC Passkey] Error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  /**
   * GET /oauth/callback
   * Handle the AT Protocol OAuth callback and complete the OIDC flow
   */
  router.get('/callback', async (req: Request, res: Response) => {
    try {
      const { code, state, error, error_description, iss } = req.query as {
        code?: string;
        state?: string;
        error?: string;
        error_description?: string;
        iss?: string;
      };

      console.log(`[OIDC Callback] Received callback with state: ${state}`);

      // Handle AT Protocol OAuth errors
      if (error) {
        console.error(`[OIDC Callback] AT Protocol error: ${error} - ${error_description}`);
        // We need to redirect back to the original client with the error
        // But we need the state to find the original request
        if (state) {
          const savedState = db.getOAuthState(state);
          if (savedState) {
            return redirectWithError(
              res,
              savedState.redirect_uri,
              undefined,
              'access_denied',
              error_description || 'Authentication failed'
            );
          }
        }
        return res.status(400).json({
          error: 'access_denied',
          error_description: error_description || 'Authentication failed',
        });
      }

      if (!code || !state) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing code or state',
        });
      }

      // Get the saved state
      const savedState = db.getOAuthState(state);
      if (!savedState) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid or expired state',
        });
      }

      // Exchange the AT Protocol code for tokens
      // Build URLSearchParams from the callback query parameters
      const callbackParams = new URLSearchParams();
      callbackParams.set('code', code);
      callbackParams.set('state', state);
      if (iss) callbackParams.set('iss', iss);

      const callbackResult = await oauthService.handleCallback(
        callbackParams,
        `${oidcService.issuer}/oauth/callback`
      );
      if (!callbackResult) {
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to complete authentication',
        });
      }

      // Get the user's DID and handle from the AT Protocol session
      const { did, handle } = callbackResult;
      console.log(`[OIDC Callback] Authenticated user: ${handle} (${did})`);

      // Get the OIDC authorization code we saved earlier (stored in code_verifier field)
      const oidcAuthCode = savedState.code_verifier;
      if (!oidcAuthCode) {
        return res.status(500).json({
          error: 'server_error',
          error_description: 'OIDC authorization state not found',
        });
      }

      // Update the authorization code with the user's identity
      const authData = db.getAuthorizationCode(oidcAuthCode);
      if (!authData) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'OIDC authorization expired',
        });
      }

      // Update with user info
      db.updateAuthorizationCodeUser(oidcAuthCode, did, handle);

      // Build the redirect URL back to the original client
      const clientRedirectUrl = new URL(authData.redirect_uri);
      clientRedirectUrl.searchParams.set('code', oidcAuthCode);
      if (authData.state) {
        clientRedirectUrl.searchParams.set('state', authData.state);
      }

      console.log(`[OIDC Callback] Redirecting to client: ${authData.redirect_uri}`);

      // Clean up the AT Protocol state
      db.deleteOAuthState(state);

      // Redirect back to the OIDC client
      res.redirect(clientRedirectUrl.toString());
    } catch (error) {
      console.error('[OIDC Callback] Error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  return router;
}

/**
 * Redirect with error parameters
 */
function redirectWithError(
  res: Response,
  redirectUri: string,
  state: string | undefined,
  error: string,
  errorDescription: string
): void {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', errorDescription);
  if (state) {
    url.searchParams.set('state', state);
  }
  res.redirect(url.toString());
}
