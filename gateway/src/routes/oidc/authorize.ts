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
import { parseScopes, hasOpenIdScope, validateScopes } from '../../services/oidc/claims.js';
import { isValidCodeChallengeMethod } from '../../services/oidc/pkce.js';

export function createAuthorizeRouter(
  db: DatabaseService,
  oidcService: OIDCService,
  oauthService: OAuthService
): Router {
  const router = Router();

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
      const loginPageHtml = `
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
    h1 {
      font-size: 24px;
      margin-bottom: 8px;
      color: #1a1a2e;
    }
    .subtitle {
      color: #666;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .client-info {
      background: #f5f5f5;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 24px;
      font-size: 13px;
      color: #444;
    }
    .client-info strong { color: #1a1a2e; }
    label {
      display: block;
      font-weight: 500;
      margin-bottom: 8px;
      color: #333;
    }
    input[type="text"] {
      width: 100%;
      padding: 14px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 16px;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #667eea;
    }
    .hint {
      font-size: 12px;
      color: #888;
      margin-top: 8px;
    }
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
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .error {
      background: #fee;
      color: #c00;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 16px;
      font-size: 14px;
      display: none;
    }
    .logo {
      text-align: center;
      margin-bottom: 24px;
      font-size: 32px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🔐</div>
    <h1>Sign in with ATAuth</h1>
    <p class="subtitle">Use your Bluesky or AT Protocol identity</p>

    <div class="client-info">
      Signing in to <strong>${client.name || client_id}</strong>
    </div>

    <div class="error" id="error"></div>

    <form id="loginForm" action="/oauth/authorize/login" method="POST">
      <input type="hidden" name="auth_code" value="${authCode}">
      <input type="hidden" name="state" value="${state || ''}">

      <label for="handle">Your Handle</label>
      <input
        type="text"
        id="handle"
        name="handle"
        placeholder="you.bsky.social"
        autocomplete="username"
        autocapitalize="none"
        spellcheck="false"
        required
      >
      <p class="hint">Enter your Bluesky handle or custom domain</p>

      <button type="submit" id="submitBtn">Continue</button>
    </form>
  </div>

  <script>
    const form = document.getElementById('loginForm');
    const handleInput = document.getElementById('handle');
    const submitBtn = document.getElementById('submitBtn');
    const errorDiv = document.getElementById('error');

    form.addEventListener('submit', async function(e) {
      e.preventDefault();
      const handle = handleInput.value.trim();
      if (!handle) {
        errorDiv.textContent = 'Please enter your handle';
        errorDiv.style.display = 'block';
        return;
      }
      submitBtn.disabled = true;
      submitBtn.textContent = 'Redirecting...';
      errorDiv.style.display = 'none';

      try {
        const res = await fetch('/oauth/authorize/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            auth_code: form.querySelector('[name="auth_code"]').value,
            state: form.querySelector('[name="state"]').value,
            handle: handle
          })
        });
        const data = await res.json();
        if (data.redirect_url) {
          window.location.href = data.redirect_url;
        } else {
          errorDiv.textContent = data.error || 'Login failed';
          errorDiv.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.textContent = 'Continue';
        }
      } catch (err) {
        errorDiv.textContent = 'Network error. Please try again.';
        errorDiv.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Continue';
      }
    });
  </script>
</body>
</html>`;

      res.type('html').send(loginPageHtml);
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

      // Sanitize handle: strip @, add .bsky.social if no domain
      let sanitizedHandle = handle.trim().replace(/^@/, '');
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
      const atprotoAuth = await oauthService.generateAuthUrl(
        authData.client_id,
        sanitizedHandle,
        `${oidcService.issuer}/oauth/callback`
      );

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
        userMessage = 'Could not find that Bluesky handle. Enter your full handle (e.g. yourname.bsky.social).';
      }
      const isJsonRequest = req.is('json');
      if (isJsonRequest) {
        res.status(400).json({ error: userMessage });
      } else {
        res.status(400).send(userMessage);
      }
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

      const callbackResult = await oauthService.handleCallback(callbackParams);
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
