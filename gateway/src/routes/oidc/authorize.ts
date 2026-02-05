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
      if (!client.redirect_uris.includes(redirect_uri)) {
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

      // Store state for callback
      // We use the AT Protocol OAuth flow as the identity provider
      // Generate AT Protocol OAuth URL
      const atprotoAuth = await oauthService.generateAuthUrl(
        client_id,
        '', // No handle yet - will be filled by user
        `${oidcService.issuer}/oauth/callback`
      );

      if (!atprotoAuth) {
        return redirectWithError(res, redirect_uri, state, 'server_error', 'Failed to generate auth URL');
      }

      // Store our OIDC state in the database, keyed by AT Protocol state
      const atprotoState = atprotoAuth.state;
      if (atprotoState) {
        db.saveAuthorizationCode({
          code: authCode,
          client_id,
          redirect_uri,
          scope: scopeValidation.scopes.join(' '),
          nonce,
          code_challenge,
          code_challenge_method: code_challenge_method as 'S256' | 'plain' | undefined,
          did: '', // Will be filled on callback
          handle: '', // Will be filled on callback
          created_at: authState.created_at,
          expires_at: authState.expires_at,
          used: false,
        });

        // Store mapping from AT Protocol state to our auth code
        db.saveOAuthState({
          state: atprotoState,
          code_verifier: authCode, // Reuse this field to store our auth code
          app_id: client_id,
          redirect_uri,
          created_at: authState.created_at,
        });
      }

      // Redirect user to AT Protocol OAuth
      res.redirect(atprotoAuth.url);
    } catch (error) {
      console.error('[OIDC Authorize] Error:', error);
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
