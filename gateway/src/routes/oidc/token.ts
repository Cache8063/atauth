/**
 * OIDC Token Endpoint
 *
 * Handles /oauth/token - exchanges authorization codes for tokens
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../../services/database.js';
import type { OIDCService } from '../../services/oidc/index.js';
import { verifyCodeChallenge, isValidCodeVerifier } from '../../services/oidc/pkce.js';
import { hasOfflineAccessScope } from '../../services/oidc/claims.js';

export function createTokenRouter(db: DatabaseService, oidcService: OIDCService): Router {
  const router = Router();

  /**
   * POST /oauth/token
   * Exchange authorization code for tokens
   */
  router.post('/token', async (req: Request, res: Response) => {
    try {
      // Parse client credentials from Authorization header or body
      let clientId: string | undefined;
      let clientSecret: string | undefined;

      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Basic ')) {
        const base64 = authHeader.slice(6);
        const decoded = Buffer.from(base64, 'base64').toString('utf8');
        const [id, secret] = decoded.split(':');
        clientId = decodeURIComponent(id);
        clientSecret = secret ? decodeURIComponent(secret) : undefined;
      }

      // Body parameters can override
      const {
        grant_type,
        code,
        redirect_uri,
        client_id: bodyClientId,
        client_secret: bodyClientSecret,
        code_verifier,
        refresh_token,
        scope,
      } = req.body as {
        grant_type?: string;
        code?: string;
        redirect_uri?: string;
        client_id?: string;
        client_secret?: string;
        code_verifier?: string;
        refresh_token?: string;
        scope?: string;
      };

      clientId = bodyClientId || clientId;
      clientSecret = bodyClientSecret || clientSecret;

      // Validate grant_type
      if (!grant_type) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing grant_type',
        });
      }

      if (grant_type === 'authorization_code') {
        return handleAuthorizationCodeGrant(
          db,
          oidcService,
          res,
          clientId,
          clientSecret,
          code,
          redirect_uri,
          code_verifier
        );
      } else if (grant_type === 'refresh_token') {
        return handleRefreshTokenGrant(db, oidcService, res, clientId, clientSecret, refresh_token, scope);
      } else {
        return res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: 'Only authorization_code and refresh_token grants are supported',
        });
      }
    } catch (error) {
      console.error('[OIDC Token] Error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  return router;
}

async function handleAuthorizationCodeGrant(
  db: DatabaseService,
  oidcService: OIDCService,
  res: Response,
  clientId: string | undefined,
  clientSecret: string | undefined,
  code: string | undefined,
  redirectUri: string | undefined,
  codeVerifier: string | undefined
): Promise<void> {
  // Validate required parameters
  if (!code || !redirectUri) {
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing code or redirect_uri',
    });
    return;
  }

  // Get the authorization code
  const authCode = db.getAuthorizationCode(code);
  if (!authCode) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid or expired authorization code',
    });
    return;
  }

  // Check if code is already used
  if (authCode.used) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used',
    });
    return;
  }

  // Check if code is expired
  if (authCode.expires_at < Math.floor(Date.now() / 1000)) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has expired',
    });
    return;
  }

  // Validate client_id matches
  if (clientId && authCode.client_id !== clientId) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'client_id does not match',
    });
    return;
  }

  clientId = authCode.client_id;

  // Validate redirect_uri matches
  if (authCode.redirect_uri !== redirectUri) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'redirect_uri does not match',
    });
    return;
  }

  // Get client configuration
  const client = db.getOIDCClient(clientId);
  if (!client) {
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client',
    });
    return;
  }

  // Validate client authentication
  if (client.token_endpoint_auth_method !== 'none') {
    if (!clientSecret) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication required',
      });
      return;
    }

    // Verify client secret (hash incoming secret and constant-time compare against stored hash)
    const expectedHash = client.client_secret;
    const incomingHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
    if (!expectedHash || !crypto.timingSafeEqual(Buffer.from(incomingHash), Buffer.from(expectedHash))) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials',
      });
      return;
    }
  }

  // Validate PKCE
  if (authCode.code_challenge) {
    if (!codeVerifier) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing code_verifier',
      });
      return;
    }

    if (!isValidCodeVerifier(codeVerifier)) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid code_verifier format',
      });
      return;
    }

    const method = authCode.code_challenge_method || 'S256';
    if (!verifyCodeChallenge(codeVerifier, authCode.code_challenge, method)) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid code_verifier',
      });
      return;
    }
  }

  // Mark code as used
  db.markAuthorizationCodeUsed(code);

  // Generate tokens
  const scopes = authCode.scope.split(' ');
  const includeRefreshToken = hasOfflineAccessScope(scopes);

  let refreshTokenValue: string | undefined;
  if (includeRefreshToken) {
    // Generate refresh token
    refreshTokenValue = crypto.randomBytes(32).toString('base64url');
    const refreshTokenHash = crypto.createHash('sha256').update(refreshTokenValue).digest('hex');
    const familyId = crypto.randomUUID();

    db.saveRefreshToken({
      token_hash: refreshTokenHash,
      client_id: clientId,
      did: authCode.did,
      handle: authCode.handle,
      user_id: authCode.user_id,
      scope: authCode.scope,
      expires_at: new Date(Date.now() + client.refresh_token_ttl_seconds * 1000),
      revoked: false,
      family_id: familyId,
    });
  }

  const tokenResponse = oidcService.tokenService.createTokenResponse({
    sub: authCode.did,
    clientId,
    scope: authCode.scope,
    did: authCode.did,
    handle: authCode.handle,
    nonce: authCode.nonce,
    accessTokenTtl: client.access_token_ttl_seconds,
    idTokenTtl: client.id_token_ttl_seconds,
    includeRefreshToken,
    refreshToken: refreshTokenValue,
  });

  res.json(tokenResponse);
}

async function handleRefreshTokenGrant(
  db: DatabaseService,
  oidcService: OIDCService,
  res: Response,
  clientId: string | undefined,
  clientSecret: string | undefined,
  refreshToken: string | undefined,
  scope: string | undefined
): Promise<void> {
  if (!refreshToken) {
    res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing refresh_token',
    });
    return;
  }

  // Hash the refresh token to look it up
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const storedToken = db.getRefreshToken(tokenHash);

  if (!storedToken) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
    });
    return;
  }

  // Check if revoked
  if (storedToken.revoked) {
    // Revoke entire family (token reuse attack detection)
    if (storedToken.family_id) {
      db.revokeRefreshTokenFamily(storedToken.family_id);
    }
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has been revoked',
    });
    return;
  }

  // Check if expired
  if (storedToken.expires_at < new Date()) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has expired',
    });
    return;
  }

  // Validate client
  if (clientId && storedToken.client_id !== clientId) {
    res.status(400).json({
      error: 'invalid_grant',
      error_description: 'client_id does not match',
    });
    return;
  }

  clientId = storedToken.client_id;

  const client = db.getOIDCClient(clientId);
  if (!client) {
    res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client',
    });
    return;
  }

  // Validate client authentication
  if (client.token_endpoint_auth_method !== 'none') {
    if (!clientSecret) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication required',
      });
      return;
    }

    const expectedHash = client.client_secret;
    const incomingHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
    if (!expectedHash || !crypto.timingSafeEqual(Buffer.from(incomingHash), Buffer.from(expectedHash))) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials',
      });
      return;
    }
  }

  // Revoke old refresh token (rotation)
  db.revokeRefreshToken(tokenHash);

  // Generate new tokens
  const tokenScope = scope || storedToken.scope;

  // Generate new refresh token
  const newRefreshToken = crypto.randomBytes(32).toString('base64url');
  const newRefreshTokenHash = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

  db.saveRefreshToken({
    token_hash: newRefreshTokenHash,
    client_id: clientId,
    did: storedToken.did,
    handle: storedToken.handle,
    user_id: storedToken.user_id,
    scope: tokenScope,
    expires_at: new Date(Date.now() + client.refresh_token_ttl_seconds * 1000),
    revoked: false,
    family_id: storedToken.family_id,
  });

  const tokenResponse = oidcService.tokenService.createTokenResponse({
    sub: storedToken.did,
    clientId,
    scope: tokenScope,
    did: storedToken.did,
    handle: storedToken.handle,
    accessTokenTtl: client.access_token_ttl_seconds,
    idTokenTtl: client.id_token_ttl_seconds,
    includeRefreshToken: true,
    refreshToken: newRefreshToken,
  });

  res.json(tokenResponse);
}
