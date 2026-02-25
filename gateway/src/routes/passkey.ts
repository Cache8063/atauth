/**
 * Passkey Routes
 *
 * Handles WebAuthn/FIDO2 passkey registration and authentication endpoints
 */

import { Router, Request, Response } from 'express';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { DatabaseService } from '../services/database.js';
import type { PasskeyService } from '../services/passkey.js';
import type { OIDCService } from '../services/oidc/index.js';
import { HttpError } from '../utils/errors.js';
import { verifySessionCookie, parseCookies, SESSION_COOKIE_NAME } from '../utils/proxy-auth.js';

export function createPasskeyRouter(
  db: DatabaseService,
  passkeyService: PasskeyService,
  oidcService: OIDCService | null,
  sessionSecret?: string
): Router {
  const router = Router();

  /**
   * POST /auth/passkey/register/options
   * Get WebAuthn registration options
   * Requires authenticated user (via session or access token)
   */
  router.post('/register/options', async (req: Request, res: Response) => {
    try {
      const { did, handle } = await authenticateRequest(req, db, oidcService, sessionSecret);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const options = await passkeyService.generateRegistrationOptions(did, handle || '');

      res.json({
        success: true,
        options,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/passkey/register/verify
   * Verify WebAuthn registration response
   */
  router.post('/register/verify', async (req: Request, res: Response) => {
    try {
      const { did, handle } = await authenticateRequest(req, db, oidcService, sessionSecret);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { credential, name } = req.body as {
        credential: RegistrationResponseJSON;
        name?: string;
      };

      if (!credential) {
        throw new HttpError(400, 'invalid_request', 'Missing credential');
      }

      const result = await passkeyService.verifyRegistration(
        did,
        handle || '',
        credential,
        name
      );

      if (!result.success) {
        throw new HttpError(400, 'verification_failed', result.error || 'Verification failed');
      }

      res.json({
        success: true,
        passkey_id: result.credentialId,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/passkey/authenticate/options
   * Get WebAuthn authentication options
   */
  router.post('/authenticate/options', async (req: Request, res: Response) => {
    try {
      const { did } = req.body as { did?: string };

      const options = await passkeyService.generateAuthenticationOptions(did);

      res.json({
        success: true,
        options,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/passkey/authenticate/verify
   * Verify WebAuthn authentication response
   */
  router.post('/authenticate/verify', async (req: Request, res: Response) => {
    try {
      const { credential, challenge, client_id, scope } = req.body as {
        credential: AuthenticationResponseJSON;
        challenge: string;
        client_id?: string;
        scope?: string;
      };

      if (!credential || !challenge) {
        throw new HttpError(400, 'invalid_request', 'Missing credential or challenge');
      }

      const result = await passkeyService.verifyAuthentication(credential, challenge);

      if (!result.success) {
        throw new HttpError(401, 'authentication_failed', result.error || 'Authentication failed');
      }

      // If OIDC service is available and client_id is provided, issue tokens
      if (oidcService && client_id && result.did) {
        const client = db.getOIDCClient(client_id);
        if (client) {
          const tokenResponse = oidcService.tokenService.createTokenResponse({
            sub: result.did,
            clientId: client_id,
            scope: scope || 'openid',
            did: result.did,
            handle: result.handle || '',
            accessTokenTtl: client.access_token_ttl_seconds,
            idTokenTtl: client.id_token_ttl_seconds,
          });

          return res.json({
            success: true,
            did: result.did,
            handle: result.handle,
            tokens: tokenResponse,
          });
        }
      }

      // Return basic success response
      res.json({
        success: true,
        did: result.did,
        handle: result.handle,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * GET /auth/passkey/list
   * List user's registered passkeys
   */
  router.get('/list', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService, sessionSecret);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const passkeys = passkeyService.listPasskeys(did);

      res.json({
        success: true,
        passkeys,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * PUT /auth/passkey/:id
   * Rename a passkey
   */
  router.put('/:id', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService, sessionSecret);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const id = String(req.params.id);
      const { name } = req.body as { name: string };

      if (!name) {
        throw new HttpError(400, 'invalid_request', 'Missing name');
      }

      const success = passkeyService.renamePasskey(did, id, name);

      if (!success) {
        throw new HttpError(404, 'not_found', 'Passkey not found');
      }

      res.json({ success: true });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * DELETE /auth/passkey/:id
   * Delete a passkey
   */
  router.delete('/:id', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService, sessionSecret);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const id = String(req.params.id);

      // Prevent deleting last passkey if MFA is required
      // (This is a safety check - can be configured based on policy)
      const passkeyCount = passkeyService.getPasskeyCount(did);
      if (passkeyCount <= 1) {
        // Allow deletion but warn
        console.warn(`[Passkey] User ${did} is deleting their last passkey`);
      }

      const success = passkeyService.deletePasskey(did, id);

      if (!success) {
        throw new HttpError(404, 'not_found', 'Passkey not found');
      }

      res.json({ success: true });
    } catch (error) {
      handleError(res, error);
    }
  });

  return router;
}

/**
 * Authenticate request via session cookie or access token
 */
async function authenticateRequest(
  req: Request,
  db: DatabaseService,
  oidcService: OIDCService | null,
  sessionSecret?: string
): Promise<{ did?: string; handle?: string }> {
  // Try to authenticate via access token
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ') && oidcService) {
    const token = authHeader.slice(7);
    const claims = oidcService.tokenService.verifyAccessToken(token);
    if (claims) {
      // Try to get handle from user mapping
      const mapping = db.getUserMapping(claims.sub, claims.client_id);
      return {
        did: claims.sub,
        handle: mapping?.handle,
      };
    }
  }

  // Try to authenticate via session header
  const sessionId = req.headers['x-session-id'] as string;
  if (sessionId) {
    const session = db.getSession(sessionId);
    if (session && new Date(session.expires_at) > new Date()) {
      return {
        did: session.did,
        handle: session.handle,
      };
    }
  }

  // Try to authenticate via forward-auth session cookie
  if (sessionSecret) {
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies[SESSION_COOKIE_NAME];
    if (sessionCookie) {
      const proxySessionId = verifySessionCookie(sessionCookie, sessionSecret);
      if (proxySessionId) {
        const proxySession = db.getProxySession(proxySessionId);
        if (proxySession && proxySession.expires_at > Math.floor(Date.now() / 1000)) {
          return {
            did: proxySession.did,
            handle: proxySession.handle,
          };
        }
      }
    }
  }

  return {};
}

/**
 * Handle errors consistently
 */
function handleError(res: Response, error: unknown): void {
  if (error instanceof HttpError) {
    res.status(error.statusCode).json({
      error: error.code,
      message: error.message,
    });
    return;
  }

  console.error('[Passkey] Error:', error);
  res.status(500).json({
    error: 'server_error',
    message: 'Internal server error',
  });
}
