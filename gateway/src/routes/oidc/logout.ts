/**
 * OIDC End Session Endpoint
 *
 * Handles /oauth/end_session - RP-initiated logout
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../../services/database.js';
import type { OIDCService } from '../../services/oidc/index.js';

export function createLogoutRouter(db: DatabaseService, oidcService: OIDCService): Router {
  const router = Router();

  /**
   * GET /oauth/end_session
   * RP-initiated logout
   */
  router.get('/end_session', async (req: Request, res: Response) => {
    try {
      const {
        id_token_hint,
        client_id,
        post_logout_redirect_uri,
        state,
      } = req.query as {
        id_token_hint?: string;
        client_id?: string;
        post_logout_redirect_uri?: string;
        state?: string;
      };

      let sub: string | undefined;
      let tokenClientId: string | undefined;

      // Verify id_token_hint if provided
      if (id_token_hint) {
        const claims = oidcService.tokenService.verifyIdToken(id_token_hint);
        if (claims) {
          sub = claims.sub;
          tokenClientId = claims.aud;
        }
      }

      // Use client_id from token or parameter
      const effectiveClientId = client_id || tokenClientId;

      // Validate post_logout_redirect_uri if provided
      if (post_logout_redirect_uri && effectiveClientId) {
        const client = db.getOIDCClient(effectiveClientId);
        if (!client) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Unknown client',
          });
        }

        // Check if redirect URI is registered
        // For logout, we could have a separate list, but for simplicity use redirect_uris
        if (!client.redirect_uris.some((uri) => post_logout_redirect_uri.startsWith(uri.split('?')[0]))) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Invalid post_logout_redirect_uri',
          });
        }
      }

      // Revoke all refresh tokens for this user and client
      if (sub && effectiveClientId) {
        db.revokeAllRefreshTokensForUser(sub, effectiveClientId);
      }

      // If we have a post_logout_redirect_uri, redirect there
      if (post_logout_redirect_uri) {
        const redirectUrl = new URL(post_logout_redirect_uri);
        if (state) {
          redirectUrl.searchParams.set('state', state);
        }
        return res.redirect(redirectUrl.toString());
      }

      // Otherwise, show a logged out page
      res.send(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>Logged Out - ATAuth</title>
            <style>
              body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background-color: #f5f5f5;
              }
              .container {
                text-align: center;
                padding: 2rem;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
              }
              h1 { color: #333; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Logged Out</h1>
              <p>You have been successfully logged out.</p>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      console.error('[OIDC Logout] Error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error',
      });
    }
  });

  return router;
}
