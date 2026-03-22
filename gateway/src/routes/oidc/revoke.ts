/**
 * OIDC Token Revocation Endpoint
 *
 * Handles /oauth/revoke - revokes access or refresh tokens
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../../services/database.js';

export function createRevokeRouter(db: DatabaseService): Router {
  const router = Router();

  /**
   * POST /oauth/revoke
   * Revoke an access token or refresh token
   */
  router.post('/revoke', async (req: Request, res: Response) => {
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

      const {
        token,
        token_type_hint,
        client_id: bodyClientId,
        client_secret: bodyClientSecret,
      } = req.body as {
        token?: string;
        token_type_hint?: string;
        client_id?: string;
        client_secret?: string;
      };

      clientId = bodyClientId || clientId;
      clientSecret = bodyClientSecret || clientSecret;

      if (!token) {
        // Per RFC 7009, invalid tokens should return 200 OK
        res.status(200).send();
        return;
      }

      // Get client configuration
      if (clientId) {
        const client = db.getOIDCClient(clientId);
        if (!client) {
          res.status(401).json({
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
      }

      // Try to revoke as refresh token first
      if (!token_type_hint || token_type_hint === 'refresh_token') {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const refreshToken = db.getRefreshToken(tokenHash);

        if (refreshToken) {
          // Verify client owns this token
          if (clientId && refreshToken.client_id !== clientId) {
            // Token doesn't belong to this client, return success anyway (per RFC)
            res.status(200).send();
            return;
          }

          // Revoke the token and its entire family
          db.revokeRefreshToken(tokenHash);
          if (refreshToken.family_id) {
            db.revokeRefreshTokenFamily(refreshToken.family_id);
          }

          res.status(200).send();
          return;
        }
      }

      // Try to blacklist as an access token (JWT)
      try {
        const parts = token.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as {
            jti?: string;
            exp?: number;
            client_id?: string;
          };

          if (payload.jti && payload.exp) {
            // Verify client ownership if client_id provided
            if (clientId && payload.client_id && payload.client_id !== clientId) {
              res.status(200).send();
              return;
            }
            db.addRevokedToken(payload.jti, payload.exp);
          }
        }
      } catch {
        // Not a valid JWT — ignore per RFC 7009
      }

      res.status(200).send();
    } catch (error) {
      console.error('[OIDC Revoke] Error:', error);
      // Per RFC 7009, errors should still return 200 if the token is invalid
      res.status(200).send();
    }
  });

  return router;
}
