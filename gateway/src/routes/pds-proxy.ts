/**
 * PDS Write Proxy
 *
 * Allows authenticated client apps to write records to users' PDS
 * using ATAuth's stored OAuth sessions. The client authenticates with
 * its ATAuth access token; ATAuth restores the user's PDS session
 * and proxies the write request.
 *
 * Supported operations:
 *   POST /api/pds/write  — createRecord or putRecord
 */

import { Router, Request, Response } from 'express';
import type { OAuthService } from '../services/oauth.js';
import type { OIDCService } from '../services/oidc/index.js';

// Only allow these xRPC methods through the proxy
const ALLOWED_METHODS = new Set([
  'com.atproto.repo.createRecord',
  'com.atproto.repo.putRecord',
]);

// Only allow writing to these collections
const ALLOWED_COLLECTIONS = new Set([
  'xyz.arcnode.atchess.game',
  'xyz.arcnode.atchess.profile',
]);

export function createPdsProxyRoutes(
  oauthService: OAuthService,
  oidcService: OIDCService,
): Router {
  const router = Router();

  /**
   * POST /api/pds/write
   *
   * Body: {
   *   method: "com.atproto.repo.createRecord" | "com.atproto.repo.putRecord",
   *   body: { repo, collection, record, rkey? }
   * }
   *
   * Authorization: Bearer <atauth_access_token>
   */
  router.post('/write', async (req: Request, res: Response) => {
    try {
      // 1. Validate ATAuth access token
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'unauthorized',
          message: 'Missing Authorization header',
        });
      }

      const accessToken = authHeader.slice(7);
      const claims = oidcService.tokenService.verifyAccessToken(accessToken);
      if (!claims) {
        return res.status(401).json({
          error: 'invalid_token',
          message: 'Invalid or expired access token',
        });
      }

      const did = claims.sub;

      // 2. Validate request body
      const { method, body } = req.body;

      if (!method || !body) {
        return res.status(400).json({
          error: 'invalid_request',
          message: 'Missing method or body',
        });
      }

      if (!ALLOWED_METHODS.has(method)) {
        return res.status(403).json({
          error: 'method_not_allowed',
          message: `Method ${method} is not allowed through the proxy`,
        });
      }

      // 3. Validate collection
      if (!body.collection || !ALLOWED_COLLECTIONS.has(body.collection)) {
        return res.status(403).json({
          error: 'collection_not_allowed',
          message: `Collection ${body.collection} is not allowed`,
        });
      }

      // 4. Enforce that repo matches the authenticated user's DID
      if (body.repo && body.repo !== did) {
        return res.status(403).json({
          error: 'repo_mismatch',
          message: 'Can only write to your own repository',
        });
      }

      // Set repo to the authenticated user's DID
      body.repo = did;

      // 5. Check for PDS session
      if (!oauthService.hasPdsSession(did)) {
        return res.status(409).json({
          error: 'no_pds_session',
          message: 'No PDS session found. User may need to re-authenticate.',
        });
      }

      // 6. Proxy the request to the user's PDS
      console.log(`[PDS Proxy] ${method} for ${did} to ${body.collection}`);

      const pdsResponse = await oauthService.proxyPdsRequest(
        did,
        `/xrpc/${method}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        },
      );

      const responseBody = await pdsResponse.text();

      if (!pdsResponse.ok) {
        console.error(`[PDS Proxy] PDS returned ${pdsResponse.status}:`, responseBody);
        return res.status(pdsResponse.status).json({
          error: 'pds_error',
          message: `PDS returned ${pdsResponse.status}`,
          detail: responseBody,
        });
      }

      const result = JSON.parse(responseBody);
      console.log(`[PDS Proxy] Success: ${result.uri}`);
      return res.json(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.error('[PDS Proxy] Error:', message);

      if (message.includes('session') || message.includes('expired')) {
        return res.status(409).json({
          error: 'session_expired',
          message: 'PDS session expired. User needs to re-authenticate.',
        });
      }

      return res.status(500).json({
        error: 'proxy_error',
        message: 'Failed to proxy request to PDS',
      });
    }
  });

  return router;
}
