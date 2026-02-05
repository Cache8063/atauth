/**
 * OIDC Discovery Routes
 *
 * Handles /.well-known/openid-configuration and /.well-known/jwks.json
 */

import { Router } from 'express';
import type { OIDCService } from '../../services/oidc/index.js';

export function createDiscoveryRouter(oidcService: OIDCService): Router {
  const router = Router();

  /**
   * GET /.well-known/openid-configuration
   * OpenID Connect Discovery Document
   */
  router.get('/openid-configuration', (_req, res) => {
    const discoveryDoc = oidcService.getDiscoveryDocument();
    res.json(discoveryDoc);
  });

  /**
   * GET /.well-known/jwks.json
   * JSON Web Key Set
   */
  router.get('/jwks.json', (_req, res) => {
    const jwks = oidcService.getJWKS();
    res.json(jwks);
  });

  return router;
}
