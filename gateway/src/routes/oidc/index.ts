/**
 * OIDC Routes
 *
 * Aggregates all OIDC-related routes
 */

import { Router } from 'express';
import type { DatabaseService } from '../../services/database.js';
import type { OIDCService } from '../../services/oidc/index.js';
import type { OAuthService } from '../../services/oauth.js';
import type { PasskeyService } from '../../services/passkey.js';
import type { WebhookConfig } from '../../utils/webhook.js';

import { createDiscoveryRouter } from './discovery.js';
import { createAuthorizeRouter } from './authorize.js';
import { createTokenRouter } from './token.js';
import { createUserInfoRouter } from './userinfo.js';
import { createRevokeRouter } from './revoke.js';
import { createLogoutRouter } from './logout.js';

export function createOIDCRouter(
  db: DatabaseService,
  oidcService: OIDCService,
  oauthService: OAuthService,
  passkeyService?: PasskeyService | null,
  webhookConfig?: WebhookConfig
): { wellKnownRouter: Router; oauthRouter: Router } {
  // Discovery endpoints go under /.well-known
  const wellKnownRouter = createDiscoveryRouter(oidcService);

  // OAuth/OIDC endpoints go under /oauth
  const oauthRouter = Router();

  // Mount sub-routers
  const authorizeRouter = createAuthorizeRouter(db, oidcService, oauthService, passkeyService, webhookConfig);
  const tokenRouter = createTokenRouter(db, oidcService);
  const userInfoRouter = createUserInfoRouter(db, oidcService);
  const revokeRouter = createRevokeRouter(db);
  const logoutRouter = createLogoutRouter(db, oidcService);

  oauthRouter.use('/', authorizeRouter);
  oauthRouter.use('/', tokenRouter);
  oauthRouter.use('/', userInfoRouter);
  oauthRouter.use('/', revokeRouter);
  oauthRouter.use('/', logoutRouter);

  return { wellKnownRouter, oauthRouter };
}

export { createDiscoveryRouter } from './discovery.js';
export { createAuthorizeRouter } from './authorize.js';
export { createTokenRouter } from './token.js';
export { createUserInfoRouter } from './userinfo.js';
export { createRevokeRouter } from './revoke.js';
export { createLogoutRouter } from './logout.js';
