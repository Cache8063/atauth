/**
 * MFA Routes
 *
 * Handles TOTP setup, verification, and backup code management
 */

import { Router, Request, Response } from 'express';
import type { DatabaseService } from '../services/database.js';
import type { MFAService } from '../services/mfa.js';
import type { PasskeyService } from '../services/passkey.js';
import type { OIDCService } from '../services/oidc/index.js';
import { HttpError } from '../utils/errors.js';

export function createMFARouter(
  db: DatabaseService,
  mfaService: MFAService,
  passkeyService: PasskeyService | null,
  oidcService: OIDCService | null
): Router {
  const router = Router();

  /**
   * POST /auth/mfa/totp/setup
   * Start TOTP setup - returns secret and QR code
   */
  router.post('/totp/setup', async (req: Request, res: Response) => {
    try {
      const { did, handle } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      // Check if TOTP is already enabled
      if (mfaService.isTOTPEnabled(did)) {
        throw new HttpError(400, 'already_enabled', 'TOTP is already enabled');
      }

      const setup = await mfaService.setupTOTP(did, handle || '');

      res.json({
        success: true,
        ...setup,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/mfa/totp/verify-setup
   * Verify TOTP code during setup to enable TOTP
   */
  router.post('/totp/verify-setup', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { code } = req.body as { code: string };

      if (!code) {
        throw new HttpError(400, 'invalid_request', 'Missing code');
      }

      const success = mfaService.verifyAndEnableTOTP(did, code);

      if (!success) {
        throw new HttpError(400, 'invalid_code', 'Invalid verification code');
      }

      // Generate backup codes
      const backupCodes = mfaService.generateBackupCodes(did);

      res.json({
        success: true,
        message: 'TOTP enabled successfully',
        backup_codes: backupCodes,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/mfa/totp/verify
   * Verify TOTP code during login
   * Requires authentication -- DID comes from the authenticated session, not the request body
   */
  router.post('/totp/verify', async (req: Request, res: Response) => {
    try {
      const { did: authedDid } = await authenticateRequest(req, db, oidcService);
      const { code, client_id, scope } = req.body as {
        code: string;
        client_id?: string;
        scope?: string;
      };

      const did = authedDid;
      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      if (!code) {
        throw new HttpError(400, 'invalid_request', 'Missing code');
      }

      const success = mfaService.verifyTOTP(did, code);

      if (!success) {
        throw new HttpError(401, 'invalid_code', 'Invalid TOTP code');
      }

      // If OIDC service is available and client_id is provided, issue tokens
      if (oidcService && client_id) {
        const client = db.getOIDCClient(client_id);
        const mapping = db.getUserMapping(did, client_id);
        if (client) {
          const tokenResponse = oidcService.tokenService.createTokenResponse({
            sub: did,
            clientId: client_id,
            scope: scope || 'openid',
            did,
            handle: mapping?.handle || '',
            accessTokenTtl: client.access_token_ttl_seconds,
            idTokenTtl: client.id_token_ttl_seconds,
          });

          return res.json({
            success: true,
            did,
            tokens: tokenResponse,
          });
        }
      }

      res.json({
        success: true,
        did,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/mfa/totp/disable
   * Disable TOTP for the authenticated user
   */
  router.post('/totp/disable', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { code } = req.body as { code: string };

      if (!code) {
        throw new HttpError(400, 'invalid_request', 'Missing code');
      }

      // Verify code before disabling
      const verified = mfaService.verifyTOTP(did, code);
      if (!verified) {
        throw new HttpError(401, 'invalid_code', 'Invalid TOTP code');
      }

      mfaService.disableTOTP(did);

      res.json({
        success: true,
        message: 'TOTP disabled successfully',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/mfa/backup-codes
   * Generate new backup codes (regenerates all codes)
   */
  router.post('/backup-codes', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { code } = req.body as { code: string };

      // Require TOTP verification to regenerate backup codes
      if (!mfaService.isTOTPEnabled(did)) {
        throw new HttpError(400, 'totp_not_enabled', 'TOTP must be enabled to generate backup codes');
      }

      if (!code) {
        throw new HttpError(400, 'invalid_request', 'Missing TOTP code');
      }

      const verified = mfaService.verifyTOTP(did, code);
      if (!verified) {
        throw new HttpError(401, 'invalid_code', 'Invalid TOTP code');
      }

      const backupCodes = mfaService.generateBackupCodes(did);

      res.json({
        success: true,
        codes: backupCodes,
        generated_at: new Date().toISOString(),
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/mfa/backup-codes/verify
   * Verify a backup code during login
   * Requires authentication -- DID comes from the authenticated session, not the request body
   */
  router.post('/backup-codes/verify', async (req: Request, res: Response) => {
    try {
      const { did: authedDid } = await authenticateRequest(req, db, oidcService);
      const { code, client_id, scope } = req.body as {
        code: string;
        client_id?: string;
        scope?: string;
      };

      const did = authedDid;
      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      if (!code) {
        throw new HttpError(400, 'invalid_request', 'Missing code');
      }

      const success = mfaService.verifyBackupCode(did, code);

      if (!success) {
        throw new HttpError(401, 'invalid_code', 'Invalid backup code');
      }

      // If OIDC service is available and client_id is provided, issue tokens
      if (oidcService && client_id) {
        const client = db.getOIDCClient(client_id);
        const mapping = db.getUserMapping(did, client_id);
        if (client) {
          const tokenResponse = oidcService.tokenService.createTokenResponse({
            sub: did,
            clientId: client_id,
            scope: scope || 'openid',
            did,
            handle: mapping?.handle || '',
            accessTokenTtl: client.access_token_ttl_seconds,
            idTokenTtl: client.id_token_ttl_seconds,
          });

          return res.json({
            success: true,
            did,
            tokens: tokenResponse,
          });
        }
      }

      res.json({
        success: true,
        did,
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * GET /auth/mfa/status
   * Get MFA status for the authenticated user
   */
  router.get('/status', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const passkeyCount = passkeyService?.getPasskeyCount(did) ?? 0;
      const status = mfaService.getMFAStatus(did, passkeyCount);

      res.json({
        success: true,
        ...status,
      });
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
  oidcService: OIDCService | null
): Promise<{ did?: string; handle?: string }> {
  // Try to authenticate via access token
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ') && oidcService) {
    const token = authHeader.slice(7);
    const claims = oidcService.tokenService.verifyAccessToken(token);
    if (claims) {
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

  console.error('[MFA] Error:', error);
  res.status(500).json({
    error: 'server_error',
    message: 'Internal server error',
  });
}
