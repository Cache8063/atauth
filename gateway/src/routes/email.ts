/**
 * Email Routes
 *
 * Handles email verification and account recovery endpoints
 */

import { Router, Request, Response } from 'express';
import type { DatabaseService } from '../services/database.js';
import type { EmailService } from '../services/email.js';
import type { OIDCService } from '../services/oidc/index.js';
import { HttpError } from '../utils/errors.js';

export function createEmailRouter(
  db: DatabaseService,
  emailService: EmailService,
  oidcService: OIDCService | null
): Router {
  const router = Router();

  /**
   * POST /auth/email/add
   * Add an email to the authenticated user's account
   */
  router.post('/add', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { email } = req.body as { email: string };

      if (!email || !isValidEmail(email)) {
        throw new HttpError(400, 'invalid_request', 'Invalid email address');
      }

      const result = await emailService.addEmail(did, email);

      if (!result.success) {
        throw new HttpError(400, 'add_failed', result.error || 'Failed to add email');
      }

      res.json({
        success: true,
        message: 'Verification code sent to email',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/email/verify
   * Verify an email address with a code
   */
  router.post('/verify', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { email, code } = req.body as { email: string; code: string };

      if (!email || !code) {
        throw new HttpError(400, 'invalid_request', 'Missing email or code');
      }

      const result = emailService.verifyEmail(did, email, code);

      if (!result.success) {
        throw new HttpError(400, 'verification_failed', result.error || 'Verification failed');
      }

      res.json({
        success: true,
        message: 'Email verified successfully',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/email/resend
   * Resend verification code to an email
   */
  router.post('/resend', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { email } = req.body as { email: string };

      if (!email) {
        throw new HttpError(400, 'invalid_request', 'Missing email');
      }

      const result = await emailService.resendVerificationCode(email);

      if (!result.success) {
        throw new HttpError(400, 'resend_failed', result.error || 'Failed to resend code');
      }

      res.json({
        success: true,
        message: 'Verification code resent',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * DELETE /auth/email/:email
   * Remove an email from the authenticated user's account
   */
  router.delete('/:email', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const email = String(req.params.email);

      if (!email || !isValidEmail(email)) {
        throw new HttpError(400, 'invalid_request', 'Invalid email address');
      }

      const result = emailService.removeEmail(did, email);

      if (!result.success) {
        throw new HttpError(400, 'remove_failed', result.error || 'Failed to remove email');
      }

      res.json({
        success: true,
        message: 'Email removed successfully',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/email/set-primary
   * Set an email as primary
   */
  router.post('/set-primary', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const { email } = req.body as { email: string };

      if (!email) {
        throw new HttpError(400, 'invalid_request', 'Missing email');
      }

      const result = emailService.setPrimaryEmail(did, email);

      if (!result.success) {
        throw new HttpError(400, 'set_primary_failed', result.error || 'Failed to set primary email');
      }

      res.json({
        success: true,
        message: 'Primary email updated',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * GET /auth/email/list
   * List user's emails
   */
  router.get('/list', async (req: Request, res: Response) => {
    try {
      const { did } = await authenticateRequest(req, db, oidcService);

      if (!did) {
        throw new HttpError(401, 'unauthorized', 'Authentication required');
      }

      const emails = emailService.getUserEmails(did);

      res.json({
        success: true,
        emails: emails.map(e => ({
          email: e.email,
          verified: e.verified,
          is_primary: e.is_primary,
          verified_at: e.verified_at?.toISOString(),
          created_at: e.created_at.toISOString(),
        })),
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/recovery/request
   * Request account recovery via email
   */
  router.post('/recovery/request', async (req: Request, res: Response) => {
    try {
      const { email } = req.body as { email: string };

      if (!email || !isValidEmail(email)) {
        throw new HttpError(400, 'invalid_request', 'Invalid email address');
      }

      await emailService.requestRecovery(email);

      // Always return success to avoid email enumeration
      res.json({
        success: true,
        message: 'If an account exists with this email, a recovery code has been sent',
      });
    } catch (error) {
      handleError(res, error);
    }
  });

  /**
   * POST /auth/recovery/verify
   * Verify recovery code
   */
  router.post('/recovery/verify', async (req: Request, res: Response) => {
    try {
      const { email, code, client_id, scope } = req.body as {
        email: string;
        code: string;
        client_id?: string;
        scope?: string;
      };

      if (!email || !code) {
        throw new HttpError(400, 'invalid_request', 'Missing email or code');
      }

      const result = emailService.verifyRecovery(email, code);

      if (!result.success || !result.did) {
        throw new HttpError(401, 'verification_failed', result.error || 'Verification failed');
      }

      // If OIDC service is available and client_id is provided, issue tokens
      if (oidcService && client_id) {
        const client = db.getOIDCClient(client_id);
        const mapping = db.getUserMapping(result.did, client_id);
        if (client) {
          // Restrict recovery scope to standard scopes only
          const allowedRecoveryScopes = ['openid', 'profile', 'email'];
          const requestedScopes = (scope || 'openid').split(' ');
          const validatedScope = requestedScopes
            .filter((s: string) => allowedRecoveryScopes.includes(s))
            .join(' ') || 'openid';

          const tokenResponse = oidcService.tokenService.createTokenResponse({
            sub: result.did,
            clientId: client_id,
            scope: validatedScope,
            did: result.did,
            handle: mapping?.handle || '',
            accessTokenTtl: client.access_token_ttl_seconds,
            idTokenTtl: client.id_token_ttl_seconds,
          });

          return res.json({
            success: true,
            did: result.did,
            tokens: tokenResponse,
          });
        }
      }

      res.json({
        success: true,
        did: result.did,
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
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  if (email.length > 254) return false; // RFC 5321 max length
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email);
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

  console.error('[Email] Error:', error);
  res.status(500).json({
    error: 'server_error',
    message: 'Internal server error',
  });
}
