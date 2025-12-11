/**
 * Token Routes
 *
 * Token verification and management endpoints
 */

import { Router, Request, Response } from 'express';
import { DatabaseService } from '../services/database.js';
import { verifyGatewayToken } from '../utils/hmac.js';

export function createTokenRoutes(db: DatabaseService): Router {
  const router = Router();

  /**
   * POST /token/verify
   * Verify a gateway token (for backend servers)
   *
   * Body:
   * - token: The gateway token to verify
   * - app_id: The application identifier
   */
  router.post('/verify', async (req: Request, res: Response) => {
    try {
      const { token, app_id } = req.body;

      if (!token || !app_id) {
        return res.status(400).json({
          valid: false,
          error: 'missing_params',
          message: 'token and app_id are required',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          valid: false,
          error: 'app_not_found',
          message: `Application '${app_id}' is not registered`,
        });
      }

      const payload = verifyGatewayToken(token, app.hmac_secret);
      if (!payload) {
        return res.status(401).json({
          valid: false,
          error: 'invalid_token',
          message: 'Token is invalid or expired',
        });
      }

      if (payload.app_id !== app_id) {
        return res.status(401).json({
          valid: false,
          error: 'app_mismatch',
          message: 'Token was issued for a different application',
        });
      }

      res.json({
        valid: true,
        payload: {
          did: payload.did,
          handle: payload.handle,
          user_id: payload.user_id,
          app_id: payload.app_id,
          exp: payload.exp,
        },
      });
    } catch (error) {
      console.error('Token verify error:', error);
      res.status(500).json({
        valid: false,
        error: 'verify_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /token/info
   * Get information about a token
   */
  router.get('/info', async (req: Request, res: Response) => {
    try {
      const { token, app_id } = req.query;

      if (!token || typeof token !== 'string' || !app_id || typeof app_id !== 'string') {
        return res.status(400).json({
          error: 'missing_params',
          message: 'token and app_id query parameters are required',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: `Application '${app_id}' is not registered`,
        });
      }

      const payload = verifyGatewayToken(token, app.hmac_secret);
      if (!payload) {
        return res.status(401).json({
          error: 'invalid_token',
          message: 'Token is invalid or expired',
        });
      }

      const now = Math.floor(Date.now() / 1000);
      const remainingSeconds = payload.exp - now;

      res.json({
        did: payload.did,
        handle: payload.handle,
        user_id: payload.user_id,
        app_id: payload.app_id,
        issued_at: new Date(payload.iat * 1000).toISOString(),
        expires_at: new Date(payload.exp * 1000).toISOString(),
        remaining_seconds: remainingSeconds,
      });
    } catch (error) {
      console.error('Token info error:', error);
      res.status(500).json({
        error: 'info_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  return router;
}
