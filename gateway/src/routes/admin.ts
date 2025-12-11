/**
 * Admin Routes
 *
 * Application registration and management endpoints
 */

import { Router, Request, Response } from 'express';
import { DatabaseService } from '../services/database.js';
import { generateHmacSecret } from '../utils/hmac.js';

export function createAdminRoutes(db: DatabaseService, adminToken?: string): Router {
  const router = Router();

  const requireAdmin = (req: Request, res: Response, next: () => void) => {
    if (!adminToken) {
      return res.status(403).json({
        error: 'admin_disabled',
        message: 'Admin endpoints are disabled (set ADMIN_TOKEN)',
      });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'missing_auth',
        message: 'Authorization header required',
      });
    }

    const token = authHeader.substring(7);
    if (token !== adminToken) {
      return res.status(403).json({
        error: 'invalid_token',
        message: 'Invalid admin token',
      });
    }

    next();
  };

  /**
   * POST /admin/apps
   * Register a new application
   *
   * Body:
   * - id: Unique app identifier
   * - name: Display name
   * - token_ttl_seconds: Token lifetime (default 3600)
   * - callback_url: OAuth callback URL
   */
  router.post('/apps', requireAdmin, async (req: Request, res: Response) => {
    try {
      const { id, name, token_ttl_seconds, callback_url } = req.body;

      if (!id || !name) {
        return res.status(400).json({
          error: 'missing_params',
          message: 'id and name are required',
        });
      }

      const existing = db.getApp(id);
      if (existing) {
        return res.status(409).json({
          error: 'app_exists',
          message: `Application '${id}' already exists`,
        });
      }

      const hmac_secret = generateHmacSecret();

      db.upsertApp({
        id,
        name,
        hmac_secret,
        token_ttl_seconds: token_ttl_seconds || 3600,
        callback_url,
      });

      res.status(201).json({
        id,
        name,
        hmac_secret,
        token_ttl_seconds: token_ttl_seconds || 3600,
        callback_url,
        message: 'Application registered. Store the hmac_secret securely!',
      });
    } catch (error) {
      console.error('App registration error:', error);
      res.status(500).json({
        error: 'registration_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /admin/apps/:id
   * Get application configuration (without secret)
   */
  router.get('/apps/:id', requireAdmin, async (req: Request, res: Response) => {
    try {
      const app = db.getApp(req.params.id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: `Application '${req.params.id}' not found`,
        });
      }

      res.json({
        id: app.id,
        name: app.name,
        token_ttl_seconds: app.token_ttl_seconds,
        callback_url: app.callback_url,
      });
    } catch (error) {
      console.error('Get app error:', error);
      res.status(500).json({
        error: 'get_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * PUT /admin/apps/:id
   * Update application configuration
   */
  router.put('/apps/:id', requireAdmin, async (req: Request, res: Response) => {
    try {
      const existing = db.getApp(req.params.id);
      if (!existing) {
        return res.status(404).json({
          error: 'app_not_found',
          message: `Application '${req.params.id}' not found`,
        });
      }

      const { name, token_ttl_seconds, callback_url, rotate_secret } = req.body;

      const updated = {
        id: req.params.id,
        name: name || existing.name,
        hmac_secret: rotate_secret ? generateHmacSecret() : existing.hmac_secret,
        token_ttl_seconds: token_ttl_seconds || existing.token_ttl_seconds,
        callback_url: callback_url !== undefined ? callback_url : existing.callback_url,
      };

      db.upsertApp(updated);

      const response: Record<string, unknown> = {
        id: updated.id,
        name: updated.name,
        token_ttl_seconds: updated.token_ttl_seconds,
        callback_url: updated.callback_url,
      };

      if (rotate_secret) {
        response.hmac_secret = updated.hmac_secret;
        response.message = 'Secret rotated. Update your backend configuration!';
      }

      res.json(response);
    } catch (error) {
      console.error('Update app error:', error);
      res.status(500).json({
        error: 'update_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /admin/cleanup
   * Clean up expired sessions and OAuth states
   */
  router.post('/cleanup', requireAdmin, async (_req: Request, res: Response) => {
    try {
      const statesDeleted = db.cleanupOldOAuthStates();
      const sessionsDeleted = db.cleanupExpiredSessions();

      res.json({
        oauth_states_deleted: statesDeleted,
        sessions_deleted: sessionsDeleted,
      });
    } catch (error) {
      console.error('Cleanup error:', error);
      res.status(500).json({
        error: 'cleanup_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  return router;
}
