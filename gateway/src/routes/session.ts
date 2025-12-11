/**
 * Session Routes
 *
 * Endpoints for session conflict detection and resolution
 */

import { Router, Request, Response } from 'express';
import { DatabaseService } from '../services/database.js';
import { createGatewayToken } from '../utils/hmac.js';
import type { SessionResolution, SessionConflict } from '../types/index.js';

export function createSessionRoutes(db: DatabaseService): Router {
  const router = Router();

  /**
   * POST /session/check-conflict
   * Check for existing active sessions
   */
  router.post('/check-conflict', async (req: Request, res: Response) => {
    try {
      const { session_id, app_id } = req.body;

      if (!session_id || typeof session_id !== 'string') {
        return res.status(400).json({
          error: 'missing_session_id',
          message: 'session_id is required',
        });
      }

      if (!app_id || typeof app_id !== 'string') {
        return res.status(400).json({
          error: 'missing_app_id',
          message: 'app_id is required',
        });
      }

      const pendingSession = db.getSession(session_id);
      if (!pendingSession) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Pending session not found or expired',
        });
      }

      const activeSessions = db.getActiveSessionsByDid(pendingSession.did, app_id);
      const otherSessions = activeSessions.filter((s) => s.id !== session_id);

      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const conflictingSessions = otherSessions.filter(
        (s) => s.connection_state === 'connected' || s.last_activity > fiveMinutesAgo
      );

      const response: SessionConflict = {
        has_conflict: conflictingSessions.length > 0,
        existing_sessions: conflictingSessions.map((s) => ({
          session_id: s.id,
          created_at: s.created_at.toISOString(),
          last_activity: s.last_activity.toISOString(),
          connection_state: s.connection_state,
          client_info: s.client_info,
        })),
        pending_session_id: session_id,
      };

      res.json(response);
    } catch (error) {
      console.error('Check conflict error:', error);
      res.status(500).json({
        error: 'check_conflict_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /session/resolve-conflict
   * Resolve a session conflict
   */
  router.post('/resolve-conflict', async (req: Request, res: Response) => {
    try {
      const { session_id, app_id, resolution } = req.body;

      if (!session_id || !app_id) {
        return res.status(400).json({
          error: 'missing_params',
          message: 'session_id and app_id are required',
        });
      }

      const validResolutions: SessionResolution[] = ['transfer', 'cancel', 'close_others'];
      if (!resolution || !validResolutions.includes(resolution)) {
        return res.status(400).json({
          error: 'invalid_resolution',
          message: "resolution must be: 'transfer', 'cancel', or 'close_others'",
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or expired',
        });
      }

      const app = db.getApp(app_id);
      if (!app) {
        return res.status(404).json({
          error: 'app_not_found',
          message: 'Application not found',
        });
      }

      switch (resolution as SessionResolution) {
        case 'cancel':
          db.deleteSession(session_id);
          return res.json({
            success: true,
            action: 'cancelled',
            message: 'Login cancelled',
          });

        case 'close_others':
        case 'transfer': {
          const closedCount = db.deleteOtherSessions(session_id, session.did, app_id);
          db.updateSessionConnectionState(session_id, 'pending');

          const mapping = db.getUserMapping(session.did, app_id);
          const userId = mapping?.user_id ?? session.user_id;

          const token = createGatewayToken(
            {
              did: session.did,
              handle: session.handle,
              user_id: userId,
              app_id,
            },
            app.hmac_secret,
            app.token_ttl_seconds
          );

          return res.json({
            success: true,
            action: resolution === 'transfer' ? 'transferred' : 'closed_others',
            closed_count: closedCount,
            token,
            session_id,
            did: session.did,
            handle: session.handle,
            user_id: userId,
          });
        }
      }
    } catch (error) {
      console.error('Resolve conflict error:', error);
      res.status(500).json({
        error: 'resolve_conflict_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /session/update-state
   * Update session connection state
   */
  router.post('/update-state', async (req: Request, res: Response) => {
    try {
      const { session_id, state, client_info } = req.body;

      if (!session_id) {
        return res.status(400).json({
          error: 'missing_session_id',
          message: 'session_id is required',
        });
      }

      const validStates = ['connected', 'disconnected', 'pending'];
      if (!state || !validStates.includes(state)) {
        return res.status(400).json({
          error: 'invalid_state',
          message: "state must be: 'connected', 'disconnected', or 'pending'",
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found',
        });
      }

      db.updateSessionConnectionState(session_id, state, client_info);

      res.json({ success: true, session_id, state });
    } catch (error) {
      console.error('Update state error:', error);
      res.status(500).json({
        error: 'update_state_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /session/heartbeat
   * Update session last activity
   */
  router.post('/heartbeat', async (req: Request, res: Response) => {
    try {
      const { session_id } = req.body;

      if (!session_id) {
        return res.status(400).json({
          error: 'missing_session_id',
          message: 'session_id is required',
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or expired',
        });
      }

      db.updateSessionActivity(session_id);

      res.json({ success: true, session_id });
    } catch (error) {
      console.error('Heartbeat error:', error);
      res.status(500).json({
        error: 'heartbeat_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /session/active
   * List all active sessions for the user
   */
  router.get('/active', async (req: Request, res: Response) => {
    try {
      const { session_id, app_id } = req.query;

      if (!session_id || typeof session_id !== 'string') {
        return res.status(400).json({
          error: 'missing_session_id',
          message: 'session_id is required',
        });
      }

      if (!app_id || typeof app_id !== 'string') {
        return res.status(400).json({
          error: 'missing_app_id',
          message: 'app_id is required',
        });
      }

      const session = db.getSession(session_id);
      if (!session) {
        return res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or expired',
        });
      }

      const activeSessions = db.getActiveSessionsByDid(session.did, app_id);

      res.json({
        sessions: activeSessions.map((s) => ({
          session_id: s.id,
          is_current: s.id === session_id,
          created_at: s.created_at.toISOString(),
          last_activity: s.last_activity.toISOString(),
          connection_state: s.connection_state,
          client_info: s.client_info,
        })),
      });
    } catch (error) {
      console.error('List active sessions error:', error);
      res.status(500).json({
        error: 'list_sessions_failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  return router;
}
