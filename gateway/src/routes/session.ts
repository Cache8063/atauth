/**
 * Session Routes
 *
 * Endpoints for session conflict detection and resolution.
 * Express 5 automatically forwards async errors to the error handler.
 */

import { Router, Request, Response } from 'express';
import { DatabaseService } from '../services/database.js';
import { createGatewayToken } from '../utils/hmac.js';
import { httpError } from '../utils/errors.js';
import type { SessionResolution, SessionConflict } from '../types/index.js';

export function createSessionRoutes(db: DatabaseService): Router {
  const router = Router();

  /**
   * POST /session/check-conflict
   * Check for existing active sessions
   */
  router.post('/check-conflict', async (req: Request, res: Response) => {
    const { session_id, app_id } = req.body;

    if (!session_id || typeof session_id !== 'string') {
      throw httpError.badRequest('missing_session_id', 'session_id is required');
    }

    if (!app_id || typeof app_id !== 'string') {
      throw httpError.badRequest('missing_app_id', 'app_id is required');
    }

    const pendingSession = db.getSession(session_id);
    if (!pendingSession) {
      throw httpError.notFound('session_not_found', 'Pending session not found or expired');
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
  });

  /**
   * POST /session/resolve-conflict
   * Resolve a session conflict
   */
  router.post('/resolve-conflict', async (req: Request, res: Response) => {
    const { session_id, app_id, resolution } = req.body;

    if (!session_id || !app_id) {
      throw httpError.badRequest('missing_params', 'session_id and app_id are required');
    }

    const validResolutions: SessionResolution[] = ['transfer', 'cancel', 'close_others'];
    if (!resolution || !validResolutions.includes(resolution)) {
      throw httpError.badRequest('invalid_resolution', "resolution must be: 'transfer', 'cancel', or 'close_others'");
    }

    const session = db.getSession(session_id);
    if (!session) {
      throw httpError.notFound('session_not_found', 'Session not found or expired');
    }

    const app = db.getApp(app_id);
    if (!app) {
      throw httpError.notFound('app_not_found', 'Application not found');
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
  });

  /**
   * POST /session/update-state
   * Update session connection state
   */
  router.post('/update-state', async (req: Request, res: Response) => {
    const { session_id, state, client_info } = req.body;

    if (!session_id) {
      throw httpError.badRequest('missing_session_id', 'session_id is required');
    }

    const validStates = ['connected', 'disconnected', 'pending'];
    if (!state || !validStates.includes(state)) {
      throw httpError.badRequest('invalid_state', "state must be: 'connected', 'disconnected', or 'pending'");
    }

    const session = db.getSession(session_id);
    if (!session) {
      throw httpError.notFound('session_not_found', 'Session not found');
    }

    db.updateSessionConnectionState(session_id, state, client_info);

    res.json({ success: true, session_id, state });
  });

  /**
   * POST /session/heartbeat
   * Update session last activity
   */
  router.post('/heartbeat', async (req: Request, res: Response) => {
    const { session_id } = req.body;

    if (!session_id) {
      throw httpError.badRequest('missing_session_id', 'session_id is required');
    }

    const session = db.getSession(session_id);
    if (!session) {
      throw httpError.notFound('session_not_found', 'Session not found or expired');
    }

    db.updateSessionActivity(session_id);

    res.json({ success: true, session_id });
  });

  /**
   * GET /session/active
   * List all active sessions for the user
   */
  router.get('/active', async (req: Request, res: Response) => {
    const { session_id, app_id } = req.query;

    if (!session_id || typeof session_id !== 'string') {
      throw httpError.badRequest('missing_session_id', 'session_id is required');
    }

    if (!app_id || typeof app_id !== 'string') {
      throw httpError.badRequest('missing_app_id', 'app_id is required');
    }

    const session = db.getSession(session_id);
    if (!session) {
      throw httpError.notFound('session_not_found', 'Session not found or expired');
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
  });

  return router;
}
