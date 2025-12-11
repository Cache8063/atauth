/**
 * Database Service
 *
 * SQLite database for OAuth state, app sessions, and user mappings
 */

import Database from 'better-sqlite3';
import path from 'path';
import type {
  AppConfig,
  AppSession,
  OAuthState,
  UserMapping,
  SessionConnectionState,
  ActiveSession,
} from '../types/index.js';

export class DatabaseService {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const defaultPath = path.join(process.cwd(), 'data', 'gateway.db');
    this.db = new Database(dbPath || defaultPath);
    this.initialize();
  }

  private initialize(): void {
    // Enable WAL mode for better concurrency
    this.db.pragma('journal_mode = WAL');

    // Create tables
    this.db.exec(`
      -- Application configurations (HMAC secrets per app)
      CREATE TABLE IF NOT EXISTS apps (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        hmac_secret TEXT NOT NULL,
        token_ttl_seconds INTEGER DEFAULT 3600,
        callback_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- OAuth state for PKCE flow
      CREATE TABLE IF NOT EXISTS oauth_states (
        state TEXT PRIMARY KEY,
        code_verifier TEXT NOT NULL,
        app_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (app_id) REFERENCES apps(id)
      );

      -- User mappings (DID -> app user_id)
      CREATE TABLE IF NOT EXISTS user_mappings (
        did TEXT NOT NULL,
        app_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        handle TEXT,
        linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (did, app_id),
        FOREIGN KEY (app_id) REFERENCES apps(id)
      );

      -- Active sessions
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        handle TEXT NOT NULL,
        user_id INTEGER,
        app_id TEXT NOT NULL,
        refresh_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        connection_state TEXT DEFAULT 'pending',
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_info TEXT,
        FOREIGN KEY (app_id) REFERENCES apps(id)
      );

      -- Indexes
      CREATE INDEX IF NOT EXISTS idx_oauth_states_created ON oauth_states(created_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_did_app ON sessions(did, app_id);
    `);
  }

  // App configuration methods
  getApp(appId: string): AppConfig | null {
    const stmt = this.db.prepare('SELECT * FROM apps WHERE id = ?');
    const row = stmt.get(appId) as AppConfig | undefined;
    return row || null;
  }

  upsertApp(app: AppConfig): void {
    const stmt = this.db.prepare(`
      INSERT INTO apps (id, name, hmac_secret, token_ttl_seconds, callback_url)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        hmac_secret = excluded.hmac_secret,
        token_ttl_seconds = excluded.token_ttl_seconds,
        callback_url = excluded.callback_url
    `);
    stmt.run(app.id, app.name, app.hmac_secret, app.token_ttl_seconds, app.callback_url);
  }

  // OAuth state methods
  saveOAuthState(state: OAuthState): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO oauth_states (state, code_verifier, app_id, redirect_uri, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(state.state, state.code_verifier, state.app_id, state.redirect_uri, state.created_at);
  }

  getOAuthState(state: string): OAuthState | null {
    const stmt = this.db.prepare('SELECT * FROM oauth_states WHERE state = ?');
    const row = stmt.get(state) as OAuthState | undefined;
    return row || null;
  }

  deleteOAuthState(state: string): void {
    const stmt = this.db.prepare('DELETE FROM oauth_states WHERE state = ?');
    stmt.run(state);
  }

  cleanupOldOAuthStates(): number {
    const tenMinutesAgo = Math.floor(Date.now() / 1000) - 600;
    const stmt = this.db.prepare('DELETE FROM oauth_states WHERE created_at < ?');
    const result = stmt.run(tenMinutesAgo);
    return result.changes;
  }

  // User mapping methods
  getUserMapping(did: string, appId: string): UserMapping | null {
    const stmt = this.db.prepare(
      'SELECT * FROM user_mappings WHERE did = ? AND app_id = ?'
    );
    const row = stmt.get(did, appId) as UserMapping | undefined;
    return row || null;
  }

  setUserMapping(mapping: Omit<UserMapping, 'linked_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO user_mappings (did, app_id, user_id, handle)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(did, app_id) DO UPDATE SET
        user_id = excluded.user_id,
        handle = excluded.handle
    `);
    stmt.run(mapping.did, mapping.app_id, mapping.user_id, mapping.handle);
  }

  // Session methods
  createSession(session: Omit<AppSession, 'created_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, did, handle, user_id, app_id, refresh_token, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      session.id,
      session.did,
      session.handle,
      session.user_id,
      session.app_id,
      session.refresh_token,
      session.expires_at.toISOString()
    );
  }

  getSession(sessionId: string): AppSession | null {
    const stmt = this.db.prepare('SELECT * FROM sessions WHERE id = ?');
    const row = stmt.get(sessionId) as (Omit<AppSession, 'created_at' | 'expires_at'> & {
      created_at: string;
      expires_at: string;
    }) | undefined;

    if (!row) return null;

    return {
      ...row,
      created_at: new Date(row.created_at),
      expires_at: new Date(row.expires_at),
    };
  }

  deleteSession(sessionId: string): void {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE id = ?');
    stmt.run(sessionId);
  }

  cleanupExpiredSessions(): number {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE expires_at < datetime("now")');
    const result = stmt.run();
    return result.changes;
  }

  // Session conflict detection methods
  getActiveSessionsByDid(did: string, appId: string): ActiveSession[] {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions
      WHERE did = ? AND app_id = ? AND expires_at > datetime('now')
      ORDER BY created_at DESC
    `);
    const rows = stmt.all(did, appId) as Array<{
      id: string;
      did: string;
      handle: string;
      user_id: number | null;
      app_id: string;
      refresh_token?: string;
      created_at: string;
      expires_at: string;
      connection_state: SessionConnectionState;
      last_activity: string;
      client_info?: string;
    }>;

    return rows.map((row) => ({
      ...row,
      created_at: new Date(row.created_at),
      expires_at: new Date(row.expires_at),
      last_activity: new Date(row.last_activity),
      connection_state: row.connection_state || 'pending',
    }));
  }

  updateSessionConnectionState(
    sessionId: string,
    state: SessionConnectionState,
    clientInfo?: string
  ): void {
    const stmt = this.db.prepare(`
      UPDATE sessions
      SET connection_state = ?, last_activity = datetime('now'), client_info = COALESCE(?, client_info)
      WHERE id = ?
    `);
    stmt.run(state, clientInfo, sessionId);
  }

  updateSessionActivity(sessionId: string): void {
    const stmt = this.db.prepare(`
      UPDATE sessions SET last_activity = datetime('now') WHERE id = ?
    `);
    stmt.run(sessionId);
  }

  deleteOtherSessions(keepSessionId: string, did: string, appId: string): number {
    const stmt = this.db.prepare(`
      DELETE FROM sessions
      WHERE did = ? AND app_id = ? AND id != ?
    `);
    const result = stmt.run(did, appId, keepSessionId);
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}
