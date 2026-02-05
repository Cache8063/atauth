/**
 * Database Service
 *
 * SQLite database for OAuth state, app sessions, user mappings,
 * OIDC clients, passkeys, MFA, and email verification
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
  OIDCClientConfig,
  OIDCKey,
  AuthorizationCode,
  RefreshToken,
  PasskeyCredential,
  MFATOTPConfig,
  MFABackupCode,
  UserEmail,
  EmailVerificationCode,
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

    // Run migrations for new columns and tables
    this.runMigrations();
  }

  private runMigrations(): void {
    // Check if we need to add OIDC columns to apps table
    const appColumns = this.db.pragma('table_info(apps)') as Array<{ name: string }>;
    const columnNames = appColumns.map((c) => c.name);

    if (!columnNames.includes('client_type')) {
      this.db.exec(`
        -- Add OIDC columns to apps table
        ALTER TABLE apps ADD COLUMN client_type TEXT DEFAULT 'legacy';
        ALTER TABLE apps ADD COLUMN client_secret TEXT;
        ALTER TABLE apps ADD COLUMN redirect_uris TEXT DEFAULT '[]';
        ALTER TABLE apps ADD COLUMN grant_types TEXT DEFAULT '["authorization_code"]';
        ALTER TABLE apps ADD COLUMN allowed_scopes TEXT DEFAULT '["openid"]';
        ALTER TABLE apps ADD COLUMN id_token_ttl_seconds INTEGER DEFAULT 3600;
        ALTER TABLE apps ADD COLUMN access_token_ttl_seconds INTEGER DEFAULT 3600;
        ALTER TABLE apps ADD COLUMN refresh_token_ttl_seconds INTEGER DEFAULT 604800;
        ALTER TABLE apps ADD COLUMN require_pkce BOOLEAN DEFAULT 1;
        ALTER TABLE apps ADD COLUMN token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic';
      `);
    }

    // Create OIDC signing keys table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oidc_keys (
        kid TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        private_key_encrypted TEXT NOT NULL,
        public_key_jwk TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT 1,
        use_for_signing BOOLEAN DEFAULT 1
      );
    `);

    // Create authorization codes table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS authorization_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        state TEXT,
        nonce TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        did TEXT NOT NULL,
        handle TEXT NOT NULL,
        user_id INTEGER,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (client_id) REFERENCES apps(id)
      );

      CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);
    `);

    // Add state column if it doesn't exist (migration for existing databases)
    try {
      this.db.exec('ALTER TABLE authorization_codes ADD COLUMN state TEXT');
    } catch {
      // Column already exists
    }

    // Create refresh tokens table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        did TEXT NOT NULL,
        handle TEXT NOT NULL,
        user_id INTEGER,
        scope TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        last_used_at DATETIME,
        revoked BOOLEAN DEFAULT 0,
        family_id TEXT,
        FOREIGN KEY (client_id) REFERENCES apps(id)
      );

      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id, did);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
    `);

    // Create passkey credentials table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS passkey_credentials (
        id TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        handle TEXT NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER DEFAULT 0,
        device_type TEXT,
        backed_up BOOLEAN DEFAULT 0,
        transports TEXT,
        name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME
      );

      CREATE INDEX IF NOT EXISTS idx_passkey_did ON passkey_credentials(did);
    `);

    // Create MFA TOTP table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS mfa_totp (
        did TEXT PRIMARY KEY,
        secret_encrypted TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 0,
        verified_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create MFA backup codes table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS mfa_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        did TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used BOOLEAN DEFAULT 0,
        used_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_backup_did ON mfa_backup_codes(did);
    `);

    // Create user emails table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        did TEXT NOT NULL,
        email TEXT NOT NULL,
        verified BOOLEAN DEFAULT 0,
        verified_at DATETIME,
        is_primary BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(did, email)
      );

      CREATE INDEX IF NOT EXISTS idx_email_did ON user_emails(did);
      CREATE INDEX IF NOT EXISTS idx_email_address ON user_emails(email);
    `);

    // Create email verification codes table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS email_verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        purpose TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_verify_email ON email_verification_codes(email);
      CREATE INDEX IF NOT EXISTS idx_verify_expires ON email_verification_codes(expires_at);
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
    const stmt = this.db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')");
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

  // Admin methods for listing and managing apps
  getAllApps(): Omit<AppConfig, 'hmac_secret'>[] {
    const stmt = this.db.prepare(
      'SELECT id, name, token_ttl_seconds, callback_url, created_at FROM apps ORDER BY created_at DESC'
    );
    return stmt.all() as Omit<AppConfig, 'hmac_secret'>[];
  }

  deleteApp(appId: string): void {
    // Delete related data first (order respects foreign keys)
    this.db.prepare('DELETE FROM sessions WHERE app_id = ?').run(appId);
    this.db.prepare('DELETE FROM oauth_states WHERE app_id = ?').run(appId);
    this.db.prepare('DELETE FROM user_mappings WHERE app_id = ?').run(appId);
    this.db.prepare('DELETE FROM authorization_codes WHERE client_id = ?').run(appId);
    this.db.prepare('DELETE FROM refresh_tokens WHERE client_id = ?').run(appId);
    // Delete the app
    this.db.prepare('DELETE FROM apps WHERE id = ?').run(appId);
  }

  getStats(): {
    apps_count: number;
    oidc_clients_count: number;
    active_sessions_count: number;
    users_count: number;
    passkeys_count: number;
    mfa_enabled_count: number;
    verified_emails_count: number;
  } {
    const appsCount = (this.db.prepare('SELECT COUNT(*) as count FROM apps').get() as { count: number }).count;
    const oidcClientsCount = (this.db.prepare("SELECT COUNT(*) as count FROM apps WHERE client_type = 'oidc'").get() as { count: number }).count;
    const activeSessionsCount = (this.db.prepare("SELECT COUNT(*) as count FROM sessions WHERE expires_at > datetime('now')").get() as { count: number }).count;
    const usersCount = (this.db.prepare('SELECT COUNT(DISTINCT did) as count FROM user_mappings').get() as { count: number }).count;
    const passkeysCount = (this.db.prepare('SELECT COUNT(*) as count FROM passkey_credentials').get() as { count: number }).count;
    const mfaEnabledCount = (this.db.prepare('SELECT COUNT(*) as count FROM mfa_totp WHERE enabled = 1').get() as { count: number }).count;
    const verifiedEmailsCount = (this.db.prepare('SELECT COUNT(*) as count FROM user_emails WHERE verified = 1').get() as { count: number }).count;

    return {
      apps_count: appsCount,
      oidc_clients_count: oidcClientsCount,
      active_sessions_count: activeSessionsCount,
      users_count: usersCount,
      passkeys_count: passkeysCount,
      mfa_enabled_count: mfaEnabledCount,
      verified_emails_count: verifiedEmailsCount,
    };
  }

  close(): void {
    this.db.close();
  }

  // ===== OIDC Key Management Methods =====

  saveOIDCKey(key: Omit<OIDCKey, 'created_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO oidc_keys (kid, algorithm, private_key_encrypted, public_key_jwk, is_active, use_for_signing)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(key.kid, key.algorithm, key.private_key_encrypted, key.public_key_jwk, key.is_active ? 1 : 0, key.use_for_signing ? 1 : 0);
  }

  getOIDCKey(kid: string): OIDCKey | null {
    const stmt = this.db.prepare('SELECT * FROM oidc_keys WHERE kid = ?');
    const row = stmt.get(kid) as {
      kid: string;
      algorithm: 'ES256' | 'RS256';
      private_key_encrypted: string;
      public_key_jwk: string;
      created_at: string;
      expires_at: string | null;
      is_active: number;
      use_for_signing: number;
    } | undefined;
    if (!row) return null;
    return {
      kid: row.kid,
      algorithm: row.algorithm,
      private_key_encrypted: row.private_key_encrypted,
      public_key_jwk: row.public_key_jwk,
      created_at: new Date(row.created_at),
      expires_at: row.expires_at ? new Date(row.expires_at) : undefined,
      is_active: Boolean(row.is_active),
      use_for_signing: Boolean(row.use_for_signing),
    };
  }

  getActiveOIDCKeys(): OIDCKey[] {
    const stmt = this.db.prepare('SELECT * FROM oidc_keys WHERE is_active = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as Array<{
      kid: string;
      algorithm: 'ES256' | 'RS256';
      private_key_encrypted: string;
      public_key_jwk: string;
      created_at: string;
      expires_at: string | null;
      is_active: number;
      use_for_signing: number;
    }>;
    return rows.map(row => ({
      kid: row.kid,
      algorithm: row.algorithm,
      private_key_encrypted: row.private_key_encrypted,
      public_key_jwk: row.public_key_jwk,
      created_at: new Date(row.created_at),
      expires_at: row.expires_at ? new Date(row.expires_at) : undefined,
      is_active: Boolean(row.is_active),
      use_for_signing: Boolean(row.use_for_signing),
    }));
  }

  getCurrentSigningKey(): OIDCKey | null {
    const stmt = this.db.prepare('SELECT * FROM oidc_keys WHERE is_active = 1 AND use_for_signing = 1 ORDER BY created_at DESC LIMIT 1');
    const row = stmt.get() as {
      kid: string;
      algorithm: 'ES256' | 'RS256';
      private_key_encrypted: string;
      public_key_jwk: string;
      created_at: string;
      expires_at: string | null;
      is_active: number;
      use_for_signing: number;
    } | undefined;
    if (!row) return null;
    return {
      kid: row.kid,
      algorithm: row.algorithm,
      private_key_encrypted: row.private_key_encrypted,
      public_key_jwk: row.public_key_jwk,
      created_at: new Date(row.created_at),
      expires_at: row.expires_at ? new Date(row.expires_at) : undefined,
      is_active: Boolean(row.is_active),
      use_for_signing: Boolean(row.use_for_signing),
    };
  }

  markKeyAsNotSigning(kid: string): void {
    const stmt = this.db.prepare('UPDATE oidc_keys SET use_for_signing = 0 WHERE kid = ?');
    stmt.run(kid);
  }

  deactivateKey(kid: string): void {
    const stmt = this.db.prepare('UPDATE oidc_keys SET is_active = 0, use_for_signing = 0 WHERE kid = ?');
    stmt.run(kid);
  }

  deleteOIDCKey(kid: string): void {
    const stmt = this.db.prepare('DELETE FROM oidc_keys WHERE kid = ?');
    stmt.run(kid);
  }

  // ===== Authorization Code Methods =====

  saveAuthorizationCode(code: AuthorizationCode): void {
    const stmt = this.db.prepare(`
      INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, did, handle, user_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      code.code,
      code.client_id,
      code.redirect_uri,
      code.scope,
      code.state,
      code.nonce,
      code.code_challenge,
      code.code_challenge_method,
      code.did,
      code.handle,
      code.user_id,
      code.created_at,
      code.expires_at
    );
  }

  getAuthorizationCode(code: string): AuthorizationCode | null {
    const stmt = this.db.prepare('SELECT * FROM authorization_codes WHERE code = ?');
    const row = stmt.get(code) as {
      code: string;
      client_id: string;
      redirect_uri: string;
      scope: string;
      state: string | null;
      nonce: string | null;
      code_challenge: string | null;
      code_challenge_method: 'S256' | 'plain' | null;
      did: string;
      handle: string;
      user_id: number | null;
      created_at: number;
      expires_at: number;
      used: number;
    } | undefined;
    if (!row) return null;
    return {
      code: row.code,
      client_id: row.client_id,
      redirect_uri: row.redirect_uri,
      scope: row.scope,
      state: row.state ?? undefined,
      nonce: row.nonce ?? undefined,
      code_challenge: row.code_challenge ?? undefined,
      code_challenge_method: row.code_challenge_method ?? undefined,
      did: row.did,
      handle: row.handle,
      user_id: row.user_id ?? undefined,
      created_at: row.created_at,
      expires_at: row.expires_at,
      used: Boolean(row.used),
    };
  }

  markAuthorizationCodeUsed(code: string): void {
    const stmt = this.db.prepare('UPDATE authorization_codes SET used = 1 WHERE code = ?');
    stmt.run(code);
  }

  updateAuthorizationCodeUser(code: string, did: string, handle: string): void {
    const stmt = this.db.prepare('UPDATE authorization_codes SET did = ?, handle = ? WHERE code = ?');
    stmt.run(did, handle, code);
  }

  cleanupExpiredAuthorizationCodes(): number {
    const now = Math.floor(Date.now() / 1000);
    const stmt = this.db.prepare('DELETE FROM authorization_codes WHERE expires_at < ?');
    const result = stmt.run(now);
    return result.changes;
  }

  // ===== Refresh Token Methods =====

  saveRefreshToken(token: Omit<RefreshToken, 'created_at' | 'last_used_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO refresh_tokens (token_hash, client_id, did, handle, user_id, scope, expires_at, family_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      token.token_hash,
      token.client_id,
      token.did,
      token.handle,
      token.user_id,
      token.scope,
      token.expires_at.toISOString(),
      token.family_id
    );
  }

  getRefreshToken(tokenHash: string): RefreshToken | null {
    const stmt = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
    const row = stmt.get(tokenHash) as {
      token_hash: string;
      client_id: string;
      did: string;
      handle: string;
      user_id: number | null;
      scope: string;
      created_at: string;
      expires_at: string;
      last_used_at: string | null;
      revoked: number;
      family_id: string | null;
    } | undefined;
    if (!row) return null;
    return {
      token_hash: row.token_hash,
      client_id: row.client_id,
      did: row.did,
      handle: row.handle,
      user_id: row.user_id ?? undefined,
      scope: row.scope,
      created_at: new Date(row.created_at),
      expires_at: new Date(row.expires_at),
      last_used_at: row.last_used_at ? new Date(row.last_used_at) : undefined,
      revoked: Boolean(row.revoked),
      family_id: row.family_id ?? undefined,
    };
  }

  updateRefreshTokenLastUsed(tokenHash: string): void {
    const stmt = this.db.prepare("UPDATE refresh_tokens SET last_used_at = datetime('now') WHERE token_hash = ?");
    stmt.run(tokenHash);
  }

  revokeRefreshToken(tokenHash: string): void {
    const stmt = this.db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?');
    stmt.run(tokenHash);
  }

  revokeRefreshTokenFamily(familyId: string): void {
    const stmt = this.db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?');
    stmt.run(familyId);
  }

  revokeAllRefreshTokensForUser(did: string, clientId: string): number {
    const stmt = this.db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE did = ? AND client_id = ?');
    const result = stmt.run(did, clientId);
    return result.changes;
  }

  cleanupExpiredRefreshTokens(): number {
    const stmt = this.db.prepare("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')");
    const result = stmt.run();
    return result.changes;
  }

  // ===== Passkey Credential Methods =====

  savePasskeyCredential(credential: Omit<PasskeyCredential, 'created_at' | 'last_used_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO passkey_credentials (id, did, handle, public_key, counter, device_type, backed_up, transports, name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      credential.id,
      credential.did,
      credential.handle,
      credential.public_key,
      credential.counter,
      credential.device_type,
      credential.backed_up ? 1 : 0,
      credential.transports ? JSON.stringify(credential.transports) : null,
      credential.name
    );
  }

  getPasskeyCredential(credentialId: string): PasskeyCredential | null {
    const stmt = this.db.prepare('SELECT * FROM passkey_credentials WHERE id = ?');
    const row = stmt.get(credentialId) as {
      id: string;
      did: string;
      handle: string;
      public_key: string;
      counter: number;
      device_type: 'platform' | 'cross-platform' | null;
      backed_up: number;
      transports: string | null;
      name: string | null;
      created_at: string;
      last_used_at: string | null;
    } | undefined;
    if (!row) return null;
    return {
      id: row.id,
      did: row.did,
      handle: row.handle,
      public_key: row.public_key,
      counter: row.counter,
      device_type: row.device_type,
      backed_up: Boolean(row.backed_up),
      transports: row.transports ? JSON.parse(row.transports) : null,
      name: row.name,
      created_at: new Date(row.created_at),
      last_used_at: row.last_used_at ? new Date(row.last_used_at) : null,
    };
  }

  getPasskeyCredentialsByDid(did: string): PasskeyCredential[] {
    const stmt = this.db.prepare('SELECT * FROM passkey_credentials WHERE did = ? ORDER BY created_at DESC');
    const rows = stmt.all(did) as Array<{
      id: string;
      did: string;
      handle: string;
      public_key: string;
      counter: number;
      device_type: 'platform' | 'cross-platform' | null;
      backed_up: number;
      transports: string | null;
      name: string | null;
      created_at: string;
      last_used_at: string | null;
    }>;
    return rows.map(row => ({
      id: row.id,
      did: row.did,
      handle: row.handle,
      public_key: row.public_key,
      counter: row.counter,
      device_type: row.device_type,
      backed_up: Boolean(row.backed_up),
      transports: row.transports ? JSON.parse(row.transports) : null,
      name: row.name,
      created_at: new Date(row.created_at),
      last_used_at: row.last_used_at ? new Date(row.last_used_at) : null,
    }));
  }

  updatePasskeyCounter(credentialId: string, newCounter: number): void {
    const stmt = this.db.prepare("UPDATE passkey_credentials SET counter = ?, last_used_at = datetime('now') WHERE id = ?");
    stmt.run(newCounter, credentialId);
  }

  renamePasskey(credentialId: string, name: string): void {
    const stmt = this.db.prepare('UPDATE passkey_credentials SET name = ? WHERE id = ?');
    stmt.run(name, credentialId);
  }

  deletePasskeyCredential(credentialId: string): void {
    const stmt = this.db.prepare('DELETE FROM passkey_credentials WHERE id = ?');
    stmt.run(credentialId);
  }

  countPasskeysByDid(did: string): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM passkey_credentials WHERE did = ?');
    const row = stmt.get(did) as { count: number };
    return row.count;
  }

  // ===== MFA TOTP Methods =====

  saveMFATOTP(config: Omit<MFATOTPConfig, 'created_at' | 'verified_at'>): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO mfa_totp (did, secret_encrypted, enabled)
      VALUES (?, ?, ?)
    `);
    stmt.run(config.did, config.secret_encrypted, config.enabled ? 1 : 0);
  }

  getMFATOTP(did: string): MFATOTPConfig | null {
    const stmt = this.db.prepare('SELECT * FROM mfa_totp WHERE did = ?');
    const row = stmt.get(did) as {
      did: string;
      secret_encrypted: string;
      enabled: number;
      verified_at: string | null;
      created_at: string;
    } | undefined;
    if (!row) return null;
    return {
      did: row.did,
      secret_encrypted: row.secret_encrypted,
      enabled: Boolean(row.enabled),
      verified_at: row.verified_at ? new Date(row.verified_at) : null,
      created_at: new Date(row.created_at),
    };
  }

  enableMFATOTP(did: string): void {
    const stmt = this.db.prepare("UPDATE mfa_totp SET enabled = 1, verified_at = datetime('now') WHERE did = ?");
    stmt.run(did);
  }

  disableMFATOTP(did: string): void {
    const stmt = this.db.prepare('DELETE FROM mfa_totp WHERE did = ?');
    stmt.run(did);
  }

  // ===== MFA Backup Codes Methods =====

  saveBackupCodes(did: string, codeHashes: string[]): void {
    // Delete existing codes first
    this.db.prepare('DELETE FROM mfa_backup_codes WHERE did = ?').run(did);

    const stmt = this.db.prepare(`
      INSERT INTO mfa_backup_codes (did, code_hash) VALUES (?, ?)
    `);

    const insertMany = this.db.transaction((codes: string[]) => {
      for (const codeHash of codes) {
        stmt.run(did, codeHash);
      }
    });

    insertMany(codeHashes);
  }

  getUnusedBackupCode(did: string, codeHash: string): MFABackupCode | null {
    const stmt = this.db.prepare('SELECT * FROM mfa_backup_codes WHERE did = ? AND code_hash = ? AND used = 0');
    const row = stmt.get(did, codeHash) as {
      id: number;
      did: string;
      code_hash: string;
      used: number;
      used_at: string | null;
      created_at: string;
    } | undefined;
    if (!row) return null;
    return {
      id: row.id,
      did: row.did,
      code_hash: row.code_hash,
      used: Boolean(row.used),
      used_at: row.used_at ? new Date(row.used_at) : null,
      created_at: new Date(row.created_at),
    };
  }

  markBackupCodeUsed(id: number): void {
    const stmt = this.db.prepare("UPDATE mfa_backup_codes SET used = 1, used_at = datetime('now') WHERE id = ?");
    stmt.run(id);
  }

  countUnusedBackupCodes(did: string): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM mfa_backup_codes WHERE did = ? AND used = 0');
    const row = stmt.get(did) as { count: number };
    return row.count;
  }

  // ===== User Email Methods =====

  saveUserEmail(email: Omit<UserEmail, 'id' | 'created_at' | 'verified_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO user_emails (did, email, verified, is_primary)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(did, email) DO UPDATE SET is_primary = excluded.is_primary
    `);
    stmt.run(email.did, email.email, email.verified ? 1 : 0, email.is_primary ? 1 : 0);
  }

  getUserEmails(did: string): UserEmail[] {
    const stmt = this.db.prepare('SELECT * FROM user_emails WHERE did = ? ORDER BY is_primary DESC, created_at ASC');
    const rows = stmt.all(did) as Array<{
      id: number;
      did: string;
      email: string;
      verified: number;
      verified_at: string | null;
      is_primary: number;
      created_at: string;
    }>;
    return rows.map(row => ({
      id: row.id,
      did: row.did,
      email: row.email,
      verified: Boolean(row.verified),
      verified_at: row.verified_at ? new Date(row.verified_at) : null,
      is_primary: Boolean(row.is_primary),
      created_at: new Date(row.created_at),
    }));
  }

  getUserByEmail(email: string): { did: string; handle?: string } | null {
    const stmt = this.db.prepare(`
      SELECT ue.did, um.handle FROM user_emails ue
      LEFT JOIN user_mappings um ON ue.did = um.did
      WHERE ue.email = ? AND ue.verified = 1
      LIMIT 1
    `);
    const row = stmt.get(email) as { did: string; handle?: string } | undefined;
    return row || null;
  }

  verifyUserEmail(did: string, email: string): void {
    const stmt = this.db.prepare("UPDATE user_emails SET verified = 1, verified_at = datetime('now') WHERE did = ? AND email = ?");
    stmt.run(did, email);
  }

  deleteUserEmail(did: string, email: string): void {
    const stmt = this.db.prepare('DELETE FROM user_emails WHERE did = ? AND email = ?');
    stmt.run(did, email);
  }

  setPrimaryEmail(did: string, email: string): void {
    // Unset all as non-primary first
    this.db.prepare('UPDATE user_emails SET is_primary = 0 WHERE did = ?').run(did);
    // Set the specified email as primary
    this.db.prepare('UPDATE user_emails SET is_primary = 1 WHERE did = ? AND email = ?').run(did, email);
  }

  // ===== Email Verification Code Methods =====

  saveEmailVerificationCode(code: Omit<EmailVerificationCode, 'id' | 'created_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO email_verification_codes (email, code_hash, purpose, expires_at)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(code.email, code.code_hash, code.purpose, code.expires_at.toISOString());
  }

  getValidEmailVerificationCode(email: string, codeHash: string, purpose: string): EmailVerificationCode | null {
    const stmt = this.db.prepare(`
      SELECT * FROM email_verification_codes
      WHERE email = ? AND code_hash = ? AND purpose = ? AND used = 0 AND expires_at > datetime('now')
    `);
    const row = stmt.get(email, codeHash, purpose) as {
      id: number;
      email: string;
      code_hash: string;
      purpose: 'verify' | 'recovery';
      expires_at: string;
      used: number;
      created_at: string;
    } | undefined;
    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      code_hash: row.code_hash,
      purpose: row.purpose,
      expires_at: new Date(row.expires_at),
      used: Boolean(row.used),
      created_at: new Date(row.created_at),
    };
  }

  markEmailVerificationCodeUsed(id: number): void {
    const stmt = this.db.prepare('UPDATE email_verification_codes SET used = 1 WHERE id = ?');
    stmt.run(id);
  }

  cleanupExpiredEmailVerificationCodes(): number {
    const stmt = this.db.prepare("DELETE FROM email_verification_codes WHERE expires_at < datetime('now')");
    const result = stmt.run();
    return result.changes;
  }

  // ===== OIDC Client Methods =====

  getOIDCClient(clientId: string): OIDCClientConfig | null {
    const stmt = this.db.prepare('SELECT * FROM apps WHERE id = ?');
    const row = stmt.get(clientId) as {
      id: string;
      name: string;
      client_type: 'legacy' | 'oidc';
      hmac_secret?: string;
      client_secret?: string;
      redirect_uris: string;
      grant_types: string;
      allowed_scopes: string;
      token_ttl_seconds: number;
      id_token_ttl_seconds: number;
      access_token_ttl_seconds: number;
      refresh_token_ttl_seconds: number;
      require_pkce: number;
      token_endpoint_auth_method: string;
      created_at: string;
    } | undefined;
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      client_type: row.client_type,
      hmac_secret: row.hmac_secret,
      client_secret: row.client_secret,
      redirect_uris: JSON.parse(row.redirect_uris || '[]'),
      grant_types: JSON.parse(row.grant_types || '["authorization_code"]'),
      allowed_scopes: JSON.parse(row.allowed_scopes || '["openid"]'),
      token_ttl_seconds: row.token_ttl_seconds,
      id_token_ttl_seconds: row.id_token_ttl_seconds,
      access_token_ttl_seconds: row.access_token_ttl_seconds,
      refresh_token_ttl_seconds: row.refresh_token_ttl_seconds,
      require_pkce: Boolean(row.require_pkce),
      token_endpoint_auth_method: row.token_endpoint_auth_method as 'client_secret_basic' | 'client_secret_post' | 'none',
      created_at: new Date(row.created_at),
    };
  }

  upsertOIDCClient(client: Omit<OIDCClientConfig, 'created_at'>): void {
    const stmt = this.db.prepare(`
      INSERT INTO apps (id, name, client_type, hmac_secret, client_secret, redirect_uris, grant_types, allowed_scopes, token_ttl_seconds, id_token_ttl_seconds, access_token_ttl_seconds, refresh_token_ttl_seconds, require_pkce, token_endpoint_auth_method, callback_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        client_type = excluded.client_type,
        hmac_secret = COALESCE(excluded.hmac_secret, hmac_secret),
        client_secret = COALESCE(excluded.client_secret, client_secret),
        redirect_uris = excluded.redirect_uris,
        grant_types = excluded.grant_types,
        allowed_scopes = excluded.allowed_scopes,
        token_ttl_seconds = excluded.token_ttl_seconds,
        id_token_ttl_seconds = excluded.id_token_ttl_seconds,
        access_token_ttl_seconds = excluded.access_token_ttl_seconds,
        refresh_token_ttl_seconds = excluded.refresh_token_ttl_seconds,
        require_pkce = excluded.require_pkce,
        token_endpoint_auth_method = excluded.token_endpoint_auth_method,
        callback_url = excluded.callback_url
    `);
    stmt.run(
      client.id,
      client.name,
      client.client_type,
      client.hmac_secret,
      client.client_secret,
      JSON.stringify(client.redirect_uris),
      JSON.stringify(client.grant_types),
      JSON.stringify(client.allowed_scopes),
      client.token_ttl_seconds,
      client.id_token_ttl_seconds,
      client.access_token_ttl_seconds,
      client.refresh_token_ttl_seconds,
      client.require_pkce ? 1 : 0,
      client.token_endpoint_auth_method,
      client.redirect_uris[0] || null
    );
  }

  getAllOIDCClients(): OIDCClientConfig[] {
    const stmt = this.db.prepare("SELECT * FROM apps WHERE client_type = 'oidc' ORDER BY created_at DESC");
    const rows = stmt.all() as Array<{
      id: string;
      name: string;
      client_type: 'legacy' | 'oidc';
      hmac_secret?: string;
      client_secret?: string;
      redirect_uris: string;
      grant_types: string;
      allowed_scopes: string;
      token_ttl_seconds: number;
      id_token_ttl_seconds: number;
      access_token_ttl_seconds: number;
      refresh_token_ttl_seconds: number;
      require_pkce: number;
      token_endpoint_auth_method: string;
      created_at: string;
    }>;
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      client_type: row.client_type,
      hmac_secret: row.hmac_secret,
      client_secret: row.client_secret,
      redirect_uris: JSON.parse(row.redirect_uris || '[]'),
      grant_types: JSON.parse(row.grant_types || '["authorization_code"]'),
      allowed_scopes: JSON.parse(row.allowed_scopes || '["openid"]'),
      token_ttl_seconds: row.token_ttl_seconds,
      id_token_ttl_seconds: row.id_token_ttl_seconds,
      access_token_ttl_seconds: row.access_token_ttl_seconds,
      refresh_token_ttl_seconds: row.refresh_token_ttl_seconds,
      require_pkce: Boolean(row.require_pkce),
      token_endpoint_auth_method: row.token_endpoint_auth_method as 'client_secret_basic' | 'client_secret_post' | 'none',
      created_at: new Date(row.created_at),
    }));
  }

  updateOIDCClient(clientId: string, updates: {
    client_type?: 'oidc';
    client_secret?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    allowed_scopes?: string[];
    require_pkce?: boolean;
    token_endpoint_auth_method?: string;
    id_token_ttl_seconds?: number;
    access_token_ttl_seconds?: number;
    refresh_token_ttl_seconds?: number;
  }): void {
    const sets: string[] = [];
    const values: unknown[] = [];

    if (updates.client_type !== undefined) {
      sets.push('client_type = ?');
      values.push(updates.client_type);
    }
    if (updates.client_secret !== undefined) {
      sets.push('client_secret = ?');
      values.push(updates.client_secret);
    }
    if (updates.redirect_uris !== undefined) {
      sets.push('redirect_uris = ?');
      values.push(JSON.stringify(updates.redirect_uris));
    }
    if (updates.grant_types !== undefined) {
      sets.push('grant_types = ?');
      values.push(JSON.stringify(updates.grant_types));
    }
    if (updates.allowed_scopes !== undefined) {
      sets.push('allowed_scopes = ?');
      values.push(JSON.stringify(updates.allowed_scopes));
    }
    if (updates.require_pkce !== undefined) {
      sets.push('require_pkce = ?');
      values.push(updates.require_pkce ? 1 : 0);
    }
    if (updates.token_endpoint_auth_method !== undefined) {
      sets.push('token_endpoint_auth_method = ?');
      values.push(updates.token_endpoint_auth_method);
    }
    if (updates.id_token_ttl_seconds !== undefined) {
      sets.push('id_token_ttl_seconds = ?');
      values.push(updates.id_token_ttl_seconds);
    }
    if (updates.access_token_ttl_seconds !== undefined) {
      sets.push('access_token_ttl_seconds = ?');
      values.push(updates.access_token_ttl_seconds);
      sets.push('token_ttl_seconds = ?');
      values.push(updates.access_token_ttl_seconds);
    }
    if (updates.refresh_token_ttl_seconds !== undefined) {
      sets.push('refresh_token_ttl_seconds = ?');
      values.push(updates.refresh_token_ttl_seconds);
    }

    if (sets.length > 0) {
      values.push(clientId);
      const stmt = this.db.prepare(`UPDATE apps SET ${sets.join(', ')} WHERE id = ?`);
      stmt.run(...values);
    }
  }

  updateOIDCClientSecret(clientId: string, secretHash: string): void {
    const stmt = this.db.prepare('UPDATE apps SET client_secret = ? WHERE id = ?');
    stmt.run(secretHash, clientId);
  }

  // ===== Session Admin Methods =====

  getAllActiveSessions(appId?: string, did?: string, limit = 100): ActiveSession[] {
    let sql = "SELECT * FROM sessions WHERE expires_at > datetime('now')";
    const params: unknown[] = [];

    if (appId) {
      sql += ' AND app_id = ?';
      params.push(appId);
    }
    if (did) {
      sql += ' AND did = ?';
      params.push(did);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as Array<{
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

  revokeAllSessionsForUser(did: string, appId?: string): number {
    let sql = 'DELETE FROM sessions WHERE did = ?';
    const params: unknown[] = [did];

    if (appId) {
      sql += ' AND app_id = ?';
      params.push(appId);
    }

    const stmt = this.db.prepare(sql);
    const result = stmt.run(...params);
    return result.changes;
  }
}
