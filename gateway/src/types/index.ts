/**
 * ATAuth Gateway Types
 *
 * Defines the token format and interfaces for application authentication
 */

export interface GatewayTokenPayload {
  /** AT Protocol DID (e.g., "did:plc:xyz...") */
  did: string;
  /** User's handle (e.g., "alice.bsky.social") */
  handle: string;
  /** Application-specific user ID (assigned by your app) */
  user_id: number | null;
  /** Application identifier (e.g., "myapp", "game", "dashboard") */
  app_id: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Expires at (Unix timestamp) */
  exp: number;
  /** Random nonce for replay protection */
  nonce: string;
}

export interface AppSession {
  id: string;
  did: string;
  handle: string;
  user_id: number | null;
  app_id: string;
  created_at: Date;
  expires_at: Date;
  refresh_token?: string;
}

export interface AppConfig {
  id: string;
  name: string;
  hmac_secret: string;
  token_ttl_seconds: number;
  callback_url?: string;
}

export interface OAuthState {
  state: string;
  code_verifier: string;
  app_id: string;
  redirect_uri: string;
  created_at: number;
}

export interface UserMapping {
  did: string;
  app_id: string;
  user_id: number;
  handle: string;
  linked_at: Date;
}

/** Session connection state for conflict detection */
export type SessionConnectionState = 'pending' | 'connected' | 'disconnected';

/** Extended session info with connection tracking */
export interface ActiveSession extends AppSession {
  connection_state: SessionConnectionState;
  last_activity: Date;
  client_info?: string;
}

/** Session conflict resolution options */
export type SessionResolution = 'transfer' | 'cancel' | 'close_others';

/** Session conflict information returned to client */
export interface SessionConflict {
  has_conflict: boolean;
  existing_sessions: Array<{
    session_id: string;
    created_at: string;
    last_activity: string;
    connection_state: SessionConnectionState;
    client_info?: string;
  }>;
  pending_session_id?: string;
}
