/**
 * AT Protocol authentication types
 */

/**
 * Decoded token payload from AT Protocol auth gateway
 */
export interface TokenPayload {
  /** Decentralized Identifier (e.g., "did:plc:abc123") */
  did: string;

  /** AT Protocol handle (e.g., "user.bsky.social") */
  handle: string;

  /** Application-specific user ID (optional) */
  user_id?: number | null;

  /** Application/game identifier */
  app_id?: string | null;

  /** Token issued-at timestamp (Unix seconds) */
  iat: number;

  /** Token expiration timestamp (Unix seconds) */
  exp: number;

  /** Unique nonce for this token */
  nonce: string;

  /** Additional custom claims */
  [key: string]: unknown;
}

/**
 * Authentication state
 */
export interface AuthState {
  /** Whether user is authenticated */
  isAuthenticated: boolean;

  /** Whether authentication is in progress */
  isLoading: boolean;

  /** Current user info (if authenticated) */
  user: TokenPayload | null;

  /** Raw token string */
  token: string | null;

  /** Authentication error message */
  error: string | null;
}

/**
 * Auth store actions
 */
export interface AuthActions {
  /** Set authentication token and decode user info */
  setToken: (token: string) => void;

  /** Clear authentication state (logout) */
  clearAuth: () => void;

  /** Set loading state */
  setLoading: (loading: boolean) => void;

  /** Set error message */
  setError: (error: string | null) => void;

  /** Refresh token from storage */
  refreshFromStorage: () => void;
}

/**
 * Combined auth store type
 */
export type AuthStore = AuthState & AuthActions;

/**
 * Configuration for AT Protocol authentication
 */
export interface AtAuthConfig {
  /** URL of the auth gateway */
  gatewayUrl: string;

  /** Application identifier */
  appId?: string;

  /** Storage key for persisting token */
  storageKey?: string;

  /** Whether to use localStorage (true) or sessionStorage (false) */
  persistSession?: boolean;

  /** OAuth callback URL */
  callbackUrl?: string;

  /** Token refresh threshold in seconds (refresh if less than this remaining) */
  refreshThreshold?: number;
}

/**
 * OAuth state passed to auth gateway
 */
export interface OAuthState {
  /** Return URL after authentication */
  returnTo?: string;

  /** CSRF protection nonce */
  nonce?: string;

  /** Additional state data */
  [key: string]: unknown;
}

/**
 * OAuth callback result
 */
export interface OAuthCallbackResult {
  /** Whether authentication was successful */
  success: boolean;

  /** Token if successful */
  token?: string;

  /** Decoded user payload if successful */
  user?: TokenPayload;

  /** Error message if failed */
  error?: string;

  /** Original return URL from state */
  returnTo?: string;
}
