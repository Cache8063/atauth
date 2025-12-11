/**
 * OAuth flow utilities for AT Protocol authentication
 */

import type { AtAuthConfig, OAuthState, OAuthCallbackResult } from './types';
import { decodeToken } from './token';
import { storeToken, storeOAuthState, getOAuthState, generateNonce } from './storage';

/**
 * Default configuration
 */
const DEFAULT_CONFIG: Partial<AtAuthConfig> = {
  storageKey: 'atauth_token',
  persistSession: true,
  refreshThreshold: 300,
};

/**
 * Build the OAuth authorization URL.
 *
 * @param config - Auth configuration
 * @param state - Optional state to pass through OAuth flow
 * @returns Authorization URL to redirect to
 */
export function buildAuthUrl(
  config: AtAuthConfig,
  state?: OAuthState
): string {
  const { gatewayUrl, appId, callbackUrl } = config;

  // Generate CSRF nonce
  const nonce = generateNonce();

  // Build state object
  const oauthState: OAuthState = {
    ...state,
    nonce,
  };

  // Store state for verification
  storeOAuthState(oauthState);

  // Build URL
  const url = new URL(`${gatewayUrl}/oauth/authorize`);
  url.searchParams.set('state', JSON.stringify(oauthState));

  if (appId) {
    url.searchParams.set('app_id', appId);
  }

  if (callbackUrl) {
    url.searchParams.set('redirect_uri', callbackUrl);
  }

  return url.toString();
}

/**
 * Redirect to OAuth authorization.
 *
 * @param config - Auth configuration
 * @param state - Optional state to pass through OAuth flow
 */
export function redirectToAuth(
  config: AtAuthConfig,
  state?: OAuthState
): void {
  const url = buildAuthUrl(config, state);

  if (typeof window !== 'undefined') {
    window.location.href = url;
  }
}

/**
 * Handle OAuth callback.
 *
 * Call this function on your callback page to process the authentication result.
 *
 * @param config - Auth configuration
 * @returns Callback result with token or error
 */
export function handleCallback(
  config: AtAuthConfig
): OAuthCallbackResult {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };

  if (typeof window === 'undefined') {
    return {
      success: false,
      error: 'OAuth callback must be handled in browser',
    };
  }

  const url = new URL(window.location.href);
  const token = url.searchParams.get('token');
  const error = url.searchParams.get('error');
  const stateParam = url.searchParams.get('state');

  // Handle error from gateway
  if (error) {
    return {
      success: false,
      error: decodeURIComponent(error),
    };
  }

  // Must have token
  if (!token) {
    return {
      success: false,
      error: 'No token received from auth gateway',
    };
  }

  // Verify state/CSRF
  const storedState = getOAuthState();
  let returnTo: string | undefined;

  if (stateParam) {
    try {
      const receivedState = JSON.parse(stateParam) as OAuthState;

      // Verify nonce matches
      if (storedState?.nonce && receivedState.nonce !== storedState.nonce) {
        return {
          success: false,
          error: 'Invalid OAuth state (CSRF protection)',
        };
      }

      returnTo = receivedState.returnTo;
    } catch {
      // State parse error - might be okay if state wasn't used
    }
  }

  // Decode token
  const user = decodeToken(token);
  if (!user) {
    return {
      success: false,
      error: 'Failed to decode authentication token',
    };
  }

  // Store token
  storeToken(
    token,
    fullConfig.storageKey,
    fullConfig.persistSession
  );

  // Clean up URL
  cleanCallbackUrl();

  return {
    success: true,
    token,
    user,
    returnTo,
  };
}

/**
 * Remove OAuth parameters from URL without refresh.
 */
function cleanCallbackUrl(): void {
  if (typeof window === 'undefined') return;

  const url = new URL(window.location.href);
  url.searchParams.delete('token');
  url.searchParams.delete('error');
  url.searchParams.delete('state');

  // Update URL without reload
  window.history.replaceState({}, document.title, url.pathname + url.search);
}

/**
 * Check if current page is an OAuth callback.
 *
 * @returns True if URL contains OAuth callback parameters
 */
export function isOAuthCallback(): boolean {
  if (typeof window === 'undefined') return false;

  const url = new URL(window.location.href);
  return url.searchParams.has('token') || url.searchParams.has('error');
}

/**
 * Build logout URL.
 *
 * @param config - Auth configuration
 * @param returnTo - URL to return to after logout
 * @returns Logout URL
 */
export function buildLogoutUrl(
  config: AtAuthConfig,
  returnTo?: string
): string {
  const url = new URL(`${config.gatewayUrl}/oauth/logout`);

  if (returnTo) {
    url.searchParams.set('redirect_uri', returnTo);
  }

  return url.toString();
}
