/**
 * OAuth flow utilities for AT Protocol authentication
 */

import type { AtAuthConfig, OAuthState, OAuthCallbackResult } from './types';
import { decodeToken } from './token';
import { storeToken, storeOAuthState, getOAuthState, generateNonce } from './storage';
import { parseOAuthState, validateGatewayUrl, validateCallbackUrl } from './validation';

/**
 * Default configuration
 *
 * SECURITY: persistSession defaults to false (sessionStorage) for better security.
 * Tokens stored in sessionStorage are cleared when the browser closes and are not
 * shared across tabs, reducing XSS attack persistence.
 *
 * Set persistSession: true only for explicit "remember me" functionality.
 */
const DEFAULT_CONFIG: Partial<AtAuthConfig> = {
  storageKey: 'atauth_token',
  persistSession: false,
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

  // Validate URLs require HTTPS in production
  validateGatewayUrl(gatewayUrl);
  if (callbackUrl) {
    validateCallbackUrl(callbackUrl);
  }

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
 * Tokens are passed via URL fragment (hash) for security - they won't appear
 * in server logs, browser history, or referrer headers.
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

  // Token is passed in URL fragment (hash) for security
  // Fragments are never sent to servers, keeping tokens out of logs
  const fragmentParams = new URLSearchParams(url.hash.slice(1));
  const token = fragmentParams.get('token');

  // Error may come via query param from gateway
  const error = url.searchParams.get('error');
  const stateParam = url.searchParams.get('state') || fragmentParams.get('state');

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

  // Verify state/CSRF with proper validation
  const storedState = getOAuthState();
  let returnTo: string | undefined;

  if (stateParam) {
    // Use secure parsing with validation
    const receivedState = parseOAuthState(stateParam);

    if (!receivedState) {
      return {
        success: false,
        error: 'Invalid OAuth state format',
      };
    }

    // Verify nonce matches
    if (storedState?.nonce && receivedState.nonce !== storedState.nonce) {
      return {
        success: false,
        error: 'Invalid OAuth state (CSRF protection)',
      };
    }

    returnTo = receivedState.returnTo;
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
  url.searchParams.delete('error');
  url.searchParams.delete('state');

  // Clear the hash (contains sensitive token data)
  url.hash = '';

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
  const fragmentParams = new URLSearchParams(url.hash.slice(1));

  // Token comes via fragment, error via query param
  return fragmentParams.has('token') || url.searchParams.has('error');
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
