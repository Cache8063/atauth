/**
 * atauth - AT Protocol Authentication Library
 *
 * A generic, plug-and-play authentication library for AT Protocol (Bluesky) OAuth integration.
 *
 * @example
 * ```typescript
 * import { decodeToken, handleCallback, redirectToAuth } from 'atauth';
 *
 * // Redirect to authentication
 * redirectToAuth({
 *   gatewayUrl: 'https://auth.example.com',
 *   appId: 'myapp',
 *   callbackUrl: 'https://myapp.com/auth/callback',
 * });
 *
 * // Handle callback
 * const result = handleCallback({ gatewayUrl: 'https://auth.example.com' });
 * if (result.success) {
 *   console.log('Authenticated as:', result.user?.handle);
 * }
 * ```
 *
 * @packageDocumentation
 */

// Types
export type {
  TokenPayload,
  AuthState,
  AuthActions,
  AuthStore,
  AtAuthConfig,
  OAuthState,
  OAuthCallbackResult,
} from './types';

// Token utilities
export {
  decodeToken,
  isTokenExpired,
  getTokenRemainingSeconds,
  getTokenAgeSeconds,
  shouldRefreshToken,
  getDisplayName,
  isValidDid,
  isValidHandle,
} from './token';

// Storage utilities
export {
  storeToken,
  getStoredToken,
  removeStoredToken,
  hasStoredToken,
  storeOAuthState,
  getOAuthState,
  generateNonce,
} from './storage';

// OAuth utilities
export {
  buildAuthUrl,
  redirectToAuth,
  handleCallback,
  isOAuthCallback,
  buildLogoutUrl,
} from './oauth';

/**
 * Library version
 */
export const VERSION = '0.1.0';
