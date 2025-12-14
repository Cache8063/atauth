/**
 * Input validation utilities
 */

import type { OAuthState } from './types';

/**
 * Check if the current environment is production.
 * Uses common environment indicators.
 */
function isProduction(): boolean {
  if (typeof process !== 'undefined' && process.env) {
    return process.env.NODE_ENV === 'production';
  }
  // Browser fallback: check if running on non-localhost
  if (typeof window !== 'undefined') {
    const hostname = window.location?.hostname;
    return hostname !== 'localhost' && hostname !== '127.0.0.1' && hostname !== '::1';
  }
  return false;
}

/**
 * Require HTTPS for gateway URLs in production.
 *
 * In production environments, all gateway URLs must use HTTPS to protect
 * tokens in transit. This prevents man-in-the-middle attacks.
 *
 * @param url - The URL to validate
 * @param context - Description for error message (e.g., "gatewayUrl")
 * @throws Error if HTTPS is required but not used
 */
export function requireHttpsInProduction(url: string, context = 'URL'): void {
  if (!isProduction()) {
    return; // Allow HTTP in development
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      throw new Error(
        `Security error: ${context} must use HTTPS in production. ` +
        `Got "${parsed.protocol}" in "${url}"`
      );
    }
  } catch (e) {
    if (e instanceof Error && e.message.startsWith('Security error:')) {
      throw e;
    }
    throw new Error(`Invalid ${context}: ${url}`);
  }
}

/**
 * Validate gateway URL for security requirements.
 *
 * @param gatewayUrl - The gateway URL to validate
 * @throws Error if URL is invalid or insecure
 */
export function validateGatewayUrl(gatewayUrl: string): void {
  requireHttpsInProduction(gatewayUrl, 'gatewayUrl');
}

/**
 * Validate callback URL for security requirements.
 *
 * @param callbackUrl - The callback URL to validate
 * @throws Error if URL is invalid or insecure
 */
export function validateCallbackUrl(callbackUrl: string): void {
  requireHttpsInProduction(callbackUrl, 'callbackUrl');
}

/**
 * Maximum allowed size for OAuth state string to prevent DoS.
 */
const MAX_STATE_SIZE = 4096;

/**
 * Maximum nesting depth for state object.
 */
const MAX_NESTING_DEPTH = 3;

/**
 * Validate a DID (Decentralized Identifier) format.
 *
 * @param did - The DID string to validate
 * @returns True if valid DID format
 */
export function isValidDid(did: unknown): did is string {
  if (typeof did !== 'string') return false;

  // AT Protocol DIDs start with "did:plc:" or "did:web:"
  return /^did:(plc|web):[a-zA-Z0-9._%-]+$/.test(did);
}

/**
 * Validate an AT Protocol handle format.
 *
 * @param handle - The handle to validate
 * @returns True if valid handle format
 */
export function isValidHandle(handle: unknown): handle is string {
  if (typeof handle !== 'string') return false;

  // Handles are domain-like strings (e.g., "user.bsky.social")
  // Must be lowercase alphanumeric with dots, 3-253 chars
  if (handle.length < 3 || handle.length > 253) return false;

  return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(handle) &&
    !handle.includes('..');
}

/**
 * Check object nesting depth.
 */
function getDepth(obj: unknown, current = 0): number {
  if (current > MAX_NESTING_DEPTH) return current;
  if (typeof obj !== 'object' || obj === null) return current;

  let maxDepth = current;
  for (const value of Object.values(obj)) {
    const depth = getDepth(value, current + 1);
    if (depth > maxDepth) maxDepth = depth;
  }
  return maxDepth;
}

/**
 * Validate and parse OAuth state from a string.
 * Guards against malformed JSON, oversized payloads, and deeply nested objects.
 *
 * @param stateString - The state string from URL parameter
 * @returns Validated OAuthState or null if invalid
 */
export function parseOAuthState(stateString: unknown): OAuthState | null {
  // Must be a string
  if (typeof stateString !== 'string') {
    return null;
  }

  // Check size limit to prevent DoS
  if (stateString.length > MAX_STATE_SIZE) {
    console.warn('OAuth state exceeds maximum size');
    return null;
  }

  // Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(stateString);
  } catch {
    console.warn('OAuth state is not valid JSON');
    return null;
  }

  // Must be an object
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    console.warn('OAuth state must be an object');
    return null;
  }

  // Check nesting depth
  if (getDepth(parsed) > MAX_NESTING_DEPTH) {
    console.warn('OAuth state exceeds maximum nesting depth');
    return null;
  }

  // Validate known fields
  const state = parsed as Record<string, unknown>;

  // returnTo must be a string if present
  if ('returnTo' in state && typeof state.returnTo !== 'string') {
    console.warn('OAuth state returnTo must be a string');
    return null;
  }

  // nonce must be a string if present
  if ('nonce' in state && typeof state.nonce !== 'string') {
    console.warn('OAuth state nonce must be a string');
    return null;
  }

  // Validate returnTo is a safe URL (no javascript: etc.)
  if (typeof state.returnTo === 'string') {
    try {
      const url = new URL(state.returnTo, window?.location?.origin || 'https://example.com');
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        console.warn('OAuth state returnTo has invalid protocol');
        return null;
      }
    } catch {
      // Relative URLs are OK, but must not contain dangerous schemes
      if (/^(javascript|data|vbscript):/i.test(state.returnTo)) {
        console.warn('OAuth state returnTo has dangerous scheme');
        return null;
      }
    }
  }

  return state as OAuthState;
}

/**
 * Validate an app ID.
 *
 * @param appId - The app ID to validate
 * @returns True if valid
 */
export function isValidAppId(appId: unknown): appId is string {
  if (typeof appId !== 'string') return false;

  // App IDs should be alphanumeric with hyphens/underscores, 1-64 chars
  return /^[a-zA-Z0-9_-]{1,64}$/.test(appId);
}
