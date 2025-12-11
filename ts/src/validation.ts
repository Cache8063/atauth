/**
 * Input validation utilities
 */

import type { OAuthState } from './types';

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
