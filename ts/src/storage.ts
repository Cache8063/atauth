/**
 * Token storage utilities
 */

const DEFAULT_STORAGE_KEY = 'atauth_token';

/**
 * Get the appropriate storage mechanism.
 */
function getStorage(persist: boolean): Storage | null {
  if (typeof window === 'undefined') {
    return null; // SSR
  }
  return persist ? localStorage : sessionStorage;
}

/**
 * Store authentication token.
 *
 * @param token - Token to store
 * @param key - Storage key (default: "atauth_token")
 * @param persist - Use localStorage (true) or sessionStorage (false)
 */
export function storeToken(
  token: string,
  key = DEFAULT_STORAGE_KEY,
  persist = true
): void {
  const storage = getStorage(persist);
  if (storage) {
    storage.setItem(key, token);
  }
}

/**
 * Retrieve stored authentication token.
 *
 * @param key - Storage key (default: "atauth_token")
 * @param persist - Check localStorage (true) or sessionStorage (false)
 * @returns Stored token or null
 */
export function getStoredToken(
  key = DEFAULT_STORAGE_KEY,
  persist = true
): string | null {
  const storage = getStorage(persist);
  if (storage) {
    return storage.getItem(key);
  }
  return null;
}

/**
 * Remove stored authentication token.
 *
 * @param key - Storage key (default: "atauth_token")
 * @param persist - Remove from localStorage (true) or sessionStorage (false)
 */
export function removeStoredToken(
  key = DEFAULT_STORAGE_KEY,
  persist = true
): void {
  const storage = getStorage(persist);
  if (storage) {
    storage.removeItem(key);
  }
}

/**
 * Check if a token is stored.
 *
 * @param key - Storage key (default: "atauth_token")
 * @param persist - Check localStorage (true) or sessionStorage (false)
 * @returns True if token exists
 */
export function hasStoredToken(
  key = DEFAULT_STORAGE_KEY,
  persist = true
): boolean {
  return getStoredToken(key, persist) !== null;
}

/**
 * Store OAuth state for CSRF protection.
 *
 * @param state - State object to store
 */
export function storeOAuthState(state: Record<string, unknown>): void {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem('atauth_oauth_state', JSON.stringify(state));
  }
}

/**
 * Retrieve and clear OAuth state.
 *
 * @returns Stored state or null
 */
export function getOAuthState(): Record<string, unknown> | null {
  if (typeof sessionStorage === 'undefined') {
    return null;
  }

  const stored = sessionStorage.getItem('atauth_oauth_state');
  if (stored) {
    sessionStorage.removeItem('atauth_oauth_state');
    try {
      return JSON.parse(stored);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Generate a random nonce for CSRF protection.
 *
 * @param length - Nonce length (default: 32)
 * @returns Random string
 * @throws Error if no secure random source is available
 */
export function generateNonce(length = 32): string {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';

  // Require crypto.getRandomValues - no insecure fallback
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error(
      'Secure random number generator not available. ' +
      'crypto.getRandomValues is required for CSRF protection.'
    );
  }

  const values = new Uint32Array(length);
  crypto.getRandomValues(values);
  for (let i = 0; i < length; i++) {
    result += chars[values[i] % chars.length];
  }

  return result;
}
