/**
 * Token decoding and utilities
 *
 * NOTE: This is CLIENT-SIDE decoding only. Actual verification
 * should be done server-side using the Rust library.
 */

import type { TokenPayload } from './types';

/**
 * Base64url decode (RFC 4648)
 */
function base64UrlDecode(str: string): string {
  // Add padding if needed
  let padded = str;
  while (padded.length % 4 !== 0) {
    padded += '=';
  }

  // Convert base64url to base64
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

  // Decode
  if (typeof atob === 'function') {
    return atob(base64);
  }

  // Node.js fallback
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Decode a token payload WITHOUT verification.
 *
 * ⚠️ WARNING: This does NOT verify the signature!
 * Use this only for client-side display purposes.
 * Always verify tokens server-side before trusting them.
 *
 * @param token - The token string in format "payload.signature"
 * @returns Decoded payload or null if invalid format
 */
export function decodeToken(token: string): TokenPayload | null {
  try {
    // Split token
    const parts = token.split('.');
    if (parts.length !== 2) {
      console.warn('Invalid token format: expected payload.signature');
      return null;
    }

    // Decode payload
    const payloadJson = base64UrlDecode(parts[0]);
    const payload = JSON.parse(payloadJson) as TokenPayload;

    return payload;
  } catch (error) {
    console.error('Failed to decode token:', error);
    return null;
  }
}

/**
 * Check if a decoded token is expired.
 *
 * @param payload - Decoded token payload
 * @param clockSkewSeconds - Tolerance for clock differences (default: 30)
 * @returns True if expired
 */
export function isTokenExpired(
  payload: TokenPayload,
  clockSkewSeconds = 30
): boolean {
  const now = Math.floor(Date.now() / 1000);
  return now > payload.exp + clockSkewSeconds;
}

/**
 * Get remaining token validity in seconds.
 *
 * @param payload - Decoded token payload
 * @returns Seconds remaining (0 if expired)
 */
export function getTokenRemainingSeconds(payload: TokenPayload): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(0, payload.exp - now);
}

/**
 * Get token age in seconds since issuance.
 *
 * @param payload - Decoded token payload
 * @returns Seconds since token was issued
 */
export function getTokenAgeSeconds(payload: TokenPayload): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(0, now - payload.iat);
}

/**
 * Check if a token should be refreshed.
 *
 * @param payload - Decoded token payload
 * @param thresholdSeconds - Refresh if less than this many seconds remaining
 * @returns True if token should be refreshed
 */
export function shouldRefreshToken(
  payload: TokenPayload,
  thresholdSeconds = 300
): boolean {
  return getTokenRemainingSeconds(payload) < thresholdSeconds;
}

/**
 * Extract display name from handle.
 *
 * @param handle - Full handle (e.g., "alice.bsky.social")
 * @returns Username portion (e.g., "alice")
 */
export function getDisplayName(handle: string): string {
  const parts = handle.split('.');
  return parts[0] || handle;
}

/**
 * Validate DID format (basic client-side check).
 *
 * @param did - DID string to validate
 * @returns True if format is valid
 */
export function isValidDid(did: string): boolean {
  if (!did || did.length > 512) return false;
  if (!did.startsWith('did:')) return false;

  const parts = did.split(':');
  return parts.length >= 3 && parts[1].length > 0 && parts[2].length > 0;
}

/**
 * Validate handle format (basic client-side check).
 *
 * @param handle - Handle string to validate
 * @returns True if format is valid
 */
export function isValidHandle(handle: string): boolean {
  if (!handle || handle.length > 256) return false;
  if (!handle.includes('.')) return false;

  const parts = handle.split('.');
  if (parts.some((p) => p.length === 0 || p.length > 63)) return false;

  // TLD must be at least 2 chars
  const tld = parts[parts.length - 1];
  return tld.length >= 2;
}
