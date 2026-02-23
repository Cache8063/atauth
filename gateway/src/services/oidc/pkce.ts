/**
 * PKCE (Proof Key for Code Exchange) Utilities
 *
 * Handles PKCE code challenge verification for OAuth 2.0
 */

import crypto from 'crypto';

/**
 * Verify a PKCE code verifier against a code challenge
 */
export function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
  method: 'S256' | 'plain' = 'S256'
): boolean {
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }

  // S256: SHA256(code_verifier) base64url encoded
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const computed = hash.toString('base64url');

  return computed === codeChallenge;
}

/**
 * Generate a code verifier for testing
 */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generate a code challenge from a code verifier
 */
export function generateCodeChallenge(codeVerifier: string, method: 'S256' | 'plain' = 'S256'): string {
  if (method === 'plain') {
    return codeVerifier;
  }

  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  return hash.toString('base64url');
}

/**
 * Validate code verifier format
 * Must be 43-128 characters, containing only [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
export function isValidCodeVerifier(codeVerifier: string): boolean {
  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false;
  }

  return /^[A-Za-z0-9\-._~]+$/.test(codeVerifier);
}

/**
 * Validate code challenge method
 */
export function isValidCodeChallengeMethod(method: string): method is 'S256' | 'plain' {
  return method === 'S256' || method === 'plain';
}
