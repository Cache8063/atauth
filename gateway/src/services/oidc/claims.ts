/**
 * OIDC Claims Builder
 *
 * Builds standard OIDC claims based on requested scopes
 */

import type { UserInfoResponse } from '../../types/index.js';

/**
 * Supported OIDC scopes
 */
export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

export type SupportedScope = (typeof SUPPORTED_SCOPES)[number];

/**
 * Check if a scope is supported
 */
export function isSupportedScope(scope: string): scope is SupportedScope {
  return SUPPORTED_SCOPES.includes(scope as SupportedScope);
}

/**
 * Parse and validate a scope string
 */
export function parseScopes(scopeString: string): string[] {
  return scopeString.split(' ').filter((s) => s.length > 0);
}

/**
 * Filter to only supported scopes
 */
export function filterSupportedScopes(scopes: string[]): string[] {
  return scopes.filter(isSupportedScope);
}

/**
 * Check if openid scope is included (required for OIDC)
 */
export function hasOpenIdScope(scopes: string[]): boolean {
  return scopes.includes('openid');
}

/**
 * Check if offline_access scope is included (for refresh tokens)
 */
export function hasOfflineAccessScope(scopes: string[]): boolean {
  return scopes.includes('offline_access');
}

/**
 * Build UserInfo response based on scopes
 */
export function buildUserInfo(
  user: {
    did: string;
    handle: string;
    email?: string;
    emailVerified?: boolean;
  },
  scopes: string[]
): UserInfoResponse {
  // sub is always included
  const response: UserInfoResponse = {
    sub: user.did,
  };

  // profile scope: name, preferred_username, etc.
  if (scopes.includes('profile')) {
    response.handle = user.handle;
    response.did = user.did;
    response.preferred_username = user.handle;
    // Extract name from handle (before the first .)
    const namePart = user.handle.split('.')[0];
    if (namePart) {
      response.name = namePart;
    }
  }

  // email scope: email, email_verified
  // Note: Email requires user to have added and verified an email
  // This will be populated from user_emails table when available

  return response;
}

/**
 * Validate requested scopes against allowed scopes for a client
 */
export function validateScopes(requestedScopes: string[], allowedScopes: string[]): {
  valid: boolean;
  scopes: string[];
  error?: string;
} {
  const requested = parseScopes(requestedScopes.join(' '));

  // Must include openid for OIDC
  if (!hasOpenIdScope(requested)) {
    return {
      valid: false,
      scopes: [],
      error: 'openid scope is required',
    };
  }

  // Filter to only allowed and supported scopes
  const filtered = requested.filter(
    (scope) => allowedScopes.includes(scope) && isSupportedScope(scope)
  );

  // Check if any requested scope was denied
  const denied = requested.filter(
    (scope) => !allowedScopes.includes(scope) || !isSupportedScope(scope)
  );

  if (denied.length > 0) {
    // Return only allowed scopes, but don't fail
    return {
      valid: true,
      scopes: filtered,
    };
  }

  return {
    valid: true,
    scopes: filtered,
  };
}

/**
 * Get default scopes for a client
 */
export function getDefaultScopes(allowedScopes: string[]): string[] {
  // Default to openid + profile if allowed
  const defaults: string[] = ['openid'];

  if (allowedScopes.includes('profile')) {
    defaults.push('profile');
  }

  return defaults;
}
