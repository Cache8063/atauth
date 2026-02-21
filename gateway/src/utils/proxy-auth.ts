/**
 * Forward-Auth Proxy Utilities
 *
 * HMAC-signed cookie and ticket creation/verification for the
 * forward-auth SSO gateway. Follows the same pattern as utils/hmac.ts.
 */

import crypto from 'crypto';
import type { ProxySessionCookiePayload, ProxyTicketPayload } from '../types/proxy.js';

const ALGORITHM = 'sha256';

export const SESSION_COOKIE_NAME = '_atauth_session';
export const PROXY_COOKIE_NAME = '_atauth_proxy';
export const ADMIN_COOKIE_NAME = '_atauth_admin';

// ===== Cookie Utilities =====

/**
 * Create an HMAC-signed session cookie value (for ATAuth domain).
 * Includes typ:'session' to prevent cookie confusion with proxy cookies.
 */
export function createSessionCookie(sessionId: string, secret: string, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: ProxySessionCookiePayload = { typ: 'session', sid: sessionId, iat: now, exp: now + ttlSeconds };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac(ALGORITHM, secret).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${signature}`;
}

/**
 * Verify an HMAC-signed session cookie.
 * Rejects cookies with wrong type to prevent cookie confusion attacks.
 */
export function verifySessionCookie(cookie: string, secret: string): string | null {
  const payload = verifyHmacToken<ProxySessionCookiePayload>(cookie, secret);
  if (!payload || payload.typ !== 'session') return null;
  return payload.sid;
}

// ===== Proxy Cookie Utilities =====

/**
 * Create an HMAC-signed proxy cookie (set on the protected service domain).
 * Includes typ:'proxy' to prevent cookie confusion with session cookies.
 */
export function createProxyCookie(sessionId: string, secret: string, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: ProxySessionCookiePayload = { typ: 'proxy', sid: sessionId, iat: now, exp: now + ttlSeconds };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac(ALGORITHM, secret).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${signature}`;
}

/**
 * Verify an HMAC-signed proxy cookie.
 * Rejects cookies with wrong type to prevent cookie confusion attacks.
 */
export function verifyProxyCookie(cookie: string, secret: string): string | null {
  const payload = verifyHmacToken<ProxySessionCookiePayload>(cookie, secret);
  if (!payload || payload.typ !== 'proxy') return null;
  return payload.sid;
}

// ===== Admin Cookie Utilities =====

/**
 * Create an HMAC-signed admin session cookie (24h TTL).
 * Proves the bearer successfully authenticated with the admin token.
 */
export function createAdminCookie(secret: string, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: ProxySessionCookiePayload = { typ: 'admin', sid: 'admin', iat: now, exp: now + ttlSeconds };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac(ALGORITHM, secret).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${signature}`;
}

/**
 * Verify an HMAC-signed admin session cookie.
 * Returns true if valid, false otherwise.
 */
export function verifyAdminCookie(cookie: string, secret: string): boolean {
  const payload = verifyHmacToken<ProxySessionCookiePayload>(cookie, secret);
  return payload !== null && payload.typ === 'admin';
}

// ===== Auth Ticket Utilities =====

/**
 * Create a signed auth ticket for the redirect-back flow.
 * Short-lived (60s), embedded in the redirect URL.
 */
export function createAuthTicket(
  sessionId: string,
  did: string,
  handle: string,
  targetOrigin: string,
  secret: string,
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: ProxyTicketPayload = {
    sid: sessionId,
    did,
    handle,
    origin: targetOrigin,
    iat: now,
    exp: now + 60, // 60 seconds
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac(ALGORITHM, secret).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${signature}`;
}

/**
 * Verify a signed auth ticket.
 * Returns the full payload if valid, null otherwise.
 */
export function verifyAuthTicket(
  ticket: string,
  secret: string,
  expectedOrigin?: string,
): ProxyTicketPayload | null {
  const payload = verifyHmacToken<ProxyTicketPayload>(ticket, secret);
  if (!payload) return null;
  if (expectedOrigin && payload.origin !== expectedOrigin) return null;
  return payload;
}

// ===== Helpers =====

/**
 * Generic HMAC token verification with constant-time comparison.
 */
function verifyHmacToken<T extends { exp: number }>(token: string, secret: string): T | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadBase64, providedSignature] = parts;
  const expectedSignature = crypto.createHmac(ALGORITHM, secret).update(payloadBase64).digest('base64url');

  const providedBuf = Buffer.from(providedSignature);
  const expectedBuf = Buffer.from(expectedSignature);

  if (providedBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8')) as T;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Parse a Cookie header string into key-value pairs.
 */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.substring(0, idx).trim();
    const value = pair.substring(idx + 1).trim();
    if (key) cookies[key] = value;
  }
  return cookies;
}

/**
 * Validate that a redirect URL belongs to an allowed origin.
 */
export function isAllowedRedirect(url: string, allowedOrigins: string[]): boolean {
  try {
    const parsed = new URL(url);
    return allowedOrigins.includes(parsed.origin);
  } catch {
    return false;
  }
}

/**
 * Extract origin from a URL string.
 */
export function extractOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}
