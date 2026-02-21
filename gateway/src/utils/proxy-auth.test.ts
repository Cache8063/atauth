/**
 * Forward-Auth Proxy Utilities Tests
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  createSessionCookie,
  verifySessionCookie,
  createProxyCookie,
  verifyProxyCookie,
  createAdminCookie,
  verifyAdminCookie,
  createAuthTicket,
  verifyAuthTicket,
  parseCookies,
  isAllowedRedirect,
  extractOrigin,
  SESSION_COOKIE_NAME,
  PROXY_COOKIE_NAME,
  ADMIN_COOKIE_NAME,
} from './proxy-auth.js';

const TEST_SECRET = 'test-secret-for-hmac-signing-32b!';

describe('Session Cookie', () => {
  it('should create and verify a session cookie', () => {
    const cookie = createSessionCookie('session-123', TEST_SECRET, 3600);
    const result = verifySessionCookie(cookie, TEST_SECRET);
    expect(result).toBe('session-123');
  });

  it('should reject an expired cookie', () => {
    vi.useFakeTimers();
    const cookie = createSessionCookie('session-123', TEST_SECRET, 60);
    // Advance past expiry
    vi.advanceTimersByTime(61 * 1000);
    const result = verifySessionCookie(cookie, TEST_SECRET);
    expect(result).toBeNull();
    vi.useRealTimers();
  });

  it('should reject a tampered cookie', () => {
    const cookie = createSessionCookie('session-123', TEST_SECRET, 3600);
    const tampered = cookie.slice(0, -1) + 'x';
    const result = verifySessionCookie(tampered, TEST_SECRET);
    expect(result).toBeNull();
  });

  it('should reject a cookie with wrong secret', () => {
    const cookie = createSessionCookie('session-123', TEST_SECRET, 3600);
    const result = verifySessionCookie(cookie, 'wrong-secret');
    expect(result).toBeNull();
  });

  it('should reject malformed cookies', () => {
    expect(verifySessionCookie('', TEST_SECRET)).toBeNull();
    expect(verifySessionCookie('no-dots', TEST_SECRET)).toBeNull();
    expect(verifySessionCookie('too.many.dots', TEST_SECRET)).toBeNull();
    expect(verifySessionCookie('invalid.base64!', TEST_SECRET)).toBeNull();
  });
});

describe('Proxy Cookie', () => {
  it('should create and verify a proxy cookie', () => {
    const cookie = createProxyCookie('session-456', TEST_SECRET, 86400);
    const result = verifyProxyCookie(cookie, TEST_SECRET);
    expect(result).toBe('session-456');
  });
});

describe('Cookie Confusion Prevention', () => {
  it('should reject a proxy cookie used as a session cookie', () => {
    const proxyCookie = createProxyCookie('session-123', TEST_SECRET, 3600);
    const result = verifySessionCookie(proxyCookie, TEST_SECRET);
    expect(result).toBeNull();
  });

  it('should reject a session cookie used as a proxy cookie', () => {
    const sessionCookie = createSessionCookie('session-123', TEST_SECRET, 3600);
    const result = verifyProxyCookie(sessionCookie, TEST_SECRET);
    expect(result).toBeNull();
  });
});

describe('Auth Ticket', () => {
  it('should create and verify an auth ticket', () => {
    const ticket = createAuthTicket(
      'session-789', 'did:plc:abc123', 'user.bsky.social',
      'https://search.arcnode.xyz', TEST_SECRET,
    );
    const result = verifyAuthTicket(ticket, TEST_SECRET);
    expect(result).not.toBeNull();
    expect(result!.sid).toBe('session-789');
    expect(result!.did).toBe('did:plc:abc123');
    expect(result!.handle).toBe('user.bsky.social');
    expect(result!.origin).toBe('https://search.arcnode.xyz');
  });

  it('should reject an expired ticket', () => {
    vi.useFakeTimers();
    const ticket = createAuthTicket(
      'session-789', 'did:plc:abc123', 'user.bsky.social',
      'https://search.arcnode.xyz', TEST_SECRET,
    );
    // Advance past 60s expiry
    vi.advanceTimersByTime(61 * 1000);
    const result = verifyAuthTicket(ticket, TEST_SECRET);
    expect(result).toBeNull();
    vi.useRealTimers();
  });

  it('should reject a ticket with wrong origin', () => {
    const ticket = createAuthTicket(
      'session-789', 'did:plc:abc123', 'user.bsky.social',
      'https://search.arcnode.xyz', TEST_SECRET,
    );
    const result = verifyAuthTicket(ticket, TEST_SECRET, 'https://evil.example.com');
    expect(result).toBeNull();
  });

  it('should accept a ticket with matching expected origin', () => {
    const ticket = createAuthTicket(
      'session-789', 'did:plc:abc123', 'user.bsky.social',
      'https://search.arcnode.xyz', TEST_SECRET,
    );
    const result = verifyAuthTicket(ticket, TEST_SECRET, 'https://search.arcnode.xyz');
    expect(result).not.toBeNull();
    expect(result!.sid).toBe('session-789');
  });

  it('should reject a tampered ticket', () => {
    const ticket = createAuthTicket(
      'session-789', 'did:plc:abc123', 'user.bsky.social',
      'https://search.arcnode.xyz', TEST_SECRET,
    );
    const tampered = ticket.slice(0, -1) + 'x';
    const result = verifyAuthTicket(tampered, TEST_SECRET);
    expect(result).toBeNull();
  });
});

describe('parseCookies', () => {
  it('should parse a standard cookie header', () => {
    const result = parseCookies('foo=bar; baz=qux');
    expect(result).toEqual({ foo: 'bar', baz: 'qux' });
  });

  it('should handle cookies with = in the value', () => {
    const result = parseCookies('token=abc=def=ghi');
    expect(result).toEqual({ token: 'abc=def=ghi' });
  });

  it('should return empty object for undefined', () => {
    expect(parseCookies(undefined)).toEqual({});
  });

  it('should return empty object for empty string', () => {
    expect(parseCookies('')).toEqual({});
  });

  it('should trim whitespace', () => {
    const result = parseCookies('  foo = bar ;  baz = qux  ');
    expect(result).toEqual({ foo: 'bar', baz: 'qux' });
  });
});

describe('isAllowedRedirect', () => {
  const allowed = ['https://search.arcnode.xyz', 'https://element.arcnode.xyz'];

  it('should allow a URL with an allowed origin', () => {
    expect(isAllowedRedirect('https://search.arcnode.xyz/some/path', allowed)).toBe(true);
    expect(isAllowedRedirect('https://element.arcnode.xyz/', allowed)).toBe(true);
  });

  it('should reject a URL with a disallowed origin', () => {
    expect(isAllowedRedirect('https://evil.example.com/search', allowed)).toBe(false);
  });

  it('should reject an invalid URL', () => {
    expect(isAllowedRedirect('not-a-url', allowed)).toBe(false);
  });

  it('should reject a URL with different port', () => {
    expect(isAllowedRedirect('https://search.arcnode.xyz:8443/path', allowed)).toBe(false);
  });

  it('should reject a URL with different scheme', () => {
    expect(isAllowedRedirect('http://search.arcnode.xyz/path', allowed)).toBe(false);
  });
});

describe('extractOrigin', () => {
  it('should extract origin from a full URL', () => {
    expect(extractOrigin('https://search.arcnode.xyz/some/path?q=test')).toBe('https://search.arcnode.xyz');
  });

  it('should return null for invalid URL', () => {
    expect(extractOrigin('not-a-url')).toBeNull();
  });
});

describe('Admin Cookie', () => {
  it('should create and verify an admin cookie', () => {
    const cookie = createAdminCookie(TEST_SECRET, 86400);
    expect(verifyAdminCookie(cookie, TEST_SECRET)).toBe(true);
  });

  it('should reject an expired admin cookie', () => {
    vi.useFakeTimers();
    const cookie = createAdminCookie(TEST_SECRET, 60);
    vi.advanceTimersByTime(61 * 1000);
    expect(verifyAdminCookie(cookie, TEST_SECRET)).toBe(false);
    vi.useRealTimers();
  });

  it('should reject admin cookie with wrong secret', () => {
    const cookie = createAdminCookie(TEST_SECRET, 86400);
    expect(verifyAdminCookie(cookie, 'wrong-secret')).toBe(false);
  });

  it('should reject session cookie as admin cookie', () => {
    const sessionCookie = createSessionCookie('sid', TEST_SECRET, 3600);
    expect(verifyAdminCookie(sessionCookie, TEST_SECRET)).toBe(false);
  });

  it('should reject proxy cookie as admin cookie', () => {
    const proxyCookie = createProxyCookie('sid', TEST_SECRET, 3600);
    expect(verifyAdminCookie(proxyCookie, TEST_SECRET)).toBe(false);
  });
});

describe('Cookie names', () => {
  it('should export expected cookie names', () => {
    expect(SESSION_COOKIE_NAME).toBe('_atauth_session');
    expect(PROXY_COOKIE_NAME).toBe('_atauth_proxy');
    expect(ADMIN_COOKIE_NAME).toBe('_atauth_admin');
  });
});
