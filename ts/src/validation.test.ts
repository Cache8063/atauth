import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  parseOAuthState,
  isValidAppId,
  requireHttpsInProduction,
  validateGatewayUrl,
  validateCallbackUrl,
  isValidDid,
  isValidHandle,
} from './validation';

describe('parseOAuthState', () => {
  it('parses valid state object', () => {
    const state = JSON.stringify({ returnTo: '/dashboard', nonce: 'abc123' });
    const parsed = parseOAuthState(state);

    expect(parsed).not.toBeNull();
    expect(parsed?.returnTo).toBe('/dashboard');
    expect(parsed?.nonce).toBe('abc123');
  });

  it('returns null for non-string input', () => {
    expect(parseOAuthState(null)).toBeNull();
    expect(parseOAuthState(undefined)).toBeNull();
    expect(parseOAuthState(123)).toBeNull();
    expect(parseOAuthState({})).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    expect(parseOAuthState('not json')).toBeNull();
    expect(parseOAuthState('{invalid')).toBeNull();
  });

  it('returns null for array', () => {
    expect(parseOAuthState('[]')).toBeNull();
    expect(parseOAuthState('[1,2,3]')).toBeNull();
  });

  it('returns null for oversized state', () => {
    const huge = JSON.stringify({ data: 'x'.repeat(5000) });
    expect(parseOAuthState(huge)).toBeNull();
  });

  it('returns null for deeply nested state', () => {
    const deep = JSON.stringify({ a: { b: { c: { d: { e: 'too deep' } } } } });
    expect(parseOAuthState(deep)).toBeNull();
  });

  it('returns null for non-string returnTo', () => {
    expect(parseOAuthState(JSON.stringify({ returnTo: 123 }))).toBeNull();
    expect(parseOAuthState(JSON.stringify({ returnTo: {} }))).toBeNull();
  });

  it('returns null for non-string nonce', () => {
    expect(parseOAuthState(JSON.stringify({ nonce: 123 }))).toBeNull();
  });

  it('returns null for dangerous returnTo schemes', () => {
    expect(parseOAuthState(JSON.stringify({ returnTo: 'javascript:alert(1)' }))).toBeNull();
    expect(parseOAuthState(JSON.stringify({ returnTo: 'data:text/html,<script>' }))).toBeNull();
    expect(parseOAuthState(JSON.stringify({ returnTo: 'vbscript:msgbox' }))).toBeNull();
  });

  it('allows relative URLs in returnTo', () => {
    const state = parseOAuthState(JSON.stringify({ returnTo: '/dashboard' }));
    expect(state?.returnTo).toBe('/dashboard');
  });

  it('allows https URLs in returnTo', () => {
    const state = parseOAuthState(JSON.stringify({ returnTo: 'https://example.com/page' }));
    expect(state?.returnTo).toBe('https://example.com/page');
  });
});

describe('isValidAppId', () => {
  it('accepts valid app IDs', () => {
    expect(isValidAppId('myapp')).toBe(true);
    expect(isValidAppId('my-app')).toBe(true);
    expect(isValidAppId('my_app')).toBe(true);
    expect(isValidAppId('MyApp123')).toBe(true);
  });

  it('rejects non-string input', () => {
    expect(isValidAppId(null)).toBe(false);
    expect(isValidAppId(undefined)).toBe(false);
    expect(isValidAppId(123)).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isValidAppId('')).toBe(false);
  });

  it('rejects oversized app ID', () => {
    expect(isValidAppId('a'.repeat(65))).toBe(false);
  });

  it('rejects invalid characters', () => {
    expect(isValidAppId('my app')).toBe(false);
    expect(isValidAppId('my.app')).toBe(false);
    expect(isValidAppId('my@app')).toBe(false);
  });
});

describe('isValidDid', () => {
  it('accepts did:plc format', () => {
    expect(isValidDid('did:plc:abc123xyz')).toBe(true);
  });

  it('accepts did:web format', () => {
    expect(isValidDid('did:web:example.com')).toBe(true);
  });

  it('rejects non-string', () => {
    expect(isValidDid(null)).toBe(false);
    expect(isValidDid(123)).toBe(false);
  });

  it('rejects invalid DID methods', () => {
    expect(isValidDid('did:key:abc')).toBe(false);
    expect(isValidDid('did:ethr:0x123')).toBe(false);
  });

  it('rejects malformed DIDs', () => {
    expect(isValidDid('not-a-did')).toBe(false);
    expect(isValidDid('did:plc:')).toBe(false);
  });
});

describe('isValidHandle', () => {
  it('accepts valid handles', () => {
    expect(isValidHandle('alice.bsky.social')).toBe(true);
    expect(isValidHandle('user123.example.com')).toBe(true);
  });

  it('rejects non-string', () => {
    expect(isValidHandle(null)).toBe(false);
    expect(isValidHandle(123)).toBe(false);
  });

  it('rejects too short handles', () => {
    expect(isValidHandle('a.b')).toBe(false);
  });

  it('rejects handles with consecutive dots', () => {
    expect(isValidHandle('alice..social')).toBe(false);
  });

  it('rejects uppercase handles', () => {
    expect(isValidHandle('Alice.bsky.social')).toBe(false);
  });
});

describe('requireHttpsInProduction', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('allows HTTP in development', () => {
    process.env.NODE_ENV = 'development';
    expect(() => requireHttpsInProduction('http://localhost:3000')).not.toThrow();
  });

  it('throws for HTTP in production', () => {
    process.env.NODE_ENV = 'production';
    expect(() => requireHttpsInProduction('http://example.com')).toThrow(/HTTPS/);
  });

  it('allows HTTPS in production', () => {
    process.env.NODE_ENV = 'production';
    expect(() => requireHttpsInProduction('https://example.com')).not.toThrow();
  });

  it('throws for invalid URL', () => {
    process.env.NODE_ENV = 'production';
    expect(() => requireHttpsInProduction('not-a-url')).toThrow(/Invalid/);
  });
});

describe('validateGatewayUrl', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('validates gateway URL', () => {
    process.env.NODE_ENV = 'production';
    expect(() => validateGatewayUrl('https://auth.example.com')).not.toThrow();
    expect(() => validateGatewayUrl('http://auth.example.com')).toThrow();
  });
});

describe('validateCallbackUrl', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('validates callback URL', () => {
    process.env.NODE_ENV = 'production';
    expect(() => validateCallbackUrl('https://app.example.com/callback')).not.toThrow();
    expect(() => validateCallbackUrl('http://app.example.com/callback')).toThrow();
  });
});
