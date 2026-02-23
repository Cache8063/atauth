import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  decodeToken,
  isTokenExpired,
  getTokenRemainingSeconds,
  getTokenAgeSeconds,
  shouldRefreshToken,
  getDisplayName,
  isValidDid,
  isValidHandle,
} from './token';

// Helper to create a valid token payload
function createPayload(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    did: 'did:plc:abc123',
    handle: 'alice.bsky.social',
    user_id: 1,
    app_id: 'testapp',
    iat: now,
    exp: now + 3600, // 1 hour
    nonce: 'test-nonce',
    ...overrides,
  };
}

// Helper to encode a payload as a token (without signature)
function encodePayload(payload: object): string {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString('base64url');
  return `${b64}.fake-signature`;
}

describe('decodeToken', () => {
  it('decodes a valid token', () => {
    const payload = createPayload();
    const token = encodePayload(payload);
    const decoded = decodeToken(token);

    expect(decoded).not.toBeNull();
    expect(decoded?.did).toBe(payload.did);
    expect(decoded?.handle).toBe(payload.handle);
  });

  it('returns null for invalid format (no dot)', () => {
    expect(decodeToken('invalid-token')).toBeNull();
  });

  it('returns null for invalid format (too many dots)', () => {
    expect(decodeToken('a.b.c')).toBeNull();
  });

  it('returns null for invalid base64', () => {
    expect(decodeToken('!!!invalid!!!.signature')).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    const invalidJson = Buffer.from('not json').toString('base64url');
    expect(decodeToken(`${invalidJson}.signature`)).toBeNull();
  });
});

describe('isTokenExpired', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns false for non-expired token', () => {
    const now = 1700000000000;
    vi.setSystemTime(now);

    const payload = createPayload({
      iat: 1700000000,
      exp: 1700003600, // 1 hour from now
    });

    expect(isTokenExpired(payload)).toBe(false);
  });

  it('returns true for expired token', () => {
    const now = 1700010000000; // Well past exp
    vi.setSystemTime(now);

    const payload = createPayload({
      iat: 1700000000,
      exp: 1700003600,
    });

    expect(isTokenExpired(payload)).toBe(true);
  });

  it('respects clock skew tolerance', () => {
    const now = 1700003610000; // 10 seconds past exp
    vi.setSystemTime(now);

    const payload = createPayload({
      iat: 1700000000,
      exp: 1700003600,
    });

    // With default 30s skew, should not be expired
    expect(isTokenExpired(payload, 30)).toBe(false);

    // With 0s skew, should be expired
    expect(isTokenExpired(payload, 0)).toBe(true);
  });
});

describe('getTokenRemainingSeconds', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns correct remaining time', () => {
    const now = 1700000000000;
    vi.setSystemTime(now);

    const payload = createPayload({
      exp: 1700003600, // 3600 seconds from now
    });

    expect(getTokenRemainingSeconds(payload)).toBe(3600);
  });

  it('returns 0 for expired token', () => {
    const now = 1700010000000;
    vi.setSystemTime(now);

    const payload = createPayload({
      exp: 1700003600,
    });

    expect(getTokenRemainingSeconds(payload)).toBe(0);
  });
});

describe('getTokenAgeSeconds', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns correct age', () => {
    const now = 1700001800000; // 1800 seconds after iat
    vi.setSystemTime(now);

    const payload = createPayload({
      iat: 1700000000,
    });

    expect(getTokenAgeSeconds(payload)).toBe(1800);
  });
});

describe('shouldRefreshToken', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns false when plenty of time remaining', () => {
    const now = 1700000000000;
    vi.setSystemTime(now);

    const payload = createPayload({
      exp: 1700003600, // 3600 seconds remaining
    });

    expect(shouldRefreshToken(payload, 300)).toBe(false);
  });

  it('returns true when below threshold', () => {
    const now = 1700003400000; // 200 seconds remaining
    vi.setSystemTime(now);

    const payload = createPayload({
      exp: 1700003600,
    });

    expect(shouldRefreshToken(payload, 300)).toBe(true);
  });
});

describe('getDisplayName', () => {
  it('extracts username from handle', () => {
    expect(getDisplayName('alice.bsky.social')).toBe('alice');
  });

  it('handles single-part handle', () => {
    expect(getDisplayName('alice')).toBe('alice');
  });

  it('handles empty string', () => {
    expect(getDisplayName('')).toBe('');
  });
});

describe('isValidDid', () => {
  it('accepts valid did:plc', () => {
    expect(isValidDid('did:plc:abc123')).toBe(true);
  });

  it('accepts valid did:web', () => {
    expect(isValidDid('did:web:example.com')).toBe(true);
  });

  it('rejects empty string', () => {
    expect(isValidDid('')).toBe(false);
  });

  it('rejects non-did string', () => {
    expect(isValidDid('not-a-did')).toBe(false);
  });

  it('rejects did with missing parts', () => {
    expect(isValidDid('did:plc')).toBe(false);
    expect(isValidDid('did:')).toBe(false);
  });

  it('rejects oversized did', () => {
    const longDid = 'did:plc:' + 'a'.repeat(600);
    expect(isValidDid(longDid)).toBe(false);
  });
});

describe('isValidHandle', () => {
  it('accepts valid handle', () => {
    expect(isValidHandle('alice.bsky.social')).toBe(true);
  });

  it('accepts short TLD', () => {
    expect(isValidHandle('user.co')).toBe(true);
  });

  it('rejects empty string', () => {
    expect(isValidHandle('')).toBe(false);
  });

  it('rejects handle without dot', () => {
    expect(isValidHandle('alice')).toBe(false);
  });

  it('rejects single-char TLD', () => {
    expect(isValidHandle('user.a')).toBe(false);
  });

  it('rejects oversized handle', () => {
    const longHandle = 'a'.repeat(200) + '.com';
    expect(isValidHandle(longHandle)).toBe(false);
  });

  it('rejects handle with empty segment', () => {
    expect(isValidHandle('alice..social')).toBe(false);
    expect(isValidHandle('.bsky.social')).toBe(false);
  });
});
