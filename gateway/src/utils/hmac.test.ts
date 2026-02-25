import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createGatewayToken, verifyGatewayToken, generateHmacSecret } from './hmac.js';

const TEST_SECRET = 'a'.repeat(64);

describe('generateHmacSecret', () => {
  it('should return a 64 character hex string', () => {
    const secret = generateHmacSecret();
    expect(secret).toHaveLength(64);
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should return unique values', () => {
    const a = generateHmacSecret();
    const b = generateHmacSecret();
    expect(a).not.toBe(b);
  });
});

describe('createGatewayToken', () => {
  it('should create a token with payload.signature format', () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'test.bsky.social', user_id: 1, app_id: 'myapp' },
      TEST_SECRET,
    );
    const parts = token.split('.');
    expect(parts).toHaveLength(2);
    expect(parts[0].length).toBeGreaterThan(0);
    expect(parts[1].length).toBeGreaterThan(0);
  });

  it('should embed iat, exp, and nonce in the payload', () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'test.bsky.social', user_id: null, app_id: 'myapp' },
      TEST_SECRET,
      3600,
    );
    const payload = verifyGatewayToken(token, TEST_SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.iat).toBeTypeOf('number');
    expect(payload!.exp).toBe(payload!.iat + 3600);
    expect(payload!.nonce).toHaveLength(32); // 16 bytes as hex
    expect(payload!.did).toBe('did:plc:test');
    expect(payload!.handle).toBe('test.bsky.social');
    expect(payload!.user_id).toBeNull();
    expect(payload!.app_id).toBe('myapp');
  });

  it('should use default TTL of 3600 seconds', () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'a' },
      TEST_SECRET,
    );
    const payload = verifyGatewayToken(token, TEST_SECRET);
    expect(payload!.exp - payload!.iat).toBe(3600);
  });
});

describe('verifyGatewayToken', () => {
  it('should verify a valid token', () => {
    const token = createGatewayToken(
      { did: 'did:plc:abc', handle: 'alice.bsky.social', user_id: 42, app_id: 'app1' },
      TEST_SECRET,
    );
    const payload = verifyGatewayToken(token, TEST_SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.did).toBe('did:plc:abc');
    expect(payload!.app_id).toBe('app1');
    expect(payload!.user_id).toBe(42);
  });

  it('should reject a token signed with a different secret', () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'a' },
      TEST_SECRET,
    );
    const result = verifyGatewayToken(token, 'b'.repeat(64));
    expect(result).toBeNull();
  });

  it('should reject a tampered payload', () => {
    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'a' },
      TEST_SECRET,
    );
    const [_payload, sig] = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ did: 'did:plc:evil', handle: 'h', user_id: 1, app_id: 'a', iat: 0, exp: 9999999999, nonce: 'x' })).toString('base64url');
    const result = verifyGatewayToken(`${tamperedPayload}.${sig}`, TEST_SECRET);
    expect(result).toBeNull();
  });

  it('should reject an expired token', () => {
    vi.useFakeTimers();
    const now = Date.now();
    vi.setSystemTime(now);

    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'a' },
      TEST_SECRET,
      60, // 60 second TTL
    );

    // Advance past expiry
    vi.setSystemTime(now + 61 * 1000);
    const result = verifyGatewayToken(token, TEST_SECRET);
    expect(result).toBeNull();

    vi.useRealTimers();
  });

  it('should accept a token that has not expired yet', () => {
    vi.useFakeTimers();
    const now = Date.now();
    vi.setSystemTime(now);

    const token = createGatewayToken(
      { did: 'did:plc:test', handle: 'h', user_id: 1, app_id: 'a' },
      TEST_SECRET,
      60,
    );

    // Advance to just before expiry
    vi.setSystemTime(now + 59 * 1000);
    const result = verifyGatewayToken(token, TEST_SECRET);
    expect(result).not.toBeNull();

    vi.useRealTimers();
  });

  it('should reject a token with wrong number of parts', () => {
    expect(verifyGatewayToken('single-part', TEST_SECRET)).toBeNull();
    expect(verifyGatewayToken('a.b.c', TEST_SECRET)).toBeNull();
    expect(verifyGatewayToken('', TEST_SECRET)).toBeNull();
  });

  it('should reject a token with invalid base64url payload', () => {
    // Valid base64url signature but garbage payload that won't parse as JSON
    const garbledPayload = Buffer.from('not json').toString('base64url');
    const result = verifyGatewayToken(`${garbledPayload}.${garbledPayload}`, TEST_SECRET);
    expect(result).toBeNull();
  });
});
