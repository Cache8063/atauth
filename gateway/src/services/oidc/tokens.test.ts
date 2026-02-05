/**
 * OIDC Token Service Tests
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import crypto from 'crypto';
import { TokenService } from './tokens.js';
import type { KeyManager } from './keys.js';

// Create a real key pair for testing
function createTestKeyPair() {
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  return privateKey;
}

describe('TokenService', () => {
  let tokenService: TokenService;
  let mockKeyManager: KeyManager;
  let testPrivateKey: crypto.KeyObject;

  beforeEach(() => {
    testPrivateKey = createTestKeyPair();

    mockKeyManager = {
      getSigningKey: vi.fn().mockReturnValue({
        kid: 'test-key-1',
        privateKey: testPrivateKey,
        algorithm: 'ES256' as const,
      }),
      getKeyByKid: vi.fn().mockReturnValue({
        privateKey: testPrivateKey,
        algorithm: 'ES256' as const,
      }),
    } as unknown as KeyManager;

    tokenService = new TokenService(mockKeyManager, 'https://auth.example.com');
  });

  describe('createAccessToken', () => {
    it('should create a valid access token', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid profile',
      });

      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(3);
    });

    it('should include required claims', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid profile',
        expiresIn: 3600,
      });

      const verified = tokenService.verifyAccessToken(token);
      expect(verified).not.toBeNull();
      expect(verified?.iss).toBe('https://auth.example.com');
      expect(verified?.sub).toBe('did:plc:abc123');
      expect(verified?.client_id).toBe('test-client');
      expect(verified?.scope).toBe('openid profile');
      expect(verified?.jti).toBeDefined();
    });

    it('should set correct expiration', () => {
      const expiresIn = 7200;
      const before = Math.floor(Date.now() / 1000);

      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid',
        expiresIn,
      });

      const after = Math.floor(Date.now() / 1000);
      const verified = tokenService.verifyAccessToken(token);

      expect(verified?.exp).toBeGreaterThanOrEqual(before + expiresIn);
      expect(verified?.exp).toBeLessThanOrEqual(after + expiresIn);
    });
  });

  describe('createIdToken', () => {
    it('should create a valid ID token', () => {
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(3);
    });

    it('should include AT Protocol specific claims', () => {
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      const verified = tokenService.verifyIdToken(token, 'test-client');
      expect(verified).not.toBeNull();
      expect(verified?.did).toBe('did:plc:abc123');
      expect(verified?.handle).toBe('alice.bsky.social');
    });

    it('should include nonce when provided', () => {
      const nonce = 'test-nonce-123';
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        nonce,
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      const verified = tokenService.verifyIdToken(token, 'test-client', nonce);
      expect(verified?.nonce).toBe(nonce);
    });

    it('should include at_hash when access token provided', () => {
      const accessToken = 'test-access-token';
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
        accessToken,
      });

      const verified = tokenService.verifyIdToken(token, 'test-client');
      expect(verified?.at_hash).toBeDefined();
    });
  });

  describe('createTokenResponse', () => {
    it('should create a complete token response', () => {
      const response = tokenService.createTokenResponse({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid profile',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      expect(response.access_token).toBeDefined();
      expect(response.token_type).toBe('Bearer');
      expect(response.expires_in).toBeDefined();
      expect(response.id_token).toBeDefined();
      expect(response.scope).toBe('openid profile');
    });

    it('should not include id_token without openid scope', () => {
      const response = tokenService.createTokenResponse({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'profile',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      expect(response.access_token).toBeDefined();
      expect(response.id_token).toBeUndefined();
    });

    it('should include refresh token when requested', () => {
      const response = tokenService.createTokenResponse({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid offline_access',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
        includeRefreshToken: true,
        refreshToken: 'test-refresh-token',
      });

      expect(response.refresh_token).toBe('test-refresh-token');
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify valid access tokens', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid',
      });

      const verified = tokenService.verifyAccessToken(token);
      expect(verified).not.toBeNull();
    });

    it('should reject tampered tokens', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid',
      });

      // Tamper with the token
      const parts = token.split('.');
      parts[1] = parts[1].slice(0, -5) + 'XXXXX';
      const tamperedToken = parts.join('.');

      const verified = tokenService.verifyAccessToken(tamperedToken);
      expect(verified).toBeNull();
    });

    it('should reject expired tokens', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid',
        expiresIn: -1, // Already expired
      });

      const verified = tokenService.verifyAccessToken(token);
      expect(verified).toBeNull();
    });

    it('should reject malformed tokens', () => {
      expect(tokenService.verifyAccessToken('not.a.valid.token')).toBeNull();
      expect(tokenService.verifyAccessToken('invalid')).toBeNull();
      expect(tokenService.verifyAccessToken('')).toBeNull();
    });
  });

  describe('verifyIdToken', () => {
    it('should verify valid ID tokens', () => {
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      const verified = tokenService.verifyIdToken(token);
      expect(verified).not.toBeNull();
    });

    it('should validate audience when provided', () => {
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      expect(tokenService.verifyIdToken(token, 'test-client')).not.toBeNull();
      expect(tokenService.verifyIdToken(token, 'wrong-client')).toBeNull();
    });

    it('should validate nonce when provided', () => {
      const nonce = 'test-nonce';
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        nonce,
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      expect(tokenService.verifyIdToken(token, 'test-client', nonce)).not.toBeNull();
      expect(tokenService.verifyIdToken(token, 'test-client', 'wrong-nonce')).toBeNull();
    });

    it('should reject tokens with wrong issuer', () => {
      // Create a token with our service
      const token = tokenService.createIdToken({
        sub: 'did:plc:abc123',
        aud: 'test-client',
        did: 'did:plc:abc123',
        handle: 'alice.bsky.social',
      });

      // Create a new service with different issuer
      const differentIssuerService = new TokenService(mockKeyManager, 'https://different.issuer.com');
      expect(differentIssuerService.verifyIdToken(token)).toBeNull();
    });
  });

  describe('JWT structure', () => {
    it('should have correct header structure', () => {
      const token = tokenService.createAccessToken({
        sub: 'did:plc:abc123',
        clientId: 'test-client',
        scope: 'openid',
      });

      const [headerB64] = token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

      expect(header.alg).toBe('ES256');
      expect(header.typ).toBe('JWT');
      expect(header.kid).toBe('test-key-1');
    });
  });

  describe('error handling', () => {
    it('should throw when no signing key available', () => {
      const noKeyManager = {
        getSigningKey: vi.fn().mockReturnValue(null),
      } as unknown as KeyManager;

      const service = new TokenService(noKeyManager, 'https://auth.example.com');

      expect(() =>
        service.createAccessToken({
          sub: 'did:plc:abc123',
          clientId: 'test-client',
          scope: 'openid',
        })
      ).toThrow('No signing key available');
    });
  });
});
