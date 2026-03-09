/**
 * PKCE (Proof Key for Code Exchange) Tests
 */
import { describe, it, expect } from 'vitest';
import {
  verifyCodeChallenge,
  generateCodeVerifier,
  generateCodeChallenge,
  isValidCodeVerifier,
  isValidCodeChallengeMethod,
} from './pkce.js';

describe('PKCE', () => {
  describe('generateCodeVerifier', () => {
    it('should generate a valid code verifier', () => {
      const verifier = generateCodeVerifier();
      expect(verifier).toBeDefined();
      expect(verifier.length).toBeGreaterThanOrEqual(43);
      expect(isValidCodeVerifier(verifier)).toBe(true);
    });

    it('should generate unique verifiers', () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      expect(verifier1).not.toBe(verifier2);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate S256 challenge correctly', () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

      const challenge = generateCodeChallenge(verifier, 'S256');
      expect(challenge).toBe(expectedChallenge);
    });

    it('should return verifier as challenge for plain method', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier, 'plain');
      expect(challenge).toBe(verifier);
    });

    it('should default to S256', () => {
      const verifier = generateCodeVerifier();
      const challenge1 = generateCodeChallenge(verifier);
      const challenge2 = generateCodeChallenge(verifier, 'S256');
      expect(challenge1).toBe(challenge2);
    });
  });

  describe('verifyCodeChallenge', () => {
    it('should verify S256 challenge correctly', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier, 'S256');

      expect(verifyCodeChallenge(verifier, challenge, 'S256')).toBe(true);
    });

    it('should reject invalid S256 verifier', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier, 'S256');
      const wrongVerifier = generateCodeVerifier();

      expect(verifyCodeChallenge(wrongVerifier, challenge, 'S256')).toBe(false);
    });

    it('should reject plain method as insecure', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier, 'plain');

      expect(verifyCodeChallenge(verifier, challenge, 'plain')).toBe(false);
    });

    it('should reject invalid plain verifier', () => {
      const verifier = generateCodeVerifier();
      const wrongVerifier = generateCodeVerifier();

      expect(verifyCodeChallenge(wrongVerifier, verifier, 'plain')).toBe(false);
    });

    it('should default to S256 method', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier, 'S256');

      expect(verifyCodeChallenge(verifier, challenge)).toBe(true);
    });

    // RFC 7636 test vector
    it('should pass RFC 7636 test vector', () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

      expect(verifyCodeChallenge(verifier, challenge, 'S256')).toBe(true);
    });
  });

  describe('isValidCodeVerifier', () => {
    it('should accept valid verifiers', () => {
      expect(isValidCodeVerifier('a'.repeat(43))).toBe(true);
      expect(isValidCodeVerifier('a'.repeat(128))).toBe(true);
      expect(isValidCodeVerifier('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq')).toBe(true);
      expect(isValidCodeVerifier('0123456789-._~abcdefghijklmnopqrstuvwxyzABC')).toBe(true);
    });

    it('should reject too short verifiers', () => {
      expect(isValidCodeVerifier('a'.repeat(42))).toBe(false);
      expect(isValidCodeVerifier('')).toBe(false);
    });

    it('should reject too long verifiers', () => {
      expect(isValidCodeVerifier('a'.repeat(129))).toBe(false);
    });

    it('should reject invalid characters', () => {
      expect(isValidCodeVerifier('a'.repeat(42) + '!')).toBe(false);
      expect(isValidCodeVerifier('a'.repeat(42) + ' ')).toBe(false);
      expect(isValidCodeVerifier('a'.repeat(42) + '+')).toBe(false);
      expect(isValidCodeVerifier('a'.repeat(42) + '/')).toBe(false);
    });
  });

  describe('isValidCodeChallengeMethod', () => {
    it('should accept valid methods', () => {
      expect(isValidCodeChallengeMethod('S256')).toBe(true);
    });

    it('should reject plain method', () => {
      expect(isValidCodeChallengeMethod('plain')).toBe(false);
    });

    it('should reject invalid methods', () => {
      expect(isValidCodeChallengeMethod('SHA256')).toBe(false);
      expect(isValidCodeChallengeMethod('s256')).toBe(false);
      expect(isValidCodeChallengeMethod('PLAIN')).toBe(false);
      expect(isValidCodeChallengeMethod('')).toBe(false);
      expect(isValidCodeChallengeMethod('RS256')).toBe(false);
    });
  });
});
