/**
 * OIDC Claims Tests
 */
import { describe, it, expect } from 'vitest';
import {
  SUPPORTED_SCOPES,
  isSupportedScope,
  parseScopes,
  filterSupportedScopes,
  hasOpenIdScope,
  hasOfflineAccessScope,
  buildUserInfo,
  validateScopes,
  getDefaultScopes,
} from './claims.js';

describe('OIDC Claims', () => {
  describe('SUPPORTED_SCOPES', () => {
    it('should include required OIDC scopes', () => {
      expect(SUPPORTED_SCOPES).toContain('openid');
      expect(SUPPORTED_SCOPES).toContain('profile');
      expect(SUPPORTED_SCOPES).toContain('email');
      expect(SUPPORTED_SCOPES).toContain('offline_access');
    });
  });

  describe('isSupportedScope', () => {
    it('should accept supported scopes', () => {
      expect(isSupportedScope('openid')).toBe(true);
      expect(isSupportedScope('profile')).toBe(true);
      expect(isSupportedScope('email')).toBe(true);
      expect(isSupportedScope('offline_access')).toBe(true);
    });

    it('should reject unsupported scopes', () => {
      expect(isSupportedScope('address')).toBe(false);
      expect(isSupportedScope('phone')).toBe(false);
      expect(isSupportedScope('custom')).toBe(false);
      expect(isSupportedScope('')).toBe(false);
    });
  });

  describe('parseScopes', () => {
    it('should parse space-separated scopes', () => {
      expect(parseScopes('openid profile')).toEqual(['openid', 'profile']);
      expect(parseScopes('openid profile email')).toEqual(['openid', 'profile', 'email']);
    });

    it('should handle single scope', () => {
      expect(parseScopes('openid')).toEqual(['openid']);
    });

    it('should handle empty string', () => {
      expect(parseScopes('')).toEqual([]);
    });

    it('should filter out empty strings from multiple spaces', () => {
      expect(parseScopes('openid  profile')).toEqual(['openid', 'profile']);
    });
  });

  describe('filterSupportedScopes', () => {
    it('should filter to only supported scopes', () => {
      const scopes = ['openid', 'profile', 'custom', 'email', 'unknown'];
      expect(filterSupportedScopes(scopes)).toEqual(['openid', 'profile', 'email']);
    });

    it('should return empty array for all unsupported scopes', () => {
      expect(filterSupportedScopes(['custom', 'unknown'])).toEqual([]);
    });

    it('should preserve all supported scopes', () => {
      const scopes = ['openid', 'profile', 'email', 'offline_access'];
      expect(filterSupportedScopes(scopes)).toEqual(scopes);
    });
  });

  describe('hasOpenIdScope', () => {
    it('should return true when openid is present', () => {
      expect(hasOpenIdScope(['openid'])).toBe(true);
      expect(hasOpenIdScope(['openid', 'profile'])).toBe(true);
      expect(hasOpenIdScope(['profile', 'openid', 'email'])).toBe(true);
    });

    it('should return false when openid is missing', () => {
      expect(hasOpenIdScope([])).toBe(false);
      expect(hasOpenIdScope(['profile'])).toBe(false);
      expect(hasOpenIdScope(['profile', 'email'])).toBe(false);
    });
  });

  describe('hasOfflineAccessScope', () => {
    it('should return true when offline_access is present', () => {
      expect(hasOfflineAccessScope(['offline_access'])).toBe(true);
      expect(hasOfflineAccessScope(['openid', 'offline_access'])).toBe(true);
    });

    it('should return false when offline_access is missing', () => {
      expect(hasOfflineAccessScope([])).toBe(false);
      expect(hasOfflineAccessScope(['openid', 'profile'])).toBe(false);
    });
  });

  describe('buildUserInfo', () => {
    const testUser = {
      did: 'did:plc:abc123',
      handle: 'alice.bsky.social',
    };

    it('should always include sub claim', () => {
      const info = buildUserInfo(testUser, []);
      expect(info.sub).toBe(testUser.did);
    });

    it('should include profile claims when profile scope is present', () => {
      const info = buildUserInfo(testUser, ['profile']);
      expect(info.sub).toBe(testUser.did);
      expect(info.handle).toBe(testUser.handle);
      expect(info.did).toBe(testUser.did);
      expect(info.preferred_username).toBe(testUser.handle);
      expect(info.name).toBe('alice');
    });

    it('should extract name from handle correctly', () => {
      const user = { did: 'did:plc:xyz', handle: 'bob.example.com' };
      const info = buildUserInfo(user, ['profile']);
      expect(info.name).toBe('bob');
    });

    it('should not include profile claims without profile scope', () => {
      const info = buildUserInfo(testUser, ['openid']);
      expect(info.handle).toBeUndefined();
      expect(info.preferred_username).toBeUndefined();
      expect(info.name).toBeUndefined();
    });

    it('should only include sub for openid-only scope', () => {
      const info = buildUserInfo(testUser, ['openid']);
      expect(Object.keys(info)).toEqual(['sub']);
    });
  });

  describe('validateScopes', () => {
    const allowedScopes = ['openid', 'profile', 'email', 'offline_access'];

    it('should validate scopes when openid is included', () => {
      const result = validateScopes(['openid', 'profile'], allowedScopes);
      expect(result.valid).toBe(true);
      expect(result.scopes).toContain('openid');
      expect(result.scopes).toContain('profile');
    });

    it('should fail when openid is missing', () => {
      const result = validateScopes(['profile'], allowedScopes);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('openid scope is required');
    });

    it('should filter out disallowed scopes', () => {
      const result = validateScopes(['openid', 'profile', 'custom'], allowedScopes);
      expect(result.valid).toBe(true);
      expect(result.scopes).toContain('openid');
      expect(result.scopes).toContain('profile');
      expect(result.scopes).not.toContain('custom');
    });

    it('should filter out unsupported scopes', () => {
      const result = validateScopes(['openid', 'address'], allowedScopes);
      expect(result.valid).toBe(true);
      expect(result.scopes).toContain('openid');
      expect(result.scopes).not.toContain('address');
    });

    it('should respect client allowed scopes', () => {
      const limitedAllowed = ['openid', 'profile'];
      const result = validateScopes(['openid', 'profile', 'email'], limitedAllowed);
      expect(result.valid).toBe(true);
      expect(result.scopes).toContain('openid');
      expect(result.scopes).toContain('profile');
      expect(result.scopes).not.toContain('email');
    });
  });

  describe('getDefaultScopes', () => {
    it('should always include openid', () => {
      expect(getDefaultScopes([])).toContain('openid');
      expect(getDefaultScopes(['openid'])).toContain('openid');
    });

    it('should include profile if allowed', () => {
      expect(getDefaultScopes(['openid', 'profile'])).toContain('profile');
    });

    it('should not include profile if not allowed', () => {
      expect(getDefaultScopes(['openid', 'email'])).not.toContain('profile');
    });

    it('should return correct defaults for full scope set', () => {
      const allowed = ['openid', 'profile', 'email', 'offline_access'];
      const defaults = getDefaultScopes(allowed);
      expect(defaults).toEqual(['openid', 'profile']);
    });
  });
});
