/**
 * Access Check Utility Tests
 */
import { describe, it, expect } from 'vitest';
import { matchHandlePattern, checkAccess } from './access-check.js';
import type { ProxyAccessRule } from '../types/proxy.js';

function makeRule(overrides: Partial<ProxyAccessRule> & Pick<ProxyAccessRule, 'rule_type' | 'subject_type' | 'subject_value'>): ProxyAccessRule {
  return {
    id: overrides.id ?? 1,
    origin_id: overrides.origin_id ?? null,
    rule_type: overrides.rule_type,
    subject_type: overrides.subject_type,
    subject_value: overrides.subject_value,
    description: overrides.description ?? null,
    created_at: overrides.created_at ?? Math.floor(Date.now() / 1000),
  };
}

describe('matchHandlePattern', () => {
  it('should match wildcard "*" against any handle', () => {
    expect(matchHandlePattern('*', 'user.bsky.social')).toBe(true);
    expect(matchHandlePattern('*', 'anything.at.all')).toBe(true);
  });

  it('should match suffix pattern "*.domain"', () => {
    expect(matchHandlePattern('*.arcnode.xyz', 'bkb.arcnode.xyz')).toBe(true);
    expect(matchHandlePattern('*.arcnode.xyz', 'other.arcnode.xyz')).toBe(true);
  });

  it('should not match suffix pattern against different domain', () => {
    expect(matchHandlePattern('*.arcnode.xyz', 'user.bsky.social')).toBe(false);
    expect(matchHandlePattern('*.arcnode.xyz', 'arcnode.xyz')).toBe(false);
  });

  it('should match exact handle', () => {
    expect(matchHandlePattern('bkb.arcnode.xyz', 'bkb.arcnode.xyz')).toBe(true);
  });

  it('should not match different exact handle', () => {
    expect(matchHandlePattern('bkb.arcnode.xyz', 'other.arcnode.xyz')).toBe(false);
  });

  it('should be case-sensitive', () => {
    expect(matchHandlePattern('User.bsky.social', 'user.bsky.social')).toBe(false);
  });

  it('should handle nested subdomains in suffix pattern', () => {
    expect(matchHandlePattern('*.bsky.social', 'deep.sub.bsky.social')).toBe(true);
  });
});

describe('checkAccess', () => {
  const testDid = 'did:plc:test123';
  const testHandle = 'user.bsky.social';

  it('should deny by default when no rules match', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [],
      originAllowRules: [makeRule({ id: 1, rule_type: 'allow', subject_type: 'did', subject_value: 'did:plc:other' })],
      globalAllowRules: [],
    });
    expect(result.allowed).toBe(false);
    expect(result.matched_rule_id).toBeNull();
    expect(result.reason).toContain('default deny');
  });

  it('should deny when a deny rule matches', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [makeRule({ id: 10, rule_type: 'deny', subject_type: 'did', subject_value: testDid })],
      originAllowRules: [makeRule({ id: 20, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
      globalAllowRules: [],
    });
    expect(result.allowed).toBe(false);
    expect(result.matched_rule_id).toBe(10);
  });

  it('should allow when origin allow rule matches', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [],
      originAllowRules: [makeRule({ id: 5, rule_type: 'allow', subject_type: 'did', subject_value: testDid })],
      globalAllowRules: [],
    });
    expect(result.allowed).toBe(true);
    expect(result.matched_rule_id).toBe(5);
    expect(result.reason).toContain('origin rule');
  });

  it('should allow when global allow rule matches and no origin rule does', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [],
      originAllowRules: [],
      globalAllowRules: [makeRule({ id: 7, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*.bsky.social' })],
    });
    expect(result.allowed).toBe(true);
    expect(result.matched_rule_id).toBe(7);
    expect(result.reason).toContain('global rule');
  });

  it('should prefer origin allow over global allow (both match)', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [],
      originAllowRules: [makeRule({ id: 3, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
      globalAllowRules: [makeRule({ id: 4, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
    });
    expect(result.allowed).toBe(true);
    expect(result.matched_rule_id).toBe(3);
    expect(result.reason).toContain('origin rule');
  });

  it('should deny even if allow rules exist when deny rule matches', () => {
    const result = checkAccess(testDid, testHandle, {
      denyRules: [makeRule({ id: 1, rule_type: 'deny', subject_type: 'handle_pattern', subject_value: '*.bsky.social' })],
      originAllowRules: [makeRule({ id: 2, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
      globalAllowRules: [makeRule({ id: 3, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
    });
    expect(result.allowed).toBe(false);
    expect(result.matched_rule_id).toBe(1);
  });

  it('should match DID-based rules', () => {
    const result = checkAccess('did:plc:specific', 'any.handle', {
      denyRules: [],
      originAllowRules: [makeRule({ id: 1, rule_type: 'allow', subject_type: 'did', subject_value: 'did:plc:specific' })],
      globalAllowRules: [],
    });
    expect(result.allowed).toBe(true);
  });

  it('should not match DID-based rule against wrong DID', () => {
    const result = checkAccess('did:plc:other', 'any.handle', {
      denyRules: [],
      originAllowRules: [makeRule({ id: 1, rule_type: 'allow', subject_type: 'did', subject_value: 'did:plc:specific' })],
      globalAllowRules: [],
    });
    expect(result.allowed).toBe(false);
    expect(result.matched_rule_id).toBeNull();
  });

  it('should handle wildcard allow for all users', () => {
    const result = checkAccess('did:plc:anyone', 'random.handle', {
      denyRules: [],
      originAllowRules: [],
      globalAllowRules: [makeRule({ id: 1, rule_type: 'allow', subject_type: 'handle_pattern', subject_value: '*' })],
    });
    expect(result.allowed).toBe(true);
  });
});
