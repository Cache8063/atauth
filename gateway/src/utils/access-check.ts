/**
 * Forward-Auth Proxy & Client Access Control
 *
 * Evaluates access rules to determine if a user (identified by DID and handle)
 * is allowed to access a protected service or client application.
 *
 * Evaluation order:
 * 1. Deny rules (per-origin + global) - if any match, reject
 * 2. Per-origin allow rules - if any match, allow
 * 3. Global allow rules - if any match, allow
 * 4. Default deny
 */

import type { AccessCheckResult } from '../types/proxy.js';

/** Minimal rule shape required for access checking */
interface AccessRule {
  id: number;
  rule_type: 'allow' | 'deny';
  subject_type: 'did' | 'handle_pattern';
  subject_value: string;
  description: string | null;
}

/**
 * Match a handle against a pattern.
 * - "*" matches everything
 * - "*.domain.tld" matches any handle ending with ".domain.tld"
 * - "exact.handle" matches only that exact handle
 */
export function matchHandlePattern(pattern: string, handle: string): boolean {
  if (pattern === '*') return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".domain.tld"
    return handle.endsWith(suffix);
  }
  return pattern === handle;
}

/**
 * Check if a DID or handle matches a given access rule.
 */
function matchesRule(rule: AccessRule, did: string, handle: string): boolean {
  if (rule.subject_type === 'did') {
    return rule.subject_value === did;
  }
  return matchHandlePattern(rule.subject_value, handle);
}

/**
 * Evaluate access rules for a user attempting to access a protected origin or client.
 */
export function checkAccess(
  did: string,
  handle: string,
  rules: {
    denyRules: AccessRule[];
    originAllowRules: AccessRule[];
    globalAllowRules: AccessRule[];
  },
): AccessCheckResult {
  // 1. Check deny rules (both per-origin and global)
  for (const rule of rules.denyRules) {
    if (matchesRule(rule, did, handle)) {
      return {
        allowed: false,
        matched_rule_id: rule.id,
        reason: `Denied by rule #${rule.id}: ${rule.description || rule.subject_value}`,
      };
    }
  }

  // 2. Check per-origin allow rules
  for (const rule of rules.originAllowRules) {
    if (matchesRule(rule, did, handle)) {
      return {
        allowed: true,
        matched_rule_id: rule.id,
        reason: `Allowed by origin rule #${rule.id}: ${rule.description || rule.subject_value}`,
      };
    }
  }

  // 3. Check global allow rules
  for (const rule of rules.globalAllowRules) {
    if (matchesRule(rule, did, handle)) {
      return {
        allowed: true,
        matched_rule_id: rule.id,
        reason: `Allowed by global rule #${rule.id}: ${rule.description || rule.subject_value}`,
      };
    }
  }

  // 4. Default deny
  return {
    allowed: false,
    matched_rule_id: null,
    reason: 'No matching allow rule (default deny)',
  };
}
