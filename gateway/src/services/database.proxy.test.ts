/**
 * Database Service - Proxy Methods Tests
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import { DatabaseService } from './database.js';

describe('Proxy Sessions', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  afterEach(() => {
    db.close();
  });

  function makeSession(overrides: Partial<{
    id: string; did: string; handle: string;
    created_at: number; expires_at: number; last_activity: number;
    user_agent: string; ip_address: string;
  }> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
      id: overrides.id || crypto.randomBytes(16).toString('base64url'),
      did: overrides.did || 'did:plc:test123',
      handle: overrides.handle || 'test.bsky.social',
      created_at: overrides.created_at || now,
      expires_at: overrides.expires_at || now + 604800,
      last_activity: overrides.last_activity || now,
      user_agent: overrides.user_agent,
      ip_address: overrides.ip_address,
    };
  }

  it('should create and retrieve a proxy session', () => {
    const session = makeSession({ ip_address: '1.2.3.4', user_agent: 'TestAgent/1.0' });
    db.createProxySession(session);

    const retrieved = db.getProxySession(session.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(session.id);
    expect(retrieved!.did).toBe(session.did);
    expect(retrieved!.handle).toBe(session.handle);
    expect(retrieved!.ip_address).toBe('1.2.3.4');
    expect(retrieved!.user_agent).toBe('TestAgent/1.0');
  });

  it('should return null for non-existent session', () => {
    expect(db.getProxySession('nonexistent')).toBeNull();
  });

  it('should update session activity timestamp', () => {
    const session = makeSession();
    db.createProxySession(session);

    // Wait a tick so timestamp differs
    const before = db.getProxySession(session.id)!.last_activity;
    db.updateProxySessionActivity(session.id);
    const after = db.getProxySession(session.id)!.last_activity;

    expect(after).toBeGreaterThanOrEqual(before);
  });

  it('should delete a proxy session', () => {
    const session = makeSession();
    db.createProxySession(session);
    expect(db.getProxySession(session.id)).not.toBeNull();

    db.deleteProxySession(session.id);
    expect(db.getProxySession(session.id)).toBeNull();
  });

  it('should delete all sessions for a user', () => {
    const did = 'did:plc:userA';
    db.createProxySession(makeSession({ id: 's1', did }));
    db.createProxySession(makeSession({ id: 's2', did }));
    db.createProxySession(makeSession({ id: 's3', did: 'did:plc:userB' }));

    const deleted = db.deleteProxySessionsForUser(did);
    expect(deleted).toBe(2);
    expect(db.getProxySession('s1')).toBeNull();
    expect(db.getProxySession('s2')).toBeNull();
    expect(db.getProxySession('s3')).not.toBeNull();
  });

  it('should clean up expired proxy sessions', () => {
    const now = Math.floor(Date.now() / 1000);
    db.createProxySession(makeSession({ id: 'expired1', expires_at: now - 100 }));
    db.createProxySession(makeSession({ id: 'expired2', expires_at: now - 1 }));
    db.createProxySession(makeSession({ id: 'active', expires_at: now + 3600 }));

    const deleted = db.cleanupExpiredProxySessions();
    expect(deleted).toBe(2);
    expect(db.getProxySession('expired1')).toBeNull();
    expect(db.getProxySession('expired2')).toBeNull();
    expect(db.getProxySession('active')).not.toBeNull();
  });

  it('should list active proxy sessions', () => {
    const now = Math.floor(Date.now() / 1000);
    db.createProxySession(makeSession({ id: 'a1', did: 'did:plc:u1', expires_at: now + 3600 }));
    db.createProxySession(makeSession({ id: 'a2', did: 'did:plc:u2', expires_at: now + 3600 }));
    db.createProxySession(makeSession({ id: 'expired', did: 'did:plc:u1', expires_at: now - 10 }));

    const all = db.getAllProxySessions();
    expect(all).toHaveLength(2);

    const filtered = db.getAllProxySessions('did:plc:u1');
    expect(filtered).toHaveLength(1);
    expect(filtered[0].id).toBe('a1');
  });

  it('should respect limit on getAllProxySessions', () => {
    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 5; i++) {
      db.createProxySession(makeSession({ id: `s${i}`, expires_at: now + 3600 }));
    }

    const limited = db.getAllProxySessions(undefined, 3);
    expect(limited).toHaveLength(3);
  });
});

describe('Proxy Allowed Origins', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  afterEach(() => {
    db.close();
  });

  it('should add and list allowed origins', () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    db.addProxyAllowedOrigin('https://element.arcnode.xyz', 'Element');

    const origins = db.listProxyAllowedOrigins();
    expect(origins).toHaveLength(2);
    // Sorted by name ASC
    expect(origins[0].name).toBe('Element');
    expect(origins[1].name).toBe('SearXNG');
  });

  it('should return created origin with id', () => {
    const created = db.addProxyAllowedOrigin('https://test.example.com', 'Test');
    expect(created.id).toBeGreaterThan(0);
    expect(created.origin).toBe('https://test.example.com');
    expect(created.name).toBe('Test');
    expect(created.created_at).toBeGreaterThan(0);
  });

  it('should reject duplicate origins', () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    expect(() => {
      db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG Copy');
    }).toThrow(/UNIQUE/);
  });

  it('should remove an allowed origin', () => {
    const created = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    db.removeProxyAllowedOrigin(created.id);
    expect(db.listProxyAllowedOrigins()).toHaveLength(0);
  });

  it('should check if origin is allowed', () => {
    db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    expect(db.isProxyOriginAllowed('https://search.arcnode.xyz')).toBe(true);
    expect(db.isProxyOriginAllowed('https://evil.example.com')).toBe(false);
  });
});

describe('Proxy Auth Requests', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  afterEach(() => {
    db.close();
  });

  it('should save and retrieve an auth request', () => {
    const now = Math.floor(Date.now() / 1000);
    const req = {
      id: 'auth-req-123',
      redirect_uri: 'https://search.arcnode.xyz/path',
      created_at: now,
      expires_at: now + 600,
    };
    db.saveProxyAuthRequest(req);

    const retrieved = db.getProxyAuthRequest('auth-req-123');
    expect(retrieved).not.toBeNull();
    expect(retrieved!.redirect_uri).toBe('https://search.arcnode.xyz/path');
    expect(retrieved!.expires_at).toBe(now + 600);
  });

  it('should return null for non-existent auth request', () => {
    expect(db.getProxyAuthRequest('nonexistent')).toBeNull();
  });

  it('should delete an auth request', () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'del-me',
      redirect_uri: 'https://example.com',
      created_at: now,
      expires_at: now + 600,
    });

    db.deleteProxyAuthRequest('del-me');
    expect(db.getProxyAuthRequest('del-me')).toBeNull();
  });

  it('should clean up expired auth requests', () => {
    const now = Math.floor(Date.now() / 1000);
    db.saveProxyAuthRequest({
      id: 'expired1',
      redirect_uri: 'https://example.com',
      created_at: now - 700,
      expires_at: now - 100,
    });
    db.saveProxyAuthRequest({
      id: 'active',
      redirect_uri: 'https://example.com',
      created_at: now,
      expires_at: now + 600,
    });

    const deleted = db.cleanupExpiredProxyAuthRequests();
    expect(deleted).toBe(1);
    expect(db.getProxyAuthRequest('expired1')).toBeNull();
    expect(db.getProxyAuthRequest('active')).not.toBeNull();
  });
});

describe('Proxy Access Rules', () => {
  let db: DatabaseService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
  });

  afterEach(() => {
    db.close();
  });

  it('should create and list access rules', () => {
    const rule = db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: 'PDS users',
    });

    expect(rule.id).toBeGreaterThan(0);
    expect(rule.rule_type).toBe('allow');
    expect(rule.subject_value).toBe('*.arcnode.xyz');

    const rules = db.listProxyAccessRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].description).toBe('PDS users');
  });

  it('should delete an access rule', () => {
    const rule = db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'did',
      subject_value: 'did:plc:test123',
      description: null,
    });

    db.deleteProxyAccessRule(rule.id);
    expect(db.listProxyAccessRules()).toHaveLength(0);
  });

  it('should filter rules by origin_id', () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    db.createProxyAccessRule({
      origin_id: origin.id,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: 'Origin rule',
    });

    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: 'Global rule',
    });

    // Filter by origin ID should include origin-specific + global rules
    const filtered = db.listProxyAccessRules(origin.id);
    expect(filtered).toHaveLength(2);

    // All rules
    const all = db.listProxyAccessRules();
    expect(all).toHaveLength(2);
  });

  it('should partition rules for access check', () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    db.createProxyAccessRule({
      origin_id: origin.id,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*.arcnode.xyz',
      description: null,
    });
    db.createProxyAccessRule({
      origin_id: origin.id,
      rule_type: 'deny',
      subject_type: 'did',
      subject_value: 'did:plc:banned',
      description: null,
    });
    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: null,
    });

    const result = db.getProxyAccessRulesForCheck(origin.id);
    expect(result.denyRules).toHaveLength(1);
    expect(result.denyRules[0].subject_value).toBe('did:plc:banned');
    expect(result.originAllowRules).toHaveLength(1);
    expect(result.originAllowRules[0].subject_value).toBe('*.arcnode.xyz');
    expect(result.globalAllowRules).toHaveLength(1);
    expect(result.globalAllowRules[0].subject_value).toBe('*');
  });

  it('should cascade delete rules when origin is removed', () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');

    db.createProxyAccessRule({
      origin_id: origin.id,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: null,
    });

    db.createProxyAccessRule({
      origin_id: null,
      rule_type: 'allow',
      subject_type: 'handle_pattern',
      subject_value: '*',
      description: 'Global survives',
    });

    db.removeProxyAllowedOrigin(origin.id);

    const rules = db.listProxyAccessRules();
    expect(rules).toHaveLength(1);
    expect(rules[0].description).toBe('Global survives');
  });

  it('should look up origin ID by origin URL', () => {
    const origin = db.addProxyAllowedOrigin('https://search.arcnode.xyz', 'SearXNG');
    expect(db.getOriginIdByOrigin('https://search.arcnode.xyz')).toBe(origin.id);
    expect(db.getOriginIdByOrigin('https://nonexistent.example.com')).toBeNull();
  });
});
