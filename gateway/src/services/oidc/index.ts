/**
 * OIDC Services
 *
 * Central orchestrator for OpenID Connect functionality
 */

export { KeyManager } from './keys.js';
export { TokenService } from './tokens.js';
export * from './pkce.js';
export * from './claims.js';

import { KeyManager } from './keys.js';
import { TokenService } from './tokens.js';
import type { DatabaseService } from '../database.js';

export interface OIDCConfig {
  issuer: string;
  keySecret: string;
  keyAlgorithm?: 'ES256' | 'RS256';
}

/**
 * OIDC Service - main entry point for OIDC functionality
 */
export class OIDCService {
  public readonly keyManager: KeyManager;
  public readonly tokenService: TokenService;
  public readonly issuer: string;

  constructor(db: DatabaseService, config: OIDCConfig) {
    this.issuer = config.issuer;
    this.keyManager = new KeyManager(db, config.keySecret);
    this.tokenService = new TokenService(this.keyManager, config.issuer);
  }

  /**
   * Initialize OIDC - ensure signing key exists
   */
  async initialize(algorithm: 'ES256' | 'RS256' = 'ES256'): Promise<void> {
    await this.keyManager.ensureSigningKey(algorithm);
  }

  /**
   * Get the OIDC discovery document
   */
  getDiscoveryDocument(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      userinfo_endpoint: `${this.issuer}/oauth/userinfo`,
      revocation_endpoint: `${this.issuer}/oauth/revoke`,
      end_session_endpoint: `${this.issuer}/oauth/end_session`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      response_types_supported: ['code'],
      response_modes_supported: ['query', 'fragment'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256', 'RS256'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'none',
      ],
      code_challenge_methods_supported: ['S256', 'plain'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'nonce',
        'at_hash',
        'handle',
        'did',
        'name',
        'preferred_username',
      ],
    };
  }

  /**
   * Get the JWKS
   */
  getJWKS(): { keys: Array<Record<string, unknown>> } {
    const jwks = this.keyManager.getJWKS();
    return {
      keys: jwks.keys as unknown as Array<Record<string, unknown>>,
    };
  }
}
