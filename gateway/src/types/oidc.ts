/**
 * OIDC Types
 *
 * Types for OpenID Connect provider functionality
 */

/** OIDC Client types */
export type OIDCClientType = 'legacy' | 'oidc';

/** Token endpoint authentication methods */
export type TokenEndpointAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'none';

/** Extended app config for OIDC clients */
export interface OIDCClientConfig {
  id: string;
  name: string;
  client_type: OIDCClientType;
  /** HMAC secret for legacy clients */
  hmac_secret?: string;
  /** Client secret for OIDC clients (hashed) */
  client_secret?: string;
  /** JSON array of redirect URIs */
  redirect_uris: string[];
  /** JSON array of grant types */
  grant_types: string[];
  /** JSON array of allowed scopes */
  allowed_scopes: string[];
  token_ttl_seconds: number;
  id_token_ttl_seconds: number;
  access_token_ttl_seconds: number;
  refresh_token_ttl_seconds: number;
  require_pkce: boolean;
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  created_at: Date;
}

/** OIDC Signing Key */
export interface OIDCKey {
  kid: string;
  algorithm: 'ES256' | 'RS256';
  private_key_encrypted: string;
  public_key_jwk: string;
  created_at: Date;
  expires_at?: Date;
  is_active: boolean;
  use_for_signing: boolean;
}

/** JWK (JSON Web Key) for public key exposure */
export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  use: string;
  alg: string;
  kid: string;
}

/** JWKS (JSON Web Key Set) */
export interface JWKS {
  keys: JWK[];
}

/** Authorization Code */
export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
  did: string;
  handle: string;
  user_id?: number;
  created_at: number;
  expires_at: number;
  used: boolean;
}

/** Refresh Token */
export interface RefreshToken {
  token_hash: string;
  client_id: string;
  did: string;
  handle: string;
  user_id?: number;
  scope: string;
  created_at: Date;
  expires_at: Date;
  last_used_at?: Date;
  revoked: boolean;
  family_id?: string;
}

/** OIDC Discovery Document */
export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  end_session_endpoint: string;
  jwks_uri: string;
  scopes_supported: string[];
  response_types_supported: string[];
  response_modes_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: string[];
  claims_supported: string[];
}

/** ID Token Claims */
export interface IDTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  nonce?: string;
  at_hash?: string;
  /** AT Protocol specific claims */
  handle: string;
  did: string;
}

/** Access Token Claims */
export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  client_id: string;
  scope: string;
}

/** UserInfo Response */
export interface UserInfoResponse {
  sub: string;
  handle?: string;
  did?: string;
  name?: string;
  preferred_username?: string;
}

/** Token Response */
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/** Token Request */
export interface TokenRequest {
  grant_type: 'authorization_code' | 'refresh_token';
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  code_verifier?: string;
  refresh_token?: string;
  scope?: string;
}

/** Authorization Request */
export interface AuthorizationRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
}
