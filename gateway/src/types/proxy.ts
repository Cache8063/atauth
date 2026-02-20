/**
 * Forward-Auth Proxy Types
 *
 * Types for the forward-auth/SSO gateway that protects
 * arbitrary services via nginx auth_request.
 */

/** A gateway-level SSO session (stored in SQLite) */
export interface ProxySession {
  id: string;
  did: string;
  handle: string;
  created_at: number;
  expires_at: number;
  last_activity: number;
  user_agent?: string;
  ip_address?: string;
}

/** An origin allowed to use forward-auth */
export interface ProxyAllowedOrigin {
  id: number;
  origin: string; // e.g. "https://search.arcnode.xyz"
  name: string;   // e.g. "SearXNG"
  created_at: number;
}

/** Pending forward-auth login request (stored while user does AT Proto OAuth) */
export interface ProxyAuthRequest {
  id: string;
  redirect_uri: string;
  created_at: number;
  expires_at: number;
}

/** Payload inside the _atauth_session cookie (on ATAuth domain) */
export interface ProxySessionCookiePayload {
  sid: string;
  iat: number;
  exp: number;
}

/** Payload inside the _atauth_ticket URL parameter (short-lived redirect token) */
export interface ProxyTicketPayload {
  sid: string;
  did: string;
  handle: string;
  origin: string;
  iat: number;
  exp: number;
}

/** Forward-auth configuration */
export interface ForwardAuthConfig {
  enabled: boolean;
  sessionSecret: string;
  sessionTtl: number;      // seconds, default 7 days
  proxyCookieTtl: number;  // seconds, default 24h
}
