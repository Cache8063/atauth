/**
 * OAuth Service
 *
 * Handles AT Protocol OAuth flow using @atproto/oauth-client-node
 */

import { NodeOAuthClient, NodeSavedState, NodeSavedSession } from '@atproto/oauth-client-node';
import { DatabaseService } from './database.js';
import type { OAuthState } from '../types/index.js';

// OAuth stores backed by SQLite for persistence across restarts

// Capture the most recently set state key
let pendingStateKey: string | null = null;

export interface OAuthResult {
  did: string;
  handle: string;
  accessJwt?: string;
  refreshJwt?: string;
}

export class OAuthService {
  private client: NodeOAuthClient | null = null;
  private db: DatabaseService;
  private clientId: string;
  private redirectUri: string;

  constructor(db: DatabaseService, clientId: string, redirectUri: string) {
    this.db = db;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }

  async initialize(additionalRedirectUris?: string[]): Promise<void> {
    // Derive proxy callback from the primary redirect URI's base
    const baseUrl = this.redirectUri.replace(/\/[^/]*$/, '');
    const proxyCallbackUri = `${baseUrl}/proxy/callback`;

    // Collect all redirect URIs: primary, proxy, and any additional (e.g. OIDC callback)
    const redirectUris: [string, ...string[]] = [this.redirectUri, proxyCallbackUri];
    if (additionalRedirectUris) {
      for (const uri of additionalRedirectUris) {
        if (!redirectUris.includes(uri)) {
          redirectUris.push(uri);
        }
      }
    }

    this.client = new NodeOAuthClient({
      clientMetadata: {
        client_id: this.clientId,
        client_name: 'ATAuth Gateway',
        client_uri: this.clientId,
        redirect_uris: redirectUris,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'atproto transition:generic',
        application_type: 'web',
        token_endpoint_auth_method: 'none',
        dpop_bound_access_tokens: true,
      },
      stateStore: {
        get: async (key: string): Promise<NodeSavedState | undefined> => {
          const row = this.db.getOAuthSession(key);
          return row ? JSON.parse(row.data) as NodeSavedState : undefined;
        },
        set: async (key: string, state: NodeSavedState): Promise<void> => {
          const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 min
          this.db.saveOAuthSession(key, JSON.stringify(state), 'state', expiresAt);
          pendingStateKey = key;
        },
        del: async (key: string): Promise<void> => {
          this.db.deleteOAuthSession(key);
        },
      },
      sessionStore: {
        get: async (key: string): Promise<NodeSavedSession | undefined> => {
          const row = this.db.getOAuthSession(key);
          return row ? JSON.parse(row.data) as NodeSavedSession : undefined;
        },
        set: async (key: string, session: NodeSavedSession): Promise<void> => {
          const expiresAt = Math.floor(Date.now() / 1000) + 30 * 24 * 3600; // 30 days
          this.db.saveOAuthSession(key, JSON.stringify(session), 'session', expiresAt);
        },
        del: async (key: string): Promise<void> => {
          this.db.deleteOAuthSession(key);
        },
      },
    });
  }

  /**
   * Generate OAuth authorization URL
   *
   * @param appId - The application identifier
   * @param handle - The user's AT Protocol handle
   * @param customRedirect - Optional custom redirect URI
   */
  async generateAuthUrl(appId: string, handle: string, customRedirect?: string, appRedirectUri?: string): Promise<{
    url: string;
    state: string;
  }> {
    if (!this.client) {
      throw new Error('OAuth client not initialized');
    }

    if (!handle) {
      throw new Error('Handle is required for OAuth authorization');
    }

    pendingStateKey = null;

    const authorizeOptions: Record<string, string> = {
      scope: 'atproto transition:generic',
    };
    if (customRedirect) {
      authorizeOptions.redirect_uri = customRedirect;
    }

    const url = await this.client.authorize(handle, authorizeOptions);

    const state = pendingStateKey;
    if (!state) {
      throw new Error('OAuth library did not store state');
    }

    const oauthState: OAuthState = {
      state,
      code_verifier: '',
      app_id: appId,
      redirect_uri: appRedirectUri || customRedirect || this.redirectUri,
      created_at: Math.floor(Date.now() / 1000),
    };
    this.db.saveOAuthState(oauthState);

    console.log(`OAuth state saved: ${state} for app ${appId}`);

    return { url: url.toString(), state };
  }

  /**
   * Handle OAuth callback and exchange code for tokens
   *
   * @param params - URL search params from the callback
   * @param redirectUri - The redirect_uri used during authorization (must match)
   */
  async handleCallback(params: URLSearchParams, redirectUri?: string): Promise<OAuthResult> {
    if (!this.client) {
      throw new Error('OAuth client not initialized');
    }

    const callbackOptions: Record<string, string> = {};
    if (redirectUri) {
      callbackOptions.redirect_uri = redirectUri;
    }

    const { session } = await this.client.callback(params, callbackOptions);

    const did: string = session.did;

    let handle: string = did;
    try {
      const resolved = await this.resolveDidToHandle(did);
      if (resolved) {
        handle = resolved;
      }
    } catch {
      // Fall back to DID
    }

    return { did, handle };
  }

  /**
   * Restore a PDS session for a user and make an authenticated xRPC call.
   * Returns the response from the user's PDS.
   */
  async proxyPdsRequest(did: string, pathname: string, init?: RequestInit): Promise<Response> {
    if (!this.client) {
      throw new Error('OAuth client not initialized');
    }

    const session = await this.client.restore(did);
    return session.fetchHandler(pathname, init);
  }

  /**
   * Check if a PDS session exists for a DID.
   */
  hasPdsSession(did: string): boolean {
    return !!this.db.getOAuthSession(did);
  }

  private async resolveDidToHandle(did: string): Promise<string | null> {
    try {
      const response = await fetch(
        `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(did)}`
      );
      if (!response.ok) return null;
      const data = (await response.json()) as { handle: string };
      return data.handle;
    } catch {
      return null;
    }
  }

  async resolveHandle(handle: string): Promise<string | null> {
    try {
      const response = await fetch(
        `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`
      );
      if (!response.ok) return null;
      const data = (await response.json()) as { did: string };
      return data.did;
    } catch {
      return null;
    }
  }
}
