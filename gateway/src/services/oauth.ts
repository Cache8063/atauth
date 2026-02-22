/**
 * OAuth Service
 *
 * Handles AT Protocol OAuth flow using @atproto/oauth-client-node
 */

import { NodeOAuthClient, NodeSavedState, NodeSavedSession } from '@atproto/oauth-client-node';
import { DatabaseService } from './database.js';
import type { OAuthState } from '../types/index.js';

// In-memory storage for OAuth client sessions
const sessionStore = new Map<string, NodeSavedSession>();
const stateStore = new Map<string, NodeSavedState>();

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
        async get(key: string): Promise<NodeSavedState | undefined> {
          return stateStore.get(key);
        },
        async set(key: string, state: NodeSavedState): Promise<void> {
          stateStore.set(key, state);
          pendingStateKey = key;
        },
        async del(key: string): Promise<void> {
          stateStore.delete(key);
        },
      },
      sessionStore: {
        async get(key: string): Promise<NodeSavedSession | undefined> {
          return sessionStore.get(key);
        },
        async set(key: string, session: NodeSavedSession): Promise<void> {
          sessionStore.set(key, session);
        },
        async del(key: string): Promise<void> {
          sessionStore.delete(key);
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
  async generateAuthUrl(appId: string, handle: string, customRedirect?: string): Promise<{
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
      redirect_uri: customRedirect || this.redirectUri,
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
