/**
 * API Client for ATAuth Admin
 */

const API_BASE = import.meta.env.DEV ? '/admin/api' : '/admin';

interface ApiError {
  error: string;
  message: string;
}

class AdminApiClient {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: 'unknown_error',
        message: response.statusText,
      }));
      throw new Error(error.message || error.error);
    }

    return response.json();
  }

  // Stats
  async getStats() {
    return this.request<{
      apps_count: number;
      oidc_clients_count: number;
      active_sessions_count: number;
      users_count: number;
      passkeys_count: number;
      mfa_enabled_count: number;
      verified_emails_count: number;
    }>('/stats');
  }

  // Apps (Legacy)
  async getApps() {
    return this.request<{
      apps: Array<{
        id: string;
        name: string;
        token_ttl_seconds: number;
        callback_url: string;
        created_at: string;
      }>;
    }>('/apps');
  }

  async createApp(data: {
    name: string;
    callback_url: string;
    token_ttl_seconds?: number;
  }) {
    return this.request<{
      id: string;
      hmac_secret: string;
    }>('/apps', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async deleteApp(appId: string) {
    return this.request<{ success: boolean }>(`/apps/${appId}`, {
      method: 'DELETE',
    });
  }

  async rotateAppSecret(appId: string) {
    return this.request<{ hmac_secret: string }>(`/apps/${appId}/rotate`, {
      method: 'POST',
    });
  }

  // OIDC Clients
  async getOIDCClients() {
    return this.request<{
      clients: Array<{
        id: string;
        name: string;
        client_type: string;
        redirect_uris: string[];
        allowed_scopes: string[];
        grant_types: string[];
        require_pkce: boolean;
        access_token_ttl_seconds: number;
        id_token_ttl_seconds: number;
        refresh_token_ttl_seconds: number;
        created_at: string;
      }>;
    }>('/oidc/clients');
  }

  async createOIDCClient(data: {
    name: string;
    redirect_uris: string[];
    allowed_scopes?: string[];
    grant_types?: string[];
    require_pkce?: boolean;
    access_token_ttl_seconds?: number;
    id_token_ttl_seconds?: number;
    refresh_token_ttl_seconds?: number;
  }) {
    return this.request<{
      id: string;
      client_secret: string;
    }>('/oidc/clients', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateOIDCClient(
    clientId: string,
    data: {
      name?: string;
      redirect_uris?: string[];
      allowed_scopes?: string[];
      grant_types?: string[];
      require_pkce?: boolean;
      access_token_ttl_seconds?: number;
      id_token_ttl_seconds?: number;
      refresh_token_ttl_seconds?: number;
    }
  ) {
    return this.request<{ success: boolean }>(`/oidc/clients/${clientId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteOIDCClient(clientId: string) {
    return this.request<{ success: boolean }>(`/oidc/clients/${clientId}`, {
      method: 'DELETE',
    });
  }

  async rotateOIDCClientSecret(clientId: string) {
    return this.request<{ client_secret: string }>(
      `/oidc/clients/${clientId}/rotate-secret`,
      {
        method: 'POST',
      }
    );
  }

  // Sessions
  async getSessions(params?: { app_id?: string; did?: string; limit?: number }) {
    const query = new URLSearchParams();
    if (params?.app_id) query.set('app_id', params.app_id);
    if (params?.did) query.set('did', params.did);
    if (params?.limit) query.set('limit', params.limit.toString());

    const queryStr = query.toString();
    return this.request<{
      sessions: Array<{
        id: string;
        did: string;
        handle: string;
        app_id: string;
        created_at: string;
        expires_at: string;
        connection_state: string;
        last_activity: string;
      }>;
    }>(`/sessions${queryStr ? `?${queryStr}` : ''}`);
  }

  async revokeSession(sessionId: string) {
    return this.request<{ success: boolean }>(`/sessions/${sessionId}`, {
      method: 'DELETE',
    });
  }

  async revokeAllSessions(did: string, appId?: string) {
    return this.request<{ revoked: number }>('/sessions/revoke-all', {
      method: 'POST',
      body: JSON.stringify({ did, app_id: appId }),
    });
  }

  // Keys
  async getKeys() {
    return this.request<{
      keys: Array<{
        kid: string;
        algorithm: string;
        is_active: boolean;
        use_for_signing: boolean;
        created_at: string;
      }>;
    }>('/keys');
  }

  async rotateKeys() {
    return this.request<{
      kid: string;
      message: string;
    }>('/keys/rotate', {
      method: 'POST',
    });
  }

  async deleteKey(kid: string) {
    return this.request<{ success: boolean }>(`/keys/${kid}`, {
      method: 'DELETE',
    });
  }

  // Users
  async getUsers(params?: { limit?: number; offset?: number }) {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.offset) query.set('offset', params.offset.toString());

    const queryStr = query.toString();
    return this.request<{
      users: Array<{
        did: string;
        handle: string;
        passkeys_count: number;
        mfa_enabled: boolean;
        emails_count: number;
        sessions_count: number;
      }>;
    }>(`/users${queryStr ? `?${queryStr}` : ''}`);
  }

  async getUser(did: string) {
    return this.request<{
      user: {
        did: string;
        handle: string;
        passkeys: Array<{
          id: string;
          name: string | null;
          device_type: string;
          backed_up: boolean;
          last_used_at: string | null;
          created_at: string;
        }>;
        mfa_enabled: boolean;
        emails: Array<{
          email: string;
          verified: boolean;
          is_primary: boolean;
        }>;
        sessions: Array<{
          id: string;
          app_id: string;
          created_at: string;
          expires_at: string;
        }>;
      };
    }>(`/users/${encodeURIComponent(did)}`);
  }

  async revokeUserMFA(did: string) {
    return this.request<{ success: boolean }>(
      `/users/${encodeURIComponent(did)}/mfa`,
      {
        method: 'DELETE',
      }
    );
  }

  async deleteUserPasskey(did: string, credentialId: string) {
    return this.request<{ success: boolean }>(
      `/users/${encodeURIComponent(did)}/passkeys/${encodeURIComponent(credentialId)}`,
      {
        method: 'DELETE',
      }
    );
  }
}

export const api = new AdminApiClient();
