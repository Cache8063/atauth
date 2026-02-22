/**
 * OIDC App Presets
 *
 * Pre-configured settings for common self-hosted applications.
 * Used by the setup wizard to simplify OIDC client registration.
 */

export interface OIDCAppPreset {
  /** URL-safe key used in wizard routes */
  key: string;
  /** Display name */
  name: string;
  /** Short description */
  description: string;
  /** Suggested client_id */
  suggested_client_id: string;
  /** Recommended grant types */
  grant_types: string[];
  /** Recommended scopes */
  scopes: string[];
  /** Redirect URI template -- {{DOMAIN}} is replaced by user input */
  redirect_uri_template: string;
  /** Token endpoint auth method */
  token_endpoint_auth_method: 'client_secret_basic' | 'client_secret_post' | 'none';
  /** Whether PKCE should be required */
  require_pkce: boolean;
  /** Token TTLs in seconds */
  id_token_ttl_seconds: number;
  access_token_ttl_seconds: number;
  refresh_token_ttl_seconds: number;
  /** Setup instructions shown after client creation */
  setup_notes: string;
}

export const OIDC_APP_PRESETS: OIDCAppPreset[] = [
  {
    key: 'audiobookshelf',
    name: 'Audiobookshelf',
    description: 'Audiobook and podcast server',
    suggested_client_id: 'audiobookshelf',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/auth/openid/callback',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'In Audiobookshelf: Settings > Authentication > OpenID.\n- Issuer URL: Your ATAuth discovery URL\n- Client ID: The client ID above\n- Client Secret: The secret above\n- Auto Launch: Enable for automatic redirect\n- Button Text: "Sign in with AT Protocol"',
  },
  {
    key: 'jellyfin',
    name: 'Jellyfin',
    description: 'Media server (requires SSO plugin)',
    suggested_client_id: 'jellyfin',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile'],
    redirect_uri_template: 'https://{{DOMAIN}}/sso/OID/redirect/atauth',
    token_endpoint_auth_method: 'client_secret_post',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'Requires the SSO Authentication plugin.\n1. Install "SSO Authentication" from the Jellyfin plugin catalog\n2. Restart Jellyfin\n3. In Dashboard > Plugins > SSO, add an OpenID provider:\n   - Provider name: atauth\n   - OID Discovery URL: Your ATAuth discovery URL\n   - Client ID and Client Secret from above',
  },
  {
    key: 'nextcloud',
    name: 'Nextcloud',
    description: 'File sync and collaboration platform',
    suggested_client_id: 'nextcloud',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/apps/oidc_login/oidc',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'Requires the "OpenID Connect Login" app.\n1. Install from Nextcloud Apps\n2. Settings > Administration > SSO & SAML\n3. Configure:\n   - Identifier: atauth\n   - Client ID and Client Secret from above\n   - Discovery endpoint: Your ATAuth discovery URL\n   - Button display name: "ATAuth"',
  },
  {
    key: 'gitea',
    name: 'Gitea / Forgejo',
    description: 'Git hosting and DevOps platform',
    suggested_client_id: 'gitea',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/user/oauth2/atauth/callback',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'In Site Administration > Authentication Sources:\n1. Add Authentication Source > OAuth2\n2. Authentication Name: atauth\n3. OAuth2 Provider: OpenID Connect\n4. Client ID and Client Secret from above\n5. OpenID Connect Auto Discovery URL: Your ATAuth discovery URL\n6. Save',
  },
  {
    key: 'immich',
    name: 'Immich',
    description: 'Photo and video management',
    suggested_client_id: 'immich',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/auth/login\napp.immich:/',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'In Administration > Settings > OAuth:\n1. Enable OAuth Login\n2. Issuer URL: Your ATAuth discovery URL\n3. Client ID and Client Secret from above\n4. Scope: openid profile email\n5. Button Text: "Sign in with ATAuth"\nNote: Both web and mobile redirect URIs are registered.',
  },
  {
    key: 'grafana',
    name: 'Grafana',
    description: 'Monitoring and observability dashboards',
    suggested_client_id: 'grafana',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/login/generic_oauth',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'Set these environment variables (or grafana.ini):\n  GF_AUTH_GENERIC_OAUTH_ENABLED=true\n  GF_AUTH_GENERIC_OAUTH_NAME=ATAuth\n  GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana\n  GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<secret>\n  GF_AUTH_GENERIC_OAUTH_SCOPES=openid profile email\n  GF_AUTH_GENERIC_OAUTH_AUTH_URL=<issuer>/oauth/authorize\n  GF_AUTH_GENERIC_OAUTH_TOKEN_URL=<issuer>/oauth/token\n  GF_AUTH_GENERIC_OAUTH_API_URL=<issuer>/oauth/userinfo\n  GF_AUTH_GENERIC_OAUTH_USE_PKCE=true',
  },
  {
    key: 'wikijs',
    name: 'Wiki.js',
    description: 'Modern wiki engine',
    suggested_client_id: 'wikijs',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/login/atauth/callback',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: false,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'In Administration > Authentication:\n1. Add Strategy > OpenID Connect / OAuth2\n2. Client ID and Client Secret from above\n3. Authorization Endpoint URL: <issuer>/oauth/authorize\n4. Token URL: <issuer>/oauth/token\n5. User Info URL: <issuer>/oauth/userinfo\nNote: Wiki.js does not support PKCE, so it is disabled for this client.',
  },
  {
    key: 'portainer',
    name: 'Portainer',
    description: 'Container management UI',
    suggested_client_id: 'portainer',
    grant_types: ['authorization_code'],
    scopes: ['openid', 'profile'],
    redirect_uri_template: 'https://{{DOMAIN}}',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: false,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'In Settings > Authentication > OAuth:\n1. Provider: Custom\n2. Client ID and Client Secret from above\n3. Authorization URL: <issuer>/oauth/authorize\n4. Access Token URL: <issuer>/oauth/token\n5. Resource URL: <issuer>/oauth/userinfo\n6. Redirect URL: https://your-portainer-domain\n7. Scopes: openid profile',
  },
  {
    key: 'outline',
    name: 'Outline',
    description: 'Team knowledge base and wiki',
    suggested_client_id: 'outline',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/auth/oidc.callback',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'Set these environment variables:\n  OIDC_CLIENT_ID=outline\n  OIDC_CLIENT_SECRET=<secret>\n  OIDC_AUTH_URI=<issuer>/oauth/authorize\n  OIDC_TOKEN_URI=<issuer>/oauth/token\n  OIDC_USERINFO_URI=<issuer>/oauth/userinfo\n  OIDC_DISPLAY_NAME=ATAuth\n  OIDC_SCOPES=openid profile email',
  },
  {
    key: 'mealie',
    name: 'Mealie',
    description: 'Recipe management and meal planning',
    suggested_client_id: 'mealie',
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    redirect_uri_template: 'https://{{DOMAIN}}/login',
    token_endpoint_auth_method: 'client_secret_basic',
    require_pkce: true,
    id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600,
    refresh_token_ttl_seconds: 604800,
    setup_notes: 'Set these environment variables:\n  OIDC_AUTH_ENABLED=true\n  OIDC_CLIENT_ID=mealie\n  OIDC_CLIENT_SECRET=<secret>\n  OIDC_CONFIGURATION_URL=<issuer>/.well-known/openid-configuration\n  OIDC_SIGNUP_ENABLED=true\n  OIDC_PROVIDER_NAME=ATAuth',
  },
];

export function getPresetByKey(key: string): OIDCAppPreset | undefined {
  return OIDC_APP_PRESETS.find(p => p.key === key);
}
