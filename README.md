# ATAuth - OIDC Provider for AT Protocol

An OpenID Connect (OIDC) Provider that uses AT Protocol OAuth (Bluesky) as the identity source. Authenticate users via their `@handle` -- works with Bluesky or any self-hosted PDS.

## What It Does

ATAuth sits between your apps and AT Protocol identity:

```text
Your App (OIDC Client)
    |
    v
ATAuth (OIDC Provider)
    |
    v
User's PDS (Bluesky / self-hosted)
    |
    v
User authenticates with their AT Proto identity
    |
    v
ATAuth issues standard OIDC tokens back to your app
```

Any app that supports OpenID Connect can use ATAuth. No custom integration needed.

## Screenshots

<!-- Add your own screenshots to docs/screenshots/ -->

![Login - Sign in with your AT Protocol identity](docs/screenshots/login.png)

![Admin Dashboard - Stats and quick actions](docs/screenshots/dashboard.png)

![Setup Wizard - One-click setup for 20+ self-hosted apps](docs/screenshots/wizard.png)

![Access Rules - Per-user control with DID and handle patterns](docs/screenshots/access-rules.png)

## Features

- **Standard OIDC Provider**: Discovery, authorization, token, userinfo, revocation, JWKS endpoints
- **Passkey Login**: WebAuthn/FIDO2 support -- users can register passkeys and skip the Bluesky OAuth flow
- **Forward-Auth SSO Proxy**: nginx `auth_request` based single sign-on for any web service
- **Admin Dashboard**: Web UI with setup wizard for 20+ common self-hosted apps
- **Access Control**: Per-user DID and handle pattern rules with deny-overrides
- **PKCE Support**: Configurable per-client
- **ES256 Signed JWTs**: Proper key rotation via JWKS endpoint

## Quick Start

### Prerequisites

- Docker and Docker Compose
- A domain with a DNS record pointing to your server (e.g. `auth.yourdomain.com`)
- A reverse proxy that terminates TLS (Caddy, Traefik, or nginx)

### 1. Clone and configure

```bash
git clone https://github.com/Cache8063/atauth.git
cd atauth
cp gateway/.env.example .env
```

Edit `.env` -- replace every instance of `auth.yourdomain.com` with your actual domain:

```env
# These must all use your real domain
OAUTH_CLIENT_ID=https://auth.yourdomain.com/client-metadata.json
OAUTH_REDIRECT_URI=https://auth.yourdomain.com/auth/callback
OIDC_ISSUER=https://auth.yourdomain.com
WEBAUTHN_RP_ID=auth.yourdomain.com
WEBAUTHN_ORIGIN=https://auth.yourdomain.com
CORS_ORIGINS=https://app1.yourdomain.com,https://app2.yourdomain.com
```

Generate and fill in the three required secrets (run the command once per value):

```bash
openssl rand -hex 32
```

```env
ADMIN_TOKEN=<paste-generated-value>
OIDC_KEY_SECRET=<paste-generated-value>
MFA_ENCRYPTION_KEY=<paste-generated-value>
```

### 2. Start the service

```bash
docker compose up -d
```

The gateway starts on `127.0.0.1:3100`. Put a reverse proxy with TLS in front of it. The simplest option is [Caddy](https://caddyserver.com/) (automatic HTTPS):

```caddyfile
auth.yourdomain.com {
    reverse_proxy localhost:3100
}
```

See the [Homelab Deployment Guide](docs/HOMELAB.md) for Traefik and nginx examples.

### 3. Verify it's running

```bash
curl https://auth.yourdomain.com/.well-known/openid-configuration
```

You should get a JSON document with all the OIDC endpoints.

### 4. Register your first app

Open `https://auth.yourdomain.com/admin/login`, enter your `ADMIN_TOKEN`, and use the setup wizard to register an app. The wizard includes presets that auto-fill redirect URIs, scopes, and grant types.

Save the returned **client secret** -- it is only shown once.

### 5. Configure your app

Point your app's OIDC settings to ATAuth's discovery URL:

| Setting | Value |
| --- | --- |
| Discovery URL | `https://auth.yourdomain.com/.well-known/openid-configuration` |
| Client ID | The ID you chose in the wizard |
| Client Secret | The secret returned at registration |
| Scopes | `openid profile` (add `email` if needed) |

## Supported Apps

The setup wizard includes presets for:

| App | Auth Method |
| --- | --- |
| Audiobookshelf | OIDC (OpenID Connect) |
| Jellyfin | OIDC (via SSO plugin) |
| Gitea / Forgejo | OIDC (built-in) |
| Nextcloud | OIDC (via app) |
| Immich | OIDC (built-in) |
| Grafana | OIDC (built-in) |
| Wiki.js | OIDC (built-in) |
| Portainer | OIDC (built-in) |
| Outline | OIDC (built-in) |
| Mealie | OIDC (built-in) |
| Paperless-ngx | OIDC (built-in) |
| Vaultwarden | OIDC (built-in) |
| Miniflux | OIDC (built-in) |
| Mattermost | OIDC (built-in) |
| Vikunja | OIDC (built-in) |
| Plane | OIDC (built-in) |
| GoToSocial | OIDC (built-in) |
| Stirling-PDF | OIDC (built-in) |
| Tandoor Recipes | OIDC (built-in) |
| FreshRSS | OIDC (built-in) |
| Any web service | Forward-auth proxy (nginx `auth_request`) |

## Forward-Auth Proxy

For apps without OIDC support, ATAuth provides nginx `auth_request` based SSO. Enable it in `.env`:

```env
FORWARD_AUTH_ENABLED=true
FORWARD_AUTH_SESSION_SECRET=<generate-with-openssl-rand-hex-32>
```

Then configure nginx:

```nginx
location / {
    auth_request /auth/verify;
    auth_request_set $auth_did $upstream_http_x_auth_did;
    auth_request_set $auth_handle $upstream_http_x_auth_handle;
    proxy_set_header X-Auth-DID $auth_did;
    proxy_set_header X-Auth-Handle $auth_handle;
    proxy_pass http://your-app;
}

location = /auth/verify {
    internal;
    proxy_pass http://atauth:3100;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
}
```

The admin dashboard generates these config snippets for you.

## Self-Hosted PDS

With a self-hosted PDS, ATAuth becomes a fully independent auth system:

- Users get handles like `@alice.your-domain.com`
- No dependency on Bluesky servers
- Works on air-gapped networks
- Same security model as enterprise OAuth

The gateway auto-discovers the user's PDS from their handle. No special configuration needed.

## Architecture

| Component | Description |
| --- | --- |
| **Gateway** | Node.js/Express 5, TypeScript, SQLite |
| **Identity** | AT Protocol OAuth (user's PDS) |
| **OIDC Tokens** | ES256 signed JWTs |
| **Proxy Cookies** | HMAC-SHA256 signed, typed |
| **Access Control** | Deny-overrides, per-origin + global rules |

## Security

- No hardcoded secrets -- all sensitive config validated at startup
- Client secrets stored as SHA-256 hashes
- One-time flash tokens for secret display (never in URLs)
- PKCE support (configurable per-client)
- Constant-time comparison for all secret verification
- HTML escaping on all server-rendered pages
- HMAC-signed CSRF tokens on all dashboard forms
- Rate limiting on auth endpoints
- CSP with per-request nonces for inline scripts
- WAF-compatible (Cloudflare Managed Ruleset + OWASP)

## Documentation

- [Homelab Deployment Guide](docs/HOMELAB.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT
