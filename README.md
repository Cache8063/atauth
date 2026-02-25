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

## Features

- **Standard OIDC Provider**: Discovery, authorization, token, userinfo, revocation, JWKS endpoints
- **Forward-Auth SSO Proxy**: nginx `auth_request` based single sign-on for any web service
- **Admin Dashboard**: Web UI with setup wizard for common self-hosted apps
- **Access Control**: Per-user DID and handle pattern rules with deny-overrides
- **PKCE Support**: Configurable per-client
- **ES256 Signed JWTs**: Proper key rotation via JWKS endpoint

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/Cache8063/atauth.git
cd atauth/gateway
cp .env.example .env
```

Edit `.env` -- replace `auth.yourdomain.com` with your actual domain in these fields:

```env
OAUTH_CLIENT_ID=https://auth.yourdomain.com/client-metadata.json
OAUTH_REDIRECT_URI=https://auth.yourdomain.com/auth/callback
OIDC_ISSUER=https://auth.yourdomain.com
WEBAUTHN_RP_ID=auth.yourdomain.com
WEBAUTHN_ORIGIN=https://auth.yourdomain.com
```

Generate and fill in the required secrets:

```bash
openssl rand -hex 32  # Use output for each value below
```

```env
ADMIN_TOKEN=<generated-value>
OIDC_KEY_SECRET=<generated-value>
MFA_ENCRYPTION_KEY=<generated-value>
```

### 2. Start the service

```bash
cd ..  # back to repo root
docker compose up -d
```

The gateway runs on `127.0.0.1:3100`. It needs a reverse proxy with TLS in front of it. The simplest option is Caddy (auto-HTTPS):

```caddyfile
auth.yourdomain.com {
    reverse_proxy localhost:3100
}
```

See the [Homelab Deployment Guide](docs/HOMELAB.md) for Traefik and nginx examples.

### 3. Register your first app

Open `https://auth.yourdomain.com/admin/login`, enter your admin token, and use the setup wizard to register an app.

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

## OIDC Discovery

Once running, your OIDC discovery document is at:

```text
https://your-domain/.well-known/openid-configuration
```

Configure any OIDC-compatible app with this URL and it will auto-discover all endpoints.

## Forward-Auth Proxy

For apps without OIDC support, ATAuth provides an nginx `auth_request` proxy:

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
