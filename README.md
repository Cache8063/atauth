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

```bash
git clone https://github.com/Cache8063/atauth.git
cd atauth/gateway
cp .env.example .env
```

Edit `.env` and fill in the required secrets (generate with `openssl rand -hex 32`):

```env
ADMIN_TOKEN=<your-admin-token>
OIDC_KEY_SECRET=<your-oidc-key-secret>
MFA_ENCRYPTION_KEY=<your-64-hex-char-key>  # openssl rand -hex 32
```

Then start:

```bash
docker compose up -d
```

Open the admin dashboard at `https://your-domain/admin/login` and use the setup wizard to register your first app.

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

- [Development Guide](CLAUDE.md)
- [Homelab Deployment Guide](docs/HOMELAB.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT
