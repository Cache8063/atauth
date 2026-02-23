# ATAuth Homelab Deployment Guide

ATAuth provides OIDC-based authentication for your homelab using AT Protocol identities. Users sign in with their `@handle` (Bluesky or self-hosted PDS) and your apps receive standard OIDC tokens.

## Prerequisites

- Docker and Docker Compose
- A domain name with TLS (reverse proxy: Caddy, Traefik, or nginx)
- Optional: Your own PDS for fully self-hosted identity

## Deploy

```bash
git clone https://github.com/Cache8063/atauth.git
cd atauth
cp .env.example .env

# Generate admin token
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# Set your public URL
# Edit .env: OAUTH_CLIENT_ID and OAUTH_REDIRECT_URI

docker compose up -d
```

The gateway runs on port 3100. Put a reverse proxy with TLS in front of it.

## Register Apps

### Option 1: Admin Dashboard (Recommended)

Open `https://your-atauth-domain/admin/login`, enter your admin token, then use the **Setup Wizard** to register apps. It includes presets for:

- Audiobookshelf, Jellyfin, Gitea/Forgejo, Nextcloud, Immich
- Grafana, Wiki.js, Portainer, Outline, Mealie

Each preset auto-fills the correct redirect URI, scopes, and grant types.

### Option 2: Admin API

```bash
curl -X POST https://your-atauth-domain/admin/oidc/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "jellyfin",
    "name": "Jellyfin",
    "redirect_uris": ["https://jellyfin.example.com/sso/OID/redirect/ATAuth"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"],
    "require_pkce": true,
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

Save the returned `client_secret` -- it is only shown once.

## Configure Your App

Point your app's OIDC settings to ATAuth's discovery URL:

```text
https://your-atauth-domain/.well-known/openid-configuration
```

This auto-discovers all endpoints. Most apps need:

| Setting | Value |
| --- | --- |
| Discovery URL | `https://your-atauth-domain/.well-known/openid-configuration` |
| Client ID | The ID you chose when registering |
| Client Secret | The secret returned at registration |
| Scopes | `openid profile email` |

## Forward-Auth Proxy

For apps without OIDC support, ATAuth provides nginx `auth_request` based SSO.

1. Register the origin in the admin dashboard under **Proxy Origins**
2. Add access rules under **Access Rules**
3. Use the **Proxy Setup Wizard** to generate nginx config snippets

Example nginx config:

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

## Reverse Proxy Configuration

### Caddy

```caddyfile
auth.example.com {
    reverse_proxy atauth:3100
}
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.atauth.rule=Host(`auth.example.com`)"
  - "traefik.http.routers.atauth.entrypoints=websecure"
  - "traefik.http.routers.atauth.tls.certresolver=letsencrypt"
  - "traefik.http.services.atauth.loadbalancer.server.port=3100"
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/auth.example.com.crt;
    ssl_certificate_key /etc/ssl/private/auth.example.com.key;

    location / {
        proxy_pass http://atauth:3100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Self-Hosted PDS

With your own PDS, ATAuth becomes fully independent:

- Users get handles like `@alice.your-domain.com`
- No dependency on Bluesky
- Works on air-gapped networks

The gateway auto-discovers the user's PDS from their handle. No special configuration needed -- just ensure the PDS is reachable.

## Access Control

ATAuth supports per-user access rules:

- **Allow/deny by DID**: Target specific AT Protocol identities
- **Allow/deny by handle pattern**: `*.your-pds.com` matches all handles on a PDS domain
- **Deny overrides**: Deny rules always win regardless of order
- **Per-origin scoping**: Rules can target a specific origin or apply globally

Manage rules via the admin dashboard or API.

## Backup

```bash
# Backup the SQLite database
docker compose exec atauth cp /app/data/gateway.db /app/data/gateway.db.backup

# Or backup the volume
docker run --rm -v atauth_atauth-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/atauth-backup.tar.gz -C /data .
```

## Updating

```bash
docker compose pull
docker compose up -d
```

## Troubleshooting

### OIDC discovery returns 404

Ensure your `OAUTH_CLIENT_ID` URL is publicly accessible and the gateway is running.

### Users can't authenticate

1. Check the PDS is reachable from the ATAuth container
2. Verify the user's handle resolves correctly
3. Check logs: `docker compose logs atauth`

### "invalid_redirect_uri"

The redirect URI in the OIDC request must exactly match one registered for the client (including scheme, host, port, and path).
