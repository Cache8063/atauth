# ATAuth - AT Protocol OIDC Provider

## Overview
ATAuth is an OpenID Connect (OIDC) Provider that uses AT Protocol OAuth (Bluesky) as the identity source. It allows applications to authenticate users via their Bluesky accounts.

## Critical: Domain Configuration

**IMPORTANT**: ATAuth staging MUST use `workingtitle.zip` domain, NOT `arcnode.xyz`.

Why: The user's PDS is at `arcnode.xyz`. If ATAuth is also on `arcnode.xyz`, the browser sends `Sec-Fetch-Site: same-site` to the PDS OAuth endpoint, which the PDS rejects. Using a different domain (`workingtitle.zip`) makes it `cross-site`, which is allowed.

## Architecture

```
OIDC Client (e.g., Audiobookshelf)
    ↓ redirects to
ATAuth (auth-staging.workingtitle.zip) - OIDC Provider
    ↓ redirects to
User's PDS (arcnode.xyz) - AT Protocol OAuth
    ↓ user authenticates, redirects back to
ATAuth (receives AT Proto tokens, issues OIDC tokens)
    ↓ redirects back to
OIDC Client (receives OIDC tokens)
```

- **Gateway**: Node.js/Express 5, TypeScript, SQLite
- **Identity Source**: AT Protocol OAuth (user's PDS, e.g., arcnode.xyz or bsky.social)
- **Token Format**: ES256 signed JWTs
- **PKCE**: Required for all flows

## Deployment

### Current Production (DigitalOcean)
- **Public URL**: `https://auth-staging.workingtitle.zip`
- **Apricot Gateway**: `https://apricot.workingtitle.zip` (routes `/auth/*` and `/admin/*` to ATAuth)
- **OIDC Discovery**: `https://auth-staging.workingtitle.zip/.well-known/openid-configuration`
- **Cluster**: DO Managed Kubernetes (`storm-dr-cluster`, nyc1)
- **Namespace**: `atauth`
- **Registry**: `registry.digitalocean.com/ghostmesh-registry`
- **Image**: `registry.digitalocean.com/ghostmesh-registry/atauth:latest`
- **Storage**: SQLite on `do-block-storage` PVC
- **Backups**: Every 6 hours to Backblaze B2 (`age` encrypted, cronjob in `backups` namespace)

### Deployment Process (Manual)
```bash
# Build and push
docker build --platform linux/amd64 -t registry.digitalocean.com/ghostmesh-registry/atauth:latest .
docker push registry.digitalocean.com/ghostmesh-registry/atauth:latest

# Deploy
kubectl rollout restart deployment/atauth-gateway -n atauth
```

### Local k3s (Suspended)
Previously ran on k3s (Proxmox VMs 321/322) with two namespaces: `atauth-staging` (standalone)
and `apricot` (integrated with PDS). Local k3s VMs shut down as of Feb 12, 2026.
Config preserved in `gateway/k8s/overlays/staging/` and `gateway/k8s/overlays/production/`.

## Admin Access

### Admin Token
The admin token is stored in **Vaultwarden**:
- **URL**: https://vaultwarden.cloudforest-basilisk.ts.net
- **Location**: `ATAuth` folder → `Admin Token - Staging` or `Admin Token - Production`

### Using Admin API
```bash
# Set token from Vaultwarden
export ADMIN_TOKEN="<token-from-vaultwarden>"

# List OIDC clients
curl -s "https://auth-staging.workingtitle.zip/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Create/update client
curl -X POST "https://auth-staging.workingtitle.zip/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

## OIDC Client Configuration

### Registered Clients

#### Audiobookshelf

| Setting | Value |
|---------|-------|
| **Client ID** | `audiobookshelf` |
| **Client Secret** | Vaultwarden → `ATAuth/OIDC Clients/Audiobookshelf` |
| **Redirect URI** | `https://audiobookshelf.cloudforest-basilisk.ts.net/auth/openid/callback` |
| **Grant Types** | `authorization_code`, `refresh_token` |
| **Scopes** | `openid`, `profile`, `email` |
| **PKCE** | Required |

**Note**: Redirect URI is HTTPS without port (Tailscale serve handles TLS on port 443).

### Secrets Storage
All secrets in **Vaultwarden** (LXC 120 @ vaultwarden.cloudforest-basilisk.ts.net):
- `ATAuth/Admin Token - Staging`
- `ATAuth/Admin Token - Production`
- `ATAuth/OIDC Clients/Audiobookshelf`
- `ATAuth/OIDC Key Secret`

## Infrastructure

### Cloudflare Configuration
- **Account ID**: `abc90e3f264c71019a7f68204a5c4454`
- **Tunnel ID**: `600f069c-4c53-4a59-b1fd-57c5ad09c044`
- **Routes**:
  - `auth-staging.workingtitle.zip` → `http://atauth-gateway.atauth.svc.cluster.local:80` (DO cluster)
  - `apricot.workingtitle.zip` → `http://atauth-gateway.atauth.svc.cluster.local:80` (DO cluster)
  - `auth-staging.arcnode.xyz` → (DEPRECATED, causes same-site issues)

### Security (Cloudflare)
- **WAF**: Cloudflare Managed Ruleset + OWASP Core (block mode)
- **Rate Limiting**: 10 req/min on `/oauth/token`, `/oauth/authorize`, `/auth/*`
- **TLS**: Minimum 1.3, Strict mode

### Cluster Resources
```bash
# Check deployment
kubectl -n atauth get pods
kubectl -n atauth logs -l app.kubernetes.io/part-of=atauth

# View/edit config
kubectl -n atauth get configmap atauth-gateway-config -o yaml

# Restart after config change
kubectl -n atauth rollout restart deployment atauth-gateway
```

## Related Services

### User's PDS (arcnode.xyz)
- **Server**: Hetzner Cloud (pds-hetzner)
- **Public IP**: 46.224.33.19
- **Tailscale**: 100.89.0.112 (pds-hetzner)
- **SSH**: `ssh -i ~/.ssh/vaultnode_ed25519 root@100.89.0.112`
- **OAuth Endpoint**: `https://arcnode.xyz/oauth/authorize`
- **DID**: `did:plc:k23ujfuppr3hr4pxvtaz7jro`
- **Handle**: `@bkb.arcnode.xyz`

### Audiobookshelf
- **Location**: LXC 107 on `pv4`
- **Tailscale IP**: 100.115.188.60
- **URL**: `https://audiobookshelf.cloudforest-basilisk.ts.net` (via Tailscale serve)
- **Internal**: nginx (8080) → ABS (13378)
- **SSH via pv4**: `ssh root@pv4.cloudforest-basilisk.ts.net "pct exec 107 -- <command>"`

### Vaultwarden
- **Location**: LXC 120
- **URL**: https://vaultwarden.cloudforest-basilisk.ts.net

## Testing

### Run Tests
```bash
cd gateway
npm run test:unit    # Unit tests only
npm run test:e2e     # E2E tests only
npm run test         # All tests with watch
npm run test:run     # All tests once
```

### Manual OIDC Flow Test
```bash
# 1. Check discovery
curl -s "https://auth-staging.workingtitle.zip/.well-known/openid-configuration" | jq .

# 2. Check JWKS
curl -s "https://auth-staging.workingtitle.zip/.well-known/jwks.json" | jq .

# 3. Test in browser - go to Audiobookshelf and click "Login with OpenID"
```

## API Endpoints

### OIDC Endpoints
| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | Discovery document |
| `/.well-known/jwks.json` | Public signing keys |
| `/oauth/authorize` | Authorization endpoint |
| `/oauth/token` | Token exchange |
| `/oauth/userinfo` | User claims |
| `/oauth/revoke` | Token revocation |

### Admin Endpoints (requires Bearer token)
| Endpoint | Description |
|----------|-------------|
| `GET /admin/oidc/clients` | List OIDC clients |
| `POST /admin/oidc/clients` | Create OIDC client |
| `GET /admin/oidc/clients/:id` | Get client details |
| `PUT /admin/oidc/clients/:id` | Update client |
| `DELETE /admin/oidc/clients/:id` | Delete client |
| `GET /admin/sessions` | List sessions |
| `GET /admin/keys` | List signing keys |

## Troubleshooting

### "Forbidden sec-fetch-site header same-site"
**Cause**: ATAuth and user's PDS are on the same registrable domain.
**Fix**: Use `workingtitle.zip` for ATAuth, not `arcnode.xyz`.

### "invalid_redirect_uri"
**Cause**: Redirect URI in request doesn't match registered client.
**Fix**: Check client's registered redirect_uris match exactly (including https vs http, port, path).

### Token refresh failures / Users logged out
**Cause**: iOS app sends chunked encoding with empty body on refreshSession.
**Fix**: nginx with `proxy_pass_request_body off` for that endpoint (handled on PDS side).
