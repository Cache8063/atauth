# ATAuth - AT Protocol OIDC Provider

## Overview
ATAuth is an OpenID Connect (OIDC) Provider that uses AT Protocol OAuth (Bluesky) as the identity source. It allows applications to authenticate users via their Bluesky accounts.

## Architecture
- **Gateway**: Node.js/Express 5, TypeScript, SQLite
- **Identity Source**: AT Protocol OAuth (bsky.social)
- **Token Format**: ES256 signed JWTs
- **PKCE**: Required for all flows

## Deployment

### Staging
- **Public URL**: `https://auth-staging.arcnode.xyz`
- **OIDC Discovery**: `https://auth-staging.arcnode.xyz/.well-known/openid-configuration`
- **Namespace**: `atauth-staging` (k3s)
- **Image**: `10.43.37.39:5000/atauth:staging`

### Production
- **Namespace**: `atauth` (k3s)
- **Image**: `10.43.37.39:5000/atauth:latest`

## Secrets Management

### Kubernetes Secrets
Secrets are stored in Kubernetes Secrets and referenced via environment variables:
- `OIDC_KEY_SECRET`: 32-byte encryption key for OIDC signing keys
- `MFA_ENCRYPTION_KEY`: 64-char hex key for TOTP secrets
- `ADMIN_TOKEN`: Admin API authentication token

### Best Practices
1. **Never commit secrets to git** - Use Kubernetes Secrets or SealedSecrets
2. **Rotate secrets regularly** - Especially OIDC_KEY_SECRET
3. **Use strong entropy** - Generate with `openssl rand -hex 32`
4. **Audit access** - Monitor who accesses secrets

### Secret Generation Commands
```bash
# OIDC Key Secret (32 bytes)
openssl rand -hex 32

# MFA Encryption Key (32 bytes = 64 hex chars)
openssl rand -hex 32

# Admin Token
openssl rand -base64 32
```

## OIDC Client Configuration

### Registered Clients

#### Audiobookshelf

- **Client ID**: `audiobookshelf`
- **Redirect URIs**:
  - `http://audiobookshelf.cloudforest-basilisk.ts.net:13378/auth/openid/callback`
  - `https://audiobookshelf.cloudforest-basilisk.ts.net:13378/auth/openid/callback`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Scopes**: `openid`, `profile`, `email`
- **PKCE**: Required
- **Client Secret**: Stored in Vaultwarden under "ATAuth OIDC Clients"

### Secrets Storage Location

All OIDC client secrets are stored in **Vaultwarden** (LXC 120 @ vaultwarden.cloudforest-basilisk.ts.net):

- Folder: `ATAuth/OIDC Clients`
- Entry format: `{client_name} - {environment}`

### Registering New Clients
```bash
curl -X POST "https://auth-staging.arcnode.xyz/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

## Infrastructure

### Cloudflare Tunnel
- **Tunnel ID**: `600f069c-4c53-4a59-b1fd-57c5ad09c044`
- **Route**: `auth-staging.arcnode.xyz` → `atauth-gateway-staging.atauth-staging.svc.cluster.local:80`

### Security (Cloudflare)
- **WAF**: Cloudflare Managed Ruleset + OWASP Core (block mode)
- **Rate Limiting**: 10 req/min on `/oauth/token`, `/oauth/authorize`, `/auth/*`
- **TLS**: Minimum 1.3, Strict mode
- **Exposed Credentials Check**: Enabled

### Tekton Pipeline
- **Pipeline**: `atauth-build` (in `apricot` namespace)
- **Trigger**: Gitea webhook on push to `main`
- **Registry**: `gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway`

## Testing

### Run Tests
```bash
cd gateway
npm run test:unit    # Unit tests only
npm run test:e2e     # E2E tests only
npm run test         # All tests with watch
npm run test:run     # All tests once
```

### Test Coverage
- **Unit Tests**: 65 tests (PKCE, Claims, Tokens services)
- **E2E Tests**: 22 tests (full OIDC flow)

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

### Admin Endpoints
| Endpoint | Description |
|----------|-------------|
| `/admin/oidc/clients` | CRUD for OIDC clients |
| `/admin/sessions` | Session management |
| `/admin/keys` | Key management |

## Related Services

### Audiobookshelf
- **Location**: LXC 107 on `pv4`
- **IP**: 10.50.1.117 / 100.115.188.60 (Tailscale)
- **Port**: 13378
- **URL**: `http://audiobookshelf.cloudforest-basilisk.ts.net:13378`
