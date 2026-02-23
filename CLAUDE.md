# ATAuth - AT Protocol OIDC Provider

## Overview
ATAuth is an OpenID Connect (OIDC) Provider that uses AT Protocol OAuth (Bluesky) as the identity source. It allows applications to authenticate users via their Bluesky accounts.

## Critical: Domain Configuration

**IMPORTANT**: ATAuth staging MUST use `workingtitle.zip` domain, NOT `arcnode.xyz`.

Why: The user's PDS is at `arcnode.xyz`. If ATAuth is also on `arcnode.xyz`, the browser sends `Sec-Fetch-Site: same-site` to the PDS OAuth endpoint, which the PDS rejects. Using a different domain (`workingtitle.zip`) makes it `cross-site`, which is allowed.

## Architecture

### OIDC Provider Flow
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

### Forward-Auth SSO Proxy Flow
```
Browser → Protected Service (e.g., SearXNG)
    ↓ nginx auth_request subrequest
ATAuth /auth/verify (checks _atauth_proxy cookie)
    ↓ no valid session?
ATAuth /auth/login → AT Protocol OAuth → callback
    ↓ user authenticates, access rules evaluated
Session created → _atauth_proxy cookie set
    ↓ ticket exchange
Protected service receives X-Auth-DID, X-Auth-Handle headers
```

- **Gateway**: Node.js/Express 5, TypeScript, SQLite (better-sqlite3)
- **Identity Source**: AT Protocol OAuth (user's PDS, e.g., arcnode.xyz or bsky.social)
- **Token Format**: ES256 signed JWTs (OIDC), HMAC-SHA256 signed cookies (proxy)
- **PKCE**: Required for all flows
- **Forward-Auth Proxy**: nginx `auth_request` based SSO for arbitrary services
- **Access Control**: Per-user DID and handle pattern rules, deny-overrides evaluation
- **Admin Dashboard**: Server-rendered HTML at `/admin/dashboard` (cookie or Bearer token auth)

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
- **Backups**: Every 2 hours to Backblaze B2 (`age` encrypted, cronjob in `backups` namespace)
- **Strategy**: Recreate (RWO PVC for SQLite -- cannot use RollingUpdate)
- **Pre-deploy backup**: `kubectl exec -n atauth deploy/atauth -- cp /app/data/gateway.db /app/data/gateway.db.backup`
- **Rollback**: `kubectl rollout undo deployment/atauth -n atauth` (10 revisions kept)

### CI/CD (Gitea Actions)
- **Workflow**: `.gitea/workflows/deploy.yml`
- **Pipeline**: test (typecheck + lint + vitest) -> build Docker -> push to DO registry -> deploy
- **Runner**: act_runner v0.2.11 on pv4 LXC 111 (labels: `ubuntu-latest`, `host`)
- **Known issue**: `needs` job scheduling can stall. Fix: restart Gitea then act_runner on LXC 111

### Deployment Process (Manual Fallback)
```bash
# Build and push (from repo root, use unique tag to avoid k8s image caching)
TAG=$(git rev-parse --short HEAD)
docker build --platform linux/amd64 \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:latest \
  gateway/
docker push registry.digitalocean.com/ghostmesh-registry/atauth:$TAG
docker push registry.digitalocean.com/ghostmesh-registry/atauth:latest

# Deploy with specific tag (avoids IfNotPresent caching of :latest)
kubectl set image deployment/atauth \
  atauth=registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -n atauth
kubectl rollout status deployment/atauth -n atauth --timeout=120s
```

### Local k3s (Suspended)
Previously ran on k3s (Proxmox VMs 321/322). Shut down Feb 12, 2026.
Config preserved in `gateway/k8s/overlays/staging/` and `gateway/k8s/overlays/production/`.

## Admin Access

### Admin Dashboard (Web UI)
- **URL**: `https://apricot.workingtitle.zip/admin/login`
- **Auth**: Admin token from Vaultwarden (sets `_atauth_admin` cookie, 24h TTL)
- **Pages**: Overview, OIDC Clients, Setup Wizard, Origins, Access Rules, Sessions, Proxy Setup, Access Check Tool
- **CSRF**: All forms include HMAC-signed hidden tokens (1h validity)

### Admin Token
The admin token is stored in **Vaultwarden**:
- **URL**: https://vaultwarden.cloudforest-basilisk.ts.net
- **Location**: `ATAuth` folder -> `Admin Token - Staging` or `Admin Token - Production`
- **k8s secret**: `atauth-secrets` key `ATAUTH_ADMIN_TOKEN` in namespace `atauth`

### Using Admin API
```bash
# Set token from Vaultwarden (or from k8s secret)
export ADMIN_TOKEN="<token-from-vaultwarden>"

# List OIDC clients
curl -s "https://apricot.workingtitle.zip/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# List proxy origins
curl -s "https://apricot.workingtitle.zip/admin/proxy/origins" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# List access rules
curl -s "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Create access rule (allow a specific DID)
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"allow","subject_type":"did","subject_value":"did:plc:abc123"}'

# Create access rule (allow all handles on a PDS domain)
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"allow","subject_type":"handle_pattern","subject_value":"*.arcnode.xyz"}'

# Dry-run access check
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access/check" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"did":"did:plc:abc123","handle":"user.bsky.social","origin":"https://search.arcnode.xyz"}'
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

## Forward-Auth Proxy

### Access Control Model
- **Table**: `proxy_access_rules` in SQLite
- **Default**: No rules = open access (backward compatible). First rule triggers default-deny.
- **Deny overrides allow**: Deny rules always win regardless of order
- **Per-origin + global**: Rules can target a specific origin (`origin_id`) or apply globally (`origin_id = NULL`)

**Evaluation order**:
1. Deny rules (per-origin + global) -- if any match, reject
2. Per-origin allow rules -- if any match, allow
3. Global allow rules -- if any match, allow
4. No match -- deny

**Handle pattern matching**: `*` = all, `*.arcnode.xyz` = suffix match, `bkb.arcnode.xyz` = exact

### Cookie Types (HMAC-SHA256 signed, `typ` discriminator prevents confusion)
| Cookie | Purpose | TTL |
|--------|---------|-----|
| `_atauth_session` | OAuth flow session state | configurable |
| `_atauth_proxy` | Proxy auth for protected services | `SESSION_TTL` (default 7 days) |
| `_atauth_admin` | Admin dashboard session | 24 hours |

### Key Files
| File | Purpose |
|------|---------|
| `src/routes/proxy-auth.ts` | Forward-auth routes (`/auth/verify`, `/auth/login`, `/auth/callback`) + `enforceAccess` |
| `src/routes/oidc/authorize.ts` | OIDC authorization endpoint + AT Protocol OAuth callback |
| `src/routes/oidc/token.ts` | OIDC token exchange (auth_code + refresh_token grants) |
| `src/routes/oidc/userinfo.ts` | OIDC userinfo endpoint (DID-to-handle resolution) |
| `src/routes/oidc/revoke.ts` | OIDC token revocation |
| `src/utils/proxy-auth.ts` | Cookie create/verify, ticket functions, parsing utilities |
| `src/utils/access-check.ts` | Pure `matchHandlePattern` + `checkAccess` functions |
| `src/routes/admin.ts` | Admin API (Bearer + cookie auth), login/logout routes |
| `src/routes/admin-dashboard.ts` | Server-rendered HTML dashboard (all pages + CSRF) |
| `src/data/oidc-presets.ts` | OIDC setup wizard app presets (ABS, Jellyfin, Gitea, etc.) |
| `src/services/database.ts` | SQLite schema, migrations, all DB methods |
| `src/services/oauth.ts` | AT Protocol OAuth client (`generateAuthUrl`, `handleCallback`) |
| `src/types/proxy.ts` | `ProxyAccessRule`, `AccessCheckResult`, proxy config types |

### Important Notes
- **Do NOT restart ATAuth to rotate HMAC secrets** -- use admin API `PUT /admin/apps/:id` with `{"rotate_secret": true}`, then update the downstream service's k8s secret and restart that service only
- **HMAC encoding**: ATAuth signs with `createHmac('sha256', secretString)` (UTF-8). Consumers must use UTF-8 encoding of the hex secret string
- `/auth/verify` is called on every nginx subrequest -- no rate limiting on this endpoint (mounted before rate limit middleware)
- Access denied attempts are logged: `[Proxy ACL] Denied <handle> (<did>): <reason>`

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
kubectl -n atauth logs deploy/atauth --tail=50

# Check secrets
kubectl -n atauth get secret atauth-secrets -o jsonpath='{.data}' | python3 -m json.tool

# Restart
kubectl -n atauth rollout restart deployment/atauth

# Rollback
kubectl -n atauth rollout undo deployment/atauth

# SQLite access
kubectl exec -n atauth deploy/atauth -- sqlite3 /app/data/gateway.db ".tables"
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
- **URL**: `https://audiobookshelf.cloudforest-basilisk.ts.net` (via Tailscale serve → ABS:13378 directly)
- **OIDC**: Configured with ATAuth (`client_id: audiobookshelf`, `authOpenIDAutoRegister: true`)
- **SSH via pv4**: `ssh root@pv4.cloudforest-basilisk.ts.net "pct exec 107 -- <command>"`

### Vaultwarden
- **Location**: LXC 120
- **URL**: https://vaultwarden.cloudforest-basilisk.ts.net

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

### Forward-Auth Proxy Endpoints
| Endpoint | Description |
|----------|-------------|
| `GET /auth/verify` | nginx `auth_request` target (checks proxy cookie) |
| `GET /auth/login` | Initiates AT Protocol OAuth for proxy auth |
| `GET /auth/callback` | OAuth callback, creates proxy session |

### Admin Endpoints (requires Bearer token or `_atauth_admin` cookie)
| Endpoint | Description |
|----------|-------------|
| `GET /admin/login` | Login page (HTML) |
| `POST /admin/login` | Authenticate with admin token, set cookie |
| `GET /admin/logout` | Clear admin cookie |
| `GET /admin/dashboard` | Overview page (HTML) |
| `GET /admin/dashboard/origins` | Manage proxy origins (HTML) |
| `GET /admin/dashboard/access` | Manage access rules (HTML) |
| `GET /admin/dashboard/sessions` | Manage proxy sessions (HTML) |
| `GET /admin/dashboard/check` | Access check tool (HTML) |
| `GET /admin/dashboard/clients` | OIDC client list (HTML) |
| `GET /admin/dashboard/clients/new` | Create OIDC client form (HTML) |
| `GET /admin/dashboard/clients/:id/edit` | Edit OIDC client form (HTML) |
| `GET /admin/dashboard/clients/wizard` | Setup wizard app selection (HTML) |
| `GET /admin/dashboard/clients/wizard/:preset` | Setup wizard configure form (HTML) |
| `GET /admin/dashboard/proxy-wizard` | Forward-auth proxy setup wizard (HTML) |
| `GET /admin/oidc/clients` | List OIDC clients |
| `POST /admin/oidc/clients` | Create OIDC client |
| `GET /admin/oidc/clients/:id` | Get client details |
| `PUT /admin/oidc/clients/:id` | Update client |
| `DELETE /admin/oidc/clients/:id` | Delete client |
| `GET /admin/proxy/origins` | List proxy origins (JSON) |
| `POST /admin/proxy/origins` | Add proxy origin |
| `DELETE /admin/proxy/origins/:id` | Remove proxy origin |
| `GET /admin/proxy/access` | List access rules (JSON) |
| `POST /admin/proxy/access` | Create access rule |
| `DELETE /admin/proxy/access/:id` | Delete access rule |
| `POST /admin/proxy/access/check` | Dry-run access check |
| `GET /admin/proxy/sessions` | List proxy sessions |
| `DELETE /admin/proxy/sessions/:id` | Revoke proxy session |
| `GET /admin/sessions` | List OIDC sessions |
| `GET /admin/keys` | List signing keys |

## Testing

### Test Suite (262 tests)
```bash
cd gateway
npm run test:run     # All tests once
npm run test:unit    # Unit tests only (src/)
npm run test:e2e     # E2E tests only (tests/)
npm run test         # All tests with watch
npm run typecheck    # TypeScript type check
npm run lint         # ESLint
```

### Test Files
| File | Tests | Coverage |
|------|-------|----------|
| `src/utils/access-check.test.ts` | 16 | matchHandlePattern, checkAccess evaluation |
| `src/utils/proxy-auth.test.ts` | 31 | Cookie create/verify, tickets, parsing, admin cookie |
| `src/routes/admin-dashboard.test.ts` | 37 | Dashboard pages, OIDC client CRUD, wizard, proxy wizard, CSRF |
| `src/routes/admin.proxy.test.ts` | 32 | Access rules API, cookie auth login/logout |
| `src/routes/auth.test.ts` | 8 | Auth redirect_uri handling, regression tests |
| `src/routes/proxy-auth.test.ts` | 28 | Forward-auth flows, access control integration |
| `src/services/database.proxy.test.ts` | 23 | Access rules CRUD, cascade delete, partitioning |
| `src/services/oidc/tokens.test.ts` | 20 | OIDC token generation and verification |
| `src/services/oidc/claims.test.ts` | 28 | UserInfo claims building, scope filtering |
| `src/services/oidc/pkce.test.ts` | 17 | PKCE challenge/verifier generation and validation |
| `tests/oidc-flow.test.ts` | 22 | Full OIDC provider E2E flow |

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

### Access rules lock everyone out
**Fix**: Delete all rules to restore open mode:
```bash
kubectl exec -n atauth deploy/atauth -- sqlite3 /app/data/gateway.db "DELETE FROM proxy_access_rules;"
```
Or via admin API: `DELETE /admin/proxy/access/:id` with Bearer token.

### CI pipeline stuck (Gitea Actions)
**Cause**: `needs` job scheduling stalls after test job completes.
**Fix**: Restart Gitea then act_runner on LXC 111:
```bash
ssh root@pv4.cloudforest-basilisk.ts.net "pct exec 111 -- bash -c 'systemctl restart gitea && sleep 5 && systemctl restart act_runner'"
```
If still stuck, deploy manually (see Deployment Process above).

### "invalid_client" on OIDC token exchange

**Cause**: Client secret stored as SHA-256 hash but token endpoint compared raw secret.
**Fixed**: `token.ts` and `revoke.ts` now hash incoming secret before comparison (`3fc67a7`).

### "invalid_grant" redirect_uri mismatch on AT Protocol token exchange

**Cause**: `@atproto/oauth-client` falls back to `clientMetadata.redirect_uris[0]` during token exchange. Authorization used `/oauth/callback` but exchange used `/auth/callback`.
**Fixed**: `authorize.ts` now passes explicit redirect_uri to `handleCallback()` (`3fc67a7`).

### Userinfo returns empty `preferred_username`

**Cause**: `db.getUserMapping()` returns nothing for new OIDC sessions; handle defaulted to empty string.
**Fixed**: `userinfo.ts` resolves DID to handle via `app.bsky.actor.getProfile` API (`3fc67a7`).

### Dockerfile still builds admin-ui stage
The `admin-ui-builder` stage in the Dockerfile builds the old static admin UI. It's now unused (replaced by server-rendered dashboard) but harmless. Can be removed in a future cleanup.

## Pending Work
- **Dependency upgrades**: nodemailer 6->8 (CVE-2025-14874), @simplewebauthn/server 10->13, uuid 9->13, better-sqlite3 11->12
- **Dockerfile cleanup**: Remove `admin-ui-builder` stage and `admin-ui/` static files
- **Stale deployment configs**: `gateway/tekton/` (old Tekton CI), `gateway/helm/` (unused Helm chart), `.github/` (old GitHub Actions) -- can be removed
- **Rotate admin token**: Current placeholder `atauth-admin-token-2026-change-in-production` should be replaced with a proper random token
- **Setup wizard bug**: Double-protocol in redirect_uri when domain input includes `https://` prefix
