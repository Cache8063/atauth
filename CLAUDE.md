# ATAuth - AT Protocol OIDC Provider

## Overview
ATAuth is an OpenID Connect (OIDC) Provider that uses AT Protocol OAuth (Bluesky) as the identity source. It also provides a forward-auth SSO proxy for nginx `auth_request`.

## Critical: Domain Configuration

**IMPORTANT**: ATAuth MUST use `workingtitle.zip` domain, NOT `arcnode.xyz`.

Why: The user's PDS is at `arcnode.xyz`. Same registrable domain causes `Sec-Fetch-Site: same-site` which the PDS rejects. Using `workingtitle.zip` makes it `cross-site`.

## Architecture

### OIDC Flow

```
Client App -> ATAuth (OIDC Provider) -> User's PDS (AT Proto OAuth) -> ATAuth -> Client App
```

### Forward-Auth Proxy Flow
```
Browser -> nginx auth_request -> ATAuth /auth/verify -> /auth/login -> AT Proto OAuth -> session cookie
```

- **Stack**: Node.js/Express 5, TypeScript, SQLite (better-sqlite3)
- **Tokens**: ES256 JWTs (OIDC), HMAC-SHA256 cookies (proxy)
- **Admin**: Server-rendered HTML at `/admin/dashboard`

## Deployment

| Setting | Value |
|---------|-------|
| Public URL | `https://auth-staging.workingtitle.zip` |
| Apricot | `https://apricot.workingtitle.zip` (routes `/auth/*`, `/admin/*`) |
| OIDC Issuer | `https://apricot.workingtitle.zip` |
| Discovery | `https://apricot.workingtitle.zip/.well-known/openid-configuration` |
| Namespace | `atauth` (DO k8s) |
| Registry | `registry.digitalocean.com/ghostmesh-registry` |
| Storage | SQLite on `do-block-storage` PVC |
| Strategy | Recreate (RWO PVC) |
| CI/CD | `.gitea/workflows/deploy.yml` |

For deployment procedures, rollback, and monitoring: use `/deploy` command.

## Admin

- **Dashboard**: `https://apricot.workingtitle.zip/admin/login`
- **Token**: Vaultwarden -> `ATAuth/Admin Token - Staging`
- For API usage examples: use `/admin-api` command.

## Registered OIDC Clients

| Client ID | Redirect URI | PKCE | Notes |
| --- | --- | --- | --- |
| `audiobookshelf` | `https://audiobookshelf.cloudforest-basilisk.ts.net/auth/openid/callback` | Yes | Tailscale serve |
| `gitea` | `https://gitea.cloudforest-basilisk.ts.net/user/oauth2/atauth/callback` | No | Gitea doesn't send PKCE |

All client secrets in Vaultwarden under `ATAuth/OIDC Clients/<name>`.

## Key Files

| File | Purpose |
|------|---------|
| `src/routes/oidc/authorize.ts` | OIDC authorization + AT Proto OAuth callback |
| `src/routes/oidc/token.ts` | Token exchange (auth_code + refresh_token) |
| `src/routes/oidc/userinfo.ts` | User claims (DID-to-handle resolution) |
| `src/routes/proxy-auth.ts` | Forward-auth routes + `enforceAccess` |
| `src/routes/admin.ts` | Admin API (Bearer + cookie auth) |
| `src/routes/admin-dashboard.ts` | Server-rendered dashboard + CSRF |
| `src/data/oidc-presets.ts` | Setup wizard presets (ABS, Jellyfin, Gitea, etc.) |
| `src/services/database.ts` | SQLite schema, migrations, DB methods |
| `src/services/oauth.ts` | AT Proto OAuth client |
| `src/utils/access-check.ts` | `matchHandlePattern` + `checkAccess` |
| `src/utils/proxy-auth.ts` | Cookie create/verify, tickets, parsing |

## Testing (263 tests)

```bash
cd gateway
npm run test:run     # All tests
npm run typecheck    # TypeScript check
npm run lint         # ESLint
```

11 test files across `src/` (unit) and `tests/` (E2E).

## Important Notes

- **Do NOT restart ATAuth to rotate HMAC secrets** -- use admin API, then restart the downstream service only
- **HMAC encoding**: Both sides must use UTF-8 encoding of the hex secret string
- **OIDC issuer is `apricot.workingtitle.zip`**, not `auth-staging.workingtitle.zip`
- `/auth/verify` is mounted before rate limit middleware (called on every nginx subrequest)
- Client secrets stored as SHA-256 hashes (not plaintext)
- PKCE is per-client configurable (some apps like Gitea don't support it)

For troubleshooting: use `/troubleshoot` command.
