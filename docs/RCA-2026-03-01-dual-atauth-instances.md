# Root Cause Analysis: Dual ATAuth Instances & PDS Server Version Drift (2026-03-01)

## Incident

Blog authentication flow (`blog.arcnode.xyz`) failed with "OAuth state not found or expired" after PDS OAuth completed successfully. Investigation revealed a second undocumented atauth instance on the PDS Hetzner server running v1.0.0 (3+ months behind production v2.2.0). Attempted fix temporarily broke authentication for all apps using the production K8s atauth.

**Duration**: ~3 hours active debugging
**Impact**:
- Blog login broken (original issue)
- ~10 minute outage for all apps using K8s atauth (mspdesk, search, etc.) due to incorrect tunnel reroute
- PDS server running atauth v1.0.0 without passkey, proxy auth, OIDC, or admin dashboard features
**Severity**: High (P2) — partial auth outage, undocumented infrastructure drift

## Timeline

1. Blog login flow completed PDS OAuth but atauth returned "OAuth state not found"
2. Traced root cause: blog server-side called local atauth (`172.17.0.1:3100` on PDS server) for `/auth/init`, creating state locally. But PDS redirected browser to `apricot.workingtitle.zip/auth/callback` (K8s atauth) which had no knowledge of that state.
3. **Mistake**: Rerouted `apricot.workingtitle.zip` tunnel from K8s atauth to PDS server atauth — immediately broke all apps (mspdesk, search, etc.) that use K8s atauth with different HMAC secrets and app registrations.
4. Reverted tunnel within ~10 minutes.
5. **Fix**: Created `atauth.arcnode.xyz` as a separate public URL for the PDS server's atauth instance, keeping `apricot.workingtitle.zip` pointed at K8s.
6. Discovered PDS server was running atauth v1.0.0 (Dec 2025 image) while K8s was running v2.2.0 (Feb 2026). Built v2.2.0 from source and deployed.

## Root Causes

### 1. Undocumented second atauth instance

The PDS Hetzner server (`46.224.33.19`) had atauth deployed at `/opt/atauth/` using Docker image `ghcr.io/cache8063/atauth-gateway:latest` (v1.0.0, built Dec 11 2025). This instance was:
- Not documented in any infrastructure docs
- Not tracked in the Cloudflare tunnel config
- Running a version 3+ months behind production
- Had its own separate SQLite database with its own app registrations and HMAC secrets
- Accessible only via Docker bridge IP (`172.17.0.1:3100`) — no public URL

### 2. Mixed internal/external URL configuration

The atauth instance on the PDS server had:
- `OAUTH_CLIENT_ID=https://apricot.workingtitle.zip/client-metadata.json`
- `OAUTH_REDIRECT_URI=https://apricot.workingtitle.zip/auth/callback`

This meant it told the PDS "I am `apricot.workingtitle.zip`" but it was NOT `apricot.workingtitle.zip`. The PDS would redirect the browser to the real `apricot.workingtitle.zip` (K8s atauth) which had no knowledge of the state created by the PDS server's atauth.

### 3. Stale container image — no CI/CD pipeline to PDS server

The Gitea CI workflow builds images and pushes to `gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway`. But:
- The PDS server was pulling from `ghcr.io/cache8063/atauth-gateway:latest` (different registry)
- No Watchtower or auto-update mechanism for atauth on the PDS server
- The Gitea CI has been failing since Feb 25 (runner issues), so even the Gitea registry image was stale (Dec 2025)
- Had to build v2.2.0 from source directly on the server

### 4. Shared tunnel namespace without isolation

Both atauth instances shared the same `apricot.workingtitle.zip` identity. Changing the tunnel route for one immediately broke the other because:
- Different app registrations (different HMAC secrets)
- Different session stores (SQLite on each)
- Different feature sets (v1.0.0 vs v2.2.0)

## What Data Was At Risk

Checked and confirmed all data survived:
- All 5 registered apps intact (mspdesk, apricot, md, mdeditor, arcnode-blog)
- All HMAC secrets preserved (64 bytes each)
- All sessions preserved (4 active)
- K8s atauth completely untouched
- Docker volume `atauth_atauth-data` used by both old and new containers (same project prefix)

## Fix Applied

1. Created `atauth.arcnode.xyz` DNS + tunnel route → PDS server atauth (`46.224.33.19:3100`)
2. Updated PDS server atauth env:
   - `OAUTH_CLIENT_ID=https://atauth.arcnode.xyz/client-metadata.json`
   - `OAUTH_REDIRECT_URI=https://atauth.arcnode.xyz/auth/callback`
3. Built and deployed atauth v2.2.0 from source on PDS server
4. Enabled passkey (RP ID: `atauth.arcnode.xyz`), forward-auth proxy
5. Updated blog to use atauth proxy login flow (no more client-side callback delay)
6. K8s atauth (`apricot.workingtitle.zip`) left completely untouched
7. Fixed PDS nginx `Sec-Fetch-Mode` header — PDS started enforcing this header on `/oauth/authorize`, and Cloudflare Tunnel strips it. Added `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document` to the nginx proxy config alongside the existing `Sec-Fetch-Site: cross-site`. This was breaking both search.arcnode.xyz (K8s atauth) and blog.arcnode.xyz (PDS atauth) since both OAuth flows go through the same PDS.
8. Cleaned up stale PDS atauth app registrations — removed duplicate `mdeditor` (same product as `md`), stale `mspdesk` and `apricot` entries that only belong on K8s instance

## Current State (Post-Fix)

| Instance | URL | Version | Apps |
|----------|-----|---------|------|
| K8s (DO) | `apricot.workingtitle.zip` | v2.2.0 | search, mspdesk, others |
| PDS (Hetzner) | `atauth.arcnode.xyz` | v2.2.0 | arcnode-blog, md |

**Note**: Consolidation target is the K8s instance (`apricot.workingtitle.zip`). Once kubeconfig access is available, migrate PDS instance apps to K8s and decommission the PDS sidecar.

## Prevention

### Immediate

1. **Document all atauth instances** — Update infrastructure overview with both instances, their URLs, versions, and which apps use which
2. **Each instance MUST have its own unique public URL** — Never configure `OAUTH_CLIENT_ID`/`OAUTH_REDIRECT_URI` pointing to a different instance
3. **Add version endpoint** — `GET /version` returning build commit and version to quickly identify running versions

### Short-term

4. **Fix Gitea CI pipeline** — Runner has been broken since Feb 25. Fix it so images auto-build on push
5. **Add Watchtower or auto-pull** for atauth on PDS server to track Gitea registry
6. **Consolidate to single atauth instance** — Both instances have diverged data. Pick one as source of truth and migrate (see cleanup task below)

### Long-term

7. **Migrate atauth to dedicated instance** — Currently running as a sidecar on the PDS server. Should be its own container/VM with proper CI/CD, monitoring, and backup
8. **Infrastructure-as-code** — Tunnel routes, DNS, and service configs should be in version control, not manually configured
9. **Add health monitoring** — Alert if any atauth instance returns non-200 or version mismatch

## Cleanup Task

Migrate atauth to a dedicated instance off the PDS server. This was identified as necessary during this incident. Track in project TODO.

## Files Changed

- `/opt/atauth/.env` (PDS server) — Updated OAUTH_CLIENT_ID/REDIRECT_URI to atauth.arcnode.xyz
- `/opt/atauth/docker-compose.yml` (PDS server) — Switched from ghcr.io to locally built v2.2.0 image
- `/pds/nginx/nginx.conf` (PDS server) — Added `Sec-Fetch-Mode` and `Sec-Fetch-Dest` headers to `/oauth/authorize` location
- Cloudflare tunnel — Added `atauth.arcnode.xyz` ingress rule
- `arcnode-blog/src/lib/auth.ts` — Rewrote to use proxy auth flow
- `arcnode-blog/src/pages/write.astro` — Redirect to atauth proxy login instead of inline form
- `arcnode-blog/src/pages/api/publish.ts` — Use session cookies instead of HMAC token
- Deleted: `arcnode-blog/src/pages/api/login.ts`, `api/session.ts`, `auth/callback.astro`
