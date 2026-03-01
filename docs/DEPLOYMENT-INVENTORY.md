# ATAuth Deployment Inventory

**Last updated**: 2026-03-01

## Single Instance (Consolidated)

### K8s Instance (DigitalOcean)

| Field | Value |
|-------|-------|
| **Public URL** | `https://apricot.workingtitle.zip` |
| **Internal** | `atauth.atauth.svc.cluster.local:3100` |
| **Version** | v2.2.0 |
| **Routing** | Cloudflare Tunnel → K8s service |
| **Image** | `registry.digitalocean.com/ghostmesh-registry/atauth` |
| **Data** | K8s PersistentVolume (SQLite) at `/app/data/gateway.db` |
| **CI/CD** | Gitea Actions → DO registry → kubectl (currently broken as of 2026-02-25) |
| **Kubectl** | `KUBECONFIG=~/.kube/atauth-kubeconfig.yaml kubectl --insecure-skip-tls-verify -n atauth` |
| **Admin Token** | In K8s Secret `atauth-secrets` key `ATAUTH_ADMIN_TOKEN` |

**All apps use this instance.**

### Decommissioned: PDS Server Instance (Hetzner)

Stopped 2026-03-01 after consolidation. Data preserved at Docker volume `atauth_atauth-data` on pds-hetzner.

| Field | Value |
|-------|-------|
| **Former URL** | `https://atauth.arcnode.xyz` (tunnel route still exists, returns 502) |
| **Data backup** | `/var/lib/docker/volumes/atauth_atauth-data/_data/gateway.db` |
| **Config** | `/opt/atauth/.env`, `/opt/atauth/docker-compose.yml` |

## Registered Apps

### Proxy Origins (forward-auth)

| Origin | Name | Notes |
|--------|------|-------|
| `search.arcnode.xyz` | SearXNG | nginx auth_request → K8s atauth |
| `blog.arcnode.xyz` | Arcnode Blog | Redirects to proxy login, validates ticket server-side |

### OIDC Clients

| ID | Name | Redirect URI |
|----|------|-------------|
| `bits-console` | BITS Backup Console | `bits-console.cloudforest-basilisk.ts.net/auth/callback` |
| `gitea` | Gitea/Forgejo | `gitea.cloudforest-basilisk.ts.net/user/oauth2/atauth/callback` |
| `audiobookshelf` | Audiobookshelf | `audiobookshelf.cloudforest-basilisk.ts.net/auth/openid/callback` |
| `mydrawings` | MyDrawings | `rock.workingtitle.zip/api/auth/atproto/callback` |

### Legacy HMAC Apps

| ID | Name | Callback URL |
|----|------|-------------|
| `mspdesk` | MSP-Desk | `tickets.brooksitservices.com/auth/callback` |
| `mdeditor` | Markdown Editor | `md.bkb.cx/api/auth/callback` |

## Critical Rules

1. **Never reroute `apricot.workingtitle.zip`** — All apps depend on this single atauth instance. Rerouting the tunnel will break everything.

2. **PDS nginx must set Sec-Fetch headers for `/oauth/authorize`** — Cloudflare Tunnel strips browser security headers. Config at `/pds/nginx/nginx.conf` on pds-hetzner. Required headers:
   ```nginx
   proxy_set_header Sec-Fetch-Site "cross-site";
   proxy_set_header Sec-Fetch-Mode "navigate";
   proxy_set_header Sec-Fetch-Dest "document";
   ```

3. **HMAC secrets are per-app** — Each registered app has its own HMAC secret. Token verification uses `createHmac('sha256', secretString)` with UTF-8 encoding of the hex secret.

4. **SQLite single-writer** — Do NOT scale beyond 1 replica. PVC is RWO.

## Cloudflare Tunnel Routes

Tunnel: `k3s-pds-tunnel` (`600f069c-4c53-4a59-b1fd-57c5ad09c044`)

| Hostname | Destination | Notes |
|----------|-------------|-------|
| `apricot.workingtitle.zip` | K8s service `atauth:3100` | Primary — DO NOT CHANGE |

`atauth.arcnode.xyz` route and DNS CNAME removed 2026-03-01.

## Kubectl Access

```bash
# Save kubeconfig (shared separately, do not commit)
export KUBECONFIG=~/.kube/atauth-kubeconfig.yaml

# Note: TLS verify fails with DO CA cert, use --insecure-skip-tls-verify
kubectl --insecure-skip-tls-verify -n atauth get pods
kubectl --insecure-skip-tls-verify -n atauth logs deployment/atauth -f
kubectl --insecure-skip-tls-verify -n atauth rollout restart deployment/atauth

# Get admin token
kubectl --insecure-skip-tls-verify -n atauth get secret atauth-secrets \
  -o jsonpath='{.data.ATAUTH_ADMIN_TOKEN}' | base64 -d
```

See `docs/DO-HANDOFF.md` for full operations guide.

## Cleanup TODO

- [ ] Fix Gitea CI pipeline (broken since 2026-02-25)
- [x] Remove stale `atauth.arcnode.xyz` Cloudflare tunnel route + DNS (done 2026-03-01)
- [ ] Remove `/opt/atauth/` directory and Docker volumes from pds-hetzner
- [ ] Add `/version` endpoint to atauth for quick identification
- [ ] Add uptime monitoring
- [x] Consolidate to single K8s atauth instance (done 2026-03-01)
- [x] Decommission PDS atauth sidecar (done 2026-03-01)
- [x] Fix PDS nginx Sec-Fetch headers (done 2026-03-01)
- [x] Remove stale app registrations from PDS instance (done 2026-03-01)
