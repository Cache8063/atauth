# ATAuth - DigitalOcean Kubernetes Handoff

This document provides everything you need to connect to and manage the ATAuth deployment on DigitalOcean managed Kubernetes.

## Cluster Overview

| Item | Value |
|------|-------|
| Provider | DigitalOcean Managed Kubernetes |
| Cluster | `do-nyc1-storm-dr-cluster` (nyc1 region) |
| Kubernetes | v1.34.1 |
| Namespace | `atauth` |
| Nodes | 3x worker (4 vCPU, 8GB RAM each) |
| Container registry | `registry.digitalocean.com/ghostmesh-registry` |

## Connecting with kubectl

You will receive a kubeconfig file (`atauth-team-kubeconfig.yaml`) separately. This kubeconfig is scoped to the `atauth` namespace only -- you cannot access other namespaces on the cluster.

### Setup

```bash
# Option 1: Set KUBECONFIG env var
export KUBECONFIG=/path/to/atauth-team-kubeconfig.yaml

# Option 2: Merge into your default config
cp ~/.kube/config ~/.kube/config.backup
KUBECONFIG=~/.kube/config:/path/to/atauth-team-kubeconfig.yaml kubectl config view --merge --flatten > /tmp/merged && mv /tmp/merged ~/.kube/config
kubectl config use-context atauth-team@do-nyc1-storm-dr-cluster
```

### Verify

```bash
kubectl get pods -n atauth
# Should show the atauth pod running

kubectl get deployments -n atauth
# NAME     READY   UP-TO-DATE   AVAILABLE
# atauth   1/1     1            1
```

## What You Have Access To

Your ServiceAccount (`atauth-team`) has full CRUD access within the `atauth` namespace:

- Pods (including logs, exec, port-forward)
- Deployments and ReplicaSets
- Services
- Ingresses
- ConfigMaps
- Secrets
- PersistentVolumeClaims
- Events

You do **not** have access to cluster-scoped resources or other namespaces.

## Current Deployment Architecture

```
                       ┌──────────────────────┐
Internet ──> nginx     │  Ingress (nginx)      │
             ingress ──┤  apricot.workingtitle │
                       │  .zip                 │
                       └──────────┬───────────┘
                                  │
                       ┌──────────▼───────────┐
                       │  Service (ClusterIP)  │
                       │  atauth:3100          │
                       └──────────┬───────────┘
                                  │
                       ┌──────────▼───────────┐
                       │  Deployment           │
                       │  1 replica, Recreate  │
                       │  strategy             │
                       └──────────┬───────────┘
                                  │
                       ┌──────────▼───────────┐
                       │  PVC (1Gi, RWO)       │
                       │  do-block-storage     │
                       │  SQLite DB at         │
                       │  /app/data/gateway.db │
                       └──────────────────────┘
```

### Key Resources

| Resource | Name | Notes |
|----------|------|-------|
| Deployment | `atauth` | 1 replica, `Recreate` strategy (required -- RWO PVC) |
| Service | `atauth` | ClusterIP, port 3100 |
| Ingress | `atauth` | Host: `apricot.workingtitle.zip`, TLS via `atauth-tls` secret |
| PVC | `atauth-data` | 1Gi, `do-block-storage`, holds SQLite DB |
| ConfigMap | `atauth-config` | Non-sensitive env vars (CORS, OIDC issuer, WebAuthn, etc.) |
| Secret | `atauth-secrets` | `ATAUTH_ADMIN_TOKEN`, `ATAUTH_OIDC_KEY_SECRET`, `ATAUTH_FORWARD_AUTH_SESSION_SECRET` |
| Secret | `atauth-tls` | TLS cert/key for the ingress |
| Secret | `registry-ghostmesh-registry` | Docker registry pull credentials |

### Container Image

- Registry: `registry.digitalocean.com/ghostmesh-registry/atauth`
- Tags: short git SHA (e.g., `43d2471`) + `latest`
- Platform: `linux/amd64` (required -- DO nodes are amd64)
- Dockerfile: `gateway/Dockerfile`

### Environment Variables

Sourced from `atauth-config` ConfigMap:

| Env Var | ConfigMap Key | Description |
|---------|---------------|-------------|
| `OAUTH_CLIENT_ID` | `ATAUTH_OAUTH_CLIENT_ID` | AT Protocol OAuth client metadata URL |
| `OAUTH_REDIRECT_URI` | `ATAUTH_OAUTH_REDIRECT_URI` | OAuth callback URL |
| `CORS_ORIGINS` | `ATAUTH_CORS_ORIGINS` | Comma-separated allowed origins |
| `OIDC_ENABLED` | `ATAUTH_OIDC_ENABLED` | Enable OIDC provider |
| `OIDC_ISSUER` | `ATAUTH_OIDC_ISSUER` | OIDC issuer URL |
| `FORWARD_AUTH_ENABLED` | `ATAUTH_FORWARD_AUTH_ENABLED` | Enable nginx forward-auth proxy |
| `FORWARD_AUTH_SESSION_TTL` | `ATAUTH_FORWARD_AUTH_SESSION_TTL` | Session TTL in seconds |
| `FORWARD_AUTH_PROXY_COOKIE_TTL` | `ATAUTH_FORWARD_AUTH_PROXY_COOKIE_TTL` | Proxy cookie TTL in seconds |
| `MFA_ENABLED` | `ATAUTH_MFA_ENABLED` | Enable passkey/WebAuthn MFA |
| `WEBAUTHN_RP_ID` | `ATAUTH_WEBAUTHN_RP_ID` | WebAuthn relying party ID |
| `WEBAUTHN_ORIGIN` | `ATAUTH_WEBAUTHN_ORIGIN` | WebAuthn origin URL |
| `WEBAUTHN_RP_NAME` | `ATAUTH_WEBAUTHN_RP_NAME` | WebAuthn relying party display name |

Sourced from `atauth-secrets` Secret:

| Env Var | Secret Key | Description |
|---------|------------|-------------|
| `ADMIN_TOKEN` | `ATAUTH_ADMIN_TOKEN` | Admin API bearer token |
| `OIDC_KEY_SECRET` | `ATAUTH_OIDC_KEY_SECRET` | OIDC signing key secret |
| `FORWARD_AUTH_SESSION_SECRET` | `ATAUTH_FORWARD_AUTH_SESSION_SECRET` | Session encryption secret |

Hardcoded in deployment spec:

| Env Var | Value |
|---------|-------|
| `PORT` | `3100` |
| `HOST` | `0.0.0.0` |
| `NODE_ENV` | `production` |
| `DB_PATH` | `/app/data/gateway.db` |

## Common Operations

### View logs

```bash
kubectl logs -n atauth deployment/atauth -f
```

### Restart the deployment

```bash
kubectl rollout restart deployment/atauth -n atauth
kubectl rollout status deployment/atauth -n atauth
```

### Deploy a new image

```bash
kubectl set image deployment/atauth atauth=registry.digitalocean.com/ghostmesh-registry/atauth:<tag> -n atauth
kubectl rollout status deployment/atauth -n atauth --timeout=120s
```

### Update config

```bash
# Edit a ConfigMap value
kubectl patch configmap atauth-config -n atauth --type merge \
  -p '{"data":{"ATAUTH_CORS_ORIGINS":"https://apricot.workingtitle.zip,https://new-app.example.com"}}'

# Restart to pick up changes (env vars are read at startup)
kubectl rollout restart deployment/atauth -n atauth
```

### Update secrets

```bash
# Update a secret value (must be base64 encoded)
kubectl patch secret atauth-secrets -n atauth --type merge \
  -p '{"data":{"ATAUTH_ADMIN_TOKEN":"'$(echo -n "new-token-value" | base64)'"}}'

kubectl rollout restart deployment/atauth -n atauth
```

### Port-forward for local access

```bash
kubectl port-forward -n atauth svc/atauth 3100:3100
# ATAuth is now accessible at http://localhost:3100
```

### Shell into the container

```bash
kubectl exec -it -n atauth deployment/atauth -- /bin/sh
```

### Check health

```bash
# Via port-forward
curl http://localhost:3100/health

# Or check readiness probe status
kubectl describe pod -n atauth -l app=atauth | grep -A5 "Conditions:"
```

## CI/CD Pipeline

The existing Gitea Actions workflow (`.gitea/workflows/deploy.yml`) runs on push to `main`:

1. **Test job** (`ubuntu-latest` runner): `npm ci`, typecheck, lint, vitest
2. **Build and deploy job** (`host` runner): Docker build, push to DO registry, `kubectl set image`, rollout status

The pipeline uses these Gitea org-level secrets:
- `DO_REGISTRY_TOKEN` -- DO container registry API token
- `DO_KUBECONFIG` -- base64-encoded kubeconfig for the `ci-deployer` ServiceAccount

## Important Gotchas

1. **Recreate strategy is required.** The PVC is RWO (ReadWriteOnce). RollingUpdate will deadlock if the new pod lands on a different node than the old one.

2. **Domain must be `workingtitle.zip`, not `arcnode.xyz`.** The `arcnode.xyz` domain hosts a PDS (AT Protocol Personal Data Server). Using it for ATAuth causes same-site cookie/header conflicts.

3. **Docker images must target `linux/amd64`.** The DO worker nodes run amd64. ARM images will crash with exec format errors.

4. **HMAC token encoding.** ATAuth signs HMAC tokens with `createHmac('sha256', secretString)` using the UTF-8 encoding of the hex secret. Downstream services verifying tokens must match this encoding.

5. **`req.accepts('json')` matches `*/*`.** Use `req.is('json')` for Content-Type checks in Express routes.

6. **Registry pull secret must exist in namespace.** The `registry-ghostmesh-registry` secret is already present. If you recreate the namespace, you must re-add it or image pulls will fail.

7. **SQLite WAL mode.** The DB runs in WAL mode on DO block storage. Single-writer only -- do not scale beyond 1 replica.

## Live URLs

| URL | Description |
|-----|-------------|
| `https://apricot.workingtitle.zip` | ATAuth gateway (public) |
| `https://apricot.workingtitle.zip/.well-known/openid-configuration` | OIDC discovery |
| `https://apricot.workingtitle.zip/admin/login` | Admin dashboard |
| `https://apricot.workingtitle.zip/health` | Health check endpoint |
