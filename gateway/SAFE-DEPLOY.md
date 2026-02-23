# Safe Deployment Runbook for ATAuth Gateway

## Current Environment

| Setting | Value |
|---------|-------|
| Cluster | DigitalOcean Managed Kubernetes (`storm-dr-cluster`, nyc1) |
| Namespace | `atauth` |
| Registry | `registry.digitalocean.com/ghostmesh-registry` |
| Image | `registry.digitalocean.com/ghostmesh-registry/atauth` |
| URL | `https://auth-staging.workingtitle.zip` |
| Apricot | `https://apricot.workingtitle.zip` |
| Storage | SQLite on `do-block-storage` PVC |
| Strategy | Recreate (RWO PVC -- cannot use RollingUpdate) |

## Pre-Deployment Checklist

- [ ] All tests pass locally (`cd gateway && npx vitest run`)
- [ ] TypeScript compiles clean (`npx tsc --noEmit`)
- [ ] ESLint passes (`npx eslint src/`)
- [ ] Database schema changes are backward compatible
- [ ] New environment variables documented

---

## Automated Deployment (Gitea Actions)

Push to `main` triggers the CI pipeline:

1. **Test** -- typecheck + lint + vitest
2. **Build** -- Docker image with `--platform linux/amd64`
3. **Push** -- to DO registry with commit SHA + `latest` tags
4. **Deploy** -- `kubectl set image` + `kubectl rollout status`

Workflow file: `.gitea/workflows/deploy.yml`

**Known issue**: `needs` job scheduling can stall after test jobs complete.
Fix: restart Gitea then act_runner on LXC 111:
```bash
ssh root@pv4.cloudforest-basilisk.ts.net \
  "pct exec 111 -- bash -c 'systemctl restart gitea && sleep 5 && systemctl restart act_runner'"
```

---

## Manual Deployment (Fallback)

### 1. Pre-deploy backup

```bash
kubectl exec -n atauth deploy/atauth -- cp /app/data/gateway.db /app/data/gateway.db.backup
```

### 2. Build and push

```bash
cd /path/to/atauth

# Use unique tag (commit SHA or descriptive name)
TAG=$(cd gateway && git rev-parse --short HEAD)

docker build --platform linux/amd64 \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:latest \
  gateway/

docker push registry.digitalocean.com/ghostmesh-registry/atauth:$TAG
docker push registry.digitalocean.com/ghostmesh-registry/atauth:latest
```

### 3. Deploy

```bash
# Set the specific image tag (avoids k8s caching issues with :latest)
kubectl set image deployment/atauth \
  atauth=registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -n atauth

kubectl rollout status deployment/atauth -n atauth --timeout=120s
```

### 4. Verify

```bash
# Health check
curl -s https://auth-staging.workingtitle.zip/health | jq .

# OIDC discovery
curl -s https://auth-staging.workingtitle.zip/.well-known/openid-configuration | jq .

# Admin dashboard (requires auth)
curl -s -o /dev/null -w "%{http_code}" https://apricot.workingtitle.zip/admin/login

# Check logs
kubectl -n atauth logs deploy/atauth --tail=20
```

---

## Rollback

### Quick Rollback

```bash
kubectl -n atauth rollout undo deployment/atauth
kubectl -n atauth rollout status deployment/atauth
```

10 revision history is kept by default.

### Rollback with Database Restore

```bash
# Scale down
kubectl -n atauth scale deployment/atauth --replicas=0

# Restore from pre-deploy backup
kubectl -n atauth exec -it <pvc-debug-pod> -- \
  cp /app/data/gateway.db.backup /app/data/gateway.db

# Rollback image and scale up
kubectl -n atauth rollout undo deployment/atauth
kubectl -n atauth scale deployment/atauth --replicas=1
```

### Restore from B2 Backup

Automated backups run every 2 hours (CronJob in `backups` namespace, age-encrypted to Backblaze B2).

---

## Monitoring During Deployment

```bash
# Watch pod status
watch kubectl -n atauth get pods

# Stream logs
kubectl -n atauth logs -f deployment/atauth

# Check events
kubectl -n atauth get events --sort-by='.lastTimestamp'

# Monitor health endpoint
watch -n 5 'curl -s https://auth-staging.workingtitle.zip/health | jq'
```

## Important Notes

- **Image tag caching**: k8s nodes cache `:latest` with `imagePullPolicy: IfNotPresent`. Always use a unique tag (commit SHA or descriptive name) to ensure the new image is pulled.
- **RWO PVC**: Strategy must be `Recreate` since the SQLite PVC is ReadWriteOnce. RollingUpdate will deadlock when the new pod lands on a different node.
- **Domain**: Must use `workingtitle.zip`, NOT `arcnode.xyz` (same-site header issue with PDS).
