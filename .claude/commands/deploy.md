# ATAuth Deployment

## Automated (Gitea Actions)

Push to `main` triggers: test (typecheck + lint + vitest) -> build Docker -> push to DO registry -> deploy.

Workflow: `.gitea/workflows/deploy.yml`

**Stuck CI**: Restart Gitea then act_runner on LXC 111:
```bash
ssh root@pv4.cloudforest-basilisk.ts.net "pct exec 111 -- bash -c 'systemctl restart gitea && sleep 5 && systemctl restart act_runner'"
```

## Manual Fallback

```bash
# Pre-deploy backup
kubectl exec -n atauth deploy/atauth -- cp /app/data/gateway.db /app/data/gateway.db.backup

# Build with unique tag (avoids k8s image caching with :latest)
cd /Users/bryanbrooks/projects/atauth
TAG=$(cd gateway && git rev-parse --short HEAD)
docker build --platform linux/amd64 \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -t registry.digitalocean.com/ghostmesh-registry/atauth:latest \
  gateway/
docker push registry.digitalocean.com/ghostmesh-registry/atauth:$TAG
docker push registry.digitalocean.com/ghostmesh-registry/atauth:latest

# Deploy
kubectl set image deployment/atauth \
  atauth=registry.digitalocean.com/ghostmesh-registry/atauth:$TAG \
  -n atauth
kubectl rollout status deployment/atauth -n atauth --timeout=120s
```

## Verify

```bash
curl -s https://auth-staging.workingtitle.zip/health | jq .
curl -s https://auth-staging.workingtitle.zip/.well-known/openid-configuration | jq .
curl -s -o /dev/null -w "%{http_code}" https://apricot.workingtitle.zip/admin/login
kubectl -n atauth logs deploy/atauth --tail=20
```

## Rollback

```bash
# Quick rollback (10 revisions kept)
kubectl -n atauth rollout undo deployment/atauth
kubectl -n atauth rollout status deployment/atauth

# With database restore
kubectl -n atauth scale deployment/atauth --replicas=0
# restore gateway.db.backup -> gateway.db via debug pod
kubectl -n atauth rollout undo deployment/atauth
kubectl -n atauth scale deployment/atauth --replicas=1
```

## Monitoring

```bash
watch kubectl -n atauth get pods
kubectl -n atauth logs -f deployment/atauth
kubectl -n atauth get events --sort-by='.lastTimestamp'
```

## Important

- **Image tag caching**: Always use a unique tag (commit SHA). `:latest` uses `IfNotPresent`.
- **RWO PVC**: Strategy must be `Recreate`. RollingUpdate deadlocks on different nodes.
- **Domain**: Must use `workingtitle.zip`, NOT `arcnode.xyz` (same-site header issue).
- **Platform**: Must use `--platform linux/amd64` (DO nodes are amd64).
