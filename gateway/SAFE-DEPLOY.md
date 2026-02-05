# Safe Deployment Runbook for ATAuth Gateway

This document outlines the safe deployment procedure to avoid breaking production.

## Deployment Strategy

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Develop   │────▶│   Staging   │────▶│ Production  │
│   (local)   │     │  (k3s)      │     │   (k3s)     │
└─────────────┘     └─────────────┘     └─────────────┘
                          │                    │
                    auth-staging.*       auth.* (existing)
```

## Pre-Deployment Checklist

### Before ANY deployment:

- [ ] All tests pass locally
- [ ] Code reviewed and merged to appropriate branch
- [ ] Database schema changes are backward compatible
- [ ] New environment variables documented

### Before Production deployment:

- [ ] Successfully deployed and tested in staging
- [ ] Backup job completed successfully
- [ ] Rollback procedure reviewed
- [ ] Maintenance window communicated (if needed)

---

## Step-by-Step Deployment

### 1. Deploy to Staging First

```bash
# Build and push staging image
git checkout develop
docker build -t gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway:staging ./gateway
docker push gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway:staging

# Deploy to staging namespace
kubectl apply -k gateway/k8s/overlays/staging

# Verify deployment
kubectl -n atauth-staging rollout status deployment/atauth-gateway-staging
kubectl -n atauth-staging logs -f deployment/atauth-gateway-staging
```

### 2. Test Staging Environment

```bash
# Health check
curl https://auth-staging.cloudforest-basilisk.ts.net/health

# Test OIDC discovery
curl https://auth-staging.cloudforest-basilisk.ts.net/.well-known/openid-configuration

# Test admin UI
open https://auth-staging.cloudforest-basilisk.ts.net/admin

# Run integration tests against staging
# ... your test commands ...
```

### 3. Create Pre-Deployment Backup

```bash
# Trigger backup job
kubectl -n atauth create job --from=cronjob/atauth-gateway-backup pre-deploy-$(date +%Y%m%d%H%M)

# Wait for completion
kubectl -n atauth wait --for=condition=complete job/pre-deploy-$(date +%Y%m%d%H%M) --timeout=120s

# Verify backup exists
kubectl -n atauth exec -it deploy/atauth-gateway -- ls -la /backups/
```

### 4. Deploy to Production

```bash
# Tag the release
git checkout main
git tag v1.x.x
git push origin v1.x.x

# Build production image with version tag
docker build -t gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway:v1.x.x ./gateway
docker push gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway:v1.x.x

# Update production kustomization with new tag
cd gateway/k8s/overlays/production
# Edit kustomization.yaml to use new tag

# Apply with dry-run first
kubectl apply -k . --dry-run=server

# Apply for real
kubectl apply -k .

# Watch rollout
kubectl -n atauth rollout status deployment/atauth-gateway
```

### 5. Verify Production

```bash
# Health check
curl https://auth.cloudforest-basilisk.ts.net/health

# Check logs for errors
kubectl -n atauth logs -f deployment/atauth-gateway --since=5m

# Verify existing sessions still work
# ... test with existing client apps ...
```

---

## Rollback Procedure

### Quick Rollback (< 5 minutes)

```bash
# Rollback to previous deployment
kubectl -n atauth rollout undo deployment/atauth-gateway

# Verify rollback
kubectl -n atauth rollout status deployment/atauth-gateway
```

### Rollback with Database Restore

If the new version corrupted data:

```bash
# 1. Scale down the deployment
kubectl -n atauth scale deployment/atauth-gateway --replicas=0

# 2. Find the backup to restore
kubectl -n atauth exec -it <backup-pod> -- ls -la /backups/

# 3. Restore the database
kubectl -n atauth exec -it <backup-pod> -- sh -c '
  cp /backups/pre-deploy-YYYYMMDD-HHMMSS.db /data/gateway.db
'

# 4. Rollback the deployment
kubectl -n atauth rollout undo deployment/atauth-gateway

# 5. Scale back up
kubectl -n atauth scale deployment/atauth-gateway --replicas=1
```

### Full Disaster Recovery

```bash
# If everything is broken, restore from last known good state:

# 1. Delete the deployment
kubectl -n atauth delete deployment atauth-gateway

# 2. Restore database from backup
# (access the PVC directly or use a debug pod)

# 3. Deploy previous known-good version
kubectl set image deployment/atauth-gateway \
  gateway=gitea.cloudforest-basilisk.ts.net/arcnode.xyz/atauth-gateway:v1.2.0 \
  -n atauth
```

---

## Database Migration Safety

The new version adds these tables (backward compatible):

```sql
-- New tables (won't affect existing functionality)
- oidc_keys
- authorization_codes
- refresh_tokens
- passkey_credentials
- mfa_totp
- mfa_backup_codes
- user_emails
- email_verification_codes

-- Modified tables (new columns with defaults)
- apps: client_type, client_secret, redirect_uris, etc.
```

### Migration is SAFE because:

1. **New tables only** - existing tables unchanged
2. **New columns have defaults** - existing rows work
3. **Legacy mode supported** - old apps use `client_type='legacy'`
4. **No breaking changes to existing API** - `/auth/*` routes unchanged

### To verify schema compatibility:

```bash
# Export current schema
kubectl -n atauth exec deploy/atauth-gateway -- \
  sqlite3 /app/data/gateway.db ".schema" > schema-before.sql

# After deployment, compare
kubectl -n atauth exec deploy/atauth-gateway -- \
  sqlite3 /app/data/gateway.db ".schema" > schema-after.sql

diff schema-before.sql schema-after.sql
```

---

## Monitoring During Deployment

```bash
# Watch pod status
watch kubectl -n atauth get pods

# Stream logs
kubectl -n atauth logs -f deployment/atauth-gateway

# Check events
kubectl -n atauth get events --sort-by='.lastTimestamp'

# Monitor health endpoint
watch -n 5 'curl -s https://auth.cloudforest-basilisk.ts.net/health | jq'
```

---

## Environment URLs

| Environment | URL | Namespace |
|-------------|-----|-----------|
| Staging | https://auth-staging.cloudforest-basilisk.ts.net | atauth-staging |
| Production | https://auth.cloudforest-basilisk.ts.net | atauth |

## Quick Commands Reference

```bash
# Deploy staging
kubectl apply -k gateway/k8s/overlays/staging

# Deploy production
kubectl apply -k gateway/k8s/overlays/production

# Rollback
kubectl -n atauth rollout undo deployment/atauth-gateway

# Check status
kubectl -n atauth get all

# Logs
kubectl -n atauth logs -f deploy/atauth-gateway

# Backup now
kubectl -n atauth create job --from=cronjob/atauth-gateway-backup manual-backup-$(date +%s)
```
