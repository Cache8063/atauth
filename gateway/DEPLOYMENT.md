# ATAuth Gateway Deployment Guide

This guide covers deploying ATAuth Gateway using Docker and Kubernetes.

## Prerequisites

- Docker 20.10+ (for Docker deployment)
- Kubernetes 1.25+ (for K8s deployment)
- kubectl configured for your cluster
- Helm 3.x (optional, for Helm deployment)

## Quick Start with Docker

### Build the Image

```bash
cd gateway
docker build -t atauth-gateway:latest .
```

### Run with Docker

```bash
# Generate secrets
export ADMIN_TOKEN=$(openssl rand -hex 32)
export OIDC_KEY_SECRET=$(openssl rand -hex 32)
export MFA_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Run container
docker run -d \
  --name atauth-gateway \
  -p 3100:3100 \
  -v atauth-data:/app/data \
  -e ADMIN_TOKEN=$ADMIN_TOKEN \
  -e OIDC_KEY_SECRET=$OIDC_KEY_SECRET \
  -e MFA_ENCRYPTION_KEY=$MFA_ENCRYPTION_KEY \
  -e OIDC_ENABLED=true \
  -e OIDC_ISSUER=https://auth.example.com \
  -e OAUTH_CLIENT_ID=https://auth.example.com/client-metadata.json \
  -e OAUTH_REDIRECT_URI=https://auth.example.com/auth/callback \
  -e WEBAUTHN_RP_ID=auth.example.com \
  -e WEBAUTHN_ORIGIN=https://auth.example.com \
  atauth-gateway:latest
```

### Run with Docker Compose

```bash
# Create .env file with secrets
cat > .env << EOF
ADMIN_TOKEN=$(openssl rand -hex 32)
OIDC_KEY_SECRET=$(openssl rand -hex 32)
MFA_ENCRYPTION_KEY=$(openssl rand -hex 32)
EOF

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

## Kubernetes Deployment

### Option 1: Using kubectl (Kustomize)

1. **Update configuration**

   Edit `k8s/configmap.yaml` with your domain settings:
   ```yaml
   OAUTH_CLIENT_ID: "https://your-domain.com/client-metadata.json"
   OIDC_ISSUER: "https://your-domain.com"
   WEBAUTHN_RP_ID: "your-domain.com"
   ```

2. **Generate and update secrets**

   ```bash
   # Generate secrets
   ADMIN_TOKEN=$(openssl rand -hex 32)
   OIDC_KEY_SECRET=$(openssl rand -hex 32)
   MFA_ENCRYPTION_KEY=$(openssl rand -hex 32)

   # Update k8s/secret.yaml with generated values
   ```

3. **Deploy**

   ```bash
   # Apply all resources
   kubectl apply -k k8s/

   # Or apply individually
   kubectl apply -f k8s/namespace.yaml
   kubectl apply -f k8s/configmap.yaml
   kubectl apply -f k8s/secret.yaml
   kubectl apply -f k8s/pvc.yaml
   kubectl apply -f k8s/deployment.yaml
   kubectl apply -f k8s/service.yaml
   kubectl apply -f k8s/ingress.yaml
   ```

4. **Verify deployment**

   ```bash
   kubectl -n atauth get pods
   kubectl -n atauth get svc
   kubectl -n atauth logs -f deployment/atauth-gateway
   ```

### Option 2: Using Helm

1. **Install the chart**

   ```bash
   helm install atauth ./helm/atauth-gateway \
     --namespace atauth \
     --create-namespace \
     --set config.oidc.issuer=https://auth.example.com \
     --set config.oauthClientId=https://auth.example.com/client-metadata.json \
     --set config.oauthRedirectUri=https://auth.example.com/auth/callback \
     --set config.passkey.rpId=auth.example.com \
     --set config.passkey.origin=https://auth.example.com \
     --set secrets.adminToken=$(openssl rand -hex 32) \
     --set secrets.oidcKeySecret=$(openssl rand -hex 32) \
     --set secrets.mfaEncryptionKey=$(openssl rand -hex 32) \
     --set ingress.enabled=true \
     --set ingress.hosts[0].host=auth.example.com \
     --set ingress.hosts[0].paths[0].path=/ \
     --set ingress.hosts[0].paths[0].pathType=Prefix
   ```

2. **Using a values file**

   Create `my-values.yaml`:
   ```yaml
   config:
     oidc:
       issuer: "https://auth.example.com"
     oauthClientId: "https://auth.example.com/client-metadata.json"
     oauthRedirectUri: "https://auth.example.com/auth/callback"
     passkey:
       rpId: "auth.example.com"
       origin: "https://auth.example.com"

   secrets:
     adminToken: "your-generated-token"
     oidcKeySecret: "your-oidc-secret"
     mfaEncryptionKey: "your-mfa-key"

   ingress:
     enabled: true
     className: traefik  # or nginx
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
     hosts:
       - host: auth.example.com
         paths:
           - path: /
             pathType: Prefix
     tls:
       - secretName: atauth-tls
         hosts:
           - auth.example.com
   ```

   Then install:
   ```bash
   helm install atauth ./helm/atauth-gateway \
     --namespace atauth \
     --create-namespace \
     -f my-values.yaml
   ```

3. **Upgrade**

   ```bash
   helm upgrade atauth ./helm/atauth-gateway \
     --namespace atauth \
     -f my-values.yaml
   ```

## TLS Configuration

### With cert-manager

1. Install cert-manager if not already installed
2. Create a ClusterIssuer for Let's Encrypt
3. Add annotations to Ingress:
   ```yaml
   annotations:
     cert-manager.io/cluster-issuer: letsencrypt-prod
   ```

### With Traefik (k3s default)

```yaml
annotations:
  traefik.ingress.kubernetes.io/router.entrypoints: websecure
  traefik.ingress.kubernetes.io/router.tls: "true"
```

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3100` |
| `HOST` | Server host | `0.0.0.0` |
| `DB_PATH` | SQLite database path | `/app/data/gateway.db` |
| `ADMIN_TOKEN` | Admin API token | Required |
| `OAUTH_CLIENT_ID` | AT Protocol OAuth client ID | Required |
| `OAUTH_REDIRECT_URI` | OAuth callback URL | Required |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | `http://localhost:3000` |
| `OIDC_ENABLED` | Enable OIDC provider | `false` |
| `OIDC_ISSUER` | OIDC issuer URL | Required if OIDC enabled |
| `OIDC_KEY_SECRET` | Encryption key for OIDC keys | Required if OIDC enabled |
| `OIDC_KEY_ALGORITHM` | JWT signing algorithm | `ES256` |
| `PASSKEY_ENABLED` | Enable passkey auth | `true` |
| `WEBAUTHN_RP_NAME` | WebAuthn relying party name | `ATAuth` |
| `WEBAUTHN_RP_ID` | WebAuthn relying party ID | Required |
| `WEBAUTHN_ORIGIN` | WebAuthn expected origin | Required |
| `MFA_ENABLED` | Enable TOTP MFA | `true` |
| `MFA_TOTP_ISSUER` | TOTP issuer name | `ATAuth` |
| `MFA_ENCRYPTION_KEY` | Encryption key for TOTP secrets | Required if MFA enabled |
| `EMAIL_ENABLED` | Enable email verification | `false` |
| `EMAIL_PROVIDER` | Email provider (smtp/resend/sendgrid) | `smtp` |
| `EMAIL_FROM` | From address for emails | Required if email enabled |

## Health Checks

The gateway exposes a health endpoint at `/health`:

```bash
curl http://localhost:3100/health
```

Response:
```json
{
  "status": "ok",
  "service": "atauth-gateway",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Admin UI

The Admin UI is available at `/admin` when the gateway is running. Use your `ADMIN_TOKEN` to authenticate.

## Troubleshooting

### Pod not starting

Check logs:
```bash
kubectl -n atauth logs -f deployment/atauth-gateway
```

### Database permission issues

Ensure the PVC is properly provisioned and the container has write access:
```bash
kubectl -n atauth describe pvc atauth-gateway-data
```

### Ingress not working

Verify Ingress controller is running:
```bash
kubectl get pods -A | grep -E "(traefik|ingress-nginx)"
```

Check Ingress status:
```bash
kubectl -n atauth describe ingress atauth-gateway
```
