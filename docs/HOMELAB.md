# ATAuth Homelab Deployment Guide

ATAuth provides decentralized authentication for your homelab using AT Protocol. Instead of managing passwords, users authenticate with their AT Protocol identity (like `@alice.your-pds.com`).

## Why AT Protocol for Homelab Auth?

| Traditional SSO | ATAuth + AT Protocol |
|----------------|---------------------|
| You manage passwords | PDS manages identity |
| You handle MFA | PDS handles MFA |
| You store credentials | No credentials stored |
| Single point of failure | Decentralized identity |
| Complex setup (LDAP, etc.) | Simple gateway deployment |

**With a self-hosted PDS**, you have:
- Full control over your identity infrastructure
- No external dependencies (works offline)
- Same security model as enterprise OAuth
- Portable identity across the AT Protocol network

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose
- A domain name (e.g., `auth.homelab.local`)
- Reverse proxy with TLS (Caddy, Traefik, or nginx)
- Optional: Your own PDS for full independence

### 2. Deploy the Gateway

```bash
# Clone the repository
git clone https://github.com/Cache8063/atauth.git
cd atauth

# Configure environment
cp .env.example .env

# Generate admin token
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# Edit .env with your domain
nano .env

# Start the gateway
docker compose up -d
```

### 3. Configure Your Domain

Update `.env`:
```env
OAUTH_CLIENT_ID=https://auth.homelab.local/client-metadata.json
OAUTH_REDIRECT_URI=https://auth.homelab.local/auth/callback
CORS_ORIGINS=https://jellyfin.homelab.local,https://nextcloud.homelab.local
```

### 4. Register Your Apps

```bash
# Register Jellyfin
curl -X POST https://auth.homelab.local/admin/apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "jellyfin",
    "name": "Jellyfin Media Server",
    "callback_url": "https://jellyfin.homelab.local/sso/callback"
  }'

# Save the returned hmac_secret for your app's backend
```

## Reverse Proxy Configuration

### Caddy (Recommended)

```caddyfile
auth.homelab.local {
    reverse_proxy atauth:3100
}
```

### Traefik

```yaml
# docker-compose.yml labels
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.atauth.rule=Host(`auth.homelab.local`)"
  - "traefik.http.routers.atauth.entrypoints=websecure"
  - "traefik.http.routers.atauth.tls.certresolver=letsencrypt"
  - "traefik.http.services.atauth.loadbalancer.server.port=3100"
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name auth.homelab.local;

    ssl_certificate /etc/ssl/certs/auth.homelab.local.crt;
    ssl_certificate_key /etc/ssl/private/auth.homelab.local.key;

    location / {
        proxy_pass http://atauth:3100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Self-Hosted PDS Setup

For complete independence from Bluesky, run your own PDS:

```yaml
# docker-compose.pds.yml
services:
  pds:
    image: ghcr.io/bluesky-social/pds:latest
    environment:
      - PDS_HOSTNAME=pds.homelab.local
      - PDS_JWT_SECRET=your-jwt-secret
      - PDS_ADMIN_PASSWORD=your-admin-password
      - PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=your-key
      - PDS_DATA_DIRECTORY=/pds
      - PDS_BLOBSTORE_DISK_LOCATION=/pds/blocks
      - PDS_DID_PLC_URL=https://plc.directory
      - PDS_BSKY_APP_VIEW_URL=https://api.bsky.app
      - PDS_BSKY_APP_VIEW_DID=did:web:api.bsky.app
      - PDS_REPORT_SERVICE_URL=https://mod.bsky.app
      - PDS_REPORT_SERVICE_DID=did:plc:ar7c4by46qjdydhdevvrndac
      - PDS_CRAWLERS=https://bsky.network
    volumes:
      - pds-data:/pds
    ports:
      - "3000:3000"
```

Then your users can create accounts like `@alice.pds.homelab.local` and authenticate through ATAuth.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Your Homelab Network                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Jellyfin   │  │  NextCloud   │  │    Gitea     │          │
│  │              │  │              │  │              │          │
│  │  (app_id:    │  │  (app_id:    │  │  (app_id:    │          │
│  │   jellyfin)  │  │   nextcloud) │  │   gitea)     │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│         └─────────────────┼─────────────────┘                   │
│                           │                                     │
│                   ┌───────▼───────┐                            │
│                   │    ATAuth     │                            │
│                   │    Gateway    │                            │
│                   │  (one place)  │                            │
│                   └───────┬───────┘                            │
│                           │                                     │
│                   ┌───────▼───────┐                            │
│                   │  Your PDS or  │                            │
│                   │   Bluesky     │                            │
│                   └───────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

## Integrating Apps

### Generic OAuth Integration

Most apps with OAuth support can use ATAuth:

1. **Register the app** with ATAuth admin API
2. **Configure OAuth** in the app:
   - Authorization URL: `https://auth.homelab.local/auth/init`
   - Callback URL: Your app's callback
3. **Verify tokens** in your app's backend using the HMAC secret

### Token Verification (Backend)

For apps you control, verify tokens server-side:

**Node.js:**
```javascript
import crypto from 'crypto';

function verifyToken(token, secret) {
  const [payloadB64, signature] = token.split('.');
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payloadB64)
    .digest('base64url');

  if (signature !== expected) return null;

  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url'));
  if (payload.exp < Date.now() / 1000) return null;

  return payload; // { did, handle, user_id, app_id, exp }
}
```

**Rust:**
```rust
use atauth::TokenVerifier;

let verifier = TokenVerifier::new(b"your-hmac-secret");
match verifier.verify(token) {
    Ok(payload) => println!("Authenticated: {}", payload.handle),
    Err(e) => println!("Invalid token: {}", e),
}
```

## Security Considerations

1. **Always use TLS** - OAuth requires HTTPS
2. **Protect admin token** - Only use for initial app registration
3. **HMAC secrets** - Store securely, rotate periodically
4. **Rate limiting** - Built-in, but consider additional WAF rules
5. **Network isolation** - Keep ATAuth on a trusted network segment

## Troubleshooting

### OAuth Error: "Client not found"

Your `OAUTH_CLIENT_ID` must be a publicly accessible URL that returns valid client metadata. Verify:
```bash
curl https://auth.homelab.local/client-metadata.json
```

### Users Can't Authenticate

1. Check PDS is reachable from ATAuth container
2. Verify user's handle resolves correctly
3. Check ATAuth logs: `docker compose logs atauth`

### Token Verification Fails

1. Ensure HMAC secret matches between gateway and your app
2. Check token hasn't expired
3. Verify `app_id` matches the registered app

## Updating

```bash
docker compose pull
docker compose up -d
```

## Backup

The gateway stores data in a SQLite database:
```bash
# Backup
docker compose exec atauth cp /app/data/gateway.db /app/data/gateway.db.backup

# Or backup the volume
docker run --rm -v atauth_atauth-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/atauth-backup.tar.gz -C /data .
```
