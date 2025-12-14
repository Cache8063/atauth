# ATAuth - Decentralized Authentication for AT Protocol

A complete, plug-and-play authentication system using AT Protocol (Bluesky) OAuth. Use it with Bluesky or **run your own PDS** for fully self-hosted, decentralized identity.

## Why ATAuth?

**No more password databases.** Users authenticate with their AT Protocol identity (`@user.bsky.social` or `@alice.your-pds.com`). You verify tokens - the identity provider handles the rest.

| Traditional Auth | ATAuth |
|-----------------|--------|
| You store passwords | PDS manages identity |
| You implement MFA | PDS handles MFA |
| Password resets, account recovery | Not your problem |
| LDAP, Active Directory complexity | Simple token verification |

**With a self-hosted PDS**, ATAuth becomes a fully independent auth system - no different from running your own Keycloak, but with portable, decentralized identities.

## Quick Start (Docker)

```bash
# Clone and configure
git clone https://github.com/Cache8063/atauth.git
cd atauth
cp .env.example .env
echo "ADMIN_TOKEN=$(openssl rand -hex 32)" >> .env

# Start the gateway
docker compose up -d

# Register your first app
curl -X POST http://localhost:3100/admin/apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id": "myapp", "name": "My Application"}'
```

See [docs/HOMELAB.md](docs/HOMELAB.md) for complete deployment guide.

## Components

| Component | Description |
|-----------|-------------|
| **[gateway/](gateway/)** | Node.js OAuth gateway server ([Docker image](https://ghcr.io/cache8063/atauth-gateway)) |
| **[src/](src/)** | Rust token verification library |
| **[ts/](ts/)** | TypeScript/React frontend utilities |

## Architecture

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Your Apps      │────▶│  ATAuth Gateway │────▶│  PDS            │
│  (any stack)    │     │   (one place)   │     │ (yours or bsky) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ HMAC token            │ AT Protocol OAuth
        ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Your Backend   │────▶│  Token Verify   │
│  (Rust/Node/?)  │     │  (atauth lib)   │
└─────────────────┘     └─────────────────┘
```

**The gateway handles the complex OAuth flow once.** Your apps receive simple HMAC-signed tokens to verify.

## Self-Hosted PDS = Full Independence

When you run your own PDS:
- Users get handles like `@alice.your-domain.com`
- No dependency on Bluesky servers
- Works on air-gapped networks
- Same security model as enterprise OAuth
- Your identity, your infrastructure

```yaml
# Add to your docker-compose.yml
services:
  pds:
    image: ghcr.io/bluesky-social/pds:latest
    # ... configure for your domain
```

## Installation

### Docker (Recommended)

```bash
# From GitHub Container Registry
docker pull ghcr.io/cache8063/atauth-gateway:latest

# From Gitea Container Registry (self-hosted mirror)
docker pull your-gitea-instance.example.com/arcnode.xyz/atauth-gateway:latest
```

### Rust Library

```toml
[dependencies]
atauth = { git = "https://github.com/Cache8063/atauth" }
```

### TypeScript/JavaScript

```bash
npm install atauth
```

## Usage

### Gateway - Register Apps

```bash
curl -X POST https://auth.example.com/admin/apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "jellyfin",
    "name": "Jellyfin",
    "callback_url": "https://jellyfin.example.com/sso/callback"
  }'
# Returns: { "hmac_secret": "..." } - save this!
```

### Rust - Verify Tokens

```rust
use atauth::TokenVerifier;

// Secret must be at least 32 bytes (256 bits) for security
let verifier = TokenVerifier::new(b"your-hmac-secret-at-least-32-bytes!")
    .expect("Secret must be at least 32 bytes");

match verifier.verify(token) {
    Ok(payload) => {
        println!("Welcome, {}!", payload.handle);
        // payload.did, payload.user_id, payload.app_id available
    }
    Err(e) => eprintln!("Auth failed: {}", e),
}
```

### TypeScript - Frontend Integration

```tsx
import { useAuthStore } from 'atauth/react';

function LoginButton() {
  const { isAuthenticated, user, login, logout } = useAuthStore();

  if (isAuthenticated) {
    return (
      <>
        <span>Welcome, {user?.handle}!</span>
        <button onClick={logout}>Logout</button>
      </>
    );
  }

  return <button onClick={login}>Login with AT Protocol</button>;
}
```

### Node.js - Verify Tokens

```javascript
import crypto from 'crypto';

function verifyToken(token, secret) {
  const [payloadB64, signature] = token.split('.');
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payloadB64)
    .digest('base64url');

  // Constant-time comparison
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }

  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url'));
  return payload.exp > Date.now() / 1000 ? payload : null;
}
```

## Features

- **Multi-App Support**: One gateway serves all your apps with isolated secrets
- **Rate Limiting**: Built-in IP-based rate limiting (configurable)
- **Session Management**: SQLite or PostgreSQL session stores
- **Security Hardened**: Constant-time comparison, CSRF protection, secure token transport
- **Docker Ready**: Multi-arch images (amd64/arm64)
- **Homelab Friendly**: Works with Traefik, Caddy, nginx

## Token Format

Simple HMAC-signed tokens (not full JWT):

```
base64url(payload).base64url(hmac_sha256(payload, secret))
```

Payload:
```json
{
  "did": "did:plc:abc123...",
  "handle": "user.bsky.social",
  "user_id": 42,
  "app_id": "myapp",
  "iat": 1699900000,
  "exp": 1699903600,
  "nonce": "random-string"
}
```

## Documentation

- [Homelab Deployment Guide](docs/HOMELAB.md) - Docker, reverse proxy configs, self-hosted PDS
- [Security Policy](SECURITY.md) - Reporting vulnerabilities
- [Contributing](CONTRIBUTING.md) - How to contribute

## Use Cases

- **Homelab SSO**: Single sign-on for Jellyfin, NextCloud, Gitea, etc.
- **Multi-tenant Apps**: Users bring their own identity
- **AT Protocol Apps**: Games, social apps, tools for the ATmosphere
- **Enterprise**: Self-hosted PDS for internal identity

## Security

- HMAC-SHA256 with constant-time verification
- Rate limiting on all endpoints
- CSRF protection via cryptographic nonces
- Tokens in URL fragments (not query params)
- Sanitized error responses

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT
