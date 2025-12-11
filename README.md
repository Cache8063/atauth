# ATAuth - AT Protocol Authentication Library

A complete, plug-and-play authentication system for AT Protocol (Bluesky) OAuth integration.

## Components

| Component | Description |
|-----------|-------------|
| **[gateway/](gateway/)** | Node.js OAuth gateway server |
| **[src/](src/)** | Rust token verification library |
| **[ts/](ts/)** | TypeScript/React frontend utilities |

## Features

- **OAuth Gateway**: Ready-to-deploy AT Protocol OAuth server
- **Token Verification**: Secure HMAC-SHA256 with constant-time comparison
- **Session Management**: Trait-based storage with SQLite and PostgreSQL backends
- **Rate Limiting**: IP-based rate limiting with configurable thresholds
- **Input Validation**: DID and handle format validation
- **TypeScript Support**: Full TypeScript/React utilities for frontend integration

## Architecture

```text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Your Frontend  │────▶│  ATAuth Gateway │────▶│   Bluesky PDS   │
│  (React/Next)   │     │   (Node.js)     │     │ (OAuth Provider)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │ token                 │ HMAC secret
        ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Your Backend   │────▶│  Token Verify   │
│  (Rust/Node)    │     │  (atauth lib)   │
└─────────────────┘     └─────────────────┘
```

## Installation

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
atauth = { git = "https://github.com/Cache8063/atauth" }
```

Or with specific features:

```toml
[dependencies]
atauth = { git = "https://github.com/Cache8063/atauth", features = ["session-sqlite", "rate-limit"] }
```

### TypeScript/JavaScript

```bash
npm install atauth
# or
pnpm add atauth
```

## Quick Start

### Rust - Basic Token Verification

```rust
use atauth::{TokenVerifier, TokenPayload};

// Create a verifier with your HMAC secret (shared with auth gateway)
let verifier = TokenVerifier::new(b"your-secret-key");

// Verify a token from the auth gateway
match verifier.verify("token-from-client") {
    Ok(payload) => {
        println!("Authenticated: {} ({})", payload.handle, payload.did);
        // payload.user_id contains app-specific user ID if linked
    }
    Err(e) => {
        eprintln!("Auth failed: {}", e);
    }
}
```

### Rust - With Session Store

```rust
use atauth::{TokenVerifier, SessionManager};
use atauth::session::SqliteSessionStore;

// Setup
let verifier = TokenVerifier::new(b"your-secret-key");
let session_store = SqliteSessionStore::new("sessions.db")?;
let sessions = SessionManager::new(session_store);

// On login
if let Ok(payload) = verifier.verify(token) {
    let session = sessions.create_session(&payload, token.to_string())?;
    // Return session.token to client as session cookie
}

// On subsequent requests
match sessions.validate(session_token) {
    Ok(session) => {
        // User is authenticated
        println!("User: {}", session.handle);
    }
    Err(_) => {
        // Invalid or expired session
    }
}

// On logout
sessions.invalidate(session_token)?;
```

### Rust - With Rate Limiting

```rust
use atauth::rate_limit::{RateLimiter, RateLimiterConfig};
use std::time::Duration;

let config = RateLimiterConfig::default()
    .with_max_attempts(5)
    .with_lockout(Duration::from_secs(300));

let limiter = RateLimiter::new(config);

// Before authentication attempt
let client_ip = "192.168.1.1".parse().unwrap();
if let Err(e) = limiter.check(&client_ip) {
    return Err(e); // Rate limited
}

// After failed attempt
limiter.record_failure(&client_ip);

// After successful attempt
limiter.record_success(&client_ip);
```

### TypeScript - React Integration

```tsx
import { initAuthStore, useAuthStore } from 'atauth/react';

// Initialize once at app startup
initAuthStore({
  gatewayUrl: 'https://auth.example.com',
  appId: 'myapp',
  callbackUrl: 'https://myapp.com/auth/callback',
});

function LoginButton() {
  const { isAuthenticated, user, login, logout, isLoading } = useAuthStore();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (isAuthenticated) {
    return (
      <div>
        <span>Welcome, {user?.handle}!</span>
        <button onClick={logout}>Logout</button>
      </div>
    );
  }

  return <button onClick={() => login()}>Login with Bluesky</button>;
}
```

### TypeScript - Manual Token Handling

```typescript
import {
  decodeToken,
  handleCallback,
  isOAuthCallback,
  redirectToAuth
} from 'atauth';

// Redirect to auth
redirectToAuth({
  gatewayUrl: 'https://auth.example.com',
  appId: 'myapp',
  callbackUrl: window.location.origin + '/callback',
});

// Handle callback page
if (isOAuthCallback()) {
  const result = handleCallback({ gatewayUrl: 'https://auth.example.com' });

  if (result.success) {
    console.log('Logged in as:', result.user?.handle);
    // Redirect to app
    window.location.href = result.returnTo || '/';
  } else {
    console.error('Auth failed:', result.error);
  }
}
```

## Token Format

Tokens follow a JWT-like structure: `base64url(payload).base64url(signature)`

### Payload Structure

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

## API Reference

### Rust

#### `TokenVerifier`

- `new(secret: &[u8])` - Create verifier with HMAC secret
- `from_hex(hex: &str)` - Create from hex-encoded secret
- `from_base64(b64: &str)` - Create from base64-encoded secret
- `verify(token: &str) -> Result<TokenPayload>` - Verify and decode token
- `sign(payload: &TokenPayload) -> Result<String>` - Sign a payload (for gateways)

#### `SessionManager<S: SessionStore>`

- `new(store: S)` - Create manager with store
- `create_session(payload, token)` - Create session from token
- `validate(token)` - Validate and optionally extend session
- `invalidate(token)` - Delete session
- `invalidate_all_for_did(did)` - Delete all sessions for user
- `cleanup()` - Remove expired sessions

#### `RateLimiter`

- `new(config)` - Create with configuration
- `check(ip)` - Check if IP can attempt auth
- `record_failure(ip)` - Record failed attempt
- `record_success(ip)` - Clear on success

### TypeScript

#### Token Utilities

- `decodeToken(token)` - Decode without verification
- `isTokenExpired(payload)` - Check expiration
- `getTokenRemainingSeconds(payload)` - Time until expiry
- `isValidDid(did)` - Validate DID format
- `isValidHandle(handle)` - Validate handle format

#### OAuth Utilities

- `redirectToAuth(config, state?)` - Start OAuth flow
- `handleCallback(config)` - Process callback
- `isOAuthCallback()` - Check if on callback page
- `buildLogoutUrl(config)` - Get logout URL

#### React Hooks

- `useAuthStore()` - Main auth hook
- `useUser()` - Get current user
- `useIsAuthenticated()` - Check auth status
- `useNeedsRefresh()` - Check if token needs refresh

## Security Considerations

- **Server-side verification**: Always verify tokens server-side. Client-side decoding is for display only.
- **Constant-time comparison**: Signature verification uses constant-time comparison to prevent timing attacks.
- **Rate limiting**: Enable rate limiting in production to prevent brute force attacks.
- **HTTPS only**: Always use HTTPS in production.
- **Secure secrets**: Store HMAC secrets securely, never in client code.

## License

MIT
