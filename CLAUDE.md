# ATAuth - AT Protocol Authentication Library

## Project Structure

```
atauth/
├── src/
│   ├── lib.rs           # Library entry point
│   ├── error.rs         # Error types (AuthError, AuthResult)
│   ├── token.rs         # Token verification (TokenVerifier, TokenPayload)
│   ├── validation.rs    # DID/handle validation
│   ├── rate_limit.rs    # IP-based rate limiting
│   └── session/
│       ├── mod.rs
│       ├── store.rs     # SessionStore trait, SessionManager
│       ├── sqlite.rs    # SQLite implementation
│       └── postgres.rs  # PostgreSQL implementation (placeholder)
├── ts/                  # TypeScript package
│   └── src/
│       ├── index.ts     # Main exports
│       ├── react.ts     # React hooks (useAuthStore)
│       ├── types.ts     # TypeScript types
│       ├── token.ts     # Client-side token utilities
│       ├── storage.ts   # Browser storage utilities
│       └── oauth.ts     # OAuth flow utilities
├── examples/
│   ├── basic_verification.rs
│   └── with_session_store.rs
├── Cargo.toml
└── README.md
```

## Key Components

### Rust Library

- **TokenVerifier**: HMAC-SHA256 token verification with constant-time comparison
- **TokenPayload**: Decoded token with DID, handle, user_id, expiration
- **SessionManager**: High-level session CRUD operations
- **SessionStore trait**: Implement for custom backends (Redis, etc.)
- **RateLimiter**: IP-based auth attempt limiting

### TypeScript Package

- **decodeToken()**: Client-side token decoding (NOT verification)
- **handleCallback()**: OAuth callback processing
- **useAuthStore()**: Zustand-based React hook

## Features

- `default` = `session-sqlite`
- `session-sqlite` - SQLite session backend
- `session-postgres` - PostgreSQL session backend (WIP)
- `rate-limit` - IP-based rate limiting
- `full` - All features

## Build Commands

```bash
# Rust
cargo build
cargo test
cargo run --example basic_verification
cargo run --example with_session_store --features session-sqlite

# TypeScript
cd ts && npm install && npm run build
```

## Security Notes

- Server-side verification required (client decoding is display-only)
- Constant-time comparison prevents timing attacks
- Rate limiting should be enabled in production
