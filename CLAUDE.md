# ATAuth - Development Guide

## Overview

ATAuth is an OIDC Provider that uses AT Protocol OAuth (Bluesky) as the identity source. It also provides a forward-auth SSO proxy for nginx `auth_request`.

## Project Structure

```
gateway/
  src/
    index.ts                    # Express app setup, middleware, route mounting
    config.ts                   # Environment config with validation
    routes/
      auth.ts                   # Legacy HMAC auth flow (/auth/init, /auth/callback)
      admin.ts                  # Admin API (Bearer + cookie auth)
      admin-dashboard.ts        # Server-rendered admin UI + CSRF
      session.ts                # Session conflict detection/resolution
      token.ts                  # HMAC token verify/info
      passkey.ts                # WebAuthn registration/authentication routes
      user-profile.ts           # User profile page (passkey + session management)
      proxy-auth.ts             # Forward-auth routes + enforceAccess
      email.ts                  # Email verification routes
      mfa.ts                    # TOTP MFA routes
      oidc/
        index.ts                # OIDC route aggregator
        authorize.ts            # OIDC authorization + AT Proto OAuth callback
        token.ts                # Token exchange (auth_code + refresh_token)
        userinfo.ts             # User claims (DID-to-handle resolution)
        revoke.ts               # Token revocation (RFC 7009)
        logout.ts               # End session endpoint
        discovery.ts            # .well-known/openid-configuration + JWKS
    services/
      database.ts               # SQLite schema, migrations, all DB methods
      oauth.ts                  # AT Protocol OAuth client (NodeOAuthClient)
      oidc/                     # OIDC token + key services
      passkey.ts                # WebAuthn credential management
      email.ts                  # Email sending (SMTP/SES)
      mfa.ts                    # TOTP generation/verification
    middleware/
      rateLimit.ts              # IP-based rate limiting
    utils/
      hmac.ts                   # HMAC-SHA256 token creation/verification
      errors.ts                 # HttpError class + factory functions
      access-check.ts           # Handle pattern matching + access control
      proxy-auth.ts             # Proxy cookie + ticket helpers
    data/
      oidc-presets.ts           # Setup wizard presets (22 apps)
    types/
      index.ts                  # Shared TypeScript types
  tests/
    oidc-flow.test.ts           # E2E OIDC authorization flow tests
  data/                         # SQLite database (runtime, gitignored)
```

## Development

```bash
cd gateway
npm install
cp .env.example .env            # Fill in required secrets
npm run dev                     # tsx watch (hot reload)
```

### Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Start with hot reload (tsx watch) |
| `npm run build` | TypeScript compile to dist/ |
| `npm start` | Run compiled output |
| `npm test` | Vitest in watch mode |
| `npm run test:run` | Vitest single run |
| `npm run typecheck` | tsc --noEmit |
| `npm run lint` | ESLint |

### Required Environment Variables

Generate secrets with `openssl rand -hex 32`:

- `ADMIN_TOKEN` - Admin API authentication
- `OIDC_KEY_SECRET` - ES256 key derivation (when OIDC enabled)
- `MFA_ENCRYPTION_KEY` - TOTP secret encryption (when MFA enabled)
- `FORWARD_AUTH_SESSION_SECRET` - Proxy session cookies (when forward-auth enabled)

## Testing

**827 tests** across 45 test files. Run with:

```bash
npm run test:run              # All tests
npm run test:run -- --coverage  # With coverage report
```

### Test Patterns

- **Database**: `new DatabaseService(':memory:')` for in-memory SQLite
- **HTTP routes**: supertest with Express app
- **Mocks**: `vi.fn()`, `vi.spyOn()`, `vi.mock()` for module mocks
- **Time**: `vi.useFakeTimers()` / `vi.useRealTimers()` for expiry tests
- **OIDC services**: Mock object with `tokenService` and `keyService` stubs
- **WebAuthn**: Full `vi.mock('@simplewebauthn/server')` at module level

### Test file naming

Tests live alongside source files as `*.test.ts`. E2E tests are in `tests/`.

## Key Technical Details

- **Express 5** with async error handling (throw from route handlers)
- **SQLite** via better-sqlite3 (synchronous API, WAL mode)
- **ES256 JWTs** for OIDC tokens, **HMAC-SHA256** for gateway/proxy tokens
- **Client secrets** stored as SHA-256 hashes, never plaintext
- **PKCE** configurable per OIDC client
- **CSP** with per-request nonces for inline scripts
- **CSRF** via HMAC-signed tokens on all dashboard forms

## Common Patterns

### Error handling

```typescript
import { badRequest, unauthorized, notFound } from '../utils/errors.js';
// Throw from any route handler -- Express 5 catches async throws
throw badRequest('Missing required field');
```

### Database access

```typescript
// All DB methods are synchronous (better-sqlite3)
const app = db.getApp('my-app');
db.upsertApp({ id: 'my-app', name: 'My App', ... });
```

### Adding OIDC presets

Edit `src/data/oidc-presets.ts`. Each preset needs: `id`, `name`, `icon` (SVG), `defaultConfig`, and optional `setup_notes` (markdown).

## Gotchas

- `req.accepts('json')` matches `*/*` -- use `req.is('json')` to check Content-Type
- `/auth/verify` is mounted before rate limit middleware (called on every nginx subrequest)
- HMAC tokens: both sides must use UTF-8 encoding of the hex secret string
- Proxy cookies use a `typ` discriminator to prevent cross-endpoint replay
- OIDC issuer URL must exactly match what clients configure (including path)
