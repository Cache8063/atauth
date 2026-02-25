# Project Structure

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

## Route Mounting Order (index.ts)

1. `/auth/verify` — forward-auth verify (before rate limit)
2. Rate limit middleware
3. `/oauth` — OIDC routes (authorize, token, userinfo, revoke, logout, discovery)
4. `/auth` — legacy HMAC auth + forward-auth login/callback
5. `/admin` — admin API + dashboard
6. `/session` — session management
7. `/token` — HMAC token verify/info
8. `/passkey` — WebAuthn routes
9. `/user` — user profile page
10. `/email` — email verification
11. `/mfa` — TOTP MFA

## Key Service Dependencies

- `DatabaseService` — used by all routes
- `OAuthService` — AT Protocol OAuth, used by auth + OIDC authorize
- `OIDCService` — token signing/verification, used by OIDC routes
- `PasskeyService` — WebAuthn, used by passkey + OIDC authorize routes
- `MFAService` — TOTP, used by MFA routes + admin
- `EmailService` — email sending, used by email routes
