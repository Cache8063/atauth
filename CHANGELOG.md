# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-03-09

### Added

- Passkey login support for forward-auth proxy flow (previously only available in OIDC flow)
- New endpoint `POST /auth/proxy/passkey` for WebAuthn authentication in proxy-auth
- Passkey button and WebAuthn JavaScript on proxy login page (feature-detected)
- GitHub Actions CI workflow for the FOSS repository

### Security

- MFA verify endpoints (`/auth/mfa/totp/verify`, `/auth/mfa/backup-codes/verify`) now require authentication; DID comes from session, not request body
- Session expiry enforced at the database query level (`getSession()` checks `expires_at`)
- OIDC logout redirect validation uses origin comparison instead of prefix matching (prevents open redirect)
- PKCE `plain` method rejected; only `S256` accepted with constant-time comparison
- Empty DID guard in OIDC token endpoint prevents minting tokens for unauthenticated authorization codes
- Handle format validation in OIDC authorize endpoint
- `trust proxy` configured for correct client IP behind reverse proxies
- `user_id` NaN validation in auth link endpoint

### Changed

- Removed `uuid` package dependency (replaced with `crypto.randomUUID()`)
- Test suite expanded to 404 tests

## [2.2.0] - 2026-02-24

### Added

- 10 new OIDC setup wizard presets: Paperless-ngx, Vaultwarden, Miniflux, Mattermost, Vikunja, Plane, GoToSocial, Stirling-PDF, Tandoor Recipes, FreshRSS
- Development guide (CLAUDE.md) with project structure, testing patterns, and common gotchas
- Unit tests for OIDC revocation, logout, userinfo, passkey service, session management, token verification, rate limiting, HMAC utilities, and error handling
- Audit log for all admin operations with 90-day retention cleanup
- `GET /admin/audit-log` endpoint for viewing admin activity

### Changed

- Passkey registration now requires discoverable credentials (`residentKey: 'required'`)
- Rate limit increased from 10 to 30 requests per window
- Test suite expanded to 394 tests across 22 test files (~56% statement coverage)
- Request body size limited to 16kb (JSON and URL-encoded)

### Fixed

- Forward-auth user profile: `x-forwarded-proto` header handling for correct protocol detection
- Email removal endpoint validates email format before processing
- Proxy auth handle validation rejects malformed handles
- CORS startup validation rejects wildcard origin with credentials mode

## [2.1.0] - 2026-02-24

### Added

- User profile page at `/auth/profile` with passkey registration, passkey management (rename/delete), and active session management (view/revoke)
- Forward-auth session cookie authentication for passkey API routes (enables profile page WebAuthn registration)

### Changed

- Login page theme: dark mode, no emojis, gradient accent (blue-violet), matching admin dashboard aesthetic
- Both OIDC and forward-auth login pages share the new dark theme
- Passkey button text simplified to "Sign in with passkey" with SVG key icon
- Brand text "ATAuth" replaces emoji lock logo

## [2.0.3] - 2026-02-23

### Added

- Passkey login on the OIDC authorize page: users with a registered passkey can now sign in with biometrics or a security key, skipping the Bluesky OAuth flow entirely
- New endpoint `POST /oauth/authorize/passkey` completes the OIDC authorization code flow via WebAuthn
- Login page shows "Sign in with a passkey" button when passkeys are enabled (feature-detected; hidden if browser lacks WebAuthn support)
- Tests for passkey authorize flow (8 new tests)

## [2.0.2] - 2026-02-23

### Security

- Removed hardcoded fallback secrets from config; OIDC_KEY_SECRET, MFA_ENCRYPTION_KEY, and FORWARD_AUTH_SESSION_SECRET are now required when their features are enabled
- Fixed XSS in OIDC login page: all user-controlled values (clientName, state, authCode, errorMessage) are now HTML-escaped
- Client secrets no longer appear in URL query parameters; uses one-time flash tokens instead
- Updated nodemailer from v6 to v7 (SES transport security fix)
- Updated docker-compose.yaml to use required variable syntax (`${VAR:?msg}`) for secrets
- Updated .env.example with all current configuration options

## [2.0.1] - 2026-02-23

### Fixed

- Setup wizard double-protocol bug: entering `https://abs.example.com` in domain field no longer produces `https://https://abs.example.com/...` in redirect URIs

### Added

- Gitea OIDC client registration (client_id: `gitea`, PKCE disabled for compatibility)
- Regression test for wizard domain protocol stripping

### Removed

- `gateway/admin-ui/` -- old React SPA (replaced by server-rendered dashboard)
- `gateway/tekton/` -- old Tekton CI for suspended k3s
- `gateway/helm/` -- unused Helm chart
- `gateway/k8s/` -- old k3s kustomize manifests
- `gateway/.gitea/workflows/build.yaml` -- stale k3s deploy workflow
- `.github/` -- GitHub Actions and issue templates (repo is on Gitea)
- Dockerfile `admin-ui-builder` stage (was a no-op after admin-ui removal)

### Changed

- README.md: rewritten for OIDC provider reality (removed stale Rust/TS library references)
- docs/HOMELAB.md: updated for OIDC setup wizard workflow

## [2.0.0] - 2026-02-22

### Added

- **OIDC Provider**: Full OpenID Connect provider using AT Protocol OAuth as identity source
  - Authorization endpoint with PKCE support
  - Token endpoint (authorization_code + refresh_token grants)
  - UserInfo endpoint with DID-to-handle resolution via AT Protocol API
  - Token revocation endpoint
  - JWKS endpoint with ES256 key rotation
  - Discovery document (`/.well-known/openid-configuration`)
- **Forward-Auth SSO Proxy**: nginx `auth_request` based single sign-on for arbitrary services
  - Per-user DID and handle pattern access control rules
  - Deny-overrides evaluation model
  - Per-origin and global rule scoping
  - HMAC-SHA256 signed session cookies with `typ` discriminator
  - Ticket-based exchange for X-Auth-DID/X-Auth-Handle headers
- **Admin Dashboard**: Server-rendered HTML admin UI replacing static React SPA
  - OIDC client management (list, create, edit, delete, secret rotation)
  - Setup wizard with presets for 10 common self-hosted apps (Audiobookshelf, Jellyfin, Nextcloud, Gitea, Immich, Grafana, WikiJS, Portainer, Outline, Mealie)
  - Forward-auth proxy quick setup wizard with nginx/k8s config snippet generation
  - Proxy origin management, access rule management, session management
  - Access check dry-run tool
  - HMAC-signed CSRF tokens on all forms
  - Cookie-based auth (24h TTL) alongside Bearer token auth
- **CI/CD**: GitHub Actions pipeline (test on push)

### Changed

- **Infrastructure**: Docker Compose and Kubernetes deployment support
- **Test suite**: Expanded from ~50 to 262 tests across 11 test files

### Fixed

- OIDC token endpoint: hash incoming client secret before comparing against stored SHA-256 hash
- OIDC authorize: pass explicit redirect_uri to AT Protocol OAuth callback (prevents `@atproto/oauth-client` fallback mismatch)
- OIDC userinfo: resolve DID to handle via `app.bsky.actor.getProfile` when no cached mapping exists
- Legacy `/auth/init`: separate OAuth redirect_uri from downstream app callback URL
- Register OIDC and forward-auth callback URIs in NodeOAuthClient metadata

### Security

- Client secrets stored as SHA-256 hashes (not plaintext)
- Constant-time comparison for all secret verification
- PKCE required for OIDC clients (configurable per-client)
- Access control deny-overrides: deny rules always win regardless of order

## [1.3.0] - 2025-12-15

### Changed

- **Express 5**: Migrated gateway from Express 4 to Express 5
- **ESLint 9**: Migrated to ESLint 9 flat config with typescript-eslint 8
- **Async Error Handling**: Route handlers now use `throw` pattern instead of try/catch blocks
- Added `HttpError` class and `httpError` factory functions for cleaner error handling

### Updated Dependencies

- `express`: 4.18.2 -> 5.0.0
- `helmet`: 7.1.0 -> 8.0.0
- `@types/express`: 4.17.21 -> 5.0.0
- `eslint`: 8.56.0 -> 9.0.0
- `typescript-eslint`: 7.0.0 -> 8.0.0
- `@atproto/oauth-client-node`: 0.1.0 -> 0.3.0
- `better-sqlite3`: 11.0.0 -> 11.6.0
- `typescript`: 5.3.0 -> 5.7.0
- `vitest`: 1.0.0 -> 2.0.0
- `@types/node`: 20.10.0 -> 22.0.0

### Improved

- Enabled `projectService` in typescript-eslint for better type-aware linting performance
- Simplified error handling code (~150 lines of boilerplate removed)

## [1.2.0] - 2025-12-14

### Added

- TypeScript library unit tests for token and validation modules
- Security report issue template
- GitHub issue labels (security, rust, typescript, gateway, breaking change, ci/cd)

### Changed

- **BREAKING**: `TokenVerifier::new()` now returns `Result<Self, AuthError>` instead of `Self`
- Minimum HMAC secret key length enforced at 32 bytes (256 bits)
- TypeScript library defaults to `sessionStorage` instead of `localStorage`
- Docker compose binds to localhost only (127.0.0.1) by default

### Security

- Enforce minimum 32-byte secret key for HMAC-SHA256 in Rust library
- Add HTTPS URL validation for production environments in TypeScript
- Add redirect URI validation against registered callbacks in gateway
- Improved token storage security with sessionStorage default

## [1.0.0] - 2025-12-14

### Added

- Initial release
- Rust library for HMAC-SHA256 token verification
- TypeScript/JavaScript library for frontend integration
- React hooks and Zustand store for state management
- OAuth gateway server (Node.js/Express)
- SQLite and PostgreSQL session store backends
- Rate limiting middleware
- DID and handle validation
- Docker support with multi-arch images (amd64/arm64)
- Homelab deployment documentation
- CI/CD with GitHub Actions

### Security

- Constant-time signature comparison
- CSRF protection via cryptographic nonces
- Input validation and sanitization
- Rate limiting on all endpoints

[2.3.0]: https://github.com/Cache8063/atauth/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Cache8063/atauth/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/Cache8063/atauth/compare/v2.0.3...v2.1.0
[2.0.3]: https://github.com/Cache8063/atauth/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/Cache8063/atauth/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/Cache8063/atauth/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Cache8063/atauth/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/Cache8063/atauth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Cache8063/atauth/compare/v1.0.0...v1.2.0
[1.0.0]: https://github.com/Cache8063/atauth/releases/tag/v1.0.0
