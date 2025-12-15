# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2025-12-15

### Changed
- **Express 5**: Migrated gateway from Express 4 to Express 5
- **ESLint 9**: Migrated to ESLint 9 flat config with typescript-eslint 8
- **Async Error Handling**: Route handlers now use `throw` pattern instead of try/catch blocks
- Added `HttpError` class and `httpError` factory functions for cleaner error handling

### Updated Dependencies
- `express`: 4.18.2 → 5.0.0
- `helmet`: 7.1.0 → 8.0.0
- `@types/express`: 4.17.21 → 5.0.0
- `eslint`: 8.56.0 → 9.0.0
- `typescript-eslint`: 7.0.0 → 8.0.0
- `@atproto/oauth-client-node`: 0.1.0 → 0.3.0
- `better-sqlite3`: 11.0.0 → 11.6.0
- `typescript`: 5.3.0 → 5.7.0
- `vitest`: 1.0.0 → 2.0.0
- `@types/node`: 20.10.0 → 22.0.0

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

[1.3.0]: https://github.com/Cache8063/atauth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Cache8063/atauth/compare/v1.0.0...v1.2.0
[1.0.0]: https://github.com/Cache8063/atauth/releases/tag/v1.0.0
