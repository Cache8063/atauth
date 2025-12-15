# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.2.0]: https://github.com/Cache8063/atauth/compare/v1.0.0...v1.2.0
[1.0.0]: https://github.com/Cache8063/atauth/releases/tag/v1.0.0
