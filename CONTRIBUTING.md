# Contributing to ATAuth

Thank you for your interest in contributing to ATAuth! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Submit a pull request

## Development Setup

### Gateway Server (Primary)

```bash
cd gateway
npm install
cp .env.example .env
# Edit .env with your configuration
npm run dev

# Run tests
npm run test:run

# Type check and lint
npm run typecheck
npm run lint
```

### Rust Library (Legacy)

The `src/` directory contains a Rust HMAC token verification library from v1.x. It is preserved for reference but is not actively maintained. The gateway handles all token operations via OIDC JWTs.

### TypeScript Package (Legacy)

The `ts/` directory contains TypeScript/React frontend utilities from v1.x. It is preserved for reference but is not actively maintained. Use standard OIDC client libraries instead.

## Code Style

### Gateway (TypeScript)

- Use TypeScript strict mode
- Follow ESLint rules (`npm run lint`)
- Write tests for new functionality
- Match existing patterns in the codebase

## Pull Request Guidelines

1. **Keep PRs focused**: One feature or fix per PR
2. **Write clear commit messages**: Describe what and why
3. **Add tests**: Cover new functionality with tests
4. **Update documentation**: Keep README and docs current
5. **Follow existing patterns**: Match the codebase style

## Reporting Issues

When reporting issues, please include:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Node version)
- Relevant logs or error messages

## Feature Requests

Feature requests are welcome! Please:

- Check existing issues first
- Clearly describe the use case
- Explain why this would benefit users

## Security

If you discover a security vulnerability, please report it privately rather than opening a public issue. See SECURITY.md for details.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
