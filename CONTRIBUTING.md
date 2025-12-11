# Contributing to ATAuth

Thank you for your interest in contributing to ATAuth! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Submit a pull request

## Development Setup

### Rust Library

```bash
# Build the library
cargo build

# Run tests
cargo test

# Run examples
cargo run --example basic_verification
cargo run --example with_session_store --features session-sqlite
```

### TypeScript Package

```bash
cd ts
npm install
npm run build
npm test
```

### Gateway Server

```bash
cd gateway
npm install
cp .env.example .env
# Edit .env with your configuration
npm run dev
```

## Code Style

### Rust

- Follow standard Rust formatting (`cargo fmt`)
- Run clippy for linting (`cargo clippy`)
- Write doc comments for public APIs
- Add tests for new functionality

### TypeScript

- Use TypeScript strict mode
- Follow ESLint rules (`npm run lint`)
- Write JSDoc comments for exported functions
- Add tests for new functionality

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
- Environment details (OS, Rust/Node version)
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
