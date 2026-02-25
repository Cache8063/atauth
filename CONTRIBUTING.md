# Contributing to ATAuth

## Development Setup

```bash
cd gateway
npm install
cp .env.example .env   # Fill in required secrets
npm run dev            # Hot reload with tsx watch
```

### Verify Your Changes

```bash
npm run typecheck      # Type checking
npm run lint           # ESLint
npm run test:run       # 394 tests across 22 files
```

### Client Libraries

Rust (`src/`) and TypeScript (`ts/`) client libraries for token verification:

```bash
cargo test             # Rust library
cd ts && npm test      # TypeScript library
```

## Code Style

- TypeScript strict mode, ESLint rules enforced
- Express 5 async error handling (`throw` pattern, no try/catch wrappers)
- Tests live alongside source: `foo.ts` -> `foo.test.ts`
- In-memory SQLite for test isolation

## Pull Requests

1. One feature or fix per PR
2. Add tests for new functionality
3. All CI checks must pass (typecheck, lint, vitest)

## Security

Report vulnerabilities privately -- see [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under MIT.
