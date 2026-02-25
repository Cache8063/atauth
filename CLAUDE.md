# ATAuth - AT Protocol OIDC Provider

OIDC Provider using AT Protocol OAuth (Bluesky) as identity source, plus a forward-auth SSO proxy for nginx `auth_request`.

## Development

```bash
cd gateway
npm install
cp .env.example .env    # Fill in required secrets (openssl rand -hex 32)
npm run dev             # tsx watch (hot reload)
```

| Command | Description |
|---------|-------------|
| `npm run dev` | Hot reload (tsx watch) |
| `npm run build` | TypeScript compile |
| `npm run test:run` | Vitest single run |
| `npm run test:run -- --coverage` | With coverage |
| `npm run typecheck` | tsc --noEmit |
| `npm run lint` | ESLint |

## Stack

Express 5, TypeScript, SQLite (better-sqlite3), ES256 JWTs (OIDC), HMAC-SHA256 (gateway/proxy tokens).

## Gotchas

- `req.accepts('json')` matches `*/*` -- use `req.is('json')` to check Content-Type
- `/auth/verify` is mounted before rate limit middleware (called on every nginx subrequest)
- HMAC tokens: both sides must use UTF-8 encoding of the hex secret string
- Proxy cookies use a `typ` discriminator to prevent cross-endpoint replay
- OIDC issuer URL must exactly match what clients configure (including path)
- Client secrets stored as SHA-256 hashes, never plaintext

## Skills

- `/structure` -- project file layout, route mounting order, service dependencies
- `/testing` -- test patterns, mock examples, coverage, helper recipes
- `/patterns` -- error handling, DB access, OIDC presets, auth, HMAC format
