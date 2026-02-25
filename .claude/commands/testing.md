# Testing Guide

394 tests across 22 test files.

## Commands

```bash
cd gateway
npm run test:run                # All tests
npm run test:run -- --coverage  # With coverage report
npm test                        # Watch mode
```

## Test Patterns

### Database
Use in-memory SQLite for isolation:
```typescript
const db = new DatabaseService(':memory:');
afterEach(() => db.close());
```

### HTTP Routes
Use supertest with a minimal Express app:
```typescript
function createTestApp(db: DatabaseService) {
  const app = express();
  app.use(express.json());
  const router = createMyRouter(db);
  app.use('/path', router);
  // Add error handler for HttpError
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.statusCode || 500).json({ error: err.code, message: err.message });
  });
  return app;
}
```

### Mocking
- `vi.fn()` for simple function mocks
- `vi.spyOn(obj, 'method')` for spying on existing methods
- `vi.mock('module')` for full module mocks (hoisted to top of file)

### OIDC Service Mocks
```typescript
function createMockOIDCService(accessTokenClaims: any = null) {
  return {
    tokenService: {
      verifyAccessToken: vi.fn().mockReturnValue(accessTokenClaims),
      verifyIdToken: vi.fn(),
      createTokenResponse: vi.fn(),
    },
    keyService: { getPublicKeySet: vi.fn() },
  } as any;
}
```

### WebAuthn Mocks
Mock the entire `@simplewebauthn/server` module:
```typescript
vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn().mockResolvedValue({ challenge: 'mock' }),
  verifyRegistrationResponse: vi.fn().mockResolvedValue({ verified: true, registrationInfo: { ... } }),
  generateAuthenticationOptions: vi.fn().mockResolvedValue({ challenge: 'mock' }),
  verifyAuthenticationResponse: vi.fn().mockResolvedValue({ verified: true, authenticationInfo: { ... } }),
}));
```

### Time-Dependent Tests
```typescript
vi.useFakeTimers();
vi.setSystemTime(new Date('2026-01-01'));
// ... test expiry logic ...
vi.useRealTimers();
```

### Registering Test Data

OIDC clients (for revoke, logout, token tests):
```typescript
function registerOIDCClient(db: DatabaseService, id = 'test-client', secret = 'test-secret') {
  const secretHash = crypto.createHash('sha256').update(secret).digest('hex');
  db.upsertOIDCClient({
    id, name: 'Test', client_type: 'oidc', hmac_secret: secretHash,
    redirect_uris: ['https://app.example.com/callback'],
    grant_types: ['authorization_code'], allowed_scopes: ['openid', 'profile'],
    token_ttl_seconds: 3600, id_token_ttl_seconds: 3600,
    access_token_ttl_seconds: 3600, refresh_token_ttl_seconds: 86400,
    require_pkce: false, token_endpoint_auth_method: 'client_secret_basic',
  });
}
```

Legacy apps (for session, token tests):
```typescript
function registerApp(db: DatabaseService, id = 'test-app') {
  db.upsertApp({
    id, name: 'Test App', hmac_secret: TEST_SECRET,
    token_ttl_seconds: 3600, callback_url: 'https://app.example.com/callback',
  });
}
```

## File Organization

- Tests live alongside source: `foo.ts` -> `foo.test.ts`
- E2E tests in `tests/` directory
- No test utilities directory -- helpers are defined per test file

## Coverage

Run `npm run test:run -- --coverage` and check the terminal table.
Key areas with room for improvement: passkey routes, OIDC authorize, OIDC token exchange.
