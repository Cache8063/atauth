# Code Patterns

## Error Handling

Express 5 catches async throws. Use the `HttpError` factories:

```typescript
import { badRequest, unauthorized, notFound, forbidden, conflict } from '../utils/errors.js';

// In any route handler -- no try/catch needed
throw badRequest('Missing required field');
throw unauthorized('Token expired');
throw notFound('App not found');
```

The error handler in `index.ts` catches these and returns JSON:
```json
{ "error": "bad_request", "message": "Missing required field" }
```

## Database Access

All DB methods are synchronous (better-sqlite3):

```typescript
// Read
const app = db.getApp('my-app');
const client = db.getOIDCClient('client-id');
const session = db.getSession('session-id');

// Write
db.upsertApp({ id: 'my-app', name: 'My App', hmac_secret: '...', token_ttl_seconds: 3600 });
db.upsertOIDCClient({ id: 'client-id', name: 'Client', ... });
db.createSession({ id: 'uuid', did: 'did:plc:...', handle: '...', app_id: '...', expires_at: new Date() });

// User mappings
db.setUserMapping({ did: 'did:plc:...', app_id: 'my-app', user_id: 1, handle: 'user.bsky.social' });
const mapping = db.getUserMapping('did:plc:...', 'my-app');

// Passkeys
db.savePasskeyCredential({ id: 'cred-id', did: '...', handle: '...', public_key: '...', counter: 0, device_type: 'platform', backed_up: false, transports: null, name: null });
db.getPasskeyCredential('cred-id');
db.getPasskeyCredentialsByDid('did:plc:...');

// Audit
db.logAuditEvent('action', 'actor', 'target', 'details', 'ip');
```

## Adding OIDC Presets

Edit `src/data/oidc-presets.ts`. Each preset needs:

```typescript
{
  id: 'my-app',
  name: 'My App',
  icon: `<svg>...</svg>`,  // Inline SVG for the setup wizard
  defaultConfig: {
    redirect_uris: (domain: string) => [`https://${domain}/callback`],
    grant_types: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    require_pkce: true,
    token_endpoint_auth_method: 'client_secret_basic',
  },
  setup_notes: `Optional markdown instructions shown in the wizard.`,
}
```

## Admin Authentication

Two auth methods (both checked by `requireAdmin` middleware):

1. **Bearer token**: `Authorization: Bearer <ADMIN_TOKEN>`
2. **Cookie**: `admin_session` cookie (set via `/admin/login`, 24h TTL, HMAC-signed)

## Proxy Cookie Types

Proxy cookies have a `typ` field to prevent cross-endpoint replay:

- `session` — forward-auth session (long-lived, `/auth/login`)
- `ticket` — one-time ticket for header exchange (`/auth/verify`)

## HMAC Token Format

`base64url(JSON payload).base64url(HMAC-SHA256 signature)`

Both sides must use UTF-8 encoding of the hex secret string:
```typescript
createHmac('sha256', secretString)  // NOT Buffer.from(secret, 'hex')
```
