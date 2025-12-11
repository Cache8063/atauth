# ATAuth Gateway

AT Protocol OAuth gateway for application authentication. This gateway handles the OAuth flow with Bluesky/AT Protocol and issues HMAC-signed tokens that your backend servers can verify.

## Quick Start

### 1. Install Dependencies

```bash
cd gateway
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```bash
# Your gateway's public URL
OAUTH_CLIENT_ID=https://auth.yourdomain.com/client-metadata.json
OAUTH_REDIRECT_URI=https://auth.yourdomain.com/auth/callback

# Admin API token (generate a secure random string)
ADMIN_TOKEN=your-secure-admin-token

# Your application domains
CORS_ORIGINS=https://app.yourdomain.com,http://localhost:3000
```

### 3. Start the Gateway

```bash
npm run dev   # Development
npm start     # Production
```

### 4. Register Your Application

```bash
curl -X POST http://localhost:3100/admin/apps \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "myapp",
    "name": "My Application",
    "callback_url": "https://myapp.com/auth/callback"
  }'
```

Save the returned `hmac_secret` - you'll need it for your backend!

## API Endpoints

### Authentication Flow

#### `POST /auth/init`
Start OAuth flow.

```json
{
  "app_id": "myapp",
  "handle": "user.bsky.social",
  "redirect_uri": "https://myapp.com/auth/callback"
}
```

Returns:
```json
{
  "auth_url": "https://bsky.social/oauth/authorize?...",
  "state": "...",
  "app_id": "myapp"
}
```

#### `GET /auth/callback`
OAuth callback (redirects with token).

Query params from AT Protocol OAuth flow are processed, then redirects to your `redirect_uri` with:
- `token` - HMAC-signed token for your backend
- `session_id` - Gateway session ID
- `needs_linking` - `true` if user not yet linked to app account

#### `POST /auth/link`
Link AT Protocol identity to your app's user account.

```json
{
  "session_id": "...",
  "user_id": 123,
  "app_id": "myapp"
}
```

#### `POST /auth/refresh`
Get a fresh token for an existing session.

#### `POST /auth/logout`
Invalidate a session.

### Token Verification

#### `POST /token/verify`
Verify a token (for your backend server).

```json
{
  "token": "...",
  "app_id": "myapp"
}
```

Returns:
```json
{
  "valid": true,
  "payload": {
    "did": "did:plc:...",
    "handle": "user.bsky.social",
    "user_id": 123,
    "app_id": "myapp",
    "exp": 1699903600
  }
}
```

### Session Management

#### `POST /session/check-conflict`
Check for existing sessions (multi-device support).

#### `POST /session/resolve-conflict`
Resolve session conflict (`transfer`, `cancel`, `close_others`).

#### `POST /session/update-state`
Update connection state (for WebSocket apps).

### Admin

#### `POST /admin/apps`
Register a new application (returns HMAC secret).

#### `PUT /admin/apps/:id`
Update app config (can rotate secret).

## Integration Examples

### Frontend (React)

```tsx
import { redirectToAuth, handleCallback } from '@arcnode/atauth';

// Start login
const startLogin = async (handle: string) => {
  const response = await fetch('https://auth.yourdomain.com/auth/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app_id: 'myapp',
      handle,
      redirect_uri: window.location.origin + '/auth/callback'
    })
  });
  const { auth_url } = await response.json();
  window.location.href = auth_url;
};

// Handle callback page
const CallbackPage = () => {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    if (token) {
      // Store token and redirect to app
      localStorage.setItem('auth_token', token);
      window.location.href = '/dashboard';
    }
  }, []);
};
```

### Backend (Node.js)

```typescript
import { TokenVerifier } from 'atauth';

const verifier = new TokenVerifier(process.env.HMAC_SECRET);

app.use('/api', (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }

  try {
    const payload = verifier.verify(token);
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

### Backend (Rust)

```rust
use atauth::TokenVerifier;

let verifier = TokenVerifier::new(hmac_secret.as_bytes());

match verifier.verify(&token) {
    Ok(payload) => {
        println!("User: {} ({})", payload.handle, payload.did);
        // payload.user_id is your app's user ID if linked
    }
    Err(e) => {
        eprintln!("Auth failed: {}", e);
    }
}
```

## Deployment

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
COPY data ./data
EXPOSE 3100
CMD ["node", "dist/index.js"]
```

### systemd

```ini
[Unit]
Description=ATAuth Gateway
After=network.target

[Service]
Type=simple
User=atauth
WorkingDirectory=/opt/atauth-gateway
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

## Security Notes

1. **HTTPS Required**: Always run behind HTTPS in production
2. **Secure Admin Token**: Use a long random string for `ADMIN_TOKEN`
3. **Store HMAC Secrets Safely**: Never commit secrets to git
4. **Restrict CORS**: Only allow your application domains
