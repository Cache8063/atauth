# Root Cause Analysis: Invalid redirect_uri (2026-02-22)

## Incident

All OIDC-dependent apps (mdeditor, mydrawings) unable to authenticate via ATAuth.
Users see `500 Internal Server Error` when trying to log in.

**Duration**: ~2 days (OIDC/forward-auth features deployed 2026-02-20, reported 2026-02-22)
**Impact**: Complete authentication failure for all apps using ATAuth via OIDC or legacy `/auth/init` flow
**Severity**: Critical (P1)

## Symptoms

- `app.example.com` returns 500 Internal Server Error on login
- ATAuth pod logs: `Unhandled error: TypeError: Invalid redirect_uri` at `NodeOAuthClient.authorize`
- No AT Protocol OAuth requests reach the PDS -- error is thrown client-side before any network call

## Root Cause

Two related bugs in how `redirect_uri` was handled:

### Bug 1: OIDC callback not registered in NodeOAuthClient

The `@atproto/oauth-client` library's `NodeOAuthClient.authorize()` validates that the `redirect_uri` is in its own `clientMetadata.redirect_uris` array before sending anything to the PDS (early validation, ~line 147 of `oauth-client.js`).

The `/client-metadata.json` endpoint (served to PDSes for discovery) correctly listed all redirect URIs including the OIDC callback. However, the `NodeOAuthClient` instance inside `OAuthService` was initialized with only 2 URIs:
- `https://auth.example.com/auth/callback` (primary)
- `https://auth.example.com/proxy/callback` (proxy)

Missing:
- `https://auth.example.com/oauth/callback` (OIDC)
- `https://auth.example.com/auth/proxy/callback` (forward-auth)

**Location**: `gateway/src/services/oauth.ts` line 47, `gateway/src/index.ts` line 116

### Bug 2: Legacy auth flow passed downstream app callback as OAuth redirect_uri

The `/auth/init` route passed the downstream app's callback URL (e.g., `https://app.example.com/api/auth/callback`) as the `redirect_uri` to `NodeOAuthClient.authorize()`. This URL:
1. Was not registered in `clientMetadata.redirect_uris` (fails local validation)
2. Would not be accepted by the PDS (doesn't match client_id's registered callbacks)

The correct behavior is: the PDS should redirect back to ATAuth's own callback (`/auth/callback`), where ATAuth exchanges the code, creates an HMAC token, then redirects the user to the downstream app's callback with the token.

**Location**: `gateway/src/routes/auth.ts` lines 109-112

## Why This Wasn't Caught

- OIDC and forward-auth features were added on 2026-02-20 (via kubectl-patch to configmap)
- The OIDC authorize route (`/oidc/authorize`) correctly passed ATAuth's own callback
- The legacy `/auth/init` route (used by mdeditor) had the bug since inception, but was only exposed when `@atproto/oauth-client` started enforcing redirect_uri validation client-side
- No integration tests cover the full `/auth/init` -> PDS -> `/auth/callback` flow with a real `@atproto/oauth-client` instance

## Fix

### Commit `5936273` (partial fix)
- Modified `OAuthService.initialize()` to accept `additionalRedirectUris` parameter
- `index.ts` now passes OIDC and forward-auth callback URIs during OAuth client initialization
- Fixed Bug 1 only

### Commit `13f795f` (complete fix)
- Modified `/auth/init` to NOT pass the app's callback URL as OAuth redirect_uri
- Added `appRedirectUri` parameter to `generateAuthUrl()` -- stored in OAuth state for post-auth redirect, but not passed to `@atproto/oauth-client.authorize()`
- Fixed Bug 2

## Files Changed

- `gateway/src/services/oauth.ts` - `initialize()` accepts additional redirect URIs; `generateAuthUrl()` accepts separate `appRedirectUri` for state
- `gateway/src/index.ts` - Collects OIDC/forward-auth callback URIs and passes them during OAuth initialization
- `gateway/src/routes/auth.ts` - Legacy `/auth/init` no longer passes app callback as OAuth redirect_uri

## Prevention

- Add integration test that exercises `/auth/init` with a mock `@atproto/oauth-client` to verify redirect_uri handling
- Ensure `NodeOAuthClient.redirect_uris` and `/client-metadata.json` redirect_uris are always derived from the same source
- Log registered redirect_uris on startup for easier debugging
