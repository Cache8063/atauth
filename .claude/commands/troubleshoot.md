# ATAuth Troubleshooting

## "Forbidden sec-fetch-site header same-site"

**Cause**: ATAuth and user's PDS are on the same registrable domain.
**Fix**: Use `workingtitle.zip` for ATAuth, not `arcnode.xyz`.

## "invalid_redirect_uri"

**Cause**: Redirect URI in request doesn't match registered client.
**Fix**: Check client's registered redirect_uris match exactly (including https vs http, port, path).

## Token refresh failures / Users logged out

**Cause**: iOS app sends chunked encoding with empty body on refreshSession.
**Fix**: nginx with `proxy_pass_request_body off` for that endpoint (handled on PDS side).

## Access rules lock everyone out

**Fix**: Delete all rules to restore open mode:
```bash
kubectl exec -n atauth deploy/atauth -- sqlite3 /app/data/gateway.db "DELETE FROM proxy_access_rules;"
```
Or via admin API: `DELETE /admin/proxy/access/:id` with Bearer token.

## CI pipeline stuck (Gitea Actions)

**Cause**: `needs` job scheduling stalls after test job completes.
**Fix**: Restart Gitea then act_runner on LXC 111:
```bash
ssh root@pv4.cloudforest-basilisk.ts.net "pct exec 111 -- bash -c 'systemctl restart gitea && sleep 5 && systemctl restart act_runner'"
```
If still stuck, deploy manually (see `/deploy` command).

## "invalid_client" on OIDC token exchange

**Cause**: Client secret stored as SHA-256 hash but token endpoint compared raw secret.
**Fixed** in `3fc67a7`: `token.ts` and `revoke.ts` now hash incoming secret before comparison.

## "invalid_grant" redirect_uri mismatch on AT Protocol token exchange

**Cause**: `@atproto/oauth-client` falls back to `clientMetadata.redirect_uris[0]` during token exchange. Authorization used `/oauth/callback` but exchange used `/auth/callback`.
**Fixed** in `3fc67a7`: `authorize.ts` passes explicit redirect_uri to `handleCallback()`.

## Userinfo returns empty `preferred_username`

**Cause**: `db.getUserMapping()` returns nothing for new OIDC sessions; handle defaulted to empty string.
**Fixed** in `3fc67a7`: `userinfo.ts` resolves DID to handle via `app.bsky.actor.getProfile` API.

## PKCE required error for app that doesn't support PKCE

**Cause**: OIDC client created with `require_pkce: true` but the app (e.g., Gitea) doesn't send PKCE params.
**Fix**: Disable PKCE for the client:
```bash
curl -X PUT "https://apricot.workingtitle.zip/admin/oidc/clients/<client-id>" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"require_pkce": false}'
```

## Pod not starting / CrashLoopBackOff

```bash
kubectl -n atauth describe pod <pod-name>
kubectl -n atauth logs deploy/atauth --previous
kubectl -n atauth get events --sort-by='.lastTimestamp'
```

## SQLite locked / database busy

**Cause**: Multiple writers (shouldn't happen with single replica).
**Fix**: Verify only 1 replica running, check WAL mode:
```bash
kubectl exec -n atauth deploy/atauth -- sqlite3 /app/data/gateway.db "PRAGMA journal_mode;"
```
