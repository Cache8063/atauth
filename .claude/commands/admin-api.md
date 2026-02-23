# ATAuth Admin API

Admin token is in Vaultwarden (`ATAuth/Admin Token - Staging`).

```bash
export ADMIN_TOKEN="<token-from-vaultwarden>"
```

## OIDC Clients

```bash
# List clients
curl -s "https://apricot.workingtitle.zip/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Get client details
curl -s "https://apricot.workingtitle.zip/admin/oidc/clients/audiobookshelf" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Create client
curl -X POST "https://apricot.workingtitle.zip/admin/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "myapp",
    "name": "My Application",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"],
    "require_pkce": true,
    "token_endpoint_auth_method": "client_secret_basic"
  }'

# Update client
curl -X PUT "https://apricot.workingtitle.zip/admin/oidc/clients/myapp" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allowed_scopes": ["openid", "profile", "email"]}'

# Delete client
curl -X DELETE "https://apricot.workingtitle.zip/admin/oidc/clients/myapp" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Proxy Origins & Access Rules

```bash
# List proxy origins
curl -s "https://apricot.workingtitle.zip/admin/proxy/origins" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# List access rules
curl -s "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Create access rule (allow a specific DID)
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"allow","subject_type":"did","subject_value":"did:plc:abc123"}'

# Create access rule (allow all handles on a PDS domain)
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_type":"allow","subject_type":"handle_pattern","subject_value":"*.arcnode.xyz"}'

# Dry-run access check
curl -X POST "https://apricot.workingtitle.zip/admin/proxy/access/check" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"did":"did:plc:abc123","handle":"user.bsky.social","origin":"https://search.arcnode.xyz"}'
```

## Sessions

```bash
# List OIDC sessions
curl -s "https://apricot.workingtitle.zip/admin/sessions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# List proxy sessions
curl -s "https://apricot.workingtitle.zip/admin/proxy/sessions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Revoke a proxy session
curl -X DELETE "https://apricot.workingtitle.zip/admin/proxy/sessions/<session-id>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Kubectl Access

```bash
kubectl -n atauth get pods
kubectl -n atauth logs deploy/atauth --tail=50
kubectl -n atauth get secret atauth-secrets -o jsonpath='{.data}' | python3 -m json.tool
kubectl exec -n atauth deploy/atauth -- sqlite3 /app/data/gateway.db ".tables"
kubectl -n atauth rollout restart deployment/atauth
```
