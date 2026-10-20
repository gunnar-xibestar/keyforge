## Environment

| variable | role |
|---|---|
| `KEYFORGE_STORE` | store path |
| `KEYFORGE_ENV_FILE` | boot file setup writes (default `~/.keyforge/keyforge.env`) |
| `KEYFORGE_KMS_PROVIDER` | `local` (default), `pkcs11`, or `memory` |
| `KEYFORGE_KMS_KEY_FILE` | 32-byte local master key, mode 0600 |
| `KEYFORGE_PKCS11_MODULE` / `_TOKEN` / `_PIN` / `_KEY_LABEL` | PKCS#11 session |
| `SOFTHSM2_CONF` | SoftHSM configuration, if that is the module |
| `KEYFORGE_KMS_MEMORY_KEY` | test-only hex master key for the memory provider |
| `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_AUDIENCE` | enable Auth0. Domain is a hostname, no scheme |
| `AUTH0_REALM` | password-realm name (default `Username-Password-Authentication`) |
| `AUTH0_CLIENT_SECRET` | optional; environment only |
| `AUTH0_SCOPES` | override the small scope string requested at login |
| `KEYFORGE_TOKEN_FILE` | where the lean access token and refresh token are stored |
| `KEYFORGE_MAX_TOKEN_TTL` | access-token lifetime cap in seconds, 60–3600 |
| `KEYFORGE_PBKDF2_ITERS` | hash iterations (default 200000) |
| `KEYFORGE_AUDIT_HMAC_KEY_FILE` | optional audit HMAC key |
| `KEYFORGE_ACTOR` | optional actor claim; otherwise the Auth0 subject or the login name |

## Token diet

Access tokens stay small. These rules are enforced in `keyforge/auth.py` whenever Auth0 is enabled and a token is accepted or refreshed.

| access token rule | in keyforge |
|---|---|
| longer than 2048 bytes | `MAX_ACCESS_TOKEN_BYTES` |
| `alg` is not RS256, or the header carries anything beyond `alg`, `typ`, and `kid` | `ALLOWED_HEADER` + `alg == "RS256"` |
| payload carries anything beyond `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `azp`, `scope`, `gty`, and `jti` | `ALLOWED_CLAIMS` |
| contains `permissions`, `roles`, `groups`, profile claims, or `user_metadata` / `app_metadata` (turn **off** Auth0's "Add Permissions in the Access Token") | `FORBIDDEN_CLAIMS` |
| `scope` is not a short string of at most 8 scopes | `MAX_SCOPES` |
| `exp - iat` is longer than `KEYFORGE_MAX_TOKEN_TTL` (default 3600; the setting cannot be raised above 3600) | `max_token_ttl()` / `DEFAULT_MAX_TTL` |
| signature, issuer (`https://$AUTH0_DOMAIN/`), or audience does not match | JWKS verify + `AUTH0_DOMAIN` / `AUTH0_AUDIENCE` |
| expired (a refresh token, stored separately, is exchanged once for a new access token that must pass the same checks) | `TokenExpired` → `_refresh` |
| authorization uses the short `scope` claim only (Auth0 must grant the operator permissions you need) | `_check_scopes` |
| refresh tokens are opaque, capped at 2048 bytes, and are never accepted as access tokens | `MAX_REFRESH_TOKEN_BYTES` |
