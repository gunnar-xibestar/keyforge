# Extensibility

Material that is useful when operating or extending KeyForge, and that sits outside the main contract in [README.md](README.md).

## Use cases (draft)

These Auth0 scopes gate the **operator CLI**, not end-user apps and not `kf_...` API-key scopes (`read:packets`, etc.). In Auth0 they are API Permissions on the audience in `AUTH0_AUDIENCE`. In KeyForge they are the space-separated `scope` claim on the access token (or entries in `KEYFORGE_ROLE_MAP`).

| Use case | Who | Auth0 / env setup | What they run | Scopes needed |
|---|---|---|---|---|
| Break-glass laptop, no IdP | Solo operator | Leave `AUTH0_*` unset | Any command; OS user is trusted | *(Auth0 off)* |
| First-time enable Auth0 | Admin | Native app + Device Code + API permissions; export `AUTH0_DOMAIN` / `CLIENT_ID` / `AUDIENCE` | `auth login` → `auth status` | whatever Auth0 grants (default set in the [README](README.md#auth0)) |
| Day-to-day key inventory | Operator / auditor | User (or role map) has read only | `list`, `show`, `audit`, `export` | `keys:read` |
| Issue and rotate production keys | Key admin | Write (+ usually read) | `create`, `rotate`, `revoke`, `update`, `policy set` | `keys:write` (often also `keys:read`) |
| Run verify or the demo server | On-call / CI helper | Verify only | `verify`, `serve` | `keys:verify` |
| Recover a secret from the envelope | Security-cleared admin | Reveal separately from write | `reveal` | `reveal:secret` |
| Stay logged in across a shift | Any Auth0 user | Include refresh at login | `auth login` once; later commands refresh silently | `offline_access` (plus the scopes above) |
| Reader vs admin without fat tokens | Tenant with RBAC | Turn off “permissions in access token”; map `sub` → scopes in `KEYFORGE_ROLE_MAP` | Same commands; Auth0 token stays lean | local map wins over token `scope` |
| CI / headless login | Automation | Capture a token response offline | `auth login --from-file response.json` | scopes present in that token |

**Example role map** (`KEYFORGE_ROLE_MAP` pointing at a JSON file):

```json
{
  "auth0|alice": ["keys:read", "keys:write", "keys:verify", "reveal:secret"],
  "auth0|bob": ["keys:read", "keys:verify"]
}
```

Alice can create and reveal; Bob can list and verify only. API-key secrets still never leave the local KMS envelope path to Auth0.

**Non-goals:** Auth0 is not used to authenticate callers of `serve` (those use `Authorization: Bearer kf_...`). Auth0 is not a cloud KMS and does not wrap or store API-key material.

Access-token rejection rules: [Token diet](README.md#token-diet). Full variable list: [Environment](README.md#environment).
