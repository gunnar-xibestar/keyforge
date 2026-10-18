# Extensibility

Material that is useful when operating or extending KeyForge, and that sits outside the main contract in [README.md](README.md).

## Use cases (draft)

These Auth0 scopes gate the **operator CLI**, not end-user apps and not `kf_...` API-key scopes (`read:packets`, etc.). In Auth0 they are API Permissions on the audience in `AUTH0_AUDIENCE`. In KeyForge they are the space-separated `scope` claim on the access token — whatever Auth0 grants is what the CLI may do.

| Use case | Who | Auth0 / env setup | What they run | Scopes needed |
|---|---|---|---|---|
| Break-glass laptop, no IdP | Solo operator | Leave `AUTH0_*` unset | Any command; OS user is trusted | *(Auth0 off)* |
| First-time enable Auth0 | Admin | Native app + Password or Device Code + API permissions; `keyforge setup` or export `AUTH0_DOMAIN` / `CLIENT_ID` / `AUDIENCE` | `keyforge setup` or `auth login` → `auth status` | whatever Auth0 grants (default set in the [README](README.md#step-3-auth0-settings)) |
| Day-to-day key inventory | Operator / auditor | Auth0 user has read only | `list`, `show`, `audit`, `export` | `keys:read` |
| Issue and rotate production keys | Key admin | Write (+ usually read) | `create`, `rotate`, `revoke`, `update`, `policy set` | `keys:write` (often also `keys:read`) |
| Run verify or the demo server | On-call / CI helper | Verify only | `verify`, `serve` | `keys:verify` |
| Recover a secret from the envelope | Security-cleared admin | Reveal separately from write | `reveal` | `reveal:secret` |
| Stay logged in across a shift | Any Auth0 user | Include refresh at login | `auth login` once; later commands refresh silently | `offline_access` (plus the scopes above) |
| Reader vs admin | Tenant with RBAC | Turn off “permissions in access token”; assign API permissions to users/roles so they appear in the access token `scope` claim | Same commands; lean token | Auth0 `scope` only |
| CI / headless login | Automation | Capture a token response offline | `auth login --from-file response.json` | scopes present in that token |

Permission names in Auth0 must match exactly (no trailing spaces). API-key secrets still never leave the local KMS envelope path to Auth0.

**Non-goals:** Auth0 is not used to authenticate callers of `serve` (those use `Authorization: Bearer kf_...`). Auth0 is not a cloud KMS and does not wrap or store API-key material.

Access-token rejection rules: [Token diet](README.md#token-diet). Full variable list: [Environment](README.md#environment).
