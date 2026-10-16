# KeyForge

Local API key manager. Secrets are encrypted at rest, verification still uses a password hash, and operator login can be delegated to Auth0.

An API key looks like `kf_<env>_<32 random chars>`. `create` and `rotate` print the secret once. The store keeps two things and never the plaintext:

- a salted **PBKDF2-HMAC-SHA256** hash, used by `verify`
- an **AES-256-GCM** envelope of the secret, used by `reveal`

Keys created before envelope support have a hash only. `verify` still works for them. `reveal` does not, because the secret was never retained. Rotate those keys if you need a recoverable copy.

This is a single-operator tool. The local KMS is a software key or a PKCS#11 token you configure.

## Install

### 1. Package

Python 3.10+ and the `cryptography` package (Debian/Ubuntu: `python3-cryptography`).

```
pip install -e .          # provides the `keyforge` command
python -m keyforge ...    # or run without installing
```

PKCS#11 is optional. Install `python-pkcs11` and a module such as SoftHSM (`softhsm2`) only if you set `KEYFORGE_KMS_PROVIDER=pkcs11`.

Store: `--store PATH`, `$KEYFORGE_STORE`, or `~/.keyforge/store.json`. Writes are atomic, mode 0600, under an exclusive lock.

Without Auth0 configured, you are done — every command trusts the OS user.

### 2. Optional Auth0 login (for demo)

Auth0 is **off** until all three of `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_AUDIENCE` are set. Setting only some of them is an error.

**In the Auth0 dashboard**

1. Create an API whose **Identifier** is the audience you will put in `AUTH0_AUDIENCE` (for example `https://keyforge.local/api`).
2. Create a **Native** application (device-code friendly). Copy its **Client ID**.
3. Enable the **Device Code** grant for that application.
4. Authorize the application for the API. Add these API scopes (Auth0 → APIs → your API → Permissions):  
   `keys:read`, `keys:write`, `keys:verify`, `reveal:secret`
5. Turn **off** “Add Permissions in the Access Token” (KeyForge reads a short `scope` claim only; see [Token diet](#token-diet)).

**On your machine (prerequisites for using 'auth login')**

```
export AUTH0_DOMAIN=your-tenant.us.auth0.com    # hostname only, no https://
export AUTH0_CLIENT_ID=your_native_app_client_id
export AUTH0_AUDIENCE=https://keyforge.local/api
# optional:
# export AUTH0_SCOPES='keys:read keys:write keys:verify reveal:secret offline_access'

keyforge auth login
keyforge auth status
```

`auth login` prints a URL and a short code. Open the URL, enter the code, approve. KeyForge polls Auth0, then stores a lean access token (and refresh token when issued) in `KEYFORGE_TOKEN_FILE` or `~/.keyforge/tokens.json` (mode 0600). `auth status` shows the principal and scopes — never the token. `auth logout` deletes the file.

Until you log in, gated commands fail. After login, each command needs the matching Auth0 scope (see [Auth0](#auth0)). API-key secrets are never sent to Auth0.

Full variable list: [Environment](#environment). Access-token size rules: [Token diet](#token-diet).

## Commands

| command | purpose |
|---|---|
| `create --name --owner [--team] [--env live/test] [--scope S]... [--expires-in 30d / --expires-at ISO] [--rate-limit N] [--ip-allow CIDR]... [--label k=v]... [--description] [--dry-run]` | new key; prints the secret once and stores an envelope |
| `list [--owner --team --env --status --scope GLOB --label k=v] [--format table/json/csv]` | list keys |
| `show KEY` | metadata only (no hash, no envelope, no secret) |
| `reveal KEY` | decrypt the envelope and print the secret. Requires scope `reveal:secret` when Auth0 is enabled |
| `verify SECRET/- [--scope S] [--ip IP]` | check a secret against the hash (exit 4 if invalid). Does not decrypt |
| `rotate KEY [--grace-period 24h] [--dry-run] [--yes]` | new secret and envelope; the old secret stays valid during grace |
| `revoke KEY [--reason] [--dry-run] [--yes]` | permanent. `reveal` then refuses |
| `suspend KEY` / `resume KEY` | temporary disable |
| `update KEY ...` | scopes, labels, expiry, rate limit, allow list |
| `audit [--key --action --since --limit] [--export FILE] [--verify] [--adopt-legacy]` | audit log |
| `policy show` / `policy set FIELD VALUE` / `policy reset` | org rules |
| `export [-o FILE] [--include-audit]` / `import FILE [--overwrite] [--allow-unrevoke] [--dry-run]` | hashes and envelopes, never plaintext |
| `purge [--older-than 7d] [--include-revoked] [--dry-run] [--yes]` | delete expired and post-grace keys |
| `auth login [--from-file FILE]` / `auth status` / `auth logout` | device login, principal status, logout. Status never prints tokens. With Auth0 unset, status reports auth disabled |
| `serve [--host 127.0.0.1] [--port 8787]` | **demo** HTTP server: clients authenticate only with `Authorization: Bearer kf_...`. Not for production |
| `uninstall [--dry-run] [--yes] [--include-configured]` | delete `~/.keyforge` only. See [Uninstall](#uninstall) |

Global: `--json`, `--store`. Destructive commands prompt unless `--yes` is given (or `--dry-run`). Non-interactive stdin refuses without `--yes`.

Scopes look like `resource:action`. Grants may be globs (`read:*`). Statuses: active, suspended, revoked, expired, grace, rotated.

## Secret storage

`create` draws a fresh 32-byte data key, encrypts the secret with **AES-256-GCM**, and asks the KMS to wrap that data key. The associated data binds the ciphertext to the key id, so an envelope cannot be moved onto another record. `reveal` unwraps, decrypts, and checks the plaintext against the PBKDF2 hash before printing it. A bad tag, a wrong master key, or a hash mismatch fails closed and returns no secret.

`verify` never decrypts. It still walks candidates by prefix and compares the PBKDF2 hash in constant time.

The on-disk hash record is unchanged: `algo`, `iterations`, `salt`, `hash`. The envelope is a sibling field, `secret_envelope`, and `show` / `list` / `public()` omit both the hash and the envelope.

## KMS

`KEYFORGE_KMS_PROVIDER` selects the wrapper. Default is `local`.

| provider | what wraps the data key |
|---|---|
| `local` | AES-256-GCM under a 32-byte file. `KEYFORGE_KMS_KEY_FILE` if set, otherwise `<store-dir>/kms-master.key`. Created mode 0600. Symlinks and group/world-readable files are refused. |
| `memory` | An in-process key for tests (`KEYFORGE_KMS_MEMORY_KEY` may pin it as 64 hex chars). Useless after the process exits. |
| `pkcs11` | AES-256-GCM inside a PKCS#11 token. The wrapping key is not exported. |

The local file is a software KEK. Put `KEYFORGE_KMS_KEY_FILE` outside the store directory if the ciphertext and the wrapping key should sit on different permission boundaries. Anyone who can read both can reveal secrets.

### PKCS#11

Environment, all required:

- `KEYFORGE_PKCS11_MODULE` — module path, for example `/usr/lib/softhsm/libsofthsm2.so` or a hardware vendor library
- `KEYFORGE_PKCS11_TOKEN` — token label
- `KEYFORGE_PKCS11_PIN` — user PIN, from the environment only. It is not written to the store or to logs
- `KEYFORGE_PKCS11_KEY_LABEL` — AES key label on the token
- `KEYFORGE_PKCS11_CREATE_KEY=1` — generate a non-exportable AES-256 key when the label is missing

SoftHSM also needs `SOFTHSM2_CONF`. A typical first-time setup:

```
mkdir -p "$HOME/.keyforge/softhsm/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
  "$HOME/.keyforge/softhsm/tokens" > "$HOME/.keyforge/softhsm/softhsm2.conf"
export SOFTHSM2_CONF="$HOME/.keyforge/softhsm/softhsm2.conf"
softhsm2-util --init-token --free --label keyforge --pin "$PIN" --so-pin "$SO_PIN"
export KEYFORGE_KMS_PROVIDER=pkcs11
export KEYFORGE_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export KEYFORGE_PKCS11_TOKEN=keyforge
export KEYFORGE_PKCS11_PIN="$PIN"
export KEYFORGE_PKCS11_KEY_LABEL=keyforge-kek
export KEYFORGE_PKCS11_CREATE_KEY=1
```

`Pkcs11Kms` talks to any object with `wrap(label, dek, aad)` / `unwrap(label, blob, aad)`. `Pkcs11Token` is the real session. `FakePkcs11Token` is the in-memory stand-in the unit tests use when they are not pointing at SoftHSM. Point the environment variables above at a hardware module to use one; no code change is required.

There is no AWS or GCP provider. Those credentials are not part of this tool.

## Auth0

Setup and first login are under [Install → Optional Auth0 login](#2-optional-auth0-login-for-demo). This section is the runtime contract once Auth0 is enabled.

Default scopes requested at login (override with `AUTH0_SCOPES`):

```
keys:read keys:write keys:verify reveal:secret offline_access
```

Profile scopes (`openid`, `profile`, `email`) are not requested. `auth login --from-file response.json` validates a token response you already have; `id_token` is discarded.

When auth is on, commands require a principal:

| scope | commands |
|---|---|
| `keys:read` | list, show, audit, export, policy show |
| `keys:write` | create, rotate, revoke, suspend, resume, update, import, purge, policy set/reset |
| `keys:verify` | verify, serve |
| `reveal:secret` | reveal |

`auth login`, `auth status`, and `auth logout` do not require an existing principal. A missing scope exits **4**. The audit `actor` for an authorized command is the Auth0 `sub` unless `KEYFORGE_ACTOR` is already set. `os_user` remains the process uid.

KeyForge does not call the Auth0 Management API or `/userinfo`. API-key secrets are not sent to Auth0. `AUTH0_CLIENT_SECRET`, when used, is environment-only and is never stored.

Access-token rejection rules and the `keyforge/auth.py` symbols that enforce them: [Token diet](#token-diet). Full `AUTH0_*` / `KEYFORGE_*` variable list: [Environment](#environment). Operator scenarios that sit outside this contract: [Program extensibility](#program-extensibility).

## Exit codes

0 ok · 1 error (including authentication failure) · 2 usage/validation · 3 not found · 4 verification failed or missing Auth0 scope · 5 policy violation · 6 aborted · 7 audit log tampered · 8 store locked

## Demo HTTP server

`serve` is a small stdlib HTTP demo that proves a KeyForge secret can gate an API. It is **not** a production gateway.

| route | auth |
|---|---|
| `GET /health` | open |
| `GET /whoami` | any valid `kf_...` secret |
| `GET /packets` | secret must grant scope `read:packets` |

Each request calls `verify` (hash + status + optional scope/IP). Missing/invalid Bearer → 401; failed verify → 403. Auth0, when enabled, only gates who may *start* the server (`keys:verify`); API clients still present KeyForge secrets, never Auth0 tokens.

### Walkthrough

**1. Create a key**

```
keyforge create --name demo --owner you --scope read:packets
```

Creates a key named `demo` owned by `you`, with scope `read:packets` (required for `/packets`). The full secret (`kf_test_…` / `kf_live_…`) is printed **once** — copy it now. Only the hash is stored.

**2. Start the server**

```
keyforge serve --port 8787
```

Listens on `http://127.0.0.1:8787`. The process does not hold the store lock while idle; each request locks, calls `verify`, then unlocks. Auth0 (if enabled) only decides who may run this command; API clients authenticate with KeyForge secrets.

**3. Health check (no auth)**

```
curl -s http://127.0.0.1:8787/health
```

```json
{ "ok": true, "service": "keyforge-demo", "version": "0.2.0" }
```

`/health` is open. This only proves the process is up.

**4. Whoami without a key**

```
curl -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:8787/whoami
```

```json
{ "error": "missing or invalid Authorization Bearer token" }
```

HTTP **401**. No `Authorization: Bearer …` header → rejected before `verify`.

**5. Whoami with the key**

```
curl -s -H "Authorization: Bearer kf_..." http://127.0.0.1:8787/whoami
```

```json
{
  "ok": true,
  "route": "/whoami",
  "key": {
    "id": "key_…",
    "name": "demo",
    "prefix": "kf_test_…",
    "env": "test",
    "owner": "you",
    "scopes": ["read:packets"],
    "status": "active"
  }
}
```

The server parses the Bearer secret and runs `verify` (hash + status; no required scope on this route). The response is public metadata only — never the hash, envelope, or secret. HTTP **200** means the secret is a valid KeyForge key.

**6. Packets (scope-gated)**

```
curl -s -H "Authorization: Bearer kf_..." http://127.0.0.1:8787/packets
```

Same shape as `/whoami`, plus `"required_scope": "read:packets"`. `verify` is called with that scope. Your key has it → **200**. A key without it → **403** (`missing scope …`). A wrong or unknown secret → **403** (verify failed).

**Flow in one line:** create secret → serve → open `/health` → deny bare `/whoami` → accept Bearer on `/whoami` → require `read:packets` on `/packets`.

## Tests

```
python -m unittest discover -s tests -v
```

## Audit integrity

- `audit --verify` checks the hash chain and `audit_meta` (legacy count, event count, head). It exits 7 on any mismatch, including missing metadata.
- Stores from before hash-chaining have no metadata. Run `audit --adopt-legacy` once to start the chain. Existing events stay unprotected, and the adoption is itself audited.
- Optional HMAC: set `KEYFORGE_AUDIT_HMAC_KEY_FILE` to a file of at least 16 bytes, mode 0600, kept outside the store. If the key is missing or unusable, writes still succeed (a revoke is never blocked), but the event is stored without a MAC, a warning goes to stderr, and a later keyed `audit --verify` fails.
- For real tamper evidence, set `KEYFORGE_AUDIT_HMAC_KEY_FILE`. Without it the chain is unkeyed. Anyone who can write the store file can rebuild a valid-looking chain. Keep the key where store writers cannot read it.

## Import hardening

- The store keeps `revoked_hashes`. `purge` never clears it. `import` rejects a record whose hash or prefix matches a revoked or retired credential, unless `--allow-unrevoke` is set. `resume` and extending an expiry refuse the same match.
- Imported envelopes are checked for shape. A bad envelope aborts the import. Revealing an imported envelope only works with the same KMS key that wrapped it.
- **Known gap:** keys revoked or rotated and then purged before `revoked_hashes` existed were never recorded. Restore them from an older export as revoked records if you need that protection.

## Environment

| variable | role |
|---|---|
| `KEYFORGE_STORE` | store path |
| `KEYFORGE_KMS_PROVIDER` | `local` (default), `memory`, or `pkcs11` |
| `KEYFORGE_KMS_KEY_FILE` | 32-byte local master key, mode 0600 |
| `KEYFORGE_KMS_MEMORY_KEY` | test-only hex master key for the memory provider |
| `KEYFORGE_PKCS11_MODULE` / `_TOKEN` / `_PIN` / `_KEY_LABEL` | PKCS#11 session |
| `KEYFORGE_PKCS11_CREATE_KEY` | `1` to generate the AES key on the token |
| `SOFTHSM2_CONF` | SoftHSM configuration, if that is the module |
| `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_AUDIENCE` | enable Auth0. Domain is a hostname, no scheme |
| `AUTH0_CLIENT_SECRET` | optional; environment only |
| `AUTH0_SCOPES` | override the small scope string requested at login |
| `KEYFORGE_TOKEN_FILE` | where the lean access token and refresh token are stored |
| `KEYFORGE_ROLE_MAP` | local subject-to-scopes JSON |
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
| authorization uses the short `scope` claim; if `KEYFORGE_ROLE_MAP` points at `subject -> [scopes]`, those local scopes win (protect the map like the KMS file) | `_role_map_scopes` |
| refresh tokens are opaque, capped at 2048 bytes, and are never accepted as access tokens | `MAX_REFRESH_TOKEN_BYTES` |

## Uninstall

```
keyforge uninstall --dry-run
keyforge uninstall --yes
pip uninstall keyforge
```

`uninstall` deletes the data directory `~/.keyforge`: the store, the local KMS key that lives beside it, tokens, and anything else in that directory. It overwrites regular files before unlinking them. It does not remove the `keyforge` command. Run `pip uninstall keyforge` after the data is gone.

It refuses a symlinked data directory, a directory you do not own, and a store that another process has locked. Symlinks inside the directory are removed without deleting their targets. A file outside `~/.keyforge` is left alone, including one named by `KEYFORGE_STORE`, `KEYFORGE_TOKEN_FILE`, `KEYFORGE_KMS_KEY_FILE`, `KEYFORGE_AUDIT_HMAC_KEY_FILE`, or `KEYFORGE_ROLE_MAP`, unless you pass `--include-configured`. That flag deletes those files only, not their parent directories. `--store` is rejected.

## Program extensibility

Notes that are useful beyond this page, including the Auth0 operator use-case draft, live in [Extensibility](EXTENSIBILITY.md).
