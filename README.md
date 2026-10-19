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

PKCS#11 is optional and off unless `KEYFORGE_KMS_PROVIDER=pkcs11`. Then you need both:

```
pip install python-pkcs11          # not the unrelated PyPI package named pkcs11
sudo apt install softhsm2          # or another PKCS#11 .so (hardware token)
```

If either is missing, the first PKCS#11 operation fails with install hints. SoftHSM setup is the `pkcs11` branch of [`keyforge setup`](#step-1-kms-provider).

Store: `--store PATH`, `$KEYFORGE_STORE`, or `~/.keyforge/store.json`. Writes are atomic, mode 0600, under an exclusive lock.

`keyforge` with no command exits with a usage error. Configuration is `keyforge setup` (below). Without Auth0, every command trusts the OS user.

### 2. `keyforge setup`

Run `keyforge setup`. It is interactive and refuses a non-interactive stdin. `keyforge` with no command exits with a usage error.

The prompt writes every answer except the Auth0 password to `~/.keyforge/keyforge.env` (mode 0600). Later commands apply that file over a same-named variable inherited from the shell. The parent shell itself is unchanged.

The steps below are the prompt, in order. The reference material for each step sits under that step.

#### Step 1. KMS provider

The screen prints where each value comes from, then asks:

```
KEYFORGE_KMS_PROVIDER [local]:
```

Setup records the answer and prints `keyforge kms status` before Auth0. `result: success` means that provider is ready; `result: failure` prints the error and setup continues.

Auth0 `auth login` / `auth status` do **not** use the KMS — only `create`, `rotate`, and `reveal` (and envelope import) do.

| provider | what wraps the data key |
|---|---|
| `local` | AES-256-GCM under a 32-byte file. `KEYFORGE_KMS_KEY_FILE` if set, otherwise `<store-dir>/kms-master.key`. Created mode 0600. Symlinks and group/world-readable files are refused. `kms status` warns that this software KEK is readable by anyone who can read the file, and again when it sits in the store directory. |
| `pkcs11` | AES-256-GCM inside a PKCS#11 token. The wrapping key is not exported. |
| `memory` | Replaces `pkcs11` and `local` for unit tests. An in-process key (`KEYFORGE_KMS_MEMORY_KEY` may pin it as 64 hex chars). Useless after the process exits. |

**If you enter `local`.** Setup asks for `KEYFORGE_KMS_KEY_FILE`. Leave it blank to keep the key at `<store-dir>/kms-master.key`.

The default store is `~/.keyforge/store.json`, so the default key is `~/.keyforge/kms-master.key`. The file is a software KEK. Put `KEYFORGE_KMS_KEY_FILE` outside the store directory if the ciphertext and the wrapping key should sit on different permission boundaries. Anyone who can read both can reveal secrets.

Find the store with `echo "${KEYFORGE_STORE:-$HOME/.keyforge/store.json}"`.

**If you enter `pkcs11`.** Install the binding and a module first (see [Package](#1-package)). Setup prints the commands to create a SoftHSM token.

If one token labeled `keyforge` already exists, setup reuses it as main. If several exist, it lists them oldest first and can delete any except the main token. Create waits until you press Enter.

Setup then asks, in order, for:

- `KEYFORGE_PKCS11_MODULE` (default `/usr/lib/softhsm/libsofthsm2.so`; `dpkg -L softhsm2 | grep '\.so$'`)
- `KEYFORGE_PKCS11_TOKEN` (default `keyforge`; `softhsm2-util --show-slots`; skipped and fixed to `keyforge` when that token is reused)
- the AES key label
- the user PIN (`KEYFORGE_PKCS11_PIN`, from `--init-token --pin`, not the SO PIN)
- `SOFTHSM2_CONF` (default `~/.keyforge/softhsm/softhsm2.conf`)

If an AES key labeled `keyforge-kek` is already on the token, setup keeps that label and does not ask `KEYFORGE_PKCS11_KEY_LABEL`. Otherwise it asks for `KEYFORGE_PKCS11_KEY_LABEL` (default `keyforge-kek`).

If `keyforge-kek` is absent and other AES keys are on the token, those other keys are deleted and each deletion is printed. If `keyforge-kek` is present, setup lists the keys. A number selects that key. `d` and a number deletes any key except `keyforge-kek`. The user PIN is asked after that choice.

The new-key warning is printed only when the label was just entered, that key is present, and no PIN was saved yet.

A missing AES key is still generated on first use (create, rotate, or reveal). That generation does not ask for a new PIN; it uses the same `KEYFORGE_PKCS11_PIN` already used to open the token session.

The PIN is stored in `keyforge.env` at mode 0600. It is not written to the store or to logs. A later TTY prompt for a missing PIN stays in the process only and is not written back to `keyforge.env`.

`keyforge kms status` then reports `provider: pkcs11` and `ready: True`, or lists what is missing.

`Pkcs11Kms` talks to any object with `wrap(label, dek, aad)` / `unwrap(label, blob, aad)`.

`Pkcs11Token` is the real session: it loads the module, finds the token by label, logs in with the user PIN, and finds or creates the labeled AES key. `FakePkcs11Token` is the in-memory stand-in the unit tests use when they are not pointing at SoftHSM. `Pkcs11Kms` does not care which backend it holds.

Point the variables above at a hardware module to use one; no code change is required.

**If you enter `memory`.** Nothing else is asked. The key dies with the process. Do not use it for a store you need to open again.

#### Step 2. Whether to set up Auth0

```
Set up Auth0 now? [Y/n]
```

Pressing Enter accepts yes. Auth0 is **off** until all three of `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_AUDIENCE` are set. Setting only some of them is an error.

When all three are already in the environment (including from `keyforge.env`), setup keeps them, prints them, and does not ask this question. Unset `AUTH0_DOMAIN` to enter different values.

Answering no warns that Auth0 is necessary for the demo, then stops after saving the KMS choice: every command trusts the OS user, and there is no operator scope gate. Anyone who can run `keyforge` as this user can create, reveal, and delete keys.

Turn Auth0 on later by running `keyforge setup` again after the dashboard work below. `keyforge auth status` reports `auth disabled` until then.

#### Step 3. Auth0 settings

Answering yes prints where each value is in the dashboard (https://manage.auth0.com), then asks for them. Do the dashboard work before you answer.

1. Create an API whose **Identifier** is the audience (for example `https://keyforge.local/api`).
2. Create a **Native** application. Copy its **Client ID**.
3. Enable the **Password** grant for this prompt, and the **Device Code** grant if you will also use `auth login`.
4. Authorize the application for the API. Add these API scopes (Auth0 → APIs → your API → Permissions): `keys:read`, `keys:write`, `keys:verify`, `reveal:secret`. These are **operator** scopes for the CLI. They are not `kf_...` API-key scopes such as `read:packets`.
5. Turn **off** “Add Permissions in the Access Token” (KeyForge reads a short `scope` claim only; see [Token diet](#token-diet)). Leave **Enable RBAC** off. With RBAC off, Auth0 copies the API permissions you requested into the access token `scope` claim. A working setup does not assign those permissions to a user or role. Turning RBAC on makes Auth0 omit any permission that user or role does not have, so login returns missing scopes.
6. Under Applications → your Native app → APIs, authorize the app for that API and allow the same permissions.

The three prompts:

```
AUTH0_DOMAIN      Settings → Domain. Hostname only, no https://
AUTH0_CLIENT_ID   Applications → Native app → Settings → Client ID
AUTH0_AUDIENCE    Applications → APIs → Settings → Identifier (for example https://keyforge.local/api)
```

`AUTH0_CLIENT_SECRET` is optional and environment-only. Setup does not ask for it, and it is never stored.

`AUTH0_SCOPES` overrides the scope string requested at login. The default is:

```
keys:read keys:write keys:verify reveal:secret offline_access
```

Profile scopes (`openid`, `profile`, `email`) are not requested.

#### Step 4. Username, then password

```
username:
password:
```

The username is the database user (User Management → Users), usually the email. It is not the Client ID. The password is that user's password. It is not the Client Secret. It is sent with Auth0's password-realm grant and is not written to disk.

The default realm is `Username-Password-Authentication` (`AUTH0_REALM` overrides it). That grant has to be enabled on the Native app.

`auth login` remains a separate device-code command: it prints a URL and a short code, then stores a lean access token (and a refresh token when issued) in `KEYFORGE_TOKEN_FILE` or `~/.keyforge/tokens.json` (mode 0600).

`auth login --from-file response.json` validates a token response you already have; `id_token` is discarded. `auth logout` deletes the token file. `auth login`, `auth status`, and `auth logout` do not require an existing principal.

Setup does not print `auth status`. Run `keyforge auth status` when you want the principal, scopes, and `missing_scopes`. It never prints the token.

Auth0 returns the **intersection** of what KeyForge requested and what the tenant grants. Permission names must match exactly (trailing spaces in Auth0 silently drop a scope).

If `keyforge auth status` shows only `keys:read` and `offline_access`, the other permissions are missing in the API or the app grant. KeyForge is not dropping them. RBAC stays off for this setup; turning it on also drops any permission not assigned to that user or role.

Until you log in, gated commands fail. After login, each command needs the matching scope. A missing scope exits **4**.

The audit `actor` is the Auth0 `sub` unless `KEYFORGE_ACTOR` is already set. `os_user` remains the process uid. KeyForge does not call the Auth0 Management API or `/userinfo`. API-key secrets are not sent to Auth0.

| scope | commands |
|---|---|
| `keys:read` | list, show, audit, export, policy show |
| `keys:write` | create, rotate, revoke, suspend, resume, update, import, purge, policy set/reset |
| `keys:verify` | verify, serve |
| `reveal:secret` | reveal |

Access-token rejection rules: [Token diet](#token-diet). Every variable: [Environment](#environment). Operator scenarios outside this contract: [Program extensibility](#program-extensibility).

## Commands

| command | purpose |
|---|---|
| `create --name --owner [--team] [--env live/test] [--scope S]... [--expires-in 30d / --expires-at ISO] [--rate-limit N] [--ip-allow CIDR]... [--label k=v]... [--description] [--dry-run]` | new key; prints the secret once and stores an envelope |
| `list [--owner --team --env --status --scope GLOB --label k=v] [--format table/json/csv]` | list keys, oldest `created_at` first (`kms` wrapping provider; table/csv show `NO EXP` when no expiry; `team` last) |
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
| `setup` | boot prompt: KMS provider, optional Auth0, then username and password. Password is not saved |
| `auth login [--from-file FILE]` / `auth status` / `auth logout` | device login, principal status, logout. Status never prints tokens. With Auth0 unset, status reports auth disabled |
| `kms status` | show active KMS provider and whether it is ready (never prints the PKCS#11 PIN). Auth login does not use the KMS |
| `serve [--host 127.0.0.1] [--port 8787]` | **demo** HTTP server: clients authenticate only with `Authorization: Bearer kf_...`. Not for production |
| `uninstall [--dry-run] [--yes] [--include-configured]` | delete `~/.keyforge` only. See [Uninstall](#uninstall) |

Global: `--json`, `--store`. Destructive commands prompt unless `--yes` is given (or `--dry-run`). Non-interactive stdin refuses without `--yes`.

Scopes look like `resource:action`. Grants may be globs (`read:*`). Statuses: active, suspended, revoked, expired, grace, rotated.

## Secret storage

`create` draws a fresh 32-byte data key, encrypts the secret with **AES-256-GCM**, and asks the KMS to wrap that data key. The associated data binds the ciphertext to the key id, so an envelope cannot be moved onto another record.

`reveal` unwraps, decrypts, and checks the plaintext against the PBKDF2 hash before printing it. A bad tag, a wrong master key, or a hash mismatch fails closed and returns no secret.

`verify` never decrypts. It still walks candidates by prefix and compares the PBKDF2 hash in constant time.

The on-disk hash record is unchanged: `algo`, `iterations`, `salt`, `hash`. The envelope is a sibling field, `secret_envelope`, and `show` / `list` / `public()` omit both the hash and the envelope. `list` / `public()` do surface `kms` as the wrapping provider (`local` / `pkcs11` / `memory`) without the rest of the envelope; hash-only legacy keys show blank/`-`.

## Exit codes

0 ok · 1 error (including authentication failure) · 2 usage/validation · 3 not found · 4 verification failed or missing Auth0 scope · 5 policy violation · 6 aborted · 7 audit log tampered · 8 store locked

## Demo HTTP server

`serve` is a small stdlib HTTP demo that proves a KeyForge secret can gate an API. It is **not** a production gateway.

| route | auth |
|---|---|
| `GET /health` | open |
| `GET /whoami` | any valid `kf_...` secret |
| `GET /packets` | secret must grant scope `read:packets` |
| `GET /admin` | secret must grant scope `write:packets` |
| `POST /keys` | secret must grant API-key scope `keys:write` (demo only; does not mint) |
| `GET /verify` | secret must grant scope `read:packets` (200 ok; verify output withheld) |

Each request calls `verify` (hash + status + optional scope/IP). Missing/invalid Bearer → 401; failed verify → 403.

Auth0, when enabled, only gates who may *start* the server (`keys:verify`); API clients still present KeyForge secrets, never Auth0 tokens. **Auth0 operator** scope `keys:write` authorizes `keyforge create` on the CLI. **API-key** scope `keys:write` is a claim on a stored `kf_...` secret checked by this HTTP demo. Same name, different plane — the walkthrough key only has `read:packets`, so `POST /keys` fails. `GET /verify` accepts that same key (**200**) but still withholds verify details — success means the key is valid for the route, not that a full verify payload is returned.

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
{ "ok": true, "service": "keyforge-demo", "version": "0.3.0" }
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

**7. Admin (valid key, wrong scope)**

```
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer kf_..." http://127.0.0.1:8787/admin
```

```json
{ "error": "missing scope 'write:packets'" }
```

HTTP **403**. The secret is a valid key and `/whoami` and `/packets` accept it. `/admin` requires `write:packets`, which this key does not have.

**8. Create attempt (API-key scope `keys:write`)**

```
curl -s -w '\nHTTP %{http_code}\n' -X POST -H "Authorization: Bearer kf_..." http://127.0.0.1:8787/keys
```

```json
{ "error": "missing scope 'keys:write'" }
```

HTTP **403**. The client tries to create a secret through the demo API. `POST /keys` requires the **API-key** scope `keys:write` on the Bearer secret. This walkthrough key only has `read:packets`, so the attempt fails. That string is not the Auth0 **operator** scope of the same name used by `keyforge create`. The route never mints: even with a key that has API-key `keys:write` it returns **200**, `"created": false`, and a note that real creates use the CLI with Auth0 operator scope `keys:write`. `GET /keys` is **405**.

**9. Verify (valid key, verify output withheld)**

```
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer kf_..." http://127.0.0.1:8787/verify
```

```json
{
  "ok": true,
  "route": "/verify",
  "required_scope": "read:packets",
  "key": {
    "id": "key_…",
    "name": "demo",
    "prefix": "kf_test_…",
    "env": "test",
    "owner": "you",
    "scopes": ["read:packets"],
    "status": "active"
  },
  "note": "verify output withheld without a stronger permission (e.g. API-key scope keys:verify)"
}
```

HTTP **200**. The route requires `read:packets`, which this key has, so the call succeeds. The body is limited key metadata plus a note — no hash check dump, no envelope, and no `verified: true/false` beyond `"ok": true`. **200** means the secret is valid for the route; verify details stay withheld without a stronger permission (for example API-key scope `keys:verify`). A key without `read:packets` → **403**. No Bearer → **401**.

**Flow in one line:** create secret → serve → open `/health` → deny bare `/whoami` → accept Bearer on `/whoami` → require `read:packets` on `/packets` → reject that same key on `/admin` → reject that same key on `POST /keys` (missing API-key scope `keys:write`) → accept `GET /verify` with `read:packets` but withhold verify output.

| status | when |
|---|---|
| **200** | `/health` ok; `/whoami`, `/packets`, `/admin`, or `/verify` with a valid secret (and scope when required); `POST /keys` with API-key scope `keys:write` (`created: false`, demo only); `/verify` still omits verify details |
| **401** | missing or invalid `Authorization: Bearer …` |
| **403** | Bearer present but `verify` failed (bad secret, revoked/suspended, missing scope, IP deny) |
| **404** | unknown path |
| **405** | wrong method for the route (for example `GET /keys`, or `POST` on a GET-only path) |

## Tests

```
python -m unittest discover -s tests -v
```

## Audit integrity

The audit log records who did what to which key. Integrity is a hash chain over that log, optionally keyed with HMAC. Mutations write the next link. Checking the chain is separate: it runs only when you ask (`audit --verify`) or during `keyforge setup`. Ordinary commands do not re-verify the chain before they append.

### When events are written

Each successful mutating command appends one (or more) events to the store's `audit` list. Typical actions:

| action | command |
|---|---|
| `create` | `create` |
| `reveal` | `reveal` |
| `verify_ok` / `verify_fail` | `verify` |
| `rotate` | `rotate` |
| `revoke` / `suspend` / `resume` | status changes |
| `update` | `update` (only when something actually changes) |
| `purge` | `purge` (one event per deleted key) |
| `import` | `import` (non-dry-run) |
| `export` | `export` to a file (stdout `-` does not audit) |
| `policy_set` / `policy_reset` | `policy set` / `policy reset` |
| `audit_adopt_legacy` | `audit --adopt-legacy`, or setup when metadata is missing |
| `audit_hmac_enabled` | setup, the first time it enables a metadata MAC |

`list`, `show`, `policy show`, dry-runs, and a plain `audit` query do not append.

A brand-new store starts with `audit_meta` already present (`legacy` 0, `count` 0, `head` 64 zeros). Older stores that never had chaining need adopt (below).

### How a write extends the chain

On each append, KeyForge builds the event (`ts`, `actor`, `os_user`, `os_uid`, `action`, `key_id`, `details`), sets `prev_hash` to the current `audit_meta.head` (or 64 zeros for the first chained event), then sets `hash` to SHA-256 of the event's canonical JSON with `hash` and `mac` removed (sorted keys, no extra spaces).

`audit_meta.count` becomes the new log length. `audit_meta.head` becomes that event's `hash`. Changing a field changes that event's hash, which changes the next event's `prev_hash`, and so on to the end.

If `KEYFORGE_AUDIT_HMAC_KEY_FILE` points at a usable key, the same write also stores `mac` = HMAC-SHA256(key, hash) on the event, and refreshes `audit_meta.mac` over `legacy|count|head|hmac_from`. `hmac_from` is set to the index of the first MAC'd event the first time a key is in use.

If the key file is set but missing or unusable at write time, the event is still stored (a revoke is never blocked). A warning goes to stderr. A later keyed `audit --verify` fails.

If `audit_meta` is missing entirely on a store that already has events, new writes are appended without hashes and a warning goes to stderr. The chain stays broken until you adopt or fix the store.

`audit_meta` fields:

| field | meaning |
|---|---|
| `legacy` | how many leading events have no hash. They pre-date the chain. |
| `count` | how many events the chain expects. |
| `head` | hash of the last chained event, or the 64 zeros when nothing is chained yet. |
| `hmac_from` | index of the first event that must have a MAC, once an HMAC key is in use. |
| `mac` | HMAC-SHA256 of `legacy\|count\|head\|hmac_from`, present only when a key is in use. |

### When the chain is checked

Verification is explicit. It does not run on every create, reveal, or revoke.

**`keyforge audit --verify`.** Walks the log and compares it to `audit_meta`. Exit **0** on success, **7** on any mismatch (including missing metadata).

What fails: a missing `hash` or `prev_hash` on a chained event; a `prev_hash` that does not match the previous event; a content hash that does not match the body; a `count` or `head` that does not match the log; a bad per-event or metadata MAC when a key is in use.

Legacy events (indices below `legacy`) are counted and skipped: they are not hashed. On success the command prints `audit chain OK` with the chained-event count, the log count, and the head, plus `MAC verified` when the key checked out.

It then prints each check (`audit_meta`, legacy, MACs, hash continuity, count, head) with **ok** / **FAIL** / **skip** and the data used. A **keys and chain events** section matches `list` keys to audit events by `key_id` (event counts and actions per key), plus orphan events whose `key_id` is no longer in the store and chain events with no `key_id`. `--json` includes the same `checks` and `match` objects.

**`keyforge setup`.** After the KMS choice is saved, setup prints an `Audit chain` title, the store path, then runs the same check as `audit --verify`. It does not exit 7 on failure; it prints `AUDIT CHAIN BROKEN: …` and continues. On success it prints the same `audit chain OK` line.

Setup also repairs and hardens when it can:

1. If `audit_meta` is absent and the log has no hashed events, setup runs the same path as `audit --adopt-legacy`, then says those legacy events cannot be checked for tampering.
2. If no key file exists at `KEYFORGE_AUDIT_HMAC_KEY_FILE` (default `<store-dir>/audit-hmac.key` when unset), setup creates one (32 random bytes, mode 0600), saves the path into `keyforge.env`, and explains why. If the file already exists, it prints `audit HMAC key found: …` and reuses that secret — setup does not mint a new key on every run.
3. The first time a usable key is present and metadata has no `mac` yet, setup writes one `audit_hmac_enabled` event so the MAC starts at that event. Events before it stay without a MAC.

After the check, setup reports HMAC status (with blank lines between groups):

- If a valid chain and a matching HMAC secret were already in place, it prints `HMAC: on, verified, working` with the secret path and chain details (`chained` count, `count`, `head`). `audit --verify` will check both the hash chain and the HMAC tags.
- If setup just created the key (or is enabling MAC for the first time), it prints `HMAC: on and verified for new events`, explains that later setups reuse the file, then warns that without that key `audit --verify` only checks the unkeyed hash chain — anyone who can write the store can recompute `prev_hash` and `hash`, and verify still passes.
- If no usable HMAC secret is found, it warns that HMAC is not verifying the chain and that you lose keyed tamper evidence until `KEYFORGE_AUDIT_HMAC_KEY_FILE` points at a usable secret.

### Adopting a pre-chain store

Stores from before hash-chaining have events and no `audit_meta`.

`audit --adopt-legacy` (and setup, when metadata is absent) records that count as `legacy`, sets `head` to the 64 zeros, and appends a chained `audit_adopt_legacy` event. Those older events stay without hashes. The adoption event is chained.

If the log already contains hashed events but the metadata is gone, adopt refuses: recreating the metadata would bless a stripped log.

### What the chain does and does not catch

Without an HMAC key, the chain is unkeyed. Anyone who can write the store can edit an event and recompute `prev_hash`, `hash`, `count`, and `head`. `audit --verify` then passes. The chain still detects accidental corruption and naive edits; it does not stop a writer who understands the format.

The HMAC key file must contain at least 16 bytes, mode 0600, and must not be a symlink. With that key, a writer who cannot read the file cannot produce valid event or metadata MACs.

Default setup puts `audit-hmac.key` next to the store. Anyone who can read that directory can still forge a chain that verifies. Move the file somewhere store writers cannot read it when you need the MAC to mean tamper evidence.

Events before `hmac_from`, and every legacy event, still have no MAC. Rewriting only those events is not detected as keyed tampering.

`actor` can be overridden with `KEYFORGE_ACTOR`. Trust `os_user` / `os_uid` for who ran the process.

## Import hardening

- The store keeps `revoked_hashes`. `purge` never clears it. `import` rejects a record whose hash or prefix matches a revoked or retired credential, unless `--allow-unrevoke` is set. `resume` and extending an expiry refuse the same match.
- Imported envelopes are checked for shape. A bad envelope aborts the import. Revealing an imported envelope only works with the same KMS key that wrapped it.
- **Known gap:** keys revoked or rotated and then purged before `revoked_hashes` existed were never recorded. Restore them from an older export as revoked records if you need that protection.

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

## Uninstall

```
keyforge uninstall --dry-run
keyforge uninstall --yes
pip uninstall keyforge
```

`uninstall` deletes the data directory `~/.keyforge`: the store, the local KMS key that lives beside it, tokens, and anything else in that directory. It overwrites regular files before unlinking them. It does not remove the `keyforge` command. Run `pip uninstall keyforge` after the data is gone.

It refuses a symlinked data directory, a directory you do not own, and a store that another process has locked. Symlinks inside the directory are removed without deleting their targets.

A file outside `~/.keyforge` is left alone, including one named by `KEYFORGE_STORE`, `KEYFORGE_TOKEN_FILE`, `KEYFORGE_KMS_KEY_FILE`, or `KEYFORGE_AUDIT_HMAC_KEY_FILE`, unless you pass `--include-configured`. That flag deletes those files only, not their parent directories. `--store` is rejected.

## Program extensibility

Notes that are useful beyond this page, including the Auth0 operator use-case draft, live in [Extensibility](EXTENSIBILITY.md).
