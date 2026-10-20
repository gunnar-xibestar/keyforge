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

Creates a key named `demo` owned by `you`, with scope `read:packets` (required for `/packets`). The full secret (`kf_test_…` / `kf_live_…`) is printed **once** — copy it now. The store keeps a PBKDF2 hash and an AES-GCM envelope (`secret_envelope`), never the plaintext.

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
