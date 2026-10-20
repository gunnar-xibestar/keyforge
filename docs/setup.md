# Setup and KMS

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

Later commands apply `~/.keyforge/keyforge.env` over a same-named variable inherited from the shell. The parent shell itself is unchanged.

#### Step 1. KMS provider

The screen lists the provider names, then asks:

```
KEYFORGE_KMS_PROVIDER [local]:
```

Setup records the answer. A KMS failure is printed under `kms` at that step and setup continues. When KMS setup succeeds, that status is printed at the end under `kms`. When Auth0 login succeeds, that status is printed at the end under `auth0`.

| provider | what wraps the data key |
|---|---|
| `local` | AES-256-GCM under a 32-byte file. `KEYFORGE_KMS_KEY_FILE` if set, otherwise `<store-dir>/kms-master.key`. Created mode 0600. Symlinks and group/world-readable files are refused. `kms status` warns that this software KEK is readable by anyone who can read the file, and again when it sits in the store directory. |
| `pkcs11` | AES-256-GCM inside a PKCS#11 token. The wrapping key is not exported. |
| `memory` | Replaces `pkcs11` and `local` for unit tests. An in-process key (`KEYFORGE_KMS_MEMORY_KEY` may pin it as 64 hex chars). Useless after the process exits. |

**If you enter `local`.** Setup asks for `KEYFORGE_KMS_KEY_FILE`. Leave it blank to keep the key at `<store-dir>/kms-master.key`. It then checks that `cryptography` is installed and, when the key file already exists, that it is a regular file at mode 0600. A missing file is `result: success` with a note that the first wrap creates it.

The default store is `~/.keyforge/store.json`, so the default key is `~/.keyforge/kms-master.key`. The file is a software KEK. Put `KEYFORGE_KMS_KEY_FILE` outside the store directory if the ciphertext and the wrapping key should sit on different permission boundaries. Anyone who can read both can reveal secrets.

Find the store with `echo "${KEYFORGE_STORE:-$HOME/.keyforge/store.json}"`.

**If you enter `pkcs11`.** Install the binding and a module first (see [Package](#1-package)). Setup uses `KEYFORGE_PKCS11_MODULE` when it is already set, otherwise `/usr/lib/softhsm/libsofthsm2.so`. It does not ask for the module. The path is printed only when that file is missing or unusable. `softhsm2-util` is mentioned only when it is not on `PATH`.

If a token labeled `keyforge` is already in the SoftHSM config (`SOFTHSM2_CONF`, or `~/.keyforge/softhsm/softhsm2.conf`), setup reuses the oldest one as main. Several tokens are listed oldest first, and any except the main token can be deleted. After the user PIN opens that token, setup prints `SOFTHSM2_CONF` and does not ask for it.

If no token is found, setup prints the PKCS#11 field guide and asks for `SOFTHSM2_CONF` only then. It asks for the user PIN and the SO PIN and creates the token itself (`softhsm2-util --init-token`). The SO PIN is not saved. A failed create prints the tool error and asks again. Ctrl-C exits.

A wrong user PIN, during setup and later on `create`, `rotate`, and `reveal`, prints that the PIN is wrong and that Ctrl-C exits, then asks again. A non-interactive stdin fails on the first wrong PIN.

The token label is `keyforge`. Setup then asks for the AES key label when `keyforge-kek` is not already on the token.

If an AES key labeled `keyforge-kek` is already on the token, setup keeps that label and does not ask `KEYFORGE_PKCS11_KEY_LABEL`. Otherwise it asks for `KEYFORGE_PKCS11_KEY_LABEL` (default `keyforge-kek`).

If `keyforge-kek` is absent and other AES keys are on the token, those other keys are deleted and each deletion is printed. If `keyforge-kek` is present, setup lists the keys. A number selects that key. `d` and a number deletes any key except `keyforge-kek`. The user PIN is asked after that choice.

The new-key warning is printed only when the label was just entered, that key is present, and no PIN was saved yet.

A missing AES key is still generated on first use (create, rotate, or reveal). That generation does not ask for a new PIN; it uses the same `KEYFORGE_PKCS11_PIN` already used to open the token session.

The PIN is stored in `keyforge.env` at mode 0600. It is not written to the store or to logs. A later TTY prompt for a missing PIN stays in the process only and is not written back to `keyforge.env`.

`keyforge kms status` reports `provider: pkcs11` and `ready: True`, or lists what is missing. Setup prints that same status at the end under `kms` when it succeeds.

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
5. Turn **off** “Add Permissions in the Access Token” (KeyForge reads a short `scope` claim only; see [Token diet](configuration.md#token-diet)). Leave **Enable RBAC** off. With RBAC off, Auth0 copies the API permissions you requested into the access token `scope` claim. A working setup does not assign those permissions to a user or role. Turning RBAC on makes Auth0 omit any permission that user or role does not have, so login returns missing scopes.
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

The username is the database user (User Management → Users), usually the email. It is not the Client ID. The password is that user's password. It is not the Client Secret. It is sent with Auth0's password-realm grant and is not written to disk. A rejected password prints that it failed and that Ctrl-C exits, then asks for the password again. The username stays. A disabled Password grant, missing Auth0 settings, or a network error stops setup. A non-interactive stdin fails on the first rejection.

The default realm is `Username-Password-Authentication` (`AUTH0_REALM` overrides it). That grant has to be enabled on the Native app.

`auth login` remains a separate device-code command: it prints a URL and a short code, then stores a lean access token (and a refresh token when issued) in `KEYFORGE_TOKEN_FILE` or `~/.keyforge/tokens.json` (mode 0600).

`auth login --from-file response.json` validates a token response you already have; `id_token` is discarded. `auth logout` deletes the token file. `auth login`, `auth status`, and `auth logout` do not require an existing principal.

A successful setup login prints that result at the end under `auth0`: who logged in, scopes, `missing_scopes` when any were withheld, and `expires_at`. Run `keyforge auth status` later for the same view. It never prints the token.

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

Access-token rejection rules: [Token diet](configuration.md#token-diet). Every variable: [Environment](configuration.md#environment). Operator scenarios outside this contract: [Program extensibility](operations.md#program-extensibility).
