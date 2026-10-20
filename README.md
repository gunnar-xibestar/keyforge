# KeyForge

An educational local API key manager. KeyForge stores salted password hashes for verification and encrypted secret envelopes for reveal. Operator access can optionally use Auth0.

A key has the form `kf_<env>_<32 random chars>`. `create` and `rotate` print the secret once.

> KeyForge is designed for local use and demonstration. The built-in HTTP server is not a production gateway.

## What it does

- Create, verify, reveal, rotate, suspend, resume, and revoke API keys.
- Store a PBKDF2-HMAC-SHA256 hash and an AES-256-GCM encrypted envelope; never store the plaintext secret.
- Wrap data-encryption keys with a local software key by default, or an optional PKCS#11 token.
- Optionally gate operator commands with Auth0 scopes.
- Record changes in an audit log with a hash chain and optional HMAC integrity check.

## Quick start

Requires Python 3.10+ and `cryptography`.

```sh
pip install -e .
keyforge setup
keyforge create --name demo --owner you --scope read:packets
```

Setup defaults to the local KMS provider. At the Auth0 prompt, answer `n` for a local-only setup; without Auth0, commands trust the current OS user. The generated secret is printed once; save it somewhere safe. Verify it by pasting the secret at the prompt:

```sh
keyforge verify -
keyforge list
```

See [Setup and KMS](docs/setup.md) for provider configuration, PKCS#11/SoftHSM, and Auth0 setup.

## Commands

| command | purpose |
|---|---|
| `create --name --owner [options]` | Create a key; print its secret once |
| `list [filters]` / `show KEY` | List keys or show metadata |
| `verify SECRET/- [--scope S] [--ip IP]` | Verify without decrypting; `-` reads from stdin |
| `reveal KEY` | Decrypt and print a stored secret |
| `rotate KEY` / `revoke KEY` | Replace a key or revoke it permanently |
| `suspend KEY` / `resume KEY` / `update KEY ...` | Change key status or settings |
| `audit [options]` | Query the audit log; `--verify` checks its integrity chain |
| `policy show/set/reset` | View or change organization policy |
| `export` / `import FILE` | Export or import hashes and envelopes, never plaintext |
| `purge [options]` | Delete expired and post-grace keys |
| `setup` | Configure KMS and optional Auth0 |
| `auth login/status/logout` | Manage the local Auth0 token |
| `kms status` | Show KMS provider readiness |
| `serve` | Run the demo HTTP server |
| `uninstall` | Remove KeyForge data under `~/.keyforge` |

Global options include `--store PATH` and `--json`. Destructive commands prompt for confirmation; use `--yes` for non-interactive use, or `--dry-run` where supported. See `keyforge COMMAND --help` for complete options.

### Operator scopes

When Auth0 is enabled, commands require operator scopes. `keys:read` covers listing and inspection, `keys:write` covers key and policy changes, `keys:verify` covers verification and serving, and `reveal:secret` covers reveal. Missing scope exits with code 4. These are separate from scopes granted to API keys.

## Security model

`verify` checks a salted PBKDF2-HMAC-SHA256 hash and never decrypts. `reveal` unwraps the data key, decrypts the AES-256-GCM envelope, and checks the result against the hash before printing. The envelope is bound to its key record, so moving it to another record fails.

The default local KMS stores a software wrapping key on disk. Anyone who can read both that key and the store can reveal secrets. For a stronger separation, keep the KMS key outside the store directory or configure a PKCS#11 token. See [Setup and KMS](docs/setup.md) and [Audit integrity](docs/audit-integrity.md) for details and limitations.

## Optional guides

- [Setup and KMS](docs/setup.md) — local key storage, PKCS#11/SoftHSM, Auth0 setup, and login.
- [Demo HTTP server](docs/demo-server.md) — routes and a walkthrough using a test key.
- [Audit integrity](docs/audit-integrity.md) — hash chain, HMAC, legacy adoption, and limitations.
- [Configuration](docs/configuration.md) — environment variables and token validation rules.
- [Operations and extensibility](docs/operations.md) — import hardening, uninstall, and extension points.

## Development

Run the test suite with:

```sh
python -m unittest discover -s tests -v
```

## Exit codes

| code | meaning |
|---|---|
| 0 | Success |
| 1 | Error, including authentication failure |
| 2 | Usage or validation error |
| 3 | Not found |
| 4 | Verification failure or missing Auth0 scope |
| 5 | Policy violation |
| 6 | Operation aborted |
| 7 | Audit log integrity check failed |
| 8 | Store locked |
