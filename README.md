# KeyForge: mock enterprise API key manager

> ⚠️ **MOCK / DEMO ONLY. NOT FOR PRODUCTION.** It has no real secret storage, no HSM/KMS, no locking for concurrent writers, and no authN/authZ on the CLI itself.

Pure-stdlib Python 3.10+. Keys look like `kf_<env>_<32 random chars>`. The full secret is printed **once** at create/rotate time. Only a salted PBKDF2-HMAC-SHA256 hash plus the display prefix (`kf_live_AbCd1234`) is stored.

## Install
    pip install -e .        # provides the `keyforge` command
    python -m keyforge ...  # or run without installing

Store: `--store PATH`, or `$KEYFORGE_STORE`, or `~/.keyforge/store.json` (JSON, written atomically, mode 0600).

## Commands
| command | purpose |
|---|---|
| `create --name --owner [--team] [--env live/test] [--scope S]... [--expires-in 30d / --expires-at ISO] [--rate-limit N] [--ip-allow CIDR]... [--label k=v]... [--description] [--dry-run]` | new key |
| `list [--owner --team --env --status --scope GLOB --label k=v] [--format table/json/csv]` | list keys |
| `show KEY` | details (KEY = id, prefix or unique name) |
| `verify SECRET/- [--scope S] [--ip IP]` | check a secret (exit 4 if invalid) |
| `rotate KEY [--grace-period 24h] [--dry-run] [--yes]` | new secret; old one stays valid during the grace period |
| `revoke KEY [--reason] [--dry-run] [--yes]` | permanent |
| `suspend KEY` / `resume KEY` | temporary disable |
| `update KEY [--add-scope/--remove-scope] [--label k=v/--unset-label] [--add-ip/--remove-ip] [--expires-in/--expires-at/--no-expiry] [--rate-limit] [--description] [--dry-run]` | modify |
| `audit [--key --action --since 24h/ISO --limit N] [--export FILE]` | audit log |
| `policy show` / `policy set FIELD VALUE` / `policy reset` | org rules: `max_ttl`, `require_expiry`, `allowed_scopes` (globs), `required_labels`, `max_rate_limit`, `live_requires_ip_allow`, `default_grace_period` |
| `export [-o FILE] [--include-audit]` / `import FILE [--overwrite] [--dry-run]` | backup and migration (hashes only) |
| `purge [--older-than 7d] [--include-revoked] [--dry-run] [--yes]` | delete expired keys and rotated keys past their grace period |

Global: `--json` (machine output), `--store`. Destructive commands prompt for confirmation. When stdin is not a TTY they refuse unless `--yes` is given.

Scopes take the form `resource:action`, and grants may be globs (`read:*`).
Statuses: active, suspended, revoked, expired, grace (rotated, old key still valid), rotated.

## Exit codes
0 ok · 1 error · 2 usage/validation · 3 not found · 4 verification failed · 5 policy violation · 6 aborted (no confirmation) · 7 audit log tampered (`audit --verify`)

## Tests
    python -m unittest discover -s tests -v     # or: pytest

## Audit integrity
- `audit --verify` checks the hash chain and `audit_meta` (legacy count, event count, head). It exits 7 on any mismatch, including missing metadata.
- Stores from before hash-chaining have no metadata. Run `audit --adopt-legacy` once to start the chain. Existing events stay unprotected, and the adoption is itself audited.
- Optional HMAC: set `KEYFORGE_AUDIT_HMAC_KEY_FILE` to a file of at least 16 bytes, mode 0600, kept outside the store. If the key is missing or unusable, writes still succeed (a revoke is never blocked), but the event is stored without a MAC, a warning goes to stderr, and a later keyed `audit --verify` fails.
