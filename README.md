# KeyForge: mock enterprise API key manager

> ⚠️ **MOCK / DEMO ONLY. NOT FOR PRODUCTION.** It has no real secret storage, no HSM/KMS, and no authN/authZ on the CLI itself.

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
0 ok · 1 error · 2 usage/validation · 3 not found · 4 verification failed · 5 policy violation · 6 aborted (no confirmation) · 8 store locked (lock wait timed out)

## Tests
    python -m unittest discover -s tests -v     # or: pytest

## Release notes

### Unreleased: import hardening
- The store now keeps `revoked_hashes`, a list that `purge` never clears. It holds the id, prefix and hash of every key that was revoked, or rotated and then purged. `import` rejects any record that matches an entry on this list, whatever the record's status. The same applies to another existing key's hash or prefix. `--allow-unrevoke` overrides this. `update` (extending or clearing expiry) and `resume` refuse to revive a key whose credential is on the list.
- **Known gap:** keys revoked or rotated and then **purged before this change** were never recorded, so these checks can't catch them. If you need protection for them, restore them from an older export as revoked records. Matching ids are allowed.
