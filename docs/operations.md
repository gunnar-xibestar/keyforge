## Import hardening

- The store keeps `revoked_hashes`. `purge` never clears it. `import` rejects a record whose hash or prefix matches a revoked or retired credential, unless `--allow-unrevoke` is set. `resume` and extending an expiry refuse the same match.
- Imported envelopes are checked for shape. A bad envelope aborts the import. Revealing an imported envelope only works with the same KMS key that wrapped it.
- **Known gap:** keys revoked or rotated and then purged before `revoked_hashes` existed were never recorded. Restore them from an older export as revoked records if you need that protection.

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

Notes that are useful beyond this page, including Auth0 operator use cases, live in [Extensibility](../EXTENSIBILITY.md).
