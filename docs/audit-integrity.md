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
| `audit_hmac_enabled` | setup, the first time it loads an HMAC key while `audit_meta` has no `mac`. That event is `hmac_from`. Events before it have no MAC. Later events must have a MAC from that key. The row has no `key_id` because it records the chain, not an API key. |

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

What fails: a missing `hash` or `prev_hash` on a chained event; a `prev_hash` that does not match the previous event; a content hash that does not match the body; a `count` or `head` that does not match the log; a bad per-event MAC when a key is in use. A metadata MAC that does not match this same key is not a broken chain when at least one event MAC from `hmac_from` onward already verified and `count` and `head` match the log. With no event MAC checked, that metadata MAC is still a failure.

### Error output

`keyforge setup` prints only the summary line. `keyforge audit --verify` prints that same line, then a `checks` list. A failure exits **7**. The summary is `AUDIT CHAIN BROKEN:` plus one message. In these messages, `N` and `M` are displayed event numbers starting at 1, with the stored 0-based index in parentheses immediately beside the number (the first event in the log is `1(0)`). A walk of 23 events is `checked events 1(0) through 23(22)`. `hmac_from` shown to humans is that same form, for example `hmac_from is 22(21)`. The last-event line is `last event 23(22)`. The stored list index and the stored `hmac_from` field stay 0-based.

| Gate | Summary message |
|---|---|
| Missing `hash` or `prev_hash` | `event N is missing hash/prev_hash (stripped?)` |
| `prev_hash` does not match the previous event | `event N: prev_hash mismatch (event removed, inserted or reordered)` |
| Content hash does not match the body | `event N: content hash mismatch (event modified)` |
| Event MAC missing | `event N: MAC missing.` Then a blank line between each source: `chain:` (`hmac_from`), `hash:` (SHA-256 of the event with hash and mac removed, and `prev_hash`), `mac:` (no mac field), `write:` (`none recorded`, or the stored write-time reason such as `KEYFORGE_AUDIT_HMAC_KEY_FILE` unset, a path that could not be read, or a mode other than 0600), and `event:` with `ts`, `action`, `key_id`, `actor`, and `os_user` on their own lines. |
| Event MAC present, but it is not the HMAC of the event hash under the loaded key | `warning: event N: the computed HMAC does not match the stored mac.` The chain stays OK. `HMAC INVALID for event N`. If earlier event MACs matched, `HMAC VALID for events M through N-1`. |
| `count` does not match the log length | `event count A != recorded B (events added or truncated)` |
| `head` does not match the last chained hash | `head hash does not match metadata` |
| Metadata MAC wrong, and no event MAC was checked | `audit metadata MAC invalid` |
| MACs are present and the HMAC key was not supplied | `HMAC key required: the audit chain has MACs, but KEYFORGE_AUDIT_HMAC_KEY_FILE is unset in this process.` `keyforge.env` has no line for it. Setup used to drop that line when it rewrote the file while the variable was already set. Verify does not open `~/.keyforge/audit-hmac.key` unless the variable names that file. |

A stale metadata MAC does not get its own summary line. The summary stays `audit chain OK: …, MAC verified`.

`audit --verify` then prints each check as `[ok]`, `[FAIL]`, or `[skip]`:

| Gate | Check row |
|---|---|
| Event hashes and `prev_hash` | `hash chain continuity and content hashes` |
| `count` | `count matches log length` |
| `head` | `head matches last chained hash` |
| Event MACs from `hmac_from` | `event MACs from hmac_from` |
| Metadata MAC | `audit_meta MAC` |

The `audit_meta MAC` row is a strict compare. When event MACs pass and the metadata MAC is stale, the summary says `audit chain OK` and that row still shows `[FAIL] audit_meta MAC`. Setup rewrites only `audit_meta.mac` with the existing HMAC key in that case. It does not change event hashes.

Legacy events (indices below `legacy`) are counted and skipped: they are not hashed. On success the command prints `audit chain OK` with the chained-event count, the log count, and the head, plus `MAC verified` when the key checked out.

The checks list prints `count` and `head` once. Each row then shows only data that belongs to that check. A passing row has no extra fields. A failing `audit_meta MAC` row uses the same blank-line blocks: `tag:` (the stored tag is not HMAC-SHA256 of `legacy|count|head|hmac_from`), `values:` (`count` and `head` above), and `chain:` (a later event can be appended without refreshing the tag). A failing event-MAC row repeats the same `chain` / `hash` / `mac` / `write` / `event` blocks as the summary. A **keys and chain events** section matches `list` keys to audit events by `key_id` (event counts and actions per key), plus orphan events whose `key_id` is no longer in the store and chain events with no `key_id` (each with **date**, **ts**, **action**, and a **reason**). A long reason stays in the REASON column and continues on the next lines: `audit_hmac_enabled` is `setup:`, `expected:`, and one `missing:` block whose last sentence is the consequence. `--json` includes the same `checks` and `match` objects.

If the chain already has MACs (`audit_meta.mac` or `hmac_from`) but `KEYFORGE_AUDIT_HMAC_KEY_FILE` is unset, verify **fails** — the secret file is required to check those tags. HMAC checks are **skip**ped only when the chain never had MACs (never keyed).

**`keyforge setup`.** After the KMS choice is saved, setup prints an `Audit chain` title, the store path, then runs the same check as `audit --verify`. It does not exit 7 on failure; it prints `AUDIT CHAIN BROKEN: …` and continues. On success it prints the same `audit chain OK` line.

Setup also repairs and hardens when it can:

1. If `audit_meta` is absent and the log has no hashed events, setup runs the same path as `audit --adopt-legacy`, then says those legacy events cannot be checked for tampering.
2. If no key file exists at `KEYFORGE_AUDIT_HMAC_KEY_FILE` (default `<store-dir>/audit-hmac.key` when unset), setup creates one (32 random bytes, mode 0600), saves the path into `keyforge.env`, and explains why. If the file already exists, it prints `audit HMAC key found: …` and reuses that secret — setup does not mint a new key on every run.
3. The first time a usable key is present and metadata has no `mac` yet, setup writes one `audit_hmac_enabled` event so the MAC starts at that event. Events before it stay without a MAC.
4. If `audit_meta.mac` does not match the existing HMAC key, but the event hashes, the event MACs, `count`, and `head` do, setup rewrites only that metadata MAC. It prints `metadata MAC rewritten with the existing HMAC key.` Event hashes are not changed.

After the check, setup reports HMAC status (with blank lines between groups):

- If a valid chain and a matching HMAC secret were already in place, it prints `HMAC: on, verified, working` with the secret path and chain details (`chained` count, `count`, `head`). `audit --verify` will check both the hash chain and the HMAC tags.
- If setup just created the key (or is enabling MAC for the first time), it prints `HMAC: on and verified for new events`, explains that later setups reuse the file, then warns that deleting that secret later makes `audit --verify` fail until it is restored (the chain already has MACs).
- If no usable HMAC secret is found, it warns that HMAC is not verifying the chain: a MAC'd chain fails verify until the matching secret is restored; a never-keyed chain stays unkeyed.

### Adopting a pre-chain store

Stores from before hash-chaining have events and no `audit_meta`.

`audit --adopt-legacy` (and setup, when metadata is absent) records that count as `legacy`, sets `head` to the 64 zeros, and appends a chained `audit_adopt_legacy` event. Those older events stay without hashes. The adoption event is chained.

If the log already contains hashed events but the metadata is gone, adopt refuses: recreating the metadata would bless a stripped log.

### What the chain does and does not catch

Until MACs are enabled, the chain is unkeyed: anyone who can write the store can edit an event and recompute `prev_hash`, `hash`, `count`, and `head`, and `audit --verify` still passes. After MACs exist, deleting or unsetting the HMAC key makes verify fail until the secret is restored (or the store is replaced). The MAC still only detects a rewritten store when the writer cannot read the key file.

The HMAC key file must contain at least 16 bytes, mode 0600, and must not be a symlink. With that key, a writer who cannot read the file cannot produce valid event or metadata MACs.

Default setup puts `audit-hmac.key` next to the store. Anyone who can read that directory can still forge a chain that verifies. Move the file somewhere store writers cannot read it when you need the MAC to mean tamper evidence.

Events before `hmac_from`, and every legacy event, still have no MAC. Rewriting only those events is not detected as keyed tampering.

`actor` can be overridden with `KEYFORGE_ACTOR`. Trust `os_user` / `os_uid` for who ran the process.
