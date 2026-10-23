from __future__ import annotations
import hashlib, hmac, json, os
from ..errors import KeyForgeError

GENESIS = "0" * 64

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

def hmac_key() -> bytes | None:
    """Load the optional audit HMAC key from $KEYFORGE_AUDIT_HMAC_KEY_FILE.

    Raises KeyForgeError if the variable is set but the file is missing, unreadable, too short,
    a symlink, or accessible by group/other (mode must be 0600 or stricter)."""
    p = os.environ.get("KEYFORGE_AUDIT_HMAC_KEY_FILE")
    if not p:
        return None
    p = os.path.expanduser(p)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise KeyForgeError(
            f"KEYFORGE_AUDIT_HMAC_KEY_FILE is {p}. The file could not be read ({e.strerror})."
        )
    try:
        st = os.fstat(fd)
        if st.st_mode & 0o077:
            raise KeyForgeError(
                f"KEYFORGE_AUDIT_HMAC_KEY_FILE is {p}. Mode is {oct(st.st_mode & 0o777)}; "
                "expected 0600 (chmod 600)."
            )
        with os.fdopen(fd, "rb") as f:
            fd = None
            k = f.read().strip()
    finally:
        if fd is not None: os.close(fd)
    if len(k) < 16:
        raise KeyForgeError(
            f"KEYFORGE_AUDIT_HMAC_KEY_FILE is {p}. The file has {len(k)} bytes; at least 16 are required."
        )
    return k

def entry_hash(ev: dict) -> str:
    return hashlib.sha256(canonical({k: v for k, v in ev.items() if k not in ("hash", "mac")})).hexdigest()

def _mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def _shown(index: int) -> str:
    """Human event number with the stored index beside it: ``1(0)``. List indexes stay 0-based."""
    return f"{index + 1}({index})"


def _event_facts(ev: dict) -> str:
    """Fields stored on the event, one per line."""
    lines = []
    for name in ("ts", "action", "key_id", "actor", "os_user"):
        value = ev.get(name)
        if value is None or value == "":
            continue
        lines.append(f"  {name}: {value}")
    if not lines:
        return ""
    return "event:\n" + "\n".join(lines)


def _event_mac_error(i: int, ev: dict, key: bytes, hmac_from: int) -> str | None:
    """Why this event's MAC failed under ``key``. None when the MAC matches.

    The hash chain has already matched through this event.
    """
    if "mac" not in ev:
        write_time = ev.get("hmac_error")
        if write_time:
            why = f"write: {write_time}"
        else:
            why = "write: none recorded"
        blocks = [
            f"event {_shown(i)}: MAC missing.",
            (
                f"chain: hmac_from is {_shown(hmac_from)}, so this event must carry a MAC "
                "from the loaded HMAC key."
            ),
            (
                "hash: the stored hash equals SHA-256 of this event with hash and mac removed, "
                "and prev_hash links to the previous event."
            ),
            "mac: there is no mac field.",
            why,
        ]
        facts = _event_facts(ev)
        if facts:
            blocks.append(facts)
        return "\n\n".join(blocks)
    return None


def _event_mac_warning(i: int, ev: dict, key: bytes, hmac_from: int, matched_through: int) -> str | None:
    """Warning when the computed HMAC and the stored ``mac`` differ.

    The hash chain has already matched. This is not a broken chain: the loaded key's
    HMAC-SHA256 of the event hash is not the stored mac.
    """
    if "mac" not in ev:
        return None
    if hmac.compare_digest(ev["mac"], _mac(key, ev["hash"])):
        return None
    if matched_through < hmac_from:
        span = f"HMAC INVALID for event {_shown(i)}. This is the first event that must have a MAC."
    elif matched_through == i - 1:
        span = (
            f"HMAC VALID for events {_shown(hmac_from)} through {_shown(matched_through)}. "
            f"HMAC INVALID for event {_shown(i)}."
        )
    else:
        span = f"HMAC INVALID for event {_shown(i)}."
    return (
        f"warning: event {_shown(i)}: the computed HMAC does not match the stored mac. {span} "
        "The loaded HMAC key produces HMAC-SHA256 of this event's hash, and that value "
        "is not the stored mac. The hash chain matches through this event."
    )

def _meta_msg(m: dict) -> str:
    return f"{m.get('legacy')}|{m.get('count')}|{m.get('head')}|{m.get('hmac_from')}"

def _chain_expects_hmac(meta: dict) -> bool:
    """True when the store already carries audit MACs that need the HMAC key file."""
    return "mac" in meta or isinstance(meta.get("hmac_from"), int)


def verify_chain(log: list, meta: dict | None = None, key: bytes | None = None) -> dict:
    """Check the hash chain against the metadata. Returns
    {"ok", "checked", "legacy", "count", "head", "mac_verified", "error", "index"}.

    If the chain already has MACs (``audit_meta.mac`` or ``hmac_from``) but no HMAC key is
    supplied, verification fails — the secret must be present to check those tags.
    """
    res = {"ok": True, "checked": 0, "legacy": 0, "count": len(log), "head": GENESIS,
           "mac_verified": False, "error": None, "index": None, "warnings": []}
    def fail(msg, i=None): return {**res, "ok": False, "error": msg, "index": i}
    if meta is None:
        # New stores always get audit_meta at creation and old stores get it on their first new
        # event, so missing metadata means it was deleted (or the store predates chaining and
        # needs an explicit `audit --adopt-legacy`).
        return fail("audit metadata missing (deleted, or legacy store not adopted: run `audit --adopt-legacy`)")
    legacy = meta.get("legacy")
    if not isinstance(legacy, int) or not 0 <= legacy <= len(log):
        return fail("audit metadata has an invalid legacy count")
    if _chain_expects_hmac(meta) and not key:
        return fail(_hmac_key_missing_message())
    meta_mac_ok = True
    if key:
        expected = _mac(key, _meta_msg(meta))
        meta_mac_ok = "mac" in meta and hmac.compare_digest(meta["mac"], expected)
    hmac_from = meta.get("hmac_from", len(log))
    if not isinstance(hmac_from, int):
        hmac_from = len(log)
    prev = GENESIS
    event_macs = 0
    matched_through = hmac_from - 1
    errors: list[str] = []
    first_index = None
    def note(msg: str, i: int | None = None) -> None:
        nonlocal first_index
        errors.append(msg)
        if i is not None and first_index is None:
            first_index = i
    for i, ev in enumerate(log):
        if i < legacy:
            if "hash" in ev or "prev_hash" in ev:
                note(f"event {_shown(i)} is chained but recorded as legacy", i)
            else:
                res["legacy"] += 1
            continue
        if "hash" not in ev or "prev_hash" not in ev:
            note(f"event {_shown(i)} is missing hash/prev_hash (stripped?)", i)
            continue
        if ev["prev_hash"] != prev:
            note(f"event {_shown(i)}: prev_hash mismatch (event removed, inserted or reordered)", i)
        if entry_hash(ev) != ev["hash"]:
            note(f"event {_shown(i)}: content hash mismatch (event modified)", i)
        if key and i >= hmac_from:
            mac_error = _event_mac_error(i, ev, key, hmac_from)
            if mac_error:
                note(mac_error, i)
            else:
                mac_warning = _event_mac_warning(i, ev, key, hmac_from, matched_through)
                if mac_warning:
                    res["warnings"].append(mac_warning)
                else:
                    event_macs += 1
                    matched_through = i
        prev = ev["hash"]
        res["checked"] += 1
    if meta.get("count") != len(log):
        note(f"event count {len(log)} != recorded {meta.get('count')} (events added or truncated)")
    if meta.get("head") != prev:
        note("head hash does not match metadata")
    # A metadata MAC that does not match is stale, not a broken chain, when this same
    # key already verifies at least one event MAC and the hash chain, count, and head agree.
    # With no event MAC to check, the metadata tag is the only keyed check and still fails closed.
    if key and not meta_mac_ok:
        if event_macs == 0:
            note("audit metadata MAC invalid")
        else:
            res["meta_mac_stale"] = True
    res["head"] = prev
    res["walked"] = len(log)
    res["walked_last"] = len(log) - 1 if log else None
    res["walk_continued"] = bool(errors) and first_index is not None and bool(log) and first_index < len(log) - 1
    if log:
        res["last_event"] = {"index": len(log) - 1, "fields": dict(log[-1])}
    res["mac_verified"] = bool(key) and meta_mac_ok and event_macs > 0 and not errors
    if errors:
        res["ok"] = False
        res["error"] = errors[0]
        res["errors"] = errors
        res["index"] = first_index
        return res
    return res


def reseal_metadata_mac(store, key: bytes | None) -> bool:
    """Rewrite ``audit_meta.mac`` with ``key`` when the event chain already verifies.

    Event hashes and event MACs are left as they are. Returns True when a new metadata
    MAC was stored. A chain that does not verify under ``key`` is not modified.
    """
    if not key:
        return False
    meta = store.data.get("audit_meta")
    if not isinstance(meta, dict):
        return False
    result = verify_chain(store.audit_log, meta, key)
    if not result.get("ok") or not result.get("meta_mac_stale"):
        return False
    meta["mac"] = _mac(key, _meta_msg(meta))
    return True


def _hmac_key_missing_message() -> str:
    """Why verify cannot check MACs: the variable is empty in this process."""
    raw = os.environ.get("KEYFORGE_AUDIT_HMAC_KEY_FILE")
    if raw is not None and str(raw).strip():
        return (
            "HMAC key required: KEYFORGE_AUDIT_HMAC_KEY_FILE is set in this process, "
            "but no key bytes were passed to verify."
        )
    return (
        "HMAC key required: the audit chain has MACs, but KEYFORGE_AUDIT_HMAC_KEY_FILE "
        "is unset in this process. keyforge.env has no line for it, and the shell did not "
        "export it. Setup used to rewrite that file without the line when the variable was "
        "already set in the setup process, so the next command lost it. Verify does not open "
        "the default ~/.keyforge/audit-hmac.key unless the variable names the file. "
        "The store still has mac and hmac_from from an earlier process that had the key."
    )
