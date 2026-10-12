"""Append-only (mock) audit log stored alongside keys.

Integrity
- Every event carries ``prev_hash`` (previous event's hash, or GENESIS) and ``hash`` = SHA-256 over
  the canonical JSON bytes of the event minus ``hash``/``mac`` (sorted keys, compact separators,
  no ``default=str``: events are normalized to plain JSON before hashing, so the hashed bytes are
  exactly what round-trips through the store).
- ``store.data["audit_meta"]`` holds ``legacy`` (events that pre-date chaining, fixed when chaining
  starts), ``count`` and ``head``. Verification fails if these disagree with the log, so stripping
  ``hash``/``prev_hash`` from events or truncating the tail is detected.
- Optional HMAC: if ``$KEYFORGE_AUDIT_HMAC_KEY_FILE`` names a file (kept outside the store), each
  new event gets ``mac`` = HMAC-SHA256(key, hash) and the metadata is MAC'd too, so someone who can
  edit the store but not read the key cannot rebuild a valid chain.

Attribution: KEYFORGE_ACTOR and SUDO_USER are *claims* (env vars); ``os_user``/``os_uid`` come
from the process uid and are what to trust.
"""
from __future__ import annotations
import getpass, hashlib, hmac, json, os, sys
from .errors import KeyForgeError
from .models import iso, now, parse_iso

GENESIS = "0" * 64

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

def os_user() -> tuple[str, int | None]:
    """The real account running this process, from the uid (not spoofable via env vars)."""
    try:
        uid = os.getuid()
    except AttributeError:  # non-POSIX
        return "unknown", None
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name, uid
    except (ImportError, KeyError):
        return f"uid:{uid}", uid

def actor() -> str:
    """Claimed actor: KEYFORGE_ACTOR if set, else the login name. Informational only."""
    try:
        return os.environ.get("KEYFORGE_ACTOR") or getpass.getuser()
    except Exception:
        return "unknown"

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
        raise KeyForgeError(f"audit HMAC key file {p} unusable: {e.strerror}")
    try:
        st = os.fstat(fd)
        if st.st_mode & 0o077:
            raise KeyForgeError(f"audit HMAC key file {p} must not be group/world accessible (chmod 600)")
        with os.fdopen(fd, "rb") as f:
            fd = None
            k = f.read().strip()
    finally:
        if fd is not None: os.close(fd)
    if len(k) < 16:
        raise KeyForgeError("audit HMAC key file must contain at least 16 bytes")
    return k

def entry_hash(ev: dict) -> str:
    return hashlib.sha256(canonical({k: v for k, v in ev.items() if k not in ("hash", "mac")})).hexdigest()

def _mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

def _meta_msg(m: dict) -> str:
    return f"{m.get('legacy')}|{m.get('count')}|{m.get('head')}|{m.get('hmac_from')}"

def record(store, action: str, key_id: str | None = None, **details) -> dict:
    log = store.audit_log
    meta = store.data.get("audit_meta")
    if meta is None:
        if log:
            return _record_unchained(store, action, key_id, details)
        meta = store.data["audit_meta"] = {"legacy": 0, "count": 0, "head": GENESIS}  # empty log only
    user, uid = os_user()
    ev = {"ts": iso(now()), "actor": actor(), "os_user": user, "os_uid": uid, "action": action,
          "key_id": key_id, "details": {k: v for k, v in details.items() if v is not None},
          "prev_hash": meta["head"] if len(log) == meta["count"] else (log[-1].get("hash") if log else GENESIS)}
    sudo = os.environ.get("SUDO_USER")
    if sudo:
        ev["sudo_user_claim"] = sudo[:64]  # unverified: env var
    ev = json.loads(canonical(ev))  # normalize to exactly what will be stored (raises on non-JSON)
    ev["hash"] = entry_hash(ev)
    # Writes are never blocked by a key problem (a revoke must always land). Instead the event is
    # stored without a MAC, flagged, and a warning printed; `audit --verify` with the key then fails.
    try:
        key = hmac_key()
    except KeyForgeError as e:
        key = None
        ev["hmac_error"] = str(e)[:200]; ev["hash"] = entry_hash(ev)
        meta.pop("mac", None)
        print(f"keyforge: warning: audit event written WITHOUT HMAC: {e}", file=sys.stderr)
    if key:
        meta.setdefault("hmac_from", len(log))
        ev["mac"] = _mac(key, ev["hash"])
    log.append(ev)
    meta["count"] = len(log); meta["head"] = ev["hash"]
    if key:
        meta["mac"] = _mac(key, _meta_msg(meta))
    return ev

def _record_unchained(store, action, key_id, details) -> dict:
    """Metadata is missing on a non-empty log: never re-create it implicitly (that would bless a
    stripped log). The event is still written, so security-critical writes like revoke persist, but
    it is flagged and unchained; verify keeps failing (exit 7) until `audit --adopt-legacy`."""
    user, uid = os_user()
    ev = {"ts": iso(now()), "actor": actor(), "os_user": user, "os_uid": uid, "action": action,
          "key_id": key_id, "details": {k: v for k, v in details.items() if v is not None},
          "chain_error": "audit_meta missing on non-empty log; event not chained"}
    sudo = os.environ.get("SUDO_USER")
    if sudo:
        ev["sudo_user_claim"] = sudo[:64]
    ev = json.loads(canonical(ev))
    store.audit_log.append(ev)
    print("keyforge: warning: audit metadata missing; event written UNCHAINED "
          "(audit --verify will fail until `audit --adopt-legacy`)", file=sys.stderr)
    return ev

def verify_chain(log: list, meta: dict | None = None, key: bytes | None = None) -> dict:
    """Check the hash chain against the metadata. Returns
    {"ok", "checked", "legacy", "count", "head", "mac_verified", "error", "index"}."""
    res = {"ok": True, "checked": 0, "legacy": 0, "count": len(log), "head": GENESIS,
           "mac_verified": False, "error": None, "index": None}
    def fail(msg, i=None): return {**res, "ok": False, "error": msg, "index": i}
    if meta is None:
        # New stores always get audit_meta at creation and old stores get it on their first new
        # event, so missing metadata means it was deleted (or the store predates chaining and
        # needs an explicit `audit --adopt-legacy`).
        return fail("audit metadata missing (deleted, or legacy store not adopted: run `audit --adopt-legacy`)")
    legacy = meta.get("legacy")
    if not isinstance(legacy, int) or not 0 <= legacy <= len(log):
        return fail("audit metadata has an invalid legacy count")
    if key:
        if "mac" not in meta or not hmac.compare_digest(meta["mac"], _mac(key, _meta_msg(meta))):
            return fail("audit metadata MAC invalid")
    prev = GENESIS
    for i, ev in enumerate(log):
        if i < legacy:
            if "hash" in ev or "prev_hash" in ev:
                return fail(f"event {i} is chained but recorded as legacy", i)
            res["legacy"] += 1; continue
        if "hash" not in ev or "prev_hash" not in ev:
            return fail(f"event {i} is missing hash/prev_hash (stripped?)", i)
        if ev["prev_hash"] != prev:
            return fail(f"event {i}: prev_hash mismatch (event removed, inserted or reordered)", i)
        if entry_hash(ev) != ev["hash"]:
            return fail(f"event {i}: content hash mismatch (event modified)", i)
        if key and i >= meta.get("hmac_from", len(log)):
            if "mac" not in ev or not hmac.compare_digest(ev["mac"], _mac(key, ev["hash"])):
                return fail(f"event {i}: MAC invalid or missing", i)
        prev = ev["hash"]; res["checked"] += 1
    if meta.get("count") != len(log):
        return fail(f"event count {len(log)} != recorded {meta.get('count')} (events added or truncated)")
    if meta.get("head") != prev:
        return fail("head hash does not match metadata")
    res["head"] = prev; res["mac_verified"] = bool(key)
    return res

def adopt_legacy(store) -> dict:
    """Explicitly start chaining on a store that has only legacy events and no metadata."""
    if store.data.get("audit_meta") is not None:
        raise KeyForgeError("audit chain already initialized")
    if any("hash" in e or "prev_hash" in e for e in store.audit_log):
        raise KeyForgeError("log contains chained events but no metadata: refusing to adopt (possible tampering)")
    n = len(store.audit_log)
    store.data["audit_meta"] = {"legacy": n, "count": n, "head": GENESIS}
    return record(store, "audit_adopt_legacy", None, legacy=n)

def query(store, key_id=None, action=None, since=None, limit=None) -> list[dict]:
    out = store.audit_log
    if key_id:
        out = [e for e in out if e.get("key_id") == key_id]
    if action:
        out = [e for e in out if e["action"] == action]
    if since:
        out = [e for e in out if parse_iso(e["ts"]) >= since]
    return out[-limit:] if limit else list(out)
