"""Append-only (mock) audit log stored alongside keys.

Integrity: every event carries ``prev_hash`` (hash of the previous event, or GENESIS) and ``hash``
(SHA-256 over the canonical JSON of the event without ``hash``). ``verify_chain`` detects edits,
deletions and reordering of events. The actor named via KEYFORGE_ACTOR is only a *claim*; the
real OS account (from the process uid) is always recorded next to it as ``os_user``/``os_uid``.
"""
from __future__ import annotations
import getpass, hashlib, json, os
from .models import iso, now, parse_iso

GENESIS = "0" * 64

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

def entry_hash(ev: dict) -> str:
    body = {k: v for k, v in ev.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def head(log: list) -> str:
    for ev in reversed(log):
        if "hash" in ev:
            return ev["hash"]
    return GENESIS

def record(store, action: str, key_id: str | None = None, **details) -> dict:
    user, uid = os_user()
    ev = {"ts": iso(now()), "actor": actor(), "os_user": user, "os_uid": uid, "action": action,
          "key_id": key_id, "details": {k: v for k, v in details.items() if v is not None},
          "prev_hash": head(store.audit_log)}
    ev["hash"] = entry_hash(ev)
    store.audit_log.append(ev)
    return ev

def verify_chain(log: list) -> dict:
    """Check the hash chain. Returns {"ok", "checked", "legacy", "head", "error", "index"}.

    Events written before chaining existed (no ``hash`` field) are allowed only as a leading
    prefix and are counted as ``legacy``; they are not integrity protected.
    """
    res = {"ok": True, "checked": 0, "legacy": 0, "head": GENESIS, "error": None, "index": None}
    prev, chained = GENESIS, False
    for i, ev in enumerate(log):
        if "hash" not in ev:
            if chained:
                return {**res, "ok": False, "index": i, "error": f"event {i} is missing its hash"}
            res["legacy"] += 1; continue
        chained = True
        if ev.get("prev_hash") != prev:
            return {**res, "ok": False, "index": i,
                    "error": f"event {i}: prev_hash mismatch (event removed, inserted or reordered)"}
        if entry_hash(ev) != ev["hash"]:
            return {**res, "ok": False, "index": i, "error": f"event {i}: content hash mismatch (event modified)"}
        prev = ev["hash"]; res["checked"] += 1
    res["head"] = prev
    return res

def query(store, key_id=None, action=None, since=None, limit=None) -> list[dict]:
    out = store.audit_log
    if key_id:
        out = [e for e in out if e.get("key_id") == key_id]
    if action:
        out = [e for e in out if e["action"] == action]
    if since:
        out = [e for e in out if parse_iso(e["ts"]) >= since]
    return out[-limit:] if limit else list(out)
