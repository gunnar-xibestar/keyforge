from __future__ import annotations
import getpass, json, os, sys
from ..errors import KeyForgeError
from ..models import iso, now, parse_iso
from .chain import (
    GENESIS, canonical, hmac_key, entry_hash, _mac, _shown, _meta_msg, _chain_expects_hmac,
)

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
    key = None
    key_failure = None
    if not os.environ.get("KEYFORGE_AUDIT_HMAC_KEY_FILE") and _chain_expects_hmac(meta):
        stayed = meta.get("hmac_from")
        key_failure = (
            "KEYFORGE_AUDIT_HMAC_KEY_FILE was unset. No HMAC key file was read. "
            f"hmac_from stayed {_shown(stayed) if isinstance(stayed, int) else stayed}."
        )
    else:
        try:
            key = hmac_key()
        except KeyForgeError as e:
            key_failure = str(e)[:300]
    if key_failure:
        ev["hmac_error"] = key_failure
        ev["hash"] = entry_hash(ev)
        meta.pop("mac", None)
        print(f"keyforge: warning: audit event written WITHOUT HMAC: {key_failure}", file=sys.stderr)
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
