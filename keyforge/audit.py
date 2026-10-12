"""Append-only (mock) audit log stored alongside keys."""
from __future__ import annotations
import getpass, os
from .models import iso, now, parse_iso

def actor() -> str:
    try:
        return os.environ.get("KEYFORGE_ACTOR") or getpass.getuser()
    except Exception:
        return "unknown"

def record(store, action: str, key_id: str | None = None, **details) -> dict:
    ev = {"ts": iso(now()), "actor": actor(), "action": action, "key_id": key_id,
          "details": {k: v for k, v in details.items() if v is not None}}
    store.audit_log.append(ev)
    return ev

def query(store, key_id=None, action=None, since=None, limit=None) -> list[dict]:
    out = store.audit_log
    if key_id:
        out = [e for e in out if e.get("key_id") == key_id]
    if action:
        out = [e for e in out if e["action"] == action]
    if since:
        out = [e for e in out if parse_iso(e["ts"]) >= since]
    return out[-limit:] if limit else list(out)
