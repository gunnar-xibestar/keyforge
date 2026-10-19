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
    """1-based event number plus the stored 0-based index. List indexes stay 0-based."""
    return f"{index + 1} (index {index})"


def _event_facts(ev: dict) -> str:
    """Fields already stored on the event, for a mismatch line."""
    parts = []
    for name in ("ts", "action", "key_id", "actor", "os_user"):
        value = ev.get(name)
        if value is None or value == "":
            continue
        parts.append(f"{name}={value}")
    if not parts:
        return ""
    return " Event: " + ", ".join(parts) + "."


def _event_mac_error(i: int, ev: dict, key: bytes, hmac_from: int) -> str | None:
    """Why this event's MAC failed under ``key``. None when the MAC matches.

    The hash chain has already matched through this event.
    """
    if "mac" not in ev:
        write_time = ev.get("hmac_error")
        if write_time:
            why = f" At write time: {write_time}"
        else:
            why = " none recorded"
        return (
            f"event {_shown(i)}: MAC missing. hmac_from is {_shown(hmac_from)}, so this event must carry a MAC "
            "from the loaded HMAC key. The event hash matches: the stored hash equals SHA-256 of "
            "this event with hash and mac removed, and prev_hash links to the previous event. "
            "There is no mac field."
            + why
            + _event_facts(ev)
        )
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
        return fail(
            "HMAC key required: audit chain has MACs but KEYFORGE_AUDIT_HMAC_KEY_FILE "
            "is unset or the key was not supplied"
        )
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


def walk_movement(result: dict) -> str:
    """Whether the walk stopped at the first mismatch or kept going to the end."""
    if result.get("walk_continued"):
        return "The walk continued past the first mismatch and finished at the last event."
    if result.get("index") is not None and result.get("index") == result.get("walked_last"):
        return "The first mismatch is the last event. The walk did not continue past it."
    return "The walk finished at the last event."


def walk_line(result: dict) -> str:
    """How far verify walked, and whether that walk passed the first mismatch."""
    walked = result.get("walked")
    last = result.get("walked_last")
    if not isinstance(walked, int) or walked <= 0 or not isinstance(last, int):
        return "walk: the log has no events."
    return f"walk: checked events {_shown(0)} through {_shown(last)} ({walked} events). {walk_movement(result)}"


def last_event_lines(result: dict) -> list[str]:
    """Every stored field of the last audit event."""
    last = result.get("last_event") or {}
    fields = last.get("fields")
    if not isinstance(fields, dict):
        return []
    index = last.get("index")
    label = _shown(index) if isinstance(index, int) else index
    lines = [f"last event {label}:"]
    for name in sorted(fields):
        value = fields[name]
        if isinstance(value, (dict, list)):
            shown = json.dumps(value, sort_keys=True, separators=(", ", ": "))
        else:
            shown = value
        lines.append(f"  {name}: {shown}")
    return lines


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


def _check(name: str, ok: bool, data: dict | None = None, *, skipped: bool = False) -> dict:
    row = {"name": name, "ok": ok, "skipped": skipped}
    if data is not None:
        row["data"] = data
    return row


def _event_date(ts: str | None) -> str:
    """Calendar date from an ISO timestamp (``YYYY-MM-DD``), or empty."""
    if not ts or not isinstance(ts, str):
        return ""
    return ts[:10] if len(ts) >= 10 else ts


def _event_reason(ev: dict) -> str:
    """Human reason for an audit action result, from ``details`` or the action name."""
    details = ev.get("details") if isinstance(ev.get("details"), dict) else {}
    reason = details.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()
    action = ev.get("action") or ""
    if action == "audit_hmac_enabled":
        return "audit HMAC enabled; MAC starts at this event"
    if action == "audit_adopt_legacy":
        n = details.get("legacy")
        return f"legacy chain adopted ({n} unprotected event(s))" if n is not None else "legacy chain adopted"
    if action == "export":
        path = details.get("file")
        n = details.get("count")
        parts = []
        if path is not None:
            parts.append(f"file={path}")
        if n is not None:
            parts.append(f"count={n}")
        return "export " + " ".join(parts) if parts else "export"
    if action == "import":
        parts = [f"{k}={v}" for k, v in sorted(details.items()) if v is not None]
        return ("import " + " ".join(parts)) if parts else "import"
    if action == "policy_set":
        return f"policy {details.get('field')}={details.get('value')!r}"
    if action == "policy_reset":
        return "policy reset"
    if action == "verify_fail":
        # reason usually set; fall through with prefix hint when missing
        pre = details.get("prefix")
        return f"verify failed (prefix {pre})" if pre else "verify failed"
    if details:
        return " ".join(f"{k}={v}" for k, v in sorted(details.items()) if v is not None) or "-"
    return "-"


def key_event_match(store) -> dict:
    """Relate store keys (as in ``list``) to audit events that name them."""
    keys = list(store.all())
    by_id = {k.id: k for k in keys}
    log = store.audit_log
    events_by_key: dict[str, list] = {k.id: [] for k in keys}
    orphan: list[dict] = []
    no_key: list[dict] = []
    for i, ev in enumerate(log):
        kid = ev.get("key_id")
        ts = ev.get("ts")
        summary = {
            "index": i,
            "ts": ts,
            "date": _event_date(ts if isinstance(ts, str) else None),
            "action": ev.get("action"),
            "reason": _event_reason(ev),
            "key_id": kid,
            "hash": (ev.get("hash") or "")[:12] or None,
        }
        if not kid:
            no_key.append(summary)
        elif kid in events_by_key:
            events_by_key[kid].append(summary)
        else:
            orphan.append(summary)
    listed = []
    for k in sorted(keys, key=lambda x: x.created_at):
        evs = events_by_key[k.id]
        actions: dict[str, int] = {}
        for e in evs:
            actions[e["action"]] = actions.get(e["action"], 0) + 1
        listed.append({
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "created_at": k.created_at,
            "event_count": len(evs),
            "actions": actions,
            "events": evs,
        })
    return {
        "keys_listed": len(listed),
        "events_total": len(log),
        "events_with_key": sum(1 for e in log if e.get("key_id")),
        "events_without_key": len(no_key),
        "orphan_events": orphan,
        "no_key_events": no_key,
        "keys": listed,
    }


def verify_report(store, key: bytes | None = None) -> dict:
    """Run verify_chain and attach check details plus key↔event matching for display.

    If ``key`` is omitted, loads ``hmac_key()`` (raises when the env var is set but unusable).
    """
    if key is None:
        key = hmac_key()
    meta = store.data.get("audit_meta")
    log = store.audit_log
    result = verify_chain(log, meta, key)
    checks = []
    checks.append(_check(
        "audit_meta present",
        meta is not None,
        None if meta is None else {
            "legacy": meta.get("legacy"),
            "count": meta.get("count"),
            "head": meta.get("head"),
            "hmac_from": meta.get("hmac_from"),
            "mac": bool(meta.get("mac")),
        },
    ))
    if meta is None:
        return {**result, "checks": checks, "match": key_event_match(store)}

    legacy = meta.get("legacy")
    legacy_ok = isinstance(legacy, int) and 0 <= legacy <= len(log)
    checks.append(_check(
        "legacy count valid",
        legacy_ok,
        {"legacy": legacy, "log_length": len(log)},
    ))

    expects_hmac = _chain_expects_hmac(meta)
    if key is None and expects_hmac:
        checks.append(_check(
            "audit_meta MAC", False,
            {
                "reason": "HMAC key required: chain has MACs but KEYFORGE_AUDIT_HMAC_KEY_FILE is unset",
                "mac_present": "mac" in meta,
                "hmac_from": meta.get("hmac_from"),
            },
        ))
    elif key is None:
        checks.append(_check(
            "audit_meta MAC", True,
            {"reason": "chain has no MACs; KEYFORGE_AUDIT_HMAC_KEY_FILE unset; unkeyed verify"},
            skipped=True,
        ))
    else:
        meta_mac_ok = "mac" in meta and hmac.compare_digest(
            meta["mac"], _mac(key, _meta_msg(meta)))
        checks.append(_check(
            "audit_meta MAC", meta_mac_ok,
            {"hmac_from": meta.get("hmac_from"), "mac_present": "mac" in meta},
        ))

    # Walk the chain independently so the report can show pass/fail data per check.
    chain_ok = True
    chain_err = None
    chain_index = None
    checked = 0
    prev = GENESIS
    hmac_from = meta.get("hmac_from", len(log)) if isinstance(meta.get("hmac_from"), int) else len(log)
    event_mac_ok = True
    event_mac_errs: list[str] = []
    matched_through = hmac_from - 1
    if legacy_ok:
        for i, ev in enumerate(log):
            if i < legacy:
                if "hash" in ev or "prev_hash" in ev:
                    chain_ok = False
                    chain_err = f"event {_shown(i)} is chained but recorded as legacy"
                    chain_index = i
                    break
                continue
            if "hash" not in ev or "prev_hash" not in ev:
                chain_ok = False
                chain_err = f"event {_shown(i)} is missing hash/prev_hash"
                chain_index = i
                break
            if ev["prev_hash"] != prev:
                chain_ok = False
                chain_err = f"event {_shown(i)}: prev_hash mismatch"
                chain_index = i
                break
            if entry_hash(ev) != ev["hash"]:
                chain_ok = False
                chain_err = f"event {_shown(i)}: content hash mismatch"
                chain_index = i
                break
            if key and i >= hmac_from:
                mac_error = _event_mac_error(i, ev, key, hmac_from)
                if mac_error:
                    event_mac_ok = False
                    event_mac_errs.append(mac_error)
                else:
                    mac_warning = _event_mac_warning(i, ev, key, hmac_from, matched_through)
                    if mac_warning:
                        event_mac_errs.append(mac_warning)
                    else:
                        matched_through = i
            if "hash" in ev:
                prev = ev["hash"]
            checked += 1

    chain_data = {
        "checked": checked if chain_ok else result["checked"],
        "legacy_skipped": legacy if legacy_ok else result["legacy"],
        "head": prev if chain_ok else result["head"],
    }
    if not chain_ok:
        chain_data["error"] = chain_err
        chain_data["index"] = chain_index
    checks.append(_check("hash chain continuity and content hashes", chain_ok, chain_data))

    count_ok = meta.get("count") == len(log)
    checks.append(_check(
        "count matches log length", count_ok,
        {"meta_count": meta.get("count"), "log_length": len(log)},
    ))

    computed_head = prev if (legacy_ok and chain_ok) else result["head"]
    head_ok = chain_ok and count_ok and meta.get("head") == computed_head
    checks.append(_check(
        "head matches last chained hash", head_ok,
        {"meta_head": meta.get("head"), "computed_head": computed_head},
    ))

    if key is None and expects_hmac:
        checks.append(_check(
            "event MACs from hmac_from", False,
            {
                "reason": "HMAC key required: chain has MACs but KEYFORGE_AUDIT_HMAC_KEY_FILE is unset",
                "hmac_from": meta.get("hmac_from"),
            },
        ))
    elif key is None:
        checks.append(_check(
            "event MACs from hmac_from", True,
            {"reason": "chain has no MACs; no HMAC key; event macs not checked"},
            skipped=True,
        ))
    else:
        checks.append(_check(
            "event MACs from hmac_from",
            event_mac_ok and chain_ok,
            {
                "hmac_from": meta.get("hmac_from"),
                "mac_verified": bool(result["mac_verified"] and event_mac_ok and result["ok"]),
                **({"error": "; ".join(event_mac_errs)} if event_mac_errs else {}),
            },
        ))

    return {**result, "checks": checks, "match": key_event_match(store)}

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
