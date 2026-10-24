from __future__ import annotations
import hmac, json
from .chain import (
    GENESIS, hmac_key, entry_hash, _mac, _shown, _event_mac_error, _event_mac_warning,
    _meta_msg, _chain_expects_hmac, verify_chain, _hmac_key_missing_message,
)


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
        return "\n\n".join([
            "setup: wrote this event the first time it loaded an HMAC key and audit_meta had no mac.",
            "expected: a mac from that HMAC key on this event.",
            "missing: events before it have no mac field. Those earlier events are not checked. If this event has no mac, verification fails here.",
        ])
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
    hmac_from_raw = meta.get("hmac_from") if isinstance(meta, dict) else None
    hmac_from_shown = _shown(hmac_from_raw) if isinstance(hmac_from_raw, int) else hmac_from_raw
    checks.append(_check(
        "audit_meta present",
        meta is not None,
        None if meta is None else {
            "legacy": meta.get("legacy"),
            "hmac_from": hmac_from_shown,
            "mac": bool(meta.get("mac")),
        },
    ))
    if meta is None:
        return {**result, "checks": checks, "match": key_event_match(store)}

    legacy = meta.get("legacy")
    legacy_ok = isinstance(legacy, int) and 0 <= legacy <= len(log)
    legacy_data = None
    if not legacy_ok:
        legacy_data = {"legacy": legacy, "log_length": len(log)}
    checks.append(_check("legacy count valid", legacy_ok, legacy_data))

    expects_hmac = _chain_expects_hmac(meta)
    if key is None and expects_hmac:
        checks.append(_check(
            "audit_meta MAC", False,
            {"reason": _hmac_key_missing_message()},
        ))
    elif key is None:
        checks.append(_check(
            "audit_meta MAC", True,
            {"reason": "chain has no MACs; KEYFORGE_AUDIT_HMAC_KEY_FILE unset; unkeyed verify"},
            skipped=True,
        ))
    else:
        if "mac" not in meta:
            meta_mac_ok = False
            meta_mac_reason = "\n\n".join([
                "audit_meta has no mac.",
                "key: the loaded HMAC key was not used to sign legacy|count|head|hmac_from.",
            ])
        else:
            meta_mac_ok = hmac.compare_digest(meta["mac"], _mac(key, _meta_msg(meta)))
            meta_mac_reason = "\n\n".join([
                "audit_meta.mac does not match.",
                (
                    "tag: the stored audit_meta.mac is not HMAC-SHA256 of "
                    "legacy|count|head|hmac_from under the loaded HMAC key."
                ),
                "values: count and head above are the values in that message.",
                (
                    "chain: a later event can be appended without refreshing this tag, "
                    "so the event chain can still match while this tag does not."
                ),
            ])
        checks.append(_check(
            "audit_meta MAC", meta_mac_ok,
            None if meta_mac_ok else {"reason": meta_mac_reason},
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

    chain_data = None
    if not chain_ok:
        chain_data = {"error": chain_err}
        if chain_index is not None:
            chain_data["event"] = _shown(chain_index)
    checks.append(_check("hash chain continuity and content hashes", chain_ok, chain_data))

    count_ok = meta.get("count") == len(log)
    checks.append(_check(
        "count matches log length", count_ok,
        None if count_ok else {"meta_count": meta.get("count"), "log_length": len(log)},
    ))

    computed_head = prev if (legacy_ok and chain_ok) else result["head"]
    head_ok = chain_ok and count_ok and meta.get("head") == computed_head
    checks.append(_check(
        "head matches last chained hash", head_ok,
        None if head_ok else {"meta_head": meta.get("head"), "computed_head": computed_head},
    ))

    if key is None and expects_hmac:
        checks.append(_check(
            "event MACs from hmac_from", False,
            {"reason": _hmac_key_missing_message()},
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
            {"error": "\n\n".join(event_mac_errs)} if event_mac_errs else None,
        ))

    return {**result, "checks": checks, "match": key_event_match(store)}
