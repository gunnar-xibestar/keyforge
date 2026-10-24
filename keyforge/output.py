"""Text and JSON formatting for the CLI.

These functions moved verbatim from ``keyforge.cli``. ``cli`` binds ``_out``,
``_table``, ``_key_text``, ``_format_verify_report``, and ``_auth_scope_text``
to the objects defined here. Command handlers still in ``cli`` look those
names up on ``keyforge.cli``, so that is where to patch command output.
``test_audit_integrity`` calls ``keyforge.cli._format_verify_report``.

Inside ``_format_verify_report``, ``_table``, ``_table_wrapped``, and
``_action_cell`` are looked up in this module. ``audit.walk_line``,
``audit.last_event_lines``, and ``audit._shown`` are looked up on the audit
package when the report runs. Patch the table helpers here to change the
report's tables. Patching ``keyforge.cli._table`` changes ``list`` and
``audit`` query tables only, because those commands look ``_table`` up on
``cli``. ``_wrap_cell``, ``_table_wrapped``, and ``_action_cell`` are defined
only in this module.
"""
from __future__ import annotations

import json

from . import audit


def _out(args, data, text=None):
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    elif text is not None:
        print(text)


def _table(rows, cols):
    w = {c: max(len(c), *(len(str(r.get(c) or "")) for r in rows)) if rows else len(c) for c in cols}
    lines = ["  ".join(c.upper().ljust(w[c]) for c in cols), "  ".join("-" * w[c] for c in cols)]
    lines += ["  ".join(str(r.get(c) or "").ljust(w[c]) for c in cols) for r in rows]
    return "\n".join(lines)


def _wrap_cell(text: str, width: int) -> list[str]:
    """Wrap one cell. Blank lines in ``text`` stay blank lines."""
    import textwrap
    lines: list[str] = []
    for para in str(text).split("\n"):
        if not para:
            lines.append("")
            continue
        lines.extend(textwrap.wrap(para, width) or [""])
    return lines or ["-"]


def _table_wrapped(rows, cols, wrap_col: str, width: int = 72):
    """A table whose ``wrap_col`` continues on the following lines, under that column."""
    plain = [c for c in cols if c != wrap_col]
    w = {c: max(len(c), *(len(str(r.get(c) or "")) for r in rows)) if rows else len(c) for c in plain}
    w[wrap_col] = max(len(wrap_col), width)

    def paint(values: dict) -> str:
        return "  ".join(str(values.get(c) or "").ljust(w[c]) for c in cols)

    lines = [
        paint({c: c.upper() for c in cols}),
        paint({c: "-" * w[c] for c in cols}),
    ]
    for row in rows:
        wrapped = _wrap_cell(row.get(wrap_col) or "-", width)
        first = {c: row.get(c) or "" for c in plain}
        first[wrap_col] = wrapped[0]
        lines.append(paint(first))
        rest = {c: "" for c in plain}
        for extra in wrapped[1:]:
            rest[wrap_col] = extra
            lines.append(paint(rest))
        if len(wrapped) > 1:
            lines.append("")
    return "\n".join(lines).rstrip()


def _key_text(k):
    p = k.public()
    lines = [f"{f:<15} {p[f]}" for f in ("id", "name", "prefix", "env", "owner", "team", "effective_status",
             "created_at", "expires_at", "rate_limit", "description", "last_used_at") if p.get(f) is not None]
    lines.append(f"{'scopes':<15} {' '.join(k.scopes) or '-'}")
    if k.ip_allow: lines.append(f"{'ip_allow':<15} {' '.join(k.ip_allow)}")
    if k.labels: lines.append(f"{'labels':<15} {', '.join(f'{a}={b}' for a, b in k.labels.items())}")
    for f in ("revoked_reason", "rotated_to", "rotated_from", "grace_until"):
        if p.get(f): lines.append(f"{f:<15} {p[f]}")
    return "\n".join(lines)


def _action_cell(event: dict) -> str:
    """Action name, with the failure reason beside ``verify_fail``."""
    action = event.get("action") or ""
    reason = event.get("reason") or ""
    if action == "verify_fail" and reason not in ("", "-"):
        return f"verify_fail ({reason})"
    return action


def _format_verify_report(r: dict) -> str:
    """Human text for audit --verify: summary, each check + data, keys↔events match."""
    lines = []
    if r["ok"]:
        summary = (f"audit chain OK: {r['checked']} chained event(s), count {r['count']}, "
                   f"head {r['head']}")
        if r["mac_verified"]:
            summary += ", MAC verified"
        if r["legacy"]:
            summary += f" ({r['legacy']} legacy unchained event(s) not protected)"
    else:
        summary = "\n".join(
            f"AUDIT CHAIN BROKEN: {err}" for err in (r.get("errors") or [r["error"]])
        )
        if r.get("walked"):
            summary += "\n" + audit.walk_line(r)
            extra = audit.last_event_lines(r)
            if extra:
                summary += "\n" + "\n".join(extra)
    lines.append(summary)
    for warning in r.get("warnings") or []:
        lines.append(warning)
    lines.append("")
    lines.append("checks")
    lines.append("------")
    if r.get("count") is not None:
        lines.append(f"  count: {r['count']}")
    if r.get("head"):
        lines.append(f"  head: {r['head']}")
    lines.append("")
    for c in r.get("checks") or []:
        if c.get("skipped"):
            status = "skip"
        else:
            status = "ok" if c.get("ok") else "FAIL"
        lines.append(f"  [{status}] {c['name']}")
        data = c.get("data") or {}
        for k, v in data.items():
            if v is None:
                continue
            text = str(v)
            if "\n" in text:
                lines.append(f"         {k}:")
                lines.append("")
                for piece in text.splitlines():
                    lines.append(f"           {piece}" if piece else "")
                lines.append("")
            else:
                lines.append(f"         {k}: {text}")
    match = r.get("match") or {}
    lines.append("")
    lines.append("keys and chain events")
    lines.append("---------------------")
    lines.append(
        f"  list keys: {match.get('keys_listed', 0)}  |  "
        f"chain events: {match.get('events_total', 0)}  |  "
        f"with key_id: {match.get('events_with_key', 0)}  |  "
        f"without key_id: {match.get('events_without_key', 0)}"
    )
    lines.append("")
    key_rows = []
    for k in match.get("keys") or []:
        actions = k.get("actions") or {}
        action_s = " ".join(f"{a}×{n}" for a, n in sorted(actions.items())) or "-"
        key_rows.append({
            "id": k["id"],
            "name": k["name"],
            "prefix": k["prefix"],
            "created_at": k.get("created_at") or "",
            "events": k.get("event_count", 0),
            "actions": action_s,
        })
    if key_rows:
        lines.append(_table(key_rows, ["id", "name", "prefix", "created_at", "events", "actions"]))
    else:
        lines.append("  (no keys in store)")
    orphans = match.get("orphan_events") or []
    if orphans:
        lines.append("")
        lines.append("orphan events (key_id not in list)")
        lines.append("---------------------------------")
        lines.append(_table_wrapped(
            [{"index": audit._shown(e["index"]), "date": e.get("date") or "", "ts": e.get("ts") or "",
              "action": _action_cell(e), "reason": e.get("reason") or "-",
              "key_id": e.get("key_id") or ""} for e in orphans],
            ["index", "date", "ts", "action", "reason", "key_id"],
            "reason",
        ))
    no_key = match.get("no_key_events") or []
    if no_key:
        lines.append("")
        lines.append("chain events with no key_id")
        lines.append("---------------------------")
        lines.append(_table_wrapped(
            [{"index": audit._shown(e["index"]), "date": e.get("date") or "", "ts": e.get("ts") or "",
              "action": _action_cell(e), "reason": e.get("reason") or "-"}
             for e in no_key],
            ["index", "date", "ts", "action", "reason"],
            "reason",
        ))
    return "\n".join(lines)


def _auth_scope_text(info: dict) -> str:
    scopes = " ".join(info.get("scopes") or []) or "-"
    lines = [f"scopes: {scopes}"]
    missing = info.get("missing_scopes") or []
    if missing:
        lines.append(
            "missing_scopes: " + " ".join(missing)
            + " (Auth0 granted fewer scopes than requested; check API Permissions and the"
            + " app's Application Access grants (permission names must match exactly,"
            + " with no trailing spaces). If Enable RBAC is on, also assign them to"
            + " the user or role. Operator scopes are not the same as kf_... API-key scopes.)"
        )
    return "\n".join(lines)
