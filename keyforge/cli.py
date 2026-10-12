"""argparse CLI for KeyForge (MOCK - not for production)."""
from __future__ import annotations
import argparse, csv, io, json, sys
from . import service as svc, audit, policy as pol, __version__, MOCK_BANNER
from .errors import KeyForgeError, Aborted, ValidationError
from .models import parse_duration, now, parse_iso, iso
from .store import Store

EXIT_OK, EXIT_ERR, EXIT_USAGE, EXIT_NOTFOUND, EXIT_VERIFY, EXIT_POLICY, EXIT_ABORT = 0, 1, 2, 3, 4, 5, 6

def _kv(s):
    if "=" not in s:
        raise argparse.ArgumentTypeError(f"expected key=value, got {s!r}")
    k, v = s.split("=", 1); return k, v

def _out(args, data, text=None):
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    elif text is not None:
        print(text)

def _confirm(args, msg):
    if args.dry_run or args.yes:
        return
    if not sys.stdin.isatty():
        raise Aborted(f"{msg} - refusing without --yes (non-interactive)")
    if input(f"{msg} [y/N] ").strip().lower() not in ("y", "yes"):
        raise Aborted("aborted by user")

def _table(rows, cols):
    w = {c: max(len(c), *(len(str(r.get(c) or "")) for r in rows)) if rows else len(c) for c in cols}
    lines = ["  ".join(c.upper().ljust(w[c]) for c in cols), "  ".join("-" * w[c] for c in cols)]
    lines += ["  ".join(str(r.get(c) or "").ljust(w[c]) for c in cols) for r in rows]
    return "\n".join(lines)

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

# ---- commands --------------------------------------------------------------
def cmd_create(a, st):
    exp = svc.resolve_expiry(a.expires_in, a.expires_at)
    k, full = svc.create(st, name=a.name, owner=a.owner, env=a.env, team=a.team, scopes=a.scope or [],
                         expires_at=exp, rate_limit=a.rate_limit, ip_allow=a.ip_allow or [],
                         labels=dict(a.label or []), description=a.description, dry_run=a.dry_run)
    if a.dry_run:
        _out(a, {"dry_run": True, "key": k.public()}, "[dry-run] would create:\n" + _key_text(k)); return 0
    st.save()
    _out(a, {"key": k.public(), "secret": full},
         _key_text(k) + f"\n\nSECRET (shown once, store it now):\n  {full}")

def cmd_list(a, st):
    keys = svc.list_keys(st, a.owner, a.team, a.env, a.status, a.scope, a.label)
    rows = [k.public() for k in keys]
    for r in rows: r["scopes"] = " ".join(r["scopes"])
    fmt = "json" if a.json else a.format
    if fmt == "json":
        print(json.dumps([k.public() for k in keys], indent=2)); return
    cols = ["id", "name", "prefix", "env", "owner", "team", "effective_status", "expires_at", "scopes"]
    if fmt == "csv":
        buf = io.StringIO(); w = csv.DictWriter(buf, cols, extrasaction="ignore")
        w.writeheader(); w.writerows(rows); print(buf.getvalue(), end="")
    else:
        print(_table(rows, cols) if rows else "(no keys)")

def cmd_show(a, st):
    k = st.get(a.key); _out(a, k.public(), _key_text(k))

def cmd_verify(a, st):
    secret = a.secret
    if secret == "-": secret = sys.stdin.readline().strip()
    try:
        k = svc.verify(st, secret, scope=a.scope, ip=a.ip)
    except KeyForgeError as e:
        _out(a, {"valid": False, "reason": str(e)}, f"INVALID: {e}"); return EXIT_VERIFY
    _out(a, {"valid": True, "key_id": k.id, "status": k.effective_status(), "scopes": k.scopes},
         f"VALID: {k.id} ({k.name}) status={k.effective_status()}")

def cmd_rotate(a, st):
    _confirm(a, f"Rotate key {a.key}?")
    old, new, full, gu = svc.rotate(st, a.key, a.grace_period, a.dry_run)
    if a.dry_run:
        _out(a, {"dry_run": True, "old": old.id, "grace_until": iso(gu)},
             f"[dry-run] would rotate {old.id}; old key valid until {iso(gu)}"); return
    st.save()
    _out(a, {"old_key": old.id, "new_key": new.public(), "secret": full, "grace_until": iso(gu)},
         f"Rotated {old.id} -> {new.id} (old valid until {iso(gu)})\n\nNEW SECRET (shown once):\n  {full}")

def _status_cmd(status, verb):
    def run(a, st):
        if status == "revoked": _confirm(a, f"Revoke key {a.key}? This cannot be undone.")
        k = svc.set_status(st, a.key, status, getattr(a, "reason", None), a.dry_run)
        if not a.dry_run: st.save()
        pre = "[dry-run] would " + verb.lower().rstrip("d") if a.dry_run else verb
        _out(a, {"dry_run": a.dry_run, "key": k.public()}, f"{pre} {k.id} ({k.name})")
    return run

def cmd_update(a, st):
    exp = None
    if a.expires_in or a.expires_at: exp = svc.resolve_expiry(a.expires_in, a.expires_at)
    k = svc.update(st, a.key, add_scopes=a.add_scope or [], remove_scopes=a.remove_scope or [],
                   set_labels=dict(a.label or []), unset_labels=a.unset_label or [], expires_at=exp,
                   clear_expiry=a.no_expiry, rate_limit=a.rate_limit, description=a.description,
                   add_ip=a.add_ip or [], remove_ip=a.remove_ip or [], dry_run=a.dry_run)
    if not a.dry_run: st.save()
    _out(a, {"dry_run": a.dry_run, "key": k.public()}, ("[dry-run] would update:\n" if a.dry_run else "Updated:\n") + _key_text(k))

def cmd_audit(a, st):
    key_id = st.get(a.key).id if a.key else None
    since = None
    if a.since:
        try: since = now() - parse_duration(a.since)
        except ValueError: since = parse_iso(a.since)
    evs = audit.query(st, key_id, a.action, since, a.limit)
    if a.export:
        with open(a.export, "w") as f: json.dump(evs, f, indent=2)
        print(f"exported {len(evs)} events to {a.export}", file=sys.stderr)
    if a.json:
        print(json.dumps(evs, indent=2)); return
    rows = [{**e, "details": json.dumps(e["details"], sort_keys=True)} for e in evs]
    print(_table(rows, ["ts", "actor", "action", "key_id", "details"]) if rows else "(no events)")

POLICY_KEYS = {"max_ttl": str, "require_expiry": "bool", "allowed_scopes": list, "required_labels": list,
               "max_rate_limit": int, "live_requires_ip_allow": "bool", "default_grace_period": str}

def cmd_policy(a, st):
    if a.policy_cmd in (None, "show"):
        p = pol.effective(st)
        _out(a, p, "\n".join(f"{k:<24} {v}" for k, v in p.items())); return
    if a.policy_cmd == "reset":
        _confirm(a, "Reset org policy to defaults?")
        if not a.dry_run: st.data["policy"] = {}; audit.record(st, "policy_reset"); st.save()
        _out(a, {"reset": True, "dry_run": a.dry_run}, "policy reset" + (" (dry-run)" if a.dry_run else "")); return
    if a.field not in POLICY_KEYS:
        raise ValidationError(f"unknown policy field {a.field!r}; choose from {', '.join(POLICY_KEYS)}")
    t, raw = POLICY_KEYS[a.field], a.value
    if raw.lower() in ("none", "null", ""): val = [] if t is list else None
    elif t == "bool": val = raw.lower() in ("1", "true", "yes", "on")
    elif t is list: val = [x.strip() for x in raw.split(",") if x.strip()]
    elif t is int: val = int(raw)
    else:
        parse_duration(raw); val = raw
    if not a.dry_run:
        st.policy[a.field] = val; audit.record(st, "policy_set", None, field=a.field, value=val); st.save()
    _out(a, {a.field: val, "dry_run": a.dry_run}, f"policy {a.field} = {val}" + (" (dry-run)" if a.dry_run else ""))

def cmd_export(a, st):
    data = svc.export(st, a.include_audit)
    text = json.dumps(data, indent=2)
    if a.output in (None, "-"): print(text)
    else:
        with open(a.output, "w") as f: f.write(text)
        audit.record(st, "export", None, file=a.output, count=len(data["keys"])); st.save()
        _out(a, {"exported": len(data["keys"]), "file": a.output}, f"exported {len(data['keys'])} keys to {a.output}")

def cmd_import(a, st):
    with (sys.stdin if a.file == "-" else open(a.file)) as f: data = json.load(f)
    res = svc.import_(st, data, a.overwrite, a.dry_run, allow_unrevoke=a.allow_unrevoke)
    if not a.dry_run: st.save()
    _out(a, {**res, "dry_run": a.dry_run},
         f"{'[dry-run] ' if a.dry_run else ''}added={len(res['added'])} overwritten={len(res['overwritten'])} skipped={len(res['skipped'])}")

def cmd_purge(a, st):
    victims = svc.purge(st, a.older_than, a.include_revoked, dry_run=True)
    if victims and not a.dry_run:
        _confirm(a, f"Permanently delete {len(victims)} key record(s)?")
        svc.purge(st, a.older_than, a.include_revoked); st.save()
    _out(a, {"dry_run": a.dry_run, "purged": [k.id for k in victims]},
         f"{'[dry-run] would purge' if a.dry_run else 'purged'} {len(victims)} key(s)" +
         "".join(f"\n  {k.id} {k.name} ({k.effective_status()})" for k in victims))

# ---- parser ----------------------------------------------------------------
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--store", help="store file (default: $KEYFORGE_STORE or ~/.keyforge/store.json)")
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")
    destr = argparse.ArgumentParser(add_help=False)
    destr.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    destr.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompt")
    dry = argparse.ArgumentParser(add_help=False)
    dry.add_argument("--dry-run", action="store_true")

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--store", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub_common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    p = argparse.ArgumentParser(prog="keyforge", parents=[common],
        description=f"{MOCK_BANNER}. Manage mock enterprise API keys.",
        epilog="Exit codes: 0 ok, 1 error, 2 usage/validation, 3 not found, 4 verify failed, 5 policy violation, 6 aborted")
    p.add_argument("--version", action="version", version=f"keyforge {__version__} (MOCK)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")
    def add(name, fn, help, parents=()):
        sp = sub.add_parser(name, help=help, parents=[sub_common, *parents]); sp.set_defaults(func=fn); return sp

    c = add("create", cmd_create, "create a new API key", [dry])
    c.add_argument("--name", required=True); c.add_argument("--owner", required=True)
    c.add_argument("--team"); c.add_argument("--env", choices=["live", "test"], default="test")
    c.add_argument("--scope", action="append", help="repeatable, e.g. read:packets")
    e = c.add_mutually_exclusive_group()
    e.add_argument("--expires-in", help="duration e.g. 30d, 12h"); e.add_argument("--expires-at", help="ISO-8601 timestamp")
    c.add_argument("--rate-limit", type=int, help="requests per minute")
    c.add_argument("--ip-allow", action="append", help="CIDR, repeatable")
    c.add_argument("--label", action="append", type=_kv, help="k=v, repeatable")
    c.add_argument("--description")

    l = add("list", cmd_list, "list keys")
    l.add_argument("--owner"); l.add_argument("--team"); l.add_argument("--env", choices=["live", "test"])
    l.add_argument("--status", choices=["active", "suspended", "revoked", "expired", "rotated", "grace"])
    l.add_argument("--scope", help="glob, e.g. read:*"); l.add_argument("--label", help="k=v")
    l.add_argument("--format", choices=["table", "json", "csv"], default="table")

    s = add("show", cmd_show, "show key details"); s.add_argument("key", help="id, prefix or name")
    v = add("verify", cmd_verify, "verify a secret (use - to read from stdin)")
    v.add_argument("secret"); v.add_argument("--scope"); v.add_argument("--ip")

    r = add("rotate", cmd_rotate, "rotate a key", [destr]); r.add_argument("key")
    r.add_argument("--grace-period", help="old key stays valid this long, e.g. 24h (0s = immediate)")
    rv = add("revoke", cmd_revoke := _status_cmd("revoked", "Revoked"), "revoke a key permanently", [destr])
    rv.add_argument("key"); rv.add_argument("--reason")
    su = add("suspend", _status_cmd("suspended", "Suspended"), "temporarily disable a key", [dry])
    su.add_argument("key"); su.add_argument("--reason")
    re_ = add("resume", _status_cmd("active", "Resumed"), "re-enable a suspended key", [dry]); re_.add_argument("key")

    u = add("update", cmd_update, "update scopes/labels/expiry/etc.", [dry]); u.add_argument("key")
    u.add_argument("--add-scope", action="append"); u.add_argument("--remove-scope", action="append")
    u.add_argument("--label", action="append", type=_kv); u.add_argument("--unset-label", action="append")
    u.add_argument("--add-ip", action="append"); u.add_argument("--remove-ip", action="append")
    ue = u.add_mutually_exclusive_group()
    ue.add_argument("--expires-in"); ue.add_argument("--expires-at"); ue.add_argument("--no-expiry", action="store_true")
    u.add_argument("--rate-limit", type=int); u.add_argument("--description")

    au = add("audit", cmd_audit, "query the audit log")
    au.add_argument("--key"); au.add_argument("--action"); au.add_argument("--since", help="duration (24h) or ISO time")
    au.add_argument("--limit", type=int); au.add_argument("--export", metavar="FILE", help="write JSON to file")

    po = add("policy", cmd_policy, "show/set org policy")
    psub = po.add_subparsers(dest="policy_cmd")
    psub.add_parser("show", parents=[sub_common])
    ps = psub.add_parser("set", parents=[sub_common, dry], help=f"fields: {', '.join(POLICY_KEYS)}")
    ps.add_argument("field"); ps.add_argument("value", help="lists comma-separated; 'none' clears")
    psub.add_parser("reset", parents=[sub_common, destr])

    ex = add("export", cmd_export, "export keys (hashes only) to JSON")
    ex.add_argument("-o", "--output"); ex.add_argument("--include-audit", action="store_true")
    im = add("import", cmd_import, "import an export file", [dry])
    im.add_argument("file"); im.add_argument("--overwrite", action="store_true")
    im.add_argument("--allow-unrevoke", action="store_true",
                    help="with --overwrite, allow a non-revoked record to replace a revoked key")
    pu = add("purge", cmd_purge, "delete expired / post-grace rotated keys", [destr])
    pu.add_argument("--older-than", help="only purge if expired longer than this (e.g. 7d)")
    pu.add_argument("--include-revoked", action="store_true")
    return p

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for f in ("dry_run", "yes"):
        if not hasattr(args, f): setattr(args, f, False)
    try:
        st = Store(args.store)
        rc = args.func(args, st)
        return rc or EXIT_OK
    except KeyForgeError as e:
        if args.json: print(json.dumps({"error": str(e), "exit_code": e.exit_code}))
        else: print(f"keyforge: error: {e}", file=sys.stderr)
        return e.exit_code
    except (OSError, ValueError) as e:
        print(f"keyforge: error: {e}", file=sys.stderr); return EXIT_ERR

if __name__ == "__main__":
    sys.exit(main())
