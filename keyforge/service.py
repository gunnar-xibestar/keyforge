"""Business logic, independent of the CLI."""
from __future__ import annotations
import ipaddress, fnmatch
from datetime import datetime
from . import crypto, audit, policy as pol
from .errors import KeyForgeError, VerifyFailed, ValidationError
from .models import ApiKey, ENVS, SCOPE_RE, now, iso, parse_iso, parse_duration

def _validate(scopes, ip_allow, env=None):
    if env is not None and env not in ENVS:
        raise ValidationError(f"env must be one of {ENVS}")
    for s in scopes:
        if not SCOPE_RE.match(s):
            raise ValidationError(f"invalid scope {s!r} (expected resource:action, e.g. read:packets)")
    for c in ip_allow:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise ValidationError(f"invalid CIDR {c!r}")

def resolve_expiry(expires_in=None, expires_at=None) -> datetime | None:
    if expires_in and expires_at:
        raise ValidationError("use only one of --expires-in / --expires-at")
    try:
        if expires_in:
            return now() + parse_duration(expires_in)
        if expires_at:
            return parse_iso(expires_at)
    except ValueError as e:
        raise ValidationError(str(e))
    return None

def create(store, *, name, owner, env="test", team=None, scopes=(), expires_at=None,
           rate_limit=None, ip_allow=(), labels=None, description=None, dry_run=False,
           rotated_from=None) -> tuple[ApiKey, str | None]:
    scopes = sorted(set(scopes)); ip_allow = list(ip_allow); labels = dict(labels or {})
    _validate(scopes, ip_allow, env)
    if rate_limit is not None and rate_limit <= 0:
        raise ValidationError("rate limit must be positive")
    if expires_at and expires_at <= now():
        raise ValidationError("expiry must be in the future")
    pol.check(pol.effective(store), env=env, scopes=scopes, labels=labels,
              expires_at=expires_at, rate_limit=rate_limit, ip_allow=ip_allow)
    full, prefix = crypto.generate_key(env)
    k = ApiKey(id=crypto.new_id(), name=name, prefix=prefix, env=env, owner=owner, team=team,
               scopes=scopes, hash=crypto.hash_secret(full), created_at=iso(now()),
               expires_at=iso(expires_at), description=description, rate_limit=rate_limit,
               ip_allow=ip_allow, labels=labels, rotated_from=rotated_from)
    if dry_run:
        return k, None
    store.put(k)
    audit.record(store, "create", k.id, name=name, env=env, scopes=scopes)
    return k, full

def list_keys(store, owner=None, team=None, env=None, status=None, scope=None, label=None):
    out = []
    for k in store.all():
        if owner and k.owner != owner: continue
        if team and k.team != team: continue
        if env and k.env != env: continue
        if status and k.effective_status() != status: continue
        if scope and not any(fnmatch.fnmatch(s, scope) for s in k.scopes): continue
        if label:
            lk, _, lv = label.partition("=")
            if k.labels.get(lk) != lv: continue
        out.append(k)
    return sorted(out, key=lambda k: k.created_at)

def scope_granted(granted, required) -> bool:
    return any(fnmatch.fnmatch(required, g) for g in granted)

def verify(store, secret, scope=None, ip=None, record_use=True) -> ApiKey:
    pre = crypto.prefix_of(secret)
    reason = "unknown key"
    k = None
    for cand in store.by_prefix(pre) if pre else []:
        if crypto.check_secret(secret, cand.hash):
            k = cand; break
    if k:
        st = k.effective_status()
        if st not in ("active", "grace"):
            reason = f"key is {st}"
        elif scope and not scope_granted(k.scopes, scope):
            reason = f"missing scope {scope}"
        elif ip and k.ip_allow and not any(
                ipaddress.ip_address(ip) in ipaddress.ip_network(c, strict=False) for c in k.ip_allow):
            reason = f"ip {ip} not in allow list"
        else:
            reason = None
    if reason:
        _commit_verify(store, None, "verify_fail", k.id if k else None,
                       reason=reason, prefix=pre, scope=scope, ip=ip)
        raise VerifyFailed(reason)
    if record_use:
        ts = iso(now()); k.last_used_at = ts
        _commit_verify(store, (k.id, ts, k.hash), "verify_ok", k.id, scope=scope, ip=ip)
    return k

def _commit_verify(store, last_used, action, key_id, **details):
    """Persist verify side effects without clobbering concurrent writes.

    Under the store lock, re-read the on-disk state and apply *only* the verify delta
    (``last_used_at`` + one audit event) to it, instead of writing back the in-memory snapshot
    that was read before verification. A revoke that landed in between is thereby preserved.
    """
    held = store.locked
    if not held:
        store.acquire()
    try:
        store._load()
        if last_used:
            kid, ts, h = last_used
            cur = store.data["keys"].get(kid)
            st = ApiKey.from_dict(cur).effective_status() if cur else "deleted"
            if cur is None or cur.get("hash") != h or st not in ("active", "grace"):
                # state changed between our read and the lock: re-decide on fresh data
                reason = f"key is {st}" if cur is None or cur.get("hash") == h else "key changed during verification"
                audit.record(store, "verify_fail", kid, reason=reason, **details)
                store.save()
                raise VerifyFailed(reason)
            cur["last_used_at"] = ts
        audit.record(store, action, key_id, **details)
        store.save()
    finally:
        if not held:
            store.release()

def rotate(store, ref, grace_period=None, dry_run=False):
    old = store.get(ref)
    if old.effective_status() not in ("active",):
        raise KeyForgeError(f"cannot rotate key in status {old.effective_status()}")
    gp = grace_period or pol.effective(store).get("default_grace_period") or "0s"
    try:
        grace_until = now() + parse_duration(gp)
    except ValueError as e:
        raise ValidationError(str(e))
    exp = parse_iso(old.expires_at)
    if exp:  # preserve original TTL length
        exp = now() + (exp - parse_iso(old.created_at))
    new, full = create(store, name=old.name, owner=old.owner, env=old.env, team=old.team,
                       scopes=old.scopes, expires_at=exp, rate_limit=old.rate_limit,
                       ip_allow=old.ip_allow, labels=old.labels, description=old.description,
                       dry_run=dry_run, rotated_from=old.id)
    if dry_run:
        return old, new, None, grace_until
    old.status = "rotated"; old.rotated_to = new.id; old.grace_until = iso(grace_until)
    store.put(old)
    audit.record(store, "rotate", old.id, new_key=new.id, grace_until=iso(grace_until))
    return old, new, full, grace_until

def set_status(store, ref, status, reason=None, dry_run=False) -> ApiKey:
    k = store.get(ref)
    cur = k.effective_status()
    if cur == "revoked":
        raise KeyForgeError("key is already revoked")
    if status == "active" and k.status != "suspended":
        raise KeyForgeError(f"can only resume a suspended key (status: {cur})")
    if status == "suspended" and cur != "active":
        raise KeyForgeError(f"can only suspend an active key (status: {cur})")
    if dry_run:
        return k
    k.status = status
    if status == "revoked":
        k.revoked_reason = reason; k.revoked_at = iso(now())
    store.put(k)
    audit.record(store, {"revoked": "revoke", "suspended": "suspend", "active": "resume"}[status],
                 k.id, reason=reason)
    return k

def update(store, ref, add_scopes=(), remove_scopes=(), set_labels=None, unset_labels=(),
           expires_at=None, clear_expiry=False, rate_limit=None, description=None,
           add_ip=(), remove_ip=(), dry_run=False) -> ApiKey:
    k = store.get(ref)
    if k.effective_status() == "revoked":
        raise KeyForgeError("cannot update a revoked key")
    _validate(add_scopes, add_ip)
    scopes = sorted((set(k.scopes) | set(add_scopes)) - set(remove_scopes))
    labels = {**k.labels, **(set_labels or {})}
    for l in unset_labels: labels.pop(l, None)
    ips = [c for c in k.ip_allow if c not in remove_ip] + [c for c in add_ip if c not in k.ip_allow]
    exp = None if clear_expiry else (expires_at or parse_iso(k.expires_at))
    rl = rate_limit if rate_limit is not None else k.rate_limit
    pol.check(pol.effective(store), env=k.env, scopes=scopes, labels=labels, expires_at=exp,
              rate_limit=rl, ip_allow=ips)
    changes = {}
    for f, v in (("scopes", scopes), ("labels", labels), ("ip_allow", ips), ("expires_at", iso(exp)),
                 ("rate_limit", rl), ("description", description if description is not None else k.description)):
        if getattr(k, f) != v:
            changes[f] = v; setattr(k, f, v)
    if not dry_run and changes:
        store.put(k)
        audit.record(store, "update", k.id, changes=changes)
    return k

def purge(store, older_than=None, include_revoked=False, dry_run=False, only_ids=None) -> list[ApiKey]:
    cutoff = now() - (parse_duration(older_than) if older_than else parse_duration("0s"))
    victims = []
    for k in store.all():
        st = k.effective_status()
        if st == "expired" and parse_iso(k.expires_at) <= cutoff:
            victims.append(k)
        elif st == "rotated" and parse_iso(k.grace_until) <= cutoff:
            victims.append(k)
        elif include_revoked and st == "revoked" and parse_iso(k.revoked_at) <= cutoff:
            victims.append(k)
    if only_ids is not None:
        victims = [k for k in victims if k.id in only_ids]
    if not dry_run:
        for k in victims:
            store.delete(k.id)
            audit.record(store, "purge", k.id, status=k.effective_status())
    return victims

def export(store, include_audit=False) -> dict:
    d = {"format": "keyforge-export", "version": 1, "exported_at": iso(now()),
         "policy": store.policy, "keys": [k.to_dict() for k in store.all()]}
    if include_audit:
        d["audit"] = store.audit_log
    return d

def import_(store, data, overwrite=False, dry_run=False) -> dict:
    if data.get("format") != "keyforge-export":
        raise ValidationError("not a keyforge export file")
    res = {"added": [], "skipped": [], "overwritten": []}
    for d in data.get("keys", []):
        k = d["id"]
        if k in store.data["keys"]:
            if not overwrite:
                res["skipped"].append(k); continue
            res["overwritten"].append(k)
        else:
            res["added"].append(k)
        if not dry_run:
            store.data["keys"][k] = d
    if not dry_run:
        audit.record(store, "import", None, added=len(res["added"]),
                     overwritten=len(res["overwritten"]), skipped=len(res["skipped"]))
    return res
