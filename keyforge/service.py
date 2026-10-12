"""Business logic, independent of the CLI."""
from __future__ import annotations
import ipaddress, fnmatch
from datetime import datetime
from . import crypto, audit, policy as pol
from .errors import KeyForgeError, VerifyFailed, ValidationError, PolicyViolation
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
        audit.record(store, "verify_fail", k.id if k else None, reason=reason, prefix=pre, scope=scope, ip=ip)
        store.save()
        raise VerifyFailed(reason)
    if record_use:
        k.last_used_at = iso(now()); store.put(k)
        audit.record(store, "verify_ok", k.id, scope=scope, ip=ip)
        store.save()
    return k

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
    if status == "active" and _retired_match(_retired_creds(store), k.to_dict()):
        raise KeyForgeError(f"refusing to resume {k.id}: its credential matches a revoked or retired key")
    if status == "suspended" and cur != "active":
        raise KeyForgeError(f"can only suspend an active key (status: {cur})")
    if dry_run:
        return k
    k.status = status
    if status == "revoked":
        k.revoked_reason = reason; k.revoked_at = iso(now())
        _remember_revoked(store, k)
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
    cur_exp = parse_iso(k.expires_at)
    extends = clear_expiry and cur_exp is not None or (expires_at is not None and (cur_exp is None or expires_at > cur_exp))
    if extends and _retired_match(_retired_creds(store), k.to_dict(), exclude_id=None):
        raise KeyForgeError(f"refusing to extend/clear expiry of {k.id}: its credential matches a revoked "
                            "or retired key (rotate it instead)")
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

def purge(store, older_than=None, include_revoked=False, dry_run=False) -> list[ApiKey]:
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
    if not dry_run:
        for k in victims:
            if k.status in ("revoked", "rotated"):
                _remember_revoked(store, k, k.status)  # keep the credential on record after the key is gone
            store.delete(k.id)
            audit.record(store, "purge", k.id, status=k.effective_status())
    return victims

def export(store, include_audit=False) -> dict:
    d = {"format": "keyforge-export", "version": 1, "exported_at": iso(now()),
         "policy": store.policy, "keys": [k.to_dict() for k in store.all()]}
    if include_audit:
        d["audit"] = store.audit_log
    return d

_KEY_FIELDS = {  # field -> allowed types (None means optional)
    "id": (str,), "name": (str,), "prefix": (str,), "env": (str,), "owner": (str,),
    "team": (str, type(None)), "scopes": (list,), "hash": (dict,), "created_at": (str,),
    "expires_at": (str, type(None)), "description": (str, type(None)),
    "rate_limit": (int, type(None)), "ip_allow": (list,), "labels": (dict,), "status": (str,),
    "revoked_reason": (str, type(None)), "revoked_at": (str, type(None)),
    "rotated_to": (str, type(None)), "rotated_from": (str, type(None)),
    "grace_until": (str, type(None)), "last_used_at": (str, type(None)),
}
_REQUIRED = ("id", "name", "prefix", "env", "owner", "scopes", "hash", "created_at")
_STATUSES = ("active", "suspended", "revoked", "rotated")
_ID_RE = __import__("re").compile(r"^key_[0-9a-f]{12}$")
_HEX_RE = __import__("re").compile(r"^[0-9a-f]+$")

MIN_PBKDF2_ITERS = 1_000
MAX_PBKDF2_ITERS = 5_000_000
MIN_SALT_HEX = 32                    # 16 bytes
MAX_IMPORT_GRACE = "30d"             # grace_until may not be further out than this from now

def _validate_hash_record(h, where):
    def bad(why): raise ValidationError(f"{where}: malformed hash record ({why})")
    if not isinstance(h, dict) or set(h) != {"algo", "iterations", "salt", "hash"}:
        bad("expected exactly algo/iterations/salt/hash")
    if h["algo"] != "pbkdf2_sha256": bad("unsupported algo")
    it = h["iterations"]
    if not isinstance(it, int) or isinstance(it, bool) or not MIN_PBKDF2_ITERS <= it <= MAX_PBKDF2_ITERS:
        bad(f"iterations must be an int in [{MIN_PBKDF2_ITERS}, {MAX_PBKDF2_ITERS}]")
    salt, dk = h["salt"], h["hash"]
    if not isinstance(salt, str) or len(salt) < MIN_SALT_HEX or len(salt) % 2 or not _HEX_RE.match(salt):
        bad(f"salt must be even-length lowercase hex of at least {MIN_SALT_HEX} chars")
    if not isinstance(dk, str) or len(dk) != 64 or not _HEX_RE.match(dk):
        bad("hash must be 64 lowercase hex chars")
    try:
        bytes.fromhex(salt); bytes.fromhex(dk)
    except ValueError:
        bad("not decodable hex")

def _validate_import_record(store, d, idx) -> dict:
    """Validate one imported key record; return a normalized dict or raise ValidationError/PolicyViolation."""
    where = f"keys[{idx}]"
    if not isinstance(d, dict):
        raise ValidationError(f"{where}: record must be an object")
    unknown = set(d) - set(_KEY_FIELDS)
    if unknown:
        raise ValidationError(f"{where}: unknown field(s) {sorted(unknown)}")
    for f in _REQUIRED:
        if f not in d:
            raise ValidationError(f"{where}: missing required field {f!r}")
    for f, v in d.items():
        if not isinstance(v, _KEY_FIELDS[f]) or (f == "rate_limit" and isinstance(v, bool)):
            raise ValidationError(f"{where}: field {f!r} has wrong type")
    where = f"{where} ({d['id']})"
    if not _ID_RE.match(d["id"]):
        raise ValidationError(f"{where}: malformed id")
    status = d.get("status", "active")
    if status not in _STATUSES:
        raise ValidationError(f"{where}: invalid status {status!r}")
    if not all(isinstance(x, str) for x in d["scopes"]) or not all(isinstance(x, str) for x in d.get("ip_allow", [])):
        raise ValidationError(f"{where}: scopes and ip_allow must be lists of strings")
    if not all(isinstance(a, str) and isinstance(b, str) for a, b in d.get("labels", {}).items()):
        raise ValidationError(f"{where}: labels must map strings to strings")
    try:
        _validate(d["scopes"], d.get("ip_allow", []), d["env"])
    except ValidationError as e:
        raise ValidationError(f"{where}: {e}")
    if crypto.prefix_of(d["prefix"]) != d["prefix"] or not d["prefix"].startswith(f"kf_{d['env']}_"):
        raise ValidationError(f"{where}: prefix does not match env")
    _validate_hash_record(d["hash"], where)
    if d.get("rate_limit") is not None and d["rate_limit"] <= 0:
        raise ValidationError(f"{where}: rate limit must be positive")
    try:
        for f in ("created_at", "expires_at", "revoked_at", "grace_until", "last_used_at"):
            parse_iso(d.get(f))
    except ValueError:
        raise ValidationError(f"{where}: invalid timestamp in {f!r}")
    k = ApiKey.from_dict(d)
    if status == "revoked" and not k.revoked_at:
        raise ValidationError(f"{where}: revoked record missing revoked_at")
    if status == "rotated" and not k.grace_until:
        raise ValidationError(f"{where}: rotated record missing grace_until")
    if k.grace_until and parse_iso(k.grace_until) > now() + parse_duration(MAX_IMPORT_GRACE):
        raise ValidationError(f"{where}: grace_until exceeds the {MAX_IMPORT_GRACE} cap")
    # Enforce org policy for any record that can still authenticate (active/grace/suspended).
    if k.effective_status() not in ("revoked", "expired", "rotated"):
        try:
            pol.check(pol.effective(store), env=k.env, scopes=k.scopes, labels=k.labels,
                      expires_at=parse_iso(k.expires_at), rate_limit=k.rate_limit, ip_allow=k.ip_allow)
        except PolicyViolation as e:
            raise PolicyViolation(f"{where}: {e}")
    return k.to_dict()

def import_(store, data, overwrite=False, dry_run=False, allow_unrevoke=False) -> dict:
    """Import keys from an export file.

    The whole file is validated before anything is written: a single bad record aborts the
    import. With ``overwrite``, an existing *revoked* key is never replaced by a non-revoked
    record unless ``allow_unrevoke`` is also given (re-activating a revoked key is a deliberate act).
    """
    if not isinstance(data, dict) or data.get("format") != "keyforge-export":
        raise ValidationError("not a keyforge export file")
    if data.get("version") != 1:
        raise ValidationError(f"unsupported export version {data.get('version')!r}")
    keys = data.get("keys", [])
    if not isinstance(keys, list):
        raise ValidationError("'keys' must be a list")
    res = {"added": [], "skipped": [], "overwritten": []}
    staged, seen = [], set()
    retired = _retired_creds(store)
    changed_creds, unrevoked = [], []
    for idx, d in enumerate(keys):
        rec = _validate_import_record(store, d, idx)
        k = rec["id"]
        if k in seen:
            raise ValidationError(f"duplicate key id {k} in import file")
        seen.add(k)
        if k in store.data["keys"] and not overwrite:
            res["skipped"].append(k); continue
        # Checked for EVERY record regardless of status: an expired/rotated record can be revived
        # later with `update`, so the credential itself must not be re-introduced.
        hit = _retired_match(retired, rec)
        if hit and rec["status"] == "revoked" and all(i == k for i in hit):
            hit = None  # re-importing the same key id as revoked is harmless
        if hit:
            if not allow_unrevoke:
                raise KeyForgeError(f"refusing to import {k}: its hash or prefix belongs to revoked/retired "
                                    f"key(s) {', '.join(sorted(set(hit)))} (use --allow-unrevoke to force)")
            unrevoked.append(k)
        if not allow_unrevoke:
            for oid, od in list(store.data["keys"].items()) + [(r["id"], r) for r in staged]:
                if oid != k and (od["hash"]["hash"] == rec["hash"]["hash"] or od["prefix"] == rec["prefix"]):
                    raise KeyForgeError(f"refusing to import {k}: hash or prefix collides with key {oid} "
                                        "(use --allow-unrevoke to force)")
        if k in store.data["keys"]:
            old = store.data["keys"][k]
            if old.get("status") == "revoked" and rec["status"] != "revoked" and not allow_unrevoke:
                raise KeyForgeError(f"refusing to overwrite revoked key {k} with a non-revoked record "
                                    "(use --allow-unrevoke to force)")
            if old["hash"] != rec["hash"] or old["prefix"] != rec["prefix"]:
                changed_creds.append(k)
            res["overwritten"].append(k)
        else:
            res["added"].append(k)
        staged.append(rec)
    if not dry_run:
        for rec in staged:
            store.data["keys"][rec["id"]] = rec
            if rec["status"] == "revoked":
                _remember_revoked(store, rec)
        audit.record(store, "import", None, added=len(res["added"]),
                     overwritten=len(res["overwritten"]), skipped=len(res["skipped"]),
                     overwritten_ids=res["overwritten"] or None,
                     credential_changed_ids=changed_creds or None,
                     unrevoked=unrevoked or None)
    return res

def _remember_revoked(store, k, kind="revoked") -> None:
    """Record a retired (revoked or rotated) key's hash/prefix in a list that survives purge."""
    d = k if isinstance(k, dict) else k.to_dict()
    if not any(r["hash"] == d["hash"]["hash"] for r in store.revoked_hashes):
        store.revoked_hashes.append({"id": d["id"], "prefix": d["prefix"], "hash": d["hash"]["hash"],
                                     "kind": kind, "at": d.get("revoked_at") or d.get("grace_until")})

def _retired_creds(store) -> list[tuple[str, str, str]]:
    """(id, prefix, hash) of every remembered retired credential plus currently revoked keys."""
    out = [(r["id"], r["prefix"], r["hash"]) for r in store.revoked_hashes]
    out += [(i, kd["prefix"], kd["hash"]["hash"]) for i, kd in store.data["keys"].items()
            if kd.get("status") == "revoked"]
    return out

def _retired_match(retired, d, exclude_id=None) -> list[str]:
    return [i for i, p, h in retired if i != exclude_id and (h == d["hash"]["hash"] or p == d["prefix"])]

