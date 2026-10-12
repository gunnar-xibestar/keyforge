"""Organisation policy: max TTL, allowed scopes, required labels, etc."""
from __future__ import annotations
import fnmatch
from datetime import datetime
from .errors import PolicyViolation
from .models import parse_duration, now, parse_iso

DEFAULT_POLICY = {
    "max_ttl": None,              # e.g. "90d"
    "require_expiry": False,
    "allowed_scopes": [],         # glob patterns, empty = any
    "required_labels": [],
    "max_rate_limit": None,
    "live_requires_ip_allow": False,
    "default_grace_period": "24h",
}

def effective(store) -> dict:
    p = dict(DEFAULT_POLICY)
    p.update(store.policy)
    return p

def check(policy: dict, *, env: str, scopes, labels: dict, expires_at: datetime | None,
          rate_limit=None, ip_allow=()) -> None:
    errs = []
    if policy.get("allowed_scopes"):
        for s in scopes:
            if not any(fnmatch.fnmatch(s, pat) for pat in policy["allowed_scopes"]):
                errs.append(f"scope {s!r} not allowed by policy")
    for lbl in policy.get("required_labels") or []:
        if lbl not in labels:
            errs.append(f"required label {lbl!r} missing")
    if policy.get("require_expiry") and not expires_at:
        errs.append("policy requires an expiry")
    if policy.get("max_ttl"):
        limit = now() + parse_duration(policy["max_ttl"])
        if not expires_at:
            errs.append(f"policy max_ttl={policy['max_ttl']} requires an expiry")
        elif expires_at > limit:
            errs.append(f"expiry exceeds policy max_ttl={policy['max_ttl']}")
    if policy.get("max_rate_limit") and rate_limit and rate_limit > policy["max_rate_limit"]:
        errs.append(f"rate limit {rate_limit} exceeds policy max {policy['max_rate_limit']}")
    if policy.get("live_requires_ip_allow") and env == "live" and not ip_allow:
        errs.append("live keys require at least one --ip-allow CIDR")
    if errs:
        raise PolicyViolation("; ".join(errs))
