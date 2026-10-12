"""Data model and time helpers."""
from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone

ENVS = ("live", "test")
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]*:[a-z0-9_*-]+$")

def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None

def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

_DUR = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

def parse_duration(s: str) -> timedelta:
    m = _DUR.match(s.strip().lower())
    if not m:
        raise ValueError(f"invalid duration {s!r} (use e.g. 30d, 12h, 15m, 2w)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})

@dataclass
class ApiKey:
    id: str
    name: str
    prefix: str
    env: str
    owner: str
    team: str | None
    scopes: list[str]
    hash: dict
    created_at: str
    expires_at: str | None = None
    description: str | None = None
    rate_limit: int | None = None
    ip_allow: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    status: str = "active"          # active | suspended | revoked | rotated
    revoked_reason: str | None = None
    revoked_at: str | None = None
    rotated_to: str | None = None
    rotated_from: str | None = None
    grace_until: str | None = None
    last_used_at: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ApiKey":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def effective_status(self, at: datetime | None = None) -> str:
        at = at or now()
        if self.status in ("revoked", "suspended"):
            return self.status
        if self.status == "rotated":
            g = parse_iso(self.grace_until)
            return "grace" if g and at < g else "rotated"
        exp = parse_iso(self.expires_at)
        if exp and at >= exp:
            return "expired"
        return "active"

    def public(self) -> dict:
        d = self.to_dict()
        d.pop("hash")
        d["effective_status"] = self.effective_status()
        return d
