"""JSON file store with atomic writes. Only salted hashes are persisted."""
from __future__ import annotations
import json, os, tempfile
from pathlib import Path
from .models import ApiKey
from .errors import NotFound, KeyForgeError

DEFAULT_STORE = "~/.keyforge/store.json"

def resolve_path(path: str | None) -> Path:
    return Path(os.path.expanduser(path or os.environ.get("KEYFORGE_STORE") or DEFAULT_STORE))

class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = resolve_path(str(path) if path else None)
        self.data = {"version": 1, "keys": {}, "audit": [], "policy": {}}
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text()))
            except json.JSONDecodeError as e:
                raise KeyForgeError(f"corrupt store {self.path}: {e}")

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".kf-")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def all(self) -> list[ApiKey]:
        return [ApiKey.from_dict(d) for d in self.data["keys"].values()]

    def put(self, k: ApiKey) -> None:
        self.data["keys"][k.id] = k.to_dict()

    def delete(self, key_id: str) -> None:
        self.data["keys"].pop(key_id, None)

    def get(self, ref: str) -> ApiKey:
        """Lookup by id, exact prefix, or unique name."""
        if ref in self.data["keys"]:
            return ApiKey.from_dict(self.data["keys"][ref])
        m = [k for k in self.all() if k.prefix == ref] or [k for k in self.all() if k.name == ref]
        if len(m) == 1:
            return m[0]
        if len(m) > 1:
            raise KeyForgeError(f"ambiguous reference {ref!r}: {', '.join(k.id for k in m)}")
        raise NotFound(f"key not found: {ref}")

    def by_prefix(self, prefix: str) -> list[ApiKey]:
        return [k for k in self.all() if k.prefix == prefix]

    @property
    def policy(self) -> dict:
        return self.data.setdefault("policy", {})

    @property
    def audit_log(self) -> list:
        return self.data.setdefault("audit", [])
