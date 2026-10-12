"""JSON file store with atomic writes and an exclusive fcntl lock. Only salted hashes are persisted.

Concurrency model: a ``Store(path, lock=True)`` takes an exclusive ``flock`` on ``<store>.lock``
*before* reading the store and holds it until ``close()`` (or the end of a ``with`` block). The whole
read-modify-write cycle is therefore serialized across processes, so a concurrent ``verify`` cannot
save a stale snapshot over a ``revoke``. The CLI always opens the store this way.
"""
from __future__ import annotations
import fcntl, json, os, tempfile, time
from pathlib import Path
from .models import ApiKey
from .errors import NotFound, KeyForgeError

class StoreLocked(KeyForgeError):
    exit_code = 8

DEFAULT_STORE = "~/.keyforge/store.json"

def resolve_path(path: str | None) -> Path:
    return Path(os.path.expanduser(path or os.environ.get("KEYFORGE_STORE") or DEFAULT_STORE))

class Store:
    def __init__(self, path: str | Path | None = None, lock: bool = False):
        self.path = resolve_path(str(path) if path else None)
        self._lock_fd = None
        if lock:
            self.acquire()
        self.data = {"version": 1, "keys": {}, "audit": [], "policy": {}}
        self._load()

    # -- locking --------------------------------------------------------------
    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @property
    def locked(self) -> bool:
        return self._lock_fd is not None

    def acquire(self, timeout: float | None = None) -> None:
        """Take the exclusive lock, polling with LOCK_NB until ``timeout`` seconds
        (default $KEYFORGE_LOCK_TIMEOUT or 30s). Raises StoreLocked on timeout."""
        if self._lock_fd is not None:
            return
        if timeout is None:
            timeout = float(os.environ.get("KEYFORGE_LOCK_TIMEOUT", "30"))
        self._mkdirs()
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise StoreLocked(f"store {self.path} is locked by another process (waited {timeout:g}s)")
                    time.sleep(0.05)
        except BaseException:
            os.close(fd); raise
        self._lock_fd = fd

    def _mkdirs(self) -> None:
        d = self.path.parent
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Tighten a pre-existing KeyForge-owned dir (e.g. ~/.keyforge left at 0755). Only dirs named
        # ".keyforge" are touched, so --store /tmp/x.json never chmods a shared directory.
        if d.name == ".keyforge":
            st = os.stat(d)
            if st.st_uid == os.getuid() and st.st_mode & 0o077:
                os.chmod(d, 0o700)

    def release(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd); self._lock_fd = None

    close = release

    def __enter__(self):
        self.acquire(); self._load(); return self

    def __exit__(self, *exc):
        self.release()

    def __del__(self):
        try: self.release()
        except Exception: pass

    # -- io -------------------------------------------------------------------
    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
            except json.JSONDecodeError as e:
                raise KeyForgeError(f"corrupt store {self.path}: {e}")
            self.data = {"version": 1, "keys": {}, "audit": [], "policy": {}}
            self.data.update(data)
        else:  # brand-new store: start the audit chain now, with zero legacy events
            self.data.setdefault("audit_meta", {"legacy": 0, "count": 0, "head": "0" * 64})

    def save(self) -> None:
        """Atomically replace the store file. If this Store does not already hold the lock, the
        write itself is still done under the lock (but the caller's read was not protected)."""
        held = self.locked
        if not held:
            self.acquire()
        try:
            self._mkdirs()
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".kf-")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self.data, f, indent=2, sort_keys=True)
                    f.flush(); os.fsync(f.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
                dfd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try: os.fsync(dfd)  # make the rename durable
                finally: os.close(dfd)
            except BaseException:
                if os.path.exists(tmp): os.unlink(tmp)
                raise
        finally:
            if not held:
                self.release()

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

    @property
    def revoked_hashes(self) -> list:
        """Hashes/prefixes of every key ever revoked; never purged."""
        return self.data.setdefault("revoked_hashes", [])
