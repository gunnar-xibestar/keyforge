"""Remove local KeyForge state without following links out of the data directory.

The default target is ``~/.keyforge`` only. A symlinked directory is refused.
Symlinks inside it are unlinked and their targets are left alone. Files named
by ``KEYFORGE_STORE`` and the other path variables are removed only when they
sit inside that directory, or when ``include_configured`` is set — and then
only the file itself, never its parent directory.
"""
from __future__ import annotations
import os
from pathlib import Path
from .errors import ValidationError
from .store import StoreLocked

CONFIGURED_VARS = (
    "KEYFORGE_STORE",
    "KEYFORGE_TOKEN_FILE",
    "KEYFORGE_KMS_KEY_FILE",
    "KEYFORGE_AUDIT_HMAC_KEY_FILE",
)


def data_dir() -> Path:
    return Path.home() / ".keyforge"


def _owned_dir(path: Path) -> None:
    if path.name != ".keyforge":
        raise ValidationError(f"refusing to remove {path}: uninstall only deletes a directory named .keyforge")
    if path.is_symlink():
        raise ValidationError(f"refusing to remove {path}: the data directory is a symlink")
    if not path.exists():
        return
    if not path.is_dir():
        raise ValidationError(f"refusing to remove {path}: not a directory")
    st = path.lstat()
    if st.st_uid != os.getuid():
        raise ValidationError(f"refusing to remove {path}: not owned by the current user")


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _configured_outside(root: Path) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for var in CONFIGURED_VARS:
        raw = os.environ.get(var)
        if not raw:
            continue
        path = Path(os.path.expanduser(raw))
        candidates = [path]
        if var == "KEYFORGE_STORE":
            candidates.append(path.with_name(path.name + ".lock"))
        for candidate in candidates:
            if candidate in seen or _inside(root, candidate):
                continue
            seen.add(candidate)
            found.append(candidate)
    return found


def _check_configured_file(path: Path) -> str | None:
    if path.is_symlink():
        return f"skipped symlink {path}"
    if not path.exists():
        return None
    if not path.is_file():
        return f"skipped non-file {path}"
    if path.lstat().st_uid != os.getuid():
        return f"skipped {path}: not owned by the current user"
    return None


def _ensure_unlocked(root: Path) -> None:
    lock = root / "store.json.lock"
    if not lock.exists() or lock.is_symlink():
        return
    import fcntl
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StoreLocked(f"store {root / 'store.json'} is locked by another process")
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def plan(root: Path | None = None, *, include_configured: bool = False) -> tuple[list[Path], list[str]]:
    """Return paths to remove (children before parents) and human-readable skips."""
    root = root or data_dir()
    _owned_dir(root)
    remove: list[Path] = []
    skipped: list[str] = []
    if root.exists():
        _ensure_unlocked(root)
        for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
            current = Path(dirpath)
            for name in dirnames:
                path = current / name
                if path.is_symlink():
                    remove.append(path)
            for name in filenames:
                path = current / name
                if path.is_symlink():
                    remove.append(path)
                    continue
                if not path.is_file():
                    skipped.append(f"skipped non-file {path}")
                    continue
                st = path.lstat()
                if st.st_uid != os.getuid():
                    skipped.append(f"skipped {path}: not owned by the current user")
                    continue
                if st.st_nlink > 1:
                    skipped.append(f"skipped hard link {path}")
                    continue
                remove.append(path)
            if current != root:
                if current.is_symlink():
                    remove.append(current)
                else:
                    remove.append(current)
        remove.append(root)
    if include_configured:
        for path in _configured_outside(root):
            reason = _check_configured_file(path)
            if reason:
                skipped.append(reason)
            elif path.exists():
                remove.append(path)
    return remove, skipped


def _wipe(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        return
    size = path.stat().st_size
    with open(path, "r+b", buffering=0) as fh:
        remaining = size
        chunk = b"\0" * 65536
        while remaining:
            n = min(remaining, len(chunk))
            fh.write(chunk[:n])
            remaining -= n
        fh.flush()
        os.fsync(fh.fileno())


def apply(paths: list[Path]) -> list[str]:
    removed: list[str] = []
    for path in paths:
        if path.is_symlink():
            path.unlink()
            removed.append(str(path))
            continue
        if path.is_file():
            _wipe(path)
            path.unlink()
            removed.append(str(path))
            continue
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                continue
            removed.append(str(path))
    return removed


def run(*, dry_run: bool, include_configured: bool, root: Path | None = None) -> dict:
    paths, skipped = plan(root, include_configured=include_configured)
    if dry_run:
        return {"dry_run": True, "removed": [str(p) for p in paths], "skipped": skipped,
                "package": "pip uninstall keyforge"}
    removed = apply(paths)
    return {"dry_run": False, "removed": removed, "skipped": skipped,
            "package": "pip uninstall keyforge"}
