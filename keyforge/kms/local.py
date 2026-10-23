from __future__ import annotations
import hashlib, hmac, os, secrets, stat
from ..errors import KeyForgeError

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:  # pragma: no cover - exercised only without the system package
    raise ImportError(
        "KeyForge KMS requires the 'cryptography' package (apt install python3-cryptography)"
    ) from e


def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


class LocalKms:
    """AES-256-GCM wrap of a DEK under a software master key."""

    def __init__(self, key: bytes, *, provider: str = "local"):
        if len(key) != 32:
            raise KeyForgeError("KMS master key must be exactly 32 bytes")
        if provider not in ("local", "memory"):
            raise KeyForgeError(f"unsupported software KMS provider {provider!r}")
        self._key = key
        self.provider = provider
        self.kid = hashlib.sha256(key).hexdigest()[:16]

    def __repr__(self) -> str:
        return f"LocalKms(provider={self.provider!r}, kid={self.kid!r})"

    def wrap(self, dek: bytes, aad: bytes) -> dict:
        if len(dek) != 32:
            raise KeyForgeError("DEK must be 32 bytes")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(nonce, dek, aad)
        return {"provider": self.provider, "alg": "AES-256-GCM", "kid": self.kid,
                "nonce": nonce.hex(), "ct": ct.hex()}

    def unwrap(self, wrapped: dict, aad: bytes) -> bytes:
        if not isinstance(wrapped, dict) or wrapped.get("provider") != self.provider:
            raise KeyForgeError("wrapped DEK does not belong to this KMS provider")
        if not hmac.compare_digest(str(wrapped.get("kid", "")), self.kid):
            raise KeyForgeError("KMS key id does not match the wrapped DEK (wrong master key)")
        try:
            nonce = bytes.fromhex(wrapped["nonce"])
            ct = bytes.fromhex(wrapped["ct"])
        except (KeyError, ValueError, TypeError):
            raise KeyForgeError("malformed wrapped DEK")
        if len(nonce) != 12:
            raise KeyForgeError("malformed wrapped DEK")
        try:
            dek = AESGCM(self._key).decrypt(nonce, ct, aad)
        except InvalidTag:
            raise KeyForgeError("wrapped DEK failed authentication (tampered or wrong key)")
        if len(dek) != 32:
            raise KeyForgeError("unwrapped DEK has an unexpected length")
        return dek


_memory_key: bytes | None = None


def memory_provider() -> LocalKms:
    """Process-lifetime master key. ``KEYFORGE_KMS_MEMORY_KEY`` (64 hex chars) pins it."""
    global _memory_key
    raw = os.environ.get("KEYFORGE_KMS_MEMORY_KEY")
    if raw:
        try:
            key = bytes.fromhex(raw.strip())
        except ValueError:
            raise KeyForgeError("KEYFORGE_KMS_MEMORY_KEY must be 64 hex chars")
        if len(key) != 32:
            raise KeyForgeError("KEYFORGE_KMS_MEMORY_KEY must be 64 hex chars")
        return LocalKms(key, provider="memory")
    if _memory_key is None:
        _memory_key = secrets.token_bytes(32)
    return LocalKms(_memory_key, provider="memory")


def _load_or_create_master(path: str) -> bytes:
    """Read a 32-byte master key, creating it mode 0600 if the file is empty.

    Refuses symlinks, non-regular files, group/world access, and unexpected lengths.
    An existing file with loose permissions is not silently tightened.
    """
    path = os.path.expanduser(path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as e:
        raise KeyForgeError(f"KMS key file {path} unusable: {e.strerror}")
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyForgeError(f"KMS key file {path} is not a regular file")
        if st.st_size == 0:
            os.fchmod(fd, 0o600)
            key = secrets.token_bytes(32)
            os.write(fd, key)
            os.fsync(fd)
            return key
        if st.st_mode & 0o077:
            raise KeyForgeError(f"KMS key file {path} must not be group/world accessible (chmod 600)")
        data = os.read(fd, 64)
        if len(data) != 32:
            raise KeyForgeError(f"KMS key file {path} must contain exactly 32 bytes")
        return data
    finally:
        os.close(fd)


def local_provider(store) -> LocalKms:
    path = os.environ.get("KEYFORGE_KMS_KEY_FILE")
    if path:
        path = os.path.expanduser(path)
    else:
        path = str(store.path.parent / "kms-master.key")
    return LocalKms(_load_or_create_master(path), provider="local")

