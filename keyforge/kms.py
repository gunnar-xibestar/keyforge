"""Key-management providers that wrap data-encryption keys.

The API-key secret is encrypted with a fresh 32-byte DEK (see ``crypto.seal_secret``).
A provider only ever sees that DEK. It never sees the API-key secret.

Providers
- ``local`` (default): AES-256-GCM under a 32-byte master key in a mode-0600 file.
  ``KEYFORGE_KMS_KEY_FILE`` if set, otherwise ``<store-dir>/kms-master.key``.
  This is a software KEK. Put the file outside the store directory when you want
  the ciphertext and the wrapping key on different permission boundaries.
- ``memory``: an in-process key (``KEYFORGE_KMS_PROVIDER=memory``). For tests.
  Envelopes it writes cannot be opened in another process.
- ``pkcs11``: AES-256-GCM under an AES key that lives on a PKCS#11 token
  (SoftHSM or a hardware module). The DEK is encrypted inside the token; the
  wrapping key is not exported. Requires ``python-pkcs11`` and
  ``KEYFORGE_PKCS11_MODULE``.

``FakePkcs11Token`` is the test double for the token. ``Pkcs11Token`` is the
real session. Both expose ``wrap`` / ``unwrap`` and ``Pkcs11Kms`` does not
care which one it holds.
"""
from __future__ import annotations
import hashlib, hmac, os, secrets, stat, sys
from pathlib import Path
from .errors import KeyForgeError

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:  # pragma: no cover - exercised only without the system package
    raise ImportError(
        "KeyForge KMS requires the 'cryptography' package (apt install python3-cryptography)"
    ) from e

_PROVIDERS = ("local", "memory", "pkcs11")


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


class FakePkcs11Token:
    """In-memory PKCS#11 stand-in. AES-256-GCM under a token-held key.

    ``wrap`` returns ``nonce || ciphertext||tag``. The key bytes never leave
    this object, which is the property the real token is there to provide.
    """

    def __init__(self, key: bytes, labels: tuple[str, ...] = ("keyforge-kek",)):
        if len(key) != 32:
            raise KeyForgeError("fake PKCS#11 token key must be 32 bytes")
        self._key = key
        self.labels = set(labels)
        self.wraps = 0
        self.unwraps = 0

    def wrap(self, key_label: str, dek: bytes, aad: bytes) -> bytes:
        if key_label not in self.labels:
            raise KeyForgeError(f"PKCS#11 key {key_label!r} is not on the token")
        if len(dek) != 32:
            raise KeyForgeError("DEK must be 32 bytes")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(nonce, dek, aad)
        self.wraps += 1
        return nonce + ct

    def unwrap(self, key_label: str, blob: bytes, aad: bytes) -> bytes:
        if key_label not in self.labels:
            raise KeyForgeError(f"PKCS#11 key {key_label!r} is not on the token")
        if len(blob) < 12 + 16:
            raise KeyForgeError("PKCS#11 wrapped DEK is truncated")
        nonce, ct = blob[:12], blob[12:]
        try:
            dek = AESGCM(self._key).decrypt(nonce, ct, aad)
        except InvalidTag:
            raise KeyForgeError("PKCS#11 unwrap failed authentication")
        self.unwraps += 1
        if len(dek) != 32:
            raise KeyForgeError("unwrapped DEK has an unexpected length")
        return dek


def _new_aes_key_notice(label: str) -> str:
    """Text printed when a missing token AES key is created."""
    return (
        f"keyforge: generated a new AES-256 key labeled {label!r} on the token.\n"
        "This key cannot read secrets wrapped by an older key. "
        "The label is only a name. The old key material is not in the new key."
    )


class Pkcs11Token:
    """Real PKCS#11 session. AES-256-GCM under a token AES key.

    Environment (all required except the create flag):
    - ``KEYFORGE_PKCS11_MODULE``: path to the module, e.g.
      ``/usr/lib/softhsm/libsofthsm2.so``
    - ``KEYFORGE_PKCS11_TOKEN``: token label
    - ``KEYFORGE_PKCS11_PIN``: user PIN. Read from the environment only.
      Never written to the store, logs, or error text.
    - ``KEYFORGE_PKCS11_KEY_LABEL``: AES key label on the token. A missing key
      is generated on first use. A new key cannot read secrets wrapped by an older one.

    SoftHSM also needs ``SOFTHSM2_CONF`` pointing at its config. A hardware
    module uses the same variables with its own ``.so``.
    """

    def __init__(self, module_path: str, token_label: str, pin: str, key_label: str):
        if not module_path or not token_label or not key_label:
            raise KeyForgeError("PKCS#11 module, token label, and key label are required")
        if pin is None or pin == "":
            from .softhsm import matching_tokens, setup_instructions
            conf = os.environ.get("SOFTHSM2_CONF") or os.path.expanduser("~/.keyforge/softhsm/softhsm2.conf")
            raise KeyForgeError(
                "KEYFORGE_PKCS11_PIN is required. It is the user PIN from "
                "softhsm2-util --init-token --pin, not the SO PIN.\n"
                + setup_instructions(no_token=not matching_tokens("keyforge", conf))
            )
        self.module_path = module_path
        self.token_label = token_label
        self.key_label = key_label
        self._pin = pin

    def __repr__(self) -> str:
        return (f"Pkcs11Token(module={self.module_path!r}, token={self.token_label!r}, "
                f"key={self.key_label!r})")

    def _session(self):
        problems = []
        try:
            import pkcs11
        except ImportError:
            pkcs11 = None
            problems.append(
                "python-pkcs11 is not installed "
                "(pip install python-pkcs11 — not the unrelated PyPI package named pkcs11)"
            )
        if not os.path.exists(self.module_path):
            problems.append(
                f"PKCS#11 module not found at {self.module_path!r}; "
                "install SoftHSM (Debian/Ubuntu: sudo apt install softhsm2; "
                "module often /usr/lib/softhsm/libsofthsm2.so or "
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so) "
                "or point KEYFORGE_PKCS11_MODULE at a hardware vendor .so "
                "(SoftHSM also needs SOFTHSM2_CONF)"
            )
        if problems:
            raise KeyForgeError(
                "PKCS#11 provider is not ready: " + "; ".join(problems) + ". See README PKCS#11."
            )
        try:
            lib = pkcs11.lib(self.module_path)
            token = lib.get_token(token_label=self.token_label)
            return _open_token(token, self._pin)
        except KeyForgeError:
            raise
        except Exception as e:
            raise KeyForgeError(f"PKCS#11 login failed ({_safe_exc(e, self._pin)})") from None

    def _key(self, session):
        from pkcs11 import Attribute, KeyType, ObjectClass
        found = list(session.get_objects({
            Attribute.LABEL: self.key_label,
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
        }))
        if len(found) > 1:
            raise KeyForgeError(f"PKCS#11 token has more than one key labeled {self.key_label!r}")
        if len(found) == 1:
            return found[0]
        print(_new_aes_key_notice(self.key_label), file=sys.stderr)
        return session.generate_key(
            KeyType.AES, 256, label=self.key_label, store=True,
            template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                      Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )

    def wrap(self, key_label: str, dek: bytes, aad: bytes) -> bytes:
        if key_label != self.key_label:
            raise KeyForgeError(f"PKCS#11 key {key_label!r} is not the configured key")
        if len(dek) != 32:
            raise KeyForgeError("DEK must be 32 bytes")
        from pkcs11 import Mechanism
        from pkcs11.mechanisms import GCMParams
        nonce = secrets.token_bytes(12)
        params = GCMParams(nonce, aad=aad)
        try:
            with self._session() as session:
                key = self._key(session)
                ct = key.encrypt(dek, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        except KeyForgeError:
            raise
        except Exception as e:
            raise KeyForgeError(f"PKCS#11 wrap failed ({_safe_exc(e, self._pin)})") from None
        return nonce + bytes(ct)

    def unwrap(self, key_label: str, blob: bytes, aad: bytes) -> bytes:
        if key_label != self.key_label:
            raise KeyForgeError(f"PKCS#11 key {key_label!r} is not the configured key")
        if len(blob) < 12 + 16:
            raise KeyForgeError("PKCS#11 wrapped DEK is truncated")
        from pkcs11 import Mechanism
        from pkcs11.mechanisms import GCMParams
        nonce, ct = blob[:12], blob[12:]
        params = GCMParams(nonce, aad=aad)
        try:
            with self._session() as session:
                key = self._key(session)
                dek = key.decrypt(ct, mechanism=Mechanism.AES_GCM, mechanism_param=params)
        except KeyForgeError:
            raise
        except Exception:
            # Fail closed. Do not echo token errors that could be confused with a successful unwrap.
            raise KeyForgeError("PKCS#11 unwrap failed authentication") from None
        dek = bytes(dek)
        if len(dek) != 32:
            raise KeyForgeError("unwrapped DEK has an unexpected length")
        return dek


_REDACTED = "[redacted]"
_REDACTED_ALT = "[***]"


def _contains_pin(text: str, pin: str) -> bool:
    if not text or not pin:
        return False
    return pin.casefold() in text.casefold()


def _barrier_placeholder(pin: str) -> str:
    # ``[redacted]`` can contain the PIN (``red``, ``act``), and the text on
    # either side of that marker can rebuild the PIN. A marker that shares no
    # casefolded character with the PIN cannot put it back.
    folded = pin.casefold()

    def ok(ch: str) -> bool:
        folded_ch = ch.casefold()
        return len(folded_ch) == 1 and folded_ch not in folded

    for ch in "*#@!~":
        if ok(ch):
            return ch * 3
    for cp in list(range(0x20, 0x7F)) + list(range(0xA0, 0x250)):
        ch = chr(cp)
        if ok(ch):
            return ch
    return "\uf8ff"


def _placeholder_for(pin: str) -> str:
    for candidate in (_REDACTED, _REDACTED_ALT):
        if not _contains_pin(candidate, pin):
            return candidate
    return _barrier_placeholder(pin)


def _pin_spans(text: str, pin: str) -> list[tuple[int, int]]:
    """Original-string spans of ``pin``, case-insensitive, including overlaps."""
    folded_pin = pin.casefold()
    if not folded_pin or not text:
        return []
    folded_chars: list[str] = []
    origins: list[int] = []
    for index, ch in enumerate(text):
        for folded in ch.casefold():
            folded_chars.append(folded)
            origins.append(index)
    folded = "".join(folded_chars)
    spans: list[tuple[int, int]] = []
    start = 0
    limit = len(folded_pin)
    while start < len(folded):
        found = folded.find(folded_pin, start)
        if found < 0:
            break
        orig_start = origins[found]
        orig_end = origins[found + limit - 1] + 1
        if orig_end > orig_start:
            spans.append((orig_start, orig_end))
        start = found + 1
    merged: list[list[int]] = []
    for span_start, span_end in spans:
        if merged and span_start < merged[-1][1]:
            if span_end > merged[-1][1]:
                merged[-1][1] = span_end
        else:
            merged.append([span_start, span_end])
    return [(span_start, span_end) for span_start, span_end in merged]


def _replace_pin(text: str, pin: str, placeholder: str) -> str:
    spans = _pin_spans(text, pin)
    if not spans:
        return text
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.append(text[cursor:start])
        parts.append(placeholder)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _redact_pin(text: str, pin: str) -> str:
    """Remove every case-insensitive occurrence of ``pin``, including overlaps.

    Uses ``[redacted]`` unless that marker contains ``pin``. If a replacement
    joins with neighboring text and recreates ``pin``, a second pass uses a
    marker that cannot carry ``pin``.
    """
    if not text or not pin:
        return text
    redacted = _replace_pin(text, pin, _placeholder_for(pin))
    if _contains_pin(redacted, pin):
        redacted = _replace_pin(redacted, pin, _barrier_placeholder(pin))
    if _contains_pin(redacted, pin):
        while _contains_pin(redacted, pin):
            cleared = _replace_pin(redacted, pin, "")
            if len(cleared) >= len(redacted):
                break
            redacted = cleared
    return redacted


def _exception_blob(exc: BaseException) -> str:
    parts = [type(exc).__name__, str(exc)]
    for arg in getattr(exc, "args", ()):
        if isinstance(arg, str):
            parts.append(arg)
        elif isinstance(arg, (bytes, bytearray)):
            parts.append(arg.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _iter_exception_chain(exc: BaseException):
    """Yield ``exc`` and its ``__cause__`` / ``__context__`` links, skipping cycles."""
    seen: set[int] = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending.append(current.__context__)
        pending.append(current.__cause__)


def _mentions_pin(exc: BaseException, *pins: str) -> bool:
    secrets = [pin for pin in pins if pin]
    if not secrets:
        return False
    for current in _iter_exception_chain(exc):
        blob = _exception_blob(current)
        if any(_contains_pin(blob, secret) for secret in secrets):
            return True
    return False


def _drop_chain(exc: BaseException) -> BaseException:
    """Drop cause and context so a redacted exception cannot reprint a PIN."""
    exc.__cause__ = None
    exc.__context__ = None
    exc.__suppress_context__ = True
    return exc


def _exception_without_pin(exc: BaseException, *pins: str) -> BaseException:
    """A new exception of the same type whose text no longer contains ``pins``."""
    secrets = sorted((pin for pin in pins if pin), key=len, reverse=True)
    message = str(exc)
    name = type(exc).__name__
    for secret in secrets:
        message = _redact_pin(message, secret)
        name = _redact_pin(name, secret)
    if name != type(exc).__name__:
        rebuilt: BaseException = RuntimeError(f"{name}: {message}")
    else:
        try:
            rebuilt = type(exc)(message)
        except Exception:
            rebuilt = RuntimeError(f"{name}: {message}")
    if secrets and _mentions_pin(rebuilt, *secrets):
        safe = f"{type(exc).__name__}: {exc}"
        for secret in secrets:
            safe = _redact_pin(safe, secret)
        if _mentions_pin(RuntimeError(safe), *secrets):
            safe = _barrier_placeholder(secrets[0])
        return _drop_chain(RuntimeError(safe))
    return _drop_chain(rebuilt)


def _safe_exc(exc: BaseException, pin: str) -> str:
    """Exception text with ``pin`` removed, then capped at 200 characters.

    The PIN is removed before the cut. The cut is checked again so a sliced
    marker cannot put the PIN back.
    """
    detail = _redact_pin(f"{type(exc).__name__}: {exc}", pin)[:200]
    if pin and _contains_pin(detail, pin):
        detail = _redact_pin(detail, pin)[:200]
    if pin and _contains_pin(detail, pin):
        return _barrier_placeholder(pin)
    return detail


class Pkcs11Kms:
    """Envelope wrapper around a token (real or fake) that speaks wrap/unwrap."""

    provider = "pkcs11"

    def __init__(self, token, key_label: str):
        self.token = token
        self.key_label = key_label
        self.kid = key_label

    def __repr__(self) -> str:
        return f"Pkcs11Kms(kid={self.kid!r})"

    def wrap(self, dek: bytes, aad: bytes) -> dict:
        blob = self.token.wrap(self.key_label, dek, aad)
        return {"provider": "pkcs11", "alg": "AES-256-GCM", "kid": self.key_label, "ct": blob.hex()}

    def unwrap(self, wrapped: dict, aad: bytes) -> bytes:
        if not isinstance(wrapped, dict) or wrapped.get("provider") != "pkcs11":
            raise KeyForgeError("wrapped DEK does not belong to this KMS provider")
        if wrapped.get("kid") != self.key_label:
            raise KeyForgeError("PKCS#11 key label does not match the wrapped DEK")
        try:
            blob = bytes.fromhex(wrapped["ct"])
        except (KeyError, ValueError, TypeError):
            raise KeyForgeError("malformed wrapped DEK")
        return self.token.unwrap(self.key_label, blob, aad)


def _pin_mismatch(exc: BaseException) -> bool:
    return type(exc).__name__ == "PinIncorrect"


def _open_token(token, pin: str, read_secret=None):
    """Log in with ``pin``. A wrong PIN is asked again until it is correct or the operator stops.

    A non-interactive stdin fails on the first wrong PIN. Ctrl-C exits the prompt.
    Any other token error is re-raised with the PIN removed.
    """
    current = pin
    while True:
        try:
            return token.open(rw=True, user_pin=current)
        except Exception as e:
            if _pin_mismatch(e):
                if not sys.stdin.isatty():
                    raise KeyForgeError("no terminal") from None
                print("PIN is wrong. Ctrl-C to exit.", file=sys.stderr)
                current = read_user_pin(read_secret)
                continue
            if not _mentions_pin(e, current, pin):
                raise
            failure = _drop_chain(_exception_without_pin(e, current, pin))
        raise failure


def confirm_user_pin(module: str, token_label: str, pin: str) -> None:
    """Open the token once. A wrong PIN raises ``KeyForgeError`` and does not retry."""
    if not module or not os.path.isfile(module):
        raise KeyForgeError(f"PKCS#11 module not found or unusable at {module}")
    try:
        import pkcs11
    except ImportError:
        raise KeyForgeError(
            "python-pkcs11 is not installed (pip install python-pkcs11 — not the unrelated PyPI package named pkcs11)"
        ) from None
    try:
        lib = pkcs11.lib(module)
        token = lib.get_token(token_label=token_label)
        session = token.open(rw=True, user_pin=pin)
    except Exception as e:
        if _pin_mismatch(e):
            raise KeyForgeError("PIN is wrong. Ctrl-C to exit.") from None
        raise KeyForgeError(f"PKCS#11 login failed ({_safe_exc(e, pin)})") from None
    close = getattr(session, "close", None)
    if close is None:
        return
    try:
        close()
        return
    except Exception as e:
        if not _mentions_pin(e, pin):
            raise
        failure = _drop_chain(KeyForgeError(
            f"PKCS#11 session close failed ({_safe_exc(e, pin)})"
        ))
    raise failure


def list_aes_labels(module: str, token_label: str, pin: str) -> list[str] | None:
    """AES key labels on the token. ``None`` when the token cannot be opened."""
    try:
        token = Pkcs11Token(module, token_label, pin, "keyforge-kek")
        with token._session() as session:
            from pkcs11 import Attribute, KeyType, ObjectClass
            found = session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
            })
            labels = []
            for obj in found:
                name = getattr(obj, "label", None) or ""
                labels.append(name if isinstance(name, str) else str(name))
            return labels
    except KeyForgeError:
        return None


def destroy_aes_labels(module: str, token_label: str, pin: str, labels: list[str]) -> list[str]:
    """Delete AES keys whose labels are in ``labels``. Returns the labels removed."""
    wanted = set(labels)
    removed: list[str] = []
    token = Pkcs11Token(module, token_label, pin, "keyforge-kek")
    with token._session() as session:
        from pkcs11 import Attribute, KeyType, ObjectClass
        found = list(session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
        }))
        for obj in found:
            name = getattr(obj, "label", None) or ""
            if not isinstance(name, str):
                name = str(name)
            if name in wanted:
                obj.destroy()
                removed.append(name)
    return removed


def read_user_pin(read_secret=None) -> str:
    """Ask for the token user PIN. A blank entry prints ``input blank`` and asks again.

    The value is kept in this process only. It is not written to ``keyforge.env``.
    """
    import getpass
    read_secret = read_secret or getpass.getpass
    while True:
        pin = read_secret("KEYFORGE_PKCS11_PIN: ")
        if pin:
            os.environ["KEYFORGE_PKCS11_PIN"] = pin
            return pin
        print("input blank", file=sys.stderr)


def pkcs11_from_env() -> Pkcs11Kms:
    module = os.environ.get("KEYFORGE_PKCS11_MODULE", "")
    token = os.environ.get("KEYFORGE_PKCS11_TOKEN", "")
    pin = os.environ.get("KEYFORGE_PKCS11_PIN", "")
    label = os.environ.get("KEYFORGE_PKCS11_KEY_LABEL", "")
    if not pin and module and token and label:
        if not sys.stdin.isatty():
            raise KeyForgeError("no terminal")
        pin = read_user_pin()
    missing = [n for n, v in (("KEYFORGE_PKCS11_MODULE", module), ("KEYFORGE_PKCS11_TOKEN", token),
                              ("KEYFORGE_PKCS11_PIN", pin), ("KEYFORGE_PKCS11_KEY_LABEL", label)) if not v]
    if missing:
        message = "PKCS#11 provider is missing " + ", ".join(missing)
        if "KEYFORGE_PKCS11_PIN" in missing and not (module and token and label):
            from .softhsm import matching_tokens, setup_instructions
            conf = os.environ.get("SOFTHSM2_CONF") or os.path.expanduser("~/.keyforge/softhsm/softhsm2.conf")
            message += "\n" + setup_instructions(no_token=not matching_tokens("keyforge", conf))
        raise KeyForgeError(message)
    return Pkcs11Kms(Pkcs11Token(module, token, pin, label), label)


def provider_for(store=None):
    """Select the KMS from ``KEYFORGE_KMS_PROVIDER`` (default ``local``)."""
    kind = os.environ.get("KEYFORGE_KMS_PROVIDER", "local").strip().lower()
    if kind in ("memory", "inprocess"):
        return memory_provider()
    if kind == "pkcs11":
        return pkcs11_from_env()
    if kind == "local":
        if store is None:
            raise KeyForgeError("local KMS requires a store")
        return local_provider(store)
    raise KeyForgeError(f"unknown KEYFORGE_KMS_PROVIDER {kind!r}; choose from {', '.join(_PROVIDERS)}")


def format_status(info: dict) -> list[str]:
    """Text of ``keyforge kms status``. ``result`` is success only when ``ready`` is true."""
    if info.get("no_terminal"):
        return ["no terminal"]
    failed = not info.get("ready")
    lines = ["result: failure" if failed else "result: success",
             f"provider: {info.get('provider')}", f"ready: {info.get('ready')}"]
    if info.get("key_file") is not None:
        lines.append(f"key_file: {info['key_file']} (exists={info.get('key_file_exists')})")
        if info.get("key_file_mode") is not None:
            lines.append(f"key_file_mode: {info['key_file_mode']}")
        lines.append(f"same_directory_as_store: {info.get('same_directory_as_store')}")
        lines.append(f"python_pkcs11: {info.get('python_pkcs11')}")
    if info.get("provider") == "pkcs11":
        lines.append(f"module: {info.get('module')} (exists={info.get('module_exists')})")
        lines.append(f"token: {info.get('token')}")
        lines.append(f"key_label: {info.get('key_label')}")
        lines.append(f"pin_set: {info.get('pin_set')}")
        lines.append(f"python_pkcs11: {info.get('python_pkcs11')}")
        if info.get("softhsm2_conf") is not None:
            lines.append(f"SOFTHSM2_CONF: {info['softhsm2_conf']}")
    if info.get("missing"):
        lines.append("missing: " + ", ".join(info["missing"]))
    if info.get("softhsm_setup"):
        lines.extend(str(info["softhsm_setup"]).splitlines())
    if info.get("error"):
        lines.append(f"error: {info['error']}")
    for warning in info.get("warnings") or []:
        lines.append(f"warning: {warning}")
    if info.get("note"):
        lines.append(f"note: {info['note']}")
    return lines


def status(store_path: str | None = None) -> dict:
    """Describe the configured KMS without printing secrets or the PKCS#11 PIN.

    Used by ``keyforge kms status``. Auth0 login does not use the KMS; only
    ``create`` / ``rotate`` / ``reveal`` (and import of envelopes) do.
    """
    kind = (os.environ.get("KEYFORGE_KMS_PROVIDER") or "local").strip().lower() or "local"
    info: dict = {"provider": kind, "ready": False}
    if kind in ("memory", "inprocess"):
        info["provider"] = "memory"
        info["ready"] = True
        info["note"] = "in-process only; envelopes cannot be opened after the process exits"
        return info
    if kind == "pkcs11":
        module = os.environ.get("KEYFORGE_PKCS11_MODULE", "")
        module_path = os.path.expanduser(module) if module else ""
        token = os.environ.get("KEYFORGE_PKCS11_TOKEN", "")
        label = os.environ.get("KEYFORGE_PKCS11_KEY_LABEL", "")
        pin_set = bool(os.environ.get("KEYFORGE_PKCS11_PIN", ""))
        if not pin_set and module and token and label:
            if not sys.stdin.isatty():
                info["no_terminal"] = True
                return info
            read_user_pin()
            pin_set = True
        try:
            import pkcs11  # noqa: F401
            binding = True
        except ImportError:
            binding = False
        info.update({
            "module": module or None,
            "module_exists": bool(module_path and os.path.exists(module_path)),
            "token": token or None,
            "key_label": label or None,
            "pin_set": pin_set,
            "python_pkcs11": binding,
            "softhsm2_conf": os.environ.get("SOFTHSM2_CONF") or None,
        })
        missing = []
        if not binding:
            missing.append("python-pkcs11 (pip install python-pkcs11)")
        if not module:
            missing.append("KEYFORGE_PKCS11_MODULE")
        elif not info["module_exists"]:
            missing.append(f"module file at {module_path}")
        if not token:
            missing.append("KEYFORGE_PKCS11_TOKEN")
        if not pin_set:
            missing.append("KEYFORGE_PKCS11_PIN")
        if not label:
            missing.append("KEYFORGE_PKCS11_KEY_LABEL")
        if missing:
            info["missing"] = missing
            return info
        try:
            kms = pkcs11_from_env()
            with kms.token._session():
                pass
            info["ready"] = True
        except KeyForgeError as e:
            info["error"] = str(e)
        return info
    if kind == "local":
        path = os.environ.get("KEYFORGE_KMS_KEY_FILE")
        if path:
            path = os.path.expanduser(path)
        else:
            if store_path:
                base = os.path.expanduser(store_path)
            else:
                base = os.path.expanduser(os.environ.get("KEYFORGE_STORE") or "~/.keyforge/store.json")
            path = str(Path(base).parent / "kms-master.key")
        info["key_file"] = path
        exists = os.path.exists(path)
        info["key_file_exists"] = exists
        if store_path:
            store_base = os.path.expanduser(store_path)
        else:
            store_base = os.path.expanduser(os.environ.get("KEYFORGE_STORE") or "~/.keyforge/store.json")
        store_dir = os.path.realpath(os.path.dirname(store_base))
        key_dir = os.path.realpath(os.path.dirname(path))
        info["same_directory_as_store"] = key_dir == store_dir
        warnings = [
            "software KEK on disk; anyone who can read this file and the store can reveal secrets",
        ]
        if info["same_directory_as_store"]:
            warnings.append(
                "key file is in the same directory as the store; set KEYFORGE_KMS_KEY_FILE"
                " outside that directory so the ciphertext and the wrapping key are not"
                " on the same permission boundary"
            )
        if exists:
            mode = os.stat(path).st_mode & 0o777
            info["key_file_mode"] = oct(mode)
            if mode & 0o077:
                warnings.append(f"key file mode is {oct(mode)}; chmod 600 before create/rotate/reveal")
        try:
            import pkcs11  # noqa: F401
            pkcs11_installed = True
        except ImportError:
            pkcs11_installed = False
        info["python_pkcs11"] = pkcs11_installed
        if pkcs11_installed:
            warnings.append(
                "python-pkcs11 is installed; KEYFORGE_KMS_PROVIDER=pkcs11 keeps the wrapping key off this disk"
            )
        info["warnings"] = warnings
        info["ready"] = True
        info["note"] = "used by create/rotate/reveal; auth login does not use the KMS"
        return info
    info["error"] = f"unknown KEYFORGE_KMS_PROVIDER {kind!r}; choose from {', '.join(_PROVIDERS)}"
    return info
