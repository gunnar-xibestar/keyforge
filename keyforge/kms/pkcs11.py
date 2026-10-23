from __future__ import annotations
import os, secrets, sys
from ..errors import KeyForgeError


# Prompted user PIN for this process. Same shape as ``_memory_key``:
# unset until a prompt, then reused. Never copied into ``os.environ``.
_user_pin: str | None = None


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
    - ``KEYFORGE_PKCS11_PIN``: user PIN when the environment already has one.
      A missing PIN can also be passed in, taken from the process cache, or
      read from a TTY prompt. The prompt is not copied into the environment.
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
            from ..softhsm import matching_tokens, setup_instructions
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

            def _keep(pin: str) -> None:
                self._pin = pin

            return _open_token(token, self._pin, remember=_keep)
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
    marker cannot put the PIN back. The prompted process-cache PIN is removed
    the same way.
    """
    secrets = sorted({secret for secret in (pin, _user_pin) if secret}, key=len, reverse=True)
    detail = f"{type(exc).__name__}: {exc}"
    for secret in secrets:
        detail = _redact_pin(detail, secret)
    detail = detail[:200]
    for secret in secrets:
        if _contains_pin(detail, secret):
            detail = _redact_pin(detail, secret)[:200]
    for secret in secrets:
        if _contains_pin(detail, secret):
            return _barrier_placeholder(secret)
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


def _open_token(token, pin: str, read_secret=None, remember=None):
    """Log in with ``pin``. A wrong PIN is asked again until it is correct or the operator stops.

    A non-interactive stdin fails on the first wrong PIN. Ctrl-C exits the prompt.
    Any other token error is re-raised with the PIN removed.
    A corrected PIN stays in the process cache. ``remember``, when passed, is
    called with that PIN after the login succeeds so the caller can reuse it.
    A PIN the token rejects is removed from the cache. The retry prompt is
    cached only after that login succeeds, so Ctrl-C or a missing TTY cannot
    leave a wrong PIN ahead of ``KEYFORGE_PKCS11_PIN``.
    """
    global _user_pin
    current = pin
    prompted = False
    while True:
        try:
            session = token.open(rw=True, user_pin=current)
        except Exception as e:
            if _pin_mismatch(e):
                if _user_pin == current:
                    _user_pin = None
                if not sys.stdin.isatty():
                    raise KeyForgeError("no terminal") from None
                print("PIN is wrong. Ctrl-C to exit.", file=sys.stderr)
                current = read_user_pin(read_secret)
                # Login has not happened yet. Hold the prompt out of the cache
                # until this PIN actually opens the token.
                if _user_pin == current:
                    _user_pin = None
                prompted = True
                continue
            secrets = tuple(secret for secret in (current, pin, _user_pin) if secret)
            if not _mentions_pin(e, *secrets):
                raise
            failure = _drop_chain(_exception_without_pin(e, *secrets))
        else:
            if prompted:
                _user_pin = current
            if remember is not None and current != pin:
                remember(current)
            return session
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
        secrets = (pin, _user_pin) if _user_pin else (pin,)
        if not _mentions_pin(e, *secrets):
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

    The value is stored in this process only. It is not written to ``os.environ``
    or to ``keyforge.env``.
    """
    global _user_pin
    import getpass
    read_secret = read_secret or getpass.getpass
    while True:
        pin = read_secret("KEYFORGE_PKCS11_PIN: ")
        if pin:
            _user_pin = pin
            return pin
        print("input blank", file=sys.stderr)


class _NoTerminal(KeyForgeError):
    """stdin is not a terminal, so the user PIN cannot be prompted."""

    def __init__(self) -> None:
        super().__init__("no terminal")


def _resolve_user_pin(pin: str | None, module: str, token: str, label: str) -> str:
    """Argument, then the process cache, then ``KEYFORGE_PKCS11_PIN``, then a TTY prompt.

    A prompt runs only when the module, token label, and key label are all
    present. Otherwise the caller reports the missing settings and does not ask.
    """
    if pin:
        return pin
    if _user_pin:
        return _user_pin
    env_pin = os.environ.get("KEYFORGE_PKCS11_PIN", "")
    if env_pin:
        return env_pin
    if module and token and label:
        if not sys.stdin.isatty():
            raise _NoTerminal()
        return read_user_pin()
    return ""


def pkcs11_from_env(pin: str | None = None) -> Pkcs11Kms:
    module = os.environ.get("KEYFORGE_PKCS11_MODULE", "")
    token = os.environ.get("KEYFORGE_PKCS11_TOKEN", "")
    label = os.environ.get("KEYFORGE_PKCS11_KEY_LABEL", "")
    resolved = _resolve_user_pin(pin, module, token, label)
    missing = [n for n, v in (("KEYFORGE_PKCS11_MODULE", module), ("KEYFORGE_PKCS11_TOKEN", token),
                              ("KEYFORGE_PKCS11_PIN", resolved), ("KEYFORGE_PKCS11_KEY_LABEL", label)) if not v]
    if missing:
        message = "PKCS#11 provider is missing " + ", ".join(missing)
        if "KEYFORGE_PKCS11_PIN" in missing and not (module and token and label):
            from ..softhsm import matching_tokens, setup_instructions
            conf = os.environ.get("SOFTHSM2_CONF") or os.path.expanduser("~/.keyforge/softhsm/softhsm2.conf")
            message += "\n" + setup_instructions(no_token=not matching_tokens("keyforge", conf))
        raise KeyForgeError(message)
    return Pkcs11Kms(Pkcs11Token(module, token, resolved, label), label)
