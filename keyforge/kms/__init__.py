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
import os, secrets, sys, types
from ..errors import KeyForgeError

_PROVIDERS = ("local", "memory", "pkcs11")

from . import local, pkcs11
from .local import (
    AESGCM, InvalidTag, LocalKms, _load_or_create_master, _wipe, local_provider, memory_provider,
)
from .pkcs11 import (
    Pkcs11Kms, Pkcs11Token, _REDACTED, _REDACTED_ALT, _barrier_placeholder, _contains_pin,
    _drop_chain, _exception_blob, _exception_without_pin, _iter_exception_chain, _mentions_pin,
    _new_aes_key_notice, _open_token, _pin_mismatch, _pin_spans, _placeholder_for, _redact_pin,
    _replace_pin, _resolve_user_pin, _safe_exc, confirm_user_pin, destroy_aes_labels,
    list_aes_labels, pkcs11_from_env, read_user_pin,
)
from .status import _NoTerminal, status


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


class _UserPin:
    """The process PIN cache lives on ``pkcs11._user_pin`` and nowhere else.

    ``keyforge.kms._user_pin`` is this descriptor, so assignments and
    ``mock.patch`` on the package hit that one global. ``mock.patch`` treats a
    name that is not in the module dict as non-local and ``delattr``s it on
    the way out, then writes the saved value back if the name looks missing.
    ``__delete__`` hides the descriptor for that instant so the saved value is
    restored onto ``pkcs11._user_pin``.
    """

    def __init__(self) -> None:
        self._hidden = False

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        if self._hidden:
            raise AttributeError("_user_pin")
        return sys.modules[__name__ + ".pkcs11"]._user_pin

    def __set__(self, obj, value):
        self._hidden = False
        sys.modules[__name__ + ".pkcs11"]._user_pin = value

    def __delete__(self, obj):
        self._hidden = True


class _KmsModule(types.ModuleType):
    _user_pin = _UserPin()

    def __dir__(self):
        return sorted(set(super().__dir__()) | {"_user_pin"})


sys.modules[__name__].__class__ = _KmsModule
