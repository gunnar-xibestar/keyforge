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

``FakePkcs11Token`` lives in ``tests/fakes.py``. It is the test double for the
token. ``Pkcs11Token`` is the real session. Both expose ``wrap`` / ``unwrap``
and ``Pkcs11Kms`` does not care which one it holds.
"""
from __future__ import annotations
import os
from ..errors import KeyForgeError

_PROVIDERS = ("local", "memory", "pkcs11")

from . import local, pkcs11, status
from .local import LocalKms, local_provider, memory_provider
from .pkcs11 import (
    Pkcs11Kms, Pkcs11Token,
    _mentions_pin, _new_aes_key_notice, _open_token, _safe_exc,  # noqa: F401  # re-exported for tests
    confirm_user_pin, destroy_aes_labels, list_aes_labels, pkcs11_from_env, read_user_pin,
)
from .status import status as kms_status

__all__ = [
    "local", "pkcs11", "status",
    "LocalKms", "Pkcs11Kms", "Pkcs11Token",
    "provider_for", "local_provider", "memory_provider", "pkcs11_from_env",
    "format_status", "kms_status",
    "confirm_user_pin", "destroy_aes_labels", "list_aes_labels", "read_user_pin",
    "KeyForgeError",
]


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
