from __future__ import annotations
import os
from pathlib import Path

from ..errors import KeyForgeError
from . import _PROVIDERS
from .pkcs11 import _resolve_user_pin, pkcs11_from_env


class _NoTerminal(KeyForgeError):
    """stdin is not a terminal, so the user PIN cannot be prompted."""

    def __init__(self) -> None:
        super().__init__("no terminal")


def status(store_path: str | None = None, pin: str | None = None) -> dict:
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
        try:
            resolved = _resolve_user_pin(pin, module, token, label)
        except _NoTerminal:
            info["no_terminal"] = True
            return info
        pin_set = bool(resolved)
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
            kms = pkcs11_from_env(resolved)
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
