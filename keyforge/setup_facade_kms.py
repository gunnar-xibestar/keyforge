"""Setup's calls into the KMS.

``keyforge.kms.status`` is the submodule. The status function is ``kms_status``,
imported from that submodule. This module does not use the shadowed package name.

Patch ``keyforge.setup.confirm_user_pin``, ``keyforge.setup.list_aes_labels``,
``keyforge.setup.destroy_aes_labels``, ``keyforge.setup.format_status``, and
``keyforge.setup.kms_status``. Setup looks those names up on itself. The
functions below are bound at import, so patching ``keyforge.kms`` or
``keyforge.kms.pkcs11`` does not intercept them. ``kms_status`` calls the
function imported from ``keyforge.kms.status``.
"""
from __future__ import annotations

from .kms import format_status as _format_status
from .kms.pkcs11 import confirm_user_pin as _confirm_user_pin
from .kms.pkcs11 import destroy_aes_labels as _destroy_aes_labels
from .kms.pkcs11 import list_aes_labels as _list_aes_labels
from .kms.status import status as _status


def confirm_user_pin(module: str, token_label: str, pin: str) -> None:
    return _confirm_user_pin(module, token_label, pin)


def destroy_aes_labels(module: str, token_label: str, pin: str, labels: list[str]) -> list[str]:
    return _destroy_aes_labels(module, token_label, pin, labels)


def list_aes_labels(module: str, token_label: str, pin: str) -> list[str] | None:
    return _list_aes_labels(module, token_label, pin)


def format_status(info: dict) -> list[str]:
    return _format_status(info)


def kms_status(store_path: str | None = None, pin: str | None = None) -> dict:
    return _status(store_path, pin)
