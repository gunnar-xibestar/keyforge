"""Setup's calls into SoftHSM token discovery, creation, and deletion."""
from __future__ import annotations

from .softhsm import delete_token as _delete_token
from .softhsm import init_token as _init_token
from .softhsm import matching_tokens as _matching_tokens


def matching_tokens(label: str, conf_path: str | None) -> list[str]:
    return _matching_tokens(label, conf_path)


def init_token(conf_path: str, label: str, pin: str, so_pin: str) -> str:
    return _init_token(conf_path, label, pin, so_pin)


def delete_token(path: str, conf_path: str | None, *, label: str) -> str | None:
    return _delete_token(path, conf_path, label=label)
