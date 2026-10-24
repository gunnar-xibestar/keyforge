"""Setup's calls into the audit package.

Names are looked up on ``keyforge.audit`` when the function runs, which is where
``setup`` used to look them up.
"""
from __future__ import annotations

from . import audit


def last_event_lines(result: dict) -> list[str]:
    return audit.last_event_lines(result)


def walk_line(result: dict) -> str:
    return audit.walk_line(result)


def adopt_legacy(store) -> dict:
    return audit.adopt_legacy(store)


def hmac_key() -> bytes | None:
    return audit.hmac_key()


def record(store, action: str, key_id: str | None = None, **details) -> dict:
    return audit.record(store, action, key_id, **details)


def reseal_metadata_mac(store, key: bytes | None) -> bool:
    return audit.reseal_metadata_mac(store, key)


def verify_chain(log: list, meta: dict | None = None, key: bytes | None = None) -> dict:
    return audit.verify_chain(log, meta, key)
