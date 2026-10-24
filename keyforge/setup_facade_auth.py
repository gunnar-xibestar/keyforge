"""Setup's calls into Auth0 login and status.

Names are looked up on ``keyforge.auth`` when the function runs, which is where
``setup`` used to look them up.
"""
from __future__ import annotations

from . import auth


def password_login(username: str, password: str):
    return auth.password_login(username, password)


def scope_grant(principal):
    return auth.scope_grant(principal)


def status() -> dict:
    return auth.status()
