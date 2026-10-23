from __future__ import annotations

import secrets

from keyforge.errors import KeyForgeError
from keyforge.kms.local import AESGCM, InvalidTag


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
