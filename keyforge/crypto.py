"""Key generation, salted hashing, and envelope encryption.

Verification still uses PBKDF2-HMAC-SHA256. The recoverable copy of a secret is a
separate AES-256-GCM envelope: a fresh DEK encrypts the secret, and a KMS provider
wraps that DEK. Plaintext is never written by these functions.
"""
import hashlib, hmac, os, secrets, string
from .errors import KeyForgeError, ValidationError

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "KeyForge secret storage requires the 'cryptography' package "
        "(apt install python3-cryptography)"
    ) from e

ALPHABET = string.ascii_letters + string.digits
PREFIX_RANDOM_LEN = 8
SECRET_LEN = 32

def iterations() -> int:
    return int(os.environ.get("KEYFORGE_PBKDF2_ITERS", "200000"))

def generate_key(env: str) -> tuple[str, str]:
    """Return (full_key, display_prefix). Format: kf_<env>_<random>."""
    rnd = "".join(secrets.choice(ALPHABET) for _ in range(SECRET_LEN))
    full = f"kf_{env}_{rnd}"
    return full, f"kf_{env}_{rnd[:PREFIX_RANDOM_LEN]}"

def prefix_of(full: str) -> str | None:
    parts = full.split("_", 2)
    if len(parts) != 3 or parts[0] != "kf" or len(parts[2]) < PREFIX_RANDOM_LEN:
        return None
    return f"kf_{parts[1]}_{parts[2][:PREFIX_RANDOM_LEN]}"

def hash_secret(secret: str, salt: bytes | None = None, iters: int | None = None) -> dict:
    salt = salt or os.urandom(16)
    iters = iters or iterations()
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iters)
    return {"algo": "pbkdf2_sha256", "iterations": iters, "salt": salt.hex(), "hash": dk.hex()}

def check_secret(secret: str, h: dict) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(h["salt"]), h["iterations"])
    return hmac.compare_digest(dk.hex(), h["hash"])

def new_id() -> str:
    return "key_" + secrets.token_hex(6)

def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0

def _secret_aad(key_id: str) -> bytes:
    return f"keyforge-secret-v1|{key_id}".encode()

def _dek_aad(key_id: str) -> bytes:
    return f"keyforge-dek-v1|{key_id}".encode()

def _hex_str(value, *, exact=None, min_len=0, max_len=4096) -> str:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise ValidationError("expected even-length lowercase hex")
    if any(c not in "0123456789abcdef" for c in value):
        raise ValidationError("expected even-length lowercase hex")
    if exact is not None and len(value) != exact:
        raise ValidationError(f"expected {exact} hex chars")
    if not min_len <= len(value) <= max_len:
        raise ValidationError("hex value has an unexpected length")
    return value

def validate_envelope(env: dict) -> None:
    """Structural check used by import. Cryptographic checks happen at reveal."""
    if not isinstance(env, dict) or set(env) != {"v", "alg", "nonce", "ct", "wrapped_dek"}:
        raise ValidationError("malformed secret envelope")
    if env["v"] != 1 or env["alg"] != "AES-256-GCM":
        raise ValidationError("unsupported secret envelope algorithm")
    _hex_str(env["nonce"], exact=24)
    _hex_str(env["ct"], min_len=34, max_len=4096)  # at least 1 byte + 16-byte tag
    w = env["wrapped_dek"]
    if not isinstance(w, dict):
        raise ValidationError("malformed wrapped DEK")
    prov = w.get("provider")
    kid = w.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
        raise ValidationError("wrapped DEK key id is missing or too long")
    if prov in ("local", "memory"):
        if set(w) != {"provider", "alg", "kid", "nonce", "ct"} or w.get("alg") != "AES-256-GCM":
            raise ValidationError("malformed software-wrapped DEK")
        _hex_str(w["nonce"], exact=24)
        _hex_str(w["ct"], exact=96, max_len=96)  # 32-byte DEK + 16-byte tag
    elif prov == "pkcs11":
        if set(w) != {"provider", "alg", "kid", "ct"} or w.get("alg") != "AES-256-GCM":
            raise ValidationError("malformed pkcs11-wrapped DEK")
        _hex_str(w["ct"], min_len=(12 + 32 + 16) * 2, max_len=512)
    else:
        raise ValidationError("unknown KMS provider on secret envelope")

def seal_secret(secret: str, *, key_id: str, kms) -> dict:
    """Encrypt ``secret`` and wrap the DEK. Returns JSON-safe envelope fields."""
    if not isinstance(secret, str) or not secret:
        raise KeyForgeError("refusing to seal an empty secret")
    dek = bytearray(secrets.token_bytes(32))
    try:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(bytes(dek)).encrypt(nonce, secret.encode(), _secret_aad(key_id))
        wrapped = kms.wrap(bytes(dek), _dek_aad(key_id))
    finally:
        _wipe(dek)
    env = {"v": 1, "alg": "AES-256-GCM", "nonce": nonce.hex(), "ct": ct.hex(), "wrapped_dek": wrapped}
    validate_envelope(env)
    return env

def open_secret(envelope: dict, *, key_id: str, kms) -> str:
    """Decrypt an envelope. Fails closed on tamper, a wrong key, or a bad shape."""
    try:
        validate_envelope(envelope)
    except ValidationError as e:
        raise KeyForgeError(f"malformed secret envelope: {e}") from None
    wrapped = envelope["wrapped_dek"]
    if wrapped["provider"] != kms.provider:
        raise KeyForgeError(
            f"secret was wrapped by {wrapped['provider']!r} but the active KMS is {kms.provider!r}"
        )
    dek = bytearray(kms.unwrap(wrapped, _dek_aad(key_id)))
    try:
        try:
            pt = AESGCM(bytes(dek)).decrypt(bytes.fromhex(envelope["nonce"]),
                                            bytes.fromhex(envelope["ct"]), _secret_aad(key_id))
        except InvalidTag:
            raise KeyForgeError("secret envelope failed authentication (tampered or wrong key)")
    finally:
        _wipe(dek)
    try:
        return pt.decode()
    except UnicodeDecodeError:
        raise KeyForgeError("decrypted secret is not valid text")
