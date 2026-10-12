"""Key generation and salted hashing (PBKDF2-HMAC-SHA256). Mock only."""
import hashlib, hmac, os, secrets, string

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
