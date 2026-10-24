"""Characterization of KMS round-trips and of PIN redaction on PKCS#11 errors.

The envelopes below were produced by the current ``memory_provider`` and
``FakePkcs11Token`` code (through ``crypto.seal_secret``). They are a fixture:
a later refactor has to decrypt these bytes, not replace them with a fresh wrap.
PKCS#11 is stubbed in-process so the suite does not need SoftHSM.
"""
import io, json, logging, os, subprocess, sys, traceback, unittest
from contextlib import redirect_stderr
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyforge import crypto
from keyforge import kms
from keyforge.errors import KeyForgeError
from keyforge.kms import (
    Pkcs11Kms, Pkcs11Token, _safe_exc, confirm_user_pin,
    memory_provider, pkcs11_from_env, read_user_pin,
)
from tests.fakes import FakePkcs11Token

# Recorded ciphertext. Do not regenerate.
MEMORY_KEY_HEX = "11" * 32
MEMORY_KEY_ID = "key_fixturemem01"
MEMORY_SECRET = "kf_test_fixturesecretvalue000000"
MEMORY_ENVELOPE = {
    "v": 1,
    "alg": "AES-256-GCM",
    "nonce": "7981e5a0a056619ad530afe1",
    "ct": "8ed4d9e5d99e47152d47e567eb070f8de2dc078dc6a66150c36c364170a72b7da21dbb6efba6c4fb29f3b7c5017b29e0",
    "wrapped_dek": {
        "provider": "memory",
        "alg": "AES-256-GCM",
        "kid": "02d449a31fbb267c",
        "nonce": "53724a89da417a19cb2a89de",
        "ct": "370b69c08b616ab3b18fbaf68cdd46680ce01149bc36de8fd85bae3755e36ad428c19ee1fb37c45b3cd7d8625b7114b9",
    },
}

FAKE_TOKEN_KEY_HEX = "ab" * 32
FAKE_LABEL = "keyforge-kek"
FAKE_KEY_ID = "key_fixturepkcs1"
FAKE_SECRET = "kf_test_pkcs11fixturesecret0000"
FAKE_ENVELOPE = {
    "v": 1,
    "alg": "AES-256-GCM",
    "nonce": "3a02778f1dea0ba3e350f4b2",
    "ct": "ff1a9331c9ae75fdb1e99eb6bd7c24bc05f0ca34c3f2e33048cc7ae9d7651e8b735d31a359a2e38d2a2e0b568317b8",
    "wrapped_dek": {
        "provider": "pkcs11",
        "alg": "AES-256-GCM",
        "kid": "keyforge-kek",
        "ct": "78f68594915f594f058778fb57bc92bf05de9d87140486766fdf516457acc0af62954c73cd9b4f7a74fc513571756ae5a20d41d5f9baa9298be04fa8",
    },
}

PIN = "kf-user-pin-7c2e9a"
WRONG_PIN = "kf-wrong-pin-19aa"

_ENV_KEYS = (
    "KEYFORGE_KMS_PROVIDER", "KEYFORGE_KMS_MEMORY_KEY", "KEYFORGE_KMS_KEY_FILE",
    "KEYFORGE_PKCS11_MODULE", "KEYFORGE_PKCS11_TOKEN", "KEYFORGE_PKCS11_PIN",
    "KEYFORGE_PKCS11_KEY_LABEL", "SOFTHSM2_CONF",
)


class PinIncorrect(Exception):
    """Name matches ``kms.pkcs11._pin_mismatch`` (it checks the class name only)."""


class _QuietError(Exception):
    """``str`` hides args, so a PIN on the chain or in a bytes arg is not in the message."""

    def __str__(self):
        return "token failure"


def _dek_aad(key_id):
    return f"keyforge-dek-v1|{key_id}".encode()


class _AesKey:
    def __init__(self, label, token):
        self.label = label
        self._token = token

    def encrypt(self, data, mechanism=None, mechanism_param=None):
        if self._token.encrypt_error is not None:
            raise self._token.encrypt_error
        return AESGCM(self._token.raw_key).encrypt(
            mechanism_param.nonce, bytes(data), mechanism_param.aad)

    def decrypt(self, data, mechanism=None, mechanism_param=None):
        if self._token.decrypt_error is not None:
            raise self._token.decrypt_error
        return AESGCM(self._token.raw_key).decrypt(
            mechanism_param.nonce, bytes(data), mechanism_param.aad)


class _Session:
    def __init__(self, token):
        self._token = token

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        self._token.closed += 1
        if self._token.close_error is not None:
            raise self._token.close_error

    def get_objects(self, template):
        label = template.get("LABEL")
        keys = self._token.keys
        if label is not None:
            keys = [k for k in keys if k.label == label]
        return list(keys)

    def generate_key(self, key_type, size, label=None, store=True, template=None):
        self._token.generated.append({
            "key_type": key_type, "size": size, "label": label, "store": store,
            "template": dict(template or {}),
        })
        key = _AesKey(label, self._token)
        self._token.keys.append(key)
        return key


class _Token:
    """PKCS#11 token double. ``open`` records the PIN and can raise with it."""

    def __init__(self):
        self.raw_key = bytes(range(32))
        self.keys = []
        self.generated = []
        self.pins = []
        self.open_error = None
        self.accept_pin = None
        self.encrypt_error = None
        self.decrypt_error = None
        self.closed = 0
        self.close_error = None

    def seed(self, label, n=1):
        for _ in range(n):
            self.keys.append(_AesKey(label, self))

    def open(self, rw=True, user_pin=None):
        self.pins.append(user_pin)
        if self.open_error is not None:
            raise self.open_error
        if self.accept_pin is not None and user_pin != self.accept_pin:
            raise PinIncorrect(f"CKR_PIN_INCORRECT {user_pin}")
        return _Session(self)


def _pkcs11_module_names():
    return [name for name in list(sys.modules) if name == "pkcs11" or name.startswith("pkcs11.")]


def _snapshot_pkcs11():
    """Remove every cached ``pkcs11`` module and return the previous entries.

    Putting back only ``pkcs11`` and ``pkcs11.mechanisms`` leaves the rest of
    the real package loaded. The next import then binds a different ``KeyType``
    than ``pkcs11._pkcs11``, and SoftHSM ``generate_key`` raises
    ``ArgumentsBad: key_type must be KeyType``.
    """
    saved = {name: sys.modules[name] for name in _pkcs11_module_names()}
    for name in saved:
        del sys.modules[name]
    return saved


def _restore_pkcs11(saved):
    for name in _pkcs11_module_names():
        del sys.modules[name]
    sys.modules.update(saved)


def _install_pkcs11(testcase, token):
    import types
    saved = _snapshot_pkcs11()
    mod = types.ModuleType("pkcs11")
    mechanisms = types.ModuleType("pkcs11.mechanisms")

    class Mechanism:
        AES_GCM = "AES_GCM"

    class Attribute:
        LABEL = "LABEL"
        CLASS = "CLASS"
        KEY_TYPE = "KEY_TYPE"
        SENSITIVE = "SENSITIVE"
        EXTRACTABLE = "EXTRACTABLE"
        ENCRYPT = "ENCRYPT"
        DECRYPT = "DECRYPT"

    class KeyType:
        AES = "AES"

    class ObjectClass:
        SECRET_KEY = "SECRET_KEY"

    class GCMParams:
        def __init__(self, nonce, aad=b""):
            self.nonce = nonce
            self.aad = aad

    mechanisms.GCMParams = GCMParams
    mod.Mechanism = Mechanism
    mod.Attribute = Attribute
    mod.KeyType = KeyType
    mod.ObjectClass = ObjectClass
    mod.mechanisms = mechanisms
    mod.lib = lambda path: type("Lib", (), {"get_token": lambda self, token_label=None: token})()
    sys.modules["pkcs11"] = mod
    sys.modules["pkcs11.mechanisms"] = mechanisms
    testcase.addCleanup(_restore_pkcs11, saved)


class _EnvCase(unittest.TestCase):
    def setUp(self):
        self._saved_env = {name: os.environ.get(name) for name in _ENV_KEYS}
        for name in _ENV_KEYS:
            os.environ.pop(name, None)
        kms.pkcs11._user_pin = None
        self.addCleanup(self._restore_env)
        self.addCleanup(setattr, kms.pkcs11, "_user_pin", None)

    def _restore_env(self):
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _capture_logs(self):
        records = []

        class _Handler(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))
                if record.exc_info and record.exc_info[1] is not None:
                    records.append("".join(traceback.format_exception(record.exc_info[1])))

        root = logging.getLogger()
        handler = _Handler(level=logging.DEBUG)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(handler)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, old_level)
        return records

    def assertPinHidden(self, pin, *blobs, exc=None):
        if exc is not None:
            rendered = "".join(traceback.format_exception(exc))
            blobs = blobs + (str(exc), repr(exc), rendered)
            self.assertIsNone(exc.__cause__)
        for blob in blobs:
            self.assertNotIn(pin, blob)


class MemoryRoundTripTests(_EnvCase):
    def setUp(self):
        super().setUp()
        os.environ["KEYFORGE_KMS_MEMORY_KEY"] = MEMORY_KEY_HEX

    def test_live_encrypt_decrypt_round_trip(self):
        kms_prov = memory_provider()
        dek = bytes(range(32))
        aad = _dek_aad("key_liveround")
        wrapped = kms_prov.wrap(dek, aad)
        self.assertEqual(kms_prov.provider, "memory")
        self.assertEqual(wrapped["alg"], "AES-256-GCM")
        self.assertEqual(len(wrapped["nonce"]), 24)
        self.assertEqual(len(wrapped["ct"]), 96)
        self.assertNotEqual(wrapped["nonce"], MEMORY_ENVELOPE["wrapped_dek"]["nonce"])
        self.assertEqual(kms_prov.unwrap(wrapped, aad), dek)
        self.assertNotIn(MEMORY_KEY_HEX, repr(kms_prov))
        self.assertNotIn(MEMORY_KEY_HEX, json.dumps(wrapped))
        flipped = dict(wrapped)
        flipped["ct"] = ("0" if wrapped["ct"][0] != "0" else "1") + wrapped["ct"][1:]
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(flipped, aad)
        self.assertIn("authentication", str(cm.exception))
        with self.assertRaises(KeyForgeError):
            kms_prov.unwrap(wrapped, b"other-aad")

    def test_recorded_ciphertext_still_decrypts(self):
        kms_prov = memory_provider()
        self.assertEqual(kms_prov.kid, MEMORY_ENVELOPE["wrapped_dek"]["kid"])
        dek = kms_prov.unwrap(MEMORY_ENVELOPE["wrapped_dek"], _dek_aad(MEMORY_KEY_ID))
        self.assertEqual(len(dek), 32)
        opened = crypto.open_secret(MEMORY_ENVELOPE, key_id=MEMORY_KEY_ID, kms=kms_prov)
        self.assertEqual(opened, MEMORY_SECRET)
        blob = json.dumps(MEMORY_ENVELOPE)
        self.assertNotIn(MEMORY_SECRET, blob)
        self.assertNotIn(MEMORY_KEY_HEX, blob)

    def test_recorded_ciphertext_rejects_tamper_and_wrong_key(self):
        kms_prov = memory_provider()
        env = json.loads(json.dumps(MEMORY_ENVELOPE))
        ct = env["ct"]
        env["ct"] = ("0" if ct[0] != "0" else "1") + ct[1:]
        with self.assertRaises(KeyForgeError) as cm:
            crypto.open_secret(env, key_id=MEMORY_KEY_ID, kms=kms_prov)
        self.assertNotIn(MEMORY_SECRET, str(cm.exception))
        os.environ["KEYFORGE_KMS_MEMORY_KEY"] = "22" * 32
        other = memory_provider()
        with self.assertRaises(KeyForgeError) as cm:
            crypto.open_secret(MEMORY_ENVELOPE, key_id=MEMORY_KEY_ID, kms=other)
        self.assertIn("wrong master key", str(cm.exception))
        self.assertNotIn(MEMORY_SECRET, str(cm.exception))
        self.assertNotIn(MEMORY_KEY_HEX, str(cm.exception))

    def test_rejects_malformed_and_bad_memory_key(self):
        kms_prov = memory_provider()
        aad = _dek_aad("key_bad")
        with self.assertRaises(KeyForgeError):
            kms_prov.wrap(b"\x01" * 16, aad)
        wrapped = kms_prov.wrap(b"\x02" * 32, aad)
        foreign = dict(wrapped, provider="local")
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(foreign, aad)
        self.assertIn("does not belong", str(cm.exception))
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, ct="zz"), aad)
        self.assertIn("malformed", str(cm.exception))
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, nonce="aa" * 8), aad)
        self.assertIn("malformed", str(cm.exception))
        nonce = bytes.fromhex(wrapped["nonce"])
        short = AESGCM(bytes.fromhex(MEMORY_KEY_HEX)).encrypt(nonce, b"\x03" * 16, aad)
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, ct=short.hex()), aad)
        self.assertIn("unexpected length", str(cm.exception))

        os.environ["KEYFORGE_KMS_MEMORY_KEY"] = "not-hex"
        with self.assertRaises(KeyForgeError) as cm:
            memory_provider()
        self.assertNotIn("not-hex", str(cm.exception))
        os.environ["KEYFORGE_KMS_MEMORY_KEY"] = "ab" * 16
        with self.assertRaises(KeyForgeError) as cm:
            memory_provider()
        self.assertNotIn("ab" * 16, str(cm.exception))
        self.assertIn("64 hex", str(cm.exception))


class FakePkcs11RoundTripTests(unittest.TestCase):
    def _kms(self):
        token = FakePkcs11Token(bytes.fromhex(FAKE_TOKEN_KEY_HEX), (FAKE_LABEL,))
        return token, Pkcs11Kms(token, FAKE_LABEL)

    def test_live_encrypt_decrypt_round_trip(self):
        token, kms_prov = self._kms()
        dek = bytes(range(32))
        aad = _dek_aad("key_liveround")
        wrapped = kms_prov.wrap(dek, aad)
        self.assertEqual(token.wraps, 1)
        self.assertEqual(wrapped["provider"], "pkcs11")
        self.assertEqual(wrapped["kid"], FAKE_LABEL)
        self.assertNotIn("nonce", wrapped)
        self.assertEqual(kms_prov.unwrap(wrapped, aad), dek)
        self.assertEqual(token.unwraps, 1)
        self.assertNotEqual(wrapped["ct"], FAKE_ENVELOPE["wrapped_dek"]["ct"])
        env = crypto.seal_secret(FAKE_SECRET, key_id="key_liveround", kms=kms_prov)
        self.assertEqual(crypto.open_secret(env, key_id="key_liveround", kms=kms_prov), FAKE_SECRET)
        blob = json.dumps(env)
        self.assertNotIn(FAKE_SECRET, blob)
        self.assertNotIn(FAKE_TOKEN_KEY_HEX, blob)
        with self.assertRaises(KeyForgeError):
            kms_prov.unwrap(wrapped, b"other-aad")

    def test_recorded_ciphertext_still_decrypts(self):
        token, kms_prov = self._kms()
        dek = kms_prov.unwrap(FAKE_ENVELOPE["wrapped_dek"], _dek_aad(FAKE_KEY_ID))
        self.assertEqual(len(dek), 32)
        self.assertEqual(token.unwraps, 1)
        opened = crypto.open_secret(FAKE_ENVELOPE, key_id=FAKE_KEY_ID, kms=kms_prov)
        self.assertEqual(opened, FAKE_SECRET)
        blob = json.dumps(FAKE_ENVELOPE)
        self.assertNotIn(FAKE_SECRET, blob)
        self.assertNotIn(FAKE_TOKEN_KEY_HEX, blob)

    def test_recorded_ciphertext_rejects_tamper(self):
        _token, kms_prov = self._kms()
        env = json.loads(json.dumps(FAKE_ENVELOPE))
        blob = bytes.fromhex(env["wrapped_dek"]["ct"])
        env["wrapped_dek"]["ct"] = (bytes([blob[0] ^ 0x01]) + blob[1:]).hex()
        with self.assertRaises(KeyForgeError) as cm:
            crypto.open_secret(env, key_id=FAKE_KEY_ID, kms=kms_prov)
        self.assertIn("authentication", str(cm.exception).lower())
        self.assertNotIn(FAKE_SECRET, str(cm.exception))

    def test_rejects_bad_token_inputs(self):
        with self.assertRaises(KeyForgeError):
            FakePkcs11Token(b"\x00" * 16)
        token, kms_prov = self._kms()
        aad = b"aad"
        with self.assertRaises(KeyForgeError) as cm:
            token.wrap("missing", b"\x01" * 32, aad)
        self.assertIn("not on the token", str(cm.exception))
        with self.assertRaises(KeyForgeError):
            token.wrap(FAKE_LABEL, b"\x01" * 16, aad)
        with self.assertRaises(KeyForgeError) as cm:
            token.unwrap("missing", b"\x00" * 40, aad)
        self.assertIn("not on the token", str(cm.exception))
        with self.assertRaises(KeyForgeError) as cm:
            token.unwrap(FAKE_LABEL, b"\x00" * 20, aad)
        self.assertIn("truncated", str(cm.exception))
        nonce = b"\x07" * 12
        short = AESGCM(bytes.fromhex(FAKE_TOKEN_KEY_HEX)).encrypt(nonce, b"\x03" * 16, aad)
        with self.assertRaises(KeyForgeError) as cm:
            token.unwrap(FAKE_LABEL, nonce + short, aad)
        self.assertIn("unexpected length", str(cm.exception))

        wrapped = dict(FAKE_ENVELOPE["wrapped_dek"])
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, provider="memory"), _dek_aad(FAKE_KEY_ID))
        self.assertIn("does not belong", str(cm.exception))
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, kid="other-label"), _dek_aad(FAKE_KEY_ID))
        self.assertIn("does not match", str(cm.exception))
        with self.assertRaises(KeyForgeError) as cm:
            kms_prov.unwrap(dict(wrapped, ct="zz"), _dek_aad(FAKE_KEY_ID))
        self.assertIn("malformed", str(cm.exception))
        self.assertNotIn(FAKE_TOKEN_KEY_HEX, repr(kms_prov))


class PinRedactionTests(_EnvCase):
    def test_safe_exc_redacts_pin_before_truncating(self):
        # PIN starts inside the 200-character window and runs past it, so a
        # truncate-then-redact implementation would leave a prefix behind.
        filler = "m" * 172
        detail = _safe_exc(RuntimeError(filler + PIN + "TAIL"), PIN)
        self.assertTrue(detail.startswith("RuntimeError:"))
        self.assertLessEqual(len(detail), 200)
        self.assertIn("[redacted]", detail)
        self.assertNotIn(PIN, detail)
        self.assertNotIn(PIN[:8], detail)
        both = _safe_exc(RuntimeError(f"{PIN}/{PIN}"), PIN)
        self.assertEqual(both, "RuntimeError: [redacted]/[redacted]")
        self.assertNotIn(PIN, both)

    def test_safe_exc_leaves_text_that_does_not_contain_the_pin(self):
        detail = _safe_exc(RuntimeError("token offline"), PIN)
        self.assertEqual(detail, "RuntimeError: token offline")
        self.assertNotIn(PIN, detail)
        # An empty PIN is not a wildcard. It must not wipe the message.
        self.assertEqual(_safe_exc(RuntimeError("token offline"), ""), "RuntimeError: token offline")
        long = _safe_exc(RuntimeError("n" * 500), PIN)
        self.assertEqual(long, ("RuntimeError: " + "n" * 500)[:200])

    def assertSecretGone(self, pin, *blobs, exc=None):
        folded = pin.casefold()
        if exc is not None:
            rendered = "".join(traceback.format_exception(exc))
            blobs = blobs + (str(exc), repr(exc), rendered)
            self.assertIsNone(exc.__cause__)
            context = exc.__context__
            if context is not None:
                blobs = blobs + (
                    str(context), repr(context), "".join(traceback.format_exception(context)),
                )
        for blob in blobs:
            self.assertNotIn(folded, blob.casefold())

    def test_safe_exc_redacts_case_variants(self):
        detail = _safe_exc(RuntimeError("token said SECRET"), "secret")
        self.assertEqual(detail, "RuntimeError: token said [redacted]")
        mixed = _safe_exc(RuntimeError("SeCrEt/SECRET/secret"), "secret")
        self.assertEqual(mixed, "RuntimeError: [redacted]/[redacted]/[redacted]")
        self.assertSecretGone("secret", detail, mixed)
        # ß casefolds to "ss", so the whole word is one match, not two letters.
        sharp = _safe_exc(RuntimeError("pass STRASSE word"), "straße")
        self.assertEqual(sharp, "RuntimeError: pass [redacted] word")
        self.assertSecretGone("straße", sharp)
        self.assertSecretGone("strasse", sharp)

    def test_safe_exc_redacts_overlapping_and_repeated_pins(self):
        # A non-overlapping replace leaves the tail of "aaaa" ("[redacted]a").
        detail = _safe_exc(RuntimeError("aaaa"), "aaa")
        self.assertEqual(detail, "RuntimeError: [redacted]")
        self.assertSecretGone("aaa", detail)
        repeated = _safe_exc(RuntimeError("aaa aaa"), "aaa")
        self.assertEqual(repeated, "RuntimeError: [redacted] [redacted]")
        self.assertSecretGone("aaa", repeated)
        mixed = _safe_exc(RuntimeError("AaAa"), "aaa")
        self.assertEqual(mixed, "RuntimeError: [redacted]")
        self.assertSecretGone("aaa", mixed)
        separated = _safe_exc(RuntimeError("aaaXaaa"), "aaa")
        self.assertEqual(separated, "RuntimeError: [redacted]X[redacted]")
        self.assertSecretGone("aaa", separated)

    def test_safe_exc_pin_substring_of_placeholder_is_removed(self):
        # "red" is inside "[redacted]", so that marker would put the PIN back.
        detail = _safe_exc(RuntimeError("bad red pin"), "red")
        self.assertTrue(detail.startswith("RuntimeError:"))
        self.assertSecretGone("red", detail)
        self.assertNotIn("[redacted]", detail.casefold())
        for pin in ("red", "act", "e", "[redacted]", "Red"):
            text = f"before {pin} middle {pin.swapcase()} after"
            redacted = _safe_exc(RuntimeError(text), pin)
            self.assertLessEqual(len(redacted), 200)
            self.assertSecretGone(pin, redacted)
            if pin.casefold() in "[redacted]":
                self.assertNotIn("[redacted]", redacted.casefold())
        # The marker itself does not contain the PIN, but the join recreates it:
        # "zz[r" -> "z[redacted]" still starts with "z[r".
        joined = _safe_exc(RuntimeError("zz[r"), "z[r")
        self.assertSecretGone("z[r", joined)

    def test_safe_exc_truncation_boundary_does_not_reveal_pin(self):
        # PIN starts inside the 200-character window. A different case means a
        # case-sensitive replace after the cut would keep the prefix.
        filler = "m" * 172
        detail = _safe_exc(RuntimeError(filler + PIN.upper() + "TAIL"), PIN)
        self.assertTrue(detail.startswith("RuntimeError:"))
        self.assertLessEqual(len(detail), 200)
        self.assertIn("[redacted]", detail)
        self.assertSecretGone(PIN, detail)
        self.assertNotIn(PIN[:8].upper(), detail)
        self.assertNotIn(PIN[:8], detail.lower())
        # "red" sits where a "[redacted]" marker would be sliced to "[red".
        hostile = "x" * 182
        sliced = _safe_exc(RuntimeError(hostile + "red" + "TAIL"), "red")
        self.assertLessEqual(len(sliced), 200)
        self.assertSecretGone("red", sliced)
        self.assertNotIn("[red", sliced.lower())

    def test_read_user_pin_does_not_log_the_pin(self):
        answers = iter(["", PIN])
        prompts = []

        def read_secret(prompt):
            prompts.append(prompt)
            if len(prompts) == 1:
                self.assertIsNone(kms.pkcs11._user_pin)
            return next(answers)

        err = io.StringIO()
        logs = self._capture_logs()
        with redirect_stderr(err):
            got = read_user_pin(read_secret)
        self.assertEqual(got, PIN)
        self.assertEqual(prompts, ["KEYFORGE_PKCS11_PIN: ", "KEYFORGE_PKCS11_PIN: "])
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))
        self.assertEqual(kms.pkcs11._user_pin, PIN)
        self.assertIn("input blank", err.getvalue())
        self.assertPinHidden(PIN, err.getvalue(), "\n".join(logs), "\n".join(prompts))

    def test_open_token_retry_does_not_log_pin(self):
        from keyforge.kms import _open_token

        class Token:
            def open(self, rw, user_pin):
                if user_pin != PIN:
                    raise PinIncorrect(f"CKR_PIN_INCORRECT {user_pin}")
                return "session"

        err = io.StringIO()
        logs = self._capture_logs()
        with mock.patch("sys.stdin.isatty", return_value=True), redirect_stderr(err):
            opened = _open_token(Token(), WRONG_PIN, read_secret=lambda _p: PIN)
        self.assertEqual(opened, "session")
        self.assertIn("PIN is wrong", err.getvalue())
        joined = err.getvalue() + "\n" + "\n".join(logs)
        self.assertPinHidden(PIN, joined)
        self.assertPinHidden(WRONG_PIN, joined)

    def test_open_token_noninteractive_hides_library_pin(self):
        from keyforge.kms import _open_token

        class Token:
            def open(self, rw, user_pin):
                raise PinIncorrect(f"CKR_PIN_INCORRECT {user_pin}")

        logs = self._capture_logs()
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(KeyForgeError) as cm:
                _open_token(Token(), PIN, read_secret=lambda _p: "unused")
        self.assertIn("no terminal", str(cm.exception))
        self.assertPinHidden(PIN, "\n".join(logs), exc=cm.exception)

    def _token(self, *, label="keyforge-kek"):
        stub = _Token()
        _install_pkcs11(self, stub)
        tok = Pkcs11Token(__file__, "keyforge", PIN, label)
        return stub, tok

    def test_login_failure_redacts_pin(self):
        missing = Pkcs11Token("/no/such/libsofthsm2.so", "keyforge", PIN, "keyforge-kek")
        with self.assertRaises(KeyForgeError) as cm:
            missing._session()
        self.assertIn("not found", str(cm.exception))
        self.assertPinHidden(PIN, exc=cm.exception)

        stub, tok = self._token()
        stub.open_error = RuntimeError(f"C_Login failed {PIN}")
        err = io.StringIO()
        logs = self._capture_logs()
        with redirect_stderr(err):
            with self.assertRaises(KeyForgeError) as cm:
                tok._session()
        self.assertIn("PKCS#11 login failed", str(cm.exception))
        self.assertIn("RuntimeError:", str(cm.exception))
        self.assertIn("[redacted]", str(cm.exception))
        self.assertPinHidden(PIN, err.getvalue(), "\n".join(logs), repr(tok), exc=cm.exception)

        stub.open_error = None
        stub.accept_pin = PIN
        wrong = Pkcs11Token(__file__, "keyforge", WRONG_PIN, "keyforge-kek")
        err = io.StringIO()
        with mock.patch("sys.stdin.isatty", return_value=False), redirect_stderr(err):
            with self.assertRaises(KeyForgeError) as cm:
                wrong._session()
        self.assertEqual(str(cm.exception), "no terminal")
        self.assertPinHidden(WRONG_PIN, err.getvalue(), exc=cm.exception)
        self.assertPinHidden(PIN, err.getvalue(), exc=cm.exception)

    def test_wrap_and_unwrap_failures_hide_pin(self):
        stub, tok = self._token()
        stub.seed("keyforge-kek")
        stub.encrypt_error = RuntimeError(f"C_Encrypt {PIN}")
        dek = b"\x05" * 32
        err = io.StringIO()
        logs = self._capture_logs()
        with redirect_stderr(err):
            with self.assertRaises(KeyForgeError) as cm:
                tok.wrap("keyforge-kek", dek, b"aad")
        self.assertIn("PKCS#11 wrap failed", str(cm.exception))
        self.assertIn("[redacted]", str(cm.exception))
        self.assertPinHidden(PIN, err.getvalue(), "\n".join(logs), exc=cm.exception)

        stub.encrypt_error = None
        stub.decrypt_error = RuntimeError(f"C_Decrypt {PIN}")
        blob = b"\x01" * 12 + b"\x02" * 32
        with self.assertRaises(KeyForgeError) as cm:
            tok.unwrap("keyforge-kek", blob, b"aad")
        self.assertEqual(str(cm.exception), "PKCS#11 unwrap failed authentication")
        self.assertNotIn("[redacted]", str(cm.exception))
        self.assertNotIn("RuntimeError", str(cm.exception))
        self.assertPinHidden(PIN, exc=cm.exception)

        stub.decrypt_error = None
        stub.keys.append(_AesKey("keyforge-kek", stub))
        with self.assertRaises(KeyForgeError) as cm:
            tok.wrap("keyforge-kek", dek, b"aad")
        self.assertIn("more than one key", str(cm.exception))
        self.assertPinHidden(PIN, exc=cm.exception)

        with self.assertRaises(KeyForgeError) as cm:
            tok.wrap("other-label", dek, b"aad")
        self.assertIn("not the configured key", str(cm.exception))
        self.assertPinHidden(PIN, exc=cm.exception)

    def test_confirm_user_pin_paths_hide_pin(self):
        logs = self._capture_logs()
        err = io.StringIO()
        with redirect_stderr(err):
            with self.assertRaises(KeyForgeError) as cm:
                confirm_user_pin("/no/such/libsofthsm2.so", "keyforge", PIN)
        self.assertIn("not found", str(cm.exception))
        self.assertPinHidden(PIN, err.getvalue(), exc=cm.exception)

        import builtins
        real_import = builtins.__import__

        def block_pkcs11(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "pkcs11" or (isinstance(name, str) and name.startswith("pkcs11.")):
                raise ImportError("blocked for test")
            return real_import(name, globals, locals, fromlist, level)

        saved = _snapshot_pkcs11()
        builtins.__import__ = block_pkcs11
        try:
            with self.assertRaises(KeyForgeError) as cm:
                confirm_user_pin(__file__, "keyforge", PIN)
        finally:
            builtins.__import__ = real_import
            _restore_pkcs11(saved)
        self.assertIn("python-pkcs11", str(cm.exception))
        self.assertPinHidden(PIN, exc=cm.exception)

        stub = _Token()
        _install_pkcs11(self, stub)
        with redirect_stderr(err):
            confirm_user_pin(__file__, "keyforge", PIN)
        self.assertEqual(stub.pins, [PIN])
        self.assertEqual(stub.closed, 1)
        self.assertPinHidden(PIN, err.getvalue(), "\n".join(logs))

        stub.open_error = PinIncorrect(f"rejected {PIN}")
        with self.assertRaises(KeyForgeError) as cm:
            confirm_user_pin(__file__, "keyforge", PIN)
        self.assertEqual(str(cm.exception), "PIN is wrong. Ctrl-C to exit.")
        self.assertPinHidden(PIN, exc=cm.exception)

        stub.open_error = RuntimeError(f"slot down {PIN}")
        with self.assertRaises(KeyForgeError) as cm:
            confirm_user_pin(__file__, "keyforge", PIN)
        self.assertIn("PKCS#11 login failed", str(cm.exception))
        self.assertIn("[redacted]", str(cm.exception))
        self.assertPinHidden(PIN, "\n".join(logs), exc=cm.exception)

    def test_confirm_user_pin_close_failure_hides_pin(self):
        stub = _Token()
        _install_pkcs11(self, stub)
        # Unrelated close errors still propagate with their original text.
        stub.close_error = RuntimeError("token removed")
        with self.assertRaises(RuntimeError) as cm:
            confirm_user_pin(__file__, "keyforge", PIN)
        self.assertEqual(str(cm.exception), "token removed")
        self.assertEqual(stub.closed, 1)

        # Case variation, a repeated copy, and a PIN that sits inside "[redacted]".
        pin = "red"
        stub.closed = 0
        stub.close_error = RuntimeError(f"C_Close {pin.upper()} {pin}{pin}")
        logs = self._capture_logs()
        err = io.StringIO()
        with redirect_stderr(err):
            with self.assertRaises(KeyForgeError) as cm:
                confirm_user_pin(__file__, "keyforge", pin)
        self.assertIn("PKCS#11 session close failed", str(cm.exception))
        self.assertIn("RuntimeError:", str(cm.exception))
        self.assertNotIn("[redacted]", str(cm.exception).casefold())
        self.assertIsNone(cm.exception.__context__)
        self.assertSecretGone(pin, err.getvalue(), "\n".join(logs), exc=cm.exception)
        self.assertEqual(stub.closed, 1)

    def test_open_token_hides_non_mismatch_errors(self):
        from keyforge.kms import _open_token

        pin = "aaa"

        class Token:
            def open(self, rw, user_pin):
                raise RuntimeError(f"C_Login {user_pin.upper()} aaaa {user_pin}")

        logs = self._capture_logs()
        err = io.StringIO()
        with redirect_stderr(err):
            with self.assertRaises(RuntimeError) as cm:
                _open_token(Token(), pin)
        self.assertIsNone(cm.exception.__context__)
        self.assertNotIn("aaaa", str(cm.exception))
        self.assertSecretGone(pin, err.getvalue(), "\n".join(logs), exc=cm.exception)

        # _session re-raises KeyForgeError without _safe_exc, so _open_token
        # has to redact before that exception leaves.
        class KeyForgeToken:
            def open(self, rw, user_pin):
                raise KeyForgeError(f"slot {user_pin} RED {user_pin.upper()}")

        hostile = "red"
        with self.assertRaises(KeyForgeError) as cm:
            _open_token(KeyForgeToken(), hostile)
        self.assertNotIn("PKCS#11 login failed", str(cm.exception))
        self.assertIsNone(cm.exception.__context__)
        self.assertSecretGone(hostile, exc=cm.exception)
        self.assertNotIn("[redacted]", str(cm.exception).casefold())

        stub = _Token()
        _install_pkcs11(self, stub)
        stub.open_error = KeyForgeError(f"slot {hostile} RED")
        tok = Pkcs11Token(__file__, "keyforge", hostile, "keyforge-kek")
        with self.assertRaises(KeyForgeError) as cm:
            tok._session()
        self.assertIsNone(cm.exception.__cause__)
        self.assertSecretGone(hostile, exc=cm.exception)
        if cm.exception.__context__ is not None:
            self.assertSecretGone(hostile, exc=cm.exception.__context__)

    def _assert_raised_chain_is_clean(self, exc):
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        self.assertSecretGone(PIN, exc=exc)

    def test_cause_context_and_bytes_pins_are_not_reraised(self):
        from keyforge.kms import _mentions_pin, _open_token

        def with_cause(pin):
            err = _QuietError("token failure")
            err.__cause__ = RuntimeError(f"inner {pin}")
            return err

        def with_context(pin):
            err = _QuietError("token failure")
            err.__context__ = RuntimeError(f"inner {pin}")
            err.__suppress_context__ = False
            return err

        def with_bytes(pin):
            err = _QuietError("token failure")
            err.args = (f"inner {pin}".encode(),)
            return err

        def with_cycle(pin):
            err = _QuietError("token failure")
            inner = RuntimeError(f"inner {pin}")
            err.__cause__ = inner
            inner.__cause__ = err
            inner.__context__ = err
            return err

        # A cycle must terminate, and a clean chain must not count as a hit.
        self.assertTrue(_mentions_pin(with_cause(PIN), PIN))
        self.assertTrue(_mentions_pin(with_context(PIN), PIN))
        self.assertTrue(_mentions_pin(with_bytes(PIN), PIN))
        self.assertTrue(_mentions_pin(with_cycle(PIN), PIN))
        clean = RuntimeError("token removed")
        other = RuntimeError("offline")
        clean.__cause__ = other
        other.__context__ = clean
        self.assertFalse(_mentions_pin(clean, PIN))

        stub = _Token()
        _install_pkcs11(self, stub)
        for label, factory in (
            ("cause", with_cause),
            ("context", with_context),
            ("bytes", with_bytes),
            ("cycle", with_cycle),
        ):
            with self.subTest(path="open", leak=label):
                class Token:
                    def open(self, rw, user_pin, built=factory):
                        raise built(user_pin)

                with self.assertRaises(_QuietError) as cm:
                    _open_token(Token(), PIN)
                self.assertEqual(str(cm.exception), "token failure")
                self._assert_raised_chain_is_clean(cm.exception)

            with self.subTest(path="close", leak=label):
                stub.close_error = factory(PIN)
                with self.assertRaises(KeyForgeError) as cm:
                    confirm_user_pin(__file__, "keyforge", PIN)
                self.assertIn("PKCS#11 session close failed", str(cm.exception))
                self._assert_raised_chain_is_clean(cm.exception)

        # A chain that does not contain the PIN is still the original error.
        kept = RuntimeError("token removed")
        kept.__cause__ = RuntimeError("offline")

        class CleanToken:
            def open(self, rw, user_pin):
                raise kept

        with self.assertRaises(RuntimeError) as cm:
            _open_token(CleanToken(), PIN)
        self.assertIs(cm.exception, kept)
        self.assertEqual(str(cm.exception.__cause__), "offline")

        stub.close_error = kept
        with self.assertRaises(RuntimeError) as cm:
            confirm_user_pin(__file__, "keyforge", PIN)
        self.assertIs(cm.exception, kept)
        self.assertEqual(str(cm.exception.__cause__), "offline")

    def test_pkcs11_from_env_prompt_does_not_log_pin(self):
        os.environ["KEYFORGE_PKCS11_MODULE"] = __file__
        os.environ["KEYFORGE_PKCS11_TOKEN"] = "keyforge"
        os.environ["KEYFORGE_PKCS11_KEY_LABEL"] = "keyforge-kek"
        logs = self._capture_logs()
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(KeyForgeError) as cm:
                pkcs11_from_env()
        self.assertEqual(str(cm.exception), "no terminal")
        self.assertPinHidden(PIN, exc=cm.exception)

        answers = iter(["", PIN])
        err = io.StringIO()
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("getpass.getpass", side_effect=lambda _p: next(answers)), \
             redirect_stderr(err):
            prov = pkcs11_from_env()
        self.assertIn("input blank", err.getvalue())
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))
        self.assertEqual(kms.pkcs11._user_pin, PIN)
        self.assertEqual(prov.token._pin, PIN)
        self.assertPinHidden(PIN, err.getvalue(), "\n".join(logs), repr(prov), repr(prov.token))

    def test_status_hides_pin_on_failure_and_success(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "pkcs11"
        os.environ["KEYFORGE_PKCS11_MODULE"] = __file__
        os.environ["KEYFORGE_PKCS11_TOKEN"] = "keyforge"
        os.environ["KEYFORGE_PKCS11_KEY_LABEL"] = "keyforge-kek"
        os.environ["KEYFORGE_PKCS11_PIN"] = PIN
        stub = _Token()
        stub.open_error = RuntimeError(f"login {PIN}")
        _install_pkcs11(self, stub)
        err = io.StringIO()
        logs = self._capture_logs()
        with redirect_stderr(err):
            info = kms.status()
        text = "\n".join(kms.format_status(info))
        self.assertFalse(info["ready"])
        self.assertIn("[redacted]", info["error"])
        self.assertPinHidden(PIN, json.dumps(info), text, err.getvalue(), "\n".join(logs))

        stub.open_error = None
        stub.seed("keyforge-kek")
        with redirect_stderr(err):
            info = kms.status()
        text = "\n".join(kms.format_status(info))
        self.assertTrue(info["ready"])
        self.assertNotIn("error", info)
        self.assertPinHidden(PIN, json.dumps(info), text, err.getvalue(), "\n".join(logs))

    def test_mocked_pkcs11_round_trip_does_not_log_pin(self):
        stub, tok = self._token()
        prov = Pkcs11Kms(tok, "keyforge-kek")
        dek = bytes(range(32))
        aad = _dek_aad("key_mockround")
        err = io.StringIO()
        logs = self._capture_logs()
        with redirect_stderr(err):
            wrapped = prov.wrap(dek, aad)
            opened = prov.unwrap(wrapped, aad)
        self.assertEqual(opened, dek)
        self.assertEqual(wrapped["provider"], "pkcs11")
        self.assertEqual(stub.pins, [PIN, PIN])
        self.assertEqual(len(stub.generated), 1)
        generated = stub.generated[0]
        self.assertEqual(generated["size"], 256)
        self.assertEqual(generated["key_type"], "AES")
        self.assertTrue(generated["store"])
        self.assertEqual(generated["template"]["SENSITIVE"], True)
        self.assertEqual(generated["template"]["EXTRACTABLE"], False)
        self.assertEqual(generated["template"]["ENCRYPT"], True)
        self.assertEqual(generated["template"]["DECRYPT"], True)
        self.assertIn("generated a new AES-256 key", err.getvalue())
        self.assertPinHidden(
            PIN, err.getvalue(), "\n".join(logs), json.dumps(wrapped), repr(tok), repr(prov))

    def test_pkcs11_stub_restores_keytype_identity(self):
        try:
            import pkcs11  # noqa: F401  # raises ImportError so the test skips without python-pkcs11
            from pkcs11 import KeyType
        except ImportError:
            self.skipTest("python-pkcs11 is not installed")
        saved = _snapshot_pkcs11()
        try:
            import types
            sys.modules["pkcs11"] = types.ModuleType("pkcs11")
            sys.modules["pkcs11.mechanisms"] = types.ModuleType("pkcs11.mechanisms")
        finally:
            _restore_pkcs11(saved)
        import pkcs11._pkcs11 as ext
        from pkcs11 import KeyType as current
        self.assertIs(current, KeyType)
        self.assertIs(current, ext.KeyType)
        self.assertIsInstance(current.AES, ext.KeyType)

    def test_session_retries_on_a_tty_without_logging_pins(self):
        stub, _tok = self._token()
        stub.accept_pin = PIN
        wrong = Pkcs11Token(__file__, "keyforge", WRONG_PIN, "keyforge-kek")
        err = io.StringIO()
        logs = self._capture_logs()
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("getpass.getpass", return_value=PIN), \
             redirect_stderr(err):
            session = wrong._session()
        self.assertIsNotNone(session)
        self.assertEqual(stub.pins, [WRONG_PIN, PIN])
        self.assertIn("PIN is wrong", err.getvalue())
        joined = err.getvalue() + "\n" + "\n".join(logs)
        self.assertPinHidden(PIN, joined)
        self.assertPinHidden(WRONG_PIN, joined)


class PinCacheTests(_EnvCase):
    def _configure(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "pkcs11"
        os.environ["KEYFORGE_PKCS11_MODULE"] = __file__
        os.environ["KEYFORGE_PKCS11_TOKEN"] = "keyforge"
        os.environ["KEYFORGE_PKCS11_KEY_LABEL"] = "keyforge-kek"

    def _child_env_pin(self):
        script = (
            "import os\n"
            "value = os.environ.get('KEYFORGE_PKCS11_PIN')\n"
            "print('' if value is None else value)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, check=True,
        )
        self.assertNotIn(PIN, proc.stderr)
        return proc.stdout.strip()

    def test_memory_key_lives_on_the_local_module(self):
        from keyforge.kms import local as local_mod

        saved = local_mod._memory_key
        try:
            local_mod._memory_key = None
            prov = memory_provider()
            self.assertIs(prov._key, local_mod._memory_key)
            self.assertNotIn("_memory_key", kms.__dict__)
        finally:
            local_mod._memory_key = saved

    def test_prompt_never_sets_environ(self):
        os.environ["KEYFORGE_PKCS11_PIN"] = "env-pin"
        got = read_user_pin(lambda _prompt: PIN)
        self.assertEqual(got, PIN)
        self.assertEqual(kms.pkcs11._user_pin, PIN)
        self.assertEqual(os.environ.get("KEYFORGE_PKCS11_PIN"), "env-pin")
        self.assertNotIn(PIN, os.environ.values())

        os.environ.pop("KEYFORGE_PKCS11_PIN", None)
        read_user_pin(lambda _prompt: PIN)
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))
        self.assertEqual(kms.pkcs11._user_pin, PIN)

    def test_resolution_uses_argument_then_cache_then_env(self):
        self._configure()
        kms.pkcs11._user_pin = "cached-pin"
        os.environ["KEYFORGE_PKCS11_PIN"] = "env-pin"
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            explicit = pkcs11_from_env("explicit-pin")
        self.assertEqual(explicit.token._pin, "explicit-pin")
        self.assertEqual(kms.pkcs11._user_pin, "cached-pin")
        self.assertEqual(os.environ.get("KEYFORGE_PKCS11_PIN"), "env-pin")

        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            cached = pkcs11_from_env()
        self.assertEqual(cached.token._pin, "cached-pin")

        kms.pkcs11._user_pin = None
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            from_env = pkcs11_from_env()
        self.assertEqual(from_env.token._pin, "env-pin")
        self.assertIsNone(kms.pkcs11._user_pin)

    def test_status_prompts_only_once(self):
        self._configure()
        calls = []

        def fake(prompt):
            calls.append(prompt)
            return PIN

        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("getpass.getpass", side_effect=fake), \
             redirect_stderr(io.StringIO()):
            first = kms.status()
            pkcs11_from_env()
            second = kms.status()
        self.assertEqual(calls, ["KEYFORGE_PKCS11_PIN: "])
        self.assertTrue(first["pin_set"])
        self.assertTrue(second["pin_set"])
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))
        self.assertEqual(kms.pkcs11._user_pin, PIN)
        rendered = str(first) + str(second) + "\n".join(kms.format_status(first))
        self.assertNotIn(PIN, rendered)

        with mock.patch("sys.stdin.isatty", return_value=False), \
             mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            later = kms.status()
        self.assertTrue(later["pin_set"])
        self.assertNotEqual(kms.format_status(later), ["no terminal"])
        self.assertNotIn(PIN, str(later))

    def test_wrong_pin_retry_updates_cache_and_token_pin(self):
        stub = _Token()
        stub.accept_pin = PIN
        _install_pkcs11(self, stub)
        tok = Pkcs11Token(__file__, "keyforge", WRONG_PIN, "keyforge-kek")
        calls = []

        def fake(prompt):
            calls.append(prompt)
            return PIN

        err = io.StringIO()
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("getpass.getpass", side_effect=fake), \
             redirect_stderr(err):
            session = tok._session()
        self.assertIsNotNone(session)
        self.assertEqual(calls, ["KEYFORGE_PKCS11_PIN: "])
        self.assertEqual(tok._pin, PIN)
        self.assertEqual(kms.pkcs11._user_pin, PIN)
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))
        self.assertNotIn(PIN, err.getvalue())
        self.assertNotIn(WRONG_PIN, err.getvalue())

        calls.clear()
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("getpass.getpass", side_effect=fake), \
             redirect_stderr(io.StringIO()):
            again = tok._session()
        self.assertIsNotNone(again)
        self.assertEqual(calls, [])
        self.assertEqual(stub.pins, [WRONG_PIN, PIN, PIN])

        os.environ["KEYFORGE_PKCS11_PIN"] = WRONG_PIN
        self._configure()
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            prov = pkcs11_from_env()
        self.assertEqual(prov.token._pin, PIN)
        self.assertEqual(os.environ.get("KEYFORGE_PKCS11_PIN"), WRONG_PIN)
        self.assertNotIn(PIN, os.environ.values())

    def _rejecting_token(self):
        class Token:
            def open(self, rw, user_pin):
                raise PinIncorrect(user_pin)

        return Token()

    def test_wrong_pin_then_ctrl_c_does_not_keep_the_cache(self):
        from keyforge.kms import _open_token

        os.environ["KEYFORGE_PKCS11_PIN"] = PIN
        self._configure()
        answers = iter(["typed-wrong"])

        def read_secret(_prompt):
            try:
                return next(answers)
            except StopIteration:
                raise KeyboardInterrupt

        with mock.patch("sys.stdin.isatty", return_value=True), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                _open_token(self._rejecting_token(), WRONG_PIN, read_secret=read_secret)
        self.assertIsNone(kms.pkcs11._user_pin)
        self.assertEqual(os.environ.get("KEYFORGE_PKCS11_PIN"), PIN)

    def test_wrong_pin_without_a_tty_does_not_keep_the_cache(self):
        from keyforge.kms import _open_token

        os.environ["KEYFORGE_PKCS11_PIN"] = PIN
        read_user_pin(lambda _prompt: "typed-wrong")
        self.assertEqual(kms.pkcs11._user_pin, "typed-wrong")
        with mock.patch("sys.stdin.isatty", return_value=False), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyForgeError) as cm:
                _open_token(self._rejecting_token(), "typed-wrong", read_secret=lambda _p: "unused")
        self.assertEqual(str(cm.exception), "no terminal")
        self.assertIsNone(kms.pkcs11._user_pin)
        self.assertEqual(os.environ.get("KEYFORGE_PKCS11_PIN"), PIN)

    def test_aborted_wrong_pin_does_not_override_the_env_pin(self):
        from keyforge.kms import _open_token

        os.environ["KEYFORGE_PKCS11_PIN"] = PIN
        self._configure()
        read_user_pin(lambda _prompt: "typed-wrong")
        with mock.patch("sys.stdin.isatty", return_value=False), \
             redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyForgeError):
                _open_token(self._rejecting_token(), kms.pkcs11._user_pin, read_secret=lambda _p: "unused")
        with mock.patch("getpass.getpass", side_effect=AssertionError("prompted")):
            prov = pkcs11_from_env()
        self.assertEqual(prov.token._pin, PIN)
        self.assertIsNone(kms.pkcs11._user_pin)
        self.assertNotIn("typed-wrong", os.environ.values())

    def test_prompted_pin_does_not_reach_child_processes(self):
        os.environ["KEYFORGE_PKCS11_PIN"] = "env-pin"
        read_user_pin(lambda _prompt: PIN)
        self.assertEqual(self._child_env_pin(), "env-pin")

        os.environ.pop("KEYFORGE_PKCS11_PIN", None)
        read_user_pin(lambda _prompt: PIN)
        self.assertEqual(self._child_env_pin(), "")
        self.assertIsNone(os.environ.get("KEYFORGE_PKCS11_PIN"))


if __name__ == "__main__":
    unittest.main()
