"""PKCS#11 provider against SoftHSM when the module is installed, plus the documented env contract."""
import io, os, shutil, subprocess, tempfile, unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from keyforge import crypto, kms, service as svc
from keyforge.errors import KeyForgeError
from keyforge.kms import provider_for
from keyforge.store import Store

MODULE = "/usr/lib/softhsm/libsofthsm2.so"
TOKEN = "keyforge-test"
LABEL = "keyforge-kek"
PIN = "test-user-pin"
SO_PIN = "test-so-pin"


def _softhsm_ready():
    return os.path.exists(MODULE) and shutil.which("softhsm2-util")


@unittest.skipUnless(_softhsm_ready(), "SoftHSM is not installed")
class SoftHsmTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        tokendir = os.path.join(self.d.name, "tokens")
        os.makedirs(tokendir)
        conf = os.path.join(self.d.name, "softhsm2.conf")
        Path(conf).write_text(
            f"directories.tokendir = {tokendir}\nobjectstore.backend = file\nlog.level = ERROR\n"
        )
        kms._user_pin = None
        self._saved = {k: os.environ.get(k) for k in (
            "SOFTHSM2_CONF", "KEYFORGE_KMS_PROVIDER", "KEYFORGE_PKCS11_MODULE",
            "KEYFORGE_PKCS11_TOKEN", "KEYFORGE_PKCS11_PIN", "KEYFORGE_PKCS11_KEY_LABEL",
            "KEYFORGE_PKCS11_CREATE_KEY")}
        os.environ["SOFTHSM2_CONF"] = conf
        subprocess.run(
            ["softhsm2-util", "--init-token", "--free", "--label", TOKEN, "--pin", PIN, "--so-pin", SO_PIN],
            check=True, capture_output=True, text=True,
        )
        os.environ["KEYFORGE_KMS_PROVIDER"] = "pkcs11"
        os.environ["KEYFORGE_PKCS11_MODULE"] = MODULE
        os.environ["KEYFORGE_PKCS11_TOKEN"] = TOKEN
        os.environ["KEYFORGE_PKCS11_PIN"] = PIN
        os.environ["KEYFORGE_PKCS11_KEY_LABEL"] = LABEL
        os.environ["KEYFORGE_PKCS11_CREATE_KEY"] = "1"
        self.store = Store(os.path.join(self.d.name, "store.json"))

    def tearDown(self):
        kms._user_pin = None
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def test_token_wraps_and_fails_closed_on_tamper(self):
        k, secret = svc.create(self.store, name="n", owner="alice", scopes=["read:packets"])
        self.store.save()
        env = self.store.data["keys"][k.id]["secret_envelope"]
        self.assertEqual(env["wrapped_dek"]["provider"], "pkcs11")
        self.assertEqual(env["wrapped_dek"]["kid"], LABEL)
        raw = Path(self.store.path).read_text()
        self.assertNotIn(secret, raw)
        self.assertNotIn(PIN, raw)
        self.assertNotIn(secret[len(k.prefix):], raw)

        os.environ["KEYFORGE_PKCS11_CREATE_KEY"] = "0"
        self.assertEqual(svc.reveal(self.store, k.id), secret)

        ct = env["ct"]
        env["ct"] = ("0" if ct[0] != "0" else "1") + ct[1:]
        with self.assertRaises(KeyForgeError) as cm:
            svc.reveal(self.store, k.id)
        self.assertIn("authentication", str(cm.exception).lower())
        self.assertNotIn(secret, str(cm.exception))

        env["ct"] = ct
        blob = env["wrapped_dek"]["ct"]
        env["wrapped_dek"]["ct"] = ("0" if blob[0] != "0" else "1") + blob[1:]
        with self.assertRaises(KeyForgeError) as cm:
            crypto.open_secret(env, key_id=k.id, kms=provider_for(self.store))
        self.assertIn("authentication", str(cm.exception).lower())


class PinAttemptTests(unittest.TestCase):
    def setUp(self):
        kms._user_pin = None

    def tearDown(self):
        kms._user_pin = None

    def test_wrong_pin_retries_until_correct(self):
        from keyforge.kms import _open_token
        pins = iter(["second"])

        class Token:
            def open(self, rw, user_pin):
                if user_pin != "second":
                    raise type("PinIncorrect", (Exception,), {})("wrong")
                return "session"

        err = io.StringIO()
        with mock.patch("sys.stdin.isatty", return_value=True), redirect_stderr(err):
            opened = _open_token(Token(), "first", read_secret=lambda _p: next(pins))
        self.assertEqual(opened, "session")
        self.assertIn("PIN is wrong. Ctrl-C to exit.", err.getvalue())
        self.assertNotIn("3 attempts", err.getvalue())

    def test_noninteractive_wrong_pin_fails_once(self):
        from keyforge.kms import _open_token

        class Token:
            def open(self, rw, user_pin):
                raise type("PinIncorrect", (Exception,), {})("wrong")

        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(KeyForgeError) as cm:
                _open_token(Token(), "first", read_secret=lambda _p: "unused")
        self.assertIn("no terminal", str(cm.exception))


class NewAesKeyNoticeTests(unittest.TestCase):
    def test_warns_that_a_new_key_cannot_read_old_secrets(self):
        from keyforge.kms import _new_aes_key_notice
        text = _new_aes_key_notice("keyforge-kek")
        self.assertIn("generated a new AES-256 key labeled 'keyforge-kek'", text)
        self.assertIn("cannot read secrets wrapped by an older key", text)
        self.assertIn("The label is only a name", text)


class Pkcs11ConfigTests(unittest.TestCase):
    def setUp(self):
        kms._user_pin = None

    def tearDown(self):
        kms._user_pin = None

    def test_missing_env_is_explicit(self):
        saved = os.environ.get("KEYFORGE_KMS_PROVIDER")
        os.environ["KEYFORGE_KMS_PROVIDER"] = "pkcs11"
        for name in ("KEYFORGE_PKCS11_MODULE", "KEYFORGE_PKCS11_TOKEN",
                     "KEYFORGE_PKCS11_PIN", "KEYFORGE_PKCS11_KEY_LABEL"):
            os.environ.pop(name, None)
        try:
            with self.assertRaises(KeyForgeError) as cm:
                provider_for(None)
            self.assertIn("KEYFORGE_PKCS11_MODULE", str(cm.exception))
        finally:
            if saved is None:
                os.environ.pop("KEYFORGE_KMS_PROVIDER", None)
            else:
                os.environ["KEYFORGE_KMS_PROVIDER"] = saved

    def test_missing_module_file_explains_softhsm_install(self):
        from keyforge.kms import Pkcs11Token
        tok = Pkcs11Token("/nonexistent/libsofthsm2.so", "t", "pin", "k")
        with self.assertRaises(KeyForgeError) as cm:
            tok._session()
        msg = str(cm.exception)
        self.assertIn("not found", msg)
        self.assertIn("apt install softhsm2", msg)
        self.assertIn("SOFTHSM2_CONF", msg)

    def test_missing_python_binding_explains_pip_package(self):
        import builtins
        from keyforge.kms import Pkcs11Token
        real_import = builtins.__import__

        def block_pkcs11(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "pkcs11" or (isinstance(name, str) and name.startswith("pkcs11.")):
                raise ImportError("blocked for test")
            return real_import(name, globals, locals, fromlist, level)

        # Use a path that exists so the failure is the binding, not the .so.
        tok = Pkcs11Token(__file__, "t", "pin", "k")
        builtins.__import__ = block_pkcs11
        try:
            with self.assertRaises(KeyForgeError) as cm:
                tok._session()
        finally:
            builtins.__import__ = real_import
        msg = str(cm.exception)
        self.assertIn("pip install python-pkcs11", msg)
        self.assertIn("not the unrelated", msg)
        self.assertNotIn("not found", msg)


if __name__ == "__main__":
    unittest.main()
