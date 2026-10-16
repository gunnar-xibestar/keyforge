"""PKCS#11 provider against SoftHSM when the module is installed, plus the documented env contract."""
import os, shutil, subprocess, tempfile, unittest
from pathlib import Path

from keyforge import crypto, service as svc
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


class Pkcs11ConfigTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
