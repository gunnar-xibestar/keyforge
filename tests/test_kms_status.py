"""``keyforge kms status`` reports the configured provider without using Auth0."""
import io, os, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from keyforge import cli
from keyforge import kms


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class KmsStatusTests(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in (
            "KEYFORGE_KMS_PROVIDER", "KEYFORGE_KMS_KEY_FILE", "KEYFORGE_STORE",
            "KEYFORGE_PKCS11_MODULE", "KEYFORGE_PKCS11_TOKEN", "KEYFORGE_PKCS11_PIN",
            "KEYFORGE_PKCS11_KEY_LABEL", "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE",
        )}
        for k in self._saved:
            os.environ.pop(k, None)
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def test_default_local_status(self):
        store = os.path.join(self.d.name, "store.json")
        os.environ["KEYFORGE_STORE"] = store
        rc, out, err = _run("kms", "status")
        self.assertEqual(rc, 0, err)
        self.assertIn("result: success", out)
        self.assertIn("provider: local", out)
        self.assertIn("ready: True", out)
        self.assertIn("kms-master.key", out)
        self.assertIn("same_directory_as_store: True", out)
        self.assertIn("software KEK", out)
        self.assertIn("auth login does not use the KMS", out)

    def test_pkcs11_reports_missing_without_export_confusion(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "pkcs11"
        info = kms.status()
        self.assertEqual(info["provider"], "pkcs11")
        self.assertFalse(info["ready"])
        self.assertTrue(info.get("missing"))
        rc, out, err = _run("--json", "kms", "status")
        self.assertEqual(rc, 0, err)
        self.assertIn('"provider": "pkcs11"', out)
        self.assertIn("KEYFORGE_PKCS11_MODULE", out)

    def test_memory_ready(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "memory"
        rc, out, err = _run("kms", "status")
        self.assertEqual(rc, 0, err)
        self.assertIn("result: success", out)
        self.assertIn("provider: memory", out)
        self.assertIn("ready: True", out)


if __name__ == "__main__":
    unittest.main()
