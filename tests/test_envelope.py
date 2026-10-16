"""Envelope encryption at rest: plaintext never hits the store, reveal round-trips, tamper fails closed."""
import io, json, os, stat, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from keyforge import cli, crypto, service as svc
from keyforge.errors import KeyForgeError, ValidationError
from keyforge.kms import FakePkcs11Token, LocalKms, Pkcs11Kms, provider_for
from keyforge.store import Store

os.environ.setdefault("KEYFORGE_PBKDF2_ITERS", "1000")


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.d.name, "s.json")
        self.st = Store(self.path)

    def tearDown(self):
        self.d.cleanup()

    def test_create_stores_envelope_not_plaintext(self):
        k, secret = svc.create(self.st, name="n", owner="alice", env="live", scopes=["read:packets"])
        self.st.save()
        raw = Path(self.path).read_text()
        self.assertNotIn(secret, raw)
        self.assertNotIn(secret[len(k.prefix):], raw)
        env = self.st.data["keys"][k.id]["secret_envelope"]
        self.assertEqual(env["alg"], "AES-256-GCM")
        self.assertEqual(env["wrapped_dek"]["provider"], "local")
        self.assertNotIn("hash", k.public())
        self.assertNotIn("secret_envelope", k.public())
        self.assertNotIn("secret", k.public())
        key_file = os.path.join(self.d.name, "kms-master.key")
        self.assertEqual(stat.S_IMODE(os.stat(key_file).st_mode), 0o600)

    def test_reveal_round_trip_and_verify_without_kms(self):
        k, secret = svc.create(self.st, name="n", owner="alice")
        self.st.save()
        self.assertEqual(svc.reveal(self.st, k.id), secret)
        os.remove(os.path.join(self.d.name, "kms-master.key"))
        self.assertEqual(svc.verify(self.st, secret).id, k.id)
        with self.assertRaises(KeyForgeError):
            svc.reveal(self.st, k.id)

    def test_tamper_fails_closed(self):
        k, secret = svc.create(self.st, name="n", owner="alice")
        self.st.save()
        rec = self.st.data["keys"][k.id]
        ct = rec["secret_envelope"]["ct"]
        flipped = ("0" if ct[0] != "0" else "1") + ct[1:]
        rec["secret_envelope"]["ct"] = flipped
        with self.assertRaises(KeyForgeError) as cm:
            svc.reveal(self.st, k.id)
        self.assertIn("authentication", str(cm.exception).lower())
        self.assertNotIn(secret, str(cm.exception))
        rec["secret_envelope"]["ct"] = ct
        wrapped = rec["secret_envelope"]["wrapped_dek"]["ct"]
        rec["secret_envelope"]["wrapped_dek"]["ct"] = ("0" if wrapped[0] != "0" else "1") + wrapped[1:]
        with self.assertRaises(KeyForgeError):
            svc.reveal(self.st, k.id)

    def test_ciphertext_cannot_move_between_keys(self):
        a, sa = svc.create(self.st, name="a", owner="alice")
        b, sb = svc.create(self.st, name="b", owner="alice")
        self.st.data["keys"][b.id]["secret_envelope"] = json.loads(
            json.dumps(self.st.data["keys"][a.id]["secret_envelope"]))
        with self.assertRaises(KeyForgeError):
            svc.reveal(self.st, b.id)
        self.assertEqual(svc.reveal(self.st, a.id), sa)
        self.assertNotEqual(sa, sb)

    def test_legacy_hash_only_and_revoked(self):
        k, secret = svc.create(self.st, name="n", owner="alice")
        self.st.data["keys"][k.id].pop("secret_envelope")
        self.st.save()
        with self.assertRaises(KeyForgeError) as cm:
            svc.reveal(self.st, k.id)
        self.assertIn("legacy", str(cm.exception))
        self.assertEqual(svc.verify(self.st, secret).id, k.id)
        k2, secret2 = svc.create(self.st, name="n2", owner="alice")
        self.st.save()
        svc.set_status(self.st, k2.id, "revoked", reason="leak")
        with self.assertRaises(KeyForgeError):
            svc.reveal(self.st, k2.id)

    def test_rotate_envelopes_the_new_secret(self):
        k, old = svc.create(self.st, name="n", owner="alice")
        self.st.save()
        _, new, full, _ = svc.rotate(self.st, k.id, grace_period="1h")
        self.st.save()
        self.assertEqual(svc.reveal(self.st, k.id), old)
        self.assertEqual(svc.reveal(self.st, new.id), full)
        raw = Path(self.path).read_text()
        self.assertNotIn(old, raw)
        self.assertNotIn(full, raw)

    def test_import_rejects_bad_envelope_and_round_trips(self):
        k, secret = svc.create(self.st, name="n", owner="alice", scopes=["read:packets"])
        self.st.save()
        data = svc.export(self.st)
        data["keys"][0]["secret_envelope"]["ct"] = "zz"
        dst = Store(os.path.join(self.d.name, "dst.json"))
        with self.assertRaises(ValidationError):
            svc.import_(dst, data)
        self.assertEqual(dst.data["keys"], {})
        # same master key so reveal works after import into another file
        os.environ["KEYFORGE_KMS_KEY_FILE"] = os.path.join(self.d.name, "kms-master.key")
        try:
            fresh = svc.export(self.st)
            dst2 = Store(os.path.join(self.d.name, "dst2.json"))
            svc.import_(dst2, fresh)
            dst2.save()
            self.assertEqual(svc.reveal(dst2, k.id), secret)
            self.assertNotIn(secret, Path(dst2.path).read_text())
        finally:
            os.environ.pop("KEYFORGE_KMS_KEY_FILE", None)

    def test_audit_reveal_omits_secret(self):
        k, secret = svc.create(self.st, name="n", owner="alice")
        svc.reveal(self.st, k.id)
        self.st.save()
        ev = [e for e in self.st.audit_log if e["action"] == "reveal"]
        self.assertEqual(len(ev), 1)
        blob = json.dumps(ev)
        self.assertNotIn(secret, blob)
        self.assertNotIn(secret, Path(self.path).read_text())

    def test_cli_reveal(self):
        prior = os.environ.get("KEYFORGE_STORE")
        os.environ["KEYFORGE_STORE"] = self.path
        self.addCleanup(lambda: os.environ.__setitem__("KEYFORGE_STORE", prior) if prior is not None
                        else os.environ.pop("KEYFORGE_STORE", None))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(["--json", "create", "--name", "n", "--owner", "alice"])
        self.assertEqual(rc, 0, err.getvalue())
        created = json.loads(out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            rc = cli.main(["--json", "reveal", created["key"]["id"]])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["secret"], created["secret"])
        self.assertNotIn(created["secret"], Path(self.path).read_text())
        shown = io.StringIO()
        with redirect_stdout(shown), redirect_stderr(io.StringIO()):
            cli.main(["--json", "show", created["key"]["id"]])
        self.assertNotIn("secret_envelope", json.loads(shown.getvalue()))

    def test_loose_key_file_and_symlink_refused(self):
        path = os.path.join(self.d.name, "loose.key")
        with open(path, "wb") as f:
            f.write(b"\x01" * 32)
        os.chmod(path, 0o644)
        os.environ["KEYFORGE_KMS_KEY_FILE"] = path
        try:
            with self.assertRaises(KeyForgeError):
                svc.create(self.st, name="n", owner="alice")
            link = os.path.join(self.d.name, "link.key")
            os.symlink(path, link)
            os.environ["KEYFORGE_KMS_KEY_FILE"] = link
            with self.assertRaises(KeyForgeError):
                svc.create(self.st, name="n", owner="alice")
        finally:
            os.environ.pop("KEYFORGE_KMS_KEY_FILE", None)

    def test_fake_pkcs11_wrap_unwrap_and_tamper(self):
        token = FakePkcs11Token(os.urandom(32))
        prov = Pkcs11Kms(token, "keyforge-kek")
        env = crypto.seal_secret("kf_test_supersecretvalue00000000", key_id="key_abc123abc123", kms=prov)
        self.assertEqual(token.wraps, 1)
        self.assertNotIn("kf_test_supersecretvalue00000000", json.dumps(env))
        opened = crypto.open_secret(env, key_id="key_abc123abc123", kms=prov)
        self.assertEqual(opened, "kf_test_supersecretvalue00000000")
        self.assertEqual(token.unwraps, 1)
        blob = bytes.fromhex(env["wrapped_dek"]["ct"])
        blob = bytes([blob[0] ^ 0x01]) + blob[1:]
        env["wrapped_dek"]["ct"] = blob.hex()
        with self.assertRaises(KeyForgeError):
            crypto.open_secret(env, key_id="key_abc123abc123", kms=prov)

    def test_memory_provider_round_trip(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "memory"
        os.environ["KEYFORGE_KMS_MEMORY_KEY"] = "11" * 32
        try:
            k, secret = svc.create(self.st, name="n", owner="alice")
            self.st.save()
            self.assertEqual(self.st.data["keys"][k.id]["secret_envelope"]["wrapped_dek"]["provider"], "memory")
            self.assertFalse(os.path.exists(os.path.join(self.d.name, "kms-master.key")))
            self.assertEqual(svc.reveal(self.st, k.id), secret)
            other = LocalKms(b"\x22" * 32, provider="memory")
            with self.assertRaises(KeyForgeError):
                crypto.open_secret(k.secret_envelope, key_id=k.id, kms=other)
        finally:
            os.environ.pop("KEYFORGE_KMS_PROVIDER", None)
            os.environ.pop("KEYFORGE_KMS_MEMORY_KEY", None)

    def test_provider_for_unknown(self):
        os.environ["KEYFORGE_KMS_PROVIDER"] = "aws"
        try:
            with self.assertRaises(KeyForgeError):
                provider_for(self.st)
        finally:
            os.environ.pop("KEYFORGE_KMS_PROVIDER", None)


if __name__ == "__main__":
    unittest.main()
