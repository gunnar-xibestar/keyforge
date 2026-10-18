"""Boot prompt: KMS choice, Auth0 warning, then username and password."""
import io, os, stat, tempfile, unittest
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout

from keyforge import auth, cli
from keyforge import setup as setup_mod
from keyforge.auth import Principal


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.env_file = os.path.join(self.d.name, "keyforge.env")
        self._saved = {k: os.environ.get(k) for k in (
            "KEYFORGE_ENV_FILE", "KEYFORGE_KMS_PROVIDER", "KEYFORGE_KMS_KEY_FILE",
            "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE", "AUTH0_REALM",
            "KEYFORGE_PKCS11_MODULE", "KEYFORGE_PKCS11_TOKEN", "KEYFORGE_PKCS11_PIN",
            "KEYFORGE_PKCS11_KEY_LABEL", "KEYFORGE_PKCS11_CREATE_KEY", "SOFTHSM2_CONF",
        )}
        os.environ["KEYFORGE_ENV_FILE"] = self.env_file
        for key in self._saved:
            if key != "KEYFORGE_ENV_FILE":
                os.environ.pop(key, None)
        self.lines = []
        self.seen = []

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def _echo(self, line):
        self.lines.append(line)

    def test_skip_auth0_warns_and_saves_provider(self):
        answers = iter(["local", "", "n"])

        def read_line(prompt):
            self.seen.append(prompt)
            return next(answers)

        result = setup_mod.run(read_line=read_line, read_secret=lambda _p: "", echo=self._echo)
        self.assertEqual(result["kms_provider"], "local")
        self.assertFalse(result["auth"]["enabled"])
        self.assertEqual(self.lines[:3], ["'", "'", "'"])
        self.assertEqual(self.lines[-5:], ["'", "'", "'", "'", "'"])
        text = "\n".join(self.lines)
        self.assertIn("|_|\\_\\___|\\__, |_|", text)
        self.assertIn("software KEK", text)
        local = text.index("  local\n")
        pkcs = text.index("  pkcs11\n")
        self.assertIn("\n\n  pkcs11\n", text[local:pkcs + 12])
        self.assertIn("necessary for the demo", text)
        self.assertLess(text.index("kms status"), text.index("necessary for the demo"))
        self.assertIn("provider: local", text)
        self.assertIn("ready: True", text)
        self.assertIn("trusts the OS user", text)
        self.assertNotIn("auth status", text)
        self.assertIn("dpkg -L softhsm2", text)
        self.assertNotIn("Settings → Domain", text)
        body = Path(self.env_file).read_text()
        self.assertIn("KEYFORGE_KMS_PROVIDER=local", body)
        self.assertNotIn("AUTH0_DOMAIN", body)
        self.assertNotIn("password=", body.lower())
        self.assertEqual(stat.S_IMODE(os.stat(self.env_file).st_mode), 0o600)
        self.assertEqual(os.environ["KEYFORGE_KMS_PROVIDER"], "local")

    def test_saved_auth0_skips_the_setup_question(self):
        os.environ["AUTH0_DOMAIN"] = "tenant.example.test"
        os.environ["AUTH0_CLIENT_ID"] = "client-id"
        os.environ["AUTH0_AUDIENCE"] = "https://keyforge.local/api"
        answers = iter(["local", "", "ada@example.test"])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        def login(username, password):
            self.assertEqual(username, "ada@example.test")
            self.assertEqual(password, "user-secret")
            return Principal(sub="auth0|ada", scopes=frozenset({"keys:read"}), exp=1)

        result = setup_mod.run(
            read_line=read_line, read_secret=lambda _p: "user-secret", echo=self._echo, login=login)
        self.assertNotIn("Set up Auth0 now? [Y/n] ", prompts)
        text = "\n".join(self.lines)
        self.assertIn("Auth0 is already configured", text)
        self.assertIn("AUTH0_DOMAIN: tenant.example.test", text)
        self.assertIn("logged in as auth0|ada", text)
        body = Path(self.env_file).read_text()
        self.assertIn("AUTH0_CLIENT_ID=client-id", body)
        self.assertEqual(result["sub"], "auth0|ada")

    def test_auth0_asks_username_then_password_and_prints_status(self):
        answers = iter([
            "pkcs11",
            "",
            "/tmp/no-such-libsofthsm2.so",
            "keyforge",
            "keyforge-kek",
            "",
            "y",
            "tenant.example.test",
            "client-id",
            "https://keyforge.local/api",
            "ada@example.test",
        ])
        secrets = iter(["pin-secret", "user-secret"])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        def read_secret(prompt):
            prompts.append(prompt)
            return next(secrets)

        def login(username, password):
            self.assertEqual(username, "ada@example.test")
            self.assertEqual(password, "user-secret")
            self.assertEqual(os.environ["AUTH0_DOMAIN"], "tenant.example.test")
            self.assertEqual(os.environ["KEYFORGE_PKCS11_PIN"], "pin-secret")
            return Principal(sub="auth0|ada", scopes=frozenset({"keys:read"}), exp=1)

        real_status = auth.status

        def status():
            return {"enabled": True, "logged_in": True, "sub": "auth0|ada",
                    "scopes": ["keys:read"], "expires_at": 1, "missing_scopes": ["keys:write"]}

        auth.status = status
        try:
            result = setup_mod.run(read_line=read_line, read_secret=read_secret, echo=self._echo, login=login)
        finally:
            auth.status = real_status
        secret_prompts = [p for p in prompts if "PIN" in p or p.startswith("password")]
        self.assertEqual(secret_prompts, ["KEYFORGE_PKCS11_PIN: ", "password: "])
        user_at = prompts.index("username: ")
        self.assertLess(user_at, prompts.index("password: "))
        text = "\n".join(self.lines)
        self.assertIn("logged in as auth0|ada", text)
        self.assertNotIn("auth status", text)
        self.assertNotIn("scopes:", text)
        self.assertIn("softhsm2-util --init-token", text)
        self.assertNotIn("Reuse the oldest token?", text)
        self.assertNotIn("another terminal", text)
        self.assertLess(prompts.index("Press Enter when the new token exists: "), prompts.index("KEYFORGE_PKCS11_MODULE [/usr/lib/softhsm/libsofthsm2.so]: "))
        self.assertIn("No existing token labeled 'keyforge'", text)
        self.assertIn("That check ran and no token labeled keyforge came up", text)
        self.assertIn("/usr/lib/x86_64-linux-gnu/softhsm/", text)
        self.assertIn("Create a new token:", text)
        self.assertLess(text.index("kms status"), text.index("Auth0 dashboard"))
        self.assertIn("provider: pkcs11", text)
        self.assertIn("Applications → APIs", text)
        body = Path(self.env_file).read_text()
        self.assertIn("KEYFORGE_KMS_PROVIDER=pkcs11", body)
        self.assertIn("AUTH0_AUDIENCE=https://keyforge.local/api", body)
        self.assertIn("pin-secret", body)
        self.assertNotIn("user-secret", body)
        self.assertEqual(result["sub"], "auth0|ada")

    def test_reuse_keeps_oldest_token_and_skips_create_wait(self):
        root = Path(self.d.name) / "tokens"
        root.mkdir()
        conf = Path(self.d.name) / "softhsm2.conf"
        conf.write_text(f"directories.tokendir = {root}\n")
        os.environ["SOFTHSM2_CONF"] = str(conf)

        def write(name, mtime_ns):
            path = root / name
            path.mkdir()
            obj = path / "token.object"
            padded = b"keyforge" + b" " * (32 - len(b"keyforge"))
            obj.write_bytes((32).to_bytes(8, "big") + padded)
            os.utime(obj, ns=(mtime_ns, mtime_ns))
            return path

        oldest = write("old", 1_000)
        newer = write("new", 2_000)
        answers = iter([
            "pkcs11",
            "",
            "/tmp/no-such-libsofthsm2.so",
            "keyforge",
            "keyforge-kek",
            "",
            "n",
        ])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        setup_mod.run(read_line=read_line, read_secret=lambda _p: "pin-secret", echo=self._echo)
        self.assertIn("Reuse the oldest token? [Y/n] ", prompts)
        self.assertNotIn("Press Enter when the new token exists: ", prompts)
        self.assertTrue(oldest.is_dir())
        self.assertFalse(newer.exists())
        text = "\n".join(self.lines)
        self.assertIn("Create a new token:", text)
        self.assertIn("removed 1 newer token", text)

    def test_blank_pin_prints_softhsm_setup(self):
        from keyforge.errors import KeyForgeError
        answers = iter(["pkcs11", "", "/tmp/no-such-libsofthsm2.so", "keyforge"])

        def read_line(prompt):
            return next(answers)

        with self.assertRaises(KeyForgeError) as cm:
            setup_mod.run(read_line=read_line, read_secret=lambda _p: "", echo=self._echo)
        self.assertIn("--init-token --pin", str(cm.exception))
        self.assertIn("not the SO PIN", str(cm.exception))
        self.assertGreaterEqual("\n".join(self.lines).count("SoftHSM setup:"), 2)

    def test_bare_keyforge_needs_a_command(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            cli.main([])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_refuses_noninteractive_setup(self):
        rc, out, err = _run("setup")
        self.assertEqual(rc, 6)
        self.assertIn("non-interactive", err)

    def test_env_file_loads_when_unset(self):
        os.environ.pop("KEYFORGE_KMS_PROVIDER", None)
        Path(self.env_file).write_text("export KEYFORGE_KMS_PROVIDER='local'\n")
        setup_mod.load_env_file()
        self.assertEqual(os.environ["KEYFORGE_KMS_PROVIDER"], "local")
        os.environ["KEYFORGE_KMS_PROVIDER"] = "memory"
        setup_mod.load_env_file()
        self.assertEqual(os.environ["KEYFORGE_KMS_PROVIDER"], "local")


if __name__ == "__main__":
    unittest.main()
