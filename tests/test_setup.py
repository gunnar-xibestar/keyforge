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
            "KEYFORGE_STORE", "KEYFORGE_AUDIT_HMAC_KEY_FILE",
        )}
        os.environ["KEYFORGE_ENV_FILE"] = self.env_file
        for key in self._saved:
            if key != "KEYFORGE_ENV_FILE":
                os.environ.pop(key, None)
        os.environ["KEYFORGE_STORE"] = os.path.join(self.d.name, "store.json")
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
        self.assertGreater(text.index("\nkms\n"), text.index("necessary for the demo"))
        self.assertIn("provider: local", text)
        self.assertIn("ready: True", text)
        self.assertIn("trusts the OS user", text)
        self.assertNotIn("auth status", text)
        self.assertNotIn("dpkg -L softhsm2", text)
        self.assertIn("result: success", text)
        self.assertIn("cryptography is installed", text)
        self.assertNotIn("Settings → Domain", text)
        body = Path(self.env_file).read_text()
        self.assertIn("KEYFORGE_KMS_PROVIDER=local", body)
        self.assertIn("audit chain OK:", text)
        self.assertIn("MAC verified", text)
        self.assertIn("audit HMAC key created:", text)
        self.assertIn("HMAC: on and verified for new events", text)
        self.assertIn("Audit chain", text)
        self.assertIn("-----------", text)
        self.assertIn("warning: a new HMAC key was created because none was found at that path.", text)
        self.assertIn("Later setups reuse this file when it still exists", text)
        self.assertIn("Keep this file. The next setup reuses it instead of creating another.", text)
        self.assertIn("If this secret is deleted later, audit --verify fails until it is restored", text)
        self.assertIn("KEYFORGE_AUDIT_HMAC_KEY_FILE=", body)
        self.assertTrue(os.path.isfile(os.path.join(self.d.name, "audit-hmac.key")))
        self.assertNotIn("AUTH0_DOMAIN", body)
        self.assertNotIn("password=", body.lower())
        self.assertEqual(stat.S_IMODE(os.stat(self.env_file).st_mode), 0o600)
        self.assertEqual(os.environ["KEYFORGE_KMS_PROVIDER"], "local")

    def test_setup_reports_hmac_on_when_chain_and_secret_match(self):
        answers = iter(["local", "", "n"])

        def read_line(prompt):
            return next(answers)

        setup_mod.run(read_line=read_line, read_secret=lambda _p: "", echo=self._echo)
        self.lines.clear()
        answers = iter(["local", "", "n"])
        setup_mod.run(read_line=read_line, read_secret=lambda _p: "", echo=self._echo)
        text = "\n".join(self.lines)
        self.assertIn("Audit chain", text)
        self.assertIn("audit HMAC key found:", text)
        self.assertIn("Reusing the existing secret.", text)
        self.assertIn("HMAC: on, verified, working", text)
        self.assertIn("audit --verify will check both the hash chain and the HMAC tags.", text)
        self.assertIn("  secret:", text)
        self.assertIn("  chain:", text)
        self.assertNotIn("warning: a new HMAC key was created", text)
        self.assertNotIn("audit HMAC key created:", text)
        self.assertNotIn("warning: HMAC is not verifying", text)
        body = Path(self.env_file).read_text()
        self.assertIn("KEYFORGE_AUDIT_HMAC_KEY_FILE=", body)

    def test_setup_warns_when_hmac_secret_is_unusable(self):
        bad = os.path.join(self.d.name, "missing-hmac.key")
        os.environ["KEYFORGE_AUDIT_HMAC_KEY_FILE"] = bad
        Path(bad).write_bytes(b"short")
        os.chmod(bad, 0o600)
        answers = iter(["local", "", "n"])

        def read_line(prompt):
            return next(answers)

        setup_mod.run(read_line=read_line, read_secret=lambda _p: "", echo=self._echo)
        text = "\n".join(self.lines)
        self.assertIn("audit HMAC key is unusable:", text)
        self.assertIn("warning: HMAC is not verifying the audit chain.", text)
        self.assertIn("If the audit chain already has MACs, audit --verify fails until KEYFORGE_AUDIT_HMAC_KEY_FILE points at the matching secret.", text)
        self.assertIn("If the chain never had MACs, verify stays unkeyed until a secret is enabled.", text)

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
            "keyforge-kek",
            "y",
            "tenant.example.test",
            "client-id",
            "https://keyforge.local/api",
            "ada@example.test",
        ])
        secrets = iter(["pin-secret", "so-pin", "user-secret"])
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
        real_init = setup_mod.init_token
        real_confirm = setup_mod.confirm_user_pin
        setup_mod.init_token = lambda *a, **k: "/tmp/softhsm2.conf"
        setup_mod.confirm_user_pin = lambda *a, **k: None
        try:
            result = setup_mod.run(read_line=read_line, read_secret=read_secret, echo=self._echo, login=login)
        finally:
            auth.status = real_status
            setup_mod.init_token = real_init
            setup_mod.confirm_user_pin = real_confirm
        secret_prompts = [p for p in prompts if "PIN" in p or p.startswith("password")]
        self.assertEqual(secret_prompts, ["KEYFORGE_PKCS11_PIN: ", "KEYFORGE_PKCS11_SO_PIN: ", "password: "])
        user_at = prompts.index("username: ")
        self.assertLess(user_at, prompts.index("password: "))
        text = "\n".join(self.lines)
        self.assertIn("logged in as auth0|ada", text)
        self.assertIn("scopes: keys:read", text)
        self.assertIn("missing_scopes: keys:verify keys:write reveal:secret", text)
        self.assertIn("expires_at: 1", text)
        self.assertNotIn("auth status", text)
        self.assertNotIn("softhsm2-util --init-token", text)
        self.assertNotIn("Reuse the oldest token?", text)
        self.assertNotIn("another terminal", text)
        self.assertNotIn("Press Enter when the new token exists: ", prompts)
        self.assertNotIn("KEYFORGE_PKCS11_MODULE [/usr/lib/softhsm/libsofthsm2.so]: ", prompts)
        self.assertIn("No existing token labeled 'keyforge'", text)
        self.assertIn("Module: KEYFORGE_PKCS11_MODULE", text)
        self.assertIn("dpkg -L softhsm2", text)
        self.assertNotIn("Create a new token:", text)
        self.assertNotIn("SoftHSM setup:", text)
        self.assertIn("SOFTHSM2_CONF:", text)
        self.assertLess(text.index("\nkms\n"), text.index("Auth0 dashboard"))
        self.assertGreater(text.index("\nauth0\n"), text.index("Auth0 dashboard"))
        self.assertLess(text.index("\nauth0\n"), text.index("logged in as"))
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
            "2",
            "keyforge-kek",
            "n",
        ])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        real_confirm = setup_mod.confirm_user_pin
        setup_mod.confirm_user_pin = lambda *a, **k: None
        try:
            setup_mod.run(read_line=read_line, read_secret=lambda _p: "pin-secret", echo=self._echo)
        finally:
            setup_mod.confirm_user_pin = real_confirm
        self.assertIn("Select a number to delete, c to create, or Enter to reuse main: ", prompts)
        self.assertNotIn("Press Enter when the new token exists: ", prompts)
        self.assertTrue(oldest.is_dir())
        self.assertFalse(newer.exists())
        text = "\n".join(self.lines)
        self.assertNotIn("Create a new token:", text)
        self.assertNotIn("SOFTHSM2_CONF [", "\n".join(prompts))
        self.assertIn(f"SOFTHSM2_CONF: {conf}", text)
        self.assertIn("deleted ", text)
        self.assertIn("Reuse uses oldest token. (main)", text)
        self.assertIn("Token label: keyforge", text)
        self.assertNotIn("KEYFORGE_PKCS11_TOKEN [keyforge]: ", prompts)
        self.assertIn("a new label", text)
        self.assertIn("limited number of slots", text)

    def test_existing_keyforge_kek_skips_the_label_prompt(self):
        answers = iter(["pkcs11", "", "n"])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        def labels(module, token_label, pin):
            return ["keyforge-kek"]

        real = setup_mod.list_aes_labels
        real_init = setup_mod.init_token
        real_confirm = setup_mod.confirm_user_pin
        setup_mod.list_aes_labels = labels
        setup_mod.init_token = lambda *a, **k: "/tmp/softhsm2.conf"
        setup_mod.confirm_user_pin = lambda *a, **k: None
        try:
            setup_mod.run(read_line=read_line, read_secret=lambda _p: "pin-secret", echo=self._echo)
        finally:
            setup_mod.list_aes_labels = real
            setup_mod.init_token = real_init
            setup_mod.confirm_user_pin = real_confirm
        text = "\n".join(self.lines)
        self.assertNotIn("KEYFORGE_PKCS11_KEY_LABEL [keyforge-kek]: ", prompts)
        self.assertIn("Key label: keyforge-kek", self.lines)
        self.assertIn("1. keyforge-kek (cannot be deleted)", text)
        self.assertNotIn("The new key label you just entered will only be a name.", text)

    def test_aes_menu_cannot_delete_keyforge_kek(self):
        deleted = []
        answers = iter(["d 1", "d 2", "1"])
        lines = []

        def delete(names):
            deleted.extend(names)
            return names

        chosen = setup_mod._aes_key_menu(
            lambda _p: next(answers), lines.append, ["keyforge-kek", "old"], "keyforge-kek", delete)
        self.assertEqual(chosen, "keyforge-kek")
        self.assertEqual(deleted, ["old"])
        self.assertIn("keyforge-kek cannot be deleted.", lines)
        self.assertIn("deleted old", lines)

    def test_blank_pin_asks_again(self):
        answers = iter(["pkcs11", "", "keyforge-kek", "n"])
        secrets = iter(["", "pin-secret", "so-pin"])
        prompts = []

        def read_line(prompt):
            prompts.append(prompt)
            return next(answers)

        def read_secret(prompt):
            prompts.append(prompt)
            return next(secrets)

        real_init = setup_mod.init_token
        real_confirm = setup_mod.confirm_user_pin
        setup_mod.init_token = lambda *a, **k: "/tmp/softhsm2.conf"
        setup_mod.confirm_user_pin = lambda *a, **k: None
        try:
            setup_mod.run(read_line=read_line, read_secret=read_secret, echo=self._echo)
        finally:
            setup_mod.init_token = real_init
            setup_mod.confirm_user_pin = real_confirm
        self.assertEqual(prompts.count("KEYFORGE_PKCS11_PIN: "), 2)
        self.assertIn("input blank", self.lines)
        self.assertNotIn("SoftHSM setup:", self.lines)
        self.assertIn("KEYFORGE_PKCS11_PIN=pin-secret", Path(self.env_file).read_text())

    def test_wrong_auth0_password_is_asked_again(self):
        os.environ["AUTH0_DOMAIN"] = "tenant.example.test"
        os.environ["AUTH0_CLIENT_ID"] = "client-id"
        os.environ["AUTH0_AUDIENCE"] = "https://keyforge.local/api"
        answers = iter(["local", "", "ada@example.test"])
        secrets = iter(["nope", "user-secret"])
        calls = []

        def read_line(prompt):
            return next(answers)

        def read_secret(prompt):
            return next(secrets)

        def login(username, password):
            calls.append(password)
            if password == "nope":
                raise auth.AuthError("Auth0 token endpoint: invalid_grant: Wrong email or password")
            return Principal(sub="auth0|ada", scopes=frozenset({"keys:read"}), exp=1)

        from unittest import mock
        with mock.patch("sys.stdin.isatty", return_value=True):
            setup_mod.run(read_line=read_line, read_secret=read_secret, echo=self._echo, login=login)
        self.assertEqual(calls, ["nope", "user-secret"])
        self.assertIn("password failed. Ctrl-C to exit.", self.lines)
        self.assertNotIn("nope", Path(self.env_file).read_text())

    def test_bare_keyforge_needs_a_command(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            cli.main([])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_refuses_noninteractive_setup(self):
        rc, out, err = _run("setup")
        self.assertEqual(rc, 6)
        self.assertIn("non-interactive", err)

    def test_hmac_warning_states_whether_the_walk_continued(self):
        from keyforge import audit, service as svc
        from keyforge.store import Store
        st = Store(os.environ["KEYFORGE_STORE"])
        svc.create(st, name="n", owner="o")
        kf = os.path.join(self.d.name, "hmac.key")
        with open(kf, "wb") as f:
            f.write(b"k" * 32)
        os.chmod(kf, 0o600)
        os.environ["KEYFORGE_AUDIT_HMAC_KEY_FILE"] = kf
        audit.hmac_key()
        audit.record(st, "export")
        audit.record(st, "export")
        st.audit_log[-2].pop("mac")
        st.save()
        setup_mod._audit_chain(self._echo, {})
        text = "\n".join(self.lines)
        self.assertIn("The walk continued past the first mismatch and finished at the last event.", text)
        self.assertIn("The HMAC key file was loaded. The walk continued past the first mismatch.", text)
        self.assertIn("last event", text)
        self.assertIn("os_uid:", text)
        self.assertIn("prev_hash:", text)
        warning = text.split("warning: HMAC is not verifying the audit chain.", 1)[1]
        self.assertNotIn("AUDIT CHAIN BROKEN:", warning)

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
