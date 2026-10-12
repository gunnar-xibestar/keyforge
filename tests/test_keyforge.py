import io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import timedelta
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import cli, service as svc, crypto
from keyforge.store import Store
from keyforge.models import now, iso

def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()

class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "s.json")
        os.environ["KEYFORGE_STORE"] = self.path
    def tearDown(self): self.d.cleanup()
    def create(self, *extra):
        rc, out, _ = run("--json", "create", "--name", "n1", "--owner", "alice", *extra)
        self.assertEqual(rc, 0, out); return json.loads(out)

class TestCrypto(unittest.TestCase):
    def test_format_and_hash(self):
        full, pre = crypto.generate_key("live")
        self.assertTrue(full.startswith("kf_live_")); self.assertTrue(full.startswith(pre))
        self.assertEqual(crypto.prefix_of(full), pre)
        h = crypto.hash_secret(full, iters=1000)
        self.assertTrue(crypto.check_secret(full, h)); self.assertFalse(crypto.check_secret(full + "x", h))
        self.assertIsNone(crypto.prefix_of("garbage"))

class TestCLI(Base):
    def test_create_secret_not_stored(self):
        d = self.create("--env", "live", "--scope", "read:packets", "--scope", "write:battery",
                        "--label", "cost=ops", "--expires-in", "30d", "--ip-allow", "10.0.0.0/8")
        sec = d["secret"]; self.assertTrue(sec.startswith("kf_live_"))
        raw = open(self.path).read()
        self.assertNotIn(sec, raw); self.assertNotIn(sec[len(d["key"]["prefix"]):], raw)
        rc, out, _ = run("--json", "show", d["key"]["id"])
        self.assertNotIn("secret", json.loads(out)); self.assertNotIn("hash", json.loads(out))

    def test_verify_scope_ip(self):
        d = self.create("--scope", "read:*", "--ip-allow", "10.0.0.0/8"); s = d["secret"]
        self.assertEqual(run("verify", s)[0], 0)
        self.assertEqual(run("verify", s, "--scope", "read:packets", "--ip", "10.1.2.3")[0], 0)
        self.assertEqual(run("verify", s, "--scope", "write:battery")[0], 4)
        self.assertEqual(run("verify", s, "--ip", "192.168.1.1")[0], 4)
        self.assertEqual(run("verify", "kf_test_nope12345678")[0], 4)

    def test_invalid_inputs(self):
        for extra in (["--scope", "BAD"], ["--ip-allow", "300.1.1.1/8"], ["--expires-in", "5x"]):
            rc, _, _ = run("create", "--name", "x", "--owner", "o", *extra); self.assertEqual(rc, 2, extra)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            cli.main(["create", "--name", "x"])
        self.assertEqual(cm.exception.code, 2)

    def test_rotate_with_grace(self):
        d = self.create(); old = d["secret"]
        rc, out, _ = run("--json", "rotate", d["key"]["id"], "--grace-period", "1h", "--yes")
        r = json.loads(out); self.assertEqual(rc, 0)
        self.assertEqual(run("verify", old)[0], 0)
        self.assertEqual(run("verify", r["secret"])[0], 0)
        rc, out, _ = run("--json", "show", d["key"]["id"])
        self.assertEqual(json.loads(out)["effective_status"], "grace")

    def test_rotate_no_grace(self):
        d = self.create()
        run("rotate", d["key"]["id"], "--grace-period", "0s", "--yes")
        self.assertEqual(run("verify", d["secret"])[0], 4)

    def test_destructive_requires_yes(self):
        d = self.create()
        self.assertEqual(run("revoke", d["key"]["id"])[0], 6)   # no tty, no --yes
        self.assertEqual(run("revoke", d["key"]["id"], "--dry-run")[0], 0)
        self.assertEqual(run("verify", d["secret"])[0], 0)
        self.assertEqual(run("revoke", d["key"]["id"], "--yes", "--reason", "leak")[0], 0)
        self.assertEqual(run("verify", d["secret"])[0], 4)
        self.assertEqual(run("revoke", d["key"]["id"], "--yes")[0], 1)

    def test_suspend_resume(self):
        d = self.create(); kid = d["key"]["id"]
        run("suspend", kid); self.assertEqual(run("verify", d["secret"])[0], 4)
        run("resume", kid); self.assertEqual(run("verify", d["secret"])[0], 0)
        self.assertEqual(run("resume", kid)[0], 1)

    def test_update(self):
        d = self.create("--scope", "read:packets"); kid = d["key"]["id"]
        rc, out, _ = run("--json", "update", kid, "--add-scope", "write:battery", "--remove-scope",
                         "read:packets", "--label", "a=b", "--expires-in", "7d")
        k = json.loads(out)["key"]; self.assertEqual(k["scopes"], ["write:battery"])
        self.assertEqual(k["labels"], {"a": "b"}); self.assertIsNotNone(k["expires_at"])
        rc, out, _ = run("--json", "update", kid, "--add-scope", "admin:all", "--dry-run")
        rc, out, _ = run("--json", "show", kid); self.assertNotIn("admin:all", json.loads(out)["scopes"])

    def test_list_filters_formats(self):
        self.create("--team", "red", "--scope", "read:packets")
        run("create", "--name", "n2", "--owner", "bob", "--env", "live", "--team", "blue")
        rc, out, _ = run("list", "--format", "json", "--owner", "bob"); self.assertEqual(len(json.loads(out)), 1)
        rc, out, _ = run("list", "--format", "csv"); self.assertEqual(len(out.strip().splitlines()), 3)
        rc, out, _ = run("list", "--scope", "read:*"); self.assertIn("alice", out); self.assertNotIn("bob", out)
        rc, out, _ = run("list", "--env", "live", "--status", "active"); self.assertIn("n2", out)

    def test_policy(self):
        run("policy", "set", "max_ttl", "30d"); run("policy", "set", "allowed_scopes", "read:*,write:battery")
        run("policy", "set", "required_labels", "cost_center")
        self.assertEqual(run("create", "--name", "x", "--owner", "o", "--expires-in", "90d",
                             "--label", "cost_center=1")[0], 5)
        self.assertEqual(run("create", "--name", "x", "--owner", "o", "--expires-in", "10d")[0], 5)
        self.assertEqual(run("create", "--name", "x", "--owner", "o", "--expires-in", "10d",
                             "--label", "cost_center=1", "--scope", "admin:all")[0], 5)
        self.assertEqual(run("create", "--name", "x", "--owner", "o", "--expires-in", "10d",
                             "--label", "cost_center=1", "--scope", "read:packets")[0], 0)
        rc, out, _ = run("--json", "policy", "show"); self.assertEqual(json.loads(out)["max_ttl"], "30d")
        self.assertEqual(run("policy", "set", "bogus", "1")[0], 2)

    def test_audit(self):
        d = self.create(); run("verify", d["secret"]); run("verify", "kf_test_bad00000000")
        rc, out, _ = run("--json", "audit", "--key", d["key"]["id"])
        acts = [e["action"] for e in json.loads(out)]; self.assertEqual(acts, ["create", "verify_ok"])
        rc, out, _ = run("--json", "audit", "--action", "verify_fail", "--since", "1h")
        self.assertEqual(len(json.loads(out)), 1)
        f = os.path.join(self.d.name, "a.json"); run("audit", "--export", f)
        self.assertGreaterEqual(len(json.load(open(f))), 3)

    def test_export_import(self):
        d = self.create(); f = os.path.join(self.d.name, "e.json")
        self.assertEqual(run("export", "-o", f)[0], 0)
        os.environ["KEYFORGE_STORE"] = os.path.join(self.d.name, "other.json")
        rc, out, _ = run("--json", "import", f); self.assertEqual(len(json.loads(out)["added"]), 1)
        self.assertEqual(run("verify", d["secret"])[0], 0)
        rc, out, _ = run("--json", "import", f); self.assertEqual(len(json.loads(out)["skipped"]), 1)

    def test_purge_expired(self):
        st = Store(self.path)
        k, _ = svc.create(st, name="old", owner="o", expires_at=now() + timedelta(seconds=5)); st.save()
        st = Store(self.path); r = st.data["keys"][k.id]
        r["expires_at"] = iso(now() - timedelta(days=1)); st.save()
        self.create()
        rc, out, _ = run("--json", "purge", "--dry-run"); self.assertEqual(json.loads(out)["purged"], [k.id])
        self.assertEqual(run("purge")[0], 6)
        rc, out, _ = run("--json", "purge", "--yes"); self.assertEqual(json.loads(out)["purged"], [k.id])
        rc, out, _ = run("--json", "list"); self.assertEqual(len(json.loads(out)), 1)
        self.assertEqual(run("show", k.id)[0], 3)

    def test_store_flag_overrides_env(self):
        p2 = os.path.join(self.d.name, "flag.json")
        run("--store", p2, "create", "--name", "z", "--owner", "o"); self.assertTrue(os.path.exists(p2))

if __name__ == "__main__":
    unittest.main()
