import io, json, os, pwd, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import cli, audit, service as svc
from keyforge.store import Store

def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()

class TestAuditIntegrity(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "s.json")
        self.st = Store(self.path)
        k, s = svc.create(self.st, name="n", owner="o")
        svc.verify(self.st, s); svc.set_status(self.st, k.id, "suspended")
        self.real = pwd.getpwuid(os.getuid()).pw_name
    def tearDown(self): self.d.cleanup()

    def test_real_os_user_recorded_despite_spoofed_actor(self):
        with mock.patch.dict(os.environ, {"KEYFORGE_ACTOR": "ceo", "USER": "ceo", "LOGNAME": "ceo"}):
            ev = audit.record(self.st, "policy_set", None, field="max_ttl")
        self.assertEqual(ev["actor"], "ceo")
        self.assertEqual(ev["os_user"], self.real); self.assertEqual(ev["os_uid"], os.getuid())

    def test_chain_valid(self):
        r = audit.verify_chain(self.st.audit_log)
        self.assertTrue(r["ok"], r); self.assertEqual(r["checked"], len(self.st.audit_log))
        self.assertEqual(self.st.audit_log[0]["prev_hash"], audit.GENESIS)
        self.assertEqual(self.st.audit_log[1]["prev_hash"], self.st.audit_log[0]["hash"])
        self.assertEqual(r["head"], self.st.audit_log[-1]["hash"])

    def test_detects_modification(self):
        self.st.audit_log[1]["actor"] = "someone-else"
        r = audit.verify_chain(self.st.audit_log); self.assertFalse(r["ok"]); self.assertEqual(r["index"], 1)

    def test_detects_os_user_edit(self):
        self.st.audit_log[0]["os_user"] = "root"
        self.assertFalse(audit.verify_chain(self.st.audit_log)["ok"])

    def test_detects_deletion_and_reorder(self):
        log = list(self.st.audit_log); del log[1]
        self.assertFalse(audit.verify_chain(log)["ok"])
        log = list(self.st.audit_log); log[0], log[1] = log[1], log[0]
        self.assertFalse(audit.verify_chain(log)["ok"])

    def test_legacy_prefix_allowed_but_not_after_chain(self):
        legacy = [{"ts": "2026-01-01T00:00:00Z", "actor": "x", "action": "create", "key_id": None, "details": {}}]
        st = Store(os.path.join(self.d.name, "l.json")); st.data["audit"] = list(legacy)
        audit.record(st, "export")
        r = audit.verify_chain(st.audit_log); self.assertTrue(r["ok"]); self.assertEqual(r["legacy"], 1)
        st.audit_log.append(dict(legacy[0]))
        self.assertFalse(audit.verify_chain(st.audit_log)["ok"])

    def test_cli_verify_and_display(self):
        self.st.save()
        rc, out, _ = run("--store", self.path, "audit", "--verify"); self.assertEqual(rc, 0, out)
        self.assertIn("audit chain OK", out)
        rc, out, _ = run("--store", self.path, "audit"); self.assertIn("OS_USER", out); self.assertIn(self.real, out)
        with open(self.path) as f: data = json.load(f)
        data["audit"][0]["action"] = "nothing_to_see"
        with open(self.path, "w") as f: json.dump(data, f)
        rc, out, _ = run("--store", self.path, "--json", "audit", "--verify")
        self.assertEqual(rc, 1); self.assertFalse(json.loads(out)["ok"])

if __name__ == "__main__":
    unittest.main()
