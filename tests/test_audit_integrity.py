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
        r = audit.verify_chain(self.st.audit_log, self.st.data['audit_meta'])
        self.assertTrue(r["ok"], r); self.assertEqual(r["checked"], len(self.st.audit_log))
        self.assertEqual(self.st.audit_log[0]["prev_hash"], audit.GENESIS)
        self.assertEqual(self.st.audit_log[1]["prev_hash"], self.st.audit_log[0]["hash"])
        self.assertEqual(r["head"], self.st.audit_log[-1]["hash"])

    def test_detects_modification(self):
        self.st.audit_log[1]["actor"] = "someone-else"
        r = audit.verify_chain(self.st.audit_log, self.st.data['audit_meta']); self.assertFalse(r["ok"]); self.assertEqual(r["index"], 1)

    def test_detects_os_user_edit(self):
        self.st.audit_log[0]["os_user"] = "root"
        self.assertFalse(audit.verify_chain(self.st.audit_log, self.st.data['audit_meta'])["ok"])

    def test_detects_deletion_and_reorder(self):
        log = list(self.st.audit_log); del log[1]
        self.assertFalse(audit.verify_chain(log, self.st.data['audit_meta'])["ok"])
        log = list(self.st.audit_log); log[0], log[1] = log[1], log[0]
        self.assertFalse(audit.verify_chain(log, self.st.data['audit_meta'])["ok"])

    def test_legacy_prefix_allowed_but_not_after_chain(self):
        legacy = [{"ts": "2026-01-01T00:00:00Z", "actor": "x", "action": "create", "key_id": None, "details": {}}]
        st = Store(os.path.join(self.d.name, "l.json")); st.data["audit"] = list(legacy); st.data.pop("audit_meta")
        audit.record(st, "export")
        r = audit.verify_chain(st.audit_log, st.data['audit_meta']); self.assertTrue(r["ok"]); self.assertEqual(r["legacy"], 1)
        st.audit_log.append(dict(legacy[0])); st.data["audit_meta"]["count"] += 1
        self.assertFalse(audit.verify_chain(st.audit_log, st.data['audit_meta'])["ok"])

    def test_cli_verify_and_display(self):
        self.st.save()
        rc, out, _ = run("--store", self.path, "audit", "--verify"); self.assertEqual(rc, 0, out)
        self.assertIn("audit chain OK", out)
        rc, out, _ = run("--store", self.path, "audit"); self.assertIn("OS_USER", out); self.assertIn(self.real, out)
        with open(self.path) as f: data = json.load(f)
        data["audit"][0]["action"] = "nothing_to_see"
        with open(self.path, "w") as f: json.dump(data, f)
        rc, out, _ = run("--store", self.path, "--json", "audit", "--verify")
        self.assertEqual(rc, 7); self.assertFalse(json.loads(out)["ok"])

class TestAuditFollowups(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "s.json")
        self.st = Store(self.path)
        for i in range(3): audit.record(self.st, "export", None, n=i)
    def tearDown(self): self.d.cleanup()
    def ok(self, key=None): return audit.verify_chain(self.st.audit_log, self.st.data.get("audit_meta"), key)

    def test_stripping_hash_fields_fails(self):
        for ev in self.st.audit_log: ev.pop("hash"); ev.pop("prev_hash")
        self.assertFalse(self.ok()["ok"])
    def test_stripping_single_event_fails(self):
        ev = self.st.audit_log[2]; ev.pop("hash"); ev.pop("prev_hash")
        self.assertFalse(self.ok()["ok"])

    def test_legacy_count_frozen(self):
        legacy = {"ts": "2026-01-01T00:00:00Z", "actor": "x", "action": "create", "key_id": None, "details": {}}
        st = Store(os.path.join(self.d.name, "l.json")); st.data["audit"] = [dict(legacy), dict(legacy)]
        st.data.pop("audit_meta")  # simulate a store written before chaining existed
        audit.record(st, "export")
        self.assertEqual(st.data["audit_meta"]["legacy"], 2)
        self.assertTrue(audit.verify_chain(st.audit_log, st.data["audit_meta"])["ok"])
        del st.audit_log[0]; st.data["audit_meta"]["count"] -= 1   # drop a legacy event
        self.assertFalse(audit.verify_chain(st.audit_log, st.data["audit_meta"])["ok"])

    def test_truncation_detected_by_count(self):
        self.st.audit_log.pop()
        r = self.ok(); self.assertFalse(r["ok"])
        self.assertIn("count", r["error"])

    def test_meta_removed_fails(self):
        del self.st.data["audit_meta"]; self.assertFalse(self.ok()["ok"])

    def test_meta_stored_with_head(self):
        m = self.st.data["audit_meta"]
        self.assertEqual(m["count"], 3); self.assertEqual(m["head"], self.st.audit_log[-1]["hash"])

    def test_hash_covers_exact_stored_bytes(self):
        self.st.save()
        with open(self.path) as f: data = json.load(f)
        r = audit.verify_chain(data["audit"], data["audit_meta"]); self.assertTrue(r["ok"], r)
        with self.assertRaises(TypeError): audit.record(self.st, "x", None, obj=object())

    def test_sudo_user_claim(self):
        with mock.patch.dict(os.environ, {"SUDO_USER": "mallory"}):
            ev = audit.record(self.st, "policy_set")
        self.assertEqual(ev["sudo_user_claim"], "mallory")
        self.assertEqual(ev["os_user"], pwd.getpwuid(os.getuid()).pw_name)
        self.assertTrue(self.ok()["ok"])

    def test_hmac(self):
        kf = os.path.join(self.d.name, "hmac.key")
        with open(kf, "wb") as f: f.write(b"k" * 32)
        os.chmod(kf, 0o600)
        with mock.patch.dict(os.environ, {"KEYFORGE_AUDIT_HMAC_KEY_FILE": kf}):
            key = audit.hmac_key()
            audit.record(self.st, "export"); audit.record(self.st, "export")
        r = self.ok(key); self.assertTrue(r["ok"], r); self.assertTrue(r["mac_verified"])
        # attacker without the key rewrites an event and recomputes the chain + metadata
        ev = self.st.audit_log[4]; ev["actor"] = "eve"; ev["hash"] = audit.entry_hash(ev)
        self.st.data["audit_meta"]["head"] = ev["hash"]
        self.assertTrue(self.ok()["ok"])          # unkeyed check is fooled
        self.assertFalse(self.ok(key)["ok"])      # keyed check is not
        self.assertFalse(audit.verify_chain([], None, key)["ok"])

    def test_cli_tamper_exit_code(self):
        self.st.save()
        with open(self.path) as f: data = json.load(f)
        data["audit"].pop()
        with open(self.path, "w") as f: json.dump(data, f)
        self.assertEqual(run("--store", self.path, "audit", "--verify")[0], 7)

class TestAuditRound3(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "s.json")
    def tearDown(self): self.d.cleanup()

    def test_meta_written_at_creation(self):
        st = Store(self.path); self.assertEqual(st.data["audit_meta"]["legacy"], 0)
        st.save(); self.assertEqual(run("--store", self.path, "audit", "--verify")[0], 0)

    def test_repro_strip_everything_exits_7(self):
        rc, out, _ = run("--store", self.path, "--json", "create", "--name", "n", "--owner", "o")
        kid = json.loads(out)["key"]["id"]
        run("--store", self.path, "revoke", kid, "--yes")
        with open(self.path) as f: data = json.load(f)
        del data["audit_meta"]
        for e in data["audit"]:
            e.pop("hash", None); e.pop("prev_hash", None)
        data["audit"] = [e for e in data["audit"] if e["action"] != "revoke"]
        with open(self.path, "w") as f: json.dump(data, f)
        self.assertEqual(run("--store", self.path, "audit", "--verify")[0], 7)
        # and adopt-legacy refuses only if chained events remain; here they were all stripped, so the
        # adoption itself is recorded with the real os_user as an explicit trust decision
        self.assertEqual(run("--store", self.path, "audit", "--adopt-legacy")[0], 0)
        self.assertEqual(run("--store", self.path, "audit", "--verify")[0], 0)

    def test_adopt_legacy_refuses_with_chained_events(self):
        st = Store(self.path); audit.record(st, "export"); st.data.pop("audit_meta"); st.save()
        self.assertEqual(run("--store", self.path, "audit", "--adopt-legacy")[0], 1)

    def _keyfile(self, mode):
        kf = os.path.join(self.d.name, "k")
        with open(kf, "wb") as f: f.write(b"z" * 32)
        os.chmod(kf, mode); return kf

    def test_key_file_permissions_rejected(self):
        for mode in (0o640, 0o604, 0o644):
            kf = self._keyfile(mode)
            with mock.patch.dict(os.environ, {"KEYFORGE_AUDIT_HMAC_KEY_FILE": kf}):
                with self.assertRaises(Exception) as cm: audit.hmac_key()
                self.assertIn("chmod 600", str(cm.exception))

    def test_missing_key_does_not_block_revoke_but_verify_fails(self):
        st = Store(self.path); k, s = svc.create(st, name="n", owner="o"); st.save()
        missing = os.path.join(self.d.name, "nope")
        with mock.patch.dict(os.environ, {"KEYFORGE_AUDIT_HMAC_KEY_FILE": missing}):
            rc, _, err = run("--store", self.path, "revoke", k.id, "--yes")
            self.assertEqual(rc, 0); self.assertIn("WITHOUT HMAC", err)
            self.assertEqual(Store(self.path).get(k.id).status, "revoked")
            rc, _, err = run("--store", self.path, "audit", "--verify")
            self.assertEqual(rc, 1); self.assertIn("unusable", err)
        ev = Store(self.path).audit_log[-1]; self.assertIn("hmac_error", ev)
        self.assertTrue(audit.verify_chain(Store(self.path).audit_log, Store(self.path).data["audit_meta"])["ok"])

if __name__ == "__main__":
    unittest.main()
