import os, tempfile, unittest
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import service as svc
from keyforge.errors import VerifyFailed
from keyforge.store import Store

class TestIpAllowRequired(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.st = Store(os.path.join(self.d.name, "s.json"))
    def tearDown(self): self.d.cleanup()

    def test_allowlisted_key_requires_ip(self):
        _, s = svc.create(self.st, name="a", owner="o", ip_allow=["10.0.0.0/8"])
        for ip in (None, ""):
            with self.assertRaises(VerifyFailed) as cm: svc.verify(self.st, s, ip=ip)
            self.assertIn("no client ip", str(cm.exception))
        self.assertEqual(self.st.audit_log[-1]["action"], "verify_fail")
        svc.verify(self.st, s, ip="10.9.9.9")

    def test_malformed_ip_fails_closed(self):
        _, s = svc.create(self.st, name="a", owner="o", ip_allow=["10.0.0.0/8"])
        with self.assertRaises(VerifyFailed): svc.verify(self.st, s, ip="not-an-ip")

    def test_no_allowlist_ip_optional(self):
        _, s = svc.create(self.st, name="b", owner="o")
        svc.verify(self.st, s); svc.verify(self.st, s, ip="1.2.3.4")

if __name__ == "__main__":
    unittest.main()

class TestIpFollowups(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.st = Store(os.path.join(self.d.name, "s.json"))
    def tearDown(self): self.d.cleanup()

    def test_corrupt_stored_cidr_fails_with_audit(self):
        k, s = svc.create(self.st, name="a", owner="o", ip_allow=["10.0.0.0/8"])
        self.st.data["keys"][k.id]["ip_allow"] = ["garbage/99"]
        with self.assertRaises(VerifyFailed): svc.verify(self.st, s, ip="10.1.1.1")
        self.assertEqual(self.st.audit_log[-1]["action"], "verify_fail")
        self.st.data["keys"][k.id]["ip_allow"] = ["garbage/99", "10.0.0.0/8"]
        svc.verify(self.st, s, ip="10.1.1.1")  # valid entry still honored

    def test_ipv4_mapped_ipv6(self):
        _, s = svc.create(self.st, name="a", owner="o", ip_allow=["10.0.0.0/8"])
        svc.verify(self.st, s, ip="::ffff:10.2.3.4")
        with self.assertRaises(VerifyFailed): svc.verify(self.st, s, ip="::ffff:192.168.0.1")
        _, s2 = svc.create(self.st, name="b", owner="o", ip_allow=["::ffff:10.0.0.0/104"])
        self.st.save()  # persist before verify (verify may reload from disk once store locking lands)
        svc.verify(self.st, s2, ip="10.9.9.9")

    def test_ip_sanitized_in_reason_and_audit(self):
        _, s = svc.create(self.st, name="a", owner="o", ip_allow=["10.0.0.0/8"])
        evil = "1.2.3.4\n2026 FAKE verify_ok" + "A" * 500
        with self.assertRaises(VerifyFailed) as cm: svc.verify(self.st, s, ip=evil)
        self.assertNotIn("\n", str(cm.exception)); self.assertLess(len(str(cm.exception)), 150)
        det = self.st.audit_log[-1]["details"]
        self.assertNotIn("\n", det["ip"]); self.assertNotIn("\n", det["reason"]); self.assertLessEqual(len(det["ip"]), 70)
