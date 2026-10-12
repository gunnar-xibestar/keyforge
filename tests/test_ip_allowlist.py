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
