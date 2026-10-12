import io, os, tempfile, threading, time, unittest
from contextlib import redirect_stdout, redirect_stderr
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import cli, service as svc
from keyforge.errors import VerifyFailed
from keyforge.store import Store

class TestLocking(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "s.json")
        st = Store(self.path); self.k, self.secret = svc.create(st, name="n", owner="o"); st.save()
    def tearDown(self): self.d.cleanup()

    def test_lock_file_created_0600_and_released(self):
        with Store(self.path) as st:
            self.assertTrue(st.locked)
            self.assertEqual(os.stat(st.lock_path).st_mode & 0o777, 0o600)
        self.assertFalse(st.locked)

    def test_cli_verify_blocks_until_revoke_committed(self):
        holder = Store(self.path, lock=True)   # simulates a revoke in progress
        rc = {}
        def verify(): rc["v"] = cli.main(["--store", self.path, "verify", self.secret])
        t = threading.Thread(target=verify)
        out = io.StringIO(); ctx = redirect_stdout(out); ctx.__enter__()
        self.addCleanup(lambda: ctx.__exit__(None, None, None))
        t.start(); time.sleep(0.3)
        self.assertTrue(t.is_alive(), "verify should be blocked on the store lock")
        svc.set_status(holder, self.k.id, "revoked", reason="leak"); holder.save(); holder.close()
        t.join(10); self.assertFalse(t.is_alive())
        self.assertEqual(rc["v"], 4)
        self.assertEqual(Store(self.path).get(self.k.id).status, "revoked")

    def test_stale_verify_cannot_clobber_revoke(self):
        stale = Store(self.path)  # unlocked snapshot taken before the revoke
        with Store(self.path) as st:
            svc.set_status(st, self.k.id, "revoked", reason="leak"); st.save()
        svc.verify(stale, self.secret)  # passes on stale data, but must only write its delta
        on_disk = Store(self.path)
        self.assertEqual(on_disk.get(self.k.id).status, "revoked")
        self.assertIsNotNone(on_disk.get(self.k.id).last_used_at)
        self.assertEqual([e["action"] for e in on_disk.audit_log][-2:], ["revoke", "verify_ok"])

    def test_many_concurrent_cli_verifies_keep_all_audit_events(self):
        def v(): cli.main(["--store", self.path, "verify", self.secret])
        ts = [threading.Thread(target=v) for _ in range(8)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            [t.start() for t in ts]; [t.join(20) for t in ts]
        acts = [e["action"] for e in Store(self.path).audit_log]
        self.assertEqual(acts.count("verify_ok"), 8)

if __name__ == "__main__":
    unittest.main()
