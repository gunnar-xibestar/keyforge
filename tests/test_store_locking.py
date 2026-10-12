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
        with self.assertRaises(VerifyFailed):  # status is re-checked after reload under lock
            svc.verify(stale, self.secret)
        on_disk = Store(self.path)
        self.assertEqual(on_disk.get(self.k.id).status, "revoked")
        self.assertEqual([e["action"] for e in on_disk.audit_log][-2:], ["revoke", "verify_fail"])

    def test_many_concurrent_cli_verifies_keep_all_audit_events(self):
        def v(): cli.main(["--store", self.path, "verify", self.secret])
        ts = [threading.Thread(target=v) for _ in range(8)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            [t.start() for t in ts]; [t.join(20) for t in ts]
        acts = [e["action"] for e in Store(self.path).audit_log]
        self.assertEqual(acts.count("verify_ok"), 8)

if __name__ == "__main__":
    unittest.main()

from unittest import mock
from keyforge.store import StoreLocked

class TestLockingFollowups(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory(); self.path = os.path.join(self.d.name, "sub", "s.json")
        st = Store(self.path); self.k, self.secret = svc.create(st, name="n", owner="o"); st.save()
    def tearDown(self): self.d.cleanup()

    def test_dir_mode_0700(self):
        self.assertEqual(os.stat(os.path.dirname(self.path)).st_mode & 0o777, 0o700)

    def test_lock_timeout(self):
        holder = Store(self.path, lock=True)
        try:
            t0 = time.monotonic()
            with self.assertRaises(StoreLocked): Store(self.path).acquire(timeout=0.2)
            self.assertLess(time.monotonic() - t0, 2)
        finally:
            holder.close()

    def test_lock_file_symlink_refused(self):
        lp = self.path + ".lock"
        if os.path.exists(lp): os.unlink(lp)
        target = os.path.join(self.d.name, "victim"); open(target, "w").close()
        os.symlink(target, lp)
        with self.assertRaises(OSError): Store(self.path, lock=True)

    def test_dir_fsync_after_replace(self):
        st = Store(self.path)
        with mock.patch("keyforge.store.os.fsync", wraps=os.fsync) as fs:
            st.save()
        self.assertGreaterEqual(fs.call_count, 2)  # file + directory

    def test_lock_not_held_during_prompt(self):
        observed = {}
        def fake_input(prompt):
            # another process must be able to take the lock while we wait for the user
            other = Store(self.path); other.acquire(timeout=1)
            svc.set_status(other, self.k.id, "suspended"); other.save(); other.close()
            observed["ok"] = True
            return "y"
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", fake_input), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = cli.main(["--store", self.path, "revoke", self.k.id])
        self.assertTrue(observed.get("ok"))
        self.assertEqual(rc, 0)
        k = Store(self.path).get(self.k.id)
        self.assertEqual(k.status, "revoked")  # revoke applied on reloaded state
        self.assertIn("suspend", [e["action"] for e in Store(self.path).audit_log])

    def test_commit_verify_rechecks_status_after_reload(self):
        stale = Store(self.path)
        with Store(self.path) as st:
            svc.set_status(st, self.k.id, "revoked"); st.save()
        # stale snapshot thinks the key is active, but the reload under lock must reject it
        with self.assertRaises(VerifyFailed): svc.verify(stale, self.secret)
        on_disk = Store(self.path)
        self.assertEqual(on_disk.audit_log[-1]["action"], "verify_fail")
        self.assertIsNone(on_disk.get(self.k.id).last_used_at)

    def test_purge_only_confirmed(self):
        self.assertEqual(svc.purge(Store(self.path), include_revoked=True, only_ids=set()), [])
