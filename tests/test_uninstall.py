import os, tempfile, unittest
from pathlib import Path
from keyforge import cli
from keyforge.errors import ValidationError
from keyforge.store import StoreLocked
from keyforge.uninstall import plan, run

def _cli(*argv, home):
    import io
    from contextlib import redirect_stdout, redirect_stderr
    out, err = io.StringIO(), io.StringIO()
    old = os.environ.get("HOME")
    os.environ["HOME"] = home
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(argv))
    finally:
        if old is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old
    return rc, out.getvalue(), err.getvalue()


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.root = self.home / ".keyforge"
        self.root.mkdir()
        (self.root / "store.json").write_text('{"version":1}')
        (self.root / "kms-master.key").write_bytes(b"k" * 32)
        nested = self.root / "softhsm" / "tokens"
        nested.mkdir(parents=True)
        (nested / "token.object").write_text("tok")
        self.outside = Path(self.tmp.name) / "outside-secret"
        self.outside.write_text("keep-me")
        (self.root / "link").symlink_to(self.outside)
        os.environ["HOME"] = str(self.home)
        self._env = {k: os.environ.get(k) for k in (
            "KEYFORGE_STORE", "KEYFORGE_TOKEN_FILE", "KEYFORGE_KMS_KEY_FILE")}
        os.environ.pop("KEYFORGE_STORE", None)
        os.environ.pop("KEYFORGE_TOKEN_FILE", None)
        os.environ.pop("KEYFORGE_KMS_KEY_FILE", None)

    def tearDown(self):
        os.environ["HOME"] = str(self.home)
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_dry_run_keeps_files_and_outside_target(self):
        result = run(dry_run=True, include_configured=False, root=self.root)
        self.assertTrue(result["dry_run"])
        self.assertTrue((self.root / "store.json").exists())
        self.assertTrue(self.outside.exists())
        self.assertIn(str(self.root / "link"), result["removed"])

    def test_yes_removes_tree_but_not_symlink_target(self):
        result = run(dry_run=False, include_configured=False, root=self.root)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.outside.read_text(), "keep-me")
        self.assertTrue(any(p.endswith("store.json") for p in result["removed"]))

    def test_refuses_symlinked_directory(self):
        os.rename(self.root, self.home / "moved")
        (self.home / ".keyforge").symlink_to(self.home / "moved")
        with self.assertRaises(ValidationError):
            plan(self.home / ".keyforge")
        self.assertTrue((self.home / "moved" / "store.json").exists())

    def test_configured_file_outside_requires_flag(self):
        ext = Path(self.tmp.name) / "custom-store.json"
        ext.write_text("store")
        os.environ["KEYFORGE_STORE"] = str(ext)
        run(dry_run=False, include_configured=False, root=self.root)
        self.assertTrue(ext.exists())
        ext.write_text("store")
        # root is gone; recreate so the second call is about the outside file only
        self.root.mkdir()
        run(dry_run=False, include_configured=True, root=self.root)
        self.assertFalse(ext.exists())

    def test_skips_hard_link(self):
        hard = Path(self.tmp.name) / "hard"
        os.link(self.root / "kms-master.key", hard)
        result = run(dry_run=False, include_configured=False, root=self.root)
        self.assertTrue(hard.exists())
        self.assertTrue(any("hard link" in s for s in result["skipped"]))

    def test_locked_store(self):
        import fcntl
        lock = self.root / "store.json.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaises(StoreLocked):
                plan(self.root)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_cli_dry_run_and_reject_store_flag(self):
        rc, out, err = _cli("uninstall", "--dry-run", home=str(self.home))
        self.assertEqual(rc, 0, err)
        self.assertIn("would remove", out)
        self.assertTrue((self.root / "store.json").exists())
        rc, _, err = _cli("--store", str(self.root / "store.json"), "uninstall", "--yes", home=str(self.home))
        self.assertEqual(rc, 2, err)
        self.assertIn("--store", err)
        self.assertTrue((self.root / "store.json").exists())

    def test_cli_yes(self):
        rc, out, err = _cli("uninstall", "--yes", home=str(self.home))
        self.assertEqual(rc, 0, err)
        self.assertIn("pip uninstall keyforge", out)
        self.assertFalse(self.root.exists())
        self.assertTrue(self.outside.exists())
