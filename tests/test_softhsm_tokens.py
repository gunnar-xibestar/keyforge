"""Newer SoftHSM token directories that share a label are deleted; the oldest stays."""
import os, shutil, subprocess, tempfile, time, unittest
from pathlib import Path

from keyforge.softhsm import drop_newer_tokens, token_object_has_label

MODULE = "/usr/lib/softhsm/libsofthsm2.so"


def _token_object(label: str) -> bytes:
    padded = label.encode() + b" " * (32 - len(label))
    return (32).to_bytes(8, "big") + padded


class DropNewerTokenTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.root = Path(self.d.name) / "tokens"
        self.root.mkdir()
        self.conf = Path(self.d.name) / "softhsm2.conf"
        self.conf.write_text(f"directories.tokendir = {self.root}\n")

    def tearDown(self):
        self.d.cleanup()

    def _write(self, name: str, label: str, mtime_ns: int):
        path = self.root / name
        path.mkdir()
        obj = path / "token.object"
        obj.write_bytes(_token_object(label))
        os.utime(obj, ns=(mtime_ns, mtime_ns))
        return path

    def test_keeps_oldest_and_leaves_other_labels(self):
        oldest = self._write("old", "keyforge", 1_000)
        other = self._write("other", "other", 2_000)
        newer = self._write("new", "keyforge", 3_000)
        link = self.root / "link"
        link.symlink_to(newer)
        removed = drop_newer_tokens("keyforge", str(self.conf))
        self.assertEqual(removed, [str(newer)])
        self.assertTrue(oldest.is_dir())
        self.assertTrue(other.is_dir())
        self.assertFalse(newer.exists())
        self.assertTrue(link.is_symlink())

    def test_single_token_is_left_alone(self):
        only = self._write("only", "keyforge", 1_000)
        self.assertEqual(drop_newer_tokens("keyforge", str(self.conf)), [])
        self.assertTrue(only.is_dir())

    def test_label_match_is_space_padded(self):
        self.assertTrue(token_object_has_label(_token_object("keyforge"), "keyforge"))
        self.assertFalse(token_object_has_label(_token_object("keyforge-extra"), "keyforge"))

    def test_symlink_tokendir_is_not_deleted(self):
        real = self._write("old", "keyforge", 1)
        self._write("new", "keyforge", 2)
        linked = Path(self.d.name) / "linked-tokens"
        linked.symlink_to(self.root)
        conf = Path(self.d.name) / "link.conf"
        conf.write_text(f"directories.tokendir = {linked}\n")
        self.assertEqual(drop_newer_tokens("keyforge", str(conf)), [])
        self.assertTrue(real.is_dir())


@unittest.skipUnless(os.path.exists(MODULE) and shutil.which("softhsm2-util"), "SoftHSM is not installed")
class LiveSoftHsmDuplicateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        tokendir = os.path.join(self.d.name, "tokens")
        os.makedirs(tokendir)
        conf = os.path.join(self.d.name, "softhsm2.conf")
        Path(conf).write_text(
            f"directories.tokendir = {tokendir}\nobjectstore.backend = file\nlog.level = ERROR\n"
        )
        self.conf = conf
        self._saved = {"SOFTHSM2_CONF": os.environ.get("SOFTHSM2_CONF")}
        os.environ["SOFTHSM2_CONF"] = conf
        for _ in range(2):
            subprocess.run(
                ["softhsm2-util", "--init-token", "--free", "--label", "keyforge",
                 "--pin", "1234", "--so-pin", "5678"],
                check=True, capture_output=True, text=True,
            )
            time.sleep(0.05)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def test_real_token_objects_keep_the_oldest_label(self):
        before = [p for p in Path(self.d.name, "tokens").iterdir() if p.is_dir()]
        self.assertEqual(len(before), 2)
        oldest = min(before, key=lambda p: (p / "token.object").stat().st_mtime_ns)
        removed = drop_newer_tokens("keyforge", self.conf)
        self.assertEqual(len(removed), 1)
        self.assertNotEqual(removed[0], str(oldest))
        left = [p for p in Path(self.d.name, "tokens").iterdir() if p.is_dir()]
        self.assertEqual(left, [oldest])
        slots = subprocess.check_output(["softhsm2-util", "--show-slots"], text=True)
        self.assertEqual(slots.count("Label:            keyforge"), 1)
