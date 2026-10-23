"""Byte-exact JSON snapshots of the keyforge CLI.

The clock, key ids, KMS master key, and RNG are fixed so `--json` and
`list --format json` output is stable. Each ``now()`` call advances one
second, so ``created_at`` values differ and list order follows that field.
"""
import io
import json
import os
import random
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from keyforge import cli
from keyforge.store import Store

SNAP_DIR = Path(__file__).parent / "snapshots"

_ENV_KEYS = (
    "KEYFORGE_STORE",
    "KEYFORGE_ACTOR",
    "KEYFORGE_KMS_KEY_FILE",
    "KEYFORGE_KMS_PROVIDER",
    "KEYFORGE_KMS_MEMORY_KEY",
    "KEYFORGE_AUDIT_HMAC_KEY_FILE",
    "KEYFORGE_ENV_FILE",
    "KEYFORGE_PBKDF2_ITERS",
    "KEYFORGE_LOCK_TIMEOUT",
    "SUDO_USER",
    "AUTH0_DOMAIN",
    "AUTH0_CLIENT_ID",
    "AUTH0_AUDIENCE",
    "AUTH0_CLIENT_SECRET",
)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
            rc = code if isinstance(code, int) else 1
    return rc, out.getvalue(), err.getvalue()


class _Clock:
    """UTC clock. Every read moves forward one second."""

    def __init__(self):
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        current = self._t
        self._t = current + timedelta(seconds=1)
        return current


class _Rng:
    def __init__(self, seed=20260101):
        self._r = random.Random(seed)

    def token_bytes(self, n):
        return bytes(self._r.getrandbits(8) for _ in range(n))

    def urandom(self, n):
        return self.token_bytes(n)

    def choice(self, seq):
        return seq[self._r.randrange(len(seq))]


class DeterministicCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "store.json")
        self.kms_path = os.path.join(self.tmp.name, "kms.key")
        fd = os.open(self.kms_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, b"\x11" * 32)
        finally:
            os.close(fd)
        os.chmod(self.kms_path, 0o600)

        self._saved_env = {key: os.environ.get(key) for key in _ENV_KEYS}
        os.environ["KEYFORGE_STORE"] = self.path
        os.environ["KEYFORGE_ACTOR"] = "cli-tester"
        os.environ["KEYFORGE_KMS_KEY_FILE"] = self.kms_path
        os.environ["KEYFORGE_ENV_FILE"] = os.path.join(self.tmp.name, "missing.env")
        os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
        for key in (
            "KEYFORGE_KMS_PROVIDER",
            "KEYFORGE_KMS_MEMORY_KEY",
            "KEYFORGE_AUDIT_HMAC_KEY_FILE",
            "KEYFORGE_LOCK_TIMEOUT",
            "SUDO_USER",
            "AUTH0_DOMAIN",
            "AUTH0_CLIENT_ID",
            "AUTH0_AUDIENCE",
            "AUTH0_CLIENT_SECRET",
        ):
            os.environ.pop(key, None)

        clock = _Clock()
        rng = _Rng()
        ids = (f"key_{i:012x}" for i in range(1, 10_000))
        now = clock.__call__
        self._patchers = [
            mock.patch("keyforge.models.now", now),
            mock.patch("keyforge.service.now", now),
            mock.patch("keyforge.audit.log.now", now),
            mock.patch("keyforge.cli.now", now),
            mock.patch("keyforge.policy.now", now),
            mock.patch("keyforge.audit.log.os_user", return_value=("cli-tester", 1000)),
            mock.patch("keyforge.crypto.new_id", side_effect=lambda: next(ids)),
            mock.patch("secrets.token_bytes", rng.token_bytes),
            mock.patch("secrets.choice", rng.choice),
            mock.patch("os.urandom", rng.urandom),
        ]
        for patcher in self._patchers:
            patcher.start()
        self.addCleanup(self._stop)
        self.addCleanup(self.tmp.cleanup)

    def _stop(self):
        for patcher in reversed(self._patchers):
            patcher.stop()
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def snap(self, name, *argv):
        rc, out, err = run(*argv)
        self.assertEqual(rc, 0, f"{name}: rc={rc}\nstderr={err}\nstdout={out}")
        self.assertEqual(err, "", f"{name} wrote to stderr:\n{err}")
        self.assert_snapshot(name, out)
        return json.loads(out)

    def assert_snapshot(self, name, text):
        path = SNAP_DIR / f"{name}.json"
        if os.environ.get("UPDATE_SNAPSHOTS") == "1":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            return
        self.assertTrue(path.is_file(), f"missing snapshot {path}; regenerate with UPDATE_SNAPSHOTS=1")
        self.assertEqual(path.read_text(), text)

    def assert_error(self, code, message, *argv):
        """Text-mode failure: exact stderr, empty stdout, exact exit code."""
        rc, out, err = run(*argv)
        self.assertEqual(rc, code, f"argv={argv}\nstdout={out}\nstderr={err}")
        self.assertEqual(out, "")
        self.assertEqual(err, f"keyforge: error: {message}\n")

    def assert_json_error(self, code, message, *argv):
        """``--json`` failure envelope. ``argv`` is the command without ``--json``."""
        rc, out, err = run("--json", *argv)
        self.assertEqual(rc, code, f"argv={argv}\nstdout={out}\nstderr={err}")
        self.assertEqual(err, "")
        self.assertEqual(out, json.dumps({"error": message, "exit_code": code}) + "\n")

    def create(self, *extra, name="n1", owner="alice"):
        rc, out, err = run("--json", "create", "--name", name, "--owner", owner, *extra)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(err, "")
        return json.loads(out)


class TestCLISnapshots(DeterministicCLI):
    def test_main_commands_json_snapshots(self):
        self.snap("auth_status", "--json", "auth", "status")
        self.snap("list_empty", "list", "--format", "json")

        zeta = self.snap(
            "create",
            "--json", "create",
            "--name", "zeta",
            "--owner", "alice",
            "--team", "red",
            "--env", "test",
            "--scope", "write:battery",
            "--scope", "read:packets",
            "--expires-in", "30d",
            "--rate-limit", "120",
            "--ip-allow", "10.0.0.0/8",
            "--label", "cost=ops",
            "--label", "region=us",
            "--description", "edge gateway",
        )
        alpha = self.snap(
            "create_alpha",
            "--json", "create",
            "--name", "alpha",
            "--owner", "bob",
            "--team", "blue",
            "--env", "live",
            "--scope", "read:status",
            "--expires-at", "2026-06-01T00:00:00Z",
            "--ip-allow", "192.168.0.0/16",
            "--label", "cost=lab",
        )
        self.assertNotEqual(zeta["key"]["created_at"], alpha["key"]["created_at"])
        self.assertLess(zeta["key"]["created_at"], alpha["key"]["created_at"])

        listed = self.snap("list", "list", "--format", "json")
        self.assertEqual([row["name"] for row in listed], ["zeta", "alpha"])
        created = [row["created_at"] for row in listed]
        self.assertEqual(created, sorted(created))
        self.assertEqual(len(created), len(set(created)))
        # `--json` and `--format json` share one JSON encoding.
        rc, out, err = run("--json", "list")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assert_snapshot("list", out)

        self.snap("list_owner_bob", "list", "--format", "json", "--owner", "bob")
        self.snap("list_env_test", "list", "--format", "json", "--env", "test")

        zid = zeta["key"]["id"]
        self.snap("show", "--json", "show", zid)
        self.snap("reveal", "--json", "reveal", zid)
        self.snap(
            "verify",
            "--json", "verify", zeta["secret"],
            "--scope", "read:packets",
            "--ip", "10.1.2.3",
        )
        self.snap("show_after_verify", "--json", "show", zid)

        rotated = self.snap(
            "rotate",
            "--json", "rotate", zid, "--grace-period", "24h", "--yes",
        )
        listed = self.snap("list_after_rotate", "list", "--format", "json")
        created = [row["created_at"] for row in listed]
        self.assertEqual(created, sorted(set(created)))
        self.assertEqual([row["name"] for row in listed], ["zeta", "alpha", "zeta"])
        self.snap("list_status_grace", "list", "--format", "json", "--status", "grace")

        nid = rotated["new_key"]["id"]
        self.snap("suspend", "--json", "suspend", nid, "--reason", "maintenance")
        self.snap("resume", "--json", "resume", nid)
        self.snap(
            "update",
            "--json", "update", nid,
            "--add-scope", "admin:read",
            "--label", "tier=gold",
            "--rate-limit", "50",
            "--description", "rotated gateway",
        )
        self.snap("revoke", "--json", "revoke", zid, "--yes", "--reason", "leak")

        self.snap("policy_show", "--json", "policy", "show")
        self.snap("policy_set", "--json", "policy", "set", "max_ttl", "90d")
        self.snap("policy_show_after_set", "--json", "policy", "show")

        self.snap("export", "export")
        self.snap("export_with_audit", "export", "--include-audit")
        self.snap("audit", "--json", "audit")
        self.snap("audit_verify", "--json", "audit", "--verify")
        self.snap("policy_reset", "--json", "policy", "reset", "--yes")

        exported = os.path.join(self.tmp.name, "export.json")
        rc, out, err = run("export", "-o", exported)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(err, "")
        self.assertEqual(out, f"exported 3 keys to {exported}\n")
        self.assertTrue(os.path.isfile(exported))

        os.environ["KEYFORGE_STORE"] = os.path.join(self.tmp.name, "imported.json")
        imported = self.snap("import", "--json", "import", exported)
        self.assertEqual(imported["added"], [zeta["key"]["id"], alpha["key"]["id"], nid])
        again = self.snap("import_again", "--json", "import", exported)
        self.assertEqual(again["skipped"], imported["added"])
        self.assertEqual(again["added"], [])

    def test_dry_run_json_snapshots(self):
        self.snap(
            "create_dry_run",
            "--json", "create", "--dry-run",
            "--name", "zeta",
            "--owner", "alice",
            "--scope", "read:packets",
            "--expires-in", "7d",
        )
        rc, out, err = run("list", "--format", "json")
        self.assertEqual((rc, err, out), (0, "", "[]\n"))

        created = self.create("--scope", "read:packets", "--expires-in", "30d")
        kid = created["key"]["id"]
        self.snap(
            "update_dry_run",
            "--json", "update", kid, "--dry-run",
            "--add-scope", "write:battery",
            "--label", "cost=ops",
        )
        self.snap("rotate_dry_run", "--json", "rotate", kid, "--dry-run", "--grace-period", "12h")
        self.snap("revoke_dry_run", "--json", "revoke", kid, "--dry-run", "--reason", "leak")
        self.snap("policy_set_dry_run", "--json", "policy", "set", "max_ttl", "90d", "--dry-run")
        # Dry-run leaves the saved key active and the policy untouched.
        shown = json.loads(run("--json", "show", kid)[1])
        self.assertEqual(shown["status"], "active")
        self.assertEqual(shown["scopes"], ["read:packets"])
        policy = json.loads(run("--json", "policy", "show")[1])
        self.assertIsNone(policy["max_ttl"])

    def test_purge_json_snapshot(self):
        first = self.create("--expires-at", "2026-06-01T00:00:00Z", name="old-a", owner="alice")
        second = self.create("--expires-at", "2026-07-01T00:00:00Z", name="old-b", owner="bob")
        keeper = self.create(name="keeper", owner="carol")
        self.assertLess(first["key"]["created_at"], second["key"]["created_at"])
        self.assertLess(second["key"]["created_at"], keeper["key"]["created_at"])

        st = Store(self.path)
        try:
            st.data["keys"][first["key"]["id"]]["expires_at"] = "2025-11-01T00:00:00Z"
            st.data["keys"][second["key"]["id"]]["expires_at"] = "2025-12-01T00:00:00Z"
            st.save()
        finally:
            st.close()

        message = "Permanently delete 2 key record(s)? - refusing without --yes (non-interactive)"
        self.assert_error(6, message, "purge")
        self.assert_json_error(6, message, "purge")
        purged = self.snap("purge_dry_run", "--json", "purge", "--dry-run")
        self.assertEqual(purged["purged"], [first["key"]["id"], second["key"]["id"]])
        self.assertTrue(purged["dry_run"])
        purged = self.snap("purge", "--json", "purge", "--yes")
        self.assertEqual(purged["purged"], [first["key"]["id"], second["key"]["id"]])
        self.assertFalse(purged["dry_run"])
        remaining = self.snap("list_after_purge", "list", "--format", "json")
        self.assertEqual([row["id"] for row in remaining], [keeper["key"]["id"]])


class TestCLIFailures(DeterministicCLI):
    def test_validation_and_usage(self):
        cases = [
            (2, "invalid scope 'BAD' (expected resource:action, e.g. read:packets)",
             ["create", "--name", "x", "--owner", "o", "--scope", "BAD"]),
            (2, "invalid CIDR '300.1.1.1/8'",
             ["create", "--name", "x", "--owner", "o", "--ip-allow", "300.1.1.1/8"]),
            (2, "invalid duration '5x' (use e.g. 30d, 12h, 15m, 2w)",
             ["create", "--name", "x", "--owner", "o", "--expires-in", "5x"]),
            (2, "expiry must be in the future",
             ["create", "--name", "x", "--owner", "o", "--expires-at", "2020-01-01T00:00:00Z"]),
            (2, "rate limit must be positive",
             ["create", "--name", "x", "--owner", "o", "--rate-limit", "0"]),
            (2, "unknown policy field 'bogus'; choose from max_ttl, require_expiry, allowed_scopes, "
                "required_labels, max_rate_limit, live_requires_ip_allow, default_grace_period",
             ["policy", "set", "bogus", "1"]),
        ]
        for code, message, argv in cases:
            with self.subTest(message=message):
                self.assert_error(code, message, *argv)
                self.assert_json_error(code, message, *argv)

        rc, out, err = run("create", "--name", "x")
        self.assertEqual(rc, 2)
        self.assertIn("the following arguments are required: --owner", err)
        self.assertEqual(out, "")

        rc, out, err = run("create", "--name", "x", "--owner", "o", "--label", "nocolon")
        self.assertEqual(rc, 2)
        self.assertIn("expected key=value, got 'nocolon'", err)

        rc, out, err = run("list", "--format", "xml")
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice: 'xml'", err)

        rc, out, err = run(
            "create", "--name", "x", "--owner", "o",
            "--expires-in", "1d", "--expires-at", "2026-06-01T00:00:00Z",
        )
        self.assertEqual(rc, 2)
        self.assertIn("not allowed with argument", err)

        # argparse type errors and ValueError stay on stderr even with --json.
        rc, out, err = run("--json", "create", "--name", "x", "--owner", "o", "--rate-limit", "nope")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid int value: 'nope'", err)

        message = "invalid literal for int() with base 10: 'abc'"
        self.assert_error(1, message, "policy", "set", "max_rate_limit", "abc")
        rc, out, err = run("--json", "policy", "set", "max_rate_limit", "abc")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertEqual(err, f"keyforge: error: {message}\n")

    def test_not_found_and_ambiguous(self):
        for cmd in ("show", "reveal", "rotate", "update", "suspend", "resume", "revoke"):
            argv = [cmd, "missing"]
            if cmd in ("rotate", "revoke"):
                argv.append("--yes")
            with self.subTest(cmd=cmd):
                self.assert_error(3, "key not found: missing", *argv)
                self.assert_json_error(3, "key not found: missing", *argv)

        self.create(name="dup")
        self.create(name="dup")
        message = "ambiguous reference 'dup': key_000000000001, key_000000000002"
        self.assert_error(1, message, "show", "dup")
        self.assert_json_error(1, message, "show", "dup")

    def test_verify_failure_json_and_messages(self):
        created = self.create(
            "--scope", "read:packets",
            "--ip-allow", "10.0.0.0/8",
        )
        secret = created["secret"]
        cases = [
            ("verify_unknown", ["verify", "kf_test_nope12345678"], "unknown key"),
            ("verify_missing_scope",
             ["verify", secret, "--scope", "write:battery", "--ip", "10.1.2.3"],
             "missing scope 'write:battery'"),
            ("verify_ip_missing", ["verify", secret],
             "key has an ip allow list but no client ip was supplied"),
            ("verify_ip_denied", ["verify", secret, "--ip", "192.168.1.1"],
             "ip '192.168.1.1' not in allow list"),
        ]
        for name, argv, reason in cases:
            with self.subTest(reason=reason):
                rc, out, err = run(*argv)
                self.assertEqual(rc, 4)
                self.assertEqual(err, "")
                self.assertEqual(out, f"INVALID: {reason}\n")
                rc, out, err = run("--json", *argv)
                self.assertEqual(rc, 4)
                self.assertEqual(err, "")
                self.assert_snapshot(name, out)
                self.assertEqual(json.loads(out), {"valid": False, "reason": reason})

        run("revoke", created["key"]["id"], "--yes", "--reason", "leak")
        rc, out, err = run("verify", secret)
        self.assertEqual((rc, err, out), (4, "", "INVALID: key is revoked\n"))
        rc, out, err = run("--json", "verify", secret)
        self.assertEqual(rc, 4)
        self.assertEqual(err, "")
        self.assert_snapshot("verify_revoked", out)
        self.assertEqual(json.loads(out)["reason"], "key is revoked")

    def test_policy_violation(self):
        run("policy", "set", "allowed_scopes", "read:*")
        message = "scope 'admin:all' not allowed by policy"
        argv = ["create", "--name", "x", "--owner", "o", "--scope", "admin:all"]
        self.assert_error(5, message, *argv)
        self.assert_json_error(5, message, *argv)

        run("policy", "set", "max_ttl", "30d")
        message = "expiry exceeds policy max_ttl=30d"
        argv = ["create", "--name", "x", "--owner", "o", "--scope", "read:packets", "--expires-in", "90d"]
        self.assert_error(5, message, *argv)
        self.assert_json_error(5, message, *argv)

        run("policy", "set", "allowed_scopes", "none")
        run("policy", "set", "required_labels", "cost_center")
        message = "required label 'cost_center' missing; policy max_ttl=30d requires an expiry"
        argv = ["create", "--name", "x", "--owner", "o"]
        self.assert_error(5, message, *argv)
        self.assert_json_error(5, message, *argv)

    def test_aborted_and_state_conflicts(self):
        created = self.create()
        kid = created["key"]["id"]
        secret = created["secret"]
        message = (
            f"Revoke key {kid} (n1)? This cannot be undone. "
            "- refusing without --yes (non-interactive)"
        )
        self.assert_error(6, message, "revoke", kid)
        self.assert_json_error(6, message, "revoke", kid)
        # The refused revoke does not change the key.
        self.assertEqual(run("verify", secret)[0], 0)

        rc, _, err = run("--json", "revoke", kid, "--yes", "--reason", "leak")
        self.assertEqual(rc, 0, err)
        message = "key is already revoked"
        self.assert_error(1, message, "revoke", kid, "--yes")
        self.assert_json_error(1, message, "revoke", kid, "--yes")
        self.assert_error(1, "cannot reveal a revoked key", "reveal", kid)
        self.assert_json_error(1, "cannot reveal a revoked key", "reveal", kid)
        self.assert_error(1, "cannot update a revoked key", "update", kid, "--add-scope", "read:packets")
        self.assert_json_error(1, "cannot update a revoked key", "update", kid, "--add-scope", "read:packets")
        self.assert_error(1, "cannot rotate key in status revoked", "rotate", kid, "--yes")
        self.assert_json_error(1, "cannot rotate key in status revoked", "rotate", kid, "--yes")

        other = self.create(name="n2")
        oid = other["key"]["id"]
        message = "can only resume a suspended key (status: active)"
        self.assert_error(1, message, "resume", oid)
        self.assert_json_error(1, message, "resume", oid)
        run("suspend", oid, "--reason", "pause")
        message = "can only suspend an active key (status: suspended)"
        self.assert_error(1, message, "suspend", oid)
        self.assert_json_error(1, message, "suspend", oid)
        run("resume", oid)
        self.assertEqual(run("verify", other["secret"])[0], 0)

    def test_import_errors(self):
        bad = os.path.join(self.tmp.name, "bad.json")
        with open(bad, "w") as fh:
            fh.write('{"format": "nope"}')
        message = "not a keyforge export file"
        self.assert_error(2, message, "import", bad)
        self.assert_json_error(2, message, "import", bad)

        missing = os.path.join(self.tmp.name, "missing.json")
        rc, out, err = run("import", missing)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("No such file or directory", err)
        rc, out, err = run("--json", "import", missing)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("No such file or directory", err)

    def test_audit_tamper_exit_7(self):
        self.create()
        st = Store(self.path)
        try:
            st.data["audit"][0]["action"] = "tampered"
            st.save()
        finally:
            st.close()
        rc, out, err = run("audit", "--verify")
        self.assertEqual(rc, 7)
        self.assertEqual(err, "")
        self.assertIn(
            "AUDIT CHAIN BROKEN: event 1(0): content hash mismatch (event modified)",
            out,
        )
        rc, out, err = run("--json", "audit", "--verify")
        self.assertEqual(rc, 7)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "event 1(0): content hash mismatch (event modified)")

    def test_corrupt_store_and_lock(self):
        with open(self.path, "w") as fh:
            fh.write("{")
        rc, out, err = run("list", "--format", "json")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertRegex(
            err,
            r"^keyforge: error: corrupt store .+/store\.json: "
            r"Expecting property name enclosed in double quotes: line 1 column 2 \(char 1\)\n$",
        )
        rc, out, err = run("--json", "list", "--format", "json")
        self.assertEqual(rc, 1)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual(payload["exit_code"], 1)
        self.assertIn("corrupt store", payload["error"])
        self.assertIn("Expecting property name enclosed in double quotes", payload["error"])

        os.remove(self.path)
        holder = Store(self.path, lock=True)
        try:
            os.environ["KEYFORGE_LOCK_TIMEOUT"] = "0"
            rc, out, err = run("list", "--format", "json")
            self.assertEqual(rc, 8)
            self.assertEqual(out, "")
            self.assertIn("is locked by another process (waited 0s)", err)
            self.assertTrue(err.startswith("keyforge: error: "))
            rc, out, err = run("--json", "list", "--format", "json")
            self.assertEqual(rc, 8)
            self.assertEqual(err, "")
            payload = json.loads(out)
            self.assertEqual(payload["exit_code"], 8)
            self.assertIn("is locked by another process (waited 0s)", payload["error"])
        finally:
            holder.close()


if __name__ == "__main__":
    unittest.main()
