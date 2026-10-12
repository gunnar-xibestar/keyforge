import copy, io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import cli, service as svc
from keyforge.errors import ValidationError, PolicyViolation, KeyForgeError, VerifyFailed
from keyforge.store import Store

def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()

class TestImportValidation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.src = Store(os.path.join(self.d.name, "src.json"))
        self.k, self.secret = svc.create(self.src, name="n", owner="o", scopes=["read:packets"])
        self.src.save()
        self.export = svc.export(self.src)
        self.dst = Store(os.path.join(self.d.name, "dst.json"))
    def tearDown(self): self.d.cleanup()

    def bad(self, mutate, exc=ValidationError):
        data = copy.deepcopy(self.export); mutate(data["keys"][0])
        with self.assertRaises(exc):
            svc.import_(self.dst, data)
        self.assertEqual(self.dst.data["keys"], {})

    def test_valid_import(self):
        res = svc.import_(self.dst, self.export)
        self.assertEqual(res["added"], [self.k.id])
        self.assertEqual(svc.verify(self.dst, self.secret).id, self.k.id)

    def test_schema_rejections(self):
        self.bad(lambda r: r.pop("hash"))
        self.bad(lambda r: r.update(evil=1))
        self.bad(lambda r: r.update(scopes="admin:all"))
        self.bad(lambda r: r.update(scopes=["NOT VALID"]))
        self.bad(lambda r: r.update(ip_allow=["999.0.0.0/8"]))
        self.bad(lambda r: r.update(env="prod"))
        self.bad(lambda r: r.update(status="superuser"))
        self.bad(lambda r: r.update(id="../x"))
        self.bad(lambda r: r["hash"].update(iterations="1"))
        self.bad(lambda r: r["hash"].update(hash="zz"))
        self.bad(lambda r: r.update(expires_at="not-a-date"))
        self.bad(lambda r: r.update(rate_limit=-5))
        self.bad(lambda r: r.update(prefix="kf_live_abcdefgh"))

    def test_bad_record_aborts_whole_import(self):
        data = copy.deepcopy(self.export)
        k2, _ = svc.create(self.src, name="n2", owner="o"); data["keys"].append(k2.to_dict())
        data["keys"].append({"id": "junk"})
        with self.assertRaises(ValidationError): svc.import_(self.dst, data)
        self.assertEqual(self.dst.data["keys"], {})

    def test_policy_enforced(self):
        self.dst.policy["allowed_scopes"] = ["write:*"]
        with self.assertRaises(PolicyViolation): svc.import_(self.dst, self.export)
        self.dst.policy.clear(); self.dst.policy["max_ttl"] = "30d"
        with self.assertRaises(PolicyViolation): svc.import_(self.dst, self.export)

    def test_overwrite_cannot_resurrect_revoked(self):
        svc.import_(self.dst, self.export)
        svc.set_status(self.dst, self.k.id, "revoked", reason="leak")
        with self.assertRaises(KeyForgeError): svc.import_(self.dst, self.export, overwrite=True)
        self.assertEqual(self.dst.get(self.k.id).status, "revoked")
        res = svc.import_(self.dst, self.export, overwrite=True, allow_unrevoke=True)
        self.assertEqual(res["overwritten"], [self.k.id])
        self.assertEqual(self.dst.get(self.k.id).status, "active")
        self.assertEqual(self.dst.audit_log[-1]["details"]["unrevoked"], [self.k.id])

    def test_cli_flag(self):
        f = os.path.join(self.d.name, "e.json"); 
        with open(f, "w") as fh: json.dump(self.export, fh)
        p = self.dst.path
        self.assertEqual(run("--store", str(p), "import", f)[0], 0)
        self.assertEqual(run("--store", str(p), "revoke", self.k.id, "--yes")[0], 0)
        self.assertEqual(run("--store", str(p), "import", f, "--overwrite")[0], 1)
        self.assertEqual(run("--store", str(p), "verify", self.secret)[0], 4)
        self.assertEqual(run("--store", str(p), "import", f, "--overwrite", "--allow-unrevoke")[0], 0)
        self.assertEqual(run("--store", str(p), "verify", self.secret)[0], 0)

class TestImportFollowups(TestImportValidation):
    def test_hash_bounds(self):
        self.bad(lambda r: r["hash"].update(iterations=10))
        self.bad(lambda r: r["hash"].update(iterations=10**9))
        self.bad(lambda r: r["hash"].update(salt="ab" * 8))        # 16 hex chars, too short
        self.bad(lambda r: r["hash"].update(salt="a" * 33))        # odd length
        self.bad(lambda r: r["hash"].update(salt="g" * 32))
        self.bad(lambda r: r["hash"].update(hash="A" * 64))

    def test_grace_cap(self):
        from datetime import timedelta
        from keyforge.models import now, iso
        self.bad(lambda r: r.update(status="rotated", grace_until=iso(now() + timedelta(days=365))))

    def _revoke_and_purge_in_dst(self):
        svc.import_(self.dst, self.export)
        svc.set_status(self.dst, self.k.id, "revoked", reason="leak")
        rec = self.dst.data["keys"][self.k.id]; rec["revoked_at"] = "2020-01-01T00:00:00Z"
        svc.purge(self.dst, include_revoked=True)
        self.assertNotIn(self.k.id, self.dst.data["keys"])

    def test_revoked_hash_survives_purge_and_blocks_reimport(self):
        self._revoke_and_purge_in_dst()
        self.assertEqual(self.dst.revoked_hashes[0]["id"], self.k.id)
        with self.assertRaises(KeyForgeError): svc.import_(self.dst, self.export)
        res = svc.import_(self.dst, self.export, allow_unrevoke=True)
        self.assertEqual(res["added"], [self.k.id])
        self.assertEqual(self.dst.audit_log[-1]["details"]["unrevoked"], [self.k.id])

    def test_reissued_under_new_id_blocked(self):
        svc.import_(self.dst, self.export)
        svc.set_status(self.dst, self.k.id, "revoked")
        data = copy.deepcopy(self.export); data["keys"][0]["id"] = "key_aaaaaaaaaaaa"
        with self.assertRaises(KeyForgeError): svc.import_(self.dst, data)

    def test_collision_with_live_key_blocked(self):
        svc.import_(self.dst, self.export)
        data = copy.deepcopy(self.export); data["keys"][0]["id"] = "key_bbbbbbbbbbbb"
        with self.assertRaises(KeyForgeError): svc.import_(self.dst, data)

    def test_revoked_incoming_record_allowed_and_remembered(self):
        data = copy.deepcopy(self.export)
        data["keys"][0].update(status="revoked", revoked_at="2026-01-01T00:00:00Z")
        svc.import_(self.dst, data)
        self.assertEqual(len(self.dst.revoked_hashes), 1)

    def test_overwrite_audit_flags_credential_change(self):
        svc.import_(self.dst, self.export)
        data = copy.deepcopy(self.export); data["keys"][0]["hash"]["salt"] = "cd" * 16
        data["keys"][0]["description"] = "x"
        svc.import_(self.dst, data, overwrite=True)
        det = self.dst.audit_log[-1]["details"]
        self.assertEqual(det["overwritten_ids"], [self.k.id]); self.assertEqual(det["credential_changed_ids"], [self.k.id])
        svc.import_(self.dst, data, overwrite=True)
        self.assertNotIn("credential_changed_ids", self.dst.audit_log[-1]["details"])

class TestImportRound3(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.st = Store(os.path.join(self.d.name, "s.json"))
        self.k, self.secret = svc.create(self.st, name="n", owner="o")
        self.leak = copy.deepcopy(self.k.to_dict())
        svc.set_status(self.st, self.k.id, "revoked", reason="leak")
    def tearDown(self): self.d.cleanup()
    def data(self, **upd):
        r = copy.deepcopy(self.leak); r.update(upd)
        return {"format": "keyforge-export", "version": 1, "keys": [r]}

    def test_repro_expired_leak_under_new_id_blocked(self):
        from datetime import timedelta
        from keyforge.models import now, iso
        d = self.data(id="key_cccccccccccc", expires_at=iso(now() - timedelta(days=1)))
        with self.assertRaises(KeyForgeError): svc.import_(self.st, d)
        self.assertNotIn("key_cccccccccccc", self.st.data["keys"])

    def test_non_usable_statuses_checked(self):
        for upd in ({"status": "revoked", "revoked_at": "2026-01-01T00:00:00Z"},
                    {"status": "rotated", "grace_until": "2026-01-01T00:00:00Z"}):
            with self.assertRaises(KeyForgeError): svc.import_(self.st, self.data(id="key_dddddddddddd", **upd))

    def test_same_id_revoked_reimport_ok(self):
        d = self.data(status="revoked", revoked_at="2026-01-01T00:00:00Z")
        svc.import_(self.st, d, overwrite=True)

    def test_update_cannot_revive_retired_credential(self):
        from datetime import timedelta
        from keyforge.models import now, iso
        # repro: forced in under a new id, expired, then update --no-expiry
        d = self.data(id="key_eeeeeeeeeeee", expires_at=iso(now() - timedelta(days=1)))
        svc.import_(self.st, d, allow_unrevoke=True)
        with self.assertRaises(KeyForgeError): svc.update(self.st, "key_eeeeeeeeeeee", clear_expiry=True)
        with self.assertRaises(KeyForgeError):
            svc.update(self.st, "key_eeeeeeeeeeee", expires_at=now() + timedelta(days=5))
        svc.update(self.st, "key_eeeeeeeeeeee", description="ok")  # non-reviving updates allowed
        with self.assertRaises(VerifyFailed): svc.verify(self.st, self.secret)

    def test_resume_blocked_for_retired_credential(self):
        d = self.data(id="key_ffffffffffff", status="suspended")
        svc.import_(self.st, d, allow_unrevoke=True)
        with self.assertRaises(KeyForgeError): svc.set_status(self.st, "key_ffffffffffff", "active")

    def test_normal_update_and_resume_unaffected(self):
        from datetime import timedelta
        from keyforge.models import now
        k, _ = svc.create(self.st, name="m", owner="o")
        svc.update(self.st, k.id, expires_at=now() + timedelta(days=5)); svc.update(self.st, k.id, clear_expiry=True)
        svc.set_status(self.st, k.id, "suspended"); svc.set_status(self.st, k.id, "active")

    def test_rotated_remembered_at_purge(self):
        k, _ = svc.create(self.st, name="r", owner="o")
        old, new, _, _ = svc.rotate(self.st, k.id, grace_period="0s")
        rec = self.st.data["keys"][k.id]; rec["grace_until"] = "2020-01-01T00:00:00Z"
        svc.purge(self.st)
        self.assertNotIn(k.id, self.st.data["keys"])
        kinds = {r["id"]: r["kind"] for r in self.st.revoked_hashes}
        self.assertEqual(kinds[k.id], "rotated")

if __name__ == "__main__":
    unittest.main()
