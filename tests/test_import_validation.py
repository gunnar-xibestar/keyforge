import copy, io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr
os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"
from keyforge import cli, service as svc
from keyforge.errors import ValidationError, PolicyViolation, KeyForgeError
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

if __name__ == "__main__":
    unittest.main()
