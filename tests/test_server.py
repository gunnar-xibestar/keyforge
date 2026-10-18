"""Demo HTTP server: only KeyForge API keys authenticate."""
import io, json, os, tempfile, unittest, urllib.error, urllib.request
from contextlib import redirect_stderr, redirect_stdout

os.environ.setdefault("KEYFORGE_PBKDF2_ITERS", "1000")

from keyforge import cli, server
from keyforge.auth import required_scope


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def http_get(url, authorization=None):
    req = urllib.request.Request(url)
    if authorization is not None:
        req.add_header("Authorization", authorization)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


class _ServerFixture(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.d.name, "s.json")
        self._prev = {k: os.environ.get(k) for k in ("KEYFORGE_STORE", "KEYFORGE_KMS_PROVIDER", "KEYFORGE_KMS_MEMORY_KEY")}
        os.environ["KEYFORGE_STORE"] = self.path
        os.environ["KEYFORGE_KMS_PROVIDER"] = "memory"

    def tearDown(self):
        self.d.cleanup()
        for k, v in self._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class DispatchTests(_ServerFixture):
    def setUp(self):
        super().setUp()
        rc, out, _ = run("--json", "create", "--name", "demo", "--owner", "alice",
                         "--scope", "read:packets")
        self.assertEqual(rc, 0, out)
        self.secret = json.loads(out)["secret"]
        rc, out, _ = run("--json", "create", "--name", "noscope", "--owner", "bob",
                         "--scope", "write:battery")
        self.assertEqual(rc, 0, out)
        self.other = json.loads(out)["secret"]

    def test_health_open(self):
        status, body = server.dispatch(self.path, "GET", "/health", None, "127.0.0.1")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_whoami_requires_bearer(self):
        status, body = server.dispatch(self.path, "GET", "/whoami", None, "127.0.0.1")
        self.assertEqual(status, 401)
        status, body = server.dispatch(self.path, "GET", "/whoami", "Basic x", "127.0.0.1")
        self.assertEqual(status, 401)

    def test_whoami_accepts_key(self):
        status, body = server.dispatch(
            self.path, "GET", "/whoami", f"Bearer {self.secret}", "127.0.0.1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["key"]["name"], "demo")
        self.assertNotIn("secret", body["key"])
        self.assertNotIn("hash", body["key"])

    def test_packets_requires_scope(self):
        status, body = server.dispatch(
            self.path, "GET", "/packets", f"Bearer {self.other}", "127.0.0.1")
        self.assertEqual(status, 403)
        self.assertIn("missing scope", body["error"])
        status, body = server.dispatch(
            self.path, "GET", "/packets", f"Bearer {self.secret}", "127.0.0.1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["required_scope"], "read:packets")

    def test_admin_rejects_key_without_write_packets(self):
        status, body = server.dispatch(
            self.path, "GET", "/admin", f"Bearer {self.secret}", "127.0.0.1")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "missing scope 'write:packets'")

    def test_keys_post_rejects_demo_key_without_keys_write(self):
        status, body = server.dispatch(
            self.path, "POST", "/keys", None, "127.0.0.1")
        self.assertEqual(status, 401)
        status, body = server.dispatch(
            self.path, "POST", "/keys", f"Bearer {self.secret}", "127.0.0.1")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "missing scope 'keys:write'")

    def test_bad_secret(self):
        status, body = server.dispatch(
            self.path, "GET", "/whoami", "Bearer kf_test_nope1234567890123456789012", "127.0.0.1")
        self.assertEqual(status, 403)

    def test_unknown_route_and_method(self):
        self.assertEqual(server.dispatch(self.path, "GET", "/nope", None, "127.0.0.1")[0], 404)
        self.assertEqual(server.dispatch(self.path, "POST", "/health", None, "127.0.0.1")[0], 405)
        self.assertEqual(server.dispatch(self.path, "GET", "/keys", f"Bearer {self.secret}", "127.0.0.1")[0], 405)


class LiveServerTests(_ServerFixture):
    def setUp(self):
        super().setUp()
        rc, out, _ = run("--json", "create", "--name", "live", "--owner", "alice",
                         "--scope", "read:packets")
        self.assertEqual(rc, 0, out)
        self.secret = json.loads(out)["secret"]

    def test_http_roundtrip(self):
        with server.RunningServer(self.path) as srv:
            status, body = http_get(f"{srv.base_url}/health")
            self.assertEqual(status, 200)
            status, body = http_get(f"{srv.base_url}/whoami",
                                    f"Bearer {self.secret}")
            self.assertEqual(status, 200)
            self.assertEqual(body["key"]["owner"], "alice")
            status, body = http_get(f"{srv.base_url}/packets",
                                    f"Bearer {self.secret}")
            self.assertEqual(status, 200)
            status, _ = http_get(f"{srv.base_url}/whoami")
            self.assertEqual(status, 401)


class ServeCliTests(unittest.TestCase):
    def test_required_scope_is_verify(self):
        args = type("A", (), {"cmd": "serve"})()
        self.assertEqual(required_scope(args), "keys:verify")

    def test_help_lists_serve(self):
        text = cli.build_parser().format_help()
        self.assertIn("serve", text)
        self.assertIn("demo HTTP server", text)
