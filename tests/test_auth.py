"""Auth0 device login, token dieting, and command gates. The token endpoint is mocked."""
import base64, json, os, stat, tempfile, time, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import io

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from keyforge import auth, cli
from keyforge.auth import TokenExpired
from keyforge.errors import AuthError, Unauthorized

DOMAIN = "tenant.example.test"
AUDIENCE = "https://keyforge.example/api"
CLIENT = "client-test"
SECRET = "test-client-secret"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class _Resp:
    def __init__(self, payload):
        self._raw = json.dumps(payload).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, jwks):
        self.jwks = jwks
        self.token_body = {}
        self.calls = []

    def __call__(self, req, timeout=30):
        self.calls.append((req.full_url, req.data))
        if req.full_url.endswith("/.well-known/jwks.json"):
            return _Resp(self.jwks)
        if req.full_url.endswith("/oauth/device/code"):
            return _Resp({"device_code": "dev-code", "user_code": "ABCD-EFGH",
                          "verification_uri": "https://example.test/activate",
                          "expires_in": 300, "interval": 1})
        if req.full_url.endswith("/oauth/token"):
            return _Resp(self.token_body)
        raise AssertionError(req.full_url)


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()

        def enc(value):
            return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))

        cls.jwks = {"keys": [{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
                              "n": enc(numbers.n), "e": enc(numbers.e)}]}
        cls._key = key

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.token_file = os.path.join(self.d.name, "tokens.json")
        self.store = os.path.join(self.d.name, "store.json")
        self._saved = {k: os.environ.get(k) for k in (
            "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE", "AUTH0_CLIENT_SECRET",
            "AUTH0_SCOPES", "KEYFORGE_TOKEN_FILE", "KEYFORGE_STORE",
            "KEYFORGE_ACTOR", "KEYFORGE_MAX_TOKEN_TTL")}
        os.environ["AUTH0_DOMAIN"] = DOMAIN
        os.environ["AUTH0_CLIENT_ID"] = CLIENT
        os.environ["AUTH0_AUDIENCE"] = AUDIENCE
        os.environ["AUTH0_CLIENT_SECRET"] = SECRET
        os.environ["KEYFORGE_TOKEN_FILE"] = self.token_file
        os.environ["KEYFORGE_STORE"] = self.store
        os.environ.pop("AUTH0_SCOPES", None)
        os.environ.pop("KEYFORGE_ACTOR", None)
        self.opener = _Opener(self.jwks)
        auth._opener = self.opener
        auth.clear_jwks_cache()

    def tearDown(self):
        auth._opener = None
        auth.clear_jwks_cache()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def sign(self, payload):
        header = {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
        h = _b64(json.dumps(header, separators=(",", ":")).encode())
        p = _b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64(sig)}"

    def payload(self, **extra):
        now = int(time.time())
        body = {"iss": f"https://{DOMAIN}/", "sub": "auth0|alice", "aud": AUDIENCE,
                "iat": now, "exp": now + 600, "azp": CLIENT,
                "scope": "keys:read keys:write keys:verify reveal:secret",
                "gty": "urn:ietf:params:oauth:grant-type:device_code"}
        body.update(extra)
        return body

    def _login(self, token, **token_fields):
        self.opener.token_body = {"access_token": token, "refresh_token": "refresh-opaque",
                                  "expires_in": 600, "id_token": "profile." + ("x" * 1500),
                                  "token_type": "Bearer", **token_fields}
        return auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)

    def test_password_login_sends_username_then_uses_token(self):
        token = self.sign(self.payload(gty="password"))
        self.opener.token_body = {"access_token": token, "expires_in": 600, "token_type": "Bearer"}
        principal = auth.password_login("ada@example.test", "s3cret-value")
        self.assertEqual(principal.sub, "auth0|alice")
        url, data = self.opener.calls[-2] if self.opener.calls[-1][0].endswith("jwks.json") else self.opener.calls[-1]
        self.assertTrue(url.endswith("/oauth/token"))
        self.assertIn(b"ada%40example.test", data)
        self.assertIn(b"password-realm", data)
        self.assertIn(b"s3cret-value", data)
        self.opener.token_body = {"error": "unauthorized_client",
                                  "error_description": "Grant type 'http://auth0.com/oauth/grant-type/password-realm' not allowed for the client."}
        with self.assertRaises(AuthError) as denied:
            auth.password_login("ada@example.test", "s3cret-value")
        self.assertIn("Grant Types → Password", str(denied.exception))
        self.assertNotIn("s3cret-value", str(denied.exception))
        self.opener.token_body = {"error": "invalid_grant", "error_description": "wrong s3cret-value"}
        with self.assertRaises(AuthError) as cm:
            auth.password_login("ada@example.test", "s3cret-value")
        self.assertNotIn("s3cret-value", str(cm.exception))
        self.assertIn("[redacted]", str(cm.exception))

    def test_login_stores_lean_token_and_drops_id_token(self):
        token = self.sign(self.payload())
        principal = self._login(token)
        self.assertEqual(principal.sub, "auth0|alice")
        self.assertIn("reveal:secret", principal.scopes)
        self.assertLess(len(token.encode()), 2048)
        raw = Path(self.token_file).read_text()
        stored = json.loads(raw)
        self.assertEqual(stored["access_token"], token)
        self.assertEqual(stored["refresh_token"], "refresh-opaque")
        self.assertNotIn("id_token", stored)
        self.assertNotIn("permissions", raw)
        self.assertNotIn(SECRET, raw)
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)
        token_calls = [data for url, data in self.opener.calls if url.endswith("/oauth/token")]
        self.assertTrue(token_calls and SECRET.encode() in token_calls[0])
        rc, out, err = _run("--json", "auth", "status")
        self.assertEqual(rc, 0, err)
        status = json.loads(out)
        self.assertEqual(status["sub"], "auth0|alice")
        self.assertEqual(status["missing_scopes"], [])  # offline_access is not a command scope
        self.assertIn("keys:write", status["requested_scopes"])
        self.assertIn("offline_access", status["requested_scopes"])
        self.assertNotIn("access_token", status)
        self.assertNotIn(token, out)

    def test_status_reports_scopes_auth0_withheld(self):
        """Auth0 often returns only keys:read + offline_access when write/reveal are not granted."""
        token = self.sign(self.payload(scope="keys:read offline_access"))
        self._login(token)
        rc, out, err = _run("--json", "auth", "status")
        self.assertEqual(rc, 0, err)
        status = json.loads(out)
        self.assertEqual(status["scopes"], ["keys:read", "offline_access"])
        self.assertEqual(status["missing_scopes"],
                         ["keys:verify", "keys:write", "reveal:secret"])
        rc, out, err = _run("auth", "status")
        self.assertEqual(rc, 0, err)
        self.assertIn("missing_scopes:", out)
        self.assertIn("keys:write", out)
        self.assertIn("Auth0 granted fewer scopes", out)
        self.assertIn("If Enable RBAC is on", out)
        self.assertIn("trailing spaces", out)

    def test_overstuffed_and_expired_tokens_are_rejected(self):
        fat = self.sign(self.payload(permissions=["read:packets", "write:battery", "admin:all"]))
        with self.assertRaises(AuthError) as cm:
            self._login(fat)
        self.assertIn("overstuffed", str(cm.exception))
        self.assertFalse(os.path.exists(self.token_file))
        self.assertTrue(any(url.endswith("/.well-known/jwks.json") for url, _ in self.opener.calls))

        now = int(time.time())
        long_lived = self.sign(self.payload(iat=now, exp=now + 7200))
        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(long_lived)
        self.assertIn("lifetime", str(cm.exception))

        expired = self.sign(self.payload(iat=now - 900, exp=now - 120))
        with self.assertRaises(TokenExpired):
            auth.validate_access_token(expired)

        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token("x" * 3000)
        self.assertIn("overstuffed", str(cm.exception))

        os.environ["KEYFORGE_MAX_TOKEN_TTL"] = "99999"
        with self.assertRaises(AuthError):
            auth.validate_access_token(self.sign(self.payload()))

    def test_command_requires_principal_and_bad_scope_exits_4(self):
        rc, out, err = _run("--json", "list")
        self.assertEqual(rc, 1, err)
        self.assertIn("not logged in", err + out)

        self._login(self.sign(self.payload(scope="keys:read")))
        rc, out, _ = _run("--json", "list")
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out), [])

        # Create the key while auth is disabled, then require a principal to reveal it.
        for name in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE"):
            os.environ.pop(name)
        rc, out, err = _run("--json", "create", "--name", "n", "--owner", "alice")
        self.assertEqual(rc, 0, err)
        created = json.loads(out)
        os.environ["AUTH0_DOMAIN"] = DOMAIN
        os.environ["AUTH0_CLIENT_ID"] = CLIENT
        os.environ["AUTH0_AUDIENCE"] = AUDIENCE

        rc, out, err = _run("--json", "reveal", created["key"]["id"])
        self.assertEqual(rc, 4, err)
        self.assertIn("reveal:secret", err + out)
        self.assertNotIn(created["secret"], err + out)

        self._login(self.sign(self.payload()))
        rc, out, err = _run("--json", "reveal", created["key"]["id"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["secret"], created["secret"])
        self.assertNotIn(created["secret"], Path(self.store).read_text())

        rc, out, _ = _run("--json", "audit", "--action", "create")
        self.assertEqual(rc, 0)
        create_ev = json.loads(out)[0]
        self.assertNotEqual(create_ev["actor"], "auth0|alice")  # created while auth was off
        rc, out, _ = _run("--json", "audit", "--action", "reveal")
        self.assertEqual(json.loads(out)[0]["actor"], "auth0|alice")
        self.assertNotIn("KEYFORGE_ACTOR", os.environ)

    def test_empty_scope_stays_empty_and_permissions_claim_is_rejected(self):
        """Authorization uses the token scope claim only; permissions[] is token-diet forbidden."""
        principal = self._login(self.sign(self.payload(scope="")))
        self.assertEqual(principal.scopes, frozenset())
        with self.assertRaises(AuthError) as cm:
            self._login(self.sign(self.payload(scope="", permissions=["reveal:secret"])))
        self.assertIn("permissions", str(cm.exception))

    def test_partial_config_and_disabled_status(self):
        os.environ.pop("AUTH0_CLIENT_ID")
        os.environ.pop("AUTH0_AUDIENCE")
        rc, _, err = _run("list")
        self.assertEqual(rc, 1)
        self.assertIn("partially configured", err)
        os.environ.pop("AUTH0_DOMAIN")
        rc, out, err = _run("--json", "auth", "status")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out), {"enabled": False})

    def test_from_file_and_refresh(self):
        token = self.sign(self.payload(scope="keys:read"))
        src = os.path.join(self.d.name, "response.json")
        Path(src).write_text(json.dumps({
            "access_token": token, "refresh_token": "refresh-1", "id_token": "drop-me",
            "client_secret": SECRET,
        }))
        rc, out, err = _run("--json", "auth", "login", "--from-file", src)
        self.assertEqual(rc, 0, err)
        stored = json.loads(Path(self.token_file).read_text())
        self.assertNotIn("id_token", stored)
        self.assertNotIn("client_secret", stored)
        self.assertNotIn(SECRET, Path(self.token_file).read_text())
        self.assertNotIn(token, out)

        now = int(time.time())
        expired = self.sign(self.payload(scope="keys:read", iat=now - 900, exp=now - 120))
        fresh = self.sign(self.payload(scope="keys:verify"))
        stored["access_token"] = expired
        Path(self.token_file).write_text(json.dumps(stored))
        os.chmod(self.token_file, 0o600)
        self.opener.token_body = {"access_token": fresh, "expires_in": 600}
        principal = auth.load_principal()
        self.assertIn("keys:verify", principal.scopes)
        rewritten = json.loads(Path(self.token_file).read_text())
        self.assertEqual(rewritten["access_token"], fresh)
        self.assertEqual(rewritten["refresh_token"], "refresh-1")

    def test_bad_signature_rejected(self):
        token = self.sign(self.payload())
        broken = token[:-2] + ("a" if token[-2] != "a" else "b") + token[-1]
        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(broken)
        self.assertIn("signature", str(cm.exception))

    def test_missing_scope_is_unauthorized(self):
        self._login(self.sign(self.payload(scope="keys:read")))
        with self.assertRaises(Unauthorized):
            auth.authorize(argparse_namespace("reveal"))


class _NS:
    def __init__(self, cmd, **extra):
        self.cmd = cmd
        for k, v in extra.items():
            setattr(self, k, v)


def argparse_namespace(cmd, **extra):
    return _NS(cmd, **extra)


if __name__ == "__main__":
    unittest.main()
