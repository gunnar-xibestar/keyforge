"""Auth0 device login, token dieting, and command gates.

The token endpoint is mocked through ``auth._opener``. ``urllib.request.urlopen``
is replaced for the duration of these tests so a missed stub cannot touch the network.
"""
import base64, json, os, stat, tempfile, time, unittest, urllib.error, urllib.parse, urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
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


class _RawResp:
    def __init__(self, raw):
        self._raw = raw

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _BrokenBody:
    """HTTP error body whose ``read`` fails. ``close`` keeps HTTPError's destructor quiet."""

    def read(self, *_args, **_kwargs):
        raise OSError("connection reset")

    def close(self):
        return None


def _block_network(*_args, **_kwargs):
    raise AssertionError("urllib.request.urlopen was called; auth tests must not use the network")


def _http_error(code, body, url="https://tenant.example.test/oauth/token"):
    if body is None:
        fp = _BrokenBody()
    elif isinstance(body, bytes):
        fp = io.BytesIO(body)
    else:
        fp = io.BytesIO(json.dumps(body).encode())
    return urllib.error.HTTPError(url, code, "error", None, fp)


def _realize(action):
    if isinstance(action, BaseException):
        raise action
    if isinstance(action, bytes):
        return _RawResp(action)
    return _Resp(action)


class _Opener:
    def __init__(self, jwks):
        self.jwks = jwks
        self.token_body = {}
        self.calls = []
        self.timeouts = []
        # Non-JWKS responses consumed in order. JWKS stays on ``jwks`` unless ``jwks_action`` is set.
        self.queue = []
        self.jwks_action = None

    def __call__(self, req, timeout=30):
        self.calls.append((req.full_url, req.data))
        self.timeouts.append(timeout)
        if req.full_url.endswith("/.well-known/jwks.json"):
            if self.jwks_action is not None:
                action = self.jwks_action
                self.jwks_action = None
                return _realize(action)
            return _Resp(self.jwks)
        if self.queue:
            return _realize(self.queue.pop(0))
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
            "AUTH0_SCOPES", "AUTH0_REALM", "KEYFORGE_TOKEN_FILE", "KEYFORGE_STORE",
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
        self._real_urlopen = urllib.request.urlopen
        urllib.request.urlopen = _block_network

    def tearDown(self):
        urlopen = getattr(self, "_real_urlopen", None)
        if urlopen is not None:
            urllib.request.urlopen = urlopen
        auth._opener = None
        auth.clear_jwks_cache()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.d.cleanup()

    def sign(self, payload, *, kid="test-key"):
        header = {"alg": "RS256", "typ": "JWT", "kid": kid}
        h = _b64(json.dumps(header, separators=(",", ":")).encode())
        p = _b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64(sig)}"

    def craft(self, header, payload=None, sig="AAAA"):
        """Build a token without a valid signature. Header checks happen before verify."""
        if isinstance(header, bytes):
            h = _b64(header)
        else:
            h = _b64(json.dumps(header, separators=(",", ":")).encode())
        if payload is None:
            payload = self.payload()
        if isinstance(payload, bytes):
            p = _b64(payload)
        else:
            p = _b64(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{sig}"

    def write_token(self, data):
        Path(self.token_file).write_text(json.dumps(data))
        os.chmod(self.token_file, 0o600)

    def assert_no_temp_tokens(self, *needles):
        for path in Path(self.d.name).rglob("*"):
            self.assertFalse(path.name.startswith(".kf-auth-"), path)
            if path.is_file() and needles:
                text = path.read_text(errors="ignore")
                for needle in needles:
                    self.assertNotIn(needle, text, path)

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

    def test_gty_accepts_auth0_string_and_array_shapes(self):
        """Auth0 may emit ``gty`` as a short string or a short grant-type array."""
        for gty in (
            "password",
            "client-credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            ["password"],
            ["password", "refresh_token"],
            ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
        ):
            with self.subTest(gty=gty):
                principal = auth.validate_access_token(self.sign(self.payload(gty=gty)))
                self.assertEqual(principal.sub, "auth0|alice")

        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload(gty="x" * 81)))
        self.assertIn("claim gty is too large", str(cm.exception))

        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload(gty=["password", "x" * 81])))
        self.assertIn("claim gty is too large", str(cm.exception))

        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload(
                gty=["a", "b", "c", "d", "e"])))
        self.assertIn("claim gty is too large", str(cm.exception))

        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload(gty={"grant": "password"})))
        self.assertIn("claim gty is too large", str(cm.exception))

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

    def test_config_and_ttl_fail_closed(self):
        os.environ["KEYFORGE_MAX_TOKEN_TTL"] = "abc"
        with self.assertRaises(AuthError) as cm:
            auth.max_token_ttl()
        self.assertIn("integer", str(cm.exception))
        for raw in ("59", "0", "3601", "-5"):
            with self.subTest(raw=raw):
                os.environ["KEYFORGE_MAX_TOKEN_TTL"] = raw
                with self.assertRaises(AuthError) as cm:
                    auth.max_token_ttl()
                self.assertIn("between 60 and 3600", str(cm.exception))
        now = 1_700_000_000
        os.environ["KEYFORGE_MAX_TOKEN_TTL"] = "60"
        principal = auth.validate_access_token(
            self.sign(self.payload(iat=now, exp=now + 60)), now=now)
        self.assertEqual(principal.exp, now + 60)
        os.environ["KEYFORGE_MAX_TOKEN_TTL"] = "3600"
        auth.validate_access_token(self.sign(self.payload(iat=now, exp=now + 3600)), now=now)

        for domain in ("https://tenant.example.test", "tenant.example.test/path",
                       "localhost", "not a host", "   "):
            with self.subTest(domain=domain):
                os.environ["AUTH0_DOMAIN"] = domain
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(self.sign(self.payload()))
                self.assertIn("hostname", str(cm.exception))
        os.environ["AUTH0_DOMAIN"] = DOMAIN
        for client_id in ("", "   ", "x" * 129):
            with self.subTest(client_id=len(client_id)):
                os.environ["AUTH0_CLIENT_ID"] = client_id
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token("not-a-jwt")
                self.assertIn("AUTH0_CLIENT_ID", str(cm.exception))
        os.environ["AUTH0_CLIENT_ID"] = CLIENT
        for audience in ("", "  ", "a" * 201):
            with self.subTest(audience=len(audience)):
                os.environ["AUTH0_AUDIENCE"] = audience
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token("not-a-jwt")
                self.assertIn("AUTH0_AUDIENCE", str(cm.exception))
        os.environ["AUTH0_AUDIENCE"] = AUDIENCE

        for name in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE"):
            os.environ.pop(name)
        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload()))
        self.assertIn("not configured", str(cm.exception))

    def test_http_errors_timeouts_and_bad_bodies_leak_no_secrets(self):
        self.assertEqual(self.opener.timeouts, [])
        # Device-code failures surface `error` only. Timeouts keep the exception type, not the URL.
        cases = (
            (_http_error(401, {"error": "invalid_client",
                               "error_description": f"client {SECRET} rejected"}),
             "invalid_client"),
            (_http_error(403, {"error_description": SECRET}), "http 403"),
            (_http_error(502, b"[1, 2]"), "http 502"),
            (_http_error(502, b"\xffnot-json"), "http 502"),
            (_http_error(429, {}), "http 429"),
            (_http_error(504, None), "http 504"),
            (urllib.error.URLError(TimeoutError("timed out talking to tenant.example.test")),
             "URLError"),
            (TimeoutError(f"slow {SECRET}"), "TimeoutError"),
        )
        for action, needle in cases:
            with self.subTest(needle=needle):
                self.opener.queue = [action]
                before = len(self.opener.calls)
                with self.assertRaises(AuthError) as cm:
                    auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
                message = str(cm.exception)
                self.assertIn(needle, message)
                self.assertNotIn(SECRET, message)
                self.assertNotIn("tenant.example.test", message)
                self.assertNotIn("timed out talking", message)
                self.assertGreater(len(self.opener.calls), before)
                self.assertTrue(all(timeout == 30 for timeout in self.opener.timeouts))
                self.assertFalse(os.path.exists(self.token_file))
                self.assert_no_temp_tokens(SECRET)

        shapes = (
            (b"<html>nope</html>", "not JSON"),
            (b"[1]", "not a JSON object"),
            (b"{" + b"x" * 65536, "overstuffed"),
        )
        for raw, needle in shapes:
            with self.subTest(needle=needle):
                auth.clear_jwks_cache()
                self.opener.jwks_action = raw
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(self.sign(self.payload()))
                self.assertIn(needle, str(cm.exception))
                self.assertNotIn(SECRET, str(cm.exception))

        # Token-poll errors include error_description. The client secret is replaced, then cut at 300.
        auth.clear_jwks_cache()
        self.opener.jwks_action = None
        padded = ("a" * 250) + SECRET + ("b" * 80)
        self.opener.queue = [
            {"device_code": "dev-code", "user_code": "ABCD-EFGH",
             "verification_uri": "https://example.test/activate", "expires_in": 30, "interval": 1},
            _http_error(400, {"error": "invalid_request", "error_description": padded}),
        ]
        with self.assertRaises(AuthError) as cm:
            auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        message = str(cm.exception)
        self.assertIn("invalid_request", message)
        self.assertNotIn(SECRET, message)
        self.assertIn("[redacted]", message)
        self.assertLessEqual(len(message), 400)
        self.assertFalse(os.path.exists(self.token_file))

    def test_jwks_rejects_bad_keys_and_keeps_a_withdrawn_key_until_ttl(self):
        token = self.sign(self.payload())
        auth.validate_access_token(token)
        jwks_calls = [url for url, _ in self.opener.calls if url.endswith("/.well-known/jwks.json")]
        self.assertEqual(len(jwks_calls), 1)
        # Replacing the published set does not bypass the 300s cache, so a withdrawn key still verifies.
        self.opener.jwks = {"keys": []}
        again = auth.validate_access_token(token)
        self.assertEqual(again.sub, "auth0|alice")
        self.assertEqual(sum(url.endswith("/.well-known/jwks.json") for url, _ in self.opener.calls), 1)

        # An unknown kid also does not force a refresh.
        self.opener.jwks = {"keys": [dict(self.jwks["keys"][0], kid="rotated-key")]}
        unknown = self.sign(self.payload(), kid="rotated-key")
        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(unknown)
        self.assertIn("not found", str(cm.exception))
        auth.clear_jwks_cache()
        self.assertEqual(auth.validate_access_token(unknown).sub, "auth0|alice")

        bad_sets = (
            ({"keys": []}, "no keys"),
            ({"keys": {}}, "no keys"),
            ({}, "no keys"),
            ({"keys": [{"kty": "oct", "kid": "test-key", "alg": "HS256"}]}, "not RS256"),
            ({"keys": [{"kty": "RSA", "kid": "test-key", "alg": "RS256", "e": "AQAB"}]}, "malformed"),
            ({"keys": [{"kty": "RSA", "kid": "test-key", "alg": "RS256", "n": "!!!!", "e": "AQAB"}]},
             "malformed"),
            ({"keys": [{"kty": "RSA", "kid": "test-key", "alg": "RS256",
                        "n": _b64(b"\x01"), "e": _b64(b"\x01")}]}, "too small"),
            ({"keys": [self.jwks["keys"][0], dict(self.jwks["keys"][0])]}, "not found"),
        )
        for body, needle in bad_sets:
            with self.subTest(needle=needle):
                auth.clear_jwks_cache()
                self.opener.jwks = body
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(self.sign(self.payload()))
                self.assertIn(needle, str(cm.exception))

        # A JWKS HTTP error is fail-closed and does not surface the response body.
        auth.clear_jwks_cache()
        self.opener.jwks_action = _http_error(
            500, {"error": "server_error", "error_description": f"see {SECRET}"})
        with self.assertRaises(AuthError) as cm:
            auth.validate_access_token(self.sign(self.payload()))
        self.assertIn("no keys", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))

    def test_malformed_and_diet_tokens_are_rejected(self):
        good = self.sign(self.payload())
        header = {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
        rejects = (
            ("", "malformed"),
            ("   ", "malformed"),
            ("a.b", "malformed"),
            ("a.b.c.d", "malformed"),
            (" " + good, "malformed"),
            (good + "\n", "malformed"),
            ("ab+.e30.AAAA", "malformed"),
            ("A.e30.AAAA", "malformed"),
            (self.craft(b"not-json"), "not JSON"),
            (self.craft(b"[]"), "not an object"),
            (self.craft(b"null"), "not an object"),
            (self.craft({**header, "jku": "https://evil.test/jwks"}), "unexpected header"),
            (self.craft({**header, "alg": "none"}), "not RS256"),
            (self.craft({**header, "alg": "HS256"}), "not RS256"),
            (self.craft({**header, "typ": "JWE"}), "not RS256"),
            (self.craft({"alg": "RS256", "typ": "JWT"}), "key id"),
            (self.craft({**header, "kid": ""}), "key id"),
            (self.craft({**header, "kid": "k" * 129}), "key id"),
            (self.craft({**header, "kid": 1}), "key id"),
            (self.craft({**header, "kid": "missing-key"}), "not found"),
        )
        for token, needle in rejects:
            with self.subTest(needle=needle, token=token[:24]):
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(token)
                self.assertIn(needle, str(cm.exception))
        for value in (None, b"abc.def.ghi", 12):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(value)
                self.assertIn("malformed", str(cm.exception))

        now = 1_700_000_000

        def stamped(**extra):
            body = self.payload(iat=now, exp=now + 600)
            body.update(extra)
            return body

        auth.validate_access_token(
            self.sign(stamped(aud=[AUDIENCE, "https://other.example/api"])), now=now)
        auth.validate_access_token(
            self.sign(self.payload(iat=now, exp=now + 60, nbf=now + auth.CLOCK_SKEW)), now=now)
        # exp is still accepted at exactly CLOCK_SKEW seconds past expiry, and not one second later.
        skew_ok = self.sign(self.payload(iat=now - 600, exp=now))
        auth.validate_access_token(skew_ok, now=now + auth.CLOCK_SKEW)
        with self.assertRaises(TokenExpired):
            auth.validate_access_token(skew_ok, now=now + auth.CLOCK_SKEW + 1)
        auth.validate_access_token(
            self.sign(self.payload(iat=now + auth.CLOCK_SKEW, exp=now + auth.CLOCK_SKEW + 60)), now=now)

        diet = (
            (stamped(iss=f"https://{DOMAIN}"), "issuer"),
            (stamped(iss="https://evil.example.test/"), "issuer"),
            (stamped(aud="https://other.example/api"), "audience"),
            (stamped(aud=""), "audience"),
            (stamped(aud=[AUDIENCE, "x" * 201]), "audience"),
            (stamped(aud=["only-other"]), "audience"),
            (stamped(aud=[AUDIENCE, "", "x"]), "audience"),
            (stamped(aud=[]), "audience"),
            (stamped(sub=""), "subject"),
            (stamped(sub="s" * 129), "subject"),
            (stamped(sub=1), "subject"),
            (stamped(azp="a" * 129), "claim azp"),
            (stamped(jti="j" * 65), "claim jti"),
            (stamped(jti=1), "claim jti"),
            (stamped(email="ada@example.test"), "email"),
            (stamped(custom=True), "unexpected claim"),
            (stamped(iat=1.5), "integers"),
            (stamped(exp=True), "integers"),
            (stamped(iat=now, exp=now), "lifetime"),
            (stamped(iat=now, exp=now - 1), "lifetime"),
            (stamped(iat=now + auth.CLOCK_SKEW + 1, exp=now + auth.CLOCK_SKEW + 61), "future"),
            (stamped(nbf="later"), "not yet valid"),
            (stamped(nbf=now + auth.CLOCK_SKEW + 1), "not yet valid"),
            (stamped(scope="x" * 257), "scope claim is too large"),
            (stamped(scope=None), "scope claim is too large"),
            (stamped(scope=" ".join(f"s{i}:read" for i in range(9))), "too many scopes"),
            (stamped(scope="Keys:read"), "illegal scope"),
            (stamped(scope="nope!"), "illegal scope"),
        )
        for body, needle in diet:
            with self.subTest(needle=needle):
                with self.assertRaises(AuthError) as cm:
                    auth.validate_access_token(self.sign(body), now=now)
                self.assertIn(needle, str(cm.exception))

        # Signature verify raising something other than InvalidSignature is still a reject,
        # and the backend message is not copied into the error.
        real_key = auth._public_key

        def explode(_jwk):
            class _Key:
                def verify(self, *_args, **_kwargs):
                    raise RuntimeError(f"backend blew up {SECRET}")
            return _Key()

        auth._public_key = explode
        try:
            with self.assertRaises(AuthError) as cm:
                auth.validate_access_token(good)
        finally:
            auth._public_key = real_key
        self.assertIn("signature is invalid", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertNotIn("backend", str(cm.exception))

    def test_device_flow_errors_polling_and_expiry(self):
        token = self.sign(self.payload())
        sleeps, messages = [], []
        self.opener.queue = [
            {"device_code": "dev-secret", "user_code": "WXYZ-1234",
             "verification_uri_complete": "https://example.test/activate?user_code=WXYZ-1234",
             "expires_in": "later", "interval": ["fast"]},
            {"error": "authorization_pending", "error_description": SECRET},
            {"error": "slow_down"},
            {"access_token": token, "refresh_token": "r-new", "expires_in": 600,
             "id_token": "drop-me"},
        ]
        principal = auth.device_login(prompt=messages.append, sleep=sleeps.append)
        self.assertEqual(principal.sub, "auth0|alice")
        self.assertEqual(sleeps, [5, 10])  # bad interval falls back to 5; slow_down adds 5
        self.assertEqual(len(messages), 1)
        self.assertIn("WXYZ-1234", messages[0])
        self.assertIn("https://example.test/activate", messages[0])
        self.assertNotIn("dev-secret", messages[0])
        self.assertNotIn(SECRET, messages[0])
        device = [data for url, data in self.opener.calls if url.endswith("/oauth/device/code")]
        polls = [data for url, data in self.opener.calls if url.endswith("/oauth/token")]
        self.assertEqual(len(device), 1)
        self.assertNotIn(b"client_secret", device[0])
        self.assertNotIn(SECRET.encode(), device[0])
        self.assertEqual(len(polls), 3)
        for raw in polls:
            fields = urllib.parse.parse_qs(raw.decode())
            self.assertEqual(fields["client_secret"], [SECRET])
            self.assertEqual(fields["device_code"], ["dev-secret"])
            self.assertEqual(fields["grant_type"], ["urn:ietf:params:oauth:grant-type:device_code"])
        stored = json.loads(Path(self.token_file).read_text())
        self.assertEqual(stored["refresh_token"], "r-new")
        self.assertNotIn("id_token", stored)
        self.assertNotIn(SECRET, Path(self.token_file).read_text())
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)

        # Default prompt writes the user code to stderr and not the device_code or access token.
        self.opener.queue = []
        self.opener.token_body = {"access_token": token, "expires_in": 600}
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            auth.device_login(sleep=lambda _s: None)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("ABCD-EFGH", err.getvalue())
        self.assertNotIn("dev-code", err.getvalue())
        self.assertNotIn(token, err.getvalue() + out.getvalue())

        # interval is clamped to 60 seconds.
        sleeps.clear()
        self.opener.calls.clear()
        self.opener.queue = [
            {"device_code": "dev-code", "user_code": "ABCD-EFGH",
             "verification_uri": "https://example.test/activate", "expires_in": 30, "interval": 1000},
            {"error": "authorization_pending"},
            {"access_token": token},
        ]
        auth.device_login(prompt=lambda _m: None, sleep=sleeps.append)
        self.assertEqual(sleeps, [60])

        if os.path.exists(self.token_file):
            os.remove(self.token_file)
        starts = (
            ({"error": "unauthorized_client", "error_description": "no device"}, "unauthorized_client"),
            ({}, "missing device_code"),
        )
        for body, needle in starts:
            with self.subTest(needle=needle):
                self.opener.queue = [body]
                with self.assertRaises(AuthError) as cm:
                    auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
                self.assertIn(needle, str(cm.exception))
                self.assert_no_temp_tokens(SECRET)

        self.opener.queue = [
            {"device_code": "dev-code", "user_code": "ABCD-EFGH",
             "verification_uri": "https://example.test/activate", "expires_in": 30, "interval": 1},
            {"error": "access_denied", "error_description": "user said no"},
        ]
        with self.assertRaises(AuthError) as cm:
            auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        self.assertIn("access_denied", str(cm.exception))
        self.assertIn("user said no", str(cm.exception))
        self.assertFalse(os.path.exists(self.token_file))

        # Negative expires_in collapses to one second; a clock past that deadline stops the poll.
        self.opener.queue = [
            {"device_code": "dev-code", "user_code": "ABCD-EFGH",
             "verification_uri": "https://example.test/activate", "expires_in": -5, "interval": 1},
            {"error": "authorization_pending", "error_description": SECRET},
        ]
        with mock.patch("keyforge.auth.time.time", side_effect=[1000, 1000, 1002]):
            with self.assertRaises(AuthError) as cm:
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        self.assertIn("expired before authorization", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertNotIn("dev-code", str(cm.exception))
        self.assert_no_temp_tokens(SECRET)

        os.environ.pop("AUTH0_CLIENT_SECRET")
        self.opener.queue = []
        self.opener.calls.clear()
        self.opener.token_body = {"access_token": token, "expires_in": 600}
        auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        polls = [data for url, data in self.opener.calls if url.endswith("/oauth/token")]
        self.assertTrue(polls)
        self.assertNotIn(b"client_secret", polls[0])

        before = len(self.opener.calls)
        os.environ["AUTH0_SCOPES"] = "Nope"
        with self.assertRaises(AuthError) as cm:
            auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        self.assertIn("illegal scope", str(cm.exception))
        self.assertEqual(len(self.opener.calls), before)

    def test_refresh_fetch_redaction_and_failed_refresh_keeps_the_file(self):
        now = int(time.time())
        expired = self.sign(self.payload(scope="keys:read", iat=now - 900, exp=now - 120))
        fresh = self.sign(self.payload(scope="keys:verify"))
        refresh = "refresh-token-value"
        self.write_token({"version": 1, "access_token": expired, "refresh_token": refresh,
                          "expires_at": now - 120, "token_type": "Bearer", "scope": "keys:read",
                          "sub": "auth0|alice"})
        self.opener.token_body = {"access_token": fresh, "refresh_token": "rotated-refresh",
                                  "expires_in": 600, "id_token": "drop-me"}
        principal = auth.load_principal()
        self.assertIn("keys:verify", principal.scopes)
        stored = json.loads(Path(self.token_file).read_text())
        self.assertEqual(stored["access_token"], fresh)
        self.assertEqual(stored["refresh_token"], "rotated-refresh")
        self.assertNotIn("id_token", stored)
        self.assertNotIn(SECRET, Path(self.token_file).read_text())
        self.assertEqual(stat.S_IMODE(os.stat(self.token_file).st_mode), 0o600)
        fields = urllib.parse.parse_qs(
            [data for url, data in self.opener.calls if url.endswith("/oauth/token")][-1].decode())
        self.assertEqual(fields["grant_type"], ["refresh_token"])
        self.assertEqual(fields["refresh_token"], [refresh])
        self.assertEqual(fields["client_id"], [CLIENT])
        self.assertEqual(fields["client_secret"], [SECRET])
        self.assertNotIn("username", fields)

        # 200 JSON error: refresh token is scrubbed. The previous file is left in place.
        self.write_token({"version": 1, "access_token": expired, "refresh_token": refresh,
                          "expires_at": now - 120, "token_type": "Bearer", "scope": "keys:read",
                          "sub": "auth0|alice"})
        previous = Path(self.token_file).read_text()
        self.opener.token_body = {"error": "invalid_grant",
                                  "error_description": f"rejected {refresh} for reuse"}
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertNotIn(refresh, str(cm.exception))
        self.assertIn("[redacted]", str(cm.exception))
        self.assertNotIn(expired, str(cm.exception))
        self.assertEqual(Path(self.token_file).read_text(), previous)
        self.assert_no_temp_tokens()

        # HTTP error path redacts the client secret and the refresh token before the 300-character cap.
        self.opener.queue = [_http_error(401, {
            "error": "invalid_grant",
            "error_description": f"{SECRET} used {refresh}",
        })]
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        message = str(cm.exception)
        self.assertNotIn(SECRET, message)
        self.assertNotIn(refresh, message)
        self.assertIn("[redacted]", message)
        self.assertEqual(Path(self.token_file).read_text(), previous)

        self.opener.queue = [urllib.error.URLError(TimeoutError(f"refresh {refresh} {SECRET}"))]
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        message = str(cm.exception)
        self.assertIn("URLError", message)
        self.assertNotIn(refresh, message)
        self.assertNotIn(SECRET, message)
        self.assertNotIn("refresh ", message)
        self.assertEqual(Path(self.token_file).read_text(), previous)
        self.assert_no_temp_tokens()

        os.environ.pop("AUTH0_CLIENT_SECRET")
        self.opener.queue = []
        self.opener.calls.clear()
        self.opener.token_body = {"access_token": fresh, "expires_in": 600}
        auth.load_principal()
        fields = urllib.parse.parse_qs(
            [data for url, data in self.opener.calls if url.endswith("/oauth/token")][-1].decode())
        self.assertNotIn("client_secret", fields)
        self.assertEqual(json.loads(Path(self.token_file).read_text())["refresh_token"], refresh)

        # Expired access token with no usable refresh token is re-raised and not exchanged.
        for stored_refresh in (None, "", 5):
            with self.subTest(refresh=stored_refresh):
                body = {"version": 1, "access_token": expired, "expires_at": now - 120,
                        "token_type": "Bearer", "scope": "keys:read", "sub": "auth0|alice"}
                if stored_refresh is not None:
                    body["refresh_token"] = stored_refresh
                # Non-string refresh is an extra-or-bad value: "" is allowed by the file schema,
                # a non-string is still one of the known keys. Both must fail closed.
                if stored_refresh is not None and not isinstance(stored_refresh, str):
                    self.write_token(body)
                    with self.assertRaises(TokenExpired):
                        auth.load_principal()
                else:
                    self.write_token(body)
                    calls = len(self.opener.calls)
                    with self.assertRaises(TokenExpired):
                        auth.load_principal()
                    self.assertEqual(len(self.opener.calls), calls)

        self.write_token({"version": 1, "expires_at": now + 600, "token_type": "Bearer",
                          "scope": "keys:read", "sub": "auth0|alice"})
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("no access token", str(cm.exception))
        self.write_token({"version": 1, "access_token": 1, "expires_at": now + 600,
                          "token_type": "Bearer", "scope": "keys:read", "sub": "auth0|alice"})
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("no access token", str(cm.exception))

        # A token still inside the clock-skew window is used and does not hit the token endpoint.
        skew = self.sign(self.payload(scope="keys:read", iat=now - 600, exp=now - 30))
        self.write_token({"version": 1, "access_token": skew, "expires_at": now - 30,
                          "token_type": "Bearer", "scope": "keys:read", "sub": "auth0|alice"})
        self.opener.calls.clear()
        principal = auth.load_principal()
        self.assertEqual(principal.sub, "auth0|alice")
        self.assertFalse(any(url.endswith("/oauth/token") for url, _ in self.opener.calls))

    def test_error_fields_are_scrubbed_before_the_http_cap(self):
        # Secrets begin where a 300-character cut would land inside them. Replacing
        # after that cut leaves the prefix; replacing first removes the whole value.
        refresh = "rt-STRADDLE-value"
        password = "pw-STRADDLE-value"
        start = {"device_code": "dev-code", "user_code": "ABCD-EFGH",
                 "verification_uri": "https://example.test/activate", "expires_in": 30, "interval": 1}

        def place(secret, start_at, tail=""):
            text = ("n" * start_at) + secret + tail
            self.assertEqual(text.find(secret), start_at)
            return text

        def place_after(first, second, second_at, tail=""):
            text = first + ("n" * (second_at - len(first))) + second + tail
            self.assertEqual(text.find(second), second_at)
            self.assertEqual(text.find(first), 0)
            return text

        def assert_clean(message, *banned, kept=(), dropped=(), redacted=True):
            for secret in banned:
                self.assertNotIn(secret, message)
                self.assertNotIn(secret[:10], message)
            for text in kept:
                self.assertIn(text, message)
            for text in dropped:
                self.assertNotIn(text, message)
            if redacted:
                self.assertIn("[redacted]", message)

        def login_error(body):
            self.opener.queue = [body]
            with self.assertRaises(AuthError) as cm:
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
            return str(cm.exception)

        # Device start shows ``error`` only. The description is dropped, not echoed raw.
        with self.subTest(path="device-start-200"):
            message = login_error({"error": f"access_denied {SECRET}",
                                   "error_description": f"{SECRET} DESC-START"})
            assert_clean(message, SECRET, kept=("access_denied",), dropped=("DESC-START",))
            self.assertTrue(message.startswith("Auth0 device authorization failed:"))
            self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="device-start-http"):
            message = login_error(_http_error(400, {
                "error": f"invalid_client {SECRET}",
                "error_description": place(SECRET, 290, "DESC-START-HTTP"),
            }))
            assert_clean(message, SECRET, kept=("invalid_client",), dropped=("DESC-START-HTTP",))
            self.assertFalse(os.path.exists(self.token_file))

        # Device poll shows both fields. A 200 body is not capped; an HTTP body is, after redaction.
        with self.subTest(path="device-poll-200"):
            self.opener.queue = [start, {
                "error": SECRET,
                "error_description": place(SECRET, 290, "TAIL-KEEP-200"),
            }]
            with self.assertRaises(AuthError) as cm:
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
            message = str(cm.exception)
            assert_clean(message, SECRET, kept=("TAIL-KEEP-200",))
            self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="device-poll-http"):
            self.opener.queue = [start, _http_error(400, {
                "error": f"invalid_request {SECRET}",
                "error_description": place(SECRET, 290, "TAIL-HTTP-POLL"),
            })]
            with self.assertRaises(AuthError) as cm:
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
            message = str(cm.exception)
            assert_clean(message, SECRET, kept=("invalid_request",), dropped=("TAIL-HTTP-POLL",))
            self.assertLessEqual(len(message), 400)
            self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="device-poll-http-error-field"):
            self.opener.queue = [start, _http_error(403, {
                "error": SECRET,
                "error_description": "user said no",
            })]
            with self.assertRaises(AuthError) as cm:
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
            assert_clean(str(cm.exception), SECRET, kept=("user said no",))

        now = int(time.time())
        expired = self.sign(self.payload(scope="keys:read", iat=now - 900, exp=now - 120))

        def write_expired(token_value):
            self.write_token({"version": 1, "access_token": expired, "refresh_token": token_value,
                              "expires_at": now - 120, "token_type": "Bearer", "scope": "keys:read",
                              "sub": "auth0|alice"})
            return Path(self.token_file).read_text()

        # Client secret is replaced first (it is longer), which pulls the refresh token left.
        # It still crosses 300, so a cap before the refresh scrub would leave "rt-STRADD".
        refresh_http_desc = place_after(SECRET, refresh, 298, "TAIL-HTTP-REFRESH")
        refresh_200_desc = place_after(SECRET, refresh, 298, "TAIL-KEEP-200")
        previous = write_expired(refresh)
        with self.subTest(path="refresh-200"):
            self.opener.queue = []
            self.opener.token_body = {"error": f"invalid_grant {SECRET} {refresh}",
                                      "error_description": refresh_200_desc}
            with self.assertRaises(AuthError) as cm:
                auth.load_principal()
            message = str(cm.exception)
            assert_clean(message, SECRET, refresh, kept=("invalid_grant", "TAIL-KEEP-200"))
            self.assertEqual(Path(self.token_file).read_text(), previous)
            info = auth.status()
            self.assertNotIn(SECRET, json.dumps(info))
            self.assertNotIn(refresh, json.dumps(info))
            self.assertIn("[redacted]", info["reason"])
            rc, out, err = _run("--json", "auth", "status")
            self.assertEqual(rc, 0, err)
            self.assertNotIn(SECRET, out + err)
            self.assertNotIn(refresh, out + err)
            self.assertIn("[redacted]", out)
            self.assertEqual(Path(self.token_file).read_text(), previous)
        with self.subTest(path="refresh-http"):
            self.opener.queue = [_http_error(401, {
                "error": f"invalid_grant {SECRET} {refresh}",
                "error_description": refresh_http_desc,
            })]
            with self.assertRaises(AuthError) as cm:
                auth.load_principal()
            message = str(cm.exception)
            assert_clean(message, SECRET, refresh, kept=("invalid_grant",), dropped=("TAIL-HTTP-REFRESH",))
            self.assertLessEqual(len(message), 400)
            self.assertEqual(Path(self.token_file).read_text(), previous)
        with self.subTest(path="refresh-nested"):
            nested = f"rt-{SECRET}-tail"
            previous = write_expired(nested)
            self.opener.queue = []
            self.opener.token_body = {"error": "invalid_grant", "error_description": f"reuse {nested}"}
            with self.assertRaises(AuthError) as cm:
                auth.load_principal()
            message = str(cm.exception)
            # Replacing the client secret first would leave the refresh token's ends in place.
            self.assertNotIn(nested, message)
            self.assertNotIn(SECRET, message)
            self.assertNotIn("rt-", message)
            self.assertNotIn("-tail", message)
            self.assertIn("[redacted]", message)
            self.assertEqual(Path(self.token_file).read_text(), previous)
        with self.subTest(path="refresh-no-client-secret"):
            previous = write_expired(refresh)
            os.environ.pop("AUTH0_CLIENT_SECRET")
            self.opener.queue = []
            self.opener.token_body = {"error": f"invalid_grant {refresh}",
                                      "error_description": f"reuse {refresh}"}
            try:
                with self.assertRaises(AuthError) as cm:
                    auth.load_principal()
            finally:
                os.environ["AUTH0_CLIENT_SECRET"] = SECRET
            message = str(cm.exception)
            assert_clean(message, refresh, kept=("invalid_grant",))
            self.assertEqual(Path(self.token_file).read_text(), previous)

        if os.path.exists(self.token_file):
            os.remove(self.token_file)
        password_http_desc = place_after(SECRET, password, 298, "TAIL-HTTP-PASSWORD")
        password_200_desc = place_after(SECRET, password, 298, "TAIL-KEEP-200")
        with self.subTest(path="password-200"):
            self.opener.queue = []
            self.opener.token_body = {"error": f"invalid_grant {SECRET} {password}",
                                      "error_description": password_200_desc}
            with self.assertRaises(AuthError) as cm:
                auth.password_login("ada@example.test", password)
            message = str(cm.exception)
            assert_clean(message, SECRET, password, kept=("invalid_grant", "TAIL-KEEP-200"))
            self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="password-http"):
            self.opener.queue = [_http_error(401, {
                "error": f"invalid_grant {SECRET} {password}",
                "error_description": password_http_desc,
            })]
            with self.assertRaises(AuthError) as cm:
                auth.password_login("ada@example.test", password)
            message = str(cm.exception)
            assert_clean(message, SECRET, password, kept=("invalid_grant",), dropped=("TAIL-HTTP-PASSWORD",))
            self.assertLessEqual(len(message), 400)
            self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="password-nested"):
            nested = f"pw-{SECRET}-tail"
            self.opener.queue = []
            self.opener.token_body = {"error": nested, "error_description": f"bad {nested}"}
            with self.assertRaises(AuthError) as cm:
                auth.password_login("ada@example.test", nested)
            message = str(cm.exception)
            self.assertNotIn(nested, message)
            self.assertNotIn(SECRET, message)
            self.assertNotIn("pw-", message)
            self.assertNotIn("-tail", message)
            self.assertIn("[redacted]", message)
            self.assertFalse(os.path.exists(self.token_file))
        for label, body in (
            ("password-denied-200", {"error": "unauthorized_client",
                                    "error_description": f"{SECRET} {password} DESC-DENIED"}),
            ("password-denied-http", _http_error(403, {
                "error": "unauthorized_client",
                "error_description": place(password, 290, "DESC-DENIED"),
            })),
        ):
            with self.subTest(path=label):
                if label.endswith("http"):
                    self.opener.queue = [body]
                else:
                    self.opener.queue = []
                    self.opener.token_body = body
                with self.assertRaises(AuthError) as cm:
                    auth.password_login("ada@example.test", password)
                message = str(cm.exception)
                assert_clean(message, SECRET, password, kept=("Grant Types → Password",),
                             dropped=("DESC-DENIED",), redacted=False)
                self.assertNotIn("invalid_grant", message)
                self.assertFalse(os.path.exists(self.token_file))
        with self.subTest(path="password-no-client-secret"):
            os.environ.pop("AUTH0_CLIENT_SECRET")
            self.opener.queue = []
            self.opener.token_body = {"error": f"invalid_grant {password}",
                                      "error_description": f"nope {password}"}
            try:
                with self.assertRaises(AuthError) as cm:
                    auth.password_login("ada@example.test", password)
            finally:
                os.environ["AUTH0_CLIENT_SECRET"] = SECRET
            assert_clean(str(cm.exception), password, kept=("invalid_grant",))
        with self.subTest(path="password-timeout"):
            self.opener.queue = [TimeoutError(f"slow {password} {SECRET}")]
            with self.assertRaises(AuthError) as cm:
                auth.password_login("ada@example.test", password)
            message = str(cm.exception)
            assert_clean(message, SECRET, password, kept=("TimeoutError",), dropped=("slow",), redacted=False)

        with self.subTest(path="from-file"):
            captured = os.path.join(self.d.name, "captured.json")
            Path(captured).write_text(json.dumps({
                "error": f"invalid_grant {SECRET} {refresh}",
                "error_description": f"{SECRET} {refresh} {password} DESC-FILE",
                "refresh_token": refresh,
                "access_token": "not-stored",
            }))
            with self.assertRaises(AuthError) as cm:
                auth.accept_token_file(captured)
            message = str(cm.exception)
            # The description is omitted. The error field still cannot carry either secret.
            assert_clean(message, SECRET, refresh, password, kept=("invalid_grant",), dropped=("DESC-FILE", "not-stored"))
            self.assertFalse(os.path.exists(self.token_file))

        with self.subTest(path="jwks-http"):
            auth.clear_jwks_cache()
            self.opener.jwks_action = _http_error(500, {
                "error": f"server_error {SECRET}",
                "error_description": place(SECRET, 290, "JWKS-BODY"),
            })
            with self.assertRaises(AuthError) as cm:
                auth.validate_access_token(self.sign(self.payload()))
            message = str(cm.exception)
            assert_clean(message, SECRET, kept=("no keys",), dropped=("JWKS-BODY", "server_error"), redacted=False)
        with self.subTest(path="jwks-200"):
            auth.clear_jwks_cache()
            self.opener.jwks = {"error": f"server_error {SECRET}",
                                "error_description": place(SECRET, 290, "JWKS-BODY")}
            with self.assertRaises(AuthError) as cm:
                auth.validate_access_token(self.sign(self.payload()))
            message = str(cm.exception)
            assert_clean(message, SECRET, kept=("no keys",), dropped=("JWKS-BODY", "server_error"), redacted=False)

    def test_token_file_permissions_symlink_and_temp_cleanup(self):
        token = self.sign(self.payload())
        nested = os.path.join(self.d.name, "nested", "tokens.json")
        os.environ["KEYFORGE_TOKEN_FILE"] = nested
        old_umask = os.umask(0)
        try:
            self._login(token)
        finally:
            os.umask(old_umask)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(nested)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(nested).st_mode), 0o600)
        raw = Path(nested).read_text()
        self.assertNotIn(SECRET, raw)
        self.assertNotIn("id_token", raw)
        os.environ["KEYFORGE_TOKEN_FILE"] = self.token_file

        # A failed replace removes the temp file, even on KeyboardInterrupt, and leaves no secret behind.
        other = self.sign(self.payload(sub="auth0|bob"))
        canary_refresh = "refresh-canary-not-on-disk"
        self.opener.token_body = {"access_token": other, "refresh_token": canary_refresh,
                                  "id_token": "id-canary", "expires_in": 600}
        real_replace = os.replace

        def fail_replace(src, dst):
            self.assertEqual(stat.S_IMODE(os.stat(src).st_mode), 0o600)
            text = Path(src).read_text()
            self.assertIn(other, text)
            self.assertIn(canary_refresh, text)
            self.assertNotIn(SECRET, text)
            self.assertNotIn("id-canary", text)
            self.assertNotIn("id_token", text)
            raise KeyboardInterrupt()

        os.replace = fail_replace
        try:
            with self.assertRaises(KeyboardInterrupt):
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        finally:
            os.replace = real_replace
        self.assertFalse(os.path.exists(self.token_file))
        self.assert_no_temp_tokens(other, canary_refresh, "id-canary", SECRET)

        # The same failure must not clobber a token file that is already there.
        self._login(token)
        kept = Path(self.token_file).read_text()
        os.replace = fail_replace
        try:
            with self.assertRaises(OSError):
                self.opener.token_body = {"access_token": other, "refresh_token": canary_refresh,
                                          "expires_in": 600}
                # fail_replace raises KeyboardInterrupt; use OSError for the clobber case.
                def fail_os(src, _dst):
                    self.assertEqual(stat.S_IMODE(os.stat(src).st_mode), 0o600)
                    raise OSError("replace failed")
                os.replace = fail_os
                auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        finally:
            os.replace = real_replace
        self.assertEqual(Path(self.token_file).read_text(), kept)
        self.assertNotIn(other, kept)
        self.assert_no_temp_tokens(other, canary_refresh)

        # Symlink, directory, loose mode, unreadable, overstuffed, and garbage files are rejected
        # without echoing their contents.
        os.remove(self.token_file)
        target = os.path.join(self.d.name, "elsewhere.json")
        Path(target).write_text(json.dumps({"access_token": "CANARY-SECRET", "version": 1}))
        os.chmod(target, 0o600)
        os.symlink(target, self.token_file)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("unusable", str(cm.exception))
        self.assertNotIn("CANARY-SECRET", str(cm.exception))
        self.assertIn("CANARY-SECRET", Path(target).read_text())
        os.remove(self.token_file)

        os.mkdir(self.token_file)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("not a regular file", str(cm.exception))
        os.rmdir(self.token_file)

        Path(self.token_file).write_text(json.dumps({"access_token": "loose-canary", "version": 1}))
        for mode in (0o644, 0o640, 0o606, 0o664):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.token_file, mode)
                with self.assertRaises(AuthError) as cm:
                    auth.load_principal()
                self.assertIn("chmod 600", str(cm.exception))
                self.assertNotIn("loose-canary", str(cm.exception))

        os.chmod(self.token_file, 0)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("unusable", str(cm.exception))
        self.assertIn("Permission denied", str(cm.exception))
        os.chmod(self.token_file, 0o600)

        self.write_token({"version": 1, "access_token": token, "password": "hunter2"})
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("malformed", str(cm.exception))
        self.assertNotIn("hunter2", str(cm.exception))
        self.assertNotIn(token, str(cm.exception))

        Path(self.token_file).write_bytes(b"\xff" + b"x" * 20)
        os.chmod(self.token_file, 0o600)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("not JSON", str(cm.exception))
        Path(self.token_file).write_text("[1, 2, 3]")
        os.chmod(self.token_file, 0o600)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("malformed", str(cm.exception))
        Path(self.token_file).write_bytes(b"{" + b"x" * 65535)
        os.chmod(self.token_file, 0o600)
        with self.assertRaises(AuthError) as cm:
            auth.load_principal()
        self.assertIn("overstuffed", str(cm.exception))

        # Parent directories are not re-checked. A 0600 file in a world-accessible directory still loads.
        self._login(token)
        os.chmod(self.d.name, 0o777)
        try:
            self.assertEqual(auth.load_principal().sub, "auth0|alice")
        finally:
            os.chmod(self.d.name, 0o700)

        auth.logout()
        self.assertFalse(os.path.exists(self.token_file))
        auth.logout()
        rc, out, err = _run("--json", "auth", "status")
        self.assertEqual(rc, 0, err)
        status = json.loads(out)
        self.assertEqual(status["enabled"], True)
        self.assertEqual(status["logged_in"], False)
        self.assertIn("not logged in", status["reason"])
        self.assertNotIn("access_token", out)
        self.assertNotIn(token, out + err)
        rc, out, err = _run("auth", "logout")
        self.assertEqual(rc, 0, err)
        self.assertIn("logged out", out)

    def test_command_gates_exempt_policy_and_expiry(self):
        gates = {
            "list": "keys:read", "show": "keys:read", "audit": "keys:read", "export": "keys:read",
            "verify": "keys:verify", "serve": "keys:verify", "reveal": "reveal:secret",
            "create": "keys:write", "rotate": "keys:write", "revoke": "keys:write",
            "suspend": "keys:write", "resume": "keys:write", "update": "keys:write",
            "import": "keys:write", "purge": "keys:write",
            "auth": None, "uninstall": None, "kms": None, "setup": None,
        }
        for cmd, scope in gates.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(auth.required_scope(argparse_namespace(cmd)), scope)
        for sub, scope in (("show", "keys:read"), (None, "keys:read"), ("describe", "keys:read"),
                           ("set", "keys:write"), ("reset", "keys:write")):
            with self.subTest(policy=sub):
                self.assertEqual(auth.required_scope(argparse_namespace("policy", policy_cmd=sub)), scope)
        with self.assertRaises(AuthError) as cm:
            auth.required_scope(argparse_namespace("shell"))
        self.assertIn("refusing unscoped command 'shell'", str(cm.exception))
        with self.assertRaises(AuthError) as cm:
            auth.authorize(argparse_namespace(None))
        self.assertIn("refusing unscoped command", str(cm.exception))

        # Exempt commands do not read the token file, so a bad file does not block them.
        Path(self.token_file).write_text("not-json")
        os.chmod(self.token_file, 0o644)
        for cmd in ("auth", "uninstall", "kms", "setup"):
            with self.subTest(exempt=cmd):
                self.assertIsNone(auth.authorize(argparse_namespace(cmd)))
        with self.assertRaises(AuthError) as cm:
            auth.authorize(argparse_namespace("list"))
        self.assertIn("chmod 600", str(cm.exception))

        for name in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE"):
            os.environ.pop(name)
        self.assertIsNone(auth.authorize(argparse_namespace("reveal")))
        self.assertIsNone(auth.authorize(argparse_namespace("uninstall")))
        os.environ["AUTH0_DOMAIN"] = DOMAIN
        os.environ["AUTH0_CLIENT_ID"] = CLIENT
        os.environ["AUTH0_AUDIENCE"] = AUDIENCE

        self._login(self.sign(self.payload(scope="keys:read")))
        self.assertEqual(auth.authorize(argparse_namespace("list")).sub, "auth0|alice")
        self.assertEqual(auth.authorize(argparse_namespace("policy", policy_cmd="show")).scopes,
                         frozenset({"keys:read"}))
        with self.assertRaises(Unauthorized):
            auth.authorize(argparse_namespace("policy", policy_cmd="set"))
        with self.assertRaises(Unauthorized):
            auth.authorize(argparse_namespace("create"))
        with self.assertRaises(Unauthorized):
            auth.authorize(argparse_namespace("serve"))
        self._login(self.sign(self.payload(scope="keys:write keys:verify reveal:secret")))
        for cmd in ("create", "rotate", "revoke", "policy", "verify", "serve", "reveal"):
            extra = {"policy_cmd": "reset"} if cmd == "policy" else {}
            with self.subTest(cmd=cmd):
                principal = auth.authorize(argparse_namespace(cmd, **extra))
                self.assertEqual(principal.sub, "auth0|alice")

        now = int(time.time())
        expired = self.sign(self.payload(scope="keys:read", iat=now - 900, exp=now - 120))
        fresh = self.sign(self.payload(scope="keys:read"))
        self.write_token({"version": 1, "access_token": expired, "refresh_token": "refresh-9",
                          "expires_at": now - 120, "token_type": "Bearer", "scope": "keys:read",
                          "sub": "auth0|alice"})
        self.opener.token_body = {"access_token": fresh, "expires_in": 600}
        principal = auth.authorize(argparse_namespace("audit"))
        self.assertIn("keys:read", principal.scopes)
        self.assertEqual(json.loads(Path(self.token_file).read_text())["access_token"], fresh)

        self.write_token({"version": 1, "access_token": expired, "expires_at": now - 120,
                          "token_type": "Bearer", "scope": "keys:read", "sub": "auth0|alice"})
        with self.assertRaises(TokenExpired):
            auth.authorize(argparse_namespace("show"))
        rc, out, err = _run("--json", "list")
        self.assertEqual(rc, 1)
        self.assertIn("access token expired", out + err)
        self.assertNotIn(expired, out + err)
        info = auth.status()
        self.assertEqual(info["logged_in"], False)
        self.assertIn("expired", info["reason"])
        self.assertNotIn("access_token", info)
        self.assertNotIn(expired, json.dumps(info))

    def test_password_login_and_from_file_reject_bad_input(self):
        before = len(self.opener.calls)
        for username, password in ((" ", "secret"), ("ada", ""), ("", "secret"), (None, None)):
            with self.subTest(username=username):
                with self.assertRaises(AuthError) as cm:
                    auth.password_login(username, password)
                self.assertIn("username and password", str(cm.exception))
        self.assertEqual(len(self.opener.calls), before)
        os.environ["AUTH0_REALM"] = "x" * 129
        with self.assertRaises(AuthError) as cm:
            auth.password_login("ada", "secret")
        self.assertIn("AUTH0_REALM", str(cm.exception))
        os.environ["AUTH0_REALM"] = "   "
        with self.assertRaises(AuthError) as cm:
            auth.password_login("ada", "secret")
        self.assertIn("AUTH0_REALM", str(cm.exception))
        self.assertEqual(len(self.opener.calls), before)
        os.environ["AUTH0_SCOPES"] = "Nope"
        with self.assertRaises(AuthError) as cm:
            auth.password_login("ada", "secret")
        self.assertIn("illegal scope", str(cm.exception))
        self.assertEqual(len(self.opener.calls), before)

        os.environ["AUTH0_SCOPES"] = "keys:read"
        os.environ["AUTH0_REALM"] = "my-db"
        token = self.sign(self.payload(scope="keys:read", gty="password"))
        self.opener.token_body = {"access_token": token, "expires_in": 600}
        principal = auth.password_login("ada@example.test", "pw")
        self.assertEqual(principal.sub, "auth0|alice")
        fields = urllib.parse.parse_qs(
            [data for url, data in self.opener.calls if url.endswith("/oauth/token")][-1].decode())
        self.assertEqual(fields["realm"], ["my-db"])
        self.assertEqual(fields["username"], ["ada@example.test"])
        self.assertNotIn("refresh_token", json.loads(Path(self.token_file).read_text()))
        self.assertNotIn(SECRET, Path(self.token_file).read_text())

        self.opener.token_body = {"token_type": "Bearer", "expires_in": 600}
        with self.assertRaises(AuthError) as cm:
            auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        self.assertIn("missing an access token", str(cm.exception))
        self.assert_no_temp_tokens()
        for refresh in ("", "r" * 2049, 5):
            with self.subTest(refresh=type(refresh).__name__):
                self.opener.token_body = {"access_token": token, "refresh_token": refresh}
                with self.assertRaises(AuthError) as cm:
                    auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
                self.assertIn("refresh token", str(cm.exception))
                self.assertFalse(any(p.name.startswith(".kf-auth-") for p in Path(self.d.name).rglob("*")))
        self.opener.token_body = {"access_token": token, "refresh_token": "r" * 2048}
        auth.device_login(prompt=lambda _m: None, sleep=lambda _s: None)
        self.assertEqual(json.loads(Path(self.token_file).read_text())["refresh_token"], "r" * 2048)

        missing = os.path.join(self.d.name, "missing.json")
        with self.assertRaises(AuthError) as cm:
            auth.accept_token_file(missing)
        self.assertIn("unreadable", str(cm.exception))
        bad = os.path.join(self.d.name, "bad.json")
        Path(bad).write_text("{")
        with self.assertRaises(AuthError) as cm:
            auth.accept_token_file(bad)
        self.assertIn("unreadable", str(cm.exception))
        self.assertNotIn(token, str(cm.exception))
        Path(bad).write_text("[1]")
        with self.assertRaises(AuthError) as cm:
            auth.accept_token_file(bad)
        self.assertIn("JSON object", str(cm.exception))
        Path(bad).write_text(json.dumps({
            "error": "invalid_grant", "error_description": SECRET, "access_token": token,
            "refresh_token": "should-not-stick",
        }))
        os.remove(self.token_file)
        with self.assertRaises(AuthError) as cm:
            auth.accept_token_file(bad)
        self.assertIn("invalid_grant", str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertNotIn(token, str(cm.exception))
        self.assertFalse(os.path.exists(self.token_file))
        self.assert_no_temp_tokens()


class _NS:
    def __init__(self, cmd, **extra):
        self.cmd = cmd
        for k, v in extra.items():
            setattr(self, k, v)


def argparse_namespace(cmd, **extra):
    return _NS(cmd, **extra)


if __name__ == "__main__":
    unittest.main()
