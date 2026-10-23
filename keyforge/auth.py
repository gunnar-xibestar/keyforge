"""Optional Auth0 login for the CLI, with token dieting.

Auth is disabled unless ``AUTH0_DOMAIN``, ``AUTH0_CLIENT_ID`` and ``AUTH0_AUDIENCE``
are all set. A partial set is an error (fail closed). ``AUTH0_CLIENT_SECRET`` is
optional and is read from the environment only; it is never written to the token
file, the store, or logs, and it is stripped from Auth0 error text.

Login is the OAuth 2.0 device authorization flow, or ``auth login --from-file``
for a token response captured elsewhere. The access token is a short-lived RS256
JWT. A refresh token, when Auth0 issues one, is stored separately and is not used
as an access token.

Token diet
- Access tokens larger than 2048 bytes are rejected.
- The header may contain only ``alg``, ``typ`` and ``kid``, and ``alg`` must be RS256.
- The payload may contain only ``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``nbf``,
  ``azp``, ``scope``, ``gty`` and ``jti``. ``permissions``, ``roles``, profile claims
  and any other claim are rejected, even when the signature is valid. Turn off
  Auth0's "Add Permissions in the Access Token" setting.
- ``exp - iat`` must be between 1 second and ``KEYFORGE_MAX_TOKEN_TTL`` (default
  3600, and it cannot be raised above 3600).
- Authorization uses the space-separated ``scope`` claim (at most 8 short scopes).
  KeyForge does not call the Auth0 Management API or ``/userinfo``.

What Auth0 does not do: it never sees API-key secrets. Those stay inside the
envelope encrypted by the local or PKCS#11 KMS.
"""
from __future__ import annotations
import base64, json, os, re, stat, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass
from pathlib import Path
from .errors import AuthError, Unauthorized

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "KeyForge Auth0 support requires the 'cryptography' package "
        "(apt install python3-cryptography)"
    ) from e

REQUIRED_ENV = ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE")
MAX_ACCESS_TOKEN_BYTES = 2048
MAX_REFRESH_TOKEN_BYTES = 2048
DEFAULT_MAX_TTL = 3600
CLOCK_SKEW = 60
MAX_SCOPES = 8
MAX_SCOPE_CLAIM = 256
JWKS_TTL = 300
DEFAULT_SCOPES = "keys:read keys:write keys:verify reveal:secret offline_access"
ALLOWED_HEADER = frozenset({"alg", "typ", "kid"})
ALLOWED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "azp", "scope", "gty", "jti"})
FORBIDDEN_CLAIMS = frozenset({
    "permissions", "roles", "groups", "picture", "email", "name", "nickname",
    "given_name", "family_name", "user_metadata", "app_metadata", "identities",
})
_TOKEN_FILE_KEYS = frozenset({"version", "access_token", "refresh_token", "expires_at", "token_type", "scope", "sub"})
_CLAIM_LIMITS = {"azp": 128, "jti": 64}
# Auth0 usually sends a short string (``password``, ``client-credentials``,
# ``refresh_token``, or a grant-type URN). Some tenants/flows emit a short
# array of those strings after refresh; both shapes stay within the diet.
_GTY_LIMIT = 80
_MAX_GTY_VALUES = 4
_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HOST = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_SCOPE = re.compile(r"^[a-z][a-z0-9_:-]{0,63}$")

# Tests assign a urllib-compatible opener here. Production leaves it None.
_opener = None
_jwks_cache: dict[str, tuple[float, dict]] = {}


class TokenExpired(AuthError):
    pass


@dataclass(frozen=True)
class Principal:
    sub: str
    scopes: frozenset
    exp: int


def clear_jwks_cache() -> None:
    _jwks_cache.clear()


def auth_mode() -> str:
    """``disabled`` when no Auth0 variables are set. A partial set raises."""
    present = [k for k in REQUIRED_ENV if os.environ.get(k)]
    if not present:
        return "disabled"
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
    if missing:
        raise AuthError("Auth0 is partially configured; missing " + ", ".join(missing))
    return "enabled"


def max_token_ttl() -> int:
    raw = os.environ.get("KEYFORGE_MAX_TOKEN_TTL", str(DEFAULT_MAX_TTL))
    try:
        value = int(raw)
    except ValueError:
        raise AuthError("KEYFORGE_MAX_TOKEN_TTL must be an integer number of seconds")
    if not 60 <= value <= DEFAULT_MAX_TTL:
        raise AuthError(f"KEYFORGE_MAX_TOKEN_TTL must be between 60 and {DEFAULT_MAX_TTL} seconds")
    return value


def token_path() -> Path:
    return Path(os.path.expanduser(os.environ.get("KEYFORGE_TOKEN_FILE") or "~/.keyforge/tokens.json"))


def _config() -> dict:
    if auth_mode() != "enabled":
        raise AuthError("Auth0 is not configured")
    domain = os.environ["AUTH0_DOMAIN"].strip()
    client_id = os.environ["AUTH0_CLIENT_ID"].strip()
    audience = os.environ["AUTH0_AUDIENCE"].strip()
    if not _HOST.match(domain):
        raise AuthError("AUTH0_DOMAIN must be a hostname such as tenant.us.auth0.com (no scheme or path)")
    if not client_id or len(client_id) > 128:
        raise AuthError("AUTH0_CLIENT_ID is missing or too long")
    if not audience or len(audience) > 200:
        raise AuthError("AUTH0_AUDIENCE is missing or too long")
    return {"domain": domain, "client_id": client_id, "audience": audience,
            "secret": os.environ.get("AUTH0_CLIENT_SECRET") or ""}


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment or any(c not in _B64 for c in segment):
        raise AuthError("access token is malformed")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception:
        raise AuthError("access token is malformed")


def _json_obj(raw: bytes, what: str) -> dict:
    try:
        obj = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuthError(f"access token {what} is not JSON")
    if not isinstance(obj, dict):
        raise AuthError(f"access token {what} is not an object")
    return obj


def _redact(text: str, *secrets: str, limit: int | None = None) -> str:
    """Replace secrets before applying ``limit``, so a cut cannot leave a secret prefix."""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text if limit is None else text[:limit]


def _error_parts(body: dict, *secrets: str) -> tuple[str, str]:
    """Second pass over ``error`` and ``error_description``. HTTP descriptions are capped here."""
    known = (os.environ.get("AUTH0_CLIENT_SECRET") or "", *secrets)
    limit = 300 if body.get("_http_error") else None
    error = _redact(str(body.get("error") or ""), *known)
    description = _redact(str(body.get("error_description") or ""), *known, limit=limit)
    return error, description


def _request_json(url: str, fields: dict | None = None, timeout: float = 30, secret: str = "") -> dict:
    headers = {"Accept": "application/json"}
    data = None
    if fields is not None:
        data = urllib.parse.urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers)
    open_ = _opener or urllib.request.urlopen
    client_secret = os.environ.get("AUTH0_CLIENT_SECRET") or ""
    try:
        with open_(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = b""
        try:
            body = json.loads(raw.decode() or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        error = str(body.get("error") or f"http {e.code}")
        description = str(body.get("error_description") or "")
        # No length cap. _error_parts repeats the scrub and then caps HTTP descriptions.
        return {"_http_error": e.code,
                "error": _redact(error, client_secret, secret),
                "error_description": _redact(description, client_secret, secret)}
    except Exception as e:
        raise AuthError("Auth0 request failed: " + _redact(f"{type(e).__name__}", client_secret, limit=300)) from None
    if len(raw) > 65536:
        raise AuthError("Auth0 response is overstuffed")
    try:
        body = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuthError("Auth0 response was not JSON")
    if not isinstance(body, dict):
        raise AuthError("Auth0 response was not a JSON object")
    return body


def _public_key(jwk: dict):
    if jwk.get("kty") != "RSA" or jwk.get("alg") not in (None, "RS256"):
        raise AuthError("Auth0 JWKS key is not RS256")
    try:
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    except (KeyError, AuthError, ValueError):
        raise AuthError("Auth0 JWKS key is malformed")
    if e < 3 or n.bit_length() < 2048:
        raise AuthError("Auth0 JWKS key is too small")
    return RSAPublicNumbers(e, n).public_key()


def _jwks(domain: str) -> dict:
    now = time.time()
    hit = _jwks_cache.get(domain)
    if hit and now - hit[0] < JWKS_TTL:
        return hit[1]
    body = _request_json(f"https://{domain}/.well-known/jwks.json")
    keys = body.get("keys")
    if not isinstance(keys, list) or not keys:
        raise AuthError("Auth0 JWKS response has no keys")
    _jwks_cache[domain] = (now, body)
    return body


def _check_scopes(scope: str) -> frozenset:
    if not isinstance(scope, str) or len(scope) > MAX_SCOPE_CLAIM:
        raise AuthError("access token is overstuffed: scope claim is too large")
    parts = scope.split() if scope else []
    if len(parts) > MAX_SCOPES:
        raise AuthError("access token is overstuffed: too many scopes")
    for part in parts:
        if not _SCOPE.match(part):
            raise AuthError("access token is overstuffed: illegal scope value")
    return frozenset(parts)


def _check_gty(value) -> None:
    """Accept Auth0's short string or short string-array ``gty`` claim."""
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and 1 <= len(value) <= _MAX_GTY_VALUES:
        values = value
    else:
        raise AuthError("access token is overstuffed: claim gty is too large")
    for item in values:
        if not isinstance(item, str) or not 1 <= len(item) <= _GTY_LIMIT:
            raise AuthError("access token is overstuffed: claim gty is too large")


def requested_scopes() -> frozenset:
    """Scopes KeyForge asks Auth0 for at device login (``AUTH0_SCOPES`` or the default set)."""
    return _check_scopes(os.environ.get("AUTH0_SCOPES") or DEFAULT_SCOPES)


def scope_grant(principal: Principal) -> dict:
    """Compare requested scopes to what the principal actually has.

    Auth0 returns the intersection of the request, API Permissions, app grants,
    and (when RBAC is on) the user's assigned permissions. KeyForge does not
    invent scopes; a short grant list means the tenant withheld them.

    ``offline_access`` is requested so Auth0 may issue a refresh token; it is not
    a command-authorization scope, so it is omitted from ``missing_scopes``.
    """
    requested = sorted(requested_scopes())
    granted = sorted(principal.scopes)
    missing = sorted((set(requested) - principal.scopes) - {"offline_access"})
    return {"requested_scopes": requested, "scopes": granted, "missing_scopes": missing}


def validate_access_token(token: str, *, now: float | None = None) -> Principal:
    """Verify signature, issuer, audience, lifetime, and the token-diet claim set."""
    conf = _config()
    if not isinstance(token, str) or not token or token.strip() != token:
        raise AuthError("access token is malformed")
    if len(token.encode()) > MAX_ACCESS_TOKEN_BYTES:
        raise AuthError(f"access token is overstuffed: longer than {MAX_ACCESS_TOKEN_BYTES} bytes")
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("access token is malformed")
    header = _json_obj(_b64url_decode(parts[0]), "header")
    if set(header) - ALLOWED_HEADER:
        raise AuthError("access token is overstuffed: unexpected header field")
    if header.get("alg") != "RS256" or header.get("typ") not in (None, "JWT"):
        raise AuthError("access token algorithm is not RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
        raise AuthError("access token is missing a key id")
    jwks = _jwks(conf["domain"])
    matches = [k for k in jwks["keys"] if isinstance(k, dict) and k.get("kid") == kid]
    if len(matches) != 1:
        raise AuthError("access token key id was not found in the Auth0 JWKS")
    try:
        sig = _b64url_decode(parts[2])
        _public_key(matches[0]).verify(sig, token.rsplit(".", 1)[0].encode("ascii"),
                                       padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise AuthError("access token signature is invalid")
    except AuthError:
        raise
    except Exception:
        raise AuthError("access token signature is invalid")
    payload = _json_obj(_b64url_decode(parts[1]), "payload")
    forbidden = FORBIDDEN_CLAIMS & set(payload)
    if forbidden:
        raise AuthError("access token is overstuffed: claim " + ", ".join(sorted(forbidden)) +
                        " is not allowed (token diet)")
    extra = set(payload) - ALLOWED_CLAIMS
    if extra:
        raise AuthError("access token is overstuffed: unexpected claim " + ", ".join(sorted(extra)))
    if payload.get("iss") != f"https://{conf['domain']}/":
        raise AuthError("access token issuer does not match AUTH0_DOMAIN")
    aud = payload.get("aud")
    if isinstance(aud, str):
        auds = [aud]
    elif isinstance(aud, list) and 1 <= len(aud) <= 3 and all(isinstance(a, str) and 1 <= len(a) <= 200 for a in aud):
        auds = aud
    else:
        raise AuthError("access token is overstuffed: audience claim is not a short string or short list")
    if conf["audience"] not in auds:
        raise AuthError("access token audience does not match AUTH0_AUDIENCE")
    sub = payload.get("sub")
    if not isinstance(sub, str) or not 1 <= len(sub) <= 128:
        raise AuthError("access token subject is missing or too long")
    for name, limit in _CLAIM_LIMITS.items():
        if name in payload and (not isinstance(payload[name], str) or len(payload[name]) > limit):
            raise AuthError(f"access token is overstuffed: claim {name} is too large")
    if "gty" in payload:
        _check_gty(payload["gty"])
    iat, exp = payload.get("iat"), payload.get("exp")
    if type(iat) is not int or type(exp) is not int:
        raise AuthError("access token iat and exp must be integers")
    ttl = max_token_ttl()
    if exp - iat <= 0 or exp - iat > ttl:
        raise AuthError(f"access token exceeds the token-diet lifetime of {ttl}s")
    current = time.time() if now is None else now
    if iat > current + CLOCK_SKEW:
        raise AuthError("access token was issued in the future")
    nbf = payload.get("nbf")
    if nbf is not None and (type(nbf) is not int or nbf > current + CLOCK_SKEW):
        raise AuthError("access token is not yet valid")
    if exp < current - CLOCK_SKEW:
        raise TokenExpired("access token expired")
    scopes = _check_scopes(payload.get("scope", ""))
    return Principal(sub=sub, scopes=scopes, exp=exp)


def _require_private_token_dir(directory: Path) -> None:
    """Reject a token file whose parent directory is group- or world-writable.

    A 0600 file in a writable directory can be unlinked and replaced by someone
    other than the owner. Readable or searchable bits alone are not a refusal.
    """
    try:
        mode = os.stat(directory).st_mode
    except OSError as e:
        raise AuthError(f"token directory unusable: {e.strerror}")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AuthError("token directory must not be group/world writable (chmod 700)")


def _read_token_file() -> dict:
    path = token_path()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise AuthError("not logged in")
    except OSError as e:
        raise AuthError(f"token file unusable: {e.strerror}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AuthError("token file is not a regular file")
        if st.st_mode & 0o077:
            raise AuthError("token file must not be group/world accessible (chmod 600)")
        _require_private_token_dir(path.parent)
        raw = os.read(fd, 65536)
        if len(raw) >= 65536:
            raise AuthError("token file is overstuffed")
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuthError("token file is not JSON")
    if not isinstance(data, dict) or set(data) - _TOKEN_FILE_KEYS:
        raise AuthError("token file is malformed or overstuffed")
    return data


def _is_home_dir(directory: Path) -> bool:
    return os.path.realpath(directory) == os.path.realpath(Path.home())


def _tighten_token_dir(parent: Path) -> None:
    """Tighten a token directory we own. Never chmod ``$HOME`` or someone else's directory.

    A group- or world-writable directory we will not chmod is refused instead,
    so a token is not written where another user can replace it. ``mkdir``
    leaves an existing directory's mode unchanged; this is the follow-up.
    """
    try:
        st = os.stat(parent)
    except OSError as e:
        raise AuthError(f"token directory unusable: {e.strerror or e}")
    if st.st_uid == os.getuid() and not _is_home_dir(parent):
        try:
            os.chmod(parent, 0o700)
        except OSError as e:
            detail = e.strerror or str(e)
            raise AuthError(f"token directory {parent} could not be made private: {detail}")
        return
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AuthError(
            f"token directory {parent} must be private; chmod 700 or set KEYFORGE_TOKEN_FILE"
        )


def _write_token_file(principal: Principal, access_token: str, refresh_token: str | None) -> None:
    path = token_path()
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _tighten_token_dir(parent)
    body = {"version": 1, "access_token": access_token, "expires_at": principal.exp,
            "token_type": "Bearer", "scope": " ".join(sorted(principal.scopes)), "sub": principal.sub}
    if refresh_token:
        body["refresh_token"] = refresh_token
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".kf-auth-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(body, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    os.chmod(path, 0o600)


def _accept_token_response(tok: dict, *secrets: str) -> Principal:
    """Validate a token-endpoint body and store only the lean access token plus refresh token."""
    if tok.get("error"):
        extras = [s for s in secrets if isinstance(s, str) and s]
        refresh = tok.get("refresh_token")
        if isinstance(refresh, str) and refresh:
            extras.append(refresh)
        error, description = _error_parts(tok, *extras)
        raise AuthError(f"Auth0 token endpoint: {error}: {description}".rstrip(": "))
    access = tok.get("access_token")
    if not isinstance(access, str):
        raise AuthError("token response is missing an access token")
    principal = validate_access_token(access)
    refresh = tok.get("refresh_token")
    if refresh is not None:
        if not isinstance(refresh, str) or not refresh or len(refresh.encode()) > MAX_REFRESH_TOKEN_BYTES:
            raise AuthError("refresh token was rejected (empty or longer than 2048 bytes)")
    # id_token and any other profile-bearing fields are intentionally dropped.
    _write_token_file(principal, access, refresh if isinstance(refresh, str) else None)
    return principal


def accept_token_file(path: str) -> Principal:
    """Validate a token-response JSON file and store the lean result."""
    try:
        data = json.loads(Path(os.path.expanduser(path)).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise AuthError(f"token response file unreadable: {e}")
    if not isinstance(data, dict):
        raise AuthError("token response file must be a JSON object")
    return _accept_token_response({k: data.get(k) for k in ("access_token", "refresh_token", "expires_in", "error")})


def _refresh(refresh_token: str) -> Principal:
    conf = _config()
    fields = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": conf["client_id"]}
    if conf["secret"]:
        fields["client_secret"] = conf["secret"]
    body = _request_json(f"https://{conf['domain']}/oauth/token", fields, secret=refresh_token)
    if "refresh_token" not in body:
        body = dict(body)
        body["refresh_token"] = refresh_token
    return _accept_token_response(body, refresh_token)


def load_principal() -> Principal:
    data = _read_token_file()
    access = data.get("access_token")
    if not isinstance(access, str):
        raise AuthError("token file has no access token")
    try:
        return validate_access_token(access)
    except TokenExpired:
        refresh = data.get("refresh_token")
        if not isinstance(refresh, str) or not refresh:
            raise
        return _refresh(refresh)


def password_login(username: str, password: str) -> Principal:
    """Resource-owner login. Username, then password, are sent only to the token endpoint.

    Auth0 must allow the Password grant on the application. The default realm is
    ``Username-Password-Authentication`` (override with ``AUTH0_REALM``). The
    password is not stored. Echoed error text is stripped of the password and client secret.
    """
    conf = _config()
    username = (username or "").strip()
    if not username or not password:
        raise AuthError("username and password are required")
    scope = os.environ.get("AUTH0_SCOPES") or DEFAULT_SCOPES
    _check_scopes(scope)
    realm = (os.environ.get("AUTH0_REALM") or "Username-Password-Authentication").strip()
    if not realm or len(realm) > 128:
        raise AuthError("AUTH0_REALM is missing or too long")
    fields = {
        "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
        "username": username,
        "password": password,
        "audience": conf["audience"],
        "scope": scope,
        "client_id": conf["client_id"],
        "realm": realm,
    }
    if conf["secret"]:
        fields["client_secret"] = conf["secret"]
    body = _request_json(f"https://{conf['domain']}/oauth/token", fields, secret=password)
    if body.get("error") == "unauthorized_client":
        raise AuthError(
            "Auth0 rejected the password grant for this client. "
            "On the Native app, enable Applications → Settings → Advanced Settings → Grant Types → Password, "
            "then run keyforge setup again. "
            "`keyforge auth login` uses the device-code grant instead."
        )
    return _accept_token_response(body, password)


def device_login(*, prompt=None, sleep=time.sleep) -> Principal:
    """Run the device authorization flow and store a lean access token."""
    conf = _config()
    # Preserve operator-configured order when AUTH0_SCOPES is set; otherwise the default string.
    scope = os.environ.get("AUTH0_SCOPES") or DEFAULT_SCOPES
    _check_scopes(scope)
    prompt = prompt or (lambda message: print(message, file=sys.stderr))
    started = _request_json(f"https://{conf['domain']}/oauth/device/code", {
        "client_id": conf["client_id"], "scope": scope, "audience": conf["audience"],
    })
    if started.get("error") or "device_code" not in started:
        # This message shows ``error`` only. Both fields are scrubbed; the description is dropped.
        error, _description = _error_parts(started)
        raise AuthError("Auth0 device authorization failed: " + (error or "missing device_code"))
    uri = started.get("verification_uri") or started.get("verification_uri_complete") or ""
    prompt(f"Open {uri} and enter code {started.get('user_code')}")
    try:
        interval = int(started.get("interval") or 5)
    except (TypeError, ValueError):
        interval = 5
    interval = min(max(interval, 1), 60)
    try:
        lifetime = int(started.get("expires_in") or 900)
    except (TypeError, ValueError):
        lifetime = 900
    deadline = time.time() + min(max(lifetime, 1), 3600)
    while time.time() < deadline:
        fields = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                  "device_code": started["device_code"], "client_id": conf["client_id"]}
        if conf["secret"]:
            fields["client_secret"] = conf["secret"]
        tok = _request_json(f"https://{conf['domain']}/oauth/token", fields)
        err = tok.get("error")
        if err == "authorization_pending":
            sleep(interval)
            continue
        if err == "slow_down":
            interval += 5
            sleep(interval)
            continue
        if err:
            device_code = started.get("device_code")
            extras = (device_code,) if isinstance(device_code, str) else ()
            error, description = _error_parts(tok, *extras)
            raise AuthError(f"Auth0 token endpoint: {error}: {description}".rstrip(": "))
        return _accept_token_response(tok)
    raise AuthError("device code expired before authorization")


def _wipe_token_file(path: Path) -> None:
    """Overwrite a regular token file in place. A symlink is not followed."""
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return
        remaining = st.st_size
        zeros = b"\0" * 65536
        while remaining:
            n = os.write(fd, zeros[:min(remaining, len(zeros))])
            if n <= 0:
                raise OSError("short write wiping token file")
            remaining -= n
        os.fsync(fd)
    finally:
        os.close(fd)


def logout() -> None:
    """Delete the token file. Contents are overwritten first; a failed wipe still unlinks."""
    path = token_path()
    try:
        _wipe_token_file(path)
    except OSError:
        pass
    try:
        os.remove(path)
    except FileNotFoundError:
        return


def status() -> dict:
    if auth_mode() == "disabled":
        return {"enabled": False}
    try:
        principal = load_principal()
    except AuthError as e:
        return {"enabled": True, "logged_in": False, "reason": str(e),
                "requested_scopes": sorted(requested_scopes())}
    info = {"enabled": True, "logged_in": True, "sub": principal.sub,
            "expires_at": principal.exp}
    info.update(scope_grant(principal))
    return info


def required_scope(args) -> str | None:
    cmd = getattr(args, "cmd", None)
    if cmd in ("auth", "uninstall", "kms", "setup"):
        return None
    if cmd == "policy":
        sub = getattr(args, "policy_cmd", None) or "show"
        return "keys:write" if sub in ("set", "reset") else "keys:read"
    table = {
        "list": "keys:read", "show": "keys:read", "audit": "keys:read", "export": "keys:read",
        "verify": "keys:verify", "serve": "keys:verify", "reveal": "reveal:secret",
        "create": "keys:write", "rotate": "keys:write", "revoke": "keys:write",
        "suspend": "keys:write", "resume": "keys:write", "update": "keys:write",
        "import": "keys:write", "purge": "keys:write",
    }
    if cmd not in table:
        raise AuthError(f"refusing unscoped command {cmd!r} while Auth0 is enabled")
    return table[cmd]


def authorize(args) -> Principal | None:
    """Return the principal when Auth0 is enabled. ``None`` means auth is off."""
    if auth_mode() == "disabled":
        return None
    scope = required_scope(args)
    if scope is None:
        return None
    principal = load_principal()
    if scope not in principal.scopes:
        raise Unauthorized(f"missing scope {scope}")
    return principal
