"""Demo HTTP server that authenticates only with KeyForge API keys.

NOT FOR PRODUCTION. Loopback by default. Clients send ``Authorization: Bearer kf_...``;
Auth0 is not involved and never sees API-key secrets. Each request opens the store under
its exclusive lock, calls ``service.verify``, then releases — the server does not hold the
store lock while idle.
"""
from __future__ import annotations
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import BANNER, __version__, service as svc
from .errors import VerifyFailed
from .store import Store

# path -> {method: required scopes tuple, or None for open}
ROUTES = {
    "/health": {"GET": None},
    "/whoami": {"GET": ()},
    "/packets": {"GET": ("read:packets",)},
    "/admin": {"GET": ("write:packets",)},
    # Demo of a client attempting to create a secret. Requires API-key scope keys:write.
    # Does not mint a key; real creates use the CLI with Auth0 operator scope keys:write.
    "/keys": {"POST": ("keys:write",)},
    # Success + redact demo: requires read:packets (walkthrough key gets 200) but omits verify
    # output (hash dump, envelope, verified flag). Stronger scope would be needed for those fields.
    "/verify": {"GET": ("read:packets",)},
}


def bearer_secret(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, rest = authorization.strip().partition(" ")
    if scheme.lower() != "bearer" or not rest.strip():
        return None
    return rest.strip()


def client_ip(handler: BaseHTTPRequestHandler) -> str:
    """Prefer X-Forwarded-For only when explicitly trusted; otherwise peer address."""
    return handler.client_address[0]


def dispatch(store_path: str, method: str, path: str, authorization: str | None,
             ip: str | None) -> tuple[int, dict]:
    """Pure request handler used by the HTTP adapter and unit tests."""
    route = urlparse(path).path
    methods = ROUTES.get(route)
    if methods is None:
        return 404, {"error": "not found"}
    if method not in methods:
        return 405, {"error": "method not allowed"}
    required = methods[method]
    if required is None:
        return 200, {"ok": True, "service": "keyforge-demo", "version": __version__}

    secret = bearer_secret(authorization)
    if secret is None:
        return 401, {"error": "missing or invalid Authorization Bearer token"}

    scope = required[0] if required else None
    st = Store(store_path, lock=True)
    try:
        try:
            key = svc.verify(st, secret, scope=scope, ip=ip)
        except VerifyFailed as e:
            return 403, {"error": str(e)}
        if route == "/verify":
            # 200: key is valid for the route. Verify-sensitive fields stay out of the body —
            # read:packets authorizes the call, not a full verify dump (needs a stronger scope).
            return 200, {
                "ok": True,
                "route": route,
                "required_scope": scope,
                "key": {
                    "id": key.id,
                    "name": key.name,
                    "prefix": key.prefix,
                    "env": key.env,
                    "owner": key.owner,
                    "scopes": key.scopes,
                    "status": key.effective_status(),
                },
                "note": (
                    "verify output withheld without a stronger permission "
                    "(e.g. API-key scope keys:verify)"
                ),
            }
        body = {"ok": True, "route": route, "key": {
            "id": key.id, "name": key.name, "prefix": key.prefix, "env": key.env,
            "owner": key.owner, "scopes": key.scopes, "status": key.effective_status(),
        }}
        if scope:
            body["required_scope"] = scope
        if route == "/keys":
            body["created"] = False
            body["note"] = (
                "Demo only: this route checks API-key scope keys:write. "
                "It does not mint a secret. Real creates use `keyforge create` "
                "with Auth0 operator scope keys:write."
            )
        return 200, body
    finally:
        st.close()


def make_handler(store_path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            # Keep demo output short; still show method/path/status via default format.
            super().log_message(fmt, *args)

        def _write(self, status: int, body: dict):
            raw = json.dumps(body, indent=2).encode() + b"\n"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            status, body = dispatch(
                store_path, "GET", self.path,
                self.headers.get("Authorization"),
                client_ip(self),
            )
            self._write(status, body)

        def do_POST(self):
            status, body = dispatch(
                store_path, "POST", self.path,
                self.headers.get("Authorization"),
                client_ip(self),
            )
            self._write(status, body)

    return Handler


def serve(store_path: str, host: str = "127.0.0.1", port: int = 8787) -> int:
    """Block serving until KeyboardInterrupt. Returns 0."""
    httpd = ThreadingHTTPServer((host, port), make_handler(store_path))
    print(f"{BANNER}")
    print(f"demo server listening on http://{host}:{port}")
    print("routes: GET /health (open), GET /whoami (any key), GET /packets (scope read:packets),")
    print("        GET /admin (scope write:packets), POST /keys (scope keys:write; demo only, no mint),")
    print("        GET /verify (scope read:packets; verify output redacted)")
    print("auth:   Authorization: Bearer <kf_... secret>")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
    return 0


class RunningServer:
    """Start ``serve`` on an ephemeral port in a daemon thread (for tests)."""

    def __init__(self, store_path: str, host: str = "127.0.0.1"):
        self.store_path = store_path
        self.host = host
        self.port = None
        self._httpd = None
        self._thread = None

    def __enter__(self):
        self._httpd = ThreadingHTTPServer((self.host, 0), make_handler(self.store_path))
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        return False

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
