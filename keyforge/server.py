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

ROUTES = {
    "/health": None,           # no auth
    "/whoami": (),             # any valid key
    "/packets": ("read:packets",),
    "/admin": ("write:packets",),
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
    if method != "GET":
        return 405, {"error": "method not allowed"}
    route = urlparse(path).path
    if route not in ROUTES:
        return 404, {"error": "not found"}
    required = ROUTES[route]
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
        body = {"ok": True, "route": route, "key": {
            "id": key.id, "name": key.name, "prefix": key.prefix, "env": key.env,
            "owner": key.owner, "scopes": key.scopes, "status": key.effective_status(),
        }}
        if scope:
            body["required_scope"] = scope
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
            self._write(405, {"error": "method not allowed"})

    return Handler


def serve(store_path: str, host: str = "127.0.0.1", port: int = 8787) -> int:
    """Block serving until KeyboardInterrupt. Returns 0."""
    httpd = ThreadingHTTPServer((host, port), make_handler(store_path))
    print(f"{BANNER}")
    print(f"demo server listening on http://{host}:{port}")
    print("routes: GET /health (open), GET /whoami (any key), GET /packets (scope read:packets), GET /admin (scope write:packets)")
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
