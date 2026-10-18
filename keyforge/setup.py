"""Interactive boot: KMS provider, optional Auth0, then username and password.

Writes ``~/.keyforge/keyforge.env`` (mode 0600). Later commands apply that
file over any same-named variables inherited from the shell. The Auth0
password is never written there.
"""
from __future__ import annotations
import os, shlex, stat
from pathlib import Path

from . import auth
from .errors import AuthError, KeyForgeError
from .kms import format_status, status as kms_status
from .softhsm import drop_newer_tokens, matching_tokens

_PROVIDERS = ("local", "pkcs11", "memory")

_BANNER = r"""
 _  __          _____
| |/ /___ _   _|  ___|__  _ __ __ _  ___
| ' // _ \ | | | |_ / _ \| '__/ _` |/ _ \
| . \  __/ |_| |  _| (_) | | | (_| |  __/
|_|\_\___|\__, |_|  \___/|_|  \__, |\___|
          |___/               |___/
""".strip("\n")

_PROVIDER_TEXT = {
    "local": (
        "local — software KEK. A 32-byte file, mode 0600. "
        "Unset KEYFORGE_KMS_KEY_FILE uses <store-dir>/kms-master.key "
        "(default ~/.keyforge/kms-master.key, next to ~/.keyforge/store.json). "
        "Anyone who can read that file and the store can reveal secrets. "
        "Put KEYFORGE_KMS_KEY_FILE outside the store directory for a separate permission boundary."
    ),
    "pkcs11": "\n".join((
        "pkcs11 — AES key stays on the token and is not exported.",
        "",
        "Module: KEYFORGE_PKCS11_MODULE",
        "  SoftHSM is often /usr/lib/softhsm/libsofthsm2.so",
        "  dpkg -L softhsm2 | grep '\\.so$'",
        "",
        "Token label: KEYFORGE_PKCS11_TOKEN",
        "  softhsm2-util --show-slots",
        "",
        "User PIN: KEYFORGE_PKCS11_PIN",
        "  the PIN from --init-token, not the SO PIN",
        "",
        "Key label: KEYFORGE_PKCS11_KEY_LABEL",
        "",
        "SOFTHSM2_CONF",
        "  the softhsm2.conf whose tokendir you created",
    )),
    "memory": (
        "memory — replaces pkcs11 and local for unit tests. "
        "The key lives in the process (KEYFORGE_KMS_MEMORY_KEY may pin 64 hex chars). "
        "Envelopes cannot be opened after the process exits."
    ),
}


def env_path() -> Path:
    return Path(os.path.expanduser(os.environ.get("KEYFORGE_ENV_FILE") or "~/.keyforge/keyforge.env"))


def load_env_file(path: Path | None = None) -> None:
    """Apply every KEY=VALUE in the file, replacing a value inherited from the shell."""
    path = path or env_path()
    try:
        text = path.read_text()
    except FileNotFoundError:
        return
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line, posix=True)
        except ValueError:
            continue
        if not parts:
            continue
        token = parts[0]
        if token == "export":
            if len(parts) != 2:
                continue
            token = parts[1]
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if not key:
            continue
        os.environ[key] = value


def _write_env(values: dict[str, str]) -> Path:
    path = env_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = [
        "# KeyForge boot config. Applied over inherited environment variables.",
        "# The Auth0 password is not stored here.",
    ]
    for key, value in values.items():
        if value is None or value == "":
            continue
        lines.append(f"export {key}={shlex.quote(value)}")
    lines.append("")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, ("\n".join(lines)).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
        raise KeyForgeError(f"{path} must not be group/world accessible")
    return path


def _marks(echo, n: int) -> None:
    for _ in range(n):
        echo("'")


def _ask(read_line, prompt: str) -> str:
    return read_line(prompt).strip()


def _echo_kms_status(echo, saved: dict[str, str]) -> None:
    """Print ``keyforge kms status`` for the provider just configured. Does not abort setup."""
    previous = {key: os.environ.get(key) for key in saved}
    os.environ.update(saved)
    try:
        lines = format_status(kms_status())
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
    echo("")
    echo("kms status")
    for line in lines:
        echo(line)


def _yes(read_line, prompt: str, *, default: bool = False) -> bool:
    ans = _ask(read_line, prompt).lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def run(*, read_line, read_secret, echo, login=None) -> dict:
    """Prompt for KMS, then Auth0. ``login`` defaults to ``auth.password_login``."""
    _marks(echo, 3)
    echo("")
    for line in _BANNER.splitlines():
        echo(line)
    echo("")
    echo("KMS provider (KEYFORGE_KMS_PROVIDER). Setup saves the answer; a bare assignment in a file is not enough.")
    echo("")
    for i, name in enumerate(_PROVIDERS):
        if i:
            echo("")
        echo(f"  {name}")
        for line in _PROVIDER_TEXT[name].splitlines():
            echo(f"    {line}" if line else "")
    echo("")
    choice = _ask(read_line, "KEYFORGE_KMS_PROVIDER [local]: ").lower() or "local"
    if choice not in _PROVIDERS:
        raise KeyForgeError(f"unknown KEYFORGE_KMS_PROVIDER {choice!r}; choose from {', '.join(_PROVIDERS)}")
    saved: dict[str, str] = {"KEYFORGE_KMS_PROVIDER": choice}
    echo("")
    echo(f"selected: {choice}")
    echo(_PROVIDER_TEXT[choice])
    echo("")

    if choice == "local":
        echo("Leave blank to keep the key at <store-dir>/kms-master.key.")
        echo("Find the store with: echo \"${KEYFORGE_STORE:-$HOME/.keyforge/store.json}\"")
        key_file = _ask(read_line, "KEYFORGE_KMS_KEY_FILE (outside the store directory) []: ")
        if key_file:
            saved["KEYFORGE_KMS_KEY_FILE"] = key_file
    elif choice == "pkcs11":
        echo("Create a new token:")
        echo("  mkdir -p \"$HOME/.keyforge/softhsm/tokens\"")
        echo("  printf 'directories.tokendir = %s\\nobjectstore.backend = file\\nlog.level = ERROR\\n' \\")
        echo("    \"$HOME/.keyforge/softhsm/tokens\" > \"$HOME/.keyforge/softhsm/softhsm2.conf\"")
        echo("  SOFTHSM2_CONF=\"$HOME/.keyforge/softhsm/softhsm2.conf\" \\")
        echo("    softhsm2-util --init-token --free --label keyforge --pin \"$PIN\" --so-pin \"$SO_PIN\"")
        echo("")
        echo("The module is often /usr/lib/softhsm/libsofthsm2.so (dpkg -L softhsm2 | grep '\\.so$').")
        echo("A hardware token skips softhsm2-util and uses that vendor's .so instead.")
        echo("")
        default_conf = os.environ.get("SOFTHSM2_CONF") or os.path.expanduser("~/.keyforge/softhsm/softhsm2.conf")
        existing = matching_tokens("keyforge", default_conf)
        if existing:
            echo(f"Found {len(existing)} existing token(s) labeled 'keyforge'.")
            echo(f"  oldest: {existing[0]}")
            echo("Reuse keeps that oldest token. Newer tokens with the same label are deleted.")
            echo("Create runs --init-token again, which adds another token with that label.")
            reuse = _yes(read_line, "Reuse the oldest token? [Y/n] ", default=True)
        else:
            echo(f"No existing token labeled 'keyforge' in {default_conf}.")
            reuse = False
        if not reuse:
            _ask(read_line, "Press Enter when the new token exists: ")
        echo("")
        module = _ask(read_line, "KEYFORGE_PKCS11_MODULE [/usr/lib/softhsm/libsofthsm2.so]: ") or "/usr/lib/softhsm/libsofthsm2.so"
        token = _ask(read_line, "KEYFORGE_PKCS11_TOKEN [keyforge]: ") or "keyforge"
        echo("PIN is the token user PIN from softhsm2-util --init-token --pin, not the SO PIN.")
        pin = read_secret("KEYFORGE_PKCS11_PIN: ")
        if not pin:
            raise KeyForgeError("KEYFORGE_PKCS11_PIN is required for pkcs11")
        label = _ask(read_line, "KEYFORGE_PKCS11_KEY_LABEL [keyforge-kek]: ") or "keyforge-kek"
        if reuse:
            echo("warning: reuse deletes newer SoftHSM tokens with this label and keeps the oldest. Secrets wrapped by a deleted token cannot be opened.")
        echo("A missing AES key is generated on the token the first time it is used.")
        echo("warning: a new key cannot read secrets wrapped by an older key. The label is only a name. The old key material is not in the new key.")
        conf = _ask(read_line, f"SOFTHSM2_CONF [{default_conf}]: ") or default_conf
        if reuse and "softhsm" in os.path.basename(module).lower():
            removed = drop_newer_tokens(token, conf)
            if removed:
                echo(f"removed {len(removed)} newer token(s) labeled {token!r}; kept the oldest")
        saved.update({
            "KEYFORGE_PKCS11_MODULE": module,
            "KEYFORGE_PKCS11_TOKEN": token,
            "KEYFORGE_PKCS11_PIN": pin,
            "KEYFORGE_PKCS11_KEY_LABEL": label,
            "SOFTHSM2_CONF": conf,
        })

    _echo_kms_status(echo, saved)

    echo("")
    existing_auth = {name: os.environ.get(name, "").strip() for name in (
        "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_AUDIENCE")}
    if all(existing_auth.values()):
        echo("Auth0 is already configured. These saved values are kept.")
        echo("Unset AUTH0_DOMAIN to enter different values.")
        echo("")
        for name, value in existing_auth.items():
            echo(f"  {name}: {value}")
        echo("")
        echo("result: success")
        echo("  AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_AUDIENCE are set.")
        saved.update(existing_auth)
        for key, value in saved.items():
            os.environ[key] = value
    elif not _yes(read_line, "Set up Auth0 now? [Y/n] ", default=True):
        echo("")
        echo("warning: Auth0 is necessary for the demo. Skipping it leaves operator login disabled.")
        echo("warning: Auth0 is not set up. Every command trusts the OS user.")
        echo("warning: there is no operator scope gate. Anyone who can run keyforge as this user can create, reveal, and delete keys.")
        echo("warning: turn it on later with `keyforge setup` after creating a Native app and an API in the Auth0 dashboard.")
        path = _write_env(saved)
        for key, value in saved.items():
            os.environ[key] = value
        info = auth.status()
        echo("")
        echo("result: success")
        echo("  saved the KMS choice. Auth0 was skipped.")
        echo(f"saved: {path}")
        _marks(echo, 5)
        return {"kms_provider": choice, "auth": info, "env_file": str(path)}
    else:
        echo("")
        echo("")
        echo("Auth0 dashboard (https://manage.auth0.com):")
        echo("")
        for name, hint in (
            ("AUTH0_DOMAIN", "Settings → Domain. Hostname only, no https://"),
            ("AUTH0_CLIENT_ID", "Applications → your Native app → Settings → Client ID"),
            ("AUTH0_AUDIENCE", "Applications → APIs → your API → Settings → Identifier"),
        ):
            echo(f"  {name}")
            echo(f"    {hint}")
            echo("")
        echo("Enable the Password grant (and Device Code if you still use `auth login`) on that Native app.")
        echo("")
        echo("API Permissions: keys:read keys:write keys:verify reveal:secret")
        echo("")
        domain = _ask(read_line, "AUTH0_DOMAIN: ")
        echo("")
        client_id = _ask(read_line, "AUTH0_CLIENT_ID: ")
        echo("")
        audience = _ask(read_line, "AUTH0_AUDIENCE [https://keyforge.local/api]: ") or "https://keyforge.local/api"
        if not domain or not client_id or not audience:
            raise AuthError("Auth0 requires AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_AUDIENCE")
        saved.update({
            "AUTH0_DOMAIN": domain,
            "AUTH0_CLIENT_ID": client_id,
            "AUTH0_AUDIENCE": audience,
        })
        for key, value in saved.items():
            os.environ[key] = value

    echo("")
    echo("")
    echo("Login. Username first, then password.")
    echo("")
    echo("Username is the database user (User Management → Users), usually the email. It is not the Client ID.")
    echo("")
    echo("Password is that user's password. It is not the Client Secret and it is not written to disk.")
    echo("")
    username = _ask(read_line, "username: ")
    echo("")
    password = read_secret("password: ")
    login = login or auth.password_login
    principal = login(username, password)
    path = _write_env(saved)
    echo("")
    echo("result: success")
    echo(f"  logged in as {principal.sub}")
    echo(f"saved: {path}")
    _marks(echo, 5)
    return {"kms_provider": choice, "auth": {"logged_in": True, "sub": principal.sub}, "env_file": str(path), "sub": principal.sub}
