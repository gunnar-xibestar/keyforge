"""Interactive boot: KMS provider, optional Auth0, then username and password.

Writes ``~/.keyforge/keyforge.env`` (mode 0600). Later commands apply that
file over any same-named variables inherited from the shell. The Auth0
password is never written there.
"""
from __future__ import annotations
import os, secrets, shlex, shutil, stat, sys
from datetime import datetime
from pathlib import Path

from . import audit, auth
from .errors import AuthError, KeyForgeError
from .store import Store, resolve_path
from .kms import (
    confirm_user_pin, destroy_aes_labels, format_status, list_aes_labels, status as kms_status,
)
from .softhsm import delete_token, init_token, matching_tokens

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


def _default_module() -> str:
    return os.environ.get("KEYFORGE_PKCS11_MODULE") or "/usr/lib/softhsm/libsofthsm2.so"


def _default_conf() -> str:
    return os.environ.get("SOFTHSM2_CONF") or os.path.expanduser("~/.keyforge/softhsm/softhsm2.conf")


def _check_module(echo, module: str) -> None:
    if os.path.isfile(module) and not os.path.islink(module):
        return
    echo(f"PKCS#11 module not found or unusable at {module}")


def _check_softhsm_util(echo) -> None:
    if shutil.which("softhsm2-util"):
        return
    echo("softhsm2-util is not on PATH")


def _local_key_path(chosen: str) -> str:
    if chosen:
        return os.path.expanduser(chosen)
    base = os.path.expanduser(os.environ.get("KEYFORGE_STORE") or "~/.keyforge/store.json")
    return str(Path(base).parent / "kms-master.key")


def _verify_local(echo, key_path: str) -> None:
    echo("local — software KEK. A software AES-256 key file, mode 0600.")
    echo(f"default key: <store-dir>/kms-master.key ({key_path})")
    problems = []
    try:
        import cryptography  # noqa: F401
    except ImportError:
        problems.append("cryptography is not installed")
    if os.path.lexists(key_path):
        if os.path.islink(key_path) or not os.path.isfile(key_path):
            problems.append(f"{key_path} is not a regular file")
        else:
            mode = stat.S_IMODE(os.stat(key_path).st_mode)
            if mode != 0o600:
                problems.append(f"{key_path} mode is {oct(mode)}; expected 0600")
    if problems:
        echo("result: failure")
        for problem in problems:
            echo(f"  {problem}")
        return
    echo("result: success")
    echo("  cryptography is installed")
    if os.path.isfile(key_path):
        echo(f"  key file: {key_path}")
    else:
        echo("  key file is not created yet; the first wrap will create it")


def _read_pin(read_secret, echo, prompt: str) -> str:
    while True:
        pin = read_secret(prompt)
        if pin:
            return pin
        echo("input blank")


def _pin_opens(echo, module: str, token: str, pin: str) -> bool:
    """True when ``pin`` opens the token. A wrong PIN prints the Ctrl-C hint and returns False.

    Any other failure is printed and re-raised so setup does not save that PIN.
    """
    try:
        confirm_user_pin(module, token, pin)
    except KeyForgeError as e:
        echo(str(e))
        if "PIN is wrong" in str(e):
            if not sys.stdin.isatty():
                raise KeyForgeError("no terminal") from None
            return False
        raise
    return True


def _create_token(read_secret, echo, conf: str, module: str) -> str:
    """Ask for the user PIN and SO PIN and create the token. Returns the user PIN."""
    while True:
        pin = _read_pin(read_secret, echo, "KEYFORGE_PKCS11_PIN: ")
        so_pin = _read_pin(read_secret, echo, "KEYFORGE_PKCS11_SO_PIN: ")
        try:
            init_token(conf, "keyforge", pin, so_pin)
        except KeyForgeError as e:
            echo(str(e))
            echo("Ctrl-C to exit.")
            if not sys.stdin.isatty():
                raise
            continue
        if _pin_opens(echo, module, "keyforge", pin):
            return pin
        if not sys.stdin.isatty():
            raise KeyForgeError("no terminal")


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


def _token_menu(read_line, echo, paths: list[str], conf: str) -> bool:
    """Let the operator delete any token except the oldest. Return True to reuse main.

    False means create another token. Tokens are oldest first.
    """
    remaining = list(paths)
    while True:
        echo(f"Found {len(remaining)} existing tokens labeled 'keyforge'.")
        for i, path in enumerate(remaining, start=1):
            obj = Path(path) / "token.object"
            stamp = datetime.fromtimestamp(obj.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            role = "main" if i == 1 else "other"
            echo(f"  {i}. {role}  {stamp}  {path}")
        echo("Reuse uses oldest token. (main)")
        echo("Create runs --init-token again, which adds another token with a new label.")
        echo("warning: each token uses a slot, and SoftHSM has a limited number of slots.")
        choice = _ask(read_line, "Select a number to delete, c to create, or Enter to reuse main: ")
        if not choice:
            return True
        if choice.lower() == "c":
            return False
        if choice == "1":
            echo("The main token cannot be deleted.")
            continue
        if choice.isdigit() and 1 < int(choice) <= len(remaining):
            target = remaining[int(choice) - 1]
            removed = delete_token(target, conf, label="keyforge")
            if removed:
                echo(f"deleted {removed}")
                remaining.pop(int(choice) - 1)
            if len(remaining) == 1:
                echo("Reuse uses oldest token. (main)")
                return True
            continue
        echo("That number is not a token in this list.")


def _aes_key_menu(read_line, echo, labels: list[str], protected: str, delete) -> str:
    """Select one AES key, or delete any key except ``protected``.

    A bare number selects that key. ``d`` plus a number deletes it.
    Enter keeps ``protected`` when it is still in the list.
    ``delete`` removes labels and returns those removed.
    """
    remaining = list(labels)
    while True:
        echo("AES keys on the token:")
        for i, name in enumerate(remaining, start=1):
            note = " (cannot be deleted)" if name == protected else ""
            echo(f"  {i}. {name}{note}")
        if len(remaining) == 1 and remaining[0] == protected:
            echo(f"Key label: {protected}")
            return protected
        choice = _ask(
            read_line,
            f"Select a number, d <number> to delete, or Enter to keep {protected}: ",
        )
        if not choice:
            if protected in remaining:
                echo(f"Key label: {protected}")
                return protected
            echo(f"Key label: {remaining[0]}")
            return remaining[0]
        delete_choice = choice.lower().startswith("d")
        number = choice[1:].strip() if delete_choice else choice
        if not number.isdigit() or not 1 <= int(number) <= len(remaining):
            echo("That number is not a key in this list.")
            continue
        name = remaining[int(number) - 1]
        if not delete_choice:
            echo(f"Key label: {name}")
            return name
        if name == protected:
            echo(f"{protected} cannot be deleted.")
            continue
        for removed in delete([name]):
            echo(f"deleted {removed}")
            if removed in remaining:
                remaining.remove(removed)


def _yes(read_line, prompt: str, *, default: bool = False) -> bool:
    ans = _ask(read_line, prompt).lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def _audit_chain(echo, saved: dict) -> None:
    """Verify the audit hash chain, start it when metadata is missing, and create an HMAC key file."""
    path = resolve_path(None)
    echo("")
    echo("Audit chain")
    echo("-----------")
    echo("")
    echo(f"store: {path}")
    echo("")
    key_created = False
    key_path_was_unset = False
    hmac_was_enabled = False
    with Store(path) as st:
        if st.data.get("audit_meta") is None:
            echo("audit metadata is absent.")
            echo("")
            try:
                ev = audit.adopt_legacy(st)
                st.save()
            except KeyForgeError as e:
                echo(f"audit chain was not created: {e}")
                echo("Events already in this log cannot be checked for tampering.")
                echo("")
            else:
                n = ev["details"]["legacy"]
                echo(f"audit chain started; {n} legacy event(s) recorded as unprotected.")
                echo("A legacy event has no prev_hash or hash. Changing it or deleting it is not detected.")
                echo("")
        key_file = os.environ.get("KEYFORGE_AUDIT_HMAC_KEY_FILE", "").strip()
        if not key_file:
            key_path_was_unset = True
            key_file = str(path.parent / "audit-hmac.key")
            saved["KEYFORGE_AUDIT_HMAC_KEY_FILE"] = key_file
            os.environ["KEYFORGE_AUDIT_HMAC_KEY_FILE"] = key_file
        key_file = os.path.expanduser(key_file)
        if not os.path.lexists(key_file):
            os.makedirs(os.path.dirname(key_file) or ".", mode=0o700, exist_ok=True)
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, secrets.token_bytes(32))
            finally:
                os.close(fd)
            key_created = True
            echo(f"audit HMAC key created: {key_file}")
            echo("")
            if key_path_was_unset:
                echo("No KEYFORGE_AUDIT_HMAC_KEY_FILE was set, and no key file existed at the default path.")
            else:
                echo("KEYFORGE_AUDIT_HMAC_KEY_FILE pointed at a path with no key file yet.")
            echo("Setup created one (32 random bytes, mode 0600).")
            echo("Later setups reuse this file when it still exists; they do not mint a new secret each run.")
            echo("")
        else:
            echo(f"audit HMAC key found: {key_file}")
            echo("Reusing the existing secret. Setup does not create a new HMAC key when this file is present.")
            echo("")
        try:
            key = audit.hmac_key()
        except KeyForgeError as e:
            echo(f"audit HMAC key is unusable: {e}")
            echo("")
            key = None
        meta = st.data.get("audit_meta") or {}
        hmac_was_enabled = bool(meta.get("mac"))
        if key and meta and "mac" not in meta:
            audit.record(st, "audit_hmac_enabled")
            st.save()
            echo("A new audit event was written so the metadata MAC starts at this event.")
            echo("Events before it have no MAC. Rebuilding their hashes is not detected as tampering.")
            echo("")
        r = audit.verify_chain(st.audit_log, st.data.get("audit_meta"), key)
    if r["ok"]:
        line = f"audit chain OK: {r['checked']} chained event(s), count {r['count']}, head {r['head']}"
        if r["mac_verified"]:
            line += ", MAC verified"
        echo(line)
        if r["legacy"]:
            echo(f"{r['legacy']} legacy event(s) have no hash. Tampering with those events is not detected.")
        echo("")
    else:
        echo(f"AUDIT CHAIN BROKEN: {r['error']}")
        echo("")
    found_working = bool(key and r["ok"] and r["mac_verified"] and not key_created and hmac_was_enabled)
    next_to_store = (
        os.path.dirname(os.path.abspath(key_file)) == os.path.abspath(path.parent)
    )
    if found_working:
        echo("HMAC: on, verified, working")
        echo("")
        echo(f"  secret: {key_file}")
        echo(f"  chain: {r['checked']} chained event(s), count {r['count']}, head {r['head']}")
        if r["legacy"]:
            echo(f"  legacy: {r['legacy']} event(s) have no hash or MAC")
        echo("")
        echo("  audit --verify will check both the hash chain and the HMAC tags.")
        echo("")
        echo("The MAC detects a rewritten store only when the writer cannot read the HMAC key file.")
        if next_to_store:
            echo("This file is next to the store. Anyone who can read that directory can forge a chain that still verifies.")
    elif key and r["ok"] and r["mac_verified"]:
        echo("HMAC: on and verified for new events")
        echo("")
        echo(f"  secret: {key_file}")
        echo(f"  chain: {r['checked']} chained event(s), count {r['count']}, head {r['head']}")
        echo("")
        if key_created:
            echo("warning: a new HMAC key was created because none was found at that path.")
            echo("Keep this file. The next setup reuses it instead of creating another.")
            echo("")
            echo("If this secret is deleted later, audit --verify fails until it is restored — the chain already has MACs.")
            echo("")
        echo("The MAC detects a rewritten store only when the writer cannot read the HMAC key file.")
        if next_to_store:
            echo("This file is next to the store. Anyone who can read that directory can forge a chain that still verifies.")
    else:
        echo("warning: HMAC is not verifying the audit chain.")
        echo("")
        if not key:
            echo("No usable HMAC secret was found.")
            echo("")
        echo("If the audit chain already has MACs, audit --verify fails until KEYFORGE_AUDIT_HMAC_KEY_FILE points at the matching secret.")
        echo("If the chain never had MACs, verify stays unkeyed until a secret is enabled.")


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
        hint = _PROVIDER_TEXT[name].splitlines()[0]
        echo(f"    {hint}")
    echo("")
    choice = _ask(read_line, "KEYFORGE_KMS_PROVIDER [local]: ").lower() or "local"
    if choice not in _PROVIDERS:
        raise KeyForgeError(f"unknown KEYFORGE_KMS_PROVIDER {choice!r}; choose from {', '.join(_PROVIDERS)}")
    saved: dict[str, str] = {"KEYFORGE_KMS_PROVIDER": choice}
    echo("")
    if choice == "memory":
        echo(f"selected: {choice}")
        echo(_PROVIDER_TEXT[choice])
        echo("")

    if choice == "local":
        echo(f"selected: {choice}")
        echo("Leave blank to keep the key at <store-dir>/kms-master.key.")
        echo("Find the store with: echo \"${KEYFORGE_STORE:-$HOME/.keyforge/store.json}\"")
        key_file = _ask(read_line, "KEYFORGE_KMS_KEY_FILE (outside the store directory) []: ")
        if key_file:
            saved["KEYFORGE_KMS_KEY_FILE"] = key_file
        _verify_local(echo, _local_key_path(key_file))
        echo("")
    elif choice == "pkcs11":
        module = _default_module()
        _check_module(echo, module)
        _check_softhsm_util(echo)
        conf = _default_conf()
        existing = matching_tokens("keyforge", conf)
        if not existing:
            echo(_PROVIDER_TEXT["pkcs11"])
            echo("")
            echo(f"No existing token labeled 'keyforge' in {conf}.")
            conf = _ask(read_line, f"SOFTHSM2_CONF [{conf}]: ") or conf
            existing = matching_tokens("keyforge", conf)
        if len(existing) == 1:
            echo("Found 1 existing token labeled 'keyforge'.")
            echo(f"  oldest: {existing[0]}")
            echo("Reuse uses oldest token. (main)")
            reuse = True
        elif existing:
            reuse = _token_menu(read_line, echo, existing, conf)
        else:
            reuse = False
        echo("")
        token = "keyforge"
        if reuse:
            echo("Token label: keyforge")
            echo("PIN is the token user PIN from softhsm2-util --init-token --pin, not the SO PIN.")
            while True:
                pin = _read_pin(read_secret, echo, "KEYFORGE_PKCS11_PIN: ")
                if _pin_opens(echo, module, token, pin):
                    break
        else:
            pin = _create_token(read_secret, echo, conf, module)
        echo(f"SOFTHSM2_CONF: {conf}")
        saved_pin = pin
        aes_labels = list_aes_labels(module, token, saved_pin)
        asked_label = False
        if aes_labels:
            label = _aes_key_menu(
                read_line, echo, aes_labels, "keyforge-kek",
                lambda names: destroy_aes_labels(module, token, saved_pin, names),
            )
        else:
            label = _ask(read_line, "KEYFORGE_PKCS11_KEY_LABEL [keyforge-kek]: ") or "keyforge-kek"
            asked_label = True
            aes_labels = list_aes_labels(module, token, pin)
            if aes_labels is not None and label not in aes_labels and aes_labels:
                removed = destroy_aes_labels(module, token, pin, aes_labels)
                for name in removed:
                    echo(f"deleted {name}")
            elif aes_labels is not None and label in aes_labels:
                label = _aes_key_menu(
                    read_line, echo, aes_labels, label,
                    lambda names: destroy_aes_labels(module, token, pin, names),
                )
        if asked_label and aes_labels is not None and label in aes_labels:
            echo("The new key label you just entered will only be a name. On the first create, rotate, or reveal, if no AES key has that name, KeyForge generates a new one.")
            echo("warning: a new key cannot read secrets wrapped by an older key. The label is only a name. The old key material is not in the new key.")
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
        for key, value in saved.items():
            os.environ[key] = value
        info = auth.status()
        _audit_chain(echo, saved)
        path = _write_env(saved)
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
        echo("Leave Enable RBAC off. Turn off Add Permissions in the Access Token.")
        echo("With RBAC off, Auth0 puts those requested permissions into the scope claim. A user or role assignment is not required.")
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
    login = login or auth.password_login
    while True:
        password = read_secret("password: ")
        try:
            principal = login(username, password)
            break
        except AuthError as e:
            message = str(e)
            rejected = "invalid_grant" in message
            if not rejected:
                raise
            echo("password failed. Ctrl-C to exit.")
            if not sys.stdin.isatty():
                raise KeyForgeError("no terminal") from None
    _audit_chain(echo, saved)
    path = _write_env(saved)
    echo("")
    echo("result: success")
    echo(f"  logged in as {principal.sub}")
    echo(f"saved: {path}")
    _marks(echo, 5)
    return {"kms_provider": choice, "auth": {"logged_in": True, "sub": principal.sub}, "env_file": str(path), "sub": principal.sub}
