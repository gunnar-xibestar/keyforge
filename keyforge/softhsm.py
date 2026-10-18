"""Drop newer SoftHSM tokens that share a label, and keep the oldest.

``softhsm2-util --init-token --free`` adds another token directory. It does
not replace a token that already has that label. PKCS#11 then refuses to log
in (``MultipleTokensReturned``). When the module is SoftHSM, KeyForge deletes
the newer directories under ``directories.tokendir`` and leaves the oldest
``token.object``. A hardware module is left alone.
"""
from __future__ import annotations
import os, shutil, sys
from pathlib import Path

from .errors import KeyForgeError


def setup_instructions(*, no_token: bool = False) -> str:
    """Commands that create a SoftHSM token and its user PIN.

    The SO PIN is only for ``--so-pin``. KeyForge stores the user PIN.
    ``no_token`` adds the note that the label check found nothing.
    """
    groups = [
        "\n".join((
            "SoftHSM setup:",
            "  mkdir -p \"$HOME/.keyforge/softhsm/tokens\"",
            "  printf 'directories.tokendir = %s\\nobjectstore.backend = file\\nlog.level = ERROR\\n' \\",
            "    \"$HOME/.keyforge/softhsm/tokens\" > \"$HOME/.keyforge/softhsm/softhsm2.conf\"",
            "  SOFTHSM2_CONF=\"$HOME/.keyforge/softhsm/softhsm2.conf\" \\",
            "    softhsm2-util --init-token --free --label keyforge --pin \"$PIN\" --so-pin \"$SO_PIN\"",
        )),
        "\n".join((
            "PIN is the user PIN from --init-token --pin. Enter that as KEYFORGE_PKCS11_PIN.",
            "The SO PIN is only for --so-pin. It is not saved.",
        )),
    ]
    if no_token:
        groups.append(
            "That check ran and no token labeled keyforge came up. "
            "Create one with the commands above."
        )
    groups.append("\n".join((
        "The module is often /usr/lib/softhsm/libsofthsm2.so (dpkg -L softhsm2 | grep '\\.so$').",
        "That file is the PKCS#11 library KeyForge loads.",
    )))
    groups.append("\n".join((
        "A hardware token skips softhsm2-util and uses that vendor's .so instead. "
        "That device is not SoftHSM. Point KEYFORGE_PKCS11_MODULE at the library the vendor shipped.",
        "warning: that library runs inside KeyForge. It sees the user PIN and every data key that is wrapped.",
    )))
    return "\n\n".join(groups)


def tokendir(conf_path: str | None) -> Path | None:
    if not conf_path:
        return None
    path = Path(os.path.expanduser(conf_path))
    try:
        text = path.read_text()
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.lower().startswith("directories.tokendir"):
            continue
        _, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if not value:
            return None
        return Path(os.path.expanduser(value))
    return None


def _padded_label(label: str) -> bytes | None:
    raw = label.encode()
    if not raw or len(raw) > 32:
        return None
    return raw + b" " * (32 - len(raw))


def token_object_has_label(data: bytes, label: str) -> bool:
    """True when SoftHSM's token.object stores this label (32 bytes, space padded)."""
    padded = _padded_label(label)
    if padded is None:
        return False
    return (32).to_bytes(8, "big") + padded in data


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def matching_tokens(label: str, conf_path: str | None) -> list[str]:
    """Token directories labeled ``label``, oldest ``token.object`` first.

    An empty list means the config, tokendir, or label is missing. Symlinks
    are skipped.
    """
    root = tokendir(conf_path)
    if root is None or not root.is_dir() or root.is_symlink():
        return []
    matches: list[tuple[int, str]] = []
    try:
        children = list(root.iterdir())
    except OSError as e:
        raise KeyForgeError(f"cannot read SoftHSM tokendir {root}: {e}") from None
    for child in children:
        if not child.is_dir() or child.is_symlink():
            continue
        obj = child / "token.object"
        if not obj.is_file() or obj.is_symlink():
            continue
        if not _inside(root, child):
            continue
        try:
            data = obj.read_bytes()
            mtime = obj.stat().st_mtime_ns
        except OSError:
            continue
        if token_object_has_label(data, label):
            matches.append((mtime, str(child)))
    matches.sort()
    return [path for _, path in matches]


def drop_newer_tokens(label: str, conf_path: str | None) -> list[str]:
    """Delete newer SoftHSM token directories with ``label``. Keep the oldest.

    Age is ``token.object`` mtime. Returns the removed directory paths. Does
    nothing when the config or tokendir is missing, or when fewer than two
    tokens match. Symlinks are skipped.
    """
    matches = matching_tokens(label, conf_path)
    if len(matches) < 2:
        return []
    removed: list[str] = []
    root = tokendir(conf_path)
    for path in matches[1:]:
        target = Path(path)
        if root is None or target.is_symlink() or not _inside(root, target):
            continue
        shutil.rmtree(target)
        removed.append(path)
    if removed:
        kept = matches[0]
        print(
            f"keyforge: removed {len(removed)} newer SoftHSM token(s) labeled {label!r}; "
            f"kept the oldest at {kept}",
            file=sys.stderr,
        )
    return removed
