"""Writing received files safely.

A peer chooses the file names. They become paths only through
:func:`safe_relative_path`: every component is cleaned, ``.``/``..`` and
absolute paths are impossible, and the result is checked again against the
target directory after resolving. Files are written to an owner-only temp
file and then linked to a free name, so an existing file is never
overwritten (a name collision gets a `` (1)`` suffix).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import unicodedata
from pathlib import Path, PurePosixPath

MAX_COMPONENT_BYTES = 200
MAX_DEPTH = 8
_FORBIDDEN = set('<>:"|?*')


class UnsafePath(ValueError):
    pass


def _clean_component(part: str) -> str:
    part = unicodedata.normalize("NFC", part)
    cleaned = "".join(
        "_" if (not ch.isprintable() or ch in _FORBIDDEN) else ch for ch in part
    ).strip()
    cleaned = cleaned.rstrip(". ")
    if cleaned in ("", ".", ".."):
        return ""
    if cleaned.startswith("."):
        cleaned = "_" + cleaned[1:]  # no hidden files (.bashrc, .desktop …)
    while len(cleaned.encode("utf-8")) > MAX_COMPONENT_BYTES:
        stem, dot, suffix = cleaned.rpartition(".")
        if dot and 0 < len(suffix) <= 16 and stem:
            cleaned = stem[:-1] + "." + suffix
        else:
            cleaned = cleaned[:-1]
    return cleaned


def safe_relative_path(name: str) -> PurePosixPath:
    """A relative path below the target directory, or UnsafePath."""
    if "\x00" in name:
        raise UnsafePath("NUL in file name")
    parts = [_clean_component(p) for p in name.replace("\\", "/").split("/")]
    # Leading "/", "..", "." and empty components are dropped, never followed.
    parts = [p for p in parts if p]
    if not parts:
        raise UnsafePath("empty file name")
    if len(parts) > MAX_DEPTH:
        parts = parts[-MAX_DEPTH:]
    return PurePosixPath(*parts)


def _ensure_directory(root: Path, relative: PurePosixPath) -> Path:
    """Create the parent directories of ``relative`` below ``root`` without
    following symlinks."""
    current = root
    for part in relative.parent.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafePath("a path component is not a directory")
    return current


def prepare_root(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise UnsafePath("target directory has the wrong owner or type")
    return root.resolve()


def target_parent(root: Path, relative: PurePosixPath) -> Path:
    resolved_root = prepare_root(root)
    parent = _ensure_directory(resolved_root, relative)
    resolved = parent.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise UnsafePath("file name leaves the target directory")
    return resolved


def open_temporary(directory: Path) -> tuple[int, Path]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(16):
        path = directory / f".localsend-{secrets.token_hex(8)}.part"
        try:
            return os.open(path, flags, 0o600), path
        except FileExistsError:
            continue
    raise OSError("no free temporary name")


def _candidates(name: str):
    yield name
    stem, dot, suffix = name.rpartition(".")
    if not dot or not stem:
        stem, suffix = name, ""
    for number in range(1, 10000):
        yield f"{stem} ({number}).{suffix}" if suffix else f"{stem} ({number})"


def commit(temporary: Path, directory: Path, name: str) -> Path:
    """Give the finished temp file a free name; never replace a file."""
    os.chmod(temporary, 0o644)
    for candidate in _candidates(name):
        target = directory / candidate
        try:
            os.link(temporary, target)
        except FileExistsError:
            continue
        temporary.unlink(missing_ok=True)
        return target
    raise OSError("no free file name")


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while block := stream.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def human_size(size: int, *, german: bool = False) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            text = f"{value:.0f} {unit}" if unit in ("B", "KB") or value >= 10 else (
                f"{value:.1f} {unit}"
            )
            return text.replace(".", ",") if german else text
        value /= 1000
    return f"{size} B"
