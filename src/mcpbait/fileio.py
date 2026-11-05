"""Small, auditable file-writing primitives for evidence and client state."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import TextIO


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Atomically replace *path* with UTF-8 text and an explicit file mode."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def existing_mode(path: Path, *, default: int = 0o600) -> int:
    """Return an existing file's permission bits or a secure default."""
    try:
        return stat.S_IMODE(Path(path).stat().st_mode)
    except FileNotFoundError:
        return default


def open_private_append(path: Path) -> TextIO:
    """Open an append-only UTF-8 evidence log without a world-readable race."""
    path = Path(path)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")
