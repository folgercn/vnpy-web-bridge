"""Cleanup rules that preserve incomplete derived-publication evidence."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import RegistryError
from .file_integrity import fsync_dir


def cleanup_failed_temporary(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_nlink not in (1, 2)
    ):
        raise RegistryError("derived publication temporary object is unsafe")
    if info.st_nlink == 2:
        return
    path.unlink()
    fsync_dir(path.parent)
