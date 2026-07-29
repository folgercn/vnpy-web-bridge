"""Single-writer serialization for an independent backup anchor chain."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager

from .backup_custody import BackupPaths
from .custody_paths import SAFE_COMPONENT
from .errors import RegistryError
from .file_integrity import file_identity


@contextmanager
def backup_lock(paths: BackupPaths, key: str) -> Iterator[None]:
    if SAFE_COMPONENT.fullmatch(key) is None:
        raise RegistryError("unsafe backup lock key")
    path = paths.locks / f"{key}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        path_info = path.lstat()
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or opened.st_nlink != 1
            or file_identity(path_info) != file_identity(opened)
        ):
            raise RegistryError("backup lock file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError as exc:
        raise RegistryError("backup lock is unavailable") from exc
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
