"""Non-blocking single-writer serialization for derived catalog rebuilds."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager

from .derived_paths import DerivedPaths
from .errors import RegistryError
from .file_integrity import file_identity, fsync_dir


@contextmanager
def single_writer_lock(paths: DerivedPaths) -> Iterator[None]:
    path = paths.locks / "catalog-writer.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RegistryError(f"cannot open catalog writer lock: {exc}") from exc
    try:
        path_info = path.lstat()
        info = os.fstat(descriptor)
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
            or file_identity(path_info) != file_identity(info)
        ):
            raise RegistryError("catalog writer lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RegistryError("another catalog writer is active") from exc
        fsync_dir(paths.locks)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
