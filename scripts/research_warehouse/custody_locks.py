"""Custody serialization and warehouse identity binding."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager

from .canonical import sha256
from .custody_paths import SAFE_COMPONENT, WarehousePaths
from .errors import RegistryError
from .file_integrity import file_identity


@contextmanager
def custody_lock(paths: WarehousePaths, key: str) -> Iterator[None]:
    if SAFE_COMPONENT.fullmatch(key) is None:
        raise RegistryError("unsafe custody lock key")
    path = paths.locks / f"{key}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RegistryError("custody lock file is unavailable or unsafe") from exc
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
            raise RegistryError("custody lock file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def custody_identity(paths: WarehousePaths) -> str:
    info = paths.root.lstat()
    binding = (
        f"{paths.root}|{info.st_dev}|{info.st_ino}|"
        f"{info.st_uid}|{info.st_gid}|{stat.S_IMODE(info.st_mode):o}"
    ).encode()
    return sha256(binding)
