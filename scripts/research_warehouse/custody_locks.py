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

STABLE_CUSTODY_IDENTITY_DOMAIN = "vnpy-research-warehouse-custody-stable-v2"


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


def legacy_custody_identity_for_device(
    paths: WarehousePaths,
    device: int,
) -> str:
    """Rebuild the exact v1 identity for an explicitly attested device ID."""
    if not isinstance(device, int) or isinstance(device, bool) or device < 0:
        raise RegistryError("legacy custody device ID is invalid")
    info = paths.root.lstat()
    binding = (
        f"{paths.root}|{device}|{info.st_ino}|"
        f"{info.st_uid}|{info.st_gid}|{stat.S_IMODE(info.st_mode):o}"
    ).encode()
    return sha256(binding)


def custody_identity(paths: WarehousePaths) -> str:
    """Return the legacy v1 device-bound identity without changing its bytes."""
    return legacy_custody_identity_for_device(paths, paths.root.lstat().st_dev)


def stable_custody_identity(paths: WarehousePaths) -> str:
    """Return the durable v2 identity; runtime device checks remain separate."""
    info = paths.root.lstat()
    binding = (
        f"{STABLE_CUSTODY_IDENTITY_DOMAIN}|{paths.root}|{info.st_ino}|"
        f"{info.st_uid}|{info.st_gid}|{stat.S_IMODE(info.st_mode):o}"
    ).encode()
    return sha256(binding)
