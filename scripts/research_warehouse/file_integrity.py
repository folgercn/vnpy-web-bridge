"""Stable regular-file reads and durable low-level writes."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

from .errors import RegistryError
from .m2_acl_custody import require_acl_free_fd

MAX_RAW_BYTES = 128 * 1024 * 1024


def file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_uid,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
    )


def read_regular_strict(
    path: Path,
    label: str,
    *,
    limit: int = MAX_RAW_BYTES,
    private: bool = True,
    expected_nlink: int = 1,
    descriptor_validator: Callable[[int], None] | None = None,
) -> bytes:
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise RegistryError(f"{label} must be a regular non-symlink file")
    if path_before.st_nlink != expected_nlink:
        expected = (
            "exactly one hard link"
            if expected_nlink == 1
            else f"exactly {expected_nlink} hard links"
        )
        raise RegistryError(f"{label} must have {expected}")
    if private and (
        path_before.st_uid != os.geteuid()
        or stat.S_IMODE(path_before.st_mode) & 0o077
    ):
        raise RegistryError(f"{label} must be private and owned by current user")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        if private:
            require_acl_free_fd(descriptor, label)
        if descriptor_validator is not None:
            descriptor_validator(descriptor)
        before = os.fstat(descriptor)
        raw = _read_fd(descriptor, limit, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        repeated = _read_fd(descriptor, limit, label)
        after = os.fstat(descriptor)
        path_after = path.lstat()
    except RegistryError:
        raise
    except OSError as exc:
        raise RegistryError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    identities = {
        file_identity(path_before),
        file_identity(before),
        file_identity(after),
        file_identity(path_after),
    }
    if len(identities) != 1 or raw != repeated:
        raise RegistryError(f"{label} changed while being read")
    return raw


def _read_fd(descriptor: int, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise RegistryError(f"{label} exceeds {limit} bytes")
    return raw


def fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]
