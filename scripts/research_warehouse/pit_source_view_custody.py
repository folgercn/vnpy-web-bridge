"""Stable create-only custody for a canonical PIT source view and receipt."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .custody_paths import normalized_absolute
from .errors import RegistryError
from .file_integrity import file_identity, write_all
from .pit_source_view import RECEIPT_FILENAME, SOURCE_VIEW_FILENAME

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _require_private_directory(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RegistryError(f"{label} must be private and current-user-owned")


def _open_bound_directory(path: Path, label: str) -> tuple[int, tuple[int, ...]]:
    absolute = normalized_absolute(path)
    try:
        before = absolute.lstat()
        descriptor = os.open(absolute, DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
        after = absolute.lstat()
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable") from exc
    try:
        for info in (before, opened, after):
            _require_private_directory(info, label)
        identities = {
            _directory_identity(before),
            _directory_identity(opened),
            _directory_identity(after),
        }
        if len(identities) != 1:
            raise RegistryError(f"{label} changed while being opened")
        return descriptor, identities.pop()
    except Exception:
        os.close(descriptor)
        raise


def _read_at(parent_fd: int, name: str, *, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or opened.st_nlink != 1
        ):
            raise RegistryError("published PIT source object custody is unsafe")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise RegistryError("published PIT source object exceeds limit")
        if file_identity(opened) != file_identity(os.fstat(descriptor)):
            raise RegistryError("published PIT source object changed while read")
        return raw
    finally:
        os.close(descriptor)

def _create_at(parent_fd: int, name: str, raw: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(parent_fd)
    if _read_at(parent_fd, name, limit=max(1, len(raw))) != raw:
        raise RegistryError("published PIT source object readback mismatch")


def publish_source_view(
    output_root: Path,
    directory_id: str,
    *,
    source_view_raw: bytes,
    receipt_raw: bytes,
) -> Path:
    if "/" in directory_id or directory_id in {"", ".", ".."}:
        raise RegistryError("PIT source-view directory ID is unsafe")
    root_fd, root_identity = _open_bound_directory(output_root, "PIT output root")
    output_fd: int | None = None
    try:
        try:
            os.mkdir(directory_id, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError as exc:
            raise RegistryError("PIT source view already exists; overwrite forbidden") from exc
        output_fd = os.open(directory_id, DIRECTORY_FLAGS, dir_fd=root_fd)
        output_identity = _directory_identity(os.fstat(output_fd))
        _require_private_directory(os.fstat(output_fd), "PIT source-view directory")
        _create_at(output_fd, SOURCE_VIEW_FILENAME, source_view_raw)
        _create_at(output_fd, RECEIPT_FILENAME, receipt_raw)
        if (
            _directory_identity(output_root.lstat()) != root_identity
            or _directory_identity(
                os.stat(directory_id, dir_fd=root_fd, follow_symlinks=False)
            )
            != output_identity
        ):
            raise RegistryError("PIT source-view directory identity changed")
        os.fsync(output_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise RegistryError("PIT source-view publication failed closed") from exc
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(root_fd)
    return output_root / directory_id


def read_source_view(output: Path) -> tuple[bytes, bytes]:
    descriptor, identity = _open_bound_directory(output, "PIT source-view directory")
    try:
        if set(os.listdir(descriptor)) != {SOURCE_VIEW_FILENAME, RECEIPT_FILENAME}:
            raise RegistryError("PIT source-view file set mismatch")
        source = _read_at(descriptor, SOURCE_VIEW_FILENAME, limit=4 * 1024 * 1024)
        receipt = _read_at(descriptor, RECEIPT_FILENAME, limit=8 * 1024 * 1024)
        if _directory_identity(output.lstat()) != identity:
            raise RegistryError("PIT source-view directory changed while read")
        return source, receipt
    finally:
        os.close(descriptor)
