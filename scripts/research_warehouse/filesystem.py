"""Strict filesystem custody and create-only publication."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256
from .errors import RegistryError

MAX_RAW_BYTES = 128 * 1024 * 1024
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
LAYOUT_DIRS = ("raw", "observations", "manifests", "tmp", "locks")


@dataclass(frozen=True)
class WarehousePaths:
    root: Path
    raw: Path
    observations: Path
    manifests: Path
    temporary: Path
    locks: Path

    @classmethod
    def initialize(cls, root: Path) -> WarehousePaths:
        absolute = _normalized_absolute(root)
        if absolute.exists():
            raise RegistryError(f"warehouse root already exists: {absolute}")
        absolute.mkdir(mode=0o700)
        _fsync_dir(absolute.parent)
        for name in LAYOUT_DIRS:
            (absolute / name).mkdir(mode=0o700)
            _fsync_dir(absolute / name)
            _fsync_dir(absolute)
        _fsync_dir(absolute)
        return cls.open(absolute)

    @classmethod
    def open(cls, root: Path) -> WarehousePaths:
        absolute = _normalized_absolute(root)
        _require_private_dir(absolute, "warehouse root")
        values = {name: absolute / name for name in LAYOUT_DIRS}
        for name, path in values.items():
            _require_private_dir(path, f"warehouse {name} directory")
        devices = {absolute.lstat().st_dev}
        devices.update(path.lstat().st_dev for path in values.values())
        if len(devices) != 1:
            raise RegistryError("warehouse layout must be on one filesystem")
        return cls(
            root=absolute,
            raw=values["raw"],
            observations=values["observations"],
            manifests=values["manifests"],
            temporary=values["tmp"],
            locks=values["locks"],
        )

    def private_subdir(self, base: Path, *components: str) -> Path:
        if base not in {
            self.raw,
            self.observations,
            self.manifests,
            self.temporary,
            self.locks,
        }:
            raise RegistryError("subdirectory base is outside warehouse layout")
        current = base
        for component in components:
            if SAFE_COMPONENT.fullmatch(component) is None:
                raise RegistryError(f"unsafe custody path component: {component}")
            parent = current
            current /= component
            created = False
            try:
                current.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            _require_private_dir(current, "custody subdirectory")
            if created:
                _fsync_dir(current)
                _fsync_dir(parent)
        return current


def _normalized_absolute(path: Path) -> Path:
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    normalized = Path(os.path.normpath(str(absolute)))
    if normalized != absolute:
        raise RegistryError("warehouse path must already be normalized")
    return absolute


def _require_private_dir(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RegistryError(f"{label} must be a non-symlink directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RegistryError(f"{label} must be private and owned by current user")
    return info


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
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
) -> bytes:
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise RegistryError(f"{label} must be a regular non-symlink file")
    if path_before.st_nlink != 1:
        raise RegistryError(f"{label} must have exactly one hard link")
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
        _file_identity(path_before),
        _file_identity(before),
        _file_identity(after),
        _file_identity(path_after),
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


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_publish_temps(
    temporary_dir: Path,
    path: Path,
) -> None:
    prefix = f".publish-{path.name}-"
    changed = False
    for candidate in temporary_dir.iterdir():
        if not candidate.name.startswith(prefix) or not candidate.name.endswith(
            ".partial"
        ):
            continue
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RegistryError("metadata publish temporary object is unsafe")
        candidate.unlink()
        changed = True
    if changed:
        _fsync_dir(temporary_dir)


def create_only_bytes(
    path: Path,
    raw: bytes,
    label: str,
    *,
    temporary_dir: Path,
) -> Path:
    _require_private_dir(path.parent, f"{label} parent")
    _require_private_dir(temporary_dir, "metadata publish temporary directory")
    if path.parent.lstat().st_dev != temporary_dir.lstat().st_dev:
        raise RegistryError(f"{label} temporary and final paths differ by filesystem")
    _cleanup_publish_temps(temporary_dir, path)
    descriptor, name = tempfile.mkstemp(
        prefix=f".publish-{path.name}-",
        suffix=".partial",
        dir=temporary_dir,
    )
    temp_path = Path(name)
    os.fchmod(descriptor, 0o600)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        completed = read_regular_strict(
            temp_path,
            f"completed {label} temporary object",
            limit=max(MAX_RAW_BYTES, len(raw)),
        )
        if completed != raw:
            raise RegistryError(f"{label} temporary bytes changed before publish")
        try:
            os.link(temp_path, path, follow_symlinks=False)
            _fsync_dir(path.parent)
        except FileExistsError:
            existing = read_regular_strict(
                path, label, limit=max(MAX_RAW_BYTES, len(raw))
            )
            if existing != raw:
                raise RegistryError(
                    f"create-only {label} conflicts with existing bytes"
                )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink()
            _fsync_dir(temporary_dir)
        except FileNotFoundError:
            pass
    if read_regular_strict(path, label, limit=max(MAX_RAW_BYTES, len(raw))) != raw:
        raise RegistryError(f"{label} changed after atomic publish")
    return path


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def create_download_temp(paths: WarehousePaths) -> tuple[int, Path]:
    descriptor, name = tempfile.mkstemp(
        prefix=".download-", suffix=".partial", dir=paths.temporary
    )
    os.fchmod(descriptor, 0o600)
    return descriptor, Path(name)


def stream_to_fd(
    descriptor: int,
    chunks: Iterable[bytes],
    *,
    maximum_bytes: int = MAX_RAW_BYTES,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes) or not chunk:
            if chunk == b"":
                continue
            raise RegistryError("HTTP body stream yielded a non-byte chunk")
        total += len(chunk)
        if total > maximum_bytes:
            raise RegistryError("HTTP body exceeds raw-object safety limit")
        _write_all(descriptor, chunk)
        digest.update(chunk)
    os.fsync(descriptor)
    return total, digest.hexdigest()


def publish_temp_create_only(
    temp_path: Path,
    destination: Path,
    *,
    expected_sha256: str,
) -> tuple[Path, bool]:
    _require_private_dir(temp_path.parent, "temporary object parent")
    _require_private_dir(destination.parent, "raw object parent")
    temp_raw = read_regular_strict(temp_path, "temporary raw object")
    if sha256(temp_raw) != expected_sha256:
        raise RegistryError("temporary raw object hash changed before publish")
    if temp_path.lstat().st_dev != destination.parent.lstat().st_dev:
        raise RegistryError("temporary and raw objects are on different filesystems")
    try:
        os.link(temp_path, destination, follow_symlinks=False)
        created = True
        _fsync_dir(destination.parent)
    except FileExistsError:
        created = False
        existing = read_regular_strict(destination, "existing raw object")
        if sha256(existing) != expected_sha256 or existing != temp_raw:
            raise RegistryError("existing raw object conflicts with downloaded bytes")
    finally:
        try:
            temp_path.unlink()
            _fsync_dir(temp_path.parent)
        except FileNotFoundError:
            pass
    published = read_regular_strict(destination, "published raw object")
    if sha256(published) != expected_sha256:
        raise RegistryError("published raw object hash mismatch")
    return destination, not created


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
            or _file_identity(path_info) != _file_identity(info)
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
