"""Descriptor-held custody roots and fd-relative stable I/O."""

from __future__ import annotations

import fcntl
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .backup_contracts import InventoryEntry, WarehouseSnapshot
from .canonical import sha256
from .custody_paths import SAFE_COMPONENT, normalized_absolute
from .errors import RegistryError
from .file_integrity import file_identity, write_all

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _require_private_directory(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RegistryError(f"{label} must be a private owned directory")


def _parts(relative: str) -> tuple[str, ...]:
    parts = Path(relative).parts
    if (
        not parts
        or Path(relative).is_absolute()
        or any(SAFE_COMPONENT.fullmatch(part) is None for part in parts)
    ):
        raise RegistryError("fd-relative custody path is unsafe")
    return parts


def _read_fd(descriptor: int, limit: int, label: str) -> bytes:
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
        raise RegistryError(f"{label} exceeds {limit} bytes")
    return raw


@dataclass
class HeldCustodyRoot:
    path: Path
    descriptor: int
    identity: tuple[int, ...]

    def revalidate(self) -> None:
        try:
            path_info = self.path.lstat()
            opened = os.fstat(self.descriptor)
        except OSError as exc:
            raise RegistryError("held custody root became unavailable") from exc
        _require_private_directory(path_info, "held custody root")
        _require_private_directory(opened, "held custody root")
        if (
            _directory_identity(path_info) != self.identity
            or _directory_identity(opened) != self.identity
        ):
            raise RegistryError("held custody root pathname identity changed")

    def identity_sha256(self, *, domain: str) -> str:
        self.revalidate()
        device, inode, uid, gid, _kind, mode = self.identity
        return sha256(
            (
                f"{domain}|{self.path}|{device}|{inode}|{uid}|{gid}|{mode:o}"
            ).encode()
        )

    @contextmanager
    def open_directory(self, relative: str) -> Iterator[int]:
        descriptor = os.dup(self.descriptor)
        try:
            for component in _parts(relative):
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                _require_private_directory(
                    os.fstat(descriptor),
                    "held custody subdirectory",
                )
            yield descriptor
        except OSError as exc:
            raise RegistryError("held custody subdirectory is unavailable") from exc
        finally:
            os.close(descriptor)

    def read_file(
        self,
        relative: str,
        *,
        label: str,
        limit: int,
    ) -> bytes:
        parts = _parts(relative)
        parent_relative = "/".join(parts[:-1])
        parent_context = (
            self.open_directory(parent_relative)
            if parent_relative
            else _duplicated(self.descriptor)
        )
        with parent_context as parent_fd:
            try:
                before = os.stat(
                    parts[-1],
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                descriptor = os.open(parts[-1], FILE_FLAGS, dir_fd=parent_fd)
            except OSError as exc:
                raise RegistryError(f"{label} is unavailable") from exc
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) & 0o077
                    or opened.st_nlink != 1
                ):
                    raise RegistryError(
                        f"{label} must be a private one-link regular file"
                    )
                raw = _read_fd(descriptor, limit, label)
                os.lseek(descriptor, 0, os.SEEK_SET)
                repeated = _read_fd(descriptor, limit, label)
                after = os.fstat(descriptor)
                path_after = os.stat(
                    parts[-1],
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    len(
                        {
                            file_identity(before),
                            file_identity(opened),
                            file_identity(after),
                            file_identity(path_after),
                        }
                    )
                    != 1
                    or repeated != raw
                ):
                    raise RegistryError(f"{label} changed while being read")
                return raw
            except OSError as exc:
                raise RegistryError(f"{label} read failed closed") from exc
            finally:
                os.close(descriptor)

    def ensure_directory(self, relative: str) -> None:
        descriptor = os.dup(self.descriptor)
        try:
            for component in _parts(relative):
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                _require_private_directory(
                    os.fstat(descriptor),
                    "held destination directory",
                )
                os.fsync(descriptor)
        except OSError as exc:
            raise RegistryError("cannot create held custody directory") from exc
        finally:
            os.close(descriptor)

    def publish_bytes(
        self,
        relative: str,
        raw: bytes,
        *,
        label: str,
        temporary_directory: str = "tmp",
    ) -> None:
        parts = _parts(relative)
        parent_relative = "/".join(parts[:-1])
        if parent_relative:
            self.ensure_directory(parent_relative)
        parent_context = (
            self.open_directory(parent_relative)
            if parent_relative
            else _duplicated(self.descriptor)
        )
        with (
            parent_context as parent_fd,
            self.open_directory(temporary_directory) as temporary_fd,
        ):
            temp_name = f".held-{uuid.uuid4().hex}.partial"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(temp_name, flags, 0o600, dir_fd=temporary_fd)
            linked = False
            try:
                write_all(descriptor, raw)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                completed = _read_regular_at(
                    temporary_fd,
                    temp_name,
                    label=f"completed {label} temporary",
                    limit=max(len(raw), 1),
                    expected_nlink=1,
                )
                if completed != raw:
                    raise RegistryError(f"{label} temporary bytes changed")
                os.fsync(temporary_fd)
                try:
                    os.link(
                        temp_name,
                        parts[-1],
                        src_dir_fd=temporary_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    linked = True
                    os.fsync(parent_fd)
                except FileExistsError:
                    existing = _read_regular_at(
                        parent_fd,
                        parts[-1],
                        label=label,
                        limit=max(len(raw), 1),
                        expected_nlink=1,
                    )
                    if existing != raw:
                        raise RegistryError(
                            f"create-only {label} conflicts with existing bytes"
                        )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temp_name, dir_fd=temporary_fd)
                    os.fsync(temporary_fd)
                except FileNotFoundError:
                    pass
            expected_nlink = 1
            if linked:
                expected_nlink = 1
            if (
                _read_regular_at(
                    parent_fd,
                    parts[-1],
                    label=label,
                    limit=max(len(raw), 1),
                    expected_nlink=expected_nlink,
                )
                != raw
            ):
                raise RegistryError(f"{label} changed after publication")


@contextmanager
def _duplicated(descriptor: int) -> Iterator[int]:
    duplicated = os.dup(descriptor)
    try:
        yield duplicated
    finally:
        os.close(duplicated)


def _read_regular_at(
    parent_fd: int,
    name: str,
    *,
    label: str,
    limit: int,
    expected_nlink: int,
) -> bytes:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != expected_nlink
        ):
            raise RegistryError(f"{label} file custody is unsafe")
        raw = _read_fd(descriptor, limit, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        repeated = _read_fd(descriptor, limit, label)
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            repeated != raw
            or len(
                {
                    file_identity(before),
                    file_identity(info),
                    file_identity(after),
                    file_identity(path_after),
                }
            )
            != 1
        ):
            raise RegistryError(f"{label} changed while being read")
        return raw
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable") from exc
    finally:
        os.close(descriptor)


@contextmanager
def hold_custody_root(path: Path) -> Iterator[HeldCustodyRoot]:
    absolute = normalized_absolute(path)
    try:
        before = absolute.lstat()
        descriptor = os.open(absolute, DIRECTORY_FLAGS)
        opened = os.fstat(descriptor)
        after = absolute.lstat()
    except OSError as exc:
        raise RegistryError("custody root is unavailable") from exc
    try:
        for info in (before, opened, after):
            _require_private_directory(info, "custody root")
        identities = {
            _directory_identity(before),
            _directory_identity(opened),
            _directory_identity(after),
        }
        if len(identities) != 1:
            raise RegistryError("custody root changed while being held")
        held = HeldCustodyRoot(
            path=absolute,
            descriptor=descriptor,
            identity=identities.pop(),
        )
        yield held
        held.revalidate()
    finally:
        os.close(descriptor)


def _scan_directory(
    held: HeldCustodyRoot,
    descriptor: int,
    *,
    storage_prefix: str,
    relative_prefix: str,
    kind: str,
) -> list[InventoryEntry]:
    try:
        names = sorted(os.listdir(descriptor))
    except OSError as exc:
        raise RegistryError("held custody directory cannot be enumerated") from exc
    entries = []
    for name in names:
        if SAFE_COMPONENT.fullmatch(name) is None:
            raise RegistryError("held custody member name is unsafe")
        storage_relative = f"{storage_prefix}/{name}"
        relative = f"{relative_prefix}/{name}"
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                _require_private_directory(
                    os.fstat(child),
                    "held custody tree directory",
                )
                entries.extend(
                    _scan_directory(
                        held,
                        child,
                        storage_prefix=storage_relative,
                        relative_prefix=relative,
                        kind=kind,
                    )
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            raw = held.read_file(
                storage_relative,
                label=f"held {kind} custody object",
                limit=512 * 1024 * 1024,
            )
            entries.append(
                InventoryEntry(
                    relative_path=relative,
                    kind=kind,
                    byte_count=len(raw),
                    raw_sha256=sha256(raw),
                )
            )
        else:
            raise RegistryError("held custody tree contains a non-regular member")
    if sorted(os.listdir(descriptor)) != names:
        raise RegistryError("held custody directory membership changed")
    return entries


def scan_held_snapshot(
    held: HeldCustodyRoot,
    *,
    raw_prefix: str,
    manifests_prefix: str,
    strip_prefix: str = "",
) -> WarehouseSnapshot:
    def scan_once() -> WarehouseSnapshot:
        all_entries = []
        for kind, prefix in (
            ("raw", raw_prefix),
            ("manifest", manifests_prefix),
        ):
            marker = strip_prefix.rstrip("/") + "/" if strip_prefix else ""
            logical_prefix = prefix.removeprefix(marker)
            with held.open_directory(prefix) as descriptor:
                all_entries.extend(
                    _scan_directory(
                        held,
                        descriptor,
                        storage_prefix=prefix,
                        relative_prefix=logical_prefix,
                        kind=kind,
                    )
                )
        return WarehouseSnapshot.build(tuple(sorted(all_entries)))

    first = scan_once()
    second = scan_once()
    if first != second:
        raise RegistryError("held custody tree changed between stable scans")
    held.revalidate()
    return second


def materialize_held_snapshot(
    *,
    source: HeldCustodyRoot,
    destination: HeldCustodyRoot,
    source_prefix: str,
    destination_prefix: str,
    snapshot: WarehouseSnapshot,
    minimum_free_bytes_after: int,
) -> None:
    if (
        source.identity == destination.identity
        or source.path in destination.path.parents
        or destination.path in source.path.parents
    ):
        raise RegistryError(
            "held source and destination custody roots are not independent"
        )
    if minimum_free_bytes_after < 0:
        raise RegistryError("minimum remaining custody capacity is invalid")
    stats = os.fstatvfs(destination.descriptor)
    free = stats.f_bavail * stats.f_frsize
    required = snapshot.total_bytes
    if required > free - minimum_free_bytes_after:
        raise RegistryError("insufficient destination capacity for custody copy")
    for entry in snapshot.entries:
        source_relative = "/".join(
            value
            for value in (source_prefix.rstrip("/"), entry.relative_path)
            if value
        )
        destination_relative = "/".join(
            value
            for value in (destination_prefix.rstrip("/"), entry.relative_path)
            if value
        )
        raw = source.read_file(
            source_relative,
            label=f"held source {entry.kind} object",
            limit=max(entry.byte_count, 1),
        )
        if len(raw) != entry.byte_count or sha256(raw) != entry.raw_sha256:
            raise RegistryError("held source object changed from inventory")
        destination.publish_bytes(
            destination_relative,
            raw,
            label=f"held destination {entry.kind} object",
        )
    source.revalidate()
    destination.revalidate()


def hash_held_tree(
    held: HeldCustodyRoot,
    *,
    prefix: str,
    suffix: str,
    limit: int,
) -> tuple[tuple[str, str], ...]:
    def scan_directory(descriptor: int, relative: str) -> list[tuple[str, str]]:
        names = sorted(os.listdir(descriptor))
        values = []
        for name in names:
            if SAFE_COMPONENT.fullmatch(name) is None:
                raise RegistryError("held hash-tree member name is unsafe")
            child_relative = f"{relative}/{name}"
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
                try:
                    _require_private_directory(
                        os.fstat(child),
                        "held hash-tree directory",
                    )
                    values.extend(scan_directory(child, child_relative))
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and child_relative.endswith(suffix):
                raw = held.read_file(
                    child_relative,
                    label="held hash-tree file",
                    limit=limit,
                )
                values.append((child_relative, sha256(raw)))
            else:
                raise RegistryError("held hash-tree contains an unexpected member")
        if sorted(os.listdir(descriptor)) != names:
            raise RegistryError("held hash-tree membership changed")
        return values

    with held.open_directory(prefix) as root_fd:
        first = tuple(scan_directory(root_fd, prefix))
    with held.open_directory(prefix) as root_fd:
        second = tuple(scan_directory(root_fd, prefix))
    if not first or first != second:
        raise RegistryError("held hash-tree is empty or unstable")
    held.revalidate()
    return second


@contextmanager
def held_custody_lock(
    held: HeldCustodyRoot,
    *,
    key: str,
) -> Iterator[None]:
    if SAFE_COMPONENT.fullmatch(key) is None:
        raise RegistryError("held custody lock key is unsafe")
    with held.open_directory("locks") as locks_fd:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(f"{key}.lock", flags, 0o600, dir_fd=locks_fd)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_nlink != 1
            ):
                raise RegistryError("held custody lock file is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
