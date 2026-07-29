"""Independent append-only backup layout and exact-byte materialization."""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .backup_contracts import WarehouseSnapshot
from .custody_paths import (
    SAFE_COMPONENT,
    normalized_absolute,
    require_private_dir,
)
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .publication import create_only_bytes

BACKUP_LAYOUT_DIRS = ("objects", "anchors", "tmp", "locks")
ANCHOR_FILENAME_PATTERN = re.compile(
    r"^backup-[0-9]{8}-backup-[0-9a-f]{64}\.json$"
)


@dataclass(frozen=True)
class BackupPaths:
    root: Path
    objects: Path
    anchors: Path
    temporary: Path
    locks: Path

    @classmethod
    def initialize(cls, root: Path) -> BackupPaths:
        absolute = normalized_absolute(root)
        if absolute.exists():
            raise RegistryError(f"backup root already exists: {absolute}")
        absolute.mkdir(mode=0o700)
        fsync_dir(absolute.parent)
        for name in BACKUP_LAYOUT_DIRS:
            path = absolute / name
            path.mkdir(mode=0o700)
            fsync_dir(path)
            fsync_dir(absolute)
        for name in ("raw", "manifests"):
            path = absolute / "objects" / name
            path.mkdir(mode=0o700)
            fsync_dir(path)
            fsync_dir(absolute / "objects")
        return cls.open(absolute)

    @classmethod
    def open(cls, root: Path) -> BackupPaths:
        absolute = normalized_absolute(root)
        require_private_dir(absolute, "backup root")
        values = {name: absolute / name for name in BACKUP_LAYOUT_DIRS}
        for name, path in values.items():
            require_private_dir(path, f"backup {name} directory")
        for name in ("raw", "manifests"):
            require_private_dir(
                values["objects"] / name,
                f"backup objects {name} directory",
            )
        if {path.name for path in values["objects"].iterdir()} != {
            "raw",
            "manifests",
        }:
            raise RegistryError("backup objects root has unexpected members")
        devices = {absolute.lstat().st_dev}
        devices.update(path.lstat().st_dev for path in values.values())
        if len(devices) != 1:
            raise RegistryError("backup layout must use one destination filesystem")
        return cls(
            root=absolute,
            objects=values["objects"],
            anchors=values["anchors"],
            temporary=values["tmp"],
            locks=values["locks"],
        )

    def private_object_parent(self, relative_path: str) -> Path:
        parts = Path(relative_path).parts
        if not parts or parts[0] not in {"raw", "manifests"}:
            raise RegistryError("backup object path is outside allowed custody")
        current = self.objects
        for component in parts[:-1]:
            if SAFE_COMPONENT.fullmatch(component) is None:
                raise RegistryError("backup object path component is unsafe")
            parent = current
            current /= component
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            require_private_dir(current, "backup object directory")
            fsync_dir(current)
            fsync_dir(parent)
        return current


def _require_distinct_roots(source_root: Path, destination_root: Path) -> None:
    source = normalized_absolute(source_root)
    destination = normalized_absolute(destination_root)
    try:
        source_resolved = source.resolve(strict=True)
        destination_resolved = destination.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("backup custody root is unavailable") from exc
    if (
        source_resolved == destination_resolved
        or source_resolved in destination_resolved.parents
        or destination_resolved in source_resolved.parents
    ):
        raise RegistryError("backup source and destination must be independent roots")


def custody_identity(root: Path, *, domain: str) -> str:
    require_private_dir(root, "custody identity root")
    info = root.lstat()
    binding = (
        f"{domain}|{root}|{info.st_dev}|{info.st_ino}|{info.st_uid}|"
        f"{info.st_gid}|{stat.S_IMODE(info.st_mode):o}"
    ).encode()
    from .canonical import sha256

    return sha256(binding)


def _required_new_bytes(
    *,
    destination_root: Path,
    snapshot: WarehouseSnapshot,
) -> int:
    total = 0
    for entry in snapshot.entries:
        target = destination_root / entry.relative_path
        if not target.exists():
            total += entry.byte_count
    return total


def require_capacity(
    *,
    destination_root: Path,
    required_bytes: int,
    minimum_free_bytes_after: int,
) -> None:
    if (
        not isinstance(minimum_free_bytes_after, int)
        or isinstance(minimum_free_bytes_after, bool)
        or minimum_free_bytes_after < 0
    ):
        raise RegistryError("minimum remaining backup capacity is invalid")
    free = shutil.disk_usage(destination_root).free
    if required_bytes > free - minimum_free_bytes_after:
        raise RegistryError("insufficient destination capacity for custody copy")


def materialize_snapshot(
    *,
    source_root: Path,
    destination_root: Path,
    temporary_dir: Path,
    snapshot: WarehouseSnapshot,
    minimum_free_bytes_after: int,
    destination_parent,
) -> None:
    """Copy exact bytes create-only; caller supplies destination parent creation."""
    require_private_dir(source_root, "custody copy source root")
    require_private_dir(destination_root, "custody copy destination root")
    require_private_dir(temporary_dir, "custody copy temporary directory")
    _require_distinct_roots(source_root, destination_root)
    required = _required_new_bytes(
        destination_root=destination_root,
        snapshot=snapshot,
    )
    require_capacity(
        destination_root=destination_root,
        required_bytes=required,
        minimum_free_bytes_after=minimum_free_bytes_after,
    )
    for entry in snapshot.entries:
        source = source_root / entry.relative_path
        raw = read_regular_strict(
            source,
            f"custody source {entry.kind} object",
            limit=max(entry.byte_count, 1),
        )
        from .canonical import sha256

        if len(raw) != entry.byte_count or sha256(raw) != entry.raw_sha256:
            raise RegistryError("custody source object changed from signed inventory")
        parent = destination_parent(entry.relative_path)
        target = destination_root / entry.relative_path
        if target.parent != parent:
            raise RegistryError("custody destination parent binding mismatch")
        create_only_bytes(
            target,
            raw,
            f"backup {entry.kind} object",
            temporary_dir=temporary_dir,
        )


def require_no_unsafe_anchor_files(paths: BackupPaths) -> None:
    for path in paths.anchors.iterdir():
        info = path.lstat()
        if (
            ANCHOR_FILENAME_PATTERN.fullmatch(path.name) is None
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
        ):
            raise RegistryError("backup anchor custody contains an unsafe entry")
