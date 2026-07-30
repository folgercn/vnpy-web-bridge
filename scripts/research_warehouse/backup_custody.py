"""Independent append-only backup layout and exact-byte materialization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .custody_paths import (
    normalized_absolute,
    require_private_dir,
)
from .errors import RegistryError
from .file_integrity import fsync_dir

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
