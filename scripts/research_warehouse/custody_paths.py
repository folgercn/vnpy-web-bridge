"""Private same-filesystem warehouse layout."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import RegistryError
from .file_integrity import fsync_dir

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
        absolute = normalized_absolute(root)
        if absolute.exists():
            raise RegistryError(f"warehouse root already exists: {absolute}")
        absolute.mkdir(mode=0o700)
        fsync_dir(absolute.parent)
        for name in LAYOUT_DIRS:
            (absolute / name).mkdir(mode=0o700)
            fsync_dir(absolute / name)
            fsync_dir(absolute)
        fsync_dir(absolute)
        return cls.open(absolute)

    @classmethod
    def open(cls, root: Path) -> WarehousePaths:
        absolute = normalized_absolute(root)
        require_private_dir(absolute, "warehouse root")
        values = {name: absolute / name for name in LAYOUT_DIRS}
        for name, path in values.items():
            require_private_dir(path, f"warehouse {name} directory")
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
            require_private_dir(current, "custody subdirectory")
            if created:
                fsync_dir(current)
                fsync_dir(parent)
        return current


def normalized_absolute(path: Path) -> Path:
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    normalized = Path(os.path.normpath(str(absolute)))
    if normalized != absolute:
        raise RegistryError("warehouse path must already be normalized")
    return absolute


def require_private_dir(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RegistryError(f"{label} must be a non-symlink directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RegistryError(f"{label} must be private and owned by current user")
    return info
