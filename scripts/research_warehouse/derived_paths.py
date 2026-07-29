"""Private filesystem layout for rebuildable Research derivatives."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .custody_paths import SAFE_COMPONENT, normalized_absolute, require_private_dir
from .errors import RegistryError
from .file_integrity import fsync_dir

LAYOUT_DIRS = ("catalog", "parquet", "tmp", "locks")


@dataclass(frozen=True)
class DerivedPaths:
    root: Path
    catalog: Path
    parquet: Path
    temporary: Path
    locks: Path

    @classmethod
    def initialize(cls, root: Path) -> DerivedPaths:
        absolute = normalized_absolute(root)
        if absolute.exists():
            raise RegistryError(f"derived root already exists: {absolute}")
        absolute.mkdir(mode=0o700)
        fsync_dir(absolute.parent)
        for name in LAYOUT_DIRS:
            path = absolute / name
            path.mkdir(mode=0o700)
            fsync_dir(path)
            fsync_dir(absolute)
        return cls.open(absolute)

    @classmethod
    def open(cls, root: Path) -> DerivedPaths:
        absolute = normalized_absolute(root)
        require_private_dir(absolute, "derived root")
        values = {name: absolute / name for name in LAYOUT_DIRS}
        for name, path in values.items():
            require_private_dir(path, f"derived {name} directory")
        devices = {absolute.lstat().st_dev}
        devices.update(path.lstat().st_dev for path in values.values())
        if len(devices) != 1:
            raise RegistryError("derived layout must be on one filesystem")
        return cls(
            root=absolute,
            catalog=values["catalog"],
            parquet=values["parquet"],
            temporary=values["tmp"],
            locks=values["locks"],
        )

    def private_subdir(self, base: Path, *components: str) -> Path:
        if base not in {self.catalog, self.parquet, self.temporary, self.locks}:
            raise RegistryError("derived subdirectory base is outside layout")
        current = base
        for component in components:
            if SAFE_COMPONENT.fullmatch(component) is None:
                raise RegistryError(
                    f"unsafe derived path component: {component}"
                )
            parent = current
            current /= component
            created = False
            try:
                current.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            require_private_dir(current, "derived subdirectory")
            if created:
                fsync_dir(current)
                fsync_dir(parent)
        return current

    def require_same_filesystem_as(self, path: Path, label: str) -> None:
        try:
            device = path.lstat().st_dev
        except OSError as exc:
            raise RegistryError(f"{label} is unavailable: {path}") from exc
        if device != self.root.lstat().st_dev:
            raise RegistryError(f"{label} must share the derived filesystem")


def private_file_mode(path: Path) -> None:
    os.chmod(path, 0o600)
