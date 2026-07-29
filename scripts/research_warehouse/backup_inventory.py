"""Stable exact-byte inventory for raw and signed-manifest custody trees."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .backup_contracts import InventoryEntry, WarehouseSnapshot
from .canonical import sha256
from .custody_paths import WarehousePaths, require_private_dir
from .errors import RegistryError
from .file_integrity import read_regular_strict

MAX_BACKUP_OBJECT_BYTES = 512 * 1024 * 1024


def _require_tree_directories(root: Path) -> None:
    for path in sorted(
        (candidate for candidate in root.rglob("*") if candidate.is_dir()),
        key=str,
    ):
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RegistryError("backup inventory contains an unsafe directory")


def _scan_roots(root: Path, raw_root: Path, manifests_root: Path) -> WarehouseSnapshot:
    require_private_dir(root, "backup inventory root")
    require_private_dir(raw_root, "backup raw inventory root")
    require_private_dir(manifests_root, "backup manifest inventory root")
    _require_tree_directories(raw_root)
    _require_tree_directories(manifests_root)
    entries: list[InventoryEntry] = []
    for kind, base in (("raw", raw_root), ("manifest", manifests_root)):
        for path in sorted(base.rglob("*"), key=str):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RegistryError("backup inventory contains a non-regular object")
            relative = path.relative_to(root).as_posix()
            raw = read_regular_strict(
                path,
                f"backup inventory {kind} object",
                limit=MAX_BACKUP_OBJECT_BYTES,
            )
            entries.append(
                InventoryEntry(
                    relative_path=relative,
                    kind=kind,
                    byte_count=len(raw),
                    raw_sha256=sha256(raw),
                )
            )
    return WarehouseSnapshot.build(tuple(sorted(entries)))


def scan_warehouse_snapshot(paths: WarehousePaths) -> WarehouseSnapshot:
    """Read twice so membership or byte drift fails closed."""
    first = _scan_roots(paths.root, paths.raw, paths.manifests)
    second = _scan_roots(paths.root, paths.raw, paths.manifests)
    if first != second:
        raise RegistryError("warehouse changed while backup inventory was scanned")
    return first


def scan_object_store_snapshot(objects_root: Path) -> WarehouseSnapshot:
    """Scan an already materialized backup object store."""
    require_private_dir(objects_root, "backup objects root")
    first = _scan_roots(
        objects_root,
        objects_root / "raw",
        objects_root / "manifests",
    )
    second = _scan_roots(
        objects_root,
        objects_root / "raw",
        objects_root / "manifests",
    )
    if first != second:
        raise RegistryError("backup object store changed while being scanned")
    return first
