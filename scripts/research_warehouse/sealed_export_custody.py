"""Create-only custody and stable reads for sealed source exports."""

from __future__ import annotations

import os
from pathlib import Path

from commodity_c_fast_pure_producer_kernel import ARTIFACT_ROLES

from .custody_paths import normalized_absolute, require_private_dir
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all

MANIFEST_FILENAME = "sealed-export-manifest.json"
RECEIPT_FILENAME = "sealed-export-receipt.json"


def require_symlink_free_path(path: Path, label: str) -> Path:
    absolute = normalized_absolute(path)
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable") from exc
    if resolved != absolute:
        raise RegistryError(f"{label} path must be symlink-free")
    return absolute


def read_source_artifacts(paths: dict[str, Path]) -> dict[str, bytes]:
    if tuple(paths) != ARTIFACT_ROLES:
        raise RegistryError("source artifact role order/set mismatch")
    identities = set()
    result = {}
    for role, path in paths.items():
        path = require_symlink_free_path(path, f"source artifact {role}")
        try:
            info = path.lstat()
        except OSError as exc:
            raise RegistryError(f"source artifact {role} is unavailable") from exc
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise RegistryError("source artifacts must use distinct inodes")
        identities.add(identity)
        result[role] = read_regular_strict(
            path,
            f"source artifact {role}",
            limit=64 * 1024 * 1024,
        )
    if sum(map(len, result.values())) > 256 * 1024 * 1024:
        raise RegistryError("source artifact set exceeds aggregate limit")
    return result


def _create_only_file(parent: Path, filename: str, raw: bytes) -> Path:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        descriptor = os.open(filename, flags, 0o600, dir_fd=parent_fd)
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)
    fsync_dir(parent)
    path = parent / filename
    if read_regular_strict(path, f"published {filename}") != raw:
        raise RegistryError(f"published {filename} changed")
    return path


def create_export_directory(export_root: Path, export_id: str) -> Path:
    root = require_symlink_free_path(export_root, "sealed export root")
    require_private_dir(root, "sealed export root")
    if "/" in export_id or export_id in {".", ".."}:
        raise RegistryError("sealed export ID is unsafe")
    root_fd = os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.mkdir(export_id, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    except FileExistsError as exc:
        raise RegistryError("sealed export already exists; overwrite forbidden") from exc
    finally:
        os.close(root_fd)
    output = root / export_id
    require_private_dir(output, "sealed export directory")
    return output


def publish_export(
    output: Path,
    *,
    artifact_raw: dict[str, bytes],
    manifest_raw: bytes,
    receipt_raw: bytes,
) -> None:
    require_private_dir(output, "sealed export directory")
    for role in ARTIFACT_ROLES:
        _create_only_file(output, f"{role}.json", artifact_raw[role])
    _create_only_file(output, MANIFEST_FILENAME, manifest_raw)
    _create_only_file(output, RECEIPT_FILENAME, receipt_raw)


def read_export_directory(
    output: Path,
) -> tuple[dict[str, bytes], bytes, bytes]:
    output = require_symlink_free_path(output, "sealed export directory")
    require_private_dir(output, "sealed export directory")
    expected_names = {
        *(f"{role}.json" for role in ARTIFACT_ROLES),
        MANIFEST_FILENAME,
        RECEIPT_FILENAME,
    }
    try:
        actual_names = {item.name for item in output.iterdir()}
    except OSError as exc:
        raise RegistryError("sealed export directory is unreadable") from exc
    if actual_names != expected_names:
        raise RegistryError("sealed export directory file set mismatch")
    artifacts = {
        role: read_regular_strict(
            output / f"{role}.json",
            f"exported artifact {role}",
            limit=64 * 1024 * 1024,
        )
        for role in ARTIFACT_ROLES
    }
    manifest = read_regular_strict(
        output / MANIFEST_FILENAME,
        "sealed export manifest",
        limit=4 * 1024 * 1024,
    )
    receipt = read_regular_strict(
        output / RECEIPT_FILENAME,
        "sealed export receipt",
        limit=1024 * 1024,
    )
    return artifacts, manifest, receipt
