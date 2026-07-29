"""Create-only custody and stable reads for sealed source exports."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from commodity_c_fast_pure_producer_kernel import ARTIFACT_ROLES

from .custody_paths import normalized_absolute
from .errors import RegistryError
from .file_integrity import file_identity, read_regular_strict, write_all

MANIFEST_FILENAME = "sealed-export-manifest.json"
RECEIPT_FILENAME = "sealed-export-receipt.json"
DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


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


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _require_private_directory_info(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RegistryError(
            f"{label} must be private, current-user-owned directory"
        )


def _open_bound_directory(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, ...] | None = None,
) -> tuple[int, tuple[int, ...]]:
    try:
        before = path.lstat()
        descriptor = os.open(path, DIRECTORY_FLAGS)
    except OSError as exc:
        raise RegistryError(f"{label} is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        _require_private_directory_info(before, label)
        _require_private_directory_info(opened, label)
        identities = {
            _directory_identity(before),
            _directory_identity(opened),
            _directory_identity(after),
        }
        if len(identities) != 1 or (
            expected_identity is not None
            and expected_identity not in identities
        ):
            raise RegistryError(f"{label} changed while being opened")
        return descriptor, identities.pop()
    except Exception:
        os.close(descriptor)
        raise


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


def _read_regular_at(
    parent_fd: int,
    filename: str,
    label: str,
    *,
    limit: int,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        before = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(filename, flags, dir_fd=parent_fd)
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
                f"{label} must be private one-link regular file"
            )
        raw = _read_fd(descriptor, limit, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        repeated = _read_fd(descriptor, limit, label)
        after = os.fstat(descriptor)
        path_after = os.stat(
            filename,
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
            or raw != repeated
        ):
            raise RegistryError(f"{label} changed while being read")
        return raw
    except OSError as exc:
        raise RegistryError(f"cannot read {label}") from exc
    finally:
        os.close(descriptor)


def _create_only_file_at(parent_fd: int, filename: str, raw: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(filename, flags, 0o600, dir_fd=parent_fd)
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    except OSError as exc:
        raise RegistryError(f"cannot create-only publish {filename}") from exc
    if (
        _read_regular_at(
            parent_fd,
            filename,
            f"published {filename}",
            limit=max(len(raw), 1),
        )
        != raw
    ):
        raise RegistryError(f"published {filename} changed")


def create_and_publish_export(
    export_root: Path,
    export_id: str,
    *,
    artifact_raw: dict[str, bytes],
    manifest_raw: bytes,
    receipt_raw: bytes,
) -> Path:
    root = require_symlink_free_path(export_root, "sealed export root")
    if "/" in export_id or export_id in {".", ".."}:
        raise RegistryError("sealed export ID is unsafe")
    try:
        root_expected_info = root.lstat()
    except OSError as exc:
        raise RegistryError("sealed export root is unavailable") from exc
    _require_private_directory_info(root_expected_info, "sealed export root")
    root_expected = _directory_identity(root_expected_info)
    root_fd, root_identity = _open_bound_directory(
        root,
        "sealed export root",
        expected_identity=root_expected,
    )
    output_fd: int | None = None
    try:
        try:
            os.mkdir(export_id, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError as exc:
            raise RegistryError(
                "sealed export already exists; overwrite forbidden"
            ) from exc
        output_expected_info = os.stat(
            export_id,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _require_private_directory_info(
            output_expected_info,
            "sealed export directory",
        )
        output_expected = _directory_identity(output_expected_info)
        output_fd = os.open(export_id, DIRECTORY_FLAGS, dir_fd=root_fd)
        output_info = os.fstat(output_fd)
        _require_private_directory_info(
            output_info,
            "sealed export directory",
        )
        output_identity = _directory_identity(output_info)
        if output_identity != output_expected:
            raise RegistryError(
                "sealed export directory changed while being opened"
            )
        for role in ARTIFACT_ROLES:
            _create_only_file_at(
                output_fd,
                f"{role}.json",
                artifact_raw[role],
            )
        _create_only_file_at(output_fd, MANIFEST_FILENAME, manifest_raw)
        _create_only_file_at(output_fd, RECEIPT_FILENAME, receipt_raw)
        if (
            _directory_identity(root.lstat()) != root_identity
            or _directory_identity(
                os.stat(export_id, dir_fd=root_fd, follow_symlinks=False)
            )
            != output_identity
        ):
            raise RegistryError("sealed export directory identity changed")
        os.fsync(output_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise RegistryError("sealed export publication failed closed") from exc
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(root_fd)
    return root / export_id


def read_export_directory(
    output: Path,
) -> tuple[dict[str, bytes], bytes, bytes]:
    output = require_symlink_free_path(output, "sealed export directory")
    output_fd, output_identity = _open_bound_directory(
        output,
        "sealed export directory",
    )
    try:
        expected_names = {
            *(f"{role}.json" for role in ARTIFACT_ROLES),
            MANIFEST_FILENAME,
            RECEIPT_FILENAME,
        }
        if set(os.listdir(output_fd)) != expected_names:
            raise RegistryError("sealed export directory file set mismatch")
        artifacts = {
            role: _read_regular_at(
                output_fd,
                f"{role}.json",
                f"exported artifact {role}",
                limit=64 * 1024 * 1024,
            )
            for role in ARTIFACT_ROLES
        }
        manifest = _read_regular_at(
            output_fd,
            MANIFEST_FILENAME,
            "sealed export manifest",
            limit=4 * 1024 * 1024,
        )
        receipt = _read_regular_at(
            output_fd,
            RECEIPT_FILENAME,
            "sealed export receipt",
            limit=1024 * 1024,
        )
        if _directory_identity(output.lstat()) != output_identity:
            raise RegistryError("sealed export directory changed while read")
        return artifacts, manifest, receipt
    except OSError as exc:
        raise RegistryError("sealed export directory is unreadable") from exc
    finally:
        os.close(output_fd)
