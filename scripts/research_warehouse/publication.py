"""Crash-recoverable create-only publication for custody objects."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path

from .canonical import sha256
from .custody_paths import (
    WarehousePaths,
)
from .custody_paths import (
    require_private_dir as _require_private_dir,
)
from .errors import RegistryError
from .file_integrity import (
    MAX_RAW_BYTES,
    read_regular_strict,
)
from .file_integrity import (
    fsync_dir as _fsync_dir,
)
from .file_integrity import (
    write_all as _write_all,
)


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
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RegistryError("metadata publish temporary object is not private")
        if info.st_nlink == 2:
            try:
                target_info = path.lstat()
            except OSError as exc:
                raise RegistryError(
                    "metadata publish target is missing during recovery"
                ) from exc
            if (
                target_info.st_dev != info.st_dev
                or target_info.st_ino != info.st_ino
            ):
                raise RegistryError("metadata publish recovery identity mismatch")
            _fsync_dir(path.parent)
        elif info.st_nlink != 1:
            raise RegistryError("metadata publish temporary link count is unsafe")
        candidate.unlink()
        changed = True
    if changed:
        _fsync_dir(temporary_dir)


def recover_atomic_publishes(
    *,
    temporary_dir: Path,
    final_root: Path,
    temporary_name_prefix: str,
    final_name_glob: str,
    remove_unlinked: bool = True,
    verify_sha256_filename: bool = False,
) -> None:
    """Recover interrupted temp/link publication before scanning final files."""
    _require_private_dir(temporary_dir, "metadata recovery temporary directory")
    _require_private_dir(final_root, "metadata recovery final root")
    candidates = [
        path
        for path in temporary_dir.iterdir()
        if path.name.startswith(temporary_name_prefix)
        and path.name.endswith(".partial")
    ]
    changed = False
    for candidate in candidates:
        info = candidate.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink not in (1, 2)
        ):
            raise RegistryError("abandoned metadata temporary object is unsafe")
        if info.st_nlink == 1 and not remove_unlinked:
            continue
        matched_target: Path | None = None
        if info.st_nlink == 2:
            matches = []
            for target in final_root.rglob(final_name_glob):
                target_info = target.lstat()
                if (
                    stat.S_ISREG(target_info.st_mode)
                    and target_info.st_dev == info.st_dev
                    and target_info.st_ino == info.st_ino
                ):
                    matches.append(target)
            if len(matches) != 1:
                raise RegistryError(
                    "abandoned metadata publication has no unique final link"
                )
            matched_target = matches[0]
            if verify_sha256_filename:
                raw = read_regular_strict(
                    matched_target,
                    "recovering content-addressed object",
                    expected_nlink=2,
                )
                if matched_target.stem != sha256(raw):
                    raise RegistryError(
                        "recovered content-addressed object hash/path mismatch"
                    )
            _fsync_dir(matched_target.parent)
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
    linked = False
    final_parent_synced = False
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
        _fsync_dir(temporary_dir)
        try:
            os.link(temp_path, path, follow_symlinks=False)
            linked = True
            _fsync_dir(path.parent)
            final_parent_synced = True
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
        if not linked or final_parent_synced:
            try:
                temp_path.unlink()
                _fsync_dir(temporary_dir)
            except FileNotFoundError:
                pass
    if read_regular_strict(path, label, limit=max(MAX_RAW_BYTES, len(raw))) != raw:
        raise RegistryError(f"{label} changed after atomic publish")
    return path


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
    _fsync_dir(temp_path.parent)
    linked = False
    final_parent_synced = False
    try:
        os.link(temp_path, destination, follow_symlinks=False)
        linked = True
        created = True
        _fsync_dir(destination.parent)
        final_parent_synced = True
    except FileExistsError:
        created = False
        existing = read_regular_strict(destination, "existing raw object")
        if sha256(existing) != expected_sha256 or existing != temp_raw:
            raise RegistryError("existing raw object conflicts with downloaded bytes")
    finally:
        if not linked or final_parent_synced:
            try:
                temp_path.unlink()
                _fsync_dir(temp_path.parent)
            except FileNotFoundError:
                pass
    published = read_regular_strict(destination, "published raw object")
    if sha256(published) != expected_sha256:
        raise RegistryError("published raw object hash mismatch")
    return destination, not created
