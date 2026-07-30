"""Install one verified M2 release under the exclusive deployment lock."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any

from .errors import RegistryError
from .m2_release_artifacts import build_release_tree_manifest
from .m2_release_contracts import (
    LOGICAL_RELEASE_ROOT,
    verify_release_bundle,
    write_create_only,
)
from .m2_release_lock import hold_release_update_lock

LOGICAL_LOCK_PATH = "/usr/local/libexec/vnpyresearch/release.lock"


def _fsync_directory(path: Path) -> None:
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise RegistryError("cannot fsync M2 release parent") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_owner(root: Path, *, owner_uid: int, owner_gid: int) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        try:
            value = path.lstat()
        except OSError as exc:
            raise RegistryError("installed M2 release entry is unavailable") from exc
        if (
            stat.S_ISLNK(value.st_mode)
            or value.st_uid != owner_uid
            or value.st_gid != owner_gid
        ):
            raise RegistryError("installed M2 release ownership mismatch")


def _remove_candidate(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _copy_regular(source: Path, target: Path) -> None:
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise RegistryError("staged M2 release entry is unavailable") from exc
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
        raise RegistryError("staged M2 release file type mismatch")
    raw = source.read_bytes()
    descriptor = None
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, stat.S_IMODE(source_stat.st_mode))
    except OSError as exc:
        raise RegistryError("cannot copy staged M2 release file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _copy_tree(source: Path, target: Path) -> None:
    target.mkdir(mode=0o755)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        destination = target / relative
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise RegistryError("staged M2 release symlink is forbidden")
        if stat.S_ISDIR(value.st_mode):
            destination.mkdir(mode=stat.S_IMODE(value.st_mode))
        elif stat.S_ISREG(value.st_mode):
            _copy_regular(path, destination)
        else:
            raise RegistryError("staged M2 release entry type mismatch")
    for directory in sorted(
        (path for path in target.rglob("*") if path.is_dir()),
        reverse=True,
    ):
        _fsync_directory(directory)
    _fsync_directory(target)


def install_release_bundle(
    *,
    staged_root: Path,
    manifest: dict[str, Any],
    release_root: Path = Path(LOGICAL_RELEASE_ROOT),
    lock_path: Path = Path(LOGICAL_LOCK_PATH),
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
    enforce_logical_paths: bool = True,
    installed_manifest_output: Path | None = None,
) -> dict[str, Any]:
    if enforce_logical_paths and (
        str(release_root) != LOGICAL_RELEASE_ROOT
        or str(lock_path) != LOGICAL_LOCK_PATH
    ):
        raise RegistryError("M2 release install path is not frozen")
    if enforce_logical_paths and installed_manifest_output is None:
        raise RegistryError("installed M2 release manifest output is required")
    if installed_manifest_output is not None and (
        not installed_manifest_output.is_absolute()
        or installed_manifest_output.is_relative_to(release_root.parent)
        or installed_manifest_output.is_relative_to(
            Path("/Users/Shared/vnpy-research")
        )
    ):
        raise RegistryError("installed M2 release manifest path is unsafe")
    if os.geteuid() != expected_owner_uid or os.getegid() != expected_owner_gid:
        raise RegistryError("M2 release installer identity mismatch")
    verify_release_bundle(staged_root, manifest)
    parent = release_root.parent
    candidate = parent / "release.candidate"
    previous = parent / "release.previous"
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise RegistryError("M2 release parent is unavailable") from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or parent_stat.st_uid != expected_owner_uid
        or parent_stat.st_gid != expected_owner_gid
        or stat.S_IMODE(parent_stat.st_mode) != 0o755
    ):
        raise RegistryError("M2 release parent custody mismatch")
    if candidate.exists() or previous.exists():
        raise RegistryError("M2 release install staging path is not empty")
    with hold_release_update_lock(
        lock_path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    ):
        try:
            _copy_tree(staged_root, candidate)
            _verify_owner(
                candidate,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
            )
            verify_release_bundle(candidate, manifest)
            had_previous = release_root.exists()
            if had_previous:
                release_root.rename(previous)
                _fsync_directory(parent)
            try:
                candidate.rename(release_root)
                _fsync_directory(parent)
                _verify_owner(
                    release_root,
                    owner_uid=expected_owner_uid,
                    owner_gid=expected_owner_gid,
                )
                verify_release_bundle(release_root, manifest)
                installed_manifest_sha = None
                if installed_manifest_output is not None:
                    installed_manifest = build_release_tree_manifest(
                        release_root,
                        logical_release_root=LOGICAL_RELEASE_ROOT,
                        expected_owner_uid=expected_owner_uid,
                        expected_owner_gid=expected_owner_gid,
                    )
                    installed_manifest_sha = write_create_only(
                        installed_manifest_output,
                        installed_manifest,
                    )
            except Exception:
                if release_root.exists():
                    release_root.rename(candidate)
                if had_previous and previous.exists():
                    previous.rename(release_root)
                    _fsync_directory(parent)
                raise
        except RegistryError:
            _remove_candidate(candidate)
            raise
        except OSError as exc:
            _remove_candidate(candidate)
            raise RegistryError("M2 release installation failed") from exc
    return {
        "schema_version": "vnpy_research_m2_release_install_result_v1",
        "status": "M2_RELEASE_INSTALLED",
        "release_root": str(release_root),
        "previous_retained": previous.exists(),
        "tree_content_sha256": manifest["tree_content_sha256"],
        "installed_tree_manifest_raw_sha256": installed_manifest_sha,
    }
