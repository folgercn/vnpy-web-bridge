"""Verify, install and atomically roll back M2 Research release bundles."""

from __future__ import annotations

import ctypes
import os
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .m2_release_artifacts import build_release_tree_manifest
from .m2_release_bundle_contracts import (
    RUNTIME_METADATA_PATH,
    load_bundle_manifest,
    load_runtime_metadata,
    require_safe_package_root,
    scan_content_tree,
    tree_content_sha256,
)
from .m2_release_entry import self_check_release
from .m2_release_lock import hold_release_update_lock

AT_FDCWD = -2
RENAME_EXCHANGE = 0x2
InstallHook = Callable[[str], None]


def _remove_installer_tree(path: Path) -> None:
    try:
        path.chmod(0o700)
    except OSError:
        pass
    for directory, names, _files in os.walk(path, topdown=True):
        current = Path(directory)
        try:
            current.chmod(0o700)
        except OSError:
            pass
        for name in names:
            child = current / name
            try:
                facts = child.lstat()
                if stat.S_ISDIR(facts.st_mode) and not stat.S_ISLNK(
                    facts.st_mode
                ):
                    child.chmod(0o700)
            except OSError:
                pass
    shutil.rmtree(path)


def verify_release_package(package_root: Path) -> dict[str, Any]:
    require_safe_package_root(package_root)
    manifest, _raw = load_bundle_manifest(package_root)
    release_root = package_root / "release"
    actual = scan_content_tree(
        release_root,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
    )
    if (
        actual != manifest["entries"]
        or tree_content_sha256(actual) != manifest["tree_content_sha256"]
    ):
        raise RegistryError("M2 release package tree does not match manifest")
    runtime, _runtime_raw = load_runtime_metadata(
        release_root,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
    )
    shared_fields = (
        "release_id",
        "source_commit_sha",
        "logical_release_root",
        "dependency_lock_raw_sha256",
        "python",
        "dependencies",
        "source_bindings",
        "authority",
    )
    if any(runtime[field] != manifest[field] for field in shared_fields):
        raise RegistryError("M2 release runtime/bundle identity mismatch")
    expected_runtime_entries = [
        entry
        for entry in manifest["entries"]
        if entry["relative_path"] != RUNTIME_METADATA_PATH
    ]
    if (
        runtime["runtime_entries"] != expected_runtime_entries
        or runtime["runtime_tree_content_sha256"]
        != tree_content_sha256(expected_runtime_entries)
    ):
        raise RegistryError("M2 release runtime/bundle tree mismatch")
    return manifest


def _validate_parent(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
    create: bool,
) -> None:
    if create and not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, owner_uid, owner_gid)
        path.chmod(mode)
        fsync_dir(path.parent)
    try:
        facts = path.lstat()
    except OSError as exc:
        raise RegistryError(f"M2 release parent is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or facts.st_uid != owner_uid
        or facts.st_gid != owner_gid
        or stat.S_IMODE(facts.st_mode) != mode
    ):
        raise RegistryError(f"M2 release parent custody mismatch: {path}")


def _copy_verified_tree(
    *,
    package_root: Path,
    stage_root: Path,
    manifest: dict[str, Any],
    owner_uid: int,
    owner_gid: int,
    hook: InstallHook | None,
) -> None:
    stage_root.mkdir(mode=0o700)
    os.chown(stage_root, owner_uid, owner_gid)
    source_root = package_root / "release"
    entries = manifest["entries"]
    for entry in entries:
        if entry["kind"] != "directory":
            continue
        target = stage_root / entry["relative_path"]
        target.mkdir(mode=0o700)
        os.chown(target, owner_uid, owner_gid)
    for entry in entries:
        if entry["kind"] != "file":
            continue
        relative = entry["relative_path"]
        source = source_root / relative
        raw = read_regular_strict(
            source,
            f"M2 release package entry {relative}",
            private=False,
        )
        if (
            len(raw) != entry["size_bytes"]
            or sha256(raw) != entry["raw_sha256"]
        ):
            raise RegistryError(f"M2 release package entry drift: {relative}")
        target = stage_root / relative
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o400)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fchown(descriptor, owner_uid, owner_gid)
            os.fchmod(descriptor, int(entry["mode"], 8))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if hook is not None:
            hook(f"after_copy:{relative}")
    directories = [entry for entry in entries if entry["kind"] == "directory"]
    for entry in sorted(
        directories,
        key=lambda value: len(PurePosixPath(value["relative_path"]).parts),
        reverse=True,
    ):
        (stage_root / entry["relative_path"]).chmod(int(entry["mode"], 8))
    stage_root.chmod(0o755)
    fsync_dir(stage_root)
    fsync_dir(stage_root.parent)


def _atomic_exchange(left: Path, right: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    encoded_left = os.fsencode(left)
    encoded_right = os.fsencode(right)
    if sys.platform == "darwin":
        function = getattr(library, "renameatx_np", None)
    else:
        function = getattr(library, "renameat2", None)
    if function is None:
        raise RegistryError("atomic release directory exchange is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        AT_FDCWD,
        encoded_left,
        AT_FDCWD,
        encoded_right,
        RENAME_EXCHANGE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise RegistryError(
            f"atomic release directory exchange failed: errno={error}"
        )


def _validate_manifest_destination(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    forbidden_roots: tuple[Path, ...],
) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise RegistryError("installed release manifest path must be absolute")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RegistryError(
            "installed release manifest destination is unavailable"
        ) from exc
    else:
        raise RegistryError("installed release manifest already exists")
    try:
        parent = path.parent.resolve(strict=True)
        facts = parent.lstat()
    except OSError as exc:
        raise RegistryError(
            "installed release manifest parent is unavailable"
        ) from exc
    if (
        parent != path.parent
        or stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or facts.st_uid != owner_uid
        or facts.st_gid != owner_gid
        or stat.S_IMODE(facts.st_mode) & 0o077
    ):
        raise RegistryError("installed release manifest parent custody mismatch")
    candidate = parent / path.name
    for root in forbidden_roots:
        resolved_root = root.resolve(strict=False)
        if candidate == resolved_root or candidate.is_relative_to(resolved_root):
            raise RegistryError(
                "installed release manifest path overlaps release custody"
            )


def _create_only_manifest(
    path: Path,
    raw: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o400)
    try:
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, 0o400)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_dir(path.parent)


def _active_release_id(
    active_root: Path,
    *,
    owner_uid: int,
    owner_gid: int,
) -> str:
    result = self_check_release(
        release_root=active_root,
        role="warehouse",
        expected_owner_uid=owner_uid,
        expected_owner_gid=owner_gid,
        enforce_interpreter=False,
        import_modules=False,
    )
    return str(result["release_id"])


def install_release_package(
    *,
    package_root: Path,
    active_root: Path,
    rollback_root: Path,
    release_lock_path: Path,
    installed_manifest_path: Path,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
    hook: InstallHook | None = None,
) -> dict[str, Any]:
    manifest = verify_release_package(package_root)
    release_id = manifest["release_id"]
    parent = active_root.parent
    _validate_parent(
        parent,
        owner_uid=expected_owner_uid,
        owner_gid=expected_owner_gid,
        mode=0o755,
        create=False,
    )
    _validate_parent(
        rollback_root,
        owner_uid=expected_owner_uid,
        owner_gid=expected_owner_gid,
        mode=0o700,
        create=True,
    )
    _validate_manifest_destination(
        installed_manifest_path,
        owner_uid=expected_owner_uid,
        owner_gid=expected_owner_gid,
        forbidden_roots=(package_root, active_root, rollback_root),
    )
    stage_root = parent / f".{active_root.name}.stage.{release_id}"
    if stage_root.exists():
        raise RegistryError("M2 release staging path already exists")

    switched = False
    exchanged = False
    manifest_created = False
    old_location: Path | None = None
    try:
        with hold_release_update_lock(
            release_lock_path,
            expected_owner_uid=expected_owner_uid,
            expected_owner_gid=expected_owner_gid,
        ) as held_lock:
            _copy_verified_tree(
                package_root=package_root,
                stage_root=stage_root,
                manifest=manifest,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
                hook=hook,
            )
            installed_entries = scan_content_tree(
                stage_root,
                expected_owner_uid=expected_owner_uid,
                expected_owner_gid=expected_owner_gid,
            )
            if installed_entries != manifest["entries"]:
                raise RegistryError("installed M2 release stage differs from bundle")
            self_check_release(
                release_root=stage_root,
                role="warehouse",
                expected_owner_uid=expected_owner_uid,
                expected_owner_gid=expected_owner_gid,
                enforce_interpreter=False,
                import_modules=False,
            )
            installed_manifest = build_release_tree_manifest(
                stage_root,
                logical_release_root=str(active_root),
                expected_owner_uid=expected_owner_uid,
                expected_owner_gid=expected_owner_gid,
            )
            installed_manifest_raw = canonical_json_line(installed_manifest)
            _create_only_manifest(
                installed_manifest_path,
                installed_manifest_raw,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
            )
            manifest_created = True
            if hook is not None:
                hook("after_stage_verified")
            held_lock.revalidate()

            if active_root.exists():
                previous_id = _active_release_id(
                    active_root,
                    owner_uid=expected_owner_uid,
                    owner_gid=expected_owner_gid,
                )
                old_location = rollback_root / previous_id
                if old_location.exists():
                    raise RegistryError("rollback release already exists")
                _atomic_exchange(active_root, stage_root)
                switched = True
                exchanged = True
                if hook is not None:
                    hook("after_switch")
                os.rename(stage_root, old_location)
            else:
                os.rename(stage_root, active_root)
                switched = True
                if hook is not None:
                    hook("after_switch")
            fsync_dir(parent)
            fsync_dir(rollback_root)
            held_lock.revalidate()
            return {
                "schema_version": "vnpy_research_m2_release_install_result_v1",
                "status": "RELEASE_INSTALLED_NOT_ACTIVATED",
                "release_id": release_id,
                "source_commit_sha": manifest["source_commit_sha"],
                "bundle_tree_content_sha256": manifest[
                    "tree_content_sha256"
                ],
                "installed_manifest_path": str(installed_manifest_path),
                "installed_manifest_raw_sha256": sha256(
                    installed_manifest_raw
                ),
                "rollback_release": (
                    None if old_location is None else str(old_location)
                ),
                "authority": manifest["authority"],
            }
    except Exception:
        cleanup_candidates = [stage_root]
        if switched:
            try:
                if exchanged and old_location is not None:
                    if old_location.exists():
                        _atomic_exchange(active_root, old_location)
                        cleanup_candidates.append(old_location)
                    elif stage_root.exists():
                        _atomic_exchange(active_root, stage_root)
                elif active_root.exists():
                    os.rename(active_root, stage_root)
            except Exception as rollback_exc:
                raise RegistryError(
                    "M2 release install failed and rollback failed"
                ) from rollback_exc
        for candidate in cleanup_candidates:
            if candidate.exists():
                _remove_installer_tree(candidate)
        if manifest_created and installed_manifest_path.exists():
            installed_manifest_path.unlink()
            fsync_dir(installed_manifest_path.parent)
        raise


def rollback_release(
    *,
    active_root: Path,
    rollback_root: Path,
    rollback_candidate: Path,
    release_lock_path: Path,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
    hook: InstallHook | None = None,
) -> dict[str, Any]:
    _validate_parent(
        active_root.parent,
        owner_uid=expected_owner_uid,
        owner_gid=expected_owner_gid,
        mode=0o755,
        create=False,
    )
    _validate_parent(
        rollback_root,
        owner_uid=expected_owner_uid,
        owner_gid=expected_owner_gid,
        mode=0o700,
        create=False,
    )
    try:
        candidate_parent = rollback_candidate.parent.resolve(strict=True)
        expected_parent = rollback_root.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("M2 rollback candidate parent is unavailable") from exc
    if candidate_parent != expected_parent:
        raise RegistryError("M2 rollback candidate is outside rollback custody")
    with hold_release_update_lock(
        release_lock_path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    ) as held_lock:
        current_id = _active_release_id(
            active_root,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
        )
        rollback_id = _active_release_id(
            rollback_candidate,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
        )
        if rollback_candidate.name != rollback_id:
            raise RegistryError("M2 rollback candidate id/path mismatch")
        held_lock.revalidate()
        switched = False
        try:
            _atomic_exchange(active_root, rollback_candidate)
            switched = True
            if hook is not None:
                hook("after_switch")
            fsync_dir(active_root.parent)
            held_lock.revalidate()
            return {
                "schema_version": "vnpy_research_m2_release_rollback_result_v1",
                "status": "RELEASE_ROLLED_BACK_NOT_ACTIVATED",
                "active_release_id": rollback_id,
                "rollback_release_id": current_id,
            }
        except Exception:
            if switched:
                try:
                    _atomic_exchange(active_root, rollback_candidate)
                    fsync_dir(active_root.parent)
                    held_lock.revalidate()
                except Exception as restore_exc:
                    raise RegistryError(
                        "M2 release rollback failed and restore failed"
                    ) from restore_exc
            raise
