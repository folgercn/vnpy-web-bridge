"""Verify, install and atomically roll back M2 Research release bundles."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .m2_release_artifacts import build_release_tree_manifest
from .m2_release_bundle_contracts import (
    PYTHON_EXECUTABLE,
    RUNTIME_METADATA_PATH,
    false_authority,
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
PreflightRunner = Callable[[Path], None]
ENTRY_MODULE_PATH = "libexec/m2_release_entry.py"
INSTALL_TRANSACTION_SCHEMA = "vnpy_research_m2_release_install_transaction_v1"
TRANSACTION_STATES = {"PREPARED", "SWITCHED", "COMMITTED"}
TRANSACTION_KEYS = {
    "schema_version",
    "transaction_id",
    "state",
    "active_root",
    "rollback_root",
    "stage_root",
    "old_location",
    "new_release_id",
    "old_release_id",
    "pending_manifest_path",
    "installed_manifest_path",
    "installed_manifest_raw_sha256",
}


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
        directory = stage_root / entry["relative_path"]
        directory.chmod(int(entry["mode"], 8))
        fsync_dir(directory)
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


def _unlink_file_durable(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    fsync_dir(path.parent)


def _transaction_next_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.next")


def _transaction_create_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.create")


def _write_transaction(
    path: Path,
    transaction: dict[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
    create: bool,
) -> None:
    raw = canonical_json_line(transaction)
    if create:
        create_path = _transaction_create_path(path)
        if create_path.exists():
            _unlink_file_durable(create_path)
        try:
            _create_only_manifest(
                create_path,
                raw,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            os.link(create_path, path, follow_symlinks=False)
            fsync_dir(path.parent)
        finally:
            _unlink_file_durable(create_path)
        return
    next_path = _transaction_next_path(path)
    if next_path.exists():
        _unlink_file_durable(next_path)
    _create_only_manifest(
        next_path,
        raw,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    os.replace(next_path, path)
    fsync_dir(path.parent)


def _load_transaction(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    active_root: Path,
    rollback_root: Path,
) -> dict[str, Any] | None:
    create_path = _transaction_create_path(path)
    if create_path.exists():
        _unlink_file_durable(create_path)
    next_path = _transaction_next_path(path)
    if next_path.exists():
        _unlink_file_durable(next_path)
    if not path.exists():
        return None
    raw = read_regular_strict(path, "M2 release install transaction")
    try:
        facts = path.lstat()
    except OSError as exc:
        raise RegistryError("M2 release transaction is unavailable") from exc
    value = parse_json_strict(raw, "M2 release install transaction")
    if (
        not isinstance(value, dict)
        or set(value) != TRANSACTION_KEYS
        or value["schema_version"] != INSTALL_TRANSACTION_SCHEMA
        or canonical_json_line(value) != raw
        or facts.st_uid != owner_uid
        or facts.st_gid != owner_gid
        or stat.S_IMODE(facts.st_mode) != 0o400
        or value["state"] not in TRANSACTION_STATES
        or value["active_root"] != str(active_root)
        or value["rollback_root"] != str(rollback_root)
        or not isinstance(value["transaction_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["transaction_id"]) is None
        or not isinstance(value["new_release_id"], str)
        or (
            value["old_release_id"] is not None
            and not isinstance(value["old_release_id"], str)
        )
        or not isinstance(value["installed_manifest_raw_sha256"], str)
        or re.fullmatch(
            r"[0-9a-f]{64}",
            value["installed_manifest_raw_sha256"],
        )
        is None
    ):
        raise RegistryError("M2 release install transaction contract mismatch")
    expected_stage = active_root.parent / (
        f".{active_root.name}.stage.{value['new_release_id']}"
    )
    expected_old = (
        None
        if value["old_release_id"] is None
        else rollback_root / value["old_release_id"]
    )
    if (
        value["stage_root"] != str(expected_stage)
        or value["old_location"]
        != (None if expected_old is None else str(expected_old))
    ):
        raise RegistryError("M2 release install transaction path mismatch")
    final_path = Path(value["installed_manifest_path"])
    pending_path = Path(value["pending_manifest_path"])
    expected_pending = final_path.with_name(
        f".{final_path.name}.pending.{value['new_release_id']}"
    )
    if not final_path.is_absolute() or pending_path != expected_pending:
        raise RegistryError("M2 release transaction manifest path mismatch")
    identity = dict(value)
    identity["state"] = "PREPARED"
    identity["transaction_id"] = ""
    expected_id = sha256(canonical_json_line(identity))
    if value["transaction_id"] != expected_id:
        raise RegistryError("M2 release install transaction identity mismatch")
    return value


def _release_id_if_present(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
) -> str | None:
    if not path.exists():
        return None
    return _active_release_id(
        path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )


def _verify_manifest_raw(path: Path, expected_sha256: str) -> None:
    raw = read_regular_strict(path, "installed M2 release manifest")
    if sha256(raw) != expected_sha256:
        raise RegistryError("installed M2 release manifest hash mismatch")


def _restore_pretransaction_release(
    transaction: dict[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    active_root = Path(transaction["active_root"])
    rollback_root = Path(transaction["rollback_root"])
    stage_root = Path(transaction["stage_root"])
    old_location = (
        None
        if transaction["old_location"] is None
        else Path(transaction["old_location"])
    )
    new_id = transaction["new_release_id"]
    old_id = transaction["old_release_id"]
    active_id = _release_id_if_present(
        active_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if active_id == new_id:
        if old_id is None:
            if stage_root.exists():
                raise RegistryError(
                    "M2 release recovery staging collision on initial install"
                )
            os.rename(active_root, stage_root)
            fsync_dir(active_root.parent)
        else:
            candidate: Path | None = None
            for possible in (old_location, stage_root):
                if possible is not None and _release_id_if_present(
                    possible,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                ) == old_id:
                    candidate = possible
                    break
            if candidate is None:
                raise RegistryError(
                    "M2 release recovery cannot locate previous release"
                )
            _atomic_exchange(active_root, candidate)
            fsync_dir(active_root.parent)
            fsync_dir(rollback_root)
            if _active_release_id(
                active_root,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            ) != old_id:
                raise RegistryError("M2 release recovery restored wrong release")
    elif active_id != old_id:
        raise RegistryError("M2 release recovery active identity mismatch")
    for candidate in (stage_root, old_location):
        if candidate is not None and candidate.exists():
            candidate_id = _active_release_id(
                candidate,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            if candidate_id in {new_id, old_id}:
                _remove_installer_tree(candidate)
    fsync_dir(active_root.parent)
    fsync_dir(rollback_root)
    restored_id = _release_id_if_present(
        active_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if restored_id != old_id:
        raise RegistryError("M2 release recovery did not restore prior identity")


def _recover_install_transaction_locked(
    transaction_path: Path,
    *,
    active_root: Path,
    rollback_root: Path,
    owner_uid: int,
    owner_gid: int,
    prefer_rollback: bool,
) -> None:
    transaction = _load_transaction(
        transaction_path,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        active_root=active_root,
        rollback_root=rollback_root,
    )
    if transaction is None:
        return
    state = transaction["state"]
    pending = Path(transaction["pending_manifest_path"])
    final = Path(transaction["installed_manifest_path"])
    expected_manifest_sha = transaction["installed_manifest_raw_sha256"]
    if state == "PREPARED" or (state == "SWITCHED" and prefer_rollback):
        _restore_pretransaction_release(
            transaction,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        if final.exists():
            _verify_manifest_raw(final, expected_manifest_sha)
            _unlink_file_durable(final)
        _unlink_file_durable(pending)
        _unlink_file_durable(transaction_path)
        return
    active_id = _active_release_id(
        active_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if active_id != transaction["new_release_id"]:
        raise RegistryError("M2 release committed transaction identity mismatch")
    if state == "SWITCHED":
        if final.exists():
            _verify_manifest_raw(final, expected_manifest_sha)
            fsync_dir(final.parent)
            _unlink_file_durable(pending)
        else:
            _verify_manifest_raw(pending, expected_manifest_sha)
            os.rename(pending, final)
            fsync_dir(final.parent)
        transaction["state"] = "COMMITTED"
        _write_transaction(
            transaction_path,
            transaction,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            create=False,
        )
    _verify_manifest_raw(final, expected_manifest_sha)
    _unlink_file_durable(pending)
    _unlink_file_durable(transaction_path)


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


def _run_stage_preflight(stage_root: Path) -> None:
    expected_release_id = _active_release_id(
        stage_root,
        owner_uid=os.geteuid(),
        owner_gid=os.getegid(),
    )
    for role in ("warehouse", "monitor"):
        command = [
            PYTHON_EXECUTABLE,
            "-I",
            "-S",
            "-s",
            "-E",
            "-B",
            str(stage_root / ENTRY_MODULE_PATH),
            role,
            "preinstall-self-check",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd="/",
                env={
                    "HOME": "/var/empty",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                },
                check=False,
                capture_output=True,
                close_fds=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RegistryError(
                f"M2 release {role} interpreter preflight could not run"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RegistryError(
                f"M2 release {role} interpreter preflight failed: {detail}"
            )
        result = parse_json_strict(
            completed.stdout,
            f"M2 release {role} interpreter preflight output",
        )
        if not isinstance(result, dict):
            raise RegistryError(
                f"M2 release {role} interpreter preflight output is invalid"
            )
        if (
            result.get("status")
            != "RELEASE_SELF_CHECK_PASSED_NO_SCHEDULE_AUTHORITY"
            or result.get("role") != role
            or result.get("release_id") != expected_release_id
            or result.get("authority") != false_authority()
        ):
            raise RegistryError(
                f"M2 release {role} interpreter preflight identity mismatch"
            )


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
    preflight_runner: PreflightRunner = _run_stage_preflight,
    transaction_path: Path | None = None,
) -> dict[str, Any]:
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
    fixed_transaction_path = parent / ".release-install-transaction.json"
    if transaction_path is None:
        transaction_path = fixed_transaction_path
    elif transaction_path != fixed_transaction_path:
        raise RegistryError("M2 release transaction path is not fixed")
    with hold_release_update_lock(
        release_lock_path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    ) as held_lock:
        _recover_install_transaction_locked(
            transaction_path,
            active_root=active_root,
            rollback_root=rollback_root,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
            prefer_rollback=False,
        )
        manifest = verify_release_package(package_root)
        release_id = manifest["release_id"]
        stage_root = parent / f".{active_root.name}.stage.{release_id}"
        pending_manifest_path = installed_manifest_path.with_name(
            f".{installed_manifest_path.name}.pending.{release_id}"
        )
        old_location: Path | None = None
        installed_manifest_raw = b""
        _validate_manifest_destination(
            installed_manifest_path,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
            forbidden_roots=(package_root, active_root, rollback_root),
        )
        _validate_manifest_destination(
            pending_manifest_path,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
            forbidden_roots=(package_root, active_root, rollback_root),
        )
        if stage_root.exists():
            stage_facts = stage_root.lstat()
            if (
                stat.S_ISLNK(stage_facts.st_mode)
                or not stat.S_ISDIR(stage_facts.st_mode)
                or stage_facts.st_uid != expected_owner_uid
                or stage_facts.st_gid != expected_owner_gid
            ):
                raise RegistryError("M2 release stale stage custody mismatch")
            _remove_installer_tree(stage_root)
            fsync_dir(parent)
        try:
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
            preflight_runner(stage_root)
            installed_entries_after_preflight = scan_content_tree(
                stage_root,
                expected_owner_uid=expected_owner_uid,
                expected_owner_gid=expected_owner_gid,
            )
            if installed_entries_after_preflight != manifest["entries"]:
                raise RegistryError(
                    "installed M2 release stage drifted during preflight"
                )
            installed_manifest = build_release_tree_manifest(
                stage_root,
                logical_release_root=str(active_root),
                expected_owner_uid=expected_owner_uid,
                expected_owner_gid=expected_owner_gid,
            )
            installed_manifest_raw = canonical_json_line(installed_manifest)
            previous_id: str | None = None
            if active_root.exists():
                previous_id = _active_release_id(
                    active_root,
                    owner_uid=expected_owner_uid,
                    owner_gid=expected_owner_gid,
                )
                old_location = rollback_root / previous_id
                if old_location.exists():
                    raise RegistryError("rollback release already exists")
            transaction = {
                "schema_version": INSTALL_TRANSACTION_SCHEMA,
                "transaction_id": "",
                "state": "PREPARED",
                "active_root": str(active_root),
                "rollback_root": str(rollback_root),
                "stage_root": str(stage_root),
                "old_location": (
                    None if old_location is None else str(old_location)
                ),
                "new_release_id": release_id,
                "old_release_id": previous_id,
                "pending_manifest_path": str(pending_manifest_path),
                "installed_manifest_path": str(installed_manifest_path),
                "installed_manifest_raw_sha256": sha256(
                    installed_manifest_raw
                ),
            }
            transaction["transaction_id"] = sha256(
                canonical_json_line(transaction)
            )
            _write_transaction(
                transaction_path,
                transaction,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
                create=True,
            )
            if hook is not None:
                hook("after_transaction_prepared")
            _create_only_manifest(
                pending_manifest_path,
                installed_manifest_raw,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
            )
            if hook is not None:
                hook("after_pending_manifest")
                hook("after_stage_verified")
            held_lock.revalidate()

            if previous_id is not None:
                _atomic_exchange(active_root, stage_root)
                if hook is not None:
                    hook("after_switch")
                os.rename(stage_root, old_location)
                if hook is not None:
                    hook("after_old_release_move")
            else:
                os.rename(stage_root, active_root)
                if hook is not None:
                    hook("after_switch")
            if hook is not None:
                hook("before_parent_fsync")
            fsync_dir(parent)
            fsync_dir(rollback_root)
            if hook is not None:
                hook("after_parent_fsync")
            if _active_release_id(
                active_root,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
            ) != release_id:
                raise RegistryError("installed M2 release active identity mismatch")
            transaction["state"] = "SWITCHED"
            _write_transaction(
                transaction_path,
                transaction,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
                create=False,
            )
            if hook is not None:
                hook("after_transaction_switched")
            os.rename(pending_manifest_path, installed_manifest_path)
            if hook is not None:
                hook("after_manifest_publish_before_fsync")
            fsync_dir(installed_manifest_path.parent)
            held_lock.revalidate()
            transaction["state"] = "COMMITTED"
            _write_transaction(
                transaction_path,
                transaction,
                owner_uid=expected_owner_uid,
                owner_gid=expected_owner_gid,
                create=False,
            )
            try:
                _unlink_file_durable(transaction_path)
            except OSError:
                # COMMITTED is durable; the next operation safely reaps it.
                pass
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
            try:
                if transaction_path.exists():
                    _recover_install_transaction_locked(
                        transaction_path,
                        active_root=active_root,
                        rollback_root=rollback_root,
                        owner_uid=expected_owner_uid,
                        owner_gid=expected_owner_gid,
                        prefer_rollback=True,
                    )
                else:
                    if stage_root.exists():
                        _remove_installer_tree(stage_root)
                    _unlink_file_durable(pending_manifest_path)
                    fsync_dir(parent)
                    fsync_dir(rollback_root)
                held_lock.revalidate()
            except Exception as recovery_exc:
                raise RegistryError(
                    "M2 release install failed and recovery failed"
                ) from recovery_exc
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
    transaction_path: Path | None = None,
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
    fixed_transaction_path = (
        active_root.parent / ".release-install-transaction.json"
    )
    if transaction_path is None:
        transaction_path = fixed_transaction_path
    elif transaction_path != fixed_transaction_path:
        raise RegistryError("M2 release transaction path is not fixed")
    with hold_release_update_lock(
        release_lock_path,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    ) as held_lock:
        _recover_install_transaction_locked(
            transaction_path,
            active_root=active_root,
            rollback_root=rollback_root,
            owner_uid=expected_owner_uid,
            owner_gid=expected_owner_gid,
            prefer_rollback=False,
        )
        try:
            candidate_parent = rollback_candidate.parent.resolve(strict=True)
            expected_parent = rollback_root.resolve(strict=True)
        except OSError as exc:
            raise RegistryError(
                "M2 rollback candidate parent is unavailable"
            ) from exc
        if candidate_parent != expected_parent:
            raise RegistryError(
                "M2 rollback candidate is outside rollback custody"
            )
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
            fsync_dir(rollback_root)
            if (
                _active_release_id(
                    active_root,
                    owner_uid=expected_owner_uid,
                    owner_gid=expected_owner_gid,
                )
                != rollback_id
                or _active_release_id(
                    rollback_candidate,
                    owner_uid=expected_owner_uid,
                    owner_gid=expected_owner_gid,
                )
                != current_id
            ):
                raise RegistryError("M2 rollback active identity mismatch")
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
                    fsync_dir(rollback_root)
                    if (
                        _active_release_id(
                            active_root,
                            owner_uid=expected_owner_uid,
                            owner_gid=expected_owner_gid,
                        )
                        != current_id
                        or _active_release_id(
                            rollback_candidate,
                            owner_uid=expected_owner_uid,
                            owner_gid=expected_owner_gid,
                        )
                        != rollback_id
                    ):
                        raise RegistryError(
                            "M2 release rollback restore identity mismatch"
                        )
                    held_lock.revalidate()
                except Exception as restore_exc:
                    raise RegistryError(
                        "M2 release rollback failed and restore failed"
                    ) from restore_exc
            raise
