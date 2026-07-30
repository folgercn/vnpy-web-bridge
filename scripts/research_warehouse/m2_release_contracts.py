"""Content, manifest and Python contracts for one M2 release bundle."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import file_identity, read_regular_strict
from .m2_python_runtime import (
    RUNTIME_EXECUTABLE,
    load_python_runtime_manifest,
    verify_python_runtime,
)
from .manifest_contracts import SHA256_PATTERN

BUNDLE_SCHEMA = "vnpy_research_m2_release_bundle_manifest_v2"
REQUIREMENTS_RAW_SHA256 = (
    "4a372ecbd149efbb19bb1fd251a13c1ca395cc8356a7a66e325ed65a8b4094bf"
)
LOGICAL_RELEASE_ROOT = "/usr/local/libexec/vnpyresearch/release"
REQUIRED_ENTRYPOINTS = {
    "bin/research-warehouse-backup-signer",
    "bin/research-warehouse-job",
    "bin/research-warehouse-manifest-signer",
    "bin/research-warehouse-monitor",
    "bin/research-warehouse-operator-state",
    "bin/research-warehouse-rebuild",
}
BUNDLE_KEYS = {
    "schema_version",
    "source_commit_sha",
    "requirements_raw_sha256",
    "wheelhouse_manifest_raw_sha256",
    "python_runtime_manifest_raw_sha256",
    "python_runtime_tree_content_sha256",
    "entries",
    "tree_content_sha256",
}
ENTRY_KEYS = {
    "relative_path",
    "kind",
    "size_bytes",
    "raw_sha256",
    "mode",
}
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def regular_bytes(path: Path, label: str) -> bytes:
    return read_regular_strict(path, label, private=False)


def snapshot_bundle_content(root: Path) -> list[dict[str, Any]]:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise RegistryError("M2 release bundle root is unavailable") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o755
    ):
        raise RegistryError("M2 release bundle root custody mismatch")
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise RegistryError("M2 release bundle contains a symlink")
        if path.is_dir():
            kind = "directory"
            raw = None
            size = 0
        elif path.is_file():
            kind = "file"
            raw = regular_bytes(path, f"M2 release entry {relative}")
            size = len(raw)
        else:
            raise RegistryError("M2 release bundle entry type is forbidden")
        entries.append(
            {
                "relative_path": relative,
                "kind": kind,
                "size_bytes": size,
                "raw_sha256": None if raw is None else sha256(raw),
                "mode": f"{stat.S_IMODE(value.st_mode):04o}",
            }
        )
    by_path = {entry["relative_path"]: entry for entry in entries}
    if not REQUIRED_ENTRYPOINTS <= set(by_path) or any(
        by_path[path]["kind"] != "file"
        or int(by_path[path]["mode"], 8) & 0o111 == 0
        for path in REQUIRED_ENTRYPOINTS
    ):
        raise RegistryError("M2 release bundle is missing an executable entrypoint")
    return entries


def tree_content_sha256(entries: list[dict[str, Any]]) -> str:
    return sha256(
        canonical_json_line(
            {
                "schema_version": "vnpy_research_m2_release_bundle_content_v1",
                "entries": entries,
            }
        )
    )


def release_launcher(role: str) -> bytes:
    bootstraps = {
        "backup-signer": "research_warehouse_backup_signer.py",
        "manifest-signer": "research_warehouse_manifest_signer.py",
        "monitor": "research_warehouse_monitor.py",
        "operator-state": "research_warehouse_operator_state.py",
        "rebuild": "research_warehouse_rebuild.py",
        "warehouse": "research_warehouse_job.py",
    }
    if role not in bootstraps:
        raise RegistryError("M2 release launcher role is invalid")
    bootstrap = bootstraps[role]
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"exec {LOGICAL_RELEASE_ROOT}/runtime/{RUNTIME_EXECUTABLE} -B -I "
        f"{LOGICAL_RELEASE_ROOT}/app/{bootstrap} \"$@\"\n"
    ).encode()


def verify_release_bundle(root: Path, manifest: object) -> None:
    value = _exact(manifest, BUNDLE_KEYS, "M2 release bundle manifest")
    if (
        value["schema_version"] != BUNDLE_SCHEMA
        or COMMIT_PATTERN.fullmatch(value["source_commit_sha"]) is None
        or value["requirements_raw_sha256"] != REQUIREMENTS_RAW_SHA256
        or SHA256_PATTERN.fullmatch(value["wheelhouse_manifest_raw_sha256"]) is None
        or SHA256_PATTERN.fullmatch(
            value["python_runtime_manifest_raw_sha256"]
        )
        is None
        or SHA256_PATTERN.fullmatch(
            value["python_runtime_tree_content_sha256"]
        )
        is None
        or not isinstance(value["entries"], list)
    ):
        raise RegistryError("M2 release bundle manifest contract mismatch")
    for entry in value["entries"]:
        _exact(entry, ENTRY_KEYS, "M2 release bundle entry")
    actual_entries = snapshot_bundle_content(root)
    if (
        actual_entries != value["entries"]
        or tree_content_sha256(actual_entries) != value["tree_content_sha256"]
    ):
        raise RegistryError("M2 release bundle content mismatch")
    runtime_manifest, _digest = load_python_runtime_manifest(
        root / "python-runtime-manifest.json",
        expected_raw_sha256=value["python_runtime_manifest_raw_sha256"],
        private=False,
    )
    if (
        runtime_manifest["tree_content_sha256"]
        != value["python_runtime_tree_content_sha256"]
    ):
        raise RegistryError("M2 Python runtime tree binding mismatch")
    verify_python_runtime(root / "runtime", runtime_manifest)
    for role, relative in (
        ("backup-signer", "bin/research-warehouse-backup-signer"),
        ("warehouse", "bin/research-warehouse-job"),
        ("manifest-signer", "bin/research-warehouse-manifest-signer"),
        ("monitor", "bin/research-warehouse-monitor"),
        ("operator-state", "bin/research-warehouse-operator-state"),
        ("rebuild", "bin/research-warehouse-rebuild"),
    ):
        if regular_bytes(root / relative, f"M2 {role} launcher") != release_launcher(
            role
        ):
            raise RegistryError("M2 release launcher runtime binding mismatch")


def load_release_bundle_manifest(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(expected_raw_sha256) is None:
        raise RegistryError("expected M2 release manifest SHA256 is invalid")
    raw = regular_bytes(path, "M2 release bundle manifest")
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 release bundle manifest SHA256 mismatch")
    value = parse_json_strict(raw, "M2 release bundle manifest")
    if canonical_json_line(value) != raw:
        raise RegistryError("M2 release bundle manifest is not canonical")
    _exact(value, BUNDLE_KEYS, "M2 release bundle manifest")
    return value


def write_create_only(path: Path, value: dict[str, Any]) -> str:
    raw = canonical_json_line(value)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except FileExistsError as exc:
        raise RegistryError("M2 release manifest already exists") from exc
    except OSError as exc:
        raise RegistryError("cannot publish M2 release manifest") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    parent_descriptor = None
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise RegistryError("cannot fsync M2 release manifest parent") from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    before = path.lstat()
    reread = regular_bytes(path, "M2 release manifest")
    after = path.lstat()
    if (
        reread != raw
        or file_identity(before) != file_identity(after)
        or stat.S_IMODE(after.st_mode) != 0o600
    ):
        raise RegistryError("M2 release manifest publication mismatch")
    return sha256(raw)
