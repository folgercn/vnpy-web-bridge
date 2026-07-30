"""Strict contracts for deterministic M2 Research release bundles."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN

DEPENDENCY_LOCK_SCHEMA = "vnpy_research_m2_release_dependency_lock_v1"
BUNDLE_MANIFEST_SCHEMA = "vnpy_research_m2_release_bundle_manifest_v1"
RUNTIME_METADATA_SCHEMA = "vnpy_research_m2_release_runtime_metadata_v1"
TREE_CONTENT_SCHEMA = "vnpy_research_m2_release_content_v1"
LOGICAL_RELEASE_ROOT = "/usr/local/libexec/vnpyresearch/release"
PYTHON_IMPLEMENTATION = "CPython"
PYTHON_VERSION = "3.12.13"
PYTHON_EXECUTABLE = "/usr/local/bin/python3.12"
PLATFORM_TAG = "macosx_11_0_arm64"
RUNTIME_METADATA_PATH = "meta/release-runtime.json"
EXECUTABLE_PATHS = frozenset(
    {
        "bin/research-warehouse-job",
        "bin/research-warehouse-monitor",
        "libexec/m2_release_entry.py",
    }
)
REQUIRED_DIRECTORY_PATHS = frozenset(
    {
        "bin",
        "lib",
        "lib/python3.12",
        "lib/python3.12/site-packages",
        "lib/research_warehouse",
        "libexec",
        "meta",
    }
)
FROZEN_DEPENDENCY_LOCK_SHA256 = (
    "7ae807e51a30a33fe7b8ed9e9e07853f4a236c13073f26a5754a859b7195d881"
)
RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
WHEEL_PATTERN = re.compile(r"^[A-Za-z0-9_.+-]+\.whl$")
FROZEN_DEPENDENCIES = (
    {
        "name": "cffi",
        "version": "2.0.0",
        "wheel_filename": "cffi-2.0.0-cp312-cp312-macosx_11_0_arm64.whl",
        "wheel_sha256": (
            "8eca2a813c1cb7ad4fb74d368c2ffbbb4789d377ee5bb8df98373c2cc0dee76c"
        ),
        "size_bytes": 181048,
    },
    {
        "name": "cryptography",
        "version": "48.0.0",
        "wheel_filename": (
            "cryptography-48.0.0-cp311-abi3-macosx_10_9_universal2.whl"
        ),
        "wheel_sha256": (
            "0c558d2cdffd8f4bbb30fc7134c74d2ca9a476f830bb053074498fbc86f41ed6"
        ),
        "size_bytes": 8001587,
    },
    {
        "name": "duckdb",
        "version": "1.5.5",
        "wheel_filename": "duckdb-1.5.5-cp312-cp312-macosx_11_0_arm64.whl",
        "wheel_sha256": (
            "f0b88535a5d86fdd63dba6ea02ab68c003dfb9e4892b11256ef24c4da208baae"
        ),
        "size_bytes": 15509131,
    },
    {
        "name": "pycparser",
        "version": "2.23",
        "wheel_filename": "pycparser-2.23-py3-none-any.whl",
        "wheel_sha256": (
            "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"
        ),
        "size_bytes": 118140,
    },
)
REQUIRED_DEPENDENCIES = {
    item["name"]: item["version"] for item in FROZEN_DEPENDENCIES
}
AUTHORITY_FIELDS = {
    "account_data_read",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "network_authorized",
    "order_authorized",
    "permit_authorized",
    "position_mutation_authorized",
    "production_authorized",
    "rpc_authorized",
    "signing_authorized",
    "trading_authorized",
}
DEPENDENCY_KEYS = {
    "name",
    "version",
    "wheel_filename",
    "wheel_sha256",
    "size_bytes",
}
LOCK_KEYS = {
    "schema_version",
    "python_implementation",
    "python_version",
    "python_executable",
    "platform_tag",
    "dependencies",
    "authority",
}
ENTRY_KEYS = {
    "relative_path",
    "kind",
    "size_bytes",
    "raw_sha256",
    "mode",
}
SOURCE_BINDING_KEYS = {
    "repo_path",
    "release_path",
    "raw_sha256",
}
MANIFEST_KEYS = {
    "schema_version",
    "release_id",
    "source_commit_sha",
    "logical_release_root",
    "dependency_lock_raw_sha256",
    "python",
    "dependencies",
    "source_bindings",
    "entries",
    "tree_content_sha256",
    "authority",
}
RUNTIME_METADATA_KEYS = {
    "schema_version",
    "release_id",
    "source_commit_sha",
    "logical_release_root",
    "dependency_lock_raw_sha256",
    "python",
    "dependencies",
    "source_bindings",
    "runtime_entries",
    "runtime_tree_content_sha256",
    "authority",
}
PYTHON_KEYS = {
    "implementation",
    "version",
    "executable",
    "platform_tag",
}


@dataclass(frozen=True)
class DependencyBinding:
    name: str
    version: str
    wheel_filename: str
    wheel_sha256: str
    size_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "wheel_filename": self.wheel_filename,
            "wheel_sha256": self.wheel_sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class DependencyLock:
    raw_sha256: str
    dependencies: tuple[DependencyBinding, ...]

    def dependency_dicts(self) -> list[dict[str, Any]]:
        return [item.as_dict() for item in self.dependencies]


def validate_dependency_lock_binding(value: DependencyLock) -> None:
    if (
        not isinstance(value, DependencyLock)
        or value.raw_sha256 != FROZEN_DEPENDENCY_LOCK_SHA256
        or value.dependency_dicts() != list(FROZEN_DEPENDENCIES)
    ):
        raise RegistryError("M2 release dependency lock binding mismatch")


def false_authority() -> dict[str, bool]:
    return {field: False for field in sorted(AUTHORITY_FIELDS)}


def python_identity() -> dict[str, str]:
    return {
        "implementation": PYTHON_IMPLEMENTATION,
        "version": PYTHON_VERSION,
        "executable": PYTHON_EXECUTABLE,
        "platform_tag": PLATFORM_TAG,
    }


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RegistryError(f"{label} must be a positive integer")
    return value


def _safe_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegistryError(f"{label} must be a non-empty relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or ".." in parsed.parts
        or "." in parsed.parts
        or parsed.as_posix() != value
    ):
        raise RegistryError(f"{label} is unsafe")
    return value


def _validate_authority(value: object, label: str) -> dict[str, bool]:
    authority = _exact(value, AUTHORITY_FIELDS, label)
    if any(item is not False for item in authority.values()):
        raise RegistryError(f"{label} must be explicitly all false")
    return authority


def load_dependency_lock(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> DependencyLock:
    if SHA256_PATTERN.fullmatch(expected_raw_sha256) is None:
        raise RegistryError("dependency lock expected SHA256 is invalid")
    raw = read_regular_strict(
        path,
        "M2 release dependency lock",
        private=False,
    )
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 release dependency lock SHA256 mismatch")
    payload = parse_json_strict(raw, "M2 release dependency lock")
    lock = _exact(payload, LOCK_KEYS, "M2 release dependency lock")
    if (
        lock["schema_version"] != DEPENDENCY_LOCK_SCHEMA
        or lock["python_implementation"] != PYTHON_IMPLEMENTATION
        or lock["python_version"] != PYTHON_VERSION
        or lock["python_executable"] != PYTHON_EXECUTABLE
        or lock["platform_tag"] != PLATFORM_TAG
    ):
        raise RegistryError("M2 release dependency lock identity mismatch")
    _validate_authority(lock["authority"], "M2 dependency lock authority")
    dependencies = lock["dependencies"]
    if (
        not isinstance(dependencies, list)
        or dependencies != list(FROZEN_DEPENDENCIES)
    ):
        raise RegistryError("M2 release dependency set mismatch")
    parsed: list[DependencyBinding] = []
    for index, value in enumerate(dependencies):
        item = _exact(value, DEPENDENCY_KEYS, f"dependency[{index}]")
        name = item["name"]
        version = item["version"]
        filename = item["wheel_filename"]
        digest = item["wheel_sha256"]
        if (
            not isinstance(name, str)
            or name not in REQUIRED_DEPENDENCIES
            or version != REQUIRED_DEPENDENCIES[name]
            or not isinstance(filename, str)
            or WHEEL_PATTERN.fullmatch(filename) is None
            or not filename.lower().startswith(
                f"{name.replace('-', '_').lower()}-{version.lower()}-"
            )
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise RegistryError(f"M2 release dependency[{index}] is invalid")
        parsed.append(
            DependencyBinding(
                name=name,
                version=version,
                wheel_filename=filename,
                wheel_sha256=digest,
                size_bytes=_positive_integer(
                    item["size_bytes"],
                    f"dependency[{index}] size_bytes",
                ),
            )
        )
    return DependencyLock(
        raw_sha256=expected_raw_sha256,
        dependencies=tuple(parsed),
    )


def mode_string(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


def scan_content_tree(
    root: Path,
    *,
    exclude: frozenset[str] = frozenset(),
    expected_owner_uid: int | None = None,
    expected_owner_gid: int | None = None,
) -> list[dict[str, Any]]:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise RegistryError("M2 release content root is unavailable") from exc
    if expected_owner_uid is not None and root_stat.st_uid != expected_owner_uid:
        raise RegistryError("M2 release owner UID mismatch: .")
    if expected_owner_gid is not None and root_stat.st_gid != expected_owner_gid:
        raise RegistryError("M2 release owner GID mismatch: .")
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o755
    ):
        raise RegistryError("M2 release content root custody mismatch")
    entries: list[dict[str, Any]] = []
    for path in sorted(
        root.rglob("*"),
        key=lambda value: value.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        if relative in exclude:
            continue
        _safe_relative_path(relative, "M2 release content path")
        try:
            facts = path.lstat()
        except OSError as exc:
            raise RegistryError(
                f"M2 release content entry is unavailable: {relative}"
            ) from exc
        if stat.S_ISLNK(facts.st_mode):
            raise RegistryError(f"M2 release symlink is forbidden: {relative}")
        if expected_owner_uid is not None and facts.st_uid != expected_owner_uid:
            raise RegistryError(f"M2 release owner UID mismatch: {relative}")
        if expected_owner_gid is not None and facts.st_gid != expected_owner_gid:
            raise RegistryError(f"M2 release owner GID mismatch: {relative}")
        mode = stat.S_IMODE(facts.st_mode)
        if mode & 0o022:
            raise RegistryError(f"M2 release entry is group/world writable: {relative}")
        if stat.S_ISDIR(facts.st_mode):
            entries.append(
                {
                    "relative_path": relative,
                    "kind": "directory",
                    "size_bytes": 0,
                    "raw_sha256": None,
                    "mode": f"{mode:04o}",
                }
            )
            continue
        if not stat.S_ISREG(facts.st_mode) or facts.st_nlink != 1:
            raise RegistryError(f"M2 release entry type/link mismatch: {relative}")
        raw = read_regular_strict(
            path,
            f"M2 release content {relative}",
            private=False,
        )
        entries.append(
            {
                "relative_path": relative,
                "kind": "file",
                "size_bytes": len(raw),
                "raw_sha256": sha256(raw),
                "mode": f"{mode:04o}",
            }
        )
    return entries


def tree_content_sha256(entries: list[dict[str, Any]]) -> str:
    return sha256(
        canonical_json_line(
            {
                "schema_version": TREE_CONTENT_SCHEMA,
                "entries": entries,
            }
        )
    )


def validate_content_entries(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RegistryError(f"{label} must be a list")
    observed: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        entry = _exact(raw, ENTRY_KEYS, f"{label}[{index}]")
        relative = _safe_relative_path(
            entry["relative_path"],
            f"{label}[{index}] relative_path",
        )
        if relative in observed:
            raise RegistryError(f"{label} contains duplicate paths")
        observed.add(relative)
        kind = entry["kind"]
        mode = entry["mode"]
        if (
            kind not in {"directory", "file"}
            or not isinstance(mode, str)
            or re.fullmatch(r"0[0-7]{3}", mode) is None
            or int(mode, 8) & 0o022
        ):
            raise RegistryError(f"{label}[{index}] type/mode is invalid")
        if kind == "directory":
            if (
                mode != "0555"
                or entry["size_bytes"] != 0
                or entry["raw_sha256"] is not None
            ):
                raise RegistryError(f"{label}[{index}] directory is invalid")
        elif (
            mode
            != ("0555" if relative in EXECUTABLE_PATHS else "0444")
            or isinstance(entry["size_bytes"], bool)
            or not isinstance(entry["size_bytes"], int)
            or entry["size_bytes"] < 0
            or not isinstance(entry["raw_sha256"], str)
            or SHA256_PATTERN.fullmatch(entry["raw_sha256"]) is None
        ):
            raise RegistryError(f"{label}[{index}] file is invalid")
        result.append(entry)
    if result != sorted(result, key=lambda item: item["relative_path"]):
        raise RegistryError(f"{label} is not canonically sorted")
    return result


def _validate_required_tree_paths(
    entries: list[dict[str, Any]],
    *,
    runtime: bool,
) -> None:
    paths = {entry["relative_path"]: entry["kind"] for entry in entries}
    if (
        any(paths.get(path) != "directory" for path in REQUIRED_DIRECTORY_PATHS)
        or any(paths.get(path) != "file" for path in EXECUTABLE_PATHS)
        or (
            paths.get(RUNTIME_METADATA_PATH)
            != ("file" if not runtime else None)
        )
    ):
        raise RegistryError("M2 release required tree paths mismatch")


def validate_source_bindings(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise RegistryError("M2 release source bindings must be non-empty")
    result: list[dict[str, str]] = []
    repo_paths: set[str] = set()
    release_paths: set[str] = set()
    for index, raw in enumerate(value):
        item = _exact(raw, SOURCE_BINDING_KEYS, f"source binding[{index}]")
        repo_path = _safe_relative_path(
            item["repo_path"],
            f"source binding[{index}] repo_path",
        )
        release_path = _safe_relative_path(
            item["release_path"],
            f"source binding[{index}] release_path",
        )
        digest = item["raw_sha256"]
        if (
            not repo_path.endswith(".py")
            or not release_path.startswith("lib/research_warehouse/")
            or not release_path.endswith(".py")
            or repo_path in repo_paths
            or release_path in release_paths
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise RegistryError(f"source binding[{index}] is invalid")
        repo_paths.add(repo_path)
        release_paths.add(release_path)
        result.append(
            {
                "repo_path": repo_path,
                "release_path": release_path,
                "raw_sha256": digest,
            }
        )
    if result != sorted(result, key=lambda item: item["repo_path"]):
        raise RegistryError("M2 release source bindings are not canonical")
    return result


def _validate_source_entry_binding(
    bindings: list[dict[str, str]],
    entries: list[dict[str, Any]],
) -> None:
    files = {
        entry["relative_path"]: entry
        for entry in entries
        if entry["kind"] == "file"
    }
    bound_paths = {item["release_path"] for item in bindings}
    packaged_paths = {
        path
        for path in files
        if path.startswith("lib/research_warehouse/") and path.endswith(".py")
    }
    if bound_paths != packaged_paths:
        raise RegistryError("M2 release source bindings are incomplete")
    for item in bindings:
        entry = files[item["release_path"]]
        if entry["raw_sha256"] != item["raw_sha256"]:
            raise RegistryError("M2 release source binding hash mismatch")


def validate_manifest(value: object) -> dict[str, Any]:
    manifest = _exact(value, MANIFEST_KEYS, "M2 release bundle manifest")
    if (
        manifest["schema_version"] != BUNDLE_MANIFEST_SCHEMA
        or not isinstance(manifest["release_id"], str)
        or RELEASE_ID_PATTERN.fullmatch(manifest["release_id"]) is None
        or not isinstance(manifest["source_commit_sha"], str)
        or COMMIT_PATTERN.fullmatch(manifest["source_commit_sha"]) is None
        or manifest["logical_release_root"] != LOGICAL_RELEASE_ROOT
        or manifest["dependency_lock_raw_sha256"]
        != FROZEN_DEPENDENCY_LOCK_SHA256
        or manifest["python"] != python_identity()
    ):
        raise RegistryError("M2 release bundle manifest identity mismatch")
    _validate_authority(manifest["authority"], "M2 release bundle authority")
    dependencies = manifest["dependencies"]
    if not isinstance(dependencies, list) or dependencies != list(
        FROZEN_DEPENDENCIES
    ):
        raise RegistryError("M2 release manifest dependency set mismatch")
    for index, item in enumerate(dependencies):
        _exact(item, DEPENDENCY_KEYS, f"manifest dependency[{index}]")
    source_bindings = validate_source_bindings(manifest["source_bindings"])
    entries = validate_content_entries(manifest["entries"], "manifest entries")
    _validate_required_tree_paths(entries, runtime=False)
    _validate_source_entry_binding(source_bindings, entries)
    if manifest["tree_content_sha256"] != tree_content_sha256(entries):
        raise RegistryError("M2 release manifest tree hash mismatch")
    return manifest


def load_bundle_manifest(package_root: Path) -> tuple[dict[str, Any], bytes]:
    path = package_root / "bundle-manifest.json"
    try:
        facts = path.lstat()
    except OSError as exc:
        raise RegistryError("M2 release bundle manifest is unavailable") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_gid != os.getegid()
        or stat.S_IMODE(facts.st_mode) != 0o444
        or facts.st_nlink != 1
    ):
        raise RegistryError("M2 release bundle manifest custody mismatch")
    raw = read_regular_strict(
        path,
        "M2 release bundle manifest",
        private=False,
    )
    manifest = validate_manifest(
        parse_json_strict(raw, "M2 release bundle manifest")
    )
    if canonical_json_line(manifest) != raw:
        raise RegistryError("M2 release bundle manifest is not canonical")
    return manifest, raw


def validate_runtime_metadata(value: object) -> dict[str, Any]:
    metadata = _exact(value, RUNTIME_METADATA_KEYS, "M2 runtime metadata")
    if (
        metadata["schema_version"] != RUNTIME_METADATA_SCHEMA
        or not isinstance(metadata["release_id"], str)
        or RELEASE_ID_PATTERN.fullmatch(metadata["release_id"]) is None
        or not isinstance(metadata["source_commit_sha"], str)
        or COMMIT_PATTERN.fullmatch(metadata["source_commit_sha"]) is None
        or metadata["logical_release_root"] != LOGICAL_RELEASE_ROOT
        or metadata["dependency_lock_raw_sha256"]
        != FROZEN_DEPENDENCY_LOCK_SHA256
        or metadata["python"] != python_identity()
    ):
        raise RegistryError("M2 runtime metadata identity mismatch")
    _validate_authority(metadata["authority"], "M2 runtime authority")
    dependencies = metadata["dependencies"]
    if not isinstance(dependencies, list) or dependencies != list(
        FROZEN_DEPENDENCIES
    ):
        raise RegistryError("M2 runtime dependency set mismatch")
    source_bindings = validate_source_bindings(metadata["source_bindings"])
    entries = validate_content_entries(
        metadata["runtime_entries"],
        "runtime entries",
    )
    _validate_required_tree_paths(entries, runtime=True)
    _validate_source_entry_binding(source_bindings, entries)
    if metadata["runtime_tree_content_sha256"] != tree_content_sha256(entries):
        raise RegistryError("M2 runtime metadata tree hash mismatch")
    return metadata


def load_runtime_metadata(
    release_root: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
) -> tuple[dict[str, Any], bytes]:
    path = release_root / RUNTIME_METADATA_PATH
    try:
        facts = path.lstat()
    except OSError as exc:
        raise RegistryError("M2 release runtime metadata is unavailable") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != expected_owner_uid
        or facts.st_gid != expected_owner_gid
        or stat.S_IMODE(facts.st_mode) != 0o444
        or facts.st_nlink != 1
    ):
        raise RegistryError("M2 release runtime metadata custody mismatch")
    raw = read_regular_strict(
        path,
        "M2 release runtime metadata",
        private=False,
    )
    metadata = validate_runtime_metadata(
        parse_json_strict(raw, "M2 release runtime metadata")
    )
    if canonical_json_line(metadata) != raw:
        raise RegistryError("M2 release runtime metadata is not canonical")
    return metadata, raw


def require_release_id(value: str) -> str:
    if RELEASE_ID_PATTERN.fullmatch(value) is None:
        raise RegistryError("M2 release id is invalid")
    return value


def require_source_commit(value: str) -> str:
    if COMMIT_PATTERN.fullmatch(value) is None:
        raise RegistryError("M2 release source commit is invalid")
    return value


def require_safe_package_root(path: Path) -> None:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise RegistryError("M2 release package root is unavailable") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_gid != os.getegid()
        or stat.S_IMODE(facts.st_mode) != 0o700
    ):
        raise RegistryError(
            "M2 release package root must be private and current-user owned"
        )
