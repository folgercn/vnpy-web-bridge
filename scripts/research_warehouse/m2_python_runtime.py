"""Exact-byte contracts for one self-contained M2 Python runtime."""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN

RUNTIME_SCHEMA = "vnpy_research_m2_python_runtime_manifest_v1"
RUNTIME_CONTENT_SCHEMA = "vnpy_research_m2_python_runtime_content_v1"
RUNTIME_EXECUTABLE = "bin/python3.12"
PYTHON_RUNTIME_VERSION = "3.12.13"
PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256 = (
    "e654c21d0ba53e2c671868d4112fac5874deca4c35226d36c5cfe53bc5c9cd71"
)
PYTHON_RUNTIME_TREE_CONTENT_SHA256 = (
    "30b11e575da124b5cd1b529dc6434ee962a589073563b8b027fb33553607bfdc"
)
PYTHON_RUNTIME_MANIFEST_RAW_SHA256 = (
    "086376bad228cf428b31cc740e8e4b42a19d4f3de1de9b7efb7c743a697e45b1"
)
RUNTIME_KEYS = {
    "schema_version",
    "python_version",
    "source_archive_raw_sha256",
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


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def snapshot_python_runtime(root: Path) -> list[dict[str, Any]]:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise RegistryError("M2 Python runtime root is unavailable") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o755
    ):
        raise RegistryError("M2 Python runtime root custody mismatch")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise RegistryError("M2 Python runtime contains a symlink")
        if stat.S_ISDIR(value.st_mode):
            kind = "directory"
            raw = None
            size = 0
            expected_mode = 0o755
        elif stat.S_ISREG(value.st_mode):
            kind = "file"
            raw = read_regular_strict(
                path,
                f"M2 Python runtime entry {relative}",
                private=False,
            )
            size = len(raw)
            expected_mode = 0o555 if relative == RUNTIME_EXECUTABLE else 0o444
        else:
            raise RegistryError("M2 Python runtime entry type is forbidden")
        if stat.S_IMODE(value.st_mode) != expected_mode:
            raise RegistryError("M2 Python runtime entry mode mismatch")
        entries.append(
            {
                "relative_path": relative,
                "kind": kind,
                "size_bytes": size,
                "raw_sha256": None if raw is None else sha256(raw),
                "mode": f"{expected_mode:04o}",
            }
        )
    by_path = {entry["relative_path"]: entry for entry in entries}
    if (
        RUNTIME_EXECUTABLE not in by_path
        or by_path[RUNTIME_EXECUTABLE]["kind"] != "file"
    ):
        raise RegistryError("M2 Python runtime executable is missing")
    return entries


def runtime_content_sha256(entries: list[dict[str, Any]]) -> str:
    return sha256(
        canonical_json_line(
            {
                "schema_version": RUNTIME_CONTENT_SCHEMA,
                "entries": entries,
            }
        )
    )


def create_python_runtime_manifest(
    root: Path,
) -> dict[str, Any]:
    entries = snapshot_python_runtime(root)
    tree_digest = runtime_content_sha256(entries)
    if tree_digest != PYTHON_RUNTIME_TREE_CONTENT_SHA256:
        raise RegistryError(
            "M2 Python runtime is not the approved archive extraction"
        )
    manifest = {
        "schema_version": RUNTIME_SCHEMA,
        "python_version": PYTHON_RUNTIME_VERSION,
        "source_archive_raw_sha256": PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256,
        "entries": entries,
        "tree_content_sha256": tree_digest,
    }
    if sha256(canonical_json_line(manifest)) != PYTHON_RUNTIME_MANIFEST_RAW_SHA256:
        raise RegistryError("M2 Python runtime approved manifest mismatch")
    return manifest


def load_python_runtime_manifest(
    path: Path,
    *,
    expected_raw_sha256: str,
    private: bool = True,
) -> tuple[dict[str, Any], str]:
    if SHA256_PATTERN.fullmatch(expected_raw_sha256) is None:
        raise RegistryError("expected M2 Python runtime manifest SHA256 is invalid")
    if expected_raw_sha256 != PYTHON_RUNTIME_MANIFEST_RAW_SHA256:
        raise RegistryError("M2 Python runtime manifest is not approved")
    raw = read_regular_strict(
        path,
        "M2 Python runtime manifest",
        private=private,
    )
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 Python runtime manifest SHA256 mismatch")
    value = parse_json_strict(raw, "M2 Python runtime manifest")
    if canonical_json_line(value) != raw:
        raise RegistryError("M2 Python runtime manifest is not canonical")
    _validate_manifest(value)
    return value, expected_raw_sha256


def _validate_manifest(value: object) -> dict[str, Any]:
    manifest = _exact(value, RUNTIME_KEYS, "M2 Python runtime manifest")
    if (
        manifest["schema_version"] != RUNTIME_SCHEMA
        or manifest["python_version"] != PYTHON_RUNTIME_VERSION
        or manifest["source_archive_raw_sha256"]
        != PYTHON_RUNTIME_SOURCE_ARCHIVE_SHA256
        or manifest["tree_content_sha256"]
        != PYTHON_RUNTIME_TREE_CONTENT_SHA256
        or not isinstance(manifest["entries"], list)
        or SHA256_PATTERN.fullmatch(manifest["tree_content_sha256"]) is None
    ):
        raise RegistryError("M2 Python runtime manifest contract mismatch")
    for entry in manifest["entries"]:
        _exact(entry, ENTRY_KEYS, "M2 Python runtime entry")
    return manifest


def verify_python_runtime(root: Path, manifest: object) -> None:
    value = _validate_manifest(manifest)
    actual = snapshot_python_runtime(root)
    if (
        actual != value["entries"]
        or runtime_content_sha256(actual) != value["tree_content_sha256"]
    ):
        raise RegistryError("M2 Python runtime content mismatch")


def verify_runtime_execution(root: Path) -> Path:
    """Run only during the unprivileged build and prove private-prefix use."""
    executable = root / RUNTIME_EXECUTABLE
    completed = subprocess.run(
        [
            str(executable),
            "-B",
            "-I",
            "-c",
            (
                "import json,site,sys,sysconfig;"
                "print(json.dumps({'version':sys.version.split()[0],"
                "'prefix':sys.prefix,"
                "'stdlib':sysconfig.get_path('stdlib'),"
                "'user_site':site.ENABLE_USER_SITE},sort_keys=True))"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        facts = json.loads(completed.stdout)
        exact_root = root.resolve(strict=True)
        prefix = Path(facts["prefix"]).resolve(strict=True)
        stdlib = Path(facts["stdlib"]).resolve(strict=True)
    except (json.JSONDecodeError, KeyError, OSError, TypeError) as exc:
        raise RegistryError("M2 private Python runtime facts are invalid") from exc
    if (
        completed.returncode != 0
        or facts["version"] != PYTHON_RUNTIME_VERSION
        or facts["user_site"] is not False
        or prefix != exact_root
        or not stdlib.is_relative_to(exact_root)
    ):
        raise RegistryError("M2 Python runtime is not self-contained")
    return executable
