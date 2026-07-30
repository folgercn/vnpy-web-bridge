"""Fail-closed runtime entry for one installed M2 Research release."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import platform
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_release_bundle_contracts import (
    LOGICAL_RELEASE_ROOT,
    PYTHON_EXECUTABLE,
    PYTHON_IMPLEMENTATION,
    PYTHON_VERSION,
    RUNTIME_METADATA_PATH,
    false_authority,
    load_runtime_metadata,
    scan_content_tree,
    tree_content_sha256,
)

ROLES = {"warehouse", "monitor"}
COMMANDS = {"self-check"}
FORBIDDEN_ENVIRONMENT = {
    "COMMODITY_C_FAST_SIMNOW_RPC_REQUEST_ADDRESS",
    "COMMODITY_C_FAST_SIMNOW_RPC_SUBSCRIBE_ADDRESS",
    "DOCKER_HOST",
    "WEB_TRADE_ENABLED",
}
ROLE_IMPORTS = {
    "warehouse": (
        "research_warehouse.acquisition",
        "research_warehouse.official_calendar",
        "research_warehouse.registry",
    ),
    "monitor": (
        "research_warehouse.m2_monitor",
        "research_warehouse.backup_contracts",
    ),
}
DEPENDENCY_IMPORTS = {
    "cffi": "cffi",
    "cryptography": "cryptography",
    "duckdb": "duckdb",
    "pycparser": "pycparser",
}


def _verify_interpreter() -> None:
    if (
        platform.python_implementation() != PYTHON_IMPLEMENTATION
        or platform.python_version() != PYTHON_VERSION
        or sys.version_info[:2] != (3, 12)
        or sys.flags.isolated != 1
        or sys.flags.no_user_site != 1
    ):
        raise RegistryError("M2 release interpreter identity/isolation mismatch")
    try:
        if not os.path.samefile(sys.executable, PYTHON_EXECUTABLE):
            raise RegistryError("M2 release interpreter path mismatch")
    except OSError as exc:
        raise RegistryError("M2 release interpreter path is unavailable") from exc


def _distribution_versions(
    site_packages: Path,
) -> dict[str, str]:
    observed: dict[str, str] = {}
    try:
        distributions = importlib.metadata.distributions(path=[str(site_packages)])
        for distribution in distributions:
            name = distribution.metadata.get("Name")
            version = distribution.version
            if not name or not version:
                raise RegistryError("M2 release distribution metadata is incomplete")
            normalized = name.lower().replace("-", "_")
            if normalized in observed:
                raise RegistryError("M2 release distribution metadata is duplicated")
            observed[normalized] = version
    except (OSError, UnicodeError) as exc:
        raise RegistryError("M2 release distribution metadata is unreadable") from exc
    return observed


def _import_from_release(module_name: str, expected_root: Path) -> None:
    module = importlib.import_module(module_name)
    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str) or not origin:
        raise RegistryError(f"M2 release import has no file origin: {module_name}")
    try:
        resolved_origin = Path(origin).resolve(strict=True)
        resolved_root = expected_root.resolve(strict=True)
    except OSError as exc:
        raise RegistryError(
            f"M2 release import origin is unavailable: {module_name}"
        ) from exc
    if not resolved_origin.is_relative_to(resolved_root):
        raise RegistryError(
            f"M2 release import escaped frozen tree: {module_name}"
        )


def self_check_release(
    *,
    release_root: Path,
    role: str,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
    enforce_interpreter: bool = True,
    import_modules: bool = True,
) -> dict[str, Any]:
    if role not in ROLES:
        raise RegistryError("M2 release role is invalid")
    if release_root.as_posix() != LOGICAL_RELEASE_ROOT and enforce_interpreter:
        raise RegistryError("M2 release logical root mismatch")
    if enforce_interpreter:
        _verify_interpreter()
    if FORBIDDEN_ENVIRONMENT & set(os.environ):
        raise RegistryError("M2 release inherited a forbidden environment")
    metadata, _raw = load_runtime_metadata(
        release_root,
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )
    actual_entries = scan_content_tree(
        release_root,
        exclude=frozenset({RUNTIME_METADATA_PATH}),
        expected_owner_uid=expected_owner_uid,
        expected_owner_gid=expected_owner_gid,
    )
    if (
        actual_entries != metadata["runtime_entries"]
        or tree_content_sha256(actual_entries)
        != metadata["runtime_tree_content_sha256"]
    ):
        raise RegistryError("M2 release runtime tree does not match metadata")
    expected_versions = {
        item["name"].lower().replace("-", "_"): item["version"]
        for item in metadata["dependencies"]
    }
    observed_versions = _distribution_versions(
        release_root / "lib/python3.12/site-packages"
    )
    if observed_versions != expected_versions:
        raise RegistryError("M2 release dependency versions do not match lock")
    if import_modules:
        for dependency in sorted(DEPENDENCY_IMPORTS):
            _import_from_release(
                DEPENDENCY_IMPORTS[dependency],
                release_root / "lib/python3.12/site-packages",
            )
        for module in ROLE_IMPORTS[role]:
            _import_from_release(module, release_root / "lib")
    return {
        "schema_version": "vnpy_research_m2_release_entry_result_v1",
        "status": "RELEASE_SELF_CHECK_PASSED_NO_SCHEDULE_AUTHORITY",
        "role": role,
        "release_id": metadata["release_id"],
        "source_commit_sha": metadata["source_commit_sha"],
        "runtime_tree_content_sha256": metadata[
            "runtime_tree_content_sha256"
        ],
        "dependency_lock_raw_sha256": metadata[
            "dependency_lock_raw_sha256"
        ],
        "authority": false_authority(),
    }


def main(
    argv: list[str] | None = None,
    *,
    release_root: Path = Path(LOGICAL_RELEASE_ROOT),
) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 2 or values[0] not in ROLES or values[1] not in COMMANDS:
        return 64
    try:
        result = self_check_release(
            release_root=release_root,
            role=values[0],
        )
    except RegistryError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json_line(result))
    return 0
