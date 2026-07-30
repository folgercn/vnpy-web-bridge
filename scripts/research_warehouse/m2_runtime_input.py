"""Root-managed external pins for the M2 operational runtime."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .custody_paths import normalized_absolute
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_acl_custody import require_acl_free_fd, require_acl_free_path
from .m2_isolation_contracts import IsolationPolicy, false_authority
from .manifest_contracts import SHA256_PATTERN

RUNTIME_INPUT_SCHEMA = "vnpy_research_m2_runtime_input_v1"
DEFAULT_RUNTIME_INPUT = Path("/usr/local/libexec/vnpyresearch/runtime-input-v1.json")
INPUT_KEYS = {
    "schema_version",
    "policy_path",
    "registry_path",
    "calendar_path",
    "calendar_public_key_path",
    "calendar_source_evidence_root",
    "calendar_availability_anchor_path",
    "backup_public_key_path",
    "expected_calendar_raw_sha256",
    "expected_calendar_public_key_sha256",
    "expected_calendar_availability_anchor_raw_sha256",
    "expected_backup_public_key_sha256",
    "expected_backup_head_anchor_raw_sha256",
    "monitor_from_day",
    "collector_version",
    "authority",
}


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise RegistryError(f"{label} SHA256 is invalid")
    return value


def require_day(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD")
    try:
        result = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD") from exc
    if result.isoformat() != value:
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD")
    return result


def _path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RegistryError(f"{label} path is invalid")
    return normalized_absolute(Path(value))


@dataclass(frozen=True)
class RuntimeInput:
    path: Path
    raw_sha256: str
    payload: dict[str, Any]


def _require_root_owner_mode(info: os.stat_result, label: str) -> None:
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise RegistryError(f"{label} must be root-managed and non-writable")


def require_root_managed(path: Path) -> None:
    try:
        parent_info = path.parent.lstat()
    except OSError as exc:
        raise RegistryError("M2 root-managed runtime input is unavailable") from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RegistryError("M2 runtime input parent is unsafe")
    _require_root_owner_mode(parent_info, "M2 runtime input parent")
    require_acl_free_path(path.parent, "M2 runtime input parent")
    require_acl_free_path(path, "M2 runtime input")


def _validate_runtime_input_fd(descriptor: int) -> None:
    _require_root_owner_mode(
        os.fstat(descriptor),
        "M2 runtime input",
    )
    require_acl_free_fd(descriptor, "M2 runtime input")


def load_runtime_input(path: Path, *, policy: IsolationPolicy) -> RuntimeInput:
    require_root_managed(path)
    raw = read_regular_strict(
        path,
        "M2 runtime input",
        private=False,
        descriptor_validator=_validate_runtime_input_fd,
    )
    payload = parse_json_strict(raw, "M2 runtime input")
    if (
        not isinstance(payload, dict)
        or set(payload) != INPUT_KEYS
        or payload["schema_version"] != RUNTIME_INPUT_SCHEMA
        or raw != canonical_json_line(payload)
        or payload["authority"] != false_authority()
    ):
        raise RegistryError("M2 runtime input contract mismatch")
    for field in (
        "expected_calendar_raw_sha256",
        "expected_calendar_public_key_sha256",
        "expected_calendar_availability_anchor_raw_sha256",
        "expected_backup_public_key_sha256",
        "expected_backup_head_anchor_raw_sha256",
    ):
        require_sha(payload[field], field)
    for field in (
        "policy_path",
        "registry_path",
        "calendar_path",
        "calendar_public_key_path",
        "calendar_source_evidence_root",
        "calendar_availability_anchor_path",
        "backup_public_key_path",
    ):
        _path(payload[field], field)
    if (
        payload["policy_path"] != str(path.parent / "isolation-policy-v1.json")
        or payload["registry_path"] != str(path.parent / "source-registry-v1.json")
        or payload["collector_version"] != "m2-daily-scheduler-v1"
        or payload["authority"] != policy.payload["authority"]
    ):
        raise RegistryError("M2 runtime fixed identity mismatch")
    require_day(payload["monitor_from_day"], "monitor_from_day")
    return RuntimeInput(path=path, raw_sha256=sha256(raw), payload=payload)
