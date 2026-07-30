"""Root-managed activation of immutable, service-issued calendar inputs."""

from __future__ import annotations

from pathlib import Path

from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .m2_isolation_contracts import IsolationPolicy, false_authority
from .m2_operator_state import (
    _atomic_root_write,
    _prepare_public_root_directory,
)
from .m2_runtime_input import RuntimeInput, load_runtime_input

ROTATION_SCHEMA = "vnpy_research_m2_calendar_rotation_v1"


def activate_calendar_rotation(
    *,
    current: RuntimeInput,
    policy: IsolationPolicy,
    issued: dict[str, object],
) -> dict[str, object]:
    """Archive the old root pin, record a receipt, then atomically switch it."""
    if current.path != Path("/usr/local/libexec/vnpyresearch/runtime-input-v1.json"):
        raise RegistryError("calendar rotation requires the production runtime input")
    repeated = load_runtime_input(current.path, policy=policy)
    if repeated.raw_sha256 != current.raw_sha256:
        raise RegistryError("M2 runtime input changed during calendar rotation")
    required = {
        "calendar_path",
        "calendar_raw_sha256",
        "calendar_availability_anchor_path",
        "calendar_availability_anchor_raw_sha256",
        "available_at",
        "new_evidence_sha256",
    }
    if set(issued) != required:
        raise RegistryError("calendar issuance result contract mismatch")
    payload = dict(current.payload)
    payload.update(
        {
            "calendar_path": issued["calendar_path"],
            "expected_calendar_raw_sha256": issued["calendar_raw_sha256"],
            "calendar_availability_anchor_path": (
                issued["calendar_availability_anchor_path"]
            ),
            "expected_calendar_availability_anchor_raw_sha256": (
                issued["calendar_availability_anchor_raw_sha256"]
            ),
        }
    )
    new_raw = canonical_json_line(payload)
    new_sha = sha256(new_raw)
    rotation_root = current.path.parent / "calendar-rotations"
    _prepare_public_root_directory(rotation_root)
    archive = rotation_root / f"runtime-input-{current.raw_sha256}.json"
    _atomic_root_write(archive, canonical_json_line(current.payload), create_only=True)
    receipt = {
        "schema_version": ROTATION_SCHEMA,
        "old_runtime_input_raw_sha256": current.raw_sha256,
        "new_runtime_input_raw_sha256": new_sha,
        "calendar_raw_sha256": issued["calendar_raw_sha256"],
        "calendar_availability_anchor_raw_sha256": (
            issued["calendar_availability_anchor_raw_sha256"]
        ),
        "available_at": issued["available_at"],
        "new_evidence_sha256": issued["new_evidence_sha256"],
        "authority": false_authority(),
    }
    receipt_raw = canonical_json_line(receipt)
    receipt_path = rotation_root / f"rotation-{new_sha}.json"
    _atomic_root_write(receipt_path, receipt_raw, create_only=True)
    _atomic_root_write(current.path, new_raw, create_only=False)
    activated = load_runtime_input(current.path, policy=policy)
    if activated.raw_sha256 != new_sha:
        raise RegistryError("activated calendar runtime pin mismatch")
    return {
        **issued,
        "old_runtime_input_raw_sha256": current.raw_sha256,
        "runtime_input_raw_sha256": new_sha,
        "rotation_receipt_path": str(receipt_path),
        "rotation_receipt_raw_sha256": sha256(receipt_raw),
    }
