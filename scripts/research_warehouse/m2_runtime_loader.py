"""Load externally pinned M2 runtime evidence without private signing material."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .calendar_anchors import (
    CalendarAvailabilityAnchor,
    load_calendar_availability_anchor,
)
from .calendar_models import OfficialCalendar
from .errors import RegistryError
from .filesystem import WarehousePaths
from .m2_isolation_contracts import IsolationPolicy, load_isolation_policy
from .m2_runtime_input import RuntimeInput, load_runtime_input
from .m2_runtime_paths import RuntimePaths
from .models import SourceRegistry
from .official_calendar import load_official_calendar
from .registry import load_registry
from .signing import load_public_key, public_key_sha256


@dataclass(frozen=True)
class RuntimeContext:
    runtime_input: RuntimeInput
    policy: IsolationPolicy
    paths: WarehousePaths
    runtime: RuntimePaths
    registry: SourceRegistry
    calendar: OfficialCalendar
    availability: CalendarAvailabilityAnchor


def load_runtime_context(path: Path) -> RuntimeContext:
    policy = load_isolation_policy(path.parent / "isolation-policy-v1.json")
    runtime_input = load_runtime_input(path, policy=policy)
    value = runtime_input.payload
    registry = load_registry(Path(value["registry_path"]))
    if registry.raw_sha256 != policy.payload["registry_raw_sha256"]:
        raise RegistryError("M2 runtime registry does not match isolation policy")
    calendar_key = load_public_key(Path(value["calendar_public_key_path"]))
    if public_key_sha256(calendar_key) != value["expected_calendar_public_key_sha256"]:
        raise RegistryError("M2 calendar public key pin mismatch")
    calendar = load_official_calendar(
        Path(value["calendar_path"]),
        public_key=calendar_key,
        expected_raw_sha256=value["expected_calendar_raw_sha256"],
        source_evidence_root=Path(value["calendar_source_evidence_root"]),
    )
    availability = load_calendar_availability_anchor(
        Path(value["calendar_availability_anchor_path"]),
        expected_raw_sha256=(value["expected_calendar_availability_anchor_raw_sha256"]),
    )
    return RuntimeContext(
        runtime_input=runtime_input,
        policy=policy,
        paths=WarehousePaths.open(Path(policy.payload["custody_root"])),
        runtime=RuntimePaths.ensure(Path(policy.payload["runtime_root"])),
        registry=registry,
        calendar=calendar,
        availability=availability,
    )
