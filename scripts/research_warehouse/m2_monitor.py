"""Pure monitoring evaluation for one Research Warehouse M2 snapshot."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from .errors import RegistryError
from .m2_isolation_contracts import IsolationPolicy, false_authority
from .timeutil import parse_utc

MONITOR_INPUT_KEYS = {
    "last_success_at",
    "expected_official_day",
    "latest_official_day",
    "missing_official_days",
    "unreviewed_revision_count",
    "hash_mismatch_count",
    "disk_free_bytes",
    "last_backup_at",
    "backup_verified",
}


def _day(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be canonical ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"{label} is not canonical")
    return parsed


def evaluate_monitor(
    value: object,
    *,
    policy: IsolationPolicy,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != MONITOR_INPUT_KEYS:
        raise RegistryError("M2 monitor input fields do not match v1")
    current = now
    if current.tzinfo is None or current.utcoffset() is None:
        raise RegistryError("M2 monitor now must be timezone-aware")
    last_success = (
        None
        if value["last_success_at"] is None
        else parse_utc(value["last_success_at"], "last success")
    )
    last_backup = (
        None
        if value["last_backup_at"] is None
        else parse_utc(value["last_backup_at"], "last backup")
    )
    if (last_success is not None and last_success > current) or (
        last_backup is not None and last_backup > current
    ):
        raise RegistryError("M2 monitor facts cannot be in the future")
    expected = _day(value["expected_official_day"], "expected official day")
    latest = (
        None
        if value["latest_official_day"] is None
        else _day(value["latest_official_day"], "latest official day")
    )
    if latest is not None and latest > expected:
        raise RegistryError("M2 latest official day cannot exceed expected day")
    missing = value["missing_official_days"]
    if (
        not isinstance(missing, list)
        or any(_day(item, "missing official day") > expected for item in missing)
        or len(missing) != len(set(missing))
    ):
        raise RegistryError("M2 missing-day evidence is invalid")
    for field in (
        "unreviewed_revision_count",
        "hash_mismatch_count",
        "disk_free_bytes",
    ):
        if (
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or value[field] < 0
        ):
            raise RegistryError(f"M2 monitor {field} is invalid")
    if not isinstance(value["backup_verified"], bool):
        raise RegistryError("M2 backup_verified must be boolean")
    thresholds = policy.payload["monitor_thresholds"]
    incidents = []
    if last_success is None or current - last_success > timedelta(
        seconds=thresholds["last_success_max_age_seconds"]
    ):
        incidents.append("LAST_SUCCESS_STALE")
    if missing or latest is None or latest < expected:
        incidents.append("OFFICIAL_DAY_MISSING")
    if value["unreviewed_revision_count"]:
        incidents.append("UNREVIEWED_REVISION")
    if value["hash_mismatch_count"]:
        incidents.append("HASH_MISMATCH")
    if value["disk_free_bytes"] < thresholds["disk_free_min_bytes"]:
        incidents.append("DISK_FREE_LOW")
    if (
        not value["backup_verified"]
        or last_backup is None
        or current - last_backup
        > timedelta(seconds=thresholds["backup_max_age_seconds"])
    ):
        incidents.append("BACKUP_STALE_OR_UNVERIFIED")
    return {
        "schema_version": "vnpy_research_m2_monitor_result_v1",
        "status": "HEALTHY" if not incidents else "DEGRADED",
        "incidents": incidents,
        "authority": false_authority(),
    }
