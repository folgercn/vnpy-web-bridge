"""Derive M2 monitor facts from custody, filesystem, and backup evidence."""

from __future__ import annotations

import shutil
from datetime import date, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .backup_anchor import verify_backup_anchor
from .backup_custody import BackupPaths
from .calendar_models import OfficialCalendar
from .canonical import sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .filesystem import WarehousePaths
from .m2_daily_scheduler import AFTER_CLOSE
from .m2_receipts import load_run_receipt
from .m2_runtime_paths import RuntimePaths
from .models import SourceRegistry
from .observations import load_observations
from .revisions import revision_state
from .timeutil import format_utc, parse_utc
from .validation import validate_source_bytes

SHANGHAI = ZoneInfo("Asia/Shanghai")


def expected_official_day(
    calendar: OfficialCalendar,
    *,
    now: datetime,
) -> date:
    local = now.astimezone(SHANGHAI)
    calendar.require_day(local.date())
    upper = local.date()
    if (
        calendar.require_day(upper).is_official
        and local.time().replace(tzinfo=None) < AFTER_CLOSE
    ):
        upper = date.fromordinal(upper.toordinal() - 1)
    candidates = sorted(
        item.day
        for item in calendar.days.values()
        if item.is_official and item.day <= upper
    )
    if not candidates:
        raise RegistryError("calendar has no completed official day")
    return candidates[-1]


def verify_daily_run_receipt(
    receipt: dict[str, Any],
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    calendar: OfficialCalendar,
    calendar_availability_raw_sha256: str,
) -> datetime:
    if (
        receipt["registry_raw_sha256"] != registry.raw_sha256
        or receipt["calendar_raw_sha256"] != calendar.raw_sha256
        or receipt["calendar_availability_anchor_raw_sha256"]
        != calendar_availability_raw_sha256
        or not calendar.require_day(
            date.fromisoformat(receipt["trade_day"])
        ).is_official
    ):
        raise RegistryError("M2 run receipt authority binding mismatch")
    observed_completion = []
    for item in receipt["sources"]:
        source = registry.source(item["source_id"])
        if item["exchange"] != source.exchange:
            raise RegistryError("M2 run receipt exchange binding mismatch")
        observations = load_observations(
            paths,
            registry,
            source_id=source.source_id,
            trade_day=receipt["trade_day"],
        )
        matches = [
            observation
            for observation in observations
            if observation["observation_id"] == item["observation_id"]
        ]
        if len(matches) != 1:
            raise RegistryError("M2 run receipt observation binding mismatch")
        observation = matches[0]
        observed_completion.append(
            parse_utc(observation["last_seen_at"], "observation last_seen_at")
        )
        for field in (
            "object_id",
            "revision_id",
            "raw_sha256",
            "raw_bytes",
            "raw_relative_path",
        ):
            if observation[field] != item[field]:
                raise RegistryError("M2 run receipt custody binding mismatch")
        raw_path = paths.root / item["raw_relative_path"]
        raw = read_regular_strict(raw_path, "M2 run receipt raw evidence")
        if len(raw) != item["raw_bytes"] or sha256(raw) != item["raw_sha256"]:
            raise RegistryError("M2 run receipt raw hash binding mismatch")
        validate_source_bytes(raw, source, receipt["trade_day"])
    completed_at = max(observed_completion)
    if parse_utc(receipt["completed_at"], "run receipt completed_at") != completed_at:
        raise RegistryError("M2 run receipt completion time binding mismatch")
    return completed_at


def _unreviewed_revisions(
    receipt: dict[str, Any],
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
) -> int:
    count = 0
    for item in receipt["sources"]:
        observations = load_observations(
            paths,
            registry,
            source_id=item["source_id"],
            trade_day=receipt["trade_day"],
        )
        revisions = revision_state(observations)
        if not revisions or revisions[-1]["revision_id"] != item["revision_id"]:
            count += 1
    return count


def derive_monitor_facts(
    *,
    paths: WarehousePaths,
    runtime: RuntimePaths,
    registry: SourceRegistry,
    calendar: OfficialCalendar,
    calendar_availability_raw_sha256: str,
    monitor_from_day: date,
    backup_root: Path,
    backup_public_key_path: Path,
    expected_backup_public_key_sha256: str,
    expected_backup_head_anchor_raw_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    expected = expected_official_day(calendar, now=now)
    if (
        monitor_from_day > expected
        or not calendar.require_day(monitor_from_day).is_official
    ):
        raise RegistryError("monitor_from_day must be a completed official day")
    official_days = [
        day
        for day, item in sorted(calendar.days.items())
        if item.is_official and monitor_from_day <= day <= expected
    ]
    candidates: dict[date, list[dict[str, Any]]] = {}
    verified_completion: dict[date, datetime] = {}
    hash_mismatches = 0
    unreviewed = 0
    receipt_paths = sorted(runtime.run_receipts.glob("*.json")) + sorted(
        runtime.history_run_receipts.glob("*.json")
    )
    for receipt_path in receipt_paths:
        try:
            receipt = load_run_receipt(receipt_path)
            trade_day = date.fromisoformat(receipt["trade_day"])
            if trade_day < monitor_from_day or trade_day > expected:
                continue
            candidates.setdefault(trade_day, []).append(receipt)
        except (OSError, RegistryError, ValueError):
            hash_mismatches += 1
    valid: dict[date, dict[str, Any]] = {}
    for trade_day, receipts in candidates.items():
        verified: list[tuple[datetime, dict[str, Any]]] = []
        authority_mismatches = 0
        other_mismatches = 0
        for receipt in receipts:
            try:
                completed_at = verify_daily_run_receipt(
                    receipt,
                    paths=paths,
                    registry=registry,
                    calendar=calendar,
                    calendar_availability_raw_sha256=(
                        calendar_availability_raw_sha256
                    ),
                )
                verified.append((completed_at, receipt))
            except RegistryError as exc:
                if str(exc) == "M2 run receipt authority binding mismatch":
                    authority_mismatches += 1
                else:
                    other_mismatches += 1
            except (OSError, ValueError):
                other_mismatches += 1
        if not verified:
            hash_mismatches += authority_mismatches + other_mismatches
            continue
        # A current-authority history receipt supersedes a retained daily
        # receipt from before calendar rotation.  Preserve every other
        # verification failure as a monitor alarm.
        hash_mismatches += other_mismatches
        completed_at, receipt = max(verified, key=lambda item: item[0])
        valid[trade_day] = receipt
        verified_completion[trade_day] = completed_at
        unreviewed += _unreviewed_revisions(
            receipt,
            paths=paths,
            registry=registry,
        )
    completed = [day for day in official_days if day in valid]
    missing = [day.isoformat() for day in official_days if day not in valid]
    latest = max(completed) if completed else None
    last_success = max(
        (verified_completion[day] for day in completed),
        default=None,
    )
    backup_verified = False
    last_backup = None
    try:
        anchor = verify_backup_anchor(
            paths=BackupPaths.open(backup_root),
            public_key_path=backup_public_key_path,
            expected_public_key_sha256=expected_backup_public_key_sha256,
            expected_head_anchor_raw_sha256=(expected_backup_head_anchor_raw_sha256),
        )
        backup_verified = True
        last_backup = anchor.created_at
    except (OSError, RegistryError):
        pass
    return {
        "last_success_at": (
            format_utc(last_success, "last success")
            if last_success is not None
            else None
        ),
        "expected_official_day": expected.isoformat(),
        "latest_official_day": latest.isoformat() if latest is not None else None,
        "missing_official_days": missing,
        "unreviewed_revision_count": unreviewed,
        "hash_mismatch_count": hash_mismatches,
        "disk_free_bytes": shutil.disk_usage(paths.root).free,
        "last_backup_at": (
            format_utc(last_backup, "last backup") if last_backup is not None else None
        ),
        "backup_verified": backup_verified,
    }
