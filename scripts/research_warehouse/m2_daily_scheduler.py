"""Calendar-authoritative M2 daily acquisition scheduler."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

from .acquisition import acquire_daily
from .acquisition_models import AcquiredObject
from .calendar_anchors import CalendarAvailabilityAnchor
from .calendar_models import OfficialCalendar
from .canonical import sha256
from .clock_quality import TrustedClockSample, validate_live_clock_sample
from .errors import RegistryError
from .filesystem import WarehousePaths
from .m2_isolation_contracts import false_authority
from .m2_receipts import (
    RUN_RECEIPT_SCHEMA,
    SOURCE_IDS,
    load_run_receipt,
    publish_run_receipt,
    run_receipt_id,
)
from .m2_runtime_paths import RuntimePaths
from .models import SourceRegistry
from .official_calendar import revalidate_official_calendar_evidence
from .timeutil import format_utc

SHANGHAI = ZoneInfo("Asia/Shanghai")
AFTER_CLOSE = time(18, 0)


def due_trade_day(calendar: OfficialCalendar, *, now: datetime) -> str | None:
    local = now.astimezone(SHANGHAI)
    day = calendar.require_day(local.date())
    if not day.is_official:
        return None
    if local.time().replace(tzinfo=None) < AFTER_CLOSE:
        raise RegistryError("official-day acquisition is not due before close")
    return local.date().isoformat()


def _existing_receipt(
    runtime: RuntimePaths,
    trade_day: str,
    *,
    verify: Callable[[dict], None],
) -> Path | None:
    path = runtime.run_receipts / f"{trade_day}.json"
    if not path.exists():
        return None
    receipt = load_run_receipt(path)
    verify(receipt)
    return path


def run_daily(
    *,
    paths: WarehousePaths,
    runtime: RuntimePaths,
    registry: SourceRegistry,
    calendar: OfficialCalendar,
    availability: CalendarAvailabilityAnchor,
    clock_sample: TrustedClockSample,
    collector_version: str,
    verify_receipt: Callable[[dict], None],
    acquire: Callable[..., object] = acquire_daily,
    utc_clock: Callable[[], datetime] | None = None,
    clock_provider: Callable[[], TrustedClockSample] | None = None,
) -> dict:
    live_now = (utc_clock or (lambda: clock_sample.trusted_now))()
    validate_live_clock_sample(clock_sample, local_now=live_now)
    revalidate_official_calendar_evidence(calendar)
    availability.require_available(calendar, cutoff_at=clock_sample.trusted_now)
    trade_day = due_trade_day(calendar, now=clock_sample.trusted_now)
    if trade_day is None:
        return {
            "status": "CALENDAR_CLOSED_SKIPPED",
            "calendar_raw_sha256": calendar.raw_sha256,
            "authority": false_authority(),
        }
    return run_trade_day(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar,
        availability=availability,
        trade_day=trade_day,
        clock_sample=clock_sample,
        collector_version=collector_version,
        verify_receipt=verify_receipt,
        acquire=acquire,
        utc_clock=utc_clock,
        clock_provider=clock_provider,
    )


def run_trade_day(
    *,
    paths: WarehousePaths,
    runtime: RuntimePaths,
    registry: SourceRegistry,
    calendar: OfficialCalendar,
    availability: CalendarAvailabilityAnchor,
    trade_day: str,
    clock_sample: TrustedClockSample,
    collector_version: str,
    verify_receipt: Callable[[dict], None],
    acquire: Callable[..., object] = acquire_daily,
    utc_clock: Callable[[], datetime] | None = None,
    clock_provider: Callable[[], TrustedClockSample] | None = None,
) -> dict:
    """Acquire one explicit official day using only live observation clocks."""
    live_now = (utc_clock or (lambda: clock_sample.trusted_now))()
    validate_live_clock_sample(clock_sample, local_now=live_now)
    revalidate_official_calendar_evidence(calendar)
    availability.require_available(calendar, cutoff_at=clock_sample.trusted_now)
    try:
        parsed_day = datetime.strptime(trade_day, "%Y-%m-%d").date()
    except ValueError as exc:
        raise RegistryError("trade_day must be canonical YYYY-MM-DD") from exc
    if parsed_day.isoformat() != trade_day:
        raise RegistryError("trade_day must be canonical YYYY-MM-DD")
    if not calendar.require_day(parsed_day).is_official:
        raise RegistryError("historical acquisition day is not official")
    existing = _existing_receipt(
        runtime,
        trade_day,
        verify=verify_receipt,
    )
    if existing is not None:
        return {
            "status": "ALREADY_COMPLETE",
            "trade_day": trade_day,
            "receipt": str(existing),
            "receipt_raw_sha256": sha256(existing.read_bytes()),
            "authority": false_authority(),
        }
    results: list[tuple[object, AcquiredObject]] = []
    for source_id in SOURCE_IDS:
        source = registry.source(source_id)
        source_clock = clock_provider() if clock_provider else clock_sample
        acquired = acquire(
            paths=paths,
            registry=registry,
            source_id=source_id,
            trade_day=trade_day,
            collector_version=collector_version,
            calendar=calendar,
            clock_sample=source_clock,
            utc_clock=utc_clock,
        )
        if not isinstance(acquired, AcquiredObject):
            raise RegistryError("official-day acquisition did not return raw custody")
        results.append((source, acquired))
    completed_at = max(item.last_seen_at for _, item in results)
    payload = {
        "schema_version": RUN_RECEIPT_SCHEMA,
        "receipt_id": "",
        "trade_day": trade_day,
        "completed_at": format_utc(completed_at, "completed_at"),
        "registry_raw_sha256": registry.raw_sha256,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_availability_anchor_raw_sha256": availability.raw_sha256,
        "sources": [
            {
                "source_id": source.source_id,
                "exchange": source.exchange,
                "object_id": acquired.object_id,
                "observation_id": acquired.observation_id,
                "revision_id": acquired.revision_id,
                "raw_sha256": acquired.raw_sha256,
                "raw_bytes": acquired.raw_bytes,
                "raw_relative_path": str(acquired.raw_path.relative_to(paths.root)),
            }
            for source, acquired in results
        ],
        "authority": false_authority(),
    }
    payload["receipt_id"] = run_receipt_id(payload)
    verify_receipt(payload)
    receipt = publish_run_receipt(runtime, payload)
    return {
        "status": "OFFICIAL_DAY_COMPLETE",
        "trade_day": trade_day,
        "receipt": str(receipt),
        "receipt_raw_sha256": sha256(receipt.read_bytes()),
        "authority": false_authority(),
    }
