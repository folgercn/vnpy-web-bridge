"""Bounded, resumable historical acquisition over authoritative official days."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from datetime import date, datetime
from typing import Any

from .calendar_anchors import CalendarAvailabilityAnchor
from .calendar_models import OfficialCalendar
from .canonical import sha256
from .clock_quality import TrustedClockSample
from .daily_evidence import require_target_product_receipt_coverage
from .errors import RegistryError, RetryableTransportError
from .file_integrity import read_regular_strict
from .filesystem import WarehousePaths
from .history_backfill_receipts import (
    BACKFILL_RECEIPT_SCHEMA,
    backfill_receipt_id,
    load_backfill_receipt,
    publish_backfill_receipt,
)
from .m2_daily_scheduler import run_trade_day
from .m2_isolation_contracts import false_authority
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_operator_state import OperatorState
from .m2_receipts import load_run_receipt
from .m2_runtime_paths import RuntimePaths
from .models import SourceRegistry
from .timeutil import format_utc

DEFAULT_HISTORY_DAYS = 186
MAX_HISTORY_DAYS = 366


def history_days(
    calendar: OfficialCalendar,
    *,
    through_trade_day: date,
    count: int,
) -> tuple[date, ...]:
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or count > MAX_HISTORY_DAYS
    ):
        raise RegistryError("history day count must be between 1 and 366")
    return calendar.official_days_through(through_trade_day, count=count)


class RequestGate:
    """Monotonic in-process minimum request-start interval."""

    def __init__(
        self,
        minimum_interval_seconds: float,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            isinstance(minimum_interval_seconds, bool)
            or not isinstance(minimum_interval_seconds, (int, float))
            or not math.isfinite(minimum_interval_seconds)
            or minimum_interval_seconds < 0
        ):
            raise RegistryError("minimum request interval must be finite and nonnegative")
        self.minimum_interval_seconds = float(minimum_interval_seconds)
        self.monotonic_clock = monotonic_clock
        self.sleeper = sleeper
        self._last_started: float | None = None

    def wait(self) -> None:
        now = self.monotonic_clock()
        if self._last_started is not None:
            while True:
                elapsed = now - self._last_started
                if elapsed < 0:
                    raise RegistryError("monotonic request clock moved backwards")
                remaining = self.minimum_interval_seconds - elapsed
                if remaining <= 0:
                    break
                self.sleeper(remaining)
                now = self.monotonic_clock()
        self._last_started = now


def retrying_acquirer(
    acquire: Callable[..., object],
    *,
    clock_provider: Callable[[], TrustedClockSample],
    request_gate: RequestGate,
    maximum_attempts: int,
    initial_backoff_seconds: float,
    sleeper: Callable[[float], None] = time.sleep,
) -> Callable[..., object]:
    if (
        isinstance(maximum_attempts, bool)
        or not isinstance(maximum_attempts, int)
        or maximum_attempts < 1
        or maximum_attempts > 8
    ):
        raise RegistryError("maximum acquisition attempts must be between 1 and 8")
    if (
        isinstance(initial_backoff_seconds, bool)
        or not isinstance(initial_backoff_seconds, (int, float))
        or not math.isfinite(initial_backoff_seconds)
        or initial_backoff_seconds < 0
    ):
        raise RegistryError("initial retry backoff must be finite and nonnegative")

    def invoke(**kwargs):
        for attempt in range(1, maximum_attempts + 1):
            request_gate.wait()
            try:
                return acquire(
                    **{
                        **kwargs,
                        "clock_sample": clock_provider(),
                    }
                )
            except RetryableTransportError as exc:
                if attempt == maximum_attempts:
                    raise
                backoff = float(initial_backoff_seconds) * (2 ** (attempt - 1))
                retry_after = exc.retry_after_seconds or 0.0
                delay = max(backoff, retry_after)
                if not math.isfinite(delay) or delay < 0 or delay > 3600:
                    raise RegistryError("official source retry delay is unsafe") from exc
                sleeper(delay)
        raise AssertionError("unreachable")

    return invoke


def run_history_backfill(
    *,
    paths: WarehousePaths,
    runtime: RuntimePaths,
    registry: SourceRegistry,
    calendar: OfficialCalendar,
    availability: CalendarAvailabilityAnchor,
    through_trade_day: date,
    required_official_days: int,
    collector_version: str,
    operator_state: OperatorState,
    clock_provider: Callable[[], TrustedClockSample],
    acquire: Callable[..., object],
    utc_clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    if required_official_days != DEFAULT_HISTORY_DAYS:
        raise RegistryError("M2 production history backfill requires exactly 186 days")
    plan = history_days(
        calendar,
        through_trade_day=through_trade_day,
        count=required_official_days,
    )
    started_clock = clock_provider()
    started_at = started_clock.trusted_now
    daily = []

    def verify_history_receipt(receipt: dict[str, Any]) -> None:
        verify_daily_run_receipt(
            receipt,
            paths=paths,
            registry=registry,
            calendar=calendar,
            calendar_availability_raw_sha256=availability.raw_sha256,
        )
        require_target_product_receipt_coverage(
            paths=paths,
            registry=registry,
            receipt=receipt,
        )

    for day in plan:
        run_trade_day(
            paths=paths,
            runtime=runtime,
            registry=registry,
            calendar=calendar,
            availability=availability,
            trade_day=day.isoformat(),
            clock_sample=clock_provider(),
            collector_version=collector_version,
            verify_receipt=verify_history_receipt,
            acquire=acquire,
            utc_clock=utc_clock,
            clock_provider=clock_provider,
            receipt_directory=runtime.history_run_receipts,
        )
        receipt_path = runtime.history_run_receipts / f"{day.isoformat()}.json"
        receipt = load_run_receipt(receipt_path)
        verify_history_receipt(receipt)
        receipt_raw = read_regular_strict(
            receipt_path,
            "M2 backfill daily run receipt",
        )
        daily.append(
            {
                "trade_day": day.isoformat(),
                "run_receipt_relative_path": (
                    f"history-run-receipts/{day.isoformat()}.json"
                ),
                "run_receipt_raw_sha256": sha256(receipt_raw),
                "source_raw_sha256": [
                    item["raw_sha256"] for item in receipt["sources"]
                ],
                "source_raw_bytes": [
                    item["raw_bytes"] for item in receipt["sources"]
                ],
            }
        )
    completed_at = clock_provider().trusted_now
    expected_days = [day.isoformat() for day in plan]
    for candidate in sorted(runtime.backfill_receipts.glob("*.json")):
        existing = load_backfill_receipt(candidate)
        if (
            existing["official_days"] == expected_days
            and existing["calendar_raw_sha256"] == calendar.raw_sha256
            and existing["calendar_availability_anchor_raw_sha256"]
            == availability.raw_sha256
            and existing["registry_raw_sha256"] == registry.raw_sha256
            and existing["daily_receipts"] == daily
        ):
            return {
                "status": "M2_HISTORY_ACQUISITION_ALREADY_COMPLETE",
                "backfill_receipt": str(candidate),
                "backfill_receipt_raw_sha256": sha256(
                    read_regular_strict(
                        candidate,
                        "M2 history backfill receipt",
                    )
                ),
                "required_official_days": required_official_days,
                "first_trade_day": plan[0].isoformat(),
                "through_trade_day": plan[-1].isoformat(),
                "authority": false_authority(),
            }
    payload = {
        "schema_version": BACKFILL_RECEIPT_SCHEMA,
        "receipt_id": "",
        "started_at": format_utc(started_at, "backfill started_at"),
        "completed_at": format_utc(completed_at, "backfill completed_at"),
        "through_trade_day": through_trade_day.isoformat(),
        "required_official_days": required_official_days,
        "official_days": expected_days,
        "calendar_raw_sha256": calendar.raw_sha256,
        "calendar_availability_anchor_raw_sha256": availability.raw_sha256,
        "registry_raw_sha256": registry.raw_sha256,
        "base_manifest_sequence": operator_state.payload["manifest_sequence"],
        "base_manifest_head_seal_sha256": operator_state.payload[
            "manifest_head_seal_sha256"
        ],
        "base_manifest_head_commit_seal_sha256": operator_state.payload[
            "manifest_head_commit_seal_sha256"
        ],
        "daily_receipts": daily,
        "authority": false_authority(),
    }
    payload["receipt_id"] = backfill_receipt_id(payload)
    output = publish_backfill_receipt(runtime, payload)
    return {
        "status": "M2_HISTORY_ACQUISITION_COMPLETE",
        "backfill_receipt": str(output),
        "backfill_receipt_raw_sha256": sha256(
            read_regular_strict(output, "M2 history backfill receipt")
        ),
        "required_official_days": required_official_days,
        "first_trade_day": plan[0].isoformat(),
        "through_trade_day": plan[-1].isoformat(),
        "authority": false_authority(),
    }
