from __future__ import annotations

import sys
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.clock_quality import TrustedClockSample
from research_warehouse.errors import RegistryError, RetryableTransportError
from research_warehouse.history_backfill_receipts import (
    BACKFILL_RECEIPT_SCHEMA,
    backfill_receipt_id,
    validate_backfill_receipt,
)
from research_warehouse.m2_history_backfill import (
    RequestGate,
    history_days,
    retrying_acquirer,
)
from research_warehouse.m2_history_signer import remaining_history_days
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_request_gate import PersistentRequestGate

UTC = timezone.utc
NOW = datetime(2026, 7, 30, 12, tzinfo=UTC)


def calendar_with_official_days(count: int = 200) -> OfficialCalendar:
    end = date(2026, 7, 30)
    days = {
        end - timedelta(days=offset): CalendarDay(
            day=end - timedelta(days=offset),
            status="OFFICIAL_DAY",
            evening_session_natural_date=None,
        )
        for offset in range(count)
    }
    return OfficialCalendar.create(
        calendar_id="history-test",
        raw_sha256="a" * 64,
        valid_from=min(days),
        valid_to=max(days),
        issued_at=NOW - timedelta(days=300),
        exchanges=("SHFE", "INE"),
        days=days,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )


def test_history_plan_is_exact_oldest_to_newest_and_fail_closed() -> None:
    calendar = calendar_with_official_days()
    plan = history_days(
        calendar,
        through_trade_day=date(2026, 7, 30),
        count=186,
    )
    assert len(plan) == 186
    assert plan == tuple(sorted(plan))
    assert plan[-1] == date(2026, 7, 30)
    with pytest.raises(RegistryError, match="insufficient"):
        history_days(
            calendar,
            through_trade_day=date(2026, 7, 30),
            count=201,
        )


def test_request_gate_enforces_interval_and_rejects_clock_rollback() -> None:
    values = iter((10.0, 10.25, 11.0))
    sleeps = []
    gate = RequestGate(
        1.0,
        monotonic_clock=lambda: next(values),
        sleeper=sleeps.append,
    )
    gate.wait()
    gate.wait()
    assert sleeps == [0.75]

    rollback = iter((10.0, 9.0))
    gate = RequestGate(1.0, monotonic_clock=lambda: next(rollback))
    gate.wait()
    with pytest.raises(RegistryError, match="moved backwards"):
        gate.wait()


def test_persistent_request_gate_coordinates_separate_instances(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    samples = iter(
        (
            TrustedClockSample(NOW, NOW, 0),
            TrustedClockSample(NOW + timedelta(milliseconds=250), NOW, 0),
            TrustedClockSample(NOW + timedelta(seconds=1), NOW, 0),
        )
    )
    sleeps = []
    first = PersistentRequestGate(
        runtime,
        minimum_interval_seconds=1,
        clock_provider=lambda: next(samples),
        sleeper=sleeps.append,
    )
    second = PersistentRequestGate(
        runtime,
        minimum_interval_seconds=1,
        clock_provider=lambda: next(samples),
        sleeper=sleeps.append,
    )
    with first.request() as first_sample:
        assert first_sample.trusted_now == NOW
    with second.request() as second_sample:
        assert second_sample.trusted_now == NOW + timedelta(seconds=1)
    assert sleeps == [0.75]


def test_persistent_request_gate_holds_lock_until_http_scope_exits(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    samples = iter(
        (
            TrustedClockSample(NOW, NOW, 0),
            TrustedClockSample(NOW + timedelta(seconds=1), NOW, 0),
        )
    )
    first = PersistentRequestGate(
        runtime,
        minimum_interval_seconds=1,
        clock_provider=lambda: next(samples),
    )
    second = PersistentRequestGate(
        runtime,
        minimum_interval_seconds=1,
        clock_provider=lambda: next(samples),
    )
    entered = threading.Event()

    def enter_second() -> None:
        with second.request():
            entered.set()

    with first.request():
        worker = threading.Thread(target=enter_second)
        worker.start()
        assert entered.wait(0.05) is False
    worker.join(timeout=1)
    assert entered.is_set()


def test_retrying_acquirer_uses_fresh_clock_and_bounded_retry_after() -> None:
    clocks = []
    calls = []
    sleeps = []
    samples = iter(
        (
            TrustedClockSample(NOW, NOW, 0),
            TrustedClockSample(NOW + timedelta(seconds=7), NOW, 0),
        )
    )

    def acquire(**kwargs):
        clocks.append(kwargs["clock_sample"].trusted_now)
        calls.append(kwargs["source_id"])
        if len(calls) == 1:
            raise RetryableTransportError(
                "limited",
                retry_after_seconds=7,
            )
        return "ok"

    wrapped = retrying_acquirer(
        acquire,
        clock_provider=lambda: next(samples),
        request_gate=RequestGate(
            0,
            monotonic_clock=iter((1.0, 2.0)).__next__,
        ),
        maximum_attempts=2,
        initial_backoff_seconds=1,
        sleeper=sleeps.append,
    )
    assert wrapped(source_id="shfe") == "ok"
    assert calls == ["shfe", "shfe"]
    assert clocks[1] > clocks[0]
    assert sleeps == [7.0]


def test_backfill_receipt_binds_exact_days_receipts_and_sources() -> None:
    days = ["2026-07-29", "2026-07-30"]
    payload = {
        "schema_version": BACKFILL_RECEIPT_SCHEMA,
        "receipt_id": "",
        "started_at": "2026-07-30T12:00:00.000000Z",
        "completed_at": "2026-07-30T12:01:00.000000Z",
        "through_trade_day": days[-1],
        "required_official_days": len(days),
        "official_days": days,
        "calendar_raw_sha256": "a" * 64,
        "calendar_availability_anchor_raw_sha256": "b" * 64,
        "registry_raw_sha256": "c" * 64,
        "base_manifest_sequence": 1,
        "base_manifest_head_seal_sha256": "d" * 64,
        "base_manifest_head_commit_seal_sha256": "e" * 64,
        "daily_receipts": [
            {
                "trade_day": day,
                "run_receipt_relative_path": (
                    f"history-run-receipts/{day}.json"
                ),
                "run_receipt_raw_sha256": str(index) * 64,
                "source_raw_sha256": ["a" * 64, "b" * 64],
                "source_raw_bytes": [10, 20],
            }
            for index, day in enumerate(days, start=1)
        ],
        "authority": false_authority(),
    }
    payload["receipt_id"] = backfill_receipt_id(payload)
    assert validate_backfill_receipt(payload) == payload
    payload["daily_receipts"].reverse()
    with pytest.raises(RegistryError, match="incomplete"):
        validate_backfill_receipt(payload)


def test_history_signer_resumes_only_a_root_pinned_day_prefix() -> None:
    history = {
        "base_manifest_sequence": 1,
        "official_days": ["2025-10-27", "2025-10-28", "2025-10-29"],
    }
    state = SimpleNamespace(
        payload={
            "manifest_sequence": 2,
            "last_trade_day": "2025-10-27",
        }
    )
    assert remaining_history_days(state, history) == [
        "2025-10-28",
        "2025-10-29",
    ]
    state.payload["last_trade_day"] = "2025-10-29"
    with pytest.raises(RegistryError, match="progress day diverged"):
        remaining_history_days(state, history)
