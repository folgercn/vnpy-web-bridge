# ruff: noqa: E402

from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import inspect
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from research_warehouse.calendar_anchors import (
    CalendarAvailabilityAnchor,
    calendar_evidence_anchor_bindings,
)
from research_warehouse.calendar_models import (
    CalendarDay,
    CalendarSourceEvidence,
    OfficialCalendar,
)
from research_warehouse.canonical import canonical_json_line, sha256
import research_warehouse.daily_roll_predecessor_catalog as catalog
from research_warehouse.m2_isolation_contracts import false_authority
import research_warehouse.monthly_due_source as due
import research_warehouse.verified_daily_pit_main_roll_source as verified_roll
from test_research_warehouse_daily_roll_predecessor_catalog import _genesis_setup

UTC = timezone.utc


def _calendar_context(
    base: OfficialCalendar,
    *,
    overrides: dict[date, str] | None = None,
    omit: date | None = None,
) -> tuple[OfficialCalendar, CalendarAvailabilityAnchor]:
    rows = {
        day: CalendarDay(
            day=day,
            status=(overrides or {}).get(day, row.status),
            evening_session_natural_date=None,
        )
        for day, row in base.days.items()
        if day != omit
    }
    evidence = tuple(
        CalendarSourceEvidence(
            exchange=exchange,
            owner=f"{exchange} owner",
            source_url=f"https://example.invalid/{exchange.lower()}",
            source_type="OFFICIAL_TRADING_CALENDAR_EXPORT_OR_CLOSURE_NOTICE",
            observed_at=base.issued_at,
            raw_sha256=digest,
            raw_bytes=1,
            raw_relative_path=f"calendar-sources/{exchange.lower()}/{digest}.raw",
        )
        for exchange, digest in (("INE", "b" * 64), ("SHFE", "c" * 64))
    )
    calendar = OfficialCalendar.create(
        calendar_id=base.calendar_id,
        raw_sha256=base.raw_sha256,
        valid_from=base.valid_from,
        valid_to=base.valid_to,
        issued_at=base.issued_at,
        exchanges=("INE", "SHFE"),
        days=rows,
        source_evidence=evidence,
        source_evidence_root=Path("/not-read-by-pure-resolver"),
    )
    available_at = datetime(2025, 12, 1, tzinfo=UTC)
    availability = CalendarAvailabilityAnchor(
        raw_sha256="2" * 64,
        calendar_raw_sha256=calendar.raw_sha256,
        source_evidence_sha256=calendar_evidence_anchor_bindings(calendar),
        available_at=available_at,
    )
    return calendar, availability


def _base_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[catalog.CurrentCatalogHeadProof, OfficialCalendar]:
    kwargs, _inputs, _holder = _genesis_setup(monkeypatch, tmp_path)
    catalog.publish_predecessor_artifact(**kwargs)
    proof = catalog.load_current_catalog_head(kwargs["operator_state"].path)
    return proof, kwargs["context"].calendar


def _proof_for_day(
    proof: catalog.CurrentCatalogHeadProof,
    *,
    official_day: date,
    execution_day: date,
    following_day: date,
) -> catalog.CurrentCatalogHeadProof:
    artifact = json.loads(proof.artifact_raw)
    artifact["official_day"] = official_day.isoformat()
    artifact["execution_day"] = execution_day.isoformat()
    artifact["following_official_day"] = following_day.isoformat()
    artifact["verified_lineage"]["manifest"]["trade_day"] = official_day.isoformat()
    artifact["verified_lineage"]["run_receipt"]["completed_at"] = (
        f"{official_day.isoformat()}T10:00:00.000000Z"
    )
    continuity = artifact["verified_lineage"]["continuity"]
    if continuity["mode"] == "GENESIS_STATIC_CORE_EQUAL":
        continuity["baseline_source_month"] = (
            official_day.replace(day=1) - timedelta(days=1)
        ).strftime("%Y-%m")
        continuity["baseline_execution_day"] = official_day.isoformat()
    for row in artifact["mains"]:
        last_day = date.fromisoformat(row["official_last_trading_day"])
        row["execution_day_dte"] = (last_day - execution_day).days
        row["following_official_day_dte"] = (last_day - following_day).days
    artifact["artifact_id"] = verified_roll._artifact_id(artifact)
    artifact_raw = canonical_json_line(artifact)

    receipt = json.loads(proof.receipt_raw)
    receipt["official_day"] = official_day.isoformat()
    receipt["artifact_id"] = artifact["artifact_id"]
    receipt["artifact_raw_sha256"] = sha256(artifact_raw)
    receipt["artifact_raw_bytes"] = len(artifact_raw)
    receipt["artifact_relative_path"] = catalog._artifact_relative_path(
        artifact["artifact_id"]
    )
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_raw = canonical_json_line(receipt)
    return replace(
        proof,
        receipt_raw=receipt_raw,
        receipt_raw_sha256=sha256(receipt_raw),
        artifact_raw=artifact_raw,
        artifact_raw_sha256=sha256(artifact_raw),
        last_trade_day=official_day.isoformat(),
    )


def test_month_boundary_returns_unique_exact_root_pins(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)

    result = due.resolve_monthly_due_source(
        current_catalog_head=proof,
        calendar=calendar,
        calendar_availability=availability,
    )

    assert isinstance(result, due.MonthlyDueSource)
    assert result.status == "MONTHLY_DUE"
    assert result.source_month == "2026-06"
    assert result.research_as_of_official_day == "2026-06-30"
    assert result.execution_day == "2026-07-01"
    assert result.pins.current_catalog_receipt_raw_sha256 == proof.receipt_raw_sha256
    assert result.pins.current_catalog_artifact_raw_sha256 == proof.artifact_raw_sha256
    assert result.pins.operator_state_raw_sha256 == proof.operator_state_raw_sha256
    assert result.authority == false_authority()
    assert set(result.authority.values()) == {False}


def test_public_resolver_has_no_caller_day_month_path_or_io(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)
    assert list(inspect.signature(due.resolve_monthly_due_source).parameters) == [
        "current_catalog_head",
        "calendar",
        "calendar_availability",
    ]

    def forbidden_io(*_args, **_kwargs):
        pytest.fail("pure monthly due resolver attempted filesystem I/O")

    monkeypatch.setattr(Path, "open", forbidden_io)
    monkeypatch.setattr(Path, "read_bytes", forbidden_io)
    monkeypatch.setattr(Path, "write_bytes", forbidden_io)

    result = due.resolve_monthly_due_source(
        current_catalog_head=proof,
        calendar=calendar,
        calendar_availability=availability,
    )

    assert isinstance(result, due.MonthlyDueSource)


def test_month_end_holiday_uses_first_following_official_day(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    root_day = date(2026, 5, 6)
    overrides = {date(2026, 5, day): "CLOSED" for day in range(1, 6)}
    calendar, availability = _calendar_context(base, overrides=overrides)
    proof = _proof_for_day(
        proof,
        official_day=root_day,
        execution_day=date(2026, 5, 7),
        following_day=date(2026, 5, 8),
    )

    result = due.resolve_monthly_due_source(
        current_catalog_head=proof,
        calendar=calendar,
        calendar_availability=availability,
    )

    assert isinstance(result, due.MonthlyDueSource)
    assert result.source_month == "2026-04"
    assert result.research_as_of_official_day == "2026-04-30"
    assert result.execution_day == "2026-05-06"


def test_non_boundary_root_returns_explicit_no_monthly_due(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)
    proof = _proof_for_day(
        proof,
        official_day=date(2026, 7, 2),
        execution_day=date(2026, 7, 3),
        following_day=date(2026, 7, 6),
    )

    result = due.resolve_monthly_due_source(
        current_catalog_head=proof,
        calendar=calendar,
        calendar_availability=availability,
    )

    assert isinstance(result, due.NoMonthlyDue)
    assert result.status == "NO_MONTHLY_DUE"
    assert result.pins.current_official_day == "2026-07-02"
    assert result.authority == false_authority()


def test_duplicate_monthly_boundary_stops(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)
    real_boundary = due._official_month_boundary

    def duplicated(calendar_value, *, source_month: str):
        if source_month in {"2026-05", "2026-06"}:
            return date(2026, 6, 30), date(2026, 7, 1), date(2026, 6, 30)
        return real_boundary(calendar_value, source_month=source_month)

    monkeypatch.setattr(due, "_official_month_boundary", duplicated)

    with pytest.raises(due.MonthlyDueSourceError, match="multiple monthly"):
        due.resolve_monthly_due_source(
            current_catalog_head=proof,
            calendar=calendar,
            calendar_availability=availability,
        )


def test_whole_month_gap_stops_instead_of_backfilling_old_month(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    overrides = {
        day: "CLOSED" for day in base.days if day.year == 2026 and day.month == 5
    }
    calendar, availability = _calendar_context(base, overrides=overrides)
    proof = _proof_for_day(
        proof,
        official_day=date(2026, 6, 1),
        execution_day=date(2026, 6, 2),
        following_day=date(2026, 6, 3),
    )

    with pytest.raises(due.MonthlyDueSourceError, match="whole-month gap"):
        due.resolve_monthly_due_source(
            current_catalog_head=proof,
            calendar=calendar,
            calendar_availability=availability,
        )


def test_noncanonical_calendar_or_root_day_stops(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base, omit=date(2026, 6, 15))
    with pytest.raises(due.MonthlyDueSourceError, match="every natural day"):
        due.resolve_monthly_due_source(
            current_catalog_head=proof,
            calendar=calendar,
            calendar_availability=availability,
        )

    valid_calendar, valid_availability = _calendar_context(base)
    with pytest.raises(due.MonthlyDueSourceError, match="current-root verification"):
        due.resolve_monthly_due_source(
            current_catalog_head=replace(proof, last_trade_day="2026-7-1"),
            calendar=valid_calendar,
            calendar_availability=valid_availability,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("operator_state_raw_sha256", "f" * 64),
        ("manifest_head_seal_sha256", "e" * 64),
        ("artifact_raw_sha256", "d" * 64),
    ],
)
def test_root_cross_splice_stops(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)

    with pytest.raises(due.MonthlyDueSourceError):
        due.resolve_monthly_due_source(
            current_catalog_head=replace(proof, **{field: value}),
            calendar=calendar,
            calendar_availability=availability,
        )


def test_full_rehash_manifest_head_cross_splice_stops(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proof, base = _base_proof(monkeypatch, tmp_path)
    calendar, availability = _calendar_context(base)
    artifact = json.loads(proof.artifact_raw)
    artifact["verified_lineage"]["manifest"]["batch_seal_sha256"] = "f" * 64
    artifact["verified_lineage"]["manifest"]["commit_seal_sha256"] = "e" * 64
    artifact["artifact_id"] = verified_roll._artifact_id(artifact)
    artifact_raw = canonical_json_line(artifact)
    receipt = json.loads(proof.receipt_raw)
    receipt["artifact_id"] = artifact["artifact_id"]
    receipt["artifact_raw_sha256"] = sha256(artifact_raw)
    receipt["artifact_raw_bytes"] = len(artifact_raw)
    receipt["artifact_relative_path"] = catalog._artifact_relative_path(
        artifact["artifact_id"]
    )
    receipt["receipt_id"] = catalog._receipt_id(receipt)
    receipt_raw = canonical_json_line(receipt)
    spliced = replace(
        proof,
        receipt_raw=receipt_raw,
        receipt_raw_sha256=sha256(receipt_raw),
        artifact_raw=artifact_raw,
        artifact_raw_sha256=sha256(artifact_raw),
    )

    with pytest.raises(due.MonthlyDueSourceError, match="root cross-splice"):
        due.resolve_monthly_due_source(
            current_catalog_head=spliced,
            calendar=calendar,
            calendar_availability=availability,
        )
