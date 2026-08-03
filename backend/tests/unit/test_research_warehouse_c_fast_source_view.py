# ruff: noqa: E402
from __future__ import annotations

import json
import sys
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_execution_open_observation as open_observation
import commodity_c_fast_pure_producer_kernel as producer
import research_warehouse.c_fast_source_view as c_fast_source
from research_warehouse.c_fast_source_view import (
    BuiltCFastSourceView,
    VerifiedExecutionOpenObservation,
    build_c_fast_source_view,
    load_execution_open_observation,
    publish_built_c_fast_source_view,
    verify_built_c_fast_source_view,
)
from research_warehouse.c_fast_source_view_verify_cli import main as verify_cli
from research_warehouse.calendar_models import (
    CalendarDay,
    OfficialCalendar,
)
from research_warehouse.canonical import sha256
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.pit_source_view import PitSourceViewError
from test_research_warehouse_pit_source_view import _inputs
from test_research_warehouse_static_core_baseline import (
    _contract_registry,
)

UTC = timezone.utc


def _build(
    *,
    observed_at_utc: datetime = datetime(2026, 8, 3, 9, 0, tzinfo=UTC),
    execution_day: date = date(2026, 8, 3),
    execution_source_observed_at: datetime | None = None,
    contract_registry_sha256: str | None = None,
    history_completed_at: str | None = None,
) -> BuiltCFastSourceView:
    calendar, history, daily_raw, _key = _inputs()
    if history_completed_at is not None:
        history = {**history, "completed_at": history_completed_at}
    rows = dict(calendar.days)
    previous_official = max(day for day, row in rows.items() if row.is_official)
    current = max(rows) + timedelta(days=1)
    while current <= date(2026, 10, 20):
        is_official = current.weekday() < 5
        rows[current] = CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if is_official else "CLOSED",
            evening_session_natural_date=(
                previous_official if is_official else None
            ),
        )
        if is_official:
            previous_official = current
        current += timedelta(days=1)
    if execution_day in rows and rows[execution_day].is_official:
        rows[execution_day] = CalendarDay(
            day=execution_day,
            status="OFFICIAL_DAY",
            evening_session_natural_date=max(
                day for day, row in rows.items() if row.is_official and day < execution_day
            ),
        )
    calendar = OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=date(2026, 10, 20),
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
    daily_raw = {
        day: {
            exchange: raw.replace(b"2612", b"2609")
            .replace(b"2701", b"2610")
            .replace(b"2702", b"2611")
            for exchange, raw in sources.items()
        }
        for day, sources in daily_raw.items()
    }
    execution_day_bytes = execution_day.strftime("%Y%m%d").encode()
    execution_raw = {
        exchange: raw.replace(b'"report_date":"20260731"', b'"report_date":"' + execution_day_bytes + b'"')
        for exchange, raw in daily_raw["2026-07-31"].items()
    }
    execution_rows = {}
    for exchange, raw in execution_raw.items():
        extracted = c_fast_source.contract_rows_from_daily_raw(
            raw=raw,
            exchange=exchange,
            official_day=execution_day.isoformat(),
            include_ohlc=True,
        )
        for product_rows in extracted.values():
            for row in product_rows:
                execution_rows[row["exact_contract"]] = {
                    "exact_contract": row["exact_contract"],
                    "exchange": exchange,
                    "open_price": row["open"],
                    "tick_datetime": (
                        f"{execution_day.isoformat()}T08:29:00.000000Z"
                    ),
                    "trading_day": execution_day.isoformat(),
                    "gateway_name": "CTP",
                }
    contract_registry_raw = _contract_registry()
    return build_c_fast_source_view(
        calendar=calendar,
        calendar_anchor_raw_sha256="2" * 64,
        warehouse_registry_raw_sha256=history["registry_raw_sha256"],
        history_receipt=history,
        history_receipt_raw_sha256="3" * 64,
        operator_pins={
            "operator_state_raw_sha256": "4" * 64,
            "manifest_genesis_seal_sha256": "5" * 64,
            "manifest_head_seal_sha256": "6" * 64,
            "manifest_head_commit_seal_sha256": "7" * 64,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
        },
        daily_source_raw=daily_raw,
        execution_day_source=VerifiedExecutionOpenObservation(
            official_day=execution_day.isoformat(),
            observed_at=(
                execution_source_observed_at
                or datetime.combine(
                    execution_day, datetime.min.time(), tzinfo=UTC
                )
                + timedelta(hours=8, minutes=30)
            ),
            receipt_raw_sha256="9" * 64,
            tick_export_raw_sha256="a" * 64,
            rows=execution_rows,
        ),
        contract_registry_raw=contract_registry_raw,
        expected_contract_registry_raw_sha256=(
            contract_registry_sha256 or sha256(contract_registry_raw)
        ),
        source_month="2026-07",
        observed_at_utc=observed_at_utc,
    )


def test_warehouse_c_fast_source_is_deterministic_and_sealed_export_ready() -> None:
    first = _build()
    second = _build()

    assert first == second
    verify_built_c_fast_source_view(first)
    source = json.loads(first.source_view_raw)
    evidence = json.loads(first.evidence_raw)
    lineage = json.loads(first.lineage_raw)
    assert source["schema_version"] == producer.SOURCE_SCHEMA_VERSION
    assert source["research_as_of_official_day"] == "2026-07-31"
    assert source["execution_day"] == "2026-08-03"
    assert len(source["products"]) == 10
    assert tuple(first.artifacts) == producer.ARTIFACT_ROLES
    assert evidence["producer_replay"] == "EXACT_NINE_ARTIFACT_BYTES_VERIFIED"
    assert evidence["authority"] == false_authority()
    assert lineage["source_view_canonical_sha256"] == (
        producer.produce_research_artifacts(
            first.source_view_raw
        ).source_view_canonical_sha256
    )
    assert lineage["source_view_canonical_sha256"] == sha256(first.source_view_raw)


def test_warehouse_c_fast_source_allows_later_official_day_in_next_month() -> None:
    built = _build(
        execution_day=date(2026, 8, 4),
        observed_at_utc=datetime(2026, 8, 4, 9, 0, tzinfo=UTC),
    )

    verify_built_c_fast_source_view(built)
    source = json.loads(built.source_view_raw)
    assert source["research_as_of_official_day"] == "2026-07-31"
    assert source["execution_day"] == "2026-08-04"
    assert source["official_days"][-3:] == [
        "2026-08-03",
        "2026-08-04",
        "2026-08-05",
    ]


def test_warehouse_c_fast_source_allows_previous_evening_night_session() -> None:
    calendar, _history, _daily_raw, _key = _inputs()
    rows = dict(calendar.days)
    rows[date(2026, 8, 4)] = CalendarDay(
        day=date(2026, 8, 4),
        status="OFFICIAL_DAY",
        evening_session_natural_date=date(2026, 8, 3),
    )
    calendar = OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=calendar.valid_to,
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )

    assert c_fast_source._timestamp_belongs_to_execution_day(
        datetime(2026, 8, 3, 13, 1, tzinfo=UTC),
        official_day=date(2026, 8, 4),
        calendar=calendar,
    )
    built = _build(
        execution_day=date(2026, 8, 4),
        execution_source_observed_at=datetime(2026, 8, 3, 13, 1, tzinfo=UTC),
        observed_at_utc=datetime(2026, 8, 3, 15, 59, tzinfo=UTC),
    )
    verify_built_c_fast_source_view(built)


def test_warehouse_c_fast_source_tamper_and_missing_month_end_fail_closed() -> None:
    built = _build()
    tampered_artifacts = dict(built.artifacts)
    tampered_artifacts["target_evidence"] = tampered_artifacts[
        "target_evidence"
    ].replace(b'"target_quantity":', b'"target_quantity":1,"x":')
    tampered = BuiltCFastSourceView(
        source_view_raw=built.source_view_raw,
        artifacts=tampered_artifacts,
        lineage_raw=built.lineage_raw,
        evidence_raw=built.evidence_raw,
    )
    with pytest.raises(PitSourceViewError, match="replay diverged"):
        verify_built_c_fast_source_view(tampered)

    calendar, history, daily_raw, _key = _inputs()
    missing = deepcopy(daily_raw)
    missing.pop("2026-07-31")
    with pytest.raises(PitSourceViewError, match="exact days"):
        build_c_fast_source_view(
            calendar=calendar,
            calendar_anchor_raw_sha256="2" * 64,
            warehouse_registry_raw_sha256=history["registry_raw_sha256"],
            history_receipt=history,
            history_receipt_raw_sha256="3" * 64,
            operator_pins={
                "operator_state_raw_sha256": "4" * 64,
                "manifest_genesis_seal_sha256": "5" * 64,
                "manifest_head_seal_sha256": "6" * 64,
                "manifest_head_commit_seal_sha256": "7" * 64,
                "commit_anchor_ledger_raw_sha256": "8" * 64,
            },
            daily_source_raw=missing,
            execution_day_source=VerifiedExecutionOpenObservation(
                official_day="2026-08-03",
                observed_at=datetime(2026, 8, 3, 8, 30, tzinfo=UTC),
                receipt_raw_sha256="9" * 64,
                tick_export_raw_sha256="a" * 64,
                rows={},
            ),
            contract_registry_raw=_contract_registry(),
            expected_contract_registry_raw_sha256=sha256(_contract_registry()),
            source_month="2026-07",
            observed_at_utc=datetime(2026, 8, 3, 9, 0, tzinfo=UTC),
        )


def test_warehouse_c_fast_source_rejects_stale_observation_and_root_pin() -> None:
    with pytest.raises(PitSourceViewError, match="after history completion"):
        _build(observed_at_utc=datetime(2026, 8, 4, 9, 0, tzinfo=UTC))
    with pytest.raises(PitSourceViewError, match="after history completion"):
        _build(history_completed_at="2026-08-03T10:00:00.000000Z")
    with pytest.raises(PitSourceViewError, match="root pin mismatch"):
        _build(contract_registry_sha256="a" * 64)


def test_warehouse_c_fast_source_evidence_tamper_fails_closed() -> None:
    built = _build()
    evidence = json.loads(built.evidence_raw)
    evidence["artifact_digests"][0]["raw_bytes"] += 1
    tampered = BuiltCFastSourceView(
        source_view_raw=built.source_view_raw,
        artifacts=built.artifacts,
        lineage_raw=built.lineage_raw,
        evidence_raw=c_fast_source.canonical_json_line(evidence),
    )
    with pytest.raises(PitSourceViewError, match="evidence binding mismatch"):
        verify_built_c_fast_source_view(tampered)


def test_warehouse_c_fast_publish_is_create_only_and_cli_replays(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    built = _build()
    output = tmp_path / "published"
    publish_built_c_fast_source_view(output, built)

    assert verify_cli(["--input", str(output)]) == 0
    assert "C_FAST_WAREHOUSE_SOURCE_VIEW_VERIFIED" in capsys.readouterr().out
    with pytest.raises(PitSourceViewError, match="overwrite forbidden"):
        publish_built_c_fast_source_view(output, built)


def test_warehouse_c_fast_publish_requires_private_custody_root(
    tmp_path: Path,
) -> None:
    public_root = tmp_path / "public"
    public_root.mkdir(mode=0o755)
    public_root.chmod(0o755)
    with pytest.raises(RuntimeError, match="must be private"):
        publish_built_c_fast_source_view(public_root / "published", _build())


def test_warehouse_c_fast_publish_failure_preserves_existing_parent_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "unrelated.txt"
    sentinel.write_text("keep", encoding="utf-8")
    original_create = c_fast_source._create_at
    calls = 0

    def fail_after_first(parent_fd: int, name: str, raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected publication failure")
        original_create(parent_fd, name, raw)

    monkeypatch.setattr(c_fast_source, "_create_at", fail_after_first)
    output = tmp_path / "partial"
    with pytest.raises(PitSourceViewError, match="publication failed closed"):
        publish_built_c_fast_source_view(output, _build())

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert output.is_dir()
    assert {path.name for path in output.iterdir()} == {"source-view.json"}


def test_execution_open_observation_freezes_ctp_ticks_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    capture = tmp_path / "capture.json"
    ticks = []
    for index, product in enumerate(producer.PRODUCTS):
        exchange = producer.PRODUCT_SPECS[product]["exchange"]
        ticks.append(
            {
                "symbol": f"{product}2609",
                "exchange": exchange,
                "open_price": 1000 + index,
                "datetime": "2026-08-03T05:00:00+00:00",
                "trading_day": "20260803",
                "gateway_name": "CTP",
            }
        )
    capture.write_text(json.dumps({"data": ticks}), encoding="utf-8")
    capture.chmod(0o600)
    tick_output = tmp_path / "ticks.jsonl"
    receipt_output = tmp_path / "receipt.json"
    monkeypatch.setattr(
        open_observation,
        "_now_utc",
        lambda: datetime(2026, 8, 3, 5, 1, tzinfo=UTC),
    )
    assert (
        open_observation.main(
            [
                "--input",
                str(capture),
                "--execution-day",
                "2026-08-03",
                "--ticks-output",
                str(tick_output),
                "--receipt-output",
                str(receipt_output),
            ]
        )
        == 0
    )
    verified = load_execution_open_observation(
        receipt_path=receipt_output,
        capture_path=capture,
        tick_export_path=tick_output,
        official_day=date(2026, 8, 3),
    )
    assert len(verified.rows) == 10
    capture.write_bytes(capture.read_bytes() + b" ")
    with pytest.raises(PitSourceViewError, match="raw capture binding"):
        load_execution_open_observation(
            receipt_path=receipt_output,
            capture_path=capture,
            tick_export_path=tick_output,
            official_day=date(2026, 8, 3),
        )
    with pytest.raises(FileExistsError):
        open_observation.main(
            [
                "--input",
                str(capture),
                "--execution-day",
                "2026-08-03",
                "--ticks-output",
                str(tick_output),
                "--receipt-output",
                str(receipt_output),
            ]
        )
