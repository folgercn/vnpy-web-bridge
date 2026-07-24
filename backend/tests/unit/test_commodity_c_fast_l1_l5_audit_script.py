from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import runpy

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "commodity_c_fast_l1_l5_audit.py"
)
MODULE = runpy.run_path(
    str(SCRIPT),
    run_name="commodity_c_fast_l1_l5_audit",
)
PRODUCTS = MODULE["FROZEN_PRODUCTS"]
EXCHANGES = MODULE["PRODUCT_EXCHANGES"]


def manifest_payload() -> dict:
    return {
        "schema_version": MODULE["MANIFEST_SCHEMA_VERSION"],
        "candidate_id": MODULE["CANDIDATE_ID"],
        "snapshot_id": "c-fast-p0-test-a01",
        "targets": [
            {
                "product": product,
                "exact_contract": f"{EXCHANGES[product]}.{product}2609",
                "previous_exact_contract": None,
                "roll_expected": False,
            }
            for product in PRODUCTS
        ],
        "execution_windows": [],
    }


def write_manifest(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def tick_row(
    ts: datetime,
    *,
    ingest_id: str = "tick-1",
    ingest_seq: int = 1,
    levels: int = 5,
    received_delay: float = 0.1,
    crossed: bool = False,
    volume: float = 10,
    last_volume: float = 0,
) -> dict:
    row = {
        "ts": ts,
        "received_at": ts + timedelta(seconds=received_delay),
        "ingest_id": ingest_id,
        "ingest_seq": ingest_seq,
        "trading_day": "20260901",
        "last_price": 100,
        "last_volume": last_volume,
        "volume": volume,
    }
    for level in range(1, 6):
        available = level <= levels
        row[f"bid_price_{level}"] = (
            100 - level if available else 0
        )
        row[f"ask_price_{level}"] = (
            100 + level if available else 0
        )
        row[f"bid_volume_{level}"] = 10 if available else 0
        row[f"ask_volume_{level}"] = 11 if available else 0
    if crossed:
        row["bid_price_1"] = 102
        row["ask_price_1"] = 101
    return row


def add_row(accumulator, row: dict) -> None:
    accumulator.add(row)


def complete_session_rows(execution_time: datetime) -> list[dict]:
    timestamps = [
        *[
            datetime(2026, 8, 31, 13, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
            for index in range(20)
        ],
        *[
            datetime(2026, 8, 31, 13, 10, tzinfo=timezone.utc)
            + timedelta(seconds=index)
            for index in range(20)
        ],
        *[
            execution_time - timedelta(seconds=10)
            + timedelta(seconds=index)
            for index in range(20)
        ],
        *[
            datetime(2026, 9, 1, 1, 10, tzinfo=timezone.utc)
            + timedelta(seconds=index)
            for index in range(20)
        ],
    ]
    return [
        tick_row(
            ts,
            ingest_id=f"tick-{index}",
            ingest_seq=index,
            volume=10 + index,
            last_volume=1 if index else 0,
        )
        for index, ts in enumerate(timestamps)
    ]


class FakeCursor:
    def __init__(self, rows: list[tuple]) -> None:
        self.rows = rows
        self.offset = 0

    def fetchmany(self, size: int) -> list[tuple]:
        result = self.rows[self.offset : self.offset + size]
        self.offset += len(result)
        return result


class FakeConnection:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.sql = ""
        self.params = ()

    def execute(self, sql: str, params: tuple) -> FakeCursor:
        self.sql = sql
        self.params = params
        tuples = [
            tuple(row.get(column) for column in MODULE["QUERY_COLUMNS"])
            for row in self.rows
        ]
        return FakeCursor(tuples)


def test_manifest_rejects_missing_frozen_product(tmp_path: Path) -> None:
    payload = manifest_payload()
    payload["targets"].pop()

    with pytest.raises(MODULE["AuditError"], match="exactly ten"):
        MODULE["load_manifest"](write_manifest(tmp_path, payload))


def test_manifest_rejects_roll_without_previous_contract(
    tmp_path: Path,
) -> None:
    payload = manifest_payload()
    payload["targets"][0]["roll_expected"] = True

    with pytest.raises(
        MODULE["AuditError"],
        match="requires previous_exact_contract",
    ):
        MODULE["load_manifest"](write_manifest(tmp_path, payload))


def test_manifest_normalizes_exact_contract_and_binds_execution_window(
    tmp_path: Path,
) -> None:
    payload = manifest_payload()
    payload["execution_windows"] = [
        {
            "window_id": "ag-window-a01",
            "product": "ag",
            "exact_contract": "ag2609.SHFE",
            "execution_time": "2026-09-01T01:00:00+00:00",
            "window_seconds": 60,
        }
    ]

    _, contracts, windows = MODULE["load_manifest"](
        write_manifest(tmp_path, payload)
    )

    assert contracts[0].exact_contract == "SHFE.ag2609"
    assert contracts[0].vt_symbol == "ag2609.SHFE"
    assert windows[0].vt_symbol == "ag2609.SHFE"
    assert windows[0].execution_time.tzinfo == timezone.utc


def test_five_level_rows_are_l5_usable() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(100):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(milliseconds=500 * index),
                ingest_id=f"tick-{index}",
                ingest_seq=index,
                volume=10 + index,
                last_volume=1 if index else 0,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "L5_USABLE"
    assert result["l1_complete_ratio"] == 1
    assert result["l5_complete_ratio"] == 1
    assert result["volume_semantics"]["last_volume_match_ratio"] == 1


def test_missing_deeper_levels_cannot_fall_back_to_l5() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(20):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"tick-{index}",
                ingest_seq=index,
                levels=1,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "L1_ONLY"
    assert result["l1_complete_ratio"] == 1
    assert result["l5_complete_ratio"] == 0


def test_crossed_and_stale_rows_degrade_complete_depth() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(100):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"tick-{index}",
                ingest_seq=index,
                crossed=index < 2,
                received_delay=6 if index < 2 else 0.1,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["crossed_rows"] == 2
    assert result["anomalies"]["transport_stale_rows"] == 2


def test_duplicate_ingest_identity_is_failure_path() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    add_row(accumulator, tick_row(start, ingest_id="same", ingest_seq=1))
    add_row(
        accumulator,
        tick_row(
            start + timedelta(milliseconds=1),
            ingest_id="same",
            ingest_seq=2,
        ),
    )

    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["duplicate_ingest_ids"] == 1


def test_missing_required_identity_fields_degrade_instead_of_crashing() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    row = tick_row(datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc))
    row["received_at"] = None
    row["ingest_id"] = ""
    row["ingest_seq"] = None
    row["trading_day"] = ""
    row["last_price"] = None

    add_row(accumulator, row)
    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["missing_received_at_rows"] == 1
    assert result["anomalies"]["missing_ingest_id_rows"] == 1
    assert result["anomalies"]["missing_ingest_seq_rows"] == 1
    assert result["anomalies"]["missing_trading_day_rows"] == 1
    assert result["anomalies"]["missing_last_price_rows"] == 1


def test_contract_audit_is_select_only_and_covers_execution_window() -> None:
    execution_time = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    connection = FakeConnection(complete_session_rows(execution_time))
    contract = MODULE["ContractSpec"](
        product="ag",
        role="current",
        exact_contract="SHFE.ag2609",
        vt_symbol="ag2609.SHFE",
    )
    window = MODULE["ExecutionWindow"](
        window_id="ag-window-a01",
        product="ag",
        vt_symbol="ag2609.SHFE",
        execution_time=execution_time,
        window_seconds=60,
    )

    result, window_results = MODULE["audit_contract"](
        connection,
        contract,
        [window],
        datetime(2026, 8, 31, 12, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 8, tzinfo=timezone.utc),
    )

    assert connection.sql.lstrip().upper().startswith("SELECT")
    assert all(
        keyword not in connection.sql.upper()
        for keyword in ("INSERT", "UPDATE", "DELETE", "ALTER", "DROP")
    )
    assert connection.params[0] == "ag2609.SHFE"
    assert result["classification"] == "L5_USABLE"
    assert window_results[0]["classification"] == "L5_USABLE"
    assert window_results[0]["rows_before"] == 10
    assert window_results[0]["rows_after"] == 10


def test_full_ten_product_audit_can_reach_p0_pass(tmp_path: Path) -> None:
    execution_time = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    payload = manifest_payload()
    payload["execution_windows"] = [
        {
            "window_id": f"{product}-window-a01",
            "product": product,
            "exact_contract": f"{EXCHANGES[product]}.{product}2609",
            "execution_time": execution_time.isoformat(),
            "window_seconds": 60,
        }
        for product in PRODUCTS
    ]
    manifest, contracts, windows = MODULE["load_manifest"](
        write_manifest(tmp_path, payload)
    )
    connection = FakeConnection(complete_session_rows(execution_time))

    evidence = MODULE["audit"](
        connection,
        manifest,
        contracts,
        windows,
        datetime(2026, 8, 31, 12, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 8, tzinfo=timezone.utc),
    )

    assert evidence["summary"]["p0_pass"] is True
    assert evidence["summary"]["overall_conclusion"] == "L5_USABLE"
    assert evidence["summary"]["classification_counts"]["L5_USABLE"] == 10
    assert evidence["blockers"] == []
    assert len(evidence["contracts"]) == 10
    assert len(evidence["execution_windows"]) == 10
    assert len(json.dumps(evidence, ensure_ascii=False)) > 1000


def test_session_bucket_uses_china_market_windows() -> None:
    utc = timezone.utc
    assert (
        MODULE["session_bucket"](datetime(2026, 8, 31, 13, 0, tzinfo=utc))
        == "night_open"
    )
    assert (
        MODULE["session_bucket"](datetime(2026, 8, 31, 14, 0, tzinfo=utc))
        == "night_session"
    )
    assert (
        MODULE["session_bucket"](datetime(2026, 9, 1, 1, 0, tzinfo=utc))
        == "day_open"
    )
    assert (
        MODULE["session_bucket"](datetime(2026, 9, 1, 2, 0, tzinfo=utc))
        == "day_session"
    )


def test_missing_execution_windows_and_sessions_remain_blockers() -> None:
    contracts = []
    empty_metrics = MODULE["MetricsAccumulator"](
        dict(MODULE["THRESHOLDS"])
    ).result()
    for product in PRODUCTS:
        contracts.append(
            {
                "product": product,
                "role": "current",
                "classification": "UNUSABLE",
                "all": empty_metrics,
                "sessions": {
                    name: empty_metrics
                    for name in MODULE["REQUIRED_CURRENT_SESSIONS"]
                },
            }
        )
    manifest = manifest_payload()
    manifest["roll_expected"] = {
        product: False for product in PRODUCTS
    }

    products, blockers = MODULE["summarize_products"](
        contracts,
        [],
        manifest,
    )

    assert all(item["classification"] == "UNUSABLE" for item in products)
    assert "ag:missing_current_execution_window" in blockers
    assert "ag:no_rows" in blockers


def test_rendered_report_and_csv_do_not_include_dsn(
    tmp_path: Path,
) -> None:
    metrics = MODULE["MetricsAccumulator"](
        dict(MODULE["THRESHOLDS"])
    ).result()
    evidence = {
        "candidate_id": MODULE["CANDIDATE_ID"],
        "snapshot_id": "c-fast-p0-test-a01",
        "manifest_sha256": "a" * 64,
        "audit_window": {
            "start": "2026-08-31T12:00:00+00:00",
            "end_exclusive": "2026-09-01T08:00:00+00:00",
        },
        "summary": {
            "p0_pass": False,
            "overall_conclusion": "UNUSABLE",
            "rows": 0,
            "contracts": 1,
        },
        "products": [
            {
                "product": "ag",
                "rows": 0,
                "contracts": 1,
                "execution_windows": 0,
                "missing_sessions": ["night_open"],
                "insufficient_sessions": [],
                "classification": "UNUSABLE",
            }
        ],
        "contracts": [
            {
                "product": "ag",
                "role": "current",
                "vt_symbol": "ag2609.SHFE",
                "all": metrics,
                "sessions": {
                    name: metrics
                    for name in MODULE["REQUIRED_CURRENT_SESSIONS"]
                },
            }
        ],
        "execution_windows": [],
        "blockers": ["ag:no_rows"],
        "limitations": ["no passive point probability"],
    }
    report = MODULE["render_markdown"](evidence)
    csv_path = tmp_path / "evidence.csv"
    MODULE["write_csv"](csv_path, evidence)

    rendered = report + csv_path.read_text(encoding="utf-8")
    assert "postgresql://" not in rendered
    assert "password" not in rendered
    assert "ag:no_rows" in report
