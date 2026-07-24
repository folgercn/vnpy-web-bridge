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
AUDIT_START = datetime(2026, 8, 31, 12, tzinfo=timezone.utc)
AUDIT_END = datetime(2026, 9, 1, 8, tzinfo=timezone.utc)
SESSION_BOUNDS = {
    "night_open": (
        datetime(2026, 8, 31, 13, 0, tzinfo=timezone.utc),
        datetime(2026, 8, 31, 13, 2, 5, tzinfo=timezone.utc),
    ),
    "night_session": (
        datetime(2026, 8, 31, 13, 10, tzinfo=timezone.utc),
        datetime(2026, 8, 31, 13, 20, tzinfo=timezone.utc),
    ),
    "day_open": (
        datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 1, 2, 5, tzinfo=timezone.utc),
    ),
    "day_session": (
        datetime(2026, 9, 1, 1, 10, tzinfo=timezone.utc),
        datetime(2026, 9, 1, 1, 20, tzinfo=timezone.utc),
    ),
}


def manifest_payload() -> dict:
    return {
        "schema_version": MODULE["MANIFEST_SCHEMA_VERSION"],
        "candidate_id": MODULE["CANDIDATE_ID"],
        "snapshot_id": "c-fast-p0-test-a01",
        "audit_window": {
            "start": AUDIT_START.isoformat(),
            "end_exclusive": AUDIT_END.isoformat(),
            "trading_day": "20260901",
        },
        "session_windows": {
            name: {
                "start": start.isoformat(),
                "end_exclusive": end.isoformat(),
            }
            for name, (start, end) in SESSION_BOUNDS.items()
        },
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
    del execution_time
    timestamps = [
        timestamp
        for start, end in SESSION_BOUNDS.values()
        for timestamp in (
            start + timedelta(seconds=offset)
            for offset in range(
                0,
                int((end - start).total_seconds()),
                5,
            )
        )
    ]
    return rows_for_timestamps(timestamps)


def concentrated_execution_window_rows(
    execution_time: datetime,
) -> list[dict]:
    timestamps = [
        *[
            start + timedelta(seconds=offset)
            for name, (start, end) in SESSION_BOUNDS.items()
            if name != "day_open"
            for offset in range(0, int((end - start).total_seconds()), 5)
        ],
        *[
            execution_time + timedelta(seconds=offset)
            for offset in range(-10, 10)
        ],
    ]
    return rows_for_timestamps(sorted(timestamps))


def session_window_specs() -> list:
    return [
        MODULE["SessionWindow"](name=name, start=start, end=end)
        for name, (start, end) in SESSION_BOUNDS.items()
    ]


def rows_for_timestamps(timestamps: list[datetime]) -> list[dict]:
    return [
        tick_row(
            ts,
            ingest_id=f"tick-{index}",
            ingest_seq=index + 1,
            volume=10 + index,
            last_volume=1 if index else 0,
        )
        for index, ts in enumerate(timestamps)
    ]


def fragmented_session_rows(execution_time: datetime) -> list[dict]:
    rows = complete_session_rows(execution_time)
    start, _ = SESSION_BOUNDS["night_session"]
    replacement = [
        start + timedelta(seconds=index * 10)
        for index in range(20)
    ]
    kept = [
        row
        for row in rows
        if not (
            SESSION_BOUNDS["night_session"][0]
            <= row["ts"]
            < SESSION_BOUNDS["night_session"][1]
        )
    ]
    return rows_for_timestamps(
        sorted([row["ts"] for row in kept] + replacement)
    )


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

    with pytest.raises(MODULE["AuditError"], match="schema validation failed"):
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


def test_manifest_rejects_noncanonical_session_window(
    tmp_path: Path,
) -> None:
    payload = manifest_payload()
    payload["session_windows"]["night_session"]["end_exclusive"] = (
        datetime(2026, 8, 31, 13, 11, 40, tzinfo=timezone.utc).isoformat()
    )

    with pytest.raises(MODULE["AuditError"], match="canonical China time"):
        MODULE["load_manifest"](write_manifest(tmp_path, payload))


def test_manifest_rejects_invalid_calendar_trading_day(
    tmp_path: Path,
) -> None:
    payload = manifest_payload()
    payload["audit_window"]["trading_day"] = "20261340"

    with pytest.raises(MODULE["AuditError"], match="valid calendar date"):
        MODULE["load_manifest"](write_manifest(tmp_path, payload))


def test_manifest_strict_reader_rejects_duplicate_keys_nan_and_symlink(
    tmp_path: Path,
) -> None:
    payload_text = json.dumps(manifest_payload())
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        payload_text.replace(
            '"snapshot_id":',
            '"snapshot_id": "duplicate-id", "snapshot_id":',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(MODULE["AuditError"], match="duplicate JSON key"):
        MODULE["load_manifest"](duplicate_path)

    nan_path = tmp_path / "nan.json"
    nan_path.write_text(
        payload_text[:-1] + ', "probe": NaN}',
        encoding="utf-8",
    )
    with pytest.raises(MODULE["AuditError"], match="non-finite JSON number"):
        MODULE["load_manifest"](nan_path)

    target = write_manifest(tmp_path, manifest_payload())
    symlink_path = tmp_path / "manifest-link.json"
    symlink_path.symlink_to(target)
    with pytest.raises(MODULE["AuditError"], match="must not be a symlink"):
        MODULE["load_manifest"](symlink_path)


def test_manifest_strict_reader_detects_same_size_same_mtime_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_manifest(tmp_path, manifest_payload())
    original = path.read_text(encoding="utf-8")
    replacement = original.replace(
        "c-fast-p0-test-a01",
        "c-fast-p0-test-a02",
        1,
    )
    assert len(replacement.encode()) == len(original.encode())
    original_stat = path.stat()
    original_read = MODULE["os"].read
    mutated = False

    def mutate_before_first_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            path.write_text(replacement, encoding="utf-8")
            MODULE["os"].utime(
                path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
        return original_read(descriptor, size)

    monkeypatch.setattr(MODULE["os"], "read", mutate_before_first_read)

    with pytest.raises(MODULE["AuditError"], match="changed while"):
        MODULE["load_manifest"](path)


def test_manifest_normalizes_exact_contract_and_binds_execution_window(
    tmp_path: Path,
) -> None:
    payload = manifest_payload()
    payload["execution_windows"] = [
        {
            "window_id": "ag-window-a01",
            "product": "ag",
            "exact_contract": "ag2609.SHFE",
            "execution_time": "2026-09-01T01:01:00+00:00",
            "window_seconds": 60,
        }
    ]

    _, contracts, session_windows, windows = MODULE["load_manifest"](
        write_manifest(tmp_path, payload)
    )

    assert contracts[0].exact_contract == "SHFE.ag2609"
    assert contracts[0].vt_symbol == "ag2609.SHFE"
    assert windows[0].vt_symbol == "ag2609.SHFE"
    assert windows[0].execution_time.tzinfo == timezone.utc
    assert [item.name for item in session_windows] == [
        "night_open",
        "night_session",
        "day_open",
        "day_session",
    ]


def test_five_level_rows_are_l5_usable() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(100):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(milliseconds=500 * index),
                ingest_id=f"tick-{index}",
                ingest_seq=index + 1,
                volume=10 + index,
                last_volume=1 if index else 0,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "L5_USABLE"
    assert result["l1_complete_ratio"] == 1
    assert result["l5_complete_ratio"] == 1
    assert result["volume_semantics"]["last_volume_match_ratio"] == 1


def test_nonempty_wrong_trading_day_is_degraded() -> None:
    accumulator = MODULE["MetricsAccumulator"](
        dict(MODULE["THRESHOLDS"]),
        expected_trading_day="20260901",
    )
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(20):
        row = tick_row(
            start + timedelta(seconds=index),
            ingest_id=f"tick-{index}",
            ingest_seq=index + 1,
            volume=10 + index,
            last_volume=1 if index else 0,
        )
        row["trading_day"] = "20260831"
        add_row(accumulator, row)

    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["missing_trading_day_rows"] == 20


def test_volume_semantics_require_enough_matching_positive_deltas() -> None:
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    too_short = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    for index in range(5):
        add_row(
            too_short,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"short-{index}",
                ingest_seq=index + 1,
                volume=10 + index,
                last_volume=1 if index else 0,
            ),
        )
    assert too_short.result()["classification"] == "DEGRADED"

    mismatched = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    for index in range(20):
        add_row(
            mismatched,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"mismatch-{index}",
                ingest_seq=index + 1,
                volume=10 + index,
                last_volume=2 if index else 0,
            ),
        )
    result = mismatched.result()
    assert result["classification"] == "DEGRADED"
    assert result["volume_semantics"]["last_volume_match_ratio"] == 0


def test_missing_deeper_levels_cannot_fall_back_to_l5() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(20):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"tick-{index}",
                ingest_seq=index + 1,
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
                ingest_seq=index + 1,
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


def test_constant_zero_ingest_seq_is_degraded() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index in range(20):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"tick-{index}",
                ingest_seq=0,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["non_positive_ingest_seq_rows"] == 20
    assert result["anomalies"]["ingest_seq_non_increasing_rows"] == 19
    assert (
        result["anomalies"]["ingest_seq_repeat_across_timestamp_rows"]
        == 19
    )


def test_ingest_seq_regression_exposes_reset_candidate() -> None:
    accumulator = MODULE["MetricsAccumulator"](dict(MODULE["THRESHOLDS"]))
    start = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
    for index, ingest_seq in enumerate((100, 101, 1, 2)):
        add_row(
            accumulator,
            tick_row(
                start + timedelta(seconds=index),
                ingest_id=f"tick-{index}",
                ingest_seq=ingest_seq,
            ),
        )

    result = accumulator.result()

    assert result["classification"] == "DEGRADED"
    assert result["anomalies"]["ingest_seq_non_increasing_rows"] == 1
    assert result["anomalies"]["ingest_seq_regression_rows"] == 1
    assert result["anomalies"]["ingest_seq_reset_candidates"] == 1


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
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
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
        session_window_specs(),
        [window],
        AUDIT_START,
        AUDIT_END,
        "20260901",
    )

    assert connection.sql.lstrip().upper().startswith("SELECT")
    assert all(
        keyword not in connection.sql.upper()
        for keyword in ("INSERT", "UPDATE", "DELETE", "ALTER", "DROP")
    )
    assert connection.params[0] == "ag2609.SHFE"
    assert result["classification"] == "L5_USABLE"
    assert window_results[0]["classification"] == "L5_USABLE"
    assert window_results[0]["rows_before"] == 12
    assert window_results[0]["rows_after"] == 13
    assert window_results[0]["start_boundary_gap_seconds"] == 0
    assert window_results[0]["end_boundary_gap_seconds"] == 0
    assert window_results[0]["max_observed_tick_gap_seconds"] == 5
    assert window_results[0]["max_gap_seconds"] == 5
    assert window_results[0]["boundary_coverage_complete"] is True


def test_execution_window_requires_full_boundary_coverage() -> None:
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
    connection = FakeConnection(
        concentrated_execution_window_rows(execution_time)
    )
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

    _, window_results = MODULE["audit_contract"](
        connection,
        contract,
        session_window_specs(),
        [window],
        AUDIT_START,
        AUDIT_END,
        "20260901",
    )

    result = window_results[0]
    assert result["classification"] == "DEGRADED"
    assert result["start_boundary_gap_seconds"] == 50
    assert result["end_boundary_gap_seconds"] == 51
    assert result["max_observed_tick_gap_seconds"] == 1
    assert result["max_gap_seconds"] == 51
    assert result["boundary_coverage_complete"] is False


def test_required_session_rejects_fragmented_twenty_row_sample() -> None:
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
    connection = FakeConnection(fragmented_session_rows(execution_time))
    contract = MODULE["ContractSpec"](
        product="ag",
        role="current",
        exact_contract="SHFE.ag2609",
        vt_symbol="ag2609.SHFE",
    )

    result, _ = MODULE["audit_contract"](
        connection,
        contract,
        session_window_specs(),
        [],
        AUDIT_START,
        AUDIT_END,
        "20260901",
    )

    assert result["classification"] == "DEGRADED"
    assert (
        result["sessions"]["night_session"]["classification"]
        == "DEGRADED"
    )
    assert (
        result["session_coverage"]["night_session"]["max_gap_seconds"]
        > MODULE["THRESHOLDS"]["max_required_session_gap_seconds"]
    )


def test_full_ten_product_audit_can_reach_p0_pass(tmp_path: Path) -> None:
    execution_time = datetime(2026, 9, 1, 1, 1, tzinfo=timezone.utc)
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
    manifest, contracts, session_windows, windows = MODULE["load_manifest"](
        write_manifest(tmp_path, payload)
    )
    connection = FakeConnection(complete_session_rows(execution_time))

    evidence = MODULE["audit"](
        connection,
        manifest,
        contracts,
        session_windows,
        windows,
        AUDIT_START,
        AUDIT_END,
    )

    assert evidence["summary"]["p0_pass"] is True
    assert evidence["summary"]["overall_conclusion"] == "L5_USABLE"
    assert evidence["summary"]["classification_counts"]["L5_USABLE"] == 10
    assert evidence["blockers"] == []
    assert len(evidence["contracts"]) == 10
    assert len(evidence["execution_windows"]) == 10
    assert len(json.dumps(evidence, ensure_ascii=False)) > 1000
    MODULE["validate_json_schema"](
        evidence,
        MODULE["EVIDENCE_SCHEMA_PATH"],
        "test evidence",
    )

    with pytest.raises(MODULE["AuditError"], match="CLI start does not match"):
        MODULE["audit"](
            connection,
            manifest,
            contracts,
            session_windows,
            windows,
            AUDIT_START + timedelta(seconds=1),
            AUDIT_END,
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
            "trading_day": "20260901",
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
                "session_coverage": {
                    name: {
                        "start": SESSION_BOUNDS[name][0].isoformat(),
                        "end_exclusive": SESSION_BOUNDS[name][1].isoformat(),
                        "start_boundary_gap_seconds": None,
                        "end_boundary_gap_seconds": None,
                        "max_observed_tick_gap_seconds": None,
                        "max_gap_seconds": None,
                        "boundary_coverage_complete": False,
                        "classification": "UNUSABLE",
                    }
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
