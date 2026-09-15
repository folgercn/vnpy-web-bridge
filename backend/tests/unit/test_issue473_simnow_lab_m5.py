from __future__ import annotations

import importlib
import json
import math
import stat
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
calendar_models = importlib.import_module("research_warehouse.calendar_models")
m5 = importlib.import_module("simnow_lab_m5_run_once")
research_job = importlib.import_module("research_warehouse.m2_scheduler_cli")
pit_source = importlib.import_module("research_warehouse.pit_source_view")
preopen = importlib.import_module("research_warehouse.simnow_lab_monthly_preopen")
shfe_parameters = importlib.import_module(
    "research_warehouse.shfe_contract_parameters"
)
pit_fixture = importlib.import_module("test_research_warehouse_pit_source_view")
route_fixture = importlib.import_module("test_simnow_experimental_timely_daily_route")
daily_fixture = importlib.import_module("test_research_warehouse_daily_pit_main_roll_source")
target_fixture = importlib.import_module("test_simnow_experimental_target")
relative_vol_fixture = importlib.import_module(
    "test_commodity_relative_vol_snapshot_producer"
)
static_producer = importlib.import_module("commodity_static_core_equal_pure_producer")


def test_m5_produces_before_reusing_existing_run_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    static = tmp_path / "static.json"
    static.write_text('{"schema_version":"legacy-static"}\n', encoding="utf-8")
    thermostat = tmp_path / "thermostat.json"
    thermostat.write_text(
        '{"baseline_batch":{"source_month":"2030-01"}}\n', encoding="utf-8"
    )
    calls: list[object] = []

    def produce(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"status": "MATERIALIZED", "target_id": "a" * 64}

    monkeypatch.setattr(m5, "run_monthly_once", produce)
    monkeypatch.setattr(m5.lab_cli, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(
        m5,
        "require_fresh_daily_route",
        lambda _path, **_kwargs: date(2030, 2, 1),
    )
    monkeypatch.setattr(
        m5, "require_candidate_bindings", lambda **_kwargs: calls.append("binding")
    )

    assert (
        m5.run_once(
            static_source=static,
            thermostat_source=thermostat,
            daily_route=tmp_path / "route.json",
            monthly_bundles=tmp_path / "monthly",
            target=tmp_path / "target.json",
            lab_target=tmp_path / "lab-target.json",
        )
        == 0
    )
    assert calls[0]["source_month"] == "2030-01"
    assert calls[1] == "binding"
    assert calls[2] == [
        "run-once",
        "--input",
        str(tmp_path / "target.json"),
        "--output",
        str(tmp_path / "lab-target.json"),
        "--request-address",
        m5.lab_cli.DEFAULT_REQUEST_ADDRESS,
        "--publish-address",
        m5.lab_cli.DEFAULT_PUBLISH_ADDRESS,
        "--timeout-ms",
        "30000",
    ]


@pytest.mark.parametrize(
    ("static_schema", "thermostat_schema"),
    (
        (preopen.STATIC_SCHEMA, "legacy-thermostat"),
        ("legacy-static", preopen.THERMOSTAT_SCHEMA),
    ),
)
def test_m5_rejects_mixed_preopen_pair_before_legacy_fallback(
    tmp_path: Path, static_schema: str, thermostat_schema: str
) -> None:
    static = tmp_path / "static.json"
    thermostat = tmp_path / "thermostat.json"
    static.write_text(json.dumps({"schema_version": static_schema}) + "\n")
    thermostat.write_text(json.dumps({"schema_version": thermostat_schema}) + "\n")

    with pytest.raises(m5.SimNowLabM5Error, match="preopen pair is mixed"):
        m5._preopen_inputs(static, thermostat)


def test_m5_rejects_stale_legacy_month_before_target_or_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    static = tmp_path / "static.json"
    thermostat = tmp_path / "thermostat.json"
    static.write_text('{"schema_version":"legacy-static"}\n')
    thermostat.write_text(
        '{"baseline_batch":{"source_month":"2026-07"}}\n'
    )
    monkeypatch.setattr(
        m5,
        "require_fresh_daily_route",
        lambda *_args, **_kwargs: date(2026, 9, 1),
    )
    monkeypatch.setattr(
        m5,
        "run_monthly_once",
        lambda **_kwargs: pytest.fail("stale legacy month must not materialize"),
    )
    monkeypatch.setattr(
        m5.lab_cli,
        "main",
        lambda _args: pytest.fail("stale legacy month must not reach CURRENT/APPLY"),
    )

    with pytest.raises(m5.SimNowLabM5Error, match="LEGACY_SOURCE_MONTH_STALE"):
        m5.run_once(
            static_source=static,
            thermostat_source=thermostat,
            daily_route=tmp_path / "route.json",
            monthly_bundles=tmp_path / "monthly",
            target=tmp_path / "target.json",
            lab_target=tmp_path / "lab-target.json",
            now=datetime(2026, 8, 31, 21, 5, tzinfo=m5.SHANGHAI),
        )


def _preopen_identity() -> tuple[bytes, bytes]:
    return (
        m5.materializer.canonical_json_line(
            {"source_month": "2026-08", "execution_day": "2026-09-01"}
        ),
        b"thermostat-preopen\n",
    )


def test_m5_next_evening_stops_before_market_target_or_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"last-valid-target\n")
    monkeypatch.setattr(m5, "_preopen_inputs", lambda *_args: _preopen_identity())
    monkeypatch.setattr(
        m5,
        "require_fresh_daily_route",
        lambda *_args, **_kwargs: date(2026, 9, 2),
    )
    monkeypatch.setattr(
        m5,
        "_market_snapshot",
        lambda **_kwargs: pytest.fail("MARKET must not run in the next-evening window"),
    )
    monkeypatch.setattr(
        m5.monthly_once,
        "materialize_monthly_once",
        lambda **_kwargs: pytest.fail("target must not change in the next-evening window"),
    )
    monkeypatch.setattr(
        m5.lab_cli,
        "main",
        lambda _args: pytest.fail("apply must not run in the next-evening window"),
    )

    with pytest.raises(m5.SimNowLabM5Error, match="EXECUTION_WINDOW_MISMATCH"):
        m5.run_once(
            static_source=tmp_path / "static.json",
            thermostat_source=tmp_path / "thermostat.json",
            daily_route=tmp_path / "route.json",
            monthly_bundles=tmp_path / "bundles",
            target=target,
            lab_target=tmp_path / "lab-target.json",
            now=datetime(2026, 9, 1, 21, 5, tzinfo=m5.SHANGHAI),
        )
    assert target.read_bytes() == b"last-valid-target\n"


def test_m5_following_day_reuses_existing_bundle_without_market_or_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(m5, "_preopen_inputs", lambda *_args: _preopen_identity())
    monkeypatch.setattr(
        m5,
        "require_fresh_daily_route",
        lambda *_args, **_kwargs: date(2026, 9, 2),
    )
    monkeypatch.setattr(
        m5,
        "_market_snapshot",
        lambda **_kwargs: pytest.fail("MARKET is only for the monthly execution-open join"),
    )

    def reuse(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"status": "MATERIALIZED", "target_id": "a" * 64}

    monkeypatch.setattr(m5.monthly_once, "materialize_monthly_once", reuse)
    monkeypatch.setattr(
        m5, "require_candidate_bindings", lambda **_kwargs: calls.append("binding")
    )
    monkeypatch.setattr(m5.lab_cli, "main", lambda args: calls.append(args) or 0)

    assert (
        m5.run_once(
            static_source=tmp_path / "static.json",
            thermostat_source=tmp_path / "thermostat.json",
            daily_route=tmp_path / "route.json",
            monthly_bundles=tmp_path / "bundles",
            target=tmp_path / "target.json",
            lab_target=tmp_path / "lab-target.json",
            now=datetime(2026, 9, 2, 9, 5, tzinfo=m5.SHANGHAI),
        )
        == 0
    )
    assert calls[0] == {
        "source_month": "2026-08",
        "monthly_bundle_directory": tmp_path / "bundles",
        "daily_pit_route_path": tmp_path / "route.json",
        "target_path": tmp_path / "target.json",
    }
    assert calls[1] == "binding"


def _issue483_market_snapshot(
    *, rows: list[dict[str, object]], observed_at: str = "2026-08-31T13:01:00Z"
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": m5.preopen_join.MARKET_SCHEMA,
        "status": "MARKET",
        "observed_at": observed_at,
        "rows": rows,
        "snapshot_sha256": "",
    }
    value["snapshot_sha256"] = preopen.sha256(
        preopen.canonical_json(
            {key: item for key, item in value.items() if key != "snapshot_sha256"}
        )
    )
    return value


def test_m5_market_passes_exact_subscription_hints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        m5.lab_cli, "rpc_call", lambda **kwargs: calls.append(kwargs) or {"status": "MARKET"}
    )
    assert m5._market_snapshot(
        request_address="request", publish_address="publish", timeout_ms=30_000,
        vt_symbols=["rb2701.SHFE"],
    ) == {"status": "MARKET"}
    assert calls[0]["args"] == ("MARKET", ["rb2701.SHFE"])


def _issue483_market_row(
    *, contract: str = "SHFE.ag2609", symbol: str = "ag2609.SHFE"
) -> dict[str, object]:
    return {
        "vt_symbol": symbol,
        "exact_contract": contract,
        "exchange": contract.split(".", 1)[0],
        "open_price": 5_000.0,
        "tick_datetime": "2026-08-31T13:00:30Z",
        "trading_day": "2026-09-01",
        "gateway_name": "CTP",
    }


def test_issue483_market_selects_expected_rows_from_legal_superset() -> None:
    rows, observed_at = m5.preopen_join._market_rows(
        _issue483_market_snapshot(
            rows=[
                _issue483_market_row(),
                _issue483_market_row(
                    contract="SHFE.al2609", symbol="al2609.SHFE"
                ),
            ]
        ),
        expected={"ag": ("SHFE.ag2609", "SHFE")},
        execution_day="2026-09-01",
        now=datetime(2026, 8, 31, 13, 2, tzinfo=timezone.utc),
    )

    assert tuple(rows) == ("SHFE.ag2609",)
    assert observed_at == datetime(2026, 8, 31, 13, 1, tzinfo=timezone.utc)


def test_issue483_market_rejects_bad_hash_before_producer_work() -> None:
    snapshot = _issue483_market_snapshot(rows=[_issue483_market_row()])
    snapshot["snapshot_sha256"] = "0" * 64

    with pytest.raises(m5.preopen_join.MonthlyPreopenJoinError, match="HASH"):
        m5.preopen_join._market_rows(
            snapshot,
            expected={"ag": ("SHFE.ag2609", "SHFE")},
            execution_day="2026-09-01",
            now=datetime(2026, 8, 31, 13, 2, tzinfo=timezone.utc),
        )


def test_issue483_route_mismatch_stops_before_market_or_target_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    static = {
        "source_month": "2026-08",
        "execution_day": "2026-09-01",
        "products": [],
    }
    route = {"metadata": {"execution_day": "2026-09-02"}}
    monkeypatch.setattr(
        m5.preopen_join, "validate_preopen_pair", lambda *_: (static, {})
    )
    monkeypatch.setattr(
        m5.preopen_join.materializer,
        "read_json_stable",
        lambda *_args, **_kwargs: (route, b"{}\n"),
    )
    monkeypatch.setattr(
        m5.preopen_join.materializer, "_daily_routes", lambda _route: {}
    )
    monkeypatch.setattr(
        m5.preopen_join,
        "_market_rows",
        lambda *_args, **_kwargs: pytest.fail(
            "MARKET must not run after route mismatch"
        ),
    )

    with pytest.raises(
        m5.preopen_join.MonthlyPreopenJoinError, match="ROUTE_MISMATCH"
    ):
        m5.preopen_join.complete_and_materialize(
            static_preopen_raw=b"{}\n",
            thermostat_preopen_raw=b"{}\n",
            daily_route_path=tmp_path / "route.json",
            market_snapshot={},
            monthly_bundle_directory=tmp_path / "bundles",
            target_path=tmp_path / "target.json",
        )
    assert not (tmp_path / "target.json").exists()


def test_issue483_thermostat_accepts_real_previous_night_trading_day() -> None:
    source = relative_vol_fixture.source_view(execution_lane="simnow_shakedown")
    source["generated_at"] = "2026-08-31T21:05:00+08:00"

    result = m5.preopen_join.thermostat_producer.produce_snapshot(source)

    assert result.source_view_canonical_sha256


@pytest.mark.parametrize(
    "generated_at",
    ["2026-08-31T19:59:59+08:00", "2026-08-30T21:05:00+08:00"],
)
def test_issue483_thermostat_rejects_non_trading_day_time(
    generated_at: str,
) -> None:
    source = relative_vol_fixture.source_view(execution_lane="simnow_shakedown")
    source["generated_at"] = generated_at

    with pytest.raises(m5.preopen_join.thermostat_producer.SnapshotProducerError):
        m5.preopen_join.thermostat_producer.produce_snapshot(source)


def test_issue483_thermostat_rejects_wrong_execution_day_after_night() -> None:
    source = relative_vol_fixture.source_view(execution_lane="simnow_shakedown")
    source["generated_at"] = "2026-09-01T21:05:00+08:00"
    source["baseline_batch"]["execution_day"] = "2026-09-02"
    source["baseline_batch_hash"] = preopen.sha256(
        m5.preopen_join.thermostat_producer.canonical_json(
            {
                key: value
                for key, value in source["baseline_batch"].items()
                if key != "signature"
            }
        )
    )

    with pytest.raises(
        m5.preopen_join.thermostat_producer.SnapshotProducerError,
        match="TradingDay",
    ):
        m5.preopen_join.thermostat_producer.produce_snapshot(source)


def test_issue483_official_forward_does_not_gain_simnow_night_exception() -> None:
    source = relative_vol_fixture.source_view(execution_lane="official_forward")
    source["generated_at"] = "2026-08-31T21:05:00+08:00"

    with pytest.raises(
        m5.preopen_join.thermostat_producer.SnapshotProducerError,
        match="TradingDay",
    ):
        m5.preopen_join.thermostat_producer.produce_snapshot(source)


def _binding_paths(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    bundle = target_fixture._bundle()
    route = target_fixture._route(bundle)
    source_month = bundle["source_month"]
    bundle_raw = m5.materializer.canonical_json_line(bundle)
    route_raw = m5.materializer.canonical_json_line(route)
    target = m5.materializer.materialize_target(
        planner_bundle=bundle,
        planner_bundle_raw=bundle_raw,
        daily_route=route,
        daily_route_raw=route_raw,
        generated_at="2030-01-01T00:00:00Z",
    )
    bundles = tmp_path / "bundles"
    bundles.mkdir()
    (bundles / f"{source_month}.json").write_bytes(bundle_raw)
    route_path = tmp_path / "route.json"
    route_path.write_bytes(route_raw)
    target_path = tmp_path / "target.json"
    target_path.write_bytes(m5.materializer.canonical_json_line(target))
    return bundles, route_path, target_path, source_month


def test_m5_candidate_binding_accepts_current_monthly_bundle_and_route(
    tmp_path: Path,
) -> None:
    bundles, route, target, source_month = _binding_paths(tmp_path)

    m5.require_candidate_bindings(
        source_month=source_month,
        monthly_bundles=bundles,
        daily_route=route,
        target=target,
    )


@pytest.mark.parametrize("field", ("monthly_quantity_sha256", "daily_route_sha256"))
def test_m5_candidate_binding_rejects_coherent_hash_tamper_before_cli(
    tmp_path: Path, field: str
) -> None:
    bundles, route, target_path, source_month = _binding_paths(tmp_path)
    tampered = json.loads(target_path.read_bytes())
    tampered[field] = "0" * 64
    tampered["target_id"] = m5.materializer._target_id(tampered)
    target_path.write_bytes(m5.materializer.canonical_json_line(tampered))

    with pytest.raises(m5.SimNowLabM5Error, match="does not bind"):
        m5.require_candidate_bindings(
            source_month=source_month,
            monthly_bundles=bundles,
            daily_route=route,
            target=target_path,
        )


def test_m5_invalid_producer_input_stops_before_materialize_or_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"last-valid-target\n")
    calls: list[str] = []
    monkeypatch.setattr(
        m5, "run_monthly_once", lambda **_kwargs: calls.append("materialize")
    )
    monkeypatch.setattr(m5.lab_cli, "main", lambda _args: calls.append("apply") or 0)

    assert (
        m5.main(
            [
                "--thermostat-source",
                str(tmp_path / "missing.json"),
                "--target",
                str(target),
            ]
        )
        == 1
    )
    assert calls == []
    assert target.read_bytes() == b"last-valid-target\n"


@pytest.mark.parametrize(
    "payload",
    (
        {},
        {"baseline_batch": {}},
        {"source_month": "2030-02", "baseline_batch": {"source_month": "2030-01"}},
    ),
)
def test_m5_rejects_missing_or_inconsistent_thermostat_source_month(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    source = tmp_path / "thermostat.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(m5.SimNowLabM5Error):
        m5.source_month_from_input(source)


def test_m5_launch_agent_has_one_calendar_runner_without_target_watch() -> None:
    raw = (ROOT / "deployments/com.vnpy-web-bridge.simnow-lab.plist").read_text(
        encoding="utf-8"
    )
    assert "scripts.simnow_lab_m5_run_once" in raw
    assert "WatchPaths" not in raw
    assert raw.count("<key>Weekday</key>") == 15


def test_m5_defaults_to_read_only_research_export_seam() -> None:
    root = Path("/Users/Shared/vnpy-simnow-lab-inputs")
    assert m5.STATIC_SOURCE == root / "static-core-equal-monthly-source.json"
    assert m5.THERMOSTAT_SOURCE == root / "monthly-relative-vol-thermostat-source.json"
    assert m5.DAILY_ROUTE == root / "daily-pit-route.json"
    assert m5.TARGET.parent == m5.EVIDENCE


def test_research_export_atomic_write_is_idempotent_and_public_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outputs = (b"static", b"thermostat", b"route")
    monkeypatch.setattr(
        research_job, "SIMNOW_LAB_INPUT_DIRECTORY", tmp_path / "exports"
    )
    monkeypatch.setattr(
        research_job, "_precompute_daily_route_export", lambda *_args: outputs[2]
    )
    monkeypatch.setattr(
        research_job, "_preopen_source_month_for_completed_day", lambda *_args: None
    )
    monkeypatch.setattr(research_job, "_precompute_exports", lambda *_args: outputs)
    result = {"status": "OFFICIAL_DAY_COMPLETE", "trade_day": "2030-01-31"}
    history = tmp_path / "history.json"
    research_job.export_simnow_lab_inputs(
        context=object(), daily_result=result, history_receipt_path=history,
        operator_state=object(),
    )
    paths = [
        research_job.SIMNOW_LAB_INPUT_DIRECTORY / name
        for name in research_job.SIMNOW_LAB_EXPORT_NAMES
    ]
    before = paths[2].stat().st_mtime_ns
    assert not paths[0].exists()
    assert not paths[1].exists()
    assert paths[2].read_bytes() == outputs[2]
    assert stat.S_IMODE(paths[2].stat().st_mode) == 0o644

    research_job.export_simnow_lab_inputs(
        context=object(), daily_result=result, history_receipt_path=history,
        operator_state=object(),
    )
    assert paths[2].stat().st_mtime_ns == before


def test_monthly_preopen_scheduler_passes_pinned_shfe_expiry_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence = object()
    captured: dict[str, object] = {}
    state = SimpleNamespace(
        raw_sha256="4" * 64,
        payload={
            "manifest_genesis_seal_sha256": "5" * 64,
            "manifest_head_seal_sha256": "6" * 64,
            "manifest_head_commit_seal_sha256": "7" * 64,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
        },
    )
    monkeypatch.setattr(
        research_job,
        "_preopen_source_month_for_completed_day",
        lambda *_args: "2026-08",
    )
    monkeypatch.setattr(
        research_job,
        "_one_186_day_backfill",
        lambda *_args: ({"official_days": []}, b"history"),
    )
    monkeypatch.setattr(research_job, "_backfill_daily_raw", lambda *_args: {})
    monkeypatch.setattr(
        research_job,
        "_simnow_lab_contract_parameter_evidence",
        lambda: evidence,
    )
    monkeypatch.setattr(
        research_job,
        "_frozen_contract_registry_raw",
        lambda: b"registry",
    )

    def build(**kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(static_raw=b"static", thermostat_raw=b"thermostat")

    monkeypatch.setattr(research_job, "build_monthly_preopen", build)
    context = SimpleNamespace(
        calendar=object(),
        availability=SimpleNamespace(raw_sha256="2" * 64),
        registry=SimpleNamespace(raw_sha256="1" * 64),
    )
    assert research_job._precompute_monthly_preopen_exports(
        context, "2026-08-31", tmp_path / "history.json", state
    ) == (b"static", b"thermostat")
    assert captured["source_month"] == "2026-08"
    assert captured["shfe_contract_parameters"] is evidence


def _monthly_preopen_inputs() -> tuple[object, dict, dict, bytes]:
    calendar, history, daily_raw, _key = pit_fixture._inputs()
    rows = dict(calendar.days)
    current = calendar.valid_to + timedelta(days=1)
    extended_to = date(2026, 9, 1)
    while current <= extended_to:
        rows[current] = calendar_models.CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    calendar = calendar_models.OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=extended_to,
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
    # The PIT fixture's first synthetic delivery is Dec-2026, beyond even this
    # test calendar. Keep its complete OHLC shape with an August delivery.
    adjusted_daily_raw: dict[str, dict[str, bytes]] = {}
    for raw_day, sources in daily_raw.items():
        adjusted_daily_raw[raw_day] = {}
        for exchange, raw in sources.items():
            payload = json.loads(raw)
            for row in payload["o_curinstrument"]:
                if row["DELIVERYMONTH"] == "2612":
                    row["DELIVERYMONTH"] = "2608"
            adjusted_daily_raw[raw_day][exchange] = preopen.canonical_json(payload)
    daily_raw = adjusted_daily_raw
    return calendar, history, daily_raw, research_job._frozen_contract_registry_raw()


def _extend_calendar(calendar, extended_to: date):
    rows = dict(calendar.days)
    current = calendar.valid_to + timedelta(days=1)
    while current <= extended_to:
        rows[current] = calendar_models.CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    return calendar_models.OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=extended_to,
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )


def _shfe_parameter_evidence(
    *,
    report_day: date,
    expiry_by_instrument: dict[str, str],
):
    raw = preopen.canonical_json(
        {
            "ContractBaseInfo": [
                {
                    "INSTRUMENTID": instrument,
                    "EXCHANGEID": "SHFE",
                    "COMMODITYID": instrument[:-4],
                    "TRADINGDAY": report_day.strftime("%Y%m%d"),
                    "EXPIREDATE": expiry,
                }
                for instrument, expiry in sorted(expiry_by_instrument.items())
            ],
            "report_date": report_day.strftime("%Y%m%d"),
            "update_date": f"{report_day:%Y%m%d} 16:20:09",
        }
    )
    return shfe_parameters.evidence_from_raw(
        query_day=report_day,
        observed_at=(report_day + timedelta(days=1)).strftime(
            "%Y-%m-%dT01:00:00.000000Z"
        ),
        raw=raw,
        expected_raw_sha256=preopen.sha256(raw),
    )


def test_monthly_preopen_bridges_january_delivery_beyond_calendar_horizon() -> None:
    calendar, history, daily_raw, registry_raw = _monthly_preopen_inputs()
    calendar = _extend_calendar(calendar, date(2026, 12, 31))
    remapped: dict[str, dict[str, bytes]] = {}
    delivery_map = {"2608": "2701", "2701": "2702", "2702": "2703"}
    for raw_day, sources in daily_raw.items():
        remapped[raw_day] = {}
        for exchange, raw in sources.items():
            payload = json.loads(raw)
            if exchange == "SHFE":
                for row in payload["o_curinstrument"]:
                    row["DELIVERYMONTH"] = delivery_map.get(
                        row["DELIVERYMONTH"], row["DELIVERYMONTH"]
                    )
            remapped[raw_day][exchange] = preopen.canonical_json(payload)
    shfe_products = [
        product
        for product in m5.preopen_join.cfast.PRODUCTS
        if m5.preopen_join.cfast.PRODUCT_SPECS[product]["exchange"] == "SHFE"
    ]
    evidence = _shfe_parameter_evidence(
        report_day=date(2026, 7, 31),
        expiry_by_instrument={
            f"{product}{delivery}": expiry
            for product in shfe_products
            for delivery, expiry in (
                ("2701", "20270115"),
                ("2702", "20270215"),
                ("2703", "20270315"),
            )
        },
    )
    kwargs = {
        "calendar": calendar,
        "calendar_anchor_raw_sha256": "2" * 64,
        "warehouse_registry_raw_sha256": "1" * 64,
        "history_receipt": history,
        "history_receipt_raw_sha256": "3" * 64,
        "operator_pins": {"operator_state_raw_sha256": "4" * 64},
        "daily_source_raw": remapped,
        "contract_registry_raw": registry_raw,
        "source_month": "2026-07",
    }
    with pytest.raises(
        pit_source.PitSourceViewError,
        match="expiry evidence is required outside calendar coverage",
    ):
        preopen.build_monthly_preopen(**kwargs)

    built = preopen.build_monthly_preopen(
        **kwargs,
        shfe_contract_parameters=evidence,
    )
    static, thermostat = preopen.validate_preopen_pair(
        built.static_raw, built.thermostat_raw
    )
    assert static["pair_id"] == thermostat["pair_id"]
    assert static["lineage"] == thermostat["lineage"]
    assert len(static["lineage"]["shfe_contract_parameter_expiries"]) == len(
        shfe_products
    )
    for product in ("rb", "ru"):
        row = next(item for item in static["products"] if item["product"] == product)
        assert row["pit_main"]["exact_contract"] == f"SHFE.{product}2701"
        assert row["contract_spec"]["official_last_trading_day"] == "2027-01-15"


def test_monthly_preopen_rejects_calendar_and_shfe_expiry_disagreement() -> None:
    calendar, _history, _daily_raw, _registry_raw = _monthly_preopen_inputs()
    calendar = _extend_calendar(calendar, date(2027, 1, 31))
    evidence = _shfe_parameter_evidence(
        report_day=date(2026, 7, 31),
        expiry_by_instrument={"rb2701": "20270118"},
    )
    with pytest.raises(
        pit_source.PitSourceViewError,
        match="calendar/EXPIREDATE disagreement",
    ):
        preopen._official_last_trading_day(
            calendar=calendar,
            delivery_yyyymm=202701,
            rule=preopen.SHFE_LAST_DAY_RULE,
            exact_contract="SHFE.rb2701",
            shfe_contract_parameters=evidence,
        )


def _monthly_preopen_pair() -> tuple[bytes, bytes]:
    calendar, history, daily_raw, registry_raw = _monthly_preopen_inputs()
    built = preopen.build_monthly_preopen(
        calendar=calendar,
        calendar_anchor_raw_sha256="2" * 64,
        warehouse_registry_raw_sha256="1" * 64,
        history_receipt=history,
        history_receipt_raw_sha256="3" * 64,
        operator_pins={"operator_state_raw_sha256": "4" * 64},
        daily_source_raw=daily_raw,
        contract_registry_raw=registry_raw,
        source_month="2026-07",
    )
    return built.static_raw, built.thermostat_raw


def _august_execution_open_inputs() -> tuple[bytes, bytes, bytes, dict[str, object]]:
    start, end = date(2025, 10, 1), date(2026, 9, 30)
    days: dict[date, object] = {}
    current = start
    while current <= end:
        days[current] = calendar_models.CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    calendar = calendar_models.OfficialCalendar.create(
        calendar_id="issue483-august-calendar-v1",
        raw_sha256="a" * 64,
        valid_from=start,
        valid_to=end,
        issued_at=datetime(2025, 9, 1, tzinfo=timezone.utc),
        exchanges=("SHFE", "INE"),
        days=days,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )
    history_days = [
        day.isoformat()
        for day, row in calendar.days.items()
        if row.is_official and day <= date(2026, 8, 31)
    ][-186:]
    deliveries = {
        "SHFE": {"2612": "2609", "2701": "2610", "2702": "2611"},
        "INE": {"2612": "2610", "2701": "2611", "2702": "2612"},
    }
    daily_raw: dict[str, dict[str, bytes]] = {}
    for index, raw_day in enumerate(history_days):
        daily_raw[raw_day] = {}
        for exchange in ("SHFE", "INE"):
            payload = json.loads(pit_fixture._raw_for_day(raw_day, exchange, index))
            for row in payload["o_curinstrument"]:
                original_delivery = row["DELIVERYMONTH"]
                row["DELIVERYMONTH"] = deliveries[exchange].get(
                    original_delivery, original_delivery
                )
                if original_delivery not in {"2612", "2701", "2702"}:
                    continue
                product = row["PRODUCTID"].removesuffix("_f")
                product_index = list(m5.preopen_join.cfast.PRODUCTS).index(product)
                contract_index = ("2612", "2701", "2702").index(original_delivery)
                direction = 1 if product_index < 5 else -1
                noise = 0.00035 * (
                    ((index * (product_index + 3)) % 11) - 5
                ) / 5
                level = pit_fixture.PRODUCT_BASE[product] * 0.9 * math.exp(
                    direction * 0.001 * index + noise
                ) * (1 + contract_index * 0.01)
                tick = float(m5.preopen_join.cfast.PRODUCT_SPECS[product]["price_tick"])
                settlement = round(level / tick) * tick
                intraday = direction * 0.0002 * (1 + (index + contract_index) % 3)
                raw_open = settlement / (1 + intraday)
                row.update(
                    {
                        "OPENPRICE": str(raw_open),
                        "HIGHESTPRICE": str(max(raw_open, settlement) * 1.0001),
                        "LOWESTPRICE": str(min(raw_open, settlement) * 0.9999),
                        "CLOSEPRICE": str(settlement),
                        "SETTLEMENTPRICE": str(settlement),
                    }
                )
            daily_raw[raw_day][exchange] = preopen.canonical_json(payload)
    history = {
        "required_official_days": 186,
        "official_days": history_days,
        "daily_receipts": [],
    }
    built = preopen.build_monthly_preopen(
        calendar=calendar,
        calendar_anchor_raw_sha256="2" * 64,
        warehouse_registry_raw_sha256="1" * 64,
        history_receipt=history,
        history_receipt_raw_sha256="3" * 64,
        operator_pins={"operator_state_raw_sha256": "4" * 64},
        daily_source_raw=daily_raw,
        contract_registry_raw=research_job._frozen_contract_registry_raw(),
        source_month="2026-08",
    )
    static = json.loads(built.static_raw)
    route = {
        "schema_version": "daily-pit-route-v1",
        "mains": [
            {
                "product": row["product"],
                "exchange": row["exchange"],
                "exact_contract": row["pit_main"]["exact_contract"],
            }
            for row in static["products"]
        ],
        "metadata": {
            "route_mode": m5.materializer.SIMNOW_EXPERIMENTAL_TIMELY_ROUTE,
            "strategy_output_claim": m5.materializer.NOT_OFFICIAL_STRATEGY_OUTPUT,
            "official_day": "2026-08-31",
            "execution_day": "2026-09-01",
            "execution_cutoff_utc": "2026-09-01T01:10:00Z",
            "run_receipt_id": "issue483-august-route",
            "run_receipt_raw_sha256": "5" * 64,
            "contract_registry_raw_sha256": "6" * 64,
            "shfe_contract_parameters_raw_sha256": "7" * 64,
            "shfe_contract_parameters_observed_at": "2026-08-31T10:30:00Z",
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "official_forward_claimed": False,
        },
    }
    route_raw = preopen.canonical_json_line(route)
    rows = []
    for product in static["products"]:
        exact = product["pit_main"]["exact_contract"]
        symbol = exact.split(".", 1)[1]
        latest = product["daily"][-1]["contracts"]
        reference = next(row for row in latest if row["exact_contract"] == exact)
        rows.append(
            {
                "vt_symbol": f"{symbol}.{product['exchange']}",
                "exact_contract": exact,
                "exchange": product["exchange"],
                "open_price": reference["settlement"],
                "tick_datetime": "2026-08-31T13:05:00Z",
                "trading_day": "2026-09-01",
                "gateway_name": "CTP",
            }
        )
    market: dict[str, object] = {
        "schema_version": m5.preopen_join.MARKET_SCHEMA,
        "status": "MARKET",
        "observed_at": "2026-08-31T13:05:01Z",
        "rows": sorted(rows, key=lambda row: str(row["exact_contract"])),
    }
    market["snapshot_sha256"] = preopen.sha256(preopen.canonical_json(market))
    return built.static_raw, built.thermostat_raw, route_raw, market


def test_issue483_aug31_to_sep1_real_join_materializes_ten_product_bundle(
    tmp_path: Path,
) -> None:
    static_raw, thermostat_raw, route_raw, market = _august_execution_open_inputs()
    route = tmp_path / "daily-route.json"
    route.write_bytes(route_raw)
    bundles = tmp_path / "bundles"
    target_path = tmp_path / "target.json"

    result = m5.preopen_join.complete_and_materialize(
        static_preopen_raw=static_raw,
        thermostat_preopen_raw=thermostat_raw,
        daily_route_path=route,
        market_snapshot=market,
        monthly_bundle_directory=bundles,
        target_path=target_path,
        now=datetime(2026, 8, 31, 13, 5, 2, tzinfo=timezone.utc),
    )

    target = json.loads(target_path.read_bytes())
    bundle = json.loads((bundles / "2026-08.json").read_bytes())
    assert result["status"] == "MATERIALIZED"
    assert target["source_month"] == "2026-08"
    assert len(target["targets"]) == 10
    assert target["daily_route_sha256"] == m5.materializer._sha256(route_raw)
    assert [row["quantity"] for row in target["targets"]] == [
        row["shadow_target_quantity"]
        for row in bundle["position_manager_snapshot"]["targets"]
    ]

    following_route = json.loads(route_raw)
    following_route["metadata"].update(
        {
            "official_day": "2026-09-01",
            "execution_day": "2026-09-02",
            "execution_cutoff_utc": "2026-09-02T01:10:00Z",
            "run_receipt_id": "issue483-september-route",
            "run_receipt_raw_sha256": "8" * 64,
        }
    )
    following_raw = preopen.canonical_json_line(following_route)
    route.write_bytes(following_raw)
    following = m5.monthly_once.materialize_monthly_once(
        source_month="2026-08",
        monthly_bundle_directory=bundles,
        daily_pit_route_path=route,
        target_path=target_path,
        generated_at="2026-09-02T01:05:00Z",
    )
    rebound = json.loads(target_path.read_bytes())
    assert following["status"] == "MATERIALIZED"
    assert rebound["daily_route_sha256"] == m5.materializer._sha256(following_raw)
    assert [row["quantity"] for row in rebound["targets"]] == [
        row["quantity"] for row in target["targets"]
    ]
    m5.require_candidate_bindings(
        source_month="2026-08",
        monthly_bundles=bundles,
        daily_route=route,
        target=target_path,
    )


def test_month_end_preopen_is_bounded_pair_bound_and_not_a_producer_source() -> None:
    static_raw, thermostat_raw = _monthly_preopen_pair()
    static, thermostat = preopen.validate_preopen_pair(static_raw, thermostat_raw)

    assert len(static_raw) <= 4 * 1024 * 1024
    assert len(thermostat_raw) <= 4 * 1024 * 1024
    assert static["status"] == preopen.STATUS
    assert static["pair_id"] == thermostat["pair_id"]
    assert thermostat["static_preopen_sha256"] == preopen.sha256(static_raw)
    assert static["calendar"]["following_official_day"] == "2026-08-04"
    assert "execution_reference" not in static["products"][0]
    assert "baseline_batch" not in thermostat

    with pytest.raises(static_producer.cfast.ProducerKernelError):
        static_producer.produce_research_artifacts(static)


def test_month_end_preopen_rejects_pair_hash_tamper() -> None:
    static_raw, thermostat_raw = _monthly_preopen_pair()
    tampered = json.loads(thermostat_raw)
    tampered["static_preopen_sha256"] = "0" * 64
    with pytest.raises(pit_source.PitSourceViewError, match="hash binding"):
        preopen.validate_preopen_pair(
            static_raw, preopen.canonical_json_line(tampered)
        )


def test_nonmonth_export_recovers_staged_preopen_without_rebuilding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    static_raw, thermostat_raw = _monthly_preopen_pair()
    calendar, _history, _daily, _registry = _monthly_preopen_inputs()
    root = tmp_path / "exports"
    root.mkdir(mode=0o755)
    monkeypatch.setattr(research_job, "SIMNOW_LAB_INPUT_DIRECTORY", root)
    paths = tuple(root / name for name in research_job.SIMNOW_LAB_EXPORT_NAMES)
    for path in paths:
        path.write_bytes(b"old")
        path.chmod(0o644)
    original_replace = research_job._replace
    failed = False

    def interrupted(path: Path, raw: bytes) -> None:
        nonlocal failed
        if path == paths[1] and not failed:
            failed = True
            raise OSError("injected mid-pair interruption")
        original_replace(path, raw)

    monkeypatch.setattr(research_job, "_replace", interrupted)
    with pytest.raises(OSError, match="injected"):
        research_job._stage_and_publish_preopen_pair(
            root=root,
            monthly_paths=(paths[0], paths[1]),
            current=(b"old", b"old"),
            static_raw=static_raw,
            thermostat_raw=thermostat_raw,
        )
    monkeypatch.setattr(research_job, "_replace", original_replace)
    route_raw = b"route"
    monkeypatch.setattr(research_job, "_precompute_daily_route_export", lambda *_args: route_raw)
    monkeypatch.setattr(
        research_job,
        "_precompute_monthly_preopen_exports",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("rebuild")),
    )
    context = SimpleNamespace(calendar=calendar)
    research_job.export_simnow_lab_inputs(
        context=context,
        daily_result={"status": "OFFICIAL_DAY_COMPLETE", "trade_day": "2026-08-03"},
        history_receipt_path=tmp_path / "unused",
        operator_state=object(),
    )
    assert paths[0].read_bytes() == static_raw
    assert paths[1].read_bytes() == thermostat_raw
    assert paths[2].read_bytes() == route_raw
    assert not any(root.glob(".*preopen-pending*"))


def test_month_end_after_night_open_fails_without_recomputing_preopen(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calendar, _history, _daily, _registry = _monthly_preopen_inputs()
    root = tmp_path / "exports"
    root.mkdir(mode=0o755)
    monkeypatch.setattr(research_job, "SIMNOW_LAB_INPUT_DIRECTORY", root)
    monkeypatch.setattr(research_job, "_precompute_daily_route_export", lambda *_args: b"route")
    monkeypatch.setattr(
        research_job,
        "_precompute_monthly_preopen_exports",
        lambda *_args: (_ for _ in ()).throw(AssertionError("late preopen rebuild")),
    )

    with pytest.raises(research_job.RegistryError, match="MISSED_EXECUTION_OPEN"):
        research_job.export_simnow_lab_inputs(
            context=SimpleNamespace(calendar=calendar),
            daily_result={"status": "ALREADY_COMPLETE", "trade_day": "2026-07-31"},
            history_receipt_path=tmp_path / "unused",
            operator_state=object(),
            now=datetime.fromisoformat("2026-07-31T21:10:00+08:00"),
        )
    assert (root / research_job.SIMNOW_LAB_EXPORT_NAMES[2]).read_bytes() == b"route"
    assert not (root / research_job.SIMNOW_LAB_EXPORT_NAMES[0]).exists()
    assert not (root / research_job.SIMNOW_LAB_EXPORT_NAMES[1]).exists()


def test_noncompleted_daily_result_does_not_roll_history_or_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    context = SimpleNamespace(
        runtime=SimpleNamespace(root=Path("/unused")),
        paths=object(), registry=object(), calendar=object(),
        availability=object(), runtime_input=SimpleNamespace(
            payload={"collector_version": "test"}
        ),
    )
    monkeypatch.setattr(research_job, "load_runtime_context", lambda _path: context)
    monkeypatch.setattr(
        research_job,
        "PersistentRequestGate",
        lambda *_args, **_kwargs: SimpleNamespace(request=lambda **_kwargs: None),
    )
    monkeypatch.setattr(
        research_job, "query_trusted_clock", lambda: SimpleNamespace()
    )
    monkeypatch.setattr(
        research_job, "run_daily", lambda **_kwargs: {"status": "NO_OFFICIAL_DAY"}
    )
    monkeypatch.setattr(
        research_job, "run_history_backfill", lambda **_kwargs: calls.append("history")
    )
    monkeypatch.setattr(
        research_job, "export_simnow_lab_inputs", lambda **_kwargs: calls.append("export")
    )

    assert research_job.main([]) == 0
    assert calls == []


def test_completed_daily_result_without_trade_day_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    context = SimpleNamespace(
        runtime=SimpleNamespace(root=Path("/unused")),
        paths=object(), registry=object(), calendar=object(),
        availability=object(), runtime_input=SimpleNamespace(
            payload={"collector_version": "test"}
        ),
    )
    monkeypatch.setattr(research_job, "load_runtime_context", lambda _path: context)
    monkeypatch.setattr(
        research_job,
        "PersistentRequestGate",
        lambda *_args, **_kwargs: SimpleNamespace(request=lambda **_kwargs: None),
    )
    monkeypatch.setattr(
        research_job, "query_trusted_clock", lambda: SimpleNamespace()
    )
    monkeypatch.setattr(
        research_job,
        "run_daily",
        lambda **_kwargs: {"status": "OFFICIAL_DAY_COMPLETE"},
    )
    monkeypatch.setattr(
        research_job, "run_history_backfill", lambda **_kwargs: calls.append("history")
    )
    monkeypatch.setattr(
        research_job, "export_simnow_lab_inputs", lambda **_kwargs: calls.append("export")
    )

    assert research_job.main([]) == 2
    assert calls == []


@pytest.mark.parametrize("failure", ("history receipt failed", "route metadata failed"))
def test_research_export_publishes_daily_route_when_monthly_preopen_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    export_root = tmp_path / "exports"
    export_root.mkdir(mode=0o755)
    old = {}
    for name in research_job.SIMNOW_LAB_EXPORT_NAMES:
        path = export_root / name
        path.write_bytes(f"old-{name}".encode())
        path.chmod(0o644)
        old[name] = path.read_bytes()

    monkeypatch.setattr(research_job, "SIMNOW_LAB_INPUT_DIRECTORY", export_root)
    monkeypatch.setattr(
        research_job,
        "_precompute_monthly_preopen_exports",
        lambda *_args: (_ for _ in ()).throw(
            research_job.RegistryError(failure)
        ),
    )
    monkeypatch.setattr(
        research_job, "_precompute_daily_route_export", lambda *_args: b"fresh-route"
    )
    monkeypatch.setattr(
        research_job, "_preopen_source_month_for_completed_day", lambda *_args: "2030-01"
    )

    with pytest.raises(research_job.RegistryError, match=failure):
        research_job.export_simnow_lab_inputs(
            context=object(),
            daily_result={"status": "OFFICIAL_DAY_COMPLETE", "trade_day": "2030-01-31"},
            history_receipt_path=tmp_path / "history.json",
            operator_state=object(),
            now=datetime.fromisoformat("2030-01-31T19:00:00+08:00"),
        )

    assert (export_root / research_job.SIMNOW_LAB_EXPORT_NAMES[0]).read_bytes() == old[
        research_job.SIMNOW_LAB_EXPORT_NAMES[0]
    ]
    assert (export_root / research_job.SIMNOW_LAB_EXPORT_NAMES[1]).read_bytes() == old[
        research_job.SIMNOW_LAB_EXPORT_NAMES[1]
    ]
    assert (export_root / research_job.SIMNOW_LAB_EXPORT_NAMES[2]).read_bytes() == b"fresh-route"


def test_placeholder_bypass_cannot_admit_official_forward_baseline() -> None:
    with pytest.raises(pit_source.PitSourceViewError, match="placeholder baseline"):
        pit_source.build_source_view(
            calendar=None,
            calendar_anchor=None,
            history_receipt={},
            history_receipt_sha256="a" * 64,
            operator_state=None,
            daily_source_raw={},
            baseline_batch={"execution_lane": "official_forward"},
            business_public_key=Ed25519PublicKey.from_public_bytes(bytes(32)),
            expected_business_signer_key_id="simnow-lab-placeholder",
            source_month="2030-01",
            previous_snapshot=None,
            allow_simnow_placeholder_baseline=True,
        )


def test_shakedown_placeholder_baseline_builds_thermostat_source() -> None:
    calendar, history, daily_raw, key = pit_fixture._inputs()
    baseline = pit_fixture._signed_baseline(key)
    baseline["signature"] = pit_source.base64.b64encode(bytes(64)).decode("ascii")
    built = pit_source.build_source_view(
        calendar=calendar,
        calendar_anchor=pit_fixture._TestAnchor(),
        history_receipt=history,
        history_receipt_sha256="3" * 64,
        operator_state=pit_fixture._operator_state(),
        daily_source_raw=daily_raw,
        baseline_batch=baseline,
        business_public_key=key.public_key(),
        expected_business_signer_key_id=pit_fixture.SIGNER_KEY_ID,
        source_month="2026-07",
        previous_snapshot=None,
        allow_simnow_placeholder_baseline=True,
    )
    assert json.loads(built.source_view_raw)["baseline_batch"]["execution_lane"] == "simnow_shakedown"


def test_official_forward_bad_signature_still_uses_default_rejection() -> None:
    calendar, history, daily_raw, key = pit_fixture._inputs()
    baseline = pit_fixture._signed_baseline(key)
    baseline["execution_lane"] = "official_forward"
    with pytest.raises(pit_source.PitSourceViewError, match="signature is invalid"):
        pit_source.build_source_view(
            calendar=calendar,
            calendar_anchor=pit_fixture._TestAnchor(),
            history_receipt=history,
            history_receipt_sha256="3" * 64,
            operator_state=pit_fixture._operator_state(),
            daily_source_raw=daily_raw,
            baseline_batch=baseline,
            business_public_key=key.public_key(),
            expected_business_signer_key_id=pit_fixture.SIGNER_KEY_ID,
            source_month="2026-07",
            previous_snapshot=None,
        )


def test_daily_route_contains_exactly_ten_contracts(tmp_path: Path) -> None:
    inputs = daily_fixture._inputs()
    receipt = json.loads(inputs["run_receipt_raw"])
    parameter_raw = route_fixture._shfe_parameter_raw(
        query_day="2026-08-18", delivery="2610"
    )
    parameters = research_job.evidence_from_pinned_raw(
        observed_at="2026-08-19T01:00:00.000000Z",
        raw=parameter_raw,
        expected_raw_sha256=research_job.sha256(parameter_raw),
    )
    route = research_job._daily_route(
        context=route_fixture._context(tmp_path, inputs["calendar"]),
        trade_day="2026-08-18",
        receipt=receipt,
        receipt_raw=inputs["run_receipt_raw"],
        daily_raw=inputs["daily_source_raw"],
        registry_raw=inputs["contract_registry_raw"],
        parameters=parameters,
    )
    assert len(route["mains"]) == 10
    assert all(row["exact_contract"] for row in route["mains"])


def test_m5_rejects_stale_route_before_current_or_apply(tmp_path: Path) -> None:
    route = tmp_path / "route.json"
    route.write_text('{"metadata":{"execution_day":"2030-01-01"}}\n')

    with pytest.raises(m5.SimNowLabM5Error, match="stale"):
        m5.require_fresh_daily_route(
            route,
            now=datetime(2030, 1, 2, 9, 5, tzinfo=m5.SHANGHAI),
        )
    m5.require_fresh_daily_route(
        route,
        now=datetime(2030, 1, 1, 13, 35, tzinfo=m5.SHANGHAI),
    )
    m5.require_fresh_daily_route(
        route,
        now=datetime(2029, 12, 31, 21, 5, tzinfo=m5.SHANGHAI),
    )
