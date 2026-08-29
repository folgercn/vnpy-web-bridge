from __future__ import annotations

import importlib
import json
import stat
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
m5 = importlib.import_module("simnow_lab_m5_run_once")
research_job = importlib.import_module("research_warehouse.m2_scheduler_cli")
pit_source = importlib.import_module("research_warehouse.pit_source_view")
pit_fixture = importlib.import_module("test_research_warehouse_pit_source_view")
route_fixture = importlib.import_module("test_simnow_experimental_timely_daily_route")
daily_fixture = importlib.import_module("test_research_warehouse_daily_pit_main_roll_source")


def test_m5_produces_before_reusing_existing_run_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    thermostat = tmp_path / "thermostat.json"
    thermostat.write_text('{"source_month":"2030-01"}\n', encoding="utf-8")
    calls: list[object] = []

    def produce(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"status": "MATERIALIZED", "target_id": "a" * 64}

    monkeypatch.setattr(m5, "run_monthly_once", produce)
    monkeypatch.setattr(m5.lab_cli, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(m5, "require_fresh_daily_route", lambda _path: None)

    assert (
        m5.run_once(
            static_source=tmp_path / "static.json",
            thermostat_source=thermostat,
            daily_route=tmp_path / "route.json",
            monthly_bundles=tmp_path / "monthly",
            target=tmp_path / "target.json",
            lab_target=tmp_path / "lab-target.json",
        )
        == 0
    )
    assert calls[0]["source_month"] == "2030-01"
    assert calls[1] == [
        "run-once",
        "--input",
        str(tmp_path / "target.json"),
        "--output",
        str(tmp_path / "lab-target.json"),
    ]


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
    before = [path.stat().st_mtime_ns for path in paths]
    assert [path.read_bytes() for path in paths] == list(outputs)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o644 for path in paths)

    research_job.export_simnow_lab_inputs(
        context=object(), daily_result=result, history_receipt_path=history,
        operator_state=object(),
    )
    assert [path.stat().st_mtime_ns for path in paths] == before


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
def test_research_export_precomputes_all_inputs_before_replacing_old_files(
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
        "_precompute_exports",
        lambda *_args: (_ for _ in ()).throw(
            research_job.RegistryError(failure)
        ),
    )

    with pytest.raises(research_job.RegistryError, match=failure):
        research_job.export_simnow_lab_inputs(
            context=object(),
            daily_result={"status": "OFFICIAL_DAY_COMPLETE", "trade_day": "2030-01-31"},
            history_receipt_path=tmp_path / "history.json",
            operator_state=object(),
        )

    assert {
        name: (export_root / name).read_bytes()
        for name in research_job.SIMNOW_LAB_EXPORT_NAMES
    } == old


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
