from __future__ import annotations

import importlib
import stat
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
m5 = importlib.import_module("simnow_lab_m5_run_once")
research_job = importlib.import_module("research_warehouse.m2_scheduler_cli")


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
    research_job.export_simnow_lab_inputs(context=object(), daily_result=result)
    paths = [
        research_job.SIMNOW_LAB_INPUT_DIRECTORY / name
        for name in research_job.SIMNOW_LAB_EXPORT_NAMES
    ]
    before = [path.stat().st_mtime_ns for path in paths]
    assert [path.read_bytes() for path in paths] == list(outputs)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o644 for path in paths)

    research_job.export_simnow_lab_inputs(context=object(), daily_result=result)
    assert [path.stat().st_mtime_ns for path in paths] == before


def test_research_export_precomputes_all_inputs_before_replacing_old_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
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
            research_job.RegistryError("route failed")
        ),
    )

    with pytest.raises(research_job.RegistryError, match="route failed"):
        research_job.export_simnow_lab_inputs(
            context=object(),
            daily_result={"status": "OFFICIAL_DAY_COMPLETE", "trade_day": "2030-01-31"},
        )

    assert {
        name: (export_root / name).read_bytes()
        for name in research_job.SIMNOW_LAB_EXPORT_NAMES
    } == old


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
