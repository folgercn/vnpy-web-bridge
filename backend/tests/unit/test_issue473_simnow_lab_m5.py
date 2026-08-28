from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
m5 = importlib.import_module("simnow_lab_m5_run_once")


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

    assert m5.run_once(
        static_source=tmp_path / "static.json",
        thermostat_source=thermostat,
        daily_route=tmp_path / "route.json",
        monthly_bundles=tmp_path / "monthly",
        target=tmp_path / "target.json",
        lab_target=tmp_path / "lab-target.json",
    ) == 0
    assert calls[0]["source_month"] == "2030-01"
    assert calls[1] == ["run-once", "--input", str(tmp_path / "target.json"), "--output", str(tmp_path / "lab-target.json")]


def test_m5_invalid_producer_input_stops_before_materialize_or_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"last-valid-target\n")
    calls: list[str] = []
    monkeypatch.setattr(m5, "run_monthly_once", lambda **_kwargs: calls.append("materialize"))
    monkeypatch.setattr(m5.lab_cli, "main", lambda _args: calls.append("apply") or 0)

    assert m5.main(["--thermostat-source", str(tmp_path / "missing.json"), "--target", str(target)]) == 1
    assert calls == []
    assert target.read_bytes() == b"last-valid-target\n"


def test_m5_launch_agent_has_one_calendar_runner_without_target_watch() -> None:
    raw = (ROOT / "deployments/com.vnpy-web-bridge.simnow-lab.plist").read_text(encoding="utf-8")
    assert "scripts.simnow_lab_m5_run_once" in raw
    assert "WatchPaths" not in raw
    assert raw.count("<key>Weekday</key>") == 15
