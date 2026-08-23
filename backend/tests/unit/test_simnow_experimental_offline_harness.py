from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import simnow_experimental_offline_harness as harness  # noqa: E402
from test_simnow_experimental_target import _bundle, _raw, _target  # noqa: E402


def _assert_offline_envelope(result: dict, *, status: str) -> None:
    assert result["marker"] == "SIMNOW_EXPERIMENTAL_OFFLINE_TEST"
    assert result["disclaimers"] == [
        "OFFLINE TEST ONLY",
        "NOT REAL SIMNOW ACCEPTANCE",
    ]
    assert result["status"] == status
    assert {
        field: result[field]
        for field in (
            "production",
            "live_trading_authorized",
            "countable_forward",
            "official_forward_claimed",
            "execution_mutated",
            "gateway_mutated",
        )
    } == {
        "production": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "execution_mutated": False,
        "gateway_mutated": False,
    }


def test_offline_harness_exercises_all_planner_paths_without_real_clients() -> None:
    result = asyncio.run(
        harness.run_offline_harness(
            _target(_bundle()), _bundle(), expires_at="2099-01-01T00:00:00Z"
        )
    )

    _assert_offline_envelope(result, status="PASS")
    scenarios = {item["scenario"]: item for item in result["scenarios"]}
    assert scenarios["flat_to_open"]["result"]["phase"] == "OPEN"
    assert scenarios["same_target_noop"]["result"]["new_intents"] == 0
    for name in (
        "quantity_change_close_then_open",
        "direction_reversal_close_then_open",
        "exact_contract_change_close_then_open",
    ):
        assert scenarios[name]["close"]["phase"] == "CLOSE"
        assert scenarios[name]["post_close_open"]["phase"] == "OPEN"
    for name in (
        "active_blocks_new_mutation",
        "pending_blocks_new_mutation",
        "unknown_blocks_new_mutation",
    ):
        assert scenarios[name]["status"] == "STOP"


def test_offline_harness_cli_rejects_execute_and_emits_explicit_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle()
    target = _target(bundle)
    target_path = tmp_path / "target.json"
    bundle_path = tmp_path / "bundle.json"
    target_path.write_bytes(_raw(target))
    bundle_path.write_bytes(_raw(bundle))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "offline-harness",
            "--target",
            str(target_path),
            "--monthly-planner-bundle",
            str(bundle_path),
            "--expires-at",
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "--execute",
        ],
    )

    assert harness.main() == 2
    result = json.loads(capsys.readouterr().out)
    _assert_offline_envelope(result, status="STOP")
    assert result["error"] == "--execute is forbidden"


def test_offline_harness_cli_runs_one_shot_with_only_local_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle()
    target = _target(bundle)
    target_path = tmp_path / "target.json"
    bundle_path = tmp_path / "bundle.json"
    target_path.write_bytes(_raw(target))
    bundle_path.write_bytes(_raw(bundle))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "offline-harness",
            "--target",
            str(target_path),
            "--monthly-planner-bundle",
            str(bundle_path),
            "--expires-at",
            "2099-01-01T00:00:00Z",
        ],
    )

    assert harness.main() == 0
    result = json.loads(capsys.readouterr().out)
    _assert_offline_envelope(result, status="PASS")


def test_offline_harness_cli_read_validation_and_preview_stops_keep_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle()
    target = _target(bundle)
    target_path = tmp_path / "target.json"
    bundle_path = tmp_path / "bundle.json"
    target_path.write_bytes(_raw(target))
    bundle_path.write_bytes(_raw(bundle))

    def run(*, target_argument: Path, bundle_argument: Path) -> dict:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "offline-harness",
                "--target",
                str(target_argument),
                "--monthly-planner-bundle",
                str(bundle_argument),
                "--expires-at",
                "2099-01-01T00:00:00Z",
            ],
        )
        assert harness.main() == 1
        return json.loads(capsys.readouterr().out)

    _assert_offline_envelope(
        run(target_argument=tmp_path / "missing.json", bundle_argument=bundle_path),
        status="STOP",
    )
    target_path.write_bytes(b"{}\n")
    _assert_offline_envelope(
        run(target_argument=target_path, bundle_argument=bundle_path), status="STOP"
    )
    target_path.write_bytes(_raw(target))

    async def preview_error(*_args, **_kwargs) -> dict:
        raise harness.ExperimentalRunError("synthetic preview unavailable")

    monkeypatch.setattr(harness, "_preview", preview_error)
    _assert_offline_envelope(
        run(target_argument=target_path, bundle_argument=bundle_path), status="STOP"
    )


def test_offline_harness_does_not_construct_the_real_execution_client() -> None:
    source = (ROOT / "scripts/simnow_experimental_offline_harness.py").read_text(
        encoding="utf-8"
    )
    assert "ExecutionClient" not in source
    assert "read_simnow_continuous_v3_formal_tick_bindings" not in source
    assert "SIMNOW_EXPERIMENTAL_OFFLINE_TEST" in source
