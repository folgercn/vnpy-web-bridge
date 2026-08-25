from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import simnow_execution_path_offline_harness as harness  # noqa: E402
from test_simnow_experimental_target import (  # noqa: E402
    _bundle,
    _raw,
    _route,
    _target,
)


def _normal_181_bundle() -> dict:
    """A valid monthly normal vector whose existing planner emits 181 lots."""

    bundle = _bundle()
    for row in bundle["position_manager_snapshot"]["targets"]:
        if row["product"] == "al":
            row["shadow_target_quantity"] += 20
            break
    else:  # pragma: no cover - fixed valid fixture contract
        raise AssertionError("monthly normal fixture lacks al")
    return bundle


def _assert_offline(result: dict, *, status: str) -> None:
    assert result["marker"] == harness.OFFLINE_TEST_MARKER
    assert result["status"] == status
    assert result["production"] is False
    assert result["live_trading_authorized"] is False
    assert result["countable_forward"] is False
    assert result["official_forward_claimed"] is False
    assert result["execution_mutated"] is False
    assert result["gateway_mutated"] is False


def test_offline_path_exercises_fresh_versions_and_real_start_proof() -> None:
    bundle = _bundle()
    route = _route(bundle)
    target = _target(bundle)

    result = asyncio.run(
        harness.run_execution_path_harness(
            target,
            bundle,
            expires_at="2099-01-01T00:00:00Z",
            expected_intents=161,
            checkpoint_churn=2,
            checkpoint_retry_seconds=0.2,
            observed_start_latency_seconds=0.5,
            daily_route=route,
            planner_bundle_raw=_raw(bundle),
            daily_route_raw=_raw(route),
        )
    )

    _assert_offline(result, status="PASS")
    assert result["intent_count"] == 161
    assert result["strict_checkpoint"] == {
        "deadline_seconds": 1.0,
        "attempts": 3,
        "elapsed_seconds": 0.4,
        "status": "PASS",
    }
    versions = {row["operation"]: row for row in result["state_version_trace"]}
    assert versions["preview"]["sent_state_version"] == 4
    assert versions["start"]["sent_state_version"] == 8
    assert all(
        row["start_quote_proof_state"] == "READY"
        for row in result["timing_budget"]["scenarios"]
    )


def test_offline_path_turns_exact_price_churn_into_stop_without_mutation() -> None:
    bundle = _bundle()
    target = _target(bundle)

    result = asyncio.run(
        harness.run_execution_path_harness(
            target,
            bundle,
            expires_at="2099-01-01T00:00:00Z",
            expected_intents=161,
            observed_start_latency_seconds=5.0,
        )
    )

    _assert_offline(result, status="STOP")
    assert result["timing_budget"]["replan_required_change_seconds"] == [
        1.0,
        2.0,
        3.0,
        5.0,
    ]
    assert {
        row["start_quote_proof_state"] for row in result["timing_budget"]["scenarios"]
    } == {"REPLAN_REQUIRED"}
    assert "start" not in {row["operation"] for row in result["state_version_trace"]}


def test_normal_181_intent_fixture_uses_legal_monthly_bundle_and_stops_before_start() -> (
    None
):
    bundle = _normal_181_bundle()
    target = _target(bundle)

    result = asyncio.run(
        harness.run_execution_path_harness(
            target,
            bundle,
            expires_at="2099-01-01T00:00:00Z",
            expected_intents=181,
            observed_start_latency_seconds=5.0,
        )
    )

    _assert_offline(result, status="STOP")
    assert "target_mode" not in target
    assert result["intent_count"] == 181
    assert "start" not in {row["operation"] for row in result["state_version_trace"]}


def test_two_second_start_latency_has_mixed_exact_price_churn_result() -> None:
    bundle = _normal_181_bundle()

    result = asyncio.run(
        harness.run_execution_path_harness(
            _target(bundle),
            bundle,
            expires_at="2099-01-01T00:00:00Z",
            expected_intents=181,
            observed_start_latency_seconds=2.5,
        )
    )

    _assert_offline(result, status="STOP")
    assert result["timing_budget"]["scenarios"] == [
        {"quote_change_at_seconds": 1.0, "start_quote_proof_state": "REPLAN_REQUIRED"},
        {"quote_change_at_seconds": 2.0, "start_quote_proof_state": "REPLAN_REQUIRED"},
        {"quote_change_at_seconds": 3.0, "start_quote_proof_state": "READY"},
        {"quote_change_at_seconds": 5.0, "start_quote_proof_state": "READY"},
    ]


def test_offline_path_keeps_original_one_second_strict_checkpoint_deadline() -> None:
    result = asyncio.run(
        harness.run_execution_path_harness(
            _target(),
            _bundle(),
            expires_at="2099-01-01T00:00:00Z",
            expected_intents=161,
            checkpoint_churn=5,
            checkpoint_retry_seconds=0.25,
        )
    )

    _assert_offline(result, status="STOP")
    assert (
        result["reason"]
        == "strict checkpoint churn exceeded original one-second deadline"
    )
    assert result["strict_checkpoint"]["deadline_seconds"] == 1.0
    assert result["strict_checkpoint"]["elapsed_seconds"] > 1.0


def test_cli_rejects_execute_and_never_needs_remote_inputs(
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
            "execution-path-offline-harness",
            "--target",
            str(target_path),
            "--monthly-planner-bundle",
            str(bundle_path),
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--execute",
        ],
    )

    assert harness.main() == 2
    result = json.loads(capsys.readouterr().out)
    _assert_offline(result, status="STOP")
    assert result["reason"] == "--execute is forbidden"


def test_harness_source_has_no_real_execution_or_formal_journal_client() -> None:
    source = (ROOT / "scripts/simnow_execution_path_offline_harness.py").read_text(
        encoding="utf-8"
    )
    assert "ExecutionClient" not in source
    assert "read_simnow_continuous_v3_formal_tick_bindings" not in source
    assert "SIMNOW_EXPERIMENTAL_EXECUTION_PATH_OFFLINE_TEST" in source
