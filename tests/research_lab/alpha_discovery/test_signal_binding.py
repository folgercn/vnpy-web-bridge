"""Unit and Contract Tests for Deterministic Signal Binding and PIT Precheck (#502 Stage 2).

Verifies:
- Hand-computable fixtures for two distinct definitions (k=1 momentum vs k=2 reversal).
- Deterministic repeat stability (identical bit-for-bit SHA256 and byte length).
- Fail-closed negative cases:
  1. Unknown formula (e.g., rsi, ts_mean, rolling_vwap)
  2. Missing required fields / unsupported source features (e.g., volume, open_interest, high, low)
  3. Wrong parameter binding (lookback k mismatch, direction mismatch)
  4. Cross-contract window bleeding (RB vs HC isolation)
  5. Insufficient history window (less than k + 3 days)
  6. Target misalignment / lookahead
  7. Future data leakage (temporal order violations: first_seen > as_of or as_of >= next_first_seen)
- Integration orchestrator blocks invalid candidate before Critic/Memory.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

from research_lab.agent_control.alpha_generator import AlphaGenerationCandidate
from research_lab.agent_control.contracts import ProjectBinding
from research_lab.agent_control.discovery_integration import (
    DiscoveryIntegrationOrchestrator,
    EngineeringStatus,
    recover_round_execution_timing,
)
from research_lab.alpha_discovery import (
    AlphaDiscoveryEngine,
    AlphaHypothesis,
    ResearchMemory,
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
)
from research_lab.alpha_discovery.signal_binding import (
    CANONICAL_TARGET_DEFINITION,
    SignalBindingError,
    SyntheticTestEvidence,
    derive_signal_snapshot,
    parse_and_verify_signal_spec,
    parse_strict_trade_day,
    parse_strict_utc_iso8601,
    precheck_candidate_real_data,
    verify_derived_snapshot_pit,
)
from research_lab.config import ResearchLabConfig
from research_lab.database.result_store import ResultStore

TEST_SYNTHETIC_EVIDENCE = SyntheticTestEvidence(
    fixture_id="synthetic-offline-test-fixture-v1",
    description="Authorized offline unit test evidence",
)


def _build_synthetic_source_days() -> list[dict[str, Any]]:
    """Build a 7-day hand-computable synthetic dataset for RB2701 and HC2701.

    RB2701 price increases by exactly 1% every day:
    S_t / S_{t-1} = 1.01 => log return = ln(1.01) ~ 0.009950330853168083.
    HC2701 price changes irregularly to verify cross-contract isolation.
    """
    days = [
        "2026-09-01",
        "2026-09-02",
        "2026-09-03",
        "2026-09-04",
        "2026-09-07",
        "2026-09-08",
        "2026-09-09",
    ]
    # RB starts at 3000, grows 1% each day
    rb_prices = [3000.0 * (1.01**i) for i in range(len(days))]
    # HC fluctuates independently
    hc_prices = [3200.0, 3168.0, 3200.0, 3168.0, 3136.32, 3104.9568, 3073.907232]

    source_days = []
    for i, d in enumerate(days):
        raw_b = f"raw-{d}".encode("utf-8")
        seal_b = f"seal-{d}".encode("utf-8")
        source_days.append(
            {
                "day": d,
                "first_seen_at": f"{d}T10:30:00.000000Z",
                "committed_at": f"{d}T10:40:00.000000Z",
                "market_effective_time": f"{d}T15:00:00.000000Z",
                "market_time_authority": "SYNTHETIC_TEST_FIXTURE",
                "raw_sha256": hashlib.sha256(raw_b).hexdigest(),
                "raw_bytes": len(raw_b),
                "raw_relative_path": f"raw/shfe/{d}/data.raw",
                "batch_seal_sha256": hashlib.sha256(seal_b).hexdigest(),
                "settlement": {
                    "rb_f": rb_prices[i],
                    "hc_f": hc_prices[i],
                },
            }
        )
    return source_days


def _build_synthetic_provenance_file(
    base_dir: Path, source_days: list[dict[str, Any]] | None = None
) -> tuple[Path, str]:
    if source_days is None:
        source_days = _build_synthetic_source_days()
    prov_dir = base_dir / "provenance"
    prov_dir.mkdir(parents=True, exist_ok=True)
    prov_file = prov_dir / "test-provenance.json"
    prov_payload = {
        "schema": "issue502.real-research-snapshot.v1",
        "source_days": source_days,
        "limitations": ["Test synthetic dataset"],
    }
    raw_b = json.dumps(prov_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    prov_file.write_bytes(raw_b)
    sha = hashlib.sha256(raw_b).hexdigest()
    return prov_file, sha


def _build_valid_hypothesis(
    *,
    family: str = "momentum",
    definition: str = "log(settlement[t] / settlement[t-1])",
    direction: str = "positive",
    symbol: str = "RB2701",
    target: str = CANONICAL_TARGET_DEFINITION,
    features: tuple[str, ...] = ("settlement",),
) -> dict[str, Any]:
    hyp = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": "hyp-test-binding-001",
        "revision": "rev.1",
        "title": f"Test {family} {symbol}",
        "economic_rationale": "Settlement price momentum based on daily inventory carry.",
        "signal_family": family,
        "signal_definition": definition,
        "source_features": list(features),
        "target": target,
        "expected_direction": direction,
        "holding_horizon": "1d",
        "universe": symbol,
        "frequency": "1d",
        "known_risks": ["Thin market liquidity", "Holiday gap risk"],
        "falsification_conditions": ["Feature correlation drops below zero"],
        "proposed_screening_methods": [
            "coverage",
            "simple_correlation",
            "direction_consistency",
            "leakage_audit",
        ],
        "provenance": {
            "origin_type": "astra",
            "origin_ref": "slot-001",
            "created_by": "researcher",
            "created_at": "2026-09-29T12:00:00.000000Z",
        },
    }
    hyp["hypothesis_content_hash"] = compute_hypothesis_content_hash(hyp)
    return hyp


# =========================================================================
# 1. Hand-computable Fixtures for Two Distinct Definitions
# =========================================================================


def test_hand_computed_fixture_two_different_definitions(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)
    expected_step_return = math.log(1.01)  # ~ 0.009950330853168083

    # Definition A: k=1 Momentum on RB2701
    hyp_a = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    spec_a = parse_and_verify_signal_spec(hyp_a)
    assert spec_a.formula_id == "log_settlement_momentum_k1"
    assert spec_a.lookback_k == 1
    assert spec_a.symbol == "RB2701"
    assert not spec_a.is_negated

    res_a = derive_signal_snapshot(
        spec_a,
        source_days,
        tmp_path / "def_a",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    # For 7 days and k=1: observation indices are i = 1, 2, 3, 4 (4 rows)
    assert res_a.row_count == 4
    pit_a = verify_derived_snapshot_pit(res_a.path)
    assert len(pit_a) == 4
    for r in pit_a:
        assert r.temporal_order_valid is True
        assert r.target_non_overlapping is True
        # For RB2701, feature_val must equal expected_step_return
        f_val = float(r.feature_val)
        t_val = float(r.target_val)
        assert pytest.approx(f_val, rel=1e-12) == expected_step_return
        assert pytest.approx(t_val, rel=1e-12) == expected_step_return

    # Definition B: k=2 Reversal on RB2701 (-log(settlement[t] / settlement[t-2]))
    hyp_b = _build_valid_hypothesis(
        family="reversal",
        definition="-log(settlement[t] / settlement[t-2])",
        direction="positive",
        symbol="RB2701",
    )
    spec_b = parse_and_verify_signal_spec(hyp_b)
    assert spec_b.formula_id == "log_settlement_reversal_neg_k2"
    assert spec_b.lookback_k == 2
    assert spec_b.symbol == "RB2701"
    assert spec_b.is_negated is True

    res_b = derive_signal_snapshot(
        spec_b,
        source_days,
        tmp_path / "def_b",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    # For 7 days and k=2: observation indices are i = 2, 3, 4 (3 rows)
    assert res_b.row_count == 3
    pit_b = verify_derived_snapshot_pit(res_b.path)
    assert len(pit_b) == 3
    expected_k2_rev = -math.log(1.01**2)  # -2 * ln(1.01)
    for r in pit_b:
        assert r.temporal_order_valid is True
        assert r.target_non_overlapping is True
        f_val = float(r.feature_val)
        t_val = float(r.target_val)
        assert pytest.approx(f_val, rel=1e-12) == expected_k2_rev
        assert pytest.approx(t_val, rel=1e-12) == expected_step_return


# =========================================================================
# 2. Deterministic Repeat Stability
# =========================================================================


def test_deterministic_repeat_stability(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)
    hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    spec = parse_and_verify_signal_spec(hyp)

    res_run1 = derive_signal_snapshot(
        spec,
        source_days,
        tmp_path / "run1",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    res_run2 = derive_signal_snapshot(
        spec,
        source_days,
        tmp_path / "run2",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )

    # Bit-for-bit identical snapshot SHA256 and byte length across different dirs
    assert res_run1.sha256 == res_run2.sha256
    assert res_run1.byte_length == res_run2.byte_length
    assert res_run1.row_count == res_run2.row_count
    assert res_run1.path.read_bytes() == res_run2.path.read_bytes()

    # Repeating into the exact same directory/filename must fail closed and never overwrite
    before_csv_bytes = res_run1.path.read_bytes()
    before_meta_bytes = res_run1.metadata_path.read_bytes()
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec,
            source_days,
            tmp_path / "run1",
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "SNAPSHOT_ALREADY_EXISTS"
    assert res_run1.path.read_bytes() == before_csv_bytes
    assert res_run1.metadata_path.read_bytes() == before_meta_bytes


def test_derive_signal_snapshot_and_precheck_reject_overwrite_existing_files(tmp_path: Path) -> None:
    """Ensure derive_signal_snapshot and precheck_candidate_real_data never overwrite existing files."""
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)

    hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    spec = parse_and_verify_signal_spec(hyp)

    # 1. Pre-existing metadata file alone blocks derive_signal_snapshot before writing CSV
    meta_only_dir = tmp_path / "meta_only"
    meta_only_dir.mkdir(parents=True, exist_ok=True)
    existing_meta = meta_only_dir / f"snapshot_{spec.symbol.lower()}_{spec.formula_id}.binding.json"
    existing_meta.write_text('{"sentinel": true}', encoding="utf-8")
    with pytest.raises(SignalBindingError) as exc_meta:
        derive_signal_snapshot(
            spec,
            source_days,
            meta_only_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_meta.value.reason == "SNAPSHOT_ALREADY_EXISTS"
    assert existing_meta.read_text(encoding="utf-8") == '{"sentinel": true}'
    assert not (meta_only_dir / f"snapshot_{spec.symbol.lower()}_{spec.formula_id}.csv").exists()

    # 2. precheck_candidate_real_data rejects second invocation on same output_dir
    precheck_dir = tmp_path / "precheck_once"
    rep1 = precheck_candidate_real_data(
        candidate=hyp,
        provenance_path=prov_file,
        output_dir=precheck_dir,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    report_path = Path(rep1["report_path"])
    snap_path = Path(rep1["derived_snapshot"]["path"])
    before_rep = report_path.read_bytes()
    before_snap = snap_path.read_bytes()

    with pytest.raises(SignalBindingError) as exc_pre:
        precheck_candidate_real_data(
            candidate=hyp,
            provenance_path=prov_file,
            output_dir=precheck_dir,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_pre.value.reason == "SNAPSHOT_ALREADY_EXISTS"
    assert report_path.read_bytes() == before_rep
    assert snap_path.read_bytes() == before_snap


# =========================================================================
# 3. Fail-Closed Negative Tests
# =========================================================================


def test_negative_unknown_formula() -> None:
    # 1. Unknown indicator formulas
    for bad_def in [
        "rsi(close, 14)",
        "ts_mean(volume, 5)",
        "rolling_std(settlement, 10)",
        "close - open",
    ]:
        hyp = _build_valid_hypothesis(family="momentum", definition=bad_def)
        with pytest.raises(SignalBindingError) as exc_info:
            parse_and_verify_signal_spec(hyp)
        assert exc_info.value.reason == "UNSUPPORTED_FORMULA"


def test_negative_missing_or_unsupported_features() -> None:
    # Requesting non-existent multi-column features (volume, open_interest, etc.)
    hyp = _build_valid_hypothesis(features=("volume", "settlement"))
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp)
    assert exc_info.value.reason == "UNSUPPORTED_SOURCE_FEATURES"

    # Empty source features
    hyp_empty = _build_valid_hypothesis()
    hyp_empty["source_features"] = []
    hyp_empty["hypothesis_content_hash"] = compute_hypothesis_content_hash(hyp_empty)
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_empty)
    assert exc_info.value.reason in ("MISSING_SOURCE_FEATURES", "HYPOTHESIS_VALIDATION_FAILED")


def test_negative_parameter_and_direction_mismatch() -> None:
    # Lookback k outside 1..3
    hyp_k5 = _build_valid_hypothesis(definition="log(settlement[t] / settlement[t-5])")
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_k5)
    assert exc_info.value.reason == "UNSUPPORTED_FORMULA"

    # Momentum with negative expected_direction (unsupported by screening runner)
    hyp_dir_mismatch = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="negative",
    )
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_dir_mismatch)
    assert exc_info.value.reason == "UNSUPPORTED_EXPECTED_DIRECTION"

    # Explicit negated reversal with negative expected_direction (unsupported)
    hyp_rev_mismatch = _build_valid_hypothesis(
        family="reversal",
        definition="-log(settlement[t] / settlement[t-1])",
        direction="negative",
    )
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_rev_mismatch)
    assert exc_info.value.reason == "UNSUPPORTED_EXPECTED_DIRECTION"

    # Un-negated reversal with positive expected_direction lacks negation or inverted ratio
    hyp_rev_unnegated = _build_valid_hypothesis(
        family="reversal",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
    )
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_rev_unnegated)
    assert exc_info.value.reason == "UNSUPPORTED_REVERSAL_REPRESENTATION"


def test_negative_cross_contract_window_bleeding(tmp_path: Path) -> None:
    # Verify that RB2701 derivation strictly uses rb_f and HC2701 strictly uses hc_f
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)

    # Modify HC prices so that if bleeding occurred, it would be mathematically noticeable
    hyp_rb = _build_valid_hypothesis(symbol="RB2701")
    spec_rb = parse_and_verify_signal_spec(hyp_rb)
    res_rb = derive_signal_snapshot(
        spec_rb,
        source_days,
        tmp_path / "rb_iso",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )

    hyp_hc = _build_valid_hypothesis(symbol="HC2701")
    spec_hc = parse_and_verify_signal_spec(hyp_hc)
    res_hc = derive_signal_snapshot(
        spec_hc,
        source_days,
        tmp_path / "hc_iso",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )

    rb_text = res_rb.path.read_text(encoding="utf-8")
    hc_text = res_hc.path.read_text(encoding="utf-8")

    # In RB snapshot, all symbol entries are strictly RB2701
    assert "HC2701" not in rb_text
    # In HC snapshot, all symbol entries are strictly HC2701
    assert "RB2701" not in hc_text

    # Cross-product symbol not supported
    hyp_cu = _build_valid_hypothesis(symbol="CU2701")
    with pytest.raises(SignalBindingError) as exc_info:
        parse_and_verify_signal_spec(hyp_cu)
    assert exc_info.value.reason == "UNSUPPORTED_UNIVERSE"


def test_negative_insufficient_history_window(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()
    # For k=2, min_history_required is 2 + 3 = 5 days.
    # Provide only 4 days:
    truncated_days = source_days[:4]
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, truncated_days)
    hyp_k2 = _build_valid_hypothesis(
        family="reversal",
        definition="-log(settlement[t] / settlement[t-2])",
        direction="positive",
    )
    spec_k2 = parse_and_verify_signal_spec(hyp_k2)
    assert spec_k2.min_history_required == 5

    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec_k2,
            truncated_days,
            tmp_path / "trunc",
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "INSUFFICIENT_HISTORY_WINDOW"


def test_negative_target_misalignment() -> None:
    # Target defined as contemporaneous or backward looking
    for bad_target in [
        "log(settlement[t] / settlement[t-1])",
        "log(settlement[t+1] / settlement[t])",
        "close[t+1] - close[t]",
    ]:
        hyp = _build_valid_hypothesis(target=bad_target)
        with pytest.raises(SignalBindingError) as exc_info:
            parse_and_verify_signal_spec(hyp)
        assert exc_info.value.reason == "UNSUPPORTED_TARGET"


def test_negative_future_data_leakage(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()

    # Leakage 1: feature_availability_time > as_of_time
    leaked_days_1 = copy.deepcopy(source_days)
    leaked_days_1[1]["first_seen_at"] = "2026-09-02T10:45:00.000000Z"
    leaked_days_1[1]["committed_at"] = "2026-09-02T10:40:00.000000Z"
    prov_file1, prov_sha1 = _build_synthetic_provenance_file(tmp_path / "t1", leaked_days_1)

    spec = parse_and_verify_signal_spec(_build_valid_hypothesis())
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec,
            leaked_days_1,
            tmp_path / "leak1",
            provenance_path=prov_file1,
            provenance_sha256=prov_sha1,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "TEMPORAL_ORDER_VIOLATION"

    # Leakage 2: as_of_time >= target_start_time (target overlap)
    leaked_days_2 = copy.deepcopy(source_days)
    leaked_days_2[1]["committed_at"] = "2026-09-03T15:30:00.000000Z"  # after day 2 market_effective_time (15:00)
    prov_file2, prov_sha2 = _build_synthetic_provenance_file(tmp_path / "t2", leaked_days_2)

    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec,
            leaked_days_2,
            tmp_path / "leak2",
            provenance_path=prov_file2,
            provenance_sha256=prov_sha2,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "TARGET_OVERLAP_VIOLATION"


# =========================================================================
# 4. Integration Orchestrator Fail-Closed Boundary
# =========================================================================


def test_discovery_integration_blocks_invalid_candidate(tmp_path: Path) -> None:
    root_dir = tmp_path / "research_root"
    store = ResultStore(ResearchLabConfig(root_dir))
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "eng_out")
    orchestrator = DiscoveryIntegrationOrchestrator(engine)

    # Candidate with unsupported features (like Astra generated volume + ATR)
    invalid_hyp = _build_valid_hypothesis(
        family="momentum",
        definition="rolling_mean(volume, 5)",
        features=("volume", "atr"),
    )

    clean_snapshot = tmp_path / "dummy.csv"
    clean_snapshot.write_text("timestamp,symbol,feature_val,target_val\n", encoding="utf-8")

    pb = ProjectBinding(
        project_id="test_project",
        workspace_identity="test_workspace",
    )

    hyp_model = AlphaHypothesis.model_validate(invalid_hyp)

    res = orchestrator.integrate_candidate(
        hyp_model,
        snapshot_path=clean_snapshot,
        project_binding=pb,
    )

    # Must be fail-closed: engineering_status=ADMISSION_FAILED, scientific_decision=None
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert "UNSUPPORTED" in (res.error_code or "")
    # Memory must NOT record false REJECT
    records = memory.find_by_hypothesis_id(invalid_hyp["hypothesis_id"])
    assert len(records) == 0


def test_precheck_candidate_real_data_synthetic(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()
    prov_file = tmp_path / "test-provenance.json"
    prov_payload = {
        "schema": "issue502.real-research-snapshot.v1",
        "source_days": source_days,
        "limitations": ["Test limitations disclosure"],
    }
    prov_file.write_text(json.dumps(prov_payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )

    out_dir = tmp_path / "precheck_out"
    report = precheck_candidate_real_data(
        candidate=hyp,
        provenance_path=prov_file,
        output_dir=out_dir,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )

    assert report["precheck_status"] == "PRECHECK_PASS"
    assert report["derived_snapshot"]["row_count"] == 4
    assert report["pit_verification"]["all_temporal_order_valid"] is True
    assert report["pit_verification"]["all_target_non_overlapping"] is True
    assert Path(report["report_path"]).exists()


def test_discovery_integration_passes_valid_candidate_with_derived_snapshot(tmp_path: Path) -> None:
    root_dir = tmp_path / "research_root"
    store = ResultStore(ResearchLabConfig(root_dir))
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "eng_out")
    orchestrator = DiscoveryIntegrationOrchestrator(
        engine, synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE
    )

    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)
    valid_hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    hyp_model = AlphaHypothesis.model_validate(valid_hyp)

    pb = ProjectBinding(
        project_id="test_project",
        workspace_identity="test_workspace",
    )

    dummy_raw_path = tmp_path / "raw_placeholder.csv"
    dummy_raw_path.write_text("raw\n", encoding="utf-8")

    res = orchestrator.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_raw_path,
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": source_days,
        },
        project_binding=pb,
    )

    assert res.engineering_status == EngineeringStatus.COMPLETED.value
    assert res.scientific_decision in ("NEED_MORE_EVIDENCE", "PROMOTE", "REJECT")
    assert res.error_code is None
    # Verified memory record was appended
    records = memory.find_by_hypothesis_id(valid_hyp["hypothesis_id"])
    assert len(records) == 1
    assert records[0].record_type == "evaluation"
    assert records[0].decision in ("NEED_MORE_EVIDENCE", "PROMOTE", "REJECT")


# =========================================================================
# 5. Stage 2 Prompt Whitelist & Fail-Closed Integration Tests
# =========================================================================


def test_alpha_generator_prompt_contains_stage2_whitelist() -> None:
    from research_lab.agent_control.alpha_generator import (
        PROMPT_POLICY_VERSION,
        STAGE2_PROMPT_POLICY_VERSION,
        AlphaGenerationRequest,
        build_alpha_generation_prompt,
    )
    from research_lab.agent_control.memory_view import ResearchMemoryView
    from research_lab.agent_control.router import authorize

    binding = ProjectBinding(project_id="test", workspace_identity="/tmp/test")
    scope = authorize("alpha_generator", ["read_research_memory", "create_hypothesis"], binding)
    view = ResearchMemoryView(
        view_id="memview-test",
        view_content_hash="a" * 64,
        role="alpha_generator",
        project_binding=binding.to_dict(),
        categories=("research_gaps",),
        entries_by_category={"research_gaps": ()},
        total_entries=0,
        policy_version="research_memory_view.v1",
        generated_at="2026-09-29T12:00:00.000000Z",
        source_refs=(),
    )

    # 1. Stage 2 policy explicitly includes whitelist
    req_stage2 = AlphaGenerationRequest.create(
        objective="Stage 2 daily settlement alpha generation",
        memory_view=view,
        project_binding=binding,
        authorized_scope=scope,
        generation_policy_version=STAGE2_PROMPT_POLICY_VERSION,
    )
    prompt_stage2 = build_alpha_generation_prompt(req_stage2, view)

    assert "STAGE 2 SETTLEMENT-ONLY SIGNAL WHITELIST" in prompt_stage2
    assert "'RB2701' or 'HC2701'" in prompt_stage2
    assert "strictly ['settlement']" in prompt_stage2
    assert "log(settlement[t+2] / settlement[t+1])" in prompt_stage2
    assert "volume, open_interest, high, low, open, close, ATR, vwap, spread" in prompt_stage2
    assert "log(settlement[t] / settlement[t-1])" in prompt_stage2
    assert "log(settlement[t] / settlement[t-2])" in prompt_stage2
    assert "log(settlement[t] / settlement[t-3])" in prompt_stage2
    assert "-log(settlement[t] / settlement[t-1])" in prompt_stage2
    assert "-log(settlement[t] / settlement[t-2])" in prompt_stage2
    assert "-log(settlement[t] / settlement[t-3])" in prompt_stage2

    # 2. Default policy does NOT contain the Stage 2 whitelist
    req_default = AlphaGenerationRequest.create(
        objective="Standard alpha generation",
        memory_view=view,
        project_binding=binding,
        authorized_scope=scope,
        generation_policy_version=PROMPT_POLICY_VERSION,
    )
    prompt_default = build_alpha_generation_prompt(req_default, view)
    assert "STAGE 2 SETTLEMENT-ONLY SIGNAL WHITELIST" not in prompt_default


def test_discovery_integration_rejects_missing_raw_source(tmp_path: Path) -> None:
    root_dir = tmp_path / "research_root"
    store = ResultStore(ResearchLabConfig(root_dir))
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "eng_out")
    orchestrator = DiscoveryIntegrationOrchestrator(engine)

    valid_hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    hyp_model = AlphaHypothesis.model_validate(valid_hyp)
    pb = ProjectBinding(project_id="test_proj", workspace_identity="test_ws")

    dummy_csv = tmp_path / "dummy.csv"
    dummy_csv.write_text("dummy\n", encoding="utf-8")

    # Missing provenance_path and provenance_sha256 in dataset_binding
    res = orchestrator.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"mode": "real_lane", "provenance": "real_lane_audit"},
        project_binding=pb,
    )

    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.error_code in ("MISSING_PROVENANCE_PATH", "MISSING_RAW_DATA_SOURCE")
    assert res.scientific_decision is None
    # Ensure memory record was NOT created
    assert len(memory.find_by_hypothesis_id(valid_hyp["hypothesis_id"])) == 0


def test_caller_cannot_bypass_via_synthetic_dataset_binding_fields(tmp_path: Path) -> None:
    """Item 1: dataset_binding caller-controlled synthetic fields cannot bypass real validation."""
    root_dir = tmp_path / "research_root"
    store = ResultStore(ResearchLabConfig(root_dir))
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "eng_out")

    # Real lane orchestrator (default allow_synthetic_passthrough=False)
    real_orch = DiscoveryIntegrationOrchestrator(engine, allow_synthetic_passthrough=False)

    fake_hyp = _build_valid_hypothesis(
        family="momentum",
        definition="unsupported_feature_val",
        direction="positive",
        symbol="RB2701",
    )
    fake_hyp["source_features"] = ["unsupported_feature_val"]
    fake_hyp["hypothesis_content_hash"] = compute_hypothesis_content_hash(fake_hyp)
    hyp_model = AlphaHypothesis.model_validate(fake_hyp)
    pb = ProjectBinding(project_id="test_proj", workspace_identity="test_ws")

    dummy_csv = tmp_path / "dummy_fake.csv"
    dummy_csv.write_text("unsupported_feature_val\n", encoding="utf-8")

    # Attempt 1: caller sets mode == 'synthetic_test' in dataset_binding
    res1 = real_orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"mode": "synthetic_test"},
        project_binding=pb,
    )
    assert res1.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res1.scientific_decision is None

    # Attempt 2: caller sets allow_synthetic_passthrough == True in dataset_binding
    res2 = real_orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"allow_synthetic_passthrough": True},
        project_binding=pb,
    )
    assert res2.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res2.scientific_decision is None

    # Attempt 3: caller sets provenance string starting with 'synthetic'
    res3 = real_orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"provenance": "synthetic_generated_mock"},
        project_binding=pb,
    )
    assert res3.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res3.scientific_decision is None


def test_provenance_verification_fail_closed(tmp_path: Path) -> None:
    """Item 2: Strict provenance_path, provenance_sha256, and source_days verification."""
    root_dir = tmp_path / "research_root"
    store = ResultStore(ResearchLabConfig(root_dir))
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "eng_out")
    orch = DiscoveryIntegrationOrchestrator(engine, allow_synthetic_passthrough=False)

    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)

    valid_hyp = _build_valid_hypothesis()
    hyp_model = AlphaHypothesis.model_validate(valid_hyp)
    pb = ProjectBinding(project_id="test_proj", workspace_identity="test_ws")
    dummy_csv = tmp_path / "dummy.csv"
    dummy_csv.write_text("dummy\n", encoding="utf-8")

    # 1. Missing provenance_path
    res_no_path = orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"provenance_sha256": prov_sha, "source_days": source_days},
        project_binding=pb,
    )
    assert res_no_path.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_no_path.error_code == "MISSING_PROVENANCE_PATH"

    # 2. Missing provenance_sha256
    res_no_sha = orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={"provenance_path": str(prov_file), "source_days": source_days},
        project_binding=pb,
    )
    assert res_no_sha.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_no_sha.error_code == "MISSING_PROVENANCE_SHA"

    # 3. Non-existent provenance file
    res_bad_file = orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={
            "provenance_path": str(tmp_path / "nonexistent.json"),
            "provenance_sha256": prov_sha,
            "source_days": source_days,
        },
        project_binding=pb,
    )
    assert res_bad_file.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_bad_file.error_code == "MISSING_PROVENANCE_FILE"

    # 4. Hash mismatch
    res_hash_mismatch = orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": "0" * 64,
            "source_days": source_days,
        },
        project_binding=pb,
    )
    assert res_hash_mismatch.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_hash_mismatch.error_code == "PROVENANCE_HASH_MISMATCH"

    # 5. Caller-supplied source_days mismatch with provenance content
    tampered_source_days = copy.deepcopy(source_days)
    tampered_source_days[0]["settlement"]["rb_f"] = 99999.0
    res_days_mismatch = orch.integrate_candidate(
        hyp_model,
        snapshot_path=dummy_csv,
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": tampered_source_days,
        },
        project_binding=pb,
    )
    assert res_days_mismatch.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_days_mismatch.error_code == "SOURCE_DAYS_MISMATCH"

    # 6. Verify derived metadata has exact 64-hex source_provenance_sha256, never 'unspecified'
    spec = parse_and_verify_signal_spec(valid_hyp)
    derived = derive_signal_snapshot(
        spec=spec,
        source_days=source_days,
        output_dir=tmp_path / "meta_check",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    meta = json.loads(derived.metadata_path.read_text(encoding="utf-8"))
    assert meta["source_provenance_sha256"] == prov_sha
    assert meta["source_provenance_sha256"] != "unspecified"
    assert len(meta["source_provenance_sha256"]) == 64


def test_candidate_identity_filename_isolation(tmp_path: Path) -> None:
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)

    hyp1 = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    hyp2 = copy.deepcopy(hyp1)
    hyp2["hypothesis_id"] = "hyp-distinct-002"
    hyp2["title"] = "Different Candidate With Same Formula"
    hyp2["hypothesis_content_hash"] = compute_hypothesis_content_hash(hyp2)

    spec1 = parse_and_verify_signal_spec(hyp1)
    spec2 = parse_and_verify_signal_spec(hyp2)

    sci_hash1 = "1111111122222222333333334444444455555555666666667777777788888888"
    sci_hash2 = "aaaaaaaa99999999888888887777777766666666555555554444444433333333"

    res1 = derive_signal_snapshot(
        spec1,
        source_days,
        tmp_path / "shared",
        candidate_identity_hash=sci_hash1,
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    res2 = derive_signal_snapshot(
        spec2,
        source_days,
        tmp_path / "shared",
        candidate_identity_hash=sci_hash2,
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )

    # Isolated filenames, neither overwrote the other
    assert res1.path.name != res2.path.name
    assert "1111111122222222" in res1.path.name
    assert "aaaaaaaa99999999" in res2.path.name
    assert res1.path.exists() and res2.path.exists()
    assert res1.metadata_path.exists() and res2.metadata_path.exists()


def test_strict_utc_iso8601_and_trade_day_parsing() -> None:
    """Item 5: Strict UTC ISO8601 and YYYY-MM-DD parsing."""
    from datetime import timezone

    # 1. Valid UTC ISO8601 with Z
    dt1 = parse_strict_utc_iso8601("2026-09-29T12:00:00Z")
    assert dt1.tzinfo is not None
    assert dt1.utcoffset() == timezone.utc.utcoffset(dt1)

    # 2. Valid UTC ISO8601 with +00:00
    dt2 = parse_strict_utc_iso8601("2026-09-29T12:00:00.000000+00:00")
    assert dt2.tzinfo is not None
    assert dt2.utcoffset() == timezone.utc.utcoffset(dt2)

    # 3. Naive ISO string (no timezone) -> Rejected
    with pytest.raises(SignalBindingError) as exc_info:
        parse_strict_utc_iso8601("2026-09-29T12:00:00")
    assert exc_info.value.reason == "INVALID_DATETIME_FORMAT"

    # 4. Non-UTC offset (e.g. +08:00) -> Rejected
    with pytest.raises(SignalBindingError) as exc_info:
        parse_strict_utc_iso8601("2026-09-29T12:00:00+08:00")
    assert exc_info.value.reason == "INVALID_DATETIME_FORMAT"

    # 5. Invalid datetime string / out of bounds
    with pytest.raises(SignalBindingError) as exc_info:
        parse_strict_utc_iso8601("2026-09-29T25:00:00Z")
    assert exc_info.value.reason == "INVALID_DATETIME_FORMAT"

    # 6. Valid trading day YYYY-MM-DD
    d1 = parse_strict_trade_day("2026-09-29")
    assert str(d1) == "2026-09-29"

    # 7. Invalid trading day format (slashes)
    with pytest.raises(SignalBindingError) as exc_info:
        parse_strict_trade_day("2026/09/29")
    assert exc_info.value.reason == "INVALID_TRADE_DAY_FORMAT"

    # 8. Invalid calendar day (e.g. Feb 30)
    with pytest.raises(SignalBindingError) as exc_info:
        parse_strict_trade_day("2026-02-30")
    assert exc_info.value.reason == "INVALID_TRADE_DAY_FORMAT"


def test_phase_a_precheck_isolated_run_dir_success_and_duplicate_rejection(tmp_path: Path) -> None:
    """Verify Phase A precheck generates into isolated run dir and duplicate run_id fails closed."""
    from scripts.generate_phase_a_precheck import generate_phase_a_precheck

    runs_base = tmp_path / "runs_base"
    prov_file, _ = _build_synthetic_provenance_file(tmp_path)

    run_id = "test_run_phase_a_immutable_001"

    # 1. First run: succeeds and creates all expected files
    run_dir = generate_phase_a_precheck(
        run_id=run_id,
        runs_base_dir=runs_base,
        provenance_path=prov_file,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    assert run_dir.exists()
    assert run_dir.name == run_id

    expected_files = [
        "PRECHECK_REPORT.json",
        "PRECHECK_REPORT_RB2701_MOMENTUM_K1.json",
        "PRECHECK_REPORT_HC2701_REVERSAL_K1.json",
        "ROW_BY_ROW_PIT_EVIDENCE.md",
    ]
    for ef in expected_files:
        p = run_dir / ef
        assert p.exists(), f"Expected file {ef} missing in {run_dir}"

    # Verify reports passed
    for tag in ("RB2701_MOMENTUM_K1", "HC2701_REVERSAL_K1"):
        p = run_dir / f"PRECHECK_REPORT_{tag}.json"
        rep = json.loads(p.read_text(encoding="utf-8"))
        assert rep["precheck_status"] == "PRECHECK_PASS"
        assert rep["run_id"] == run_id

    # 2. Record bit-for-bit SHA256 of all files in run_dir
    file_hashes_before: dict[str, str] = {}
    for p in run_dir.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(run_dir))
            file_hashes_before[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

    assert len(file_hashes_before) >= 8

    # 3. Second run with the EXACT SAME run_id: must raise FileExistsError and refuse to mutate
    with pytest.raises(FileExistsError) as exc_info:
        generate_phase_a_precheck(
            run_id=run_id,
            runs_base_dir=runs_base,
            provenance_path=prov_file,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert "already exists and overwrite is strictly forbidden" in str(exc_info.value)

    # 4. Verify bit-for-bit that every file hash in run_dir is 100% unchanged
    file_hashes_after: dict[str, str] = {}
    for p in run_dir.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(run_dir))
            file_hashes_after[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

    assert file_hashes_after == file_hashes_before

    # 5. Invalid run_id with path traversal raises ValueError
    for bad_id in ("../escaped", "sub/dir", "", "   "):
        with pytest.raises(ValueError):
            generate_phase_a_precheck(
                run_id=bad_id,
                runs_base_dir=runs_base,
                provenance_path=prov_file,
            )


def test_derive_signal_snapshot_fail_closed_on_source_days_mismatch_and_missing_provenance(tmp_path: Path) -> None:
    """Verify derive_signal_snapshot strictly rejects source_days mismatch or missing provenance.

    Crucial invariant: fail-closed BEFORE any CSV or metadata snapshot files are written.
    """
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, source_days)

    hyp = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    spec = parse_and_verify_signal_spec(hyp)

    # 1. Tampered settlement price in source_days while citing canonical provenance file
    tampered_days = copy.deepcopy(source_days)
    tampered_days[0]["settlement"]["rb_f"] = 4999.0
    out_tampered = tmp_path / "out_tampered"

    with pytest.raises(SignalBindingError) as exc_tampered:
        derive_signal_snapshot(
            spec=spec,
            source_days=tampered_days,
            output_dir=out_tampered,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_tampered.value.reason == "SOURCE_DAYS_MISMATCH"
    assert not list(out_tampered.glob("*.csv")), "Must not write any CSV file on source_days mismatch"
    assert not list(out_tampered.glob("*.binding.json")), "Must not write any metadata file on source_days mismatch"

    # 2. Missing provenance_path (only arbitrary 64-hex SHA supplied)
    out_no_prov = tmp_path / "out_no_prov"
    with pytest.raises(SignalBindingError) as exc_no_prov:
        derive_signal_snapshot(
            spec=spec,
            source_days=source_days,
            output_dir=out_no_prov,
            provenance_path=None,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_no_prov.value.reason == "MISSING_PROVENANCE_PATH"
    assert not list(out_no_prov.glob("*.csv")), "Must not write any CSV file when provenance_path is None"
    assert not list(out_no_prov.glob("*.binding.json")), "Must not write any metadata when provenance_path is None"

    # 3. Non-existent provenance_path
    non_existent_prov = tmp_path / "does_not_exist" / "prov.json"
    out_missing_prov = tmp_path / "out_missing_prov"
    with pytest.raises(SignalBindingError) as exc_missing_prov:
        derive_signal_snapshot(
            spec=spec,
            source_days=source_days,
            output_dir=out_missing_prov,
            provenance_path=non_existent_prov,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_missing_prov.value.reason == "MISSING_PROVENANCE_FILE"
    assert not list(out_missing_prov.glob("*.csv")), "Must not write any CSV file when provenance file is missing"
    assert not list(out_missing_prov.glob("*.binding.json")), "Must not write metadata when provenance file is missing"


def test_backfill_counterexample_and_unverifiable_market_time(tmp_path: Path) -> None:
    """Reviewer counterexample 1: Ingestion first_seen_at cannot masquerade as market target time.

    In a backfill scenario or real warehouse custody missing market effective times:
    1. Days only have ingestion timestamps (first_seen_at, committed_at) without market_effective_time.
       -> derive_signal_snapshot MUST fail-closed with UNVERIFIABLE_TARGET_MARKET_TIME.
    2. Attempting to use delayed or out-of-order backfilled first_seen_at produces no valid causality.
    """
    raw_source = _build_synthetic_source_days()
    # Strip market_effective_time to simulate M2 raw custody
    unverifiable_days = copy.deepcopy(raw_source)
    for d in unverifiable_days:
        d.pop("market_effective_time", None)

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, unverifiable_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    out_dir = tmp_path / "out_unverifiable"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=unverifiable_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "UNVERIFIABLE_TARGET_MARKET_TIME"
    assert not list(out_dir.glob("*.csv")), "Must not write CSV when target market time is unverifiable"
    assert not list(out_dir.glob("*.binding.json")), "Must not write metadata when target market time is unverifiable"


def test_unverified_market_time_authority_fails_closed(tmp_path: Path) -> None:
    """Target market time with unverified or self-attested authority fails closed."""
    source_days = _build_synthetic_source_days()
    unverified_days = copy.deepcopy(source_days)
    for d in unverified_days:
        d["market_time_authority"] = "SELF_ATTESTED"

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, unverified_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    out_dir = tmp_path / "out_unverified_auth"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=unverified_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_info.value.reason == "UNVERIFIED_MARKET_TIME_AUTHORITY"
    assert not list(out_dir.glob("*.csv")), "Must not write CSV when market authority is unverified"


def test_lagged_inputs_actual_inputs_only_and_counterexample(tmp_path: Path) -> None:
    """For lookback k > 1, feature math only reads actual inputs (t-k and t).

    1. Positive case: k=2, intermediate day t-1 arrived/committed late (> as_of).
       Because Day t-1 is not an actual input to math.log(settle[t]/settle[t-2]),
       the snapshot derives and admits normally.
    2. Negative case: k=2, actual input Day t-2 committed after as_of -> fails closed
       with INPUT_NOT_COMMITTED_AT_AS_OF.
    """
    source_days = _build_synthetic_source_days()

    # Hypothesis with k=2: momentum log(settlement[t] / settlement[t-2])
    hyp_k2 = _build_valid_hypothesis(
        family="momentum",
        definition="log(settlement[t] / settlement[t-2])",
        direction="positive",
        symbol="RB2701",
    )
    spec_k2 = parse_and_verify_signal_spec(hyp_k2)

    # 1. Positive case: Intermediate day (index 1, Day 2026-09-02) arrives LATE (12:00 UTC)
    # Target observation index i=2 (Day 2026-09-03 as_of is 10:40 UTC).
    # Actual inputs: prev (index 0, Day 2026-09-01) committed at 10:40 <= 10:40.
    # cur (index 2, Day 2026-09-03) committed at 10:40 <= 10:40.
    # Intermediate day (index 1) committed at 12:00 > 10:40.
    intermediate_late_days = copy.deepcopy(source_days)
    intermediate_late_days[1]["committed_at"] = "2026-09-03T12:00:00.000000Z"
    intermediate_late_days[1]["first_seen_at"] = "2026-09-03T11:30:00.000000Z"

    prov_pos, prov_pos_sha = _build_synthetic_provenance_file(tmp_path / "pos", intermediate_late_days)
    out_pos = tmp_path / "out_pos"
    res_pos = derive_signal_snapshot(
        spec=spec_k2,
        source_days=intermediate_late_days,
        output_dir=out_pos,
        candidate_identity_hash="test_pos_hash",
        provenance_path=prov_pos,
        provenance_sha256=prov_pos_sha,
        synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
    )
    assert res_pos.row_count > 0
    assert res_pos.path.exists()

    # 2. Negative case: Actual input day t-2 (index 0) committed LATE (11:00 UTC > 10:40 UTC)
    actual_late_days = copy.deepcopy(source_days)
    actual_late_days[0]["committed_at"] = "2026-09-03T11:00:00.000000Z"

    prov_neg, prov_neg_sha = _build_synthetic_provenance_file(tmp_path / "neg", actual_late_days)
    out_neg = tmp_path / "out_neg"
    with pytest.raises(SignalBindingError) as exc_neg:
        derive_signal_snapshot(
            spec=spec_k2,
            source_days=actual_late_days,
            output_dir=out_neg,
            candidate_identity_hash="test_neg_hash",
            provenance_path=prov_neg,
            provenance_sha256=prov_neg_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_neg.value.reason == "INPUT_NOT_COMMITTED_AT_AS_OF"
    assert not list(out_neg.glob("*.csv"))


def test_reject_negative_expected_direction_at_admission_fail_closed(tmp_path: Path) -> None:
    """Reviewer finding 3: Under frozen scientific semantics, reject negative expected_direction."""
    hyp_neg = _build_valid_hypothesis(
        family="reversal",
        definition="log(settlement[t] / settlement[t-1])",
        direction="negative",
    )
    with pytest.raises(SignalBindingError) as exc_spec:
        parse_and_verify_signal_spec(hyp_neg)
    assert exc_spec.value.reason == "UNSUPPORTED_EXPECTED_DIRECTION"


def test_malformed_provenance_missing_field_fails_closed_as_admission_failed_with_audit(
    tmp_path: Path,
) -> None:
    """Reviewer finding 4: Hash-matching provenance with missing first_seen_at turns into ADMISSION_FAILED."""
    source_days = _build_synthetic_source_days()
    malformed_days = copy.deepcopy(source_days)
    del malformed_days[1]["first_seen_at"]

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, malformed_days)

    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(
        memory=memory,
        result_store=store,
        output_base_dir=tmp_path / "staging",
    )
    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)

    binding = {
        "snapshot_locator": str(tmp_path / "dummy.csv"),
        "snapshot_sha256": "0" * 64,
        "snapshot_byte_length": 100,
        "required_fields": ["feature_val", "target_val"],
        "available_fields": ["feature_val", "target_val"],
        "provenance_path": str(prov_file),
        "provenance_sha256": prov_sha,
        "source_days": malformed_days,
    }

    hyp = _build_valid_hypothesis(symbol="RB2701")
    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )

    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding=binding,
        project_binding=pb,
        request_id="req-malformed-test",
    )

    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None, "Malformed provenance must produce NO scientific decision"
    assert "MALFORMED_PROVENANCE" in (res.error_code or "")
    records = orchestrator.audit_trail.get_records()
    assert len(records) >= 1
    assert records[-1].engineering_status == EngineeringStatus.ADMISSION_FAILED.value


def test_malformed_provenance_top_level_list_and_settlement_fails_closed_with_audit(
    tmp_path: Path,
) -> None:
    """P2 Regression: Top-level JSON list or non-dict settlement fails closed to candidate ADMISSION_FAILED.

    Ensures no uncaught AttributeError or TypeError escapes to crash the batch,
    audit trail records the event, and zero scientific decision is produced.
    """
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(
        memory=memory,
        result_store=store,
        output_base_dir=tmp_path / "staging",
    )
    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    hyp = _build_valid_hypothesis(symbol="RB2701")
    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )

    # Structure A: Provenance top-level JSON is a list [...]
    prov_file_list = tmp_path / "prov_list.json"
    prov_file_list.write_text('[{"source_days": []}]', encoding="utf-8")
    sha_list = hashlib.sha256(prov_file_list.read_bytes()).hexdigest()

    res_a = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file_list),
            "provenance_sha256": sha_list,
        },
        project_binding=pb,
        request_id="req-list-test",
    )
    assert res_a.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_a.scientific_decision is None
    assert "MALFORMED_PROVENANCE" in (res_a.error_code or "")

    # Structure B: source_days has non-dict settlement (e.g. list [3186.0])
    source_days = _build_synthetic_source_days()
    malformed_settle_days = copy.deepcopy(source_days)
    malformed_settle_days[0]["settlement"] = [3186.0]

    prov_file_settle, sha_settle = _build_synthetic_provenance_file(
        tmp_path / "prov_b", malformed_settle_days
    )
    res_b = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file_settle),
            "provenance_sha256": sha_settle,
            "source_days": malformed_settle_days,
        },
        project_binding=pb,
        request_id="req-settle-test",
    )
    assert res_b.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_b.scientific_decision is None
    assert "MALFORMED_PROVENANCE" in (res_b.error_code or "")

    # Verify both records are in audit trail
    records = orchestrator.audit_trail.get_records()
    assert len(records) >= 2
    assert all(r.engineering_status == EngineeringStatus.ADMISSION_FAILED.value for r in records[-2:])


def test_integration_engine_critic_direction_equivalent_regression(tmp_path: Path) -> None:
    """Reviewer finding 4 regression: Integration -> Engine -> Critic for equivalent directions.

    1. 'expected_direction=negative', definition='log(settlement[t]/settlement[t-1])'
       fails closed at admission; Engine, Critic, and Memory are NEVER invoked (0 records).
    2. Equivalent formulation 'expected_direction=positive', definition='-log(settlement[t]/settlement[t-1])'
       passes admission on identical data, proceeds through Engine & Critic, and produces 1 Memory record.
    Preserves frozen scientific thresholds without alteration.
    """
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(
        memory=memory,
        result_store=store,
        output_base_dir=tmp_path / "staging",
    )
    orchestrator = DiscoveryIntegrationOrchestrator(
        engine=engine, synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE
    )
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "prov", source_days)

    dataset_binding = {
        "provenance_path": str(prov_file),
        "provenance_sha256": prov_sha,
        "source_days": source_days,
    }

    # 1. Unsupported negative expected_direction
    hyp_neg = _build_valid_hypothesis(
        family="reversal",
        definition="log(settlement[t] / settlement[t-1])",
        direction="negative",
        symbol="RB2701",
    )
    cand_neg = AlphaGenerationCandidate(
        hypothesis=hyp_neg,
        scientific_identity_hash=compute_scientific_identity_hash(hyp_neg),
        rationale="test negative",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res_neg = orchestrator.integrate_candidate(
        candidate=cand_neg,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding=dataset_binding,
        project_binding=pb,
        request_id="req-neg-test",
    )
    assert res_neg.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res_neg.scientific_decision is None
    assert res_neg.error_code == "UNSUPPORTED_EXPECTED_DIRECTION"
    # Verify zero memory records created for negative candidate
    assert len(memory.find_by_hypothesis_id(hyp_neg["hypothesis_id"])) == 0

    # 2. Equivalent positive expected_direction with explicit negation
    hyp_pos = _build_valid_hypothesis(
        family="reversal",
        definition="-log(settlement[t] / settlement[t-1])",
        direction="positive",
        symbol="RB2701",
    )
    cand_pos = AlphaGenerationCandidate(
        hypothesis=hyp_pos,
        scientific_identity_hash=compute_scientific_identity_hash(hyp_pos),
        rationale="test positive equivalent",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res_pos = orchestrator.integrate_candidate(
        candidate=cand_pos,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding=dataset_binding,
        project_binding=pb,
        request_id="req-pos-test",
    )
    assert res_pos.engineering_status == EngineeringStatus.COMPLETED.value
    assert res_pos.scientific_decision in ("NEED_MORE_EVIDENCE", "PROMOTE", "REJECT")
    assert res_pos.error_code is None
    # Memory record created and verified
    records_pos = memory.find_by_hypothesis_id(hyp_pos["hypothesis_id"])
    assert len(records_pos) == 1
    assert records_pos[0].decision == res_pos.scientific_decision


def test_spoofed_shfe_official_authority_fails_closed_without_independent_source(tmp_path: Path) -> None:
    """Codex counterexample reproduction: Spoofing market_time_authority='SHFE_OFFICIAL' fails closed.

    Reproduces Codex's exact counterexample where setting market_time_authority to 'SHFE_OFFICIAL'
    in untrusted provenance data previously bypassed verification without an independent exchange source.
    Asserts:
    1. derive_signal_snapshot raises UNVERIFIED_MARKET_TIME_AUTHORITY.
    2. Zero snapshot CSV and zero metadata binding files are written.
    3. orchestrator.integrate_candidate fails closed with ADMISSION_FAILED and zero scientific decision.
    """
    source_days = _build_synthetic_source_days()
    spoofed_days = copy.deepcopy(source_days)
    for d in spoofed_days:
        d["market_time_authority"] = "SHFE_OFFICIAL"

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "spoof_prov", spoofed_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    # 1. Direct derivation must fail closed
    out_dir = tmp_path / "spoof_out"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=spoofed_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
        )
    assert exc_info.value.reason == "UNVERIFIED_MARKET_TIME_AUTHORITY"
    assert not list(out_dir.glob("*.csv")), "Strictly forbidden to write CSV for spoofed exchange authority"
    assert not list(out_dir.glob("*.binding.json")), "Strictly forbidden to write metadata for spoofed exchange authority"

    # Even if synthetic_test_evidence is passed, 'SHFE_OFFICIAL' is an untrusted self-attested authority
    with pytest.raises(SignalBindingError) as exc_with_ev:
        derive_signal_snapshot(
            spec=spec,
            source_days=spoofed_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,
        )
    assert exc_with_ev.value.reason == "UNVERIFIED_MARKET_TIME_AUTHORITY"

    # 2. Real admission orchestrator rejects candidate
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "staging")
    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)  # default synthetic_test_evidence=None
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test spoofed shfe authority",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": spoofed_days,
        },
        project_binding=pb,
        request_id="req-spoof-shfe",
    )
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert res.error_code == "UNVERIFIED_MARKET_TIME_AUTHORITY"
    assert len(memory.find_by_hypothesis_id(hyp["hypothesis_id"])) == 0


def test_data_string_switch_synthetic_fixture_fails_closed_without_in_memory_evidence(tmp_path: Path) -> None:
    """Provenance claiming 'SYNTHETIC_TEST_FIXTURE' in untrusted data fails closed without in-memory evidence.

    Ensures that callers cannot bypass the gate simply by putting 'SYNTHETIC_TEST_FIXTURE' into
    data or provenance JSON unless authorized Python in-memory SyntheticTestEvidence is explicitly supplied.
    """
    source_days = _build_synthetic_source_days()
    # Data has market_time_authority='SYNTHETIC_TEST_FIXTURE'
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "switch_prov", source_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    # 1. derive_signal_snapshot without synthetic_test_evidence (synthetic_test_evidence=None)
    out_dir = tmp_path / "switch_out"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=source_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=None,
        )
    assert exc_info.value.reason == "UNVERIFIED_MARKET_TIME_AUTHORITY"
    assert not list(out_dir.glob("*.csv"))
    assert not list(out_dir.glob("*.binding.json"))

    # 2. Real admission orchestrator (synthetic_test_evidence=None) fails closed
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "staging")
    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)  # default synthetic_test_evidence=None
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test data string switch",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": source_days,
        },
        project_binding=pb,
        request_id="req-switch-test",
    )
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert res.error_code == "UNVERIFIED_MARKET_TIME_AUTHORITY"
    assert len(memory.find_by_hypothesis_id(hyp["hypothesis_id"])) == 0


def test_arbitrary_caller_chosen_fixture_id_fails_closed(tmp_path: Path) -> None:
    """Caller attempting to bypass via caller-chosen fixture_id strictly fails closed.

    Ensures SyntheticTestEvidence cannot be instantiated with arbitrary fixture_ids
    (e.g. 'caller-chosen', 'my-custom-fixture') to bypass verification.
    """
    source_days = _build_synthetic_source_days()
    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "caller_prov", source_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    unauthorized_evidence = SyntheticTestEvidence(fixture_id="caller-chosen")

    out_dir = tmp_path / "caller_out"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=source_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=unauthorized_evidence,
        )
    assert exc_info.value.reason == "UNAUTHORIZED_SYNTHETIC_FIXTURE"
    assert not list(out_dir.glob("*.csv")), "Strictly forbidden to write CSV for unauthorized fixture ID"
    assert not list(out_dir.glob("*.binding.json")), "Strictly forbidden to write metadata for unauthorized fixture ID"

    # Orchestrator fail-closed test
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "staging")
    orchestrator = DiscoveryIntegrationOrchestrator(
        engine=engine, synthetic_test_evidence=unauthorized_evidence
    )
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test arbitrary fixture id",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": source_days,
        },
        project_binding=pb,
        request_id="req-caller-chosen",
    )
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert res.error_code == "UNAUTHORIZED_SYNTHETIC_FIXTURE"
    assert len(memory.find_by_hypothesis_id(hyp["hypothesis_id"])) == 0


def test_real_dataset_cannot_bypass_via_synthetic_test_evidence(tmp_path: Path) -> None:
    """Real or non-whitelisted source datasets cannot bypass market time checks via SyntheticTestEvidence.

    Even if caller supplies authorized in-memory SyntheticTestEvidence(fixture_id="synthetic-offline-test-fixture-v1"),
    if source_days digest does not match the known fixed mathematical unit test fixtures,
    derivation strictly fails closed.
    """
    # 19-day realistic dataset or modified prices (representing real / non-whitelisted data)
    real_days = []
    for i in range(19):
        d_str = f"2026-09-{i+1:02d}"
        real_days.append({
            "day": d_str,
            "first_seen_at": f"{d_str}T10:30:00.000000Z",
            "committed_at": f"{d_str}T10:40:00.000000Z",
            "market_effective_time": f"{d_str}T15:00:00.000000Z",
            "market_time_authority": "SYNTHETIC_TEST_FIXTURE",  # Spoofed synthetic authority on real/arbitrary data
            "raw_sha256": "0" * 64,
            "raw_bytes": 100,
            "raw_relative_path": f"raw/{d_str}/data.raw",
            "batch_seal_sha256": "1" * 64,
            "settlement": {"rb_f": 3000.0 + i, "hc_f": 3100.0 + i},
        })

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "real_spoof_prov", real_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    out_dir = tmp_path / "real_bypass_out"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=real_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE,  # whitelisted fixture_id, but dataset is real/arbitrary
        )
    assert exc_info.value.reason == "UNAUTHORIZED_SYNTHETIC_FIXTURE"
    assert "strictly restricted to known fixed offline unit test fixtures" in exc_info.value.details
    assert not list(out_dir.glob("*.csv"))
    assert not list(out_dir.glob("*.binding.json"))

    # Orchestrator fail-closed test
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "staging")
    orchestrator = DiscoveryIntegrationOrchestrator(
        engine=engine, synthetic_test_evidence=TEST_SYNTHETIC_EVIDENCE
    )
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test real dataset bypass attempt",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": real_days,
        },
        project_binding=pb,
        request_id="req-real-bypass",
    )
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert res.error_code == "UNAUTHORIZED_SYNTHETIC_FIXTURE"
    assert len(memory.find_by_hypothesis_id(hyp["hypothesis_id"])) == 0


def test_real_m2_custody_data_fails_closed_without_market_effective_time(tmp_path: Path) -> None:
    """Real M2 Research Warehouse custody missing market effective time strictly fails closed.

    Stage 2 real lane remains BLOCKED; 0 snapshot files and 0 scientific memory records.
    """
    # 19 days simulating M2 raw custody (only first_seen_at and committed_at, no market_effective_time)
    m2_days = []
    for i in range(19):
        d_str = f"2026-09-{i+1:02d}"
        m2_days.append({
            "day": d_str,
            "first_seen_at": f"{d_str}T10:30:00.000000Z",
            "committed_at": f"{d_str}T10:40:00.000000Z",
            # No market_effective_time or settlement_effective_time!
            "raw_sha256": "0" * 64,
            "raw_bytes": 100,
            "raw_relative_path": f"raw/{d_str}/data.raw",
            "batch_seal_sha256": "1" * 64,
            "settlement": {"rb_f": 3000.0 + i, "hc_f": 3100.0 + i},
        })

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path / "m2_prov", m2_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    # 1. Direct derivation with default synthetic_test_evidence=None
    out_dir = tmp_path / "m2_out"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=m2_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
            synthetic_test_evidence=None,
        )
    assert exc_info.value.reason == "UNVERIFIABLE_TARGET_MARKET_TIME"
    assert not list(out_dir.glob("*.csv"))
    assert not list(out_dir.glob("*.binding.json"))

    # 2. Real admission orchestrator
    config = ResearchLabConfig(root=tmp_path)
    store = ResultStore(config)
    memory = ResearchMemory(store)
    engine = AlphaDiscoveryEngine(memory=memory, result_store=store, output_base_dir=tmp_path / "staging")
    orchestrator = DiscoveryIntegrationOrchestrator(engine=engine)  # default synthetic_test_evidence=None
    pb = ProjectBinding(project_id="test", workspace_identity=str(tmp_path))

    cand = AlphaGenerationCandidate(
        hypothesis=hyp,
        scientific_identity_hash=compute_scientific_identity_hash(hyp),
        rationale="test real m2 custody fail-closed",
        source_context_refs=(),
        novelty_statement="test",
        duplicate_awareness="test",
        uncertainty="test",
    )
    res = orchestrator.integrate_candidate(
        candidate=cand,
        snapshot_path=tmp_path / "dummy.csv",
        dataset_binding={
            "provenance_path": str(prov_file),
            "provenance_sha256": prov_sha,
            "source_days": m2_days,
        },
        project_binding=pb,
        request_id="req-m2-failclosed",
    )
    assert res.engineering_status == EngineeringStatus.ADMISSION_FAILED.value
    assert res.scientific_decision is None
    assert res.error_code == "UNVERIFIABLE_TARGET_MARKET_TIME"
    assert len(memory.find_by_hypothesis_id(hyp["hypothesis_id"])) == 0


def test_recover_round_execution_timing_100_percent_coverage(tmp_path: Path) -> None:
    """100% complete coverage across declared run_refs recovers max immutable completion time."""
    records = []
    expected_times = []
    for s_idx in range(2):
        s_runs = []
        s_receipts = []
        for r_idx in range(2):
            run_id = f"run-test-{s_idx}-{r_idx}"
            c_time = f"2026-09-29T10:0{s_idx}:0{r_idx}.000000Z"
            expected_times.append(c_time)

            bundle_dir = tmp_path / run_id
            bundle_dir.mkdir(parents=True, exist_ok=True)
            run_json = bundle_dir / "run.json"
            content_hash = "a" * 64
            run_payload = {
                "run_id": run_id,
                "run_content_hash": content_hash,
                "timing": {"completed_at": c_time},
            }
            raw_bytes = json.dumps(run_payload).encode("utf-8")
            run_json.write_bytes(raw_bytes)
            run_json_sha = hashlib.sha256(raw_bytes).hexdigest()

            s_runs.append({"run_id": run_id, "content_hash": content_hash})
            s_receipts.append({
                "run": {"object_id": run_id, "content_hash": content_hash},
                "bundle_location": str(bundle_dir),
                "bundle_file_sha256": {"run.json": run_json_sha},
            })
        records.append({
            "ordinal": s_idx,
            "run_refs": s_runs,
            "verified_result_store_receipts": s_receipts,
        })

    completed_at, source = recover_round_execution_timing(records)
    assert completed_at == max(expected_times)
    assert source == "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"


def test_recover_round_execution_timing_rejects_top_level_run_id_mismatch_and_bundle_sha_counterexample(
    tmp_path: Path,
) -> None:
    """Reviewer counterexample: spoofed run.json top-level run_id, invalid bundle SHA, or hash mismatch fails closed."""
    # Counterexample A: bundle_file_sha256['run.json']='0'*64 mismatch, top-level run_id='different-run'
    b_dir = tmp_path / "spoof_bundle"
    b_dir.mkdir(parents=True, exist_ok=True)
    r_file = b_dir / "run.json"
    spoofed_bytes = json.dumps({
        "run_id": "different-run",
        "run_content_hash": "c" * 64,
        "timing": {"completed_at": "2026-09-29T23:59:59.000000Z"},
    }).encode("utf-8")
    r_file.write_bytes(spoofed_bytes)

    spoofed_rec = [{
        "run_refs": [{"run_id": "declared-run", "content_hash": "d" * 64}],
        "verified_result_store_receipts": [{
            "run": {"object_id": "declared-run", "content_hash": "d" * 64},
            "bundle_location": str(b_dir),
            "bundle_file_sha256": {"run.json": "0" * 64},
        }],
    }]
    cat, src = recover_round_execution_timing(spoofed_rec)
    assert cat == "unknown"
    assert "run.json sha256 mismatch against receipt bundle inventory" in src
    assert "23:59:59" not in cat

    # Counterexample B: bundle_file_sha256 matches actual file, but run.json top-level run_id='different-run'
    real_file_sha = hashlib.sha256(spoofed_bytes).hexdigest()
    spoofed_rec[0]["verified_result_store_receipts"][0]["bundle_file_sha256"]["run.json"] = real_file_sha
    cat, src = recover_round_execution_timing(spoofed_rec)
    assert cat == "unknown"
    assert "run.json top-level run_id mismatch for declared-run: found different-run" in src

    # Counterexample C: run_id matches, but run_content_hash mismatches declared run_ref
    r_file.write_bytes(json.dumps({
        "run_id": "declared-run",
        "run_content_hash": "f" * 64,
        "timing": {"completed_at": "2026-09-29T23:59:59.000000Z"},
    }).encode("utf-8"))
    spoofed_rec[0]["verified_result_store_receipts"][0]["bundle_file_sha256"]["run.json"] = hashlib.sha256(
        r_file.read_bytes()
    ).hexdigest()
    cat, src = recover_round_execution_timing(spoofed_rec)
    assert cat == "unknown"
    assert "run_content_hash mismatch with declared run_ref" in src


def test_recover_round_execution_timing_with_result_store_refuses_cached_receipts_tampering(
    tmp_path: Path,
) -> None:
    """When result_store is supplied on resume, cached receipts in JSON are never trusted literally."""
    r1_dir = Path("artifacts/stage2_real_runs/run_20260929_stage2_universal_r1_real_v1/round_1")
    if not (r1_dir / "ROUND1_FULL_EVIDENCE.json").exists():
        pytest.skip("Real R1 artifacts not present")

    r1_store = ResultStore(ResearchLabConfig(root=r1_dir / "store"))
    r1_data = json.loads((r1_dir / "ROUND1_FULL_EVIDENCE.json").read_text(encoding="utf-8"))
    integrations = r1_data.get("integrations", [])

    # Tamper with cached verified_result_store_receipts in integration JSON
    tampered_integrations = copy.deepcopy(integrations)
    fake_bundle = tmp_path / "fake_bundle"
    fake_bundle.mkdir(parents=True, exist_ok=True)
    (fake_bundle / "run.json").write_text(
        json.dumps({
            "run_id": "fake-run",
            "run_content_hash": "0" * 64,
            "timing": {"completed_at": "2099-01-01T00:00:00.000000Z"},
        }),
        encoding="utf-8",
    )
    for item in tampered_integrations:
        item["verified_result_store_receipts"] = [{
            "run": {"object_id": "fake-run", "content_hash": "0" * 64},
            "bundle_location": str(fake_bundle),
            "bundle_file_sha256": {"run.json": hashlib.sha256((fake_bundle / "run.json").read_bytes()).hexdigest()},
        }]

    # With result_store=r1_store: authentic receipts are re-queried, tampered cache is ignored
    c_at, src = recover_round_execution_timing(tampered_integrations, result_store=r1_store)
    assert c_at == "2026-09-29T10:35:07.281286Z"
    assert "2099" not in c_at

    # If run_refs declare a non-existent run_id, result_store re-query fails closed to unknown
    tampered_integrations[0]["run_refs"].append({"run_id": "run-non-existent-9999"})
    c_at_bad, src_bad = recover_round_execution_timing(tampered_integrations, result_store=r1_store)
    assert c_at_bad == "unknown"
    assert "ResultStore query_v2_runs returned 0 receipts" in src_bad


def test_recover_round_execution_timing_missing_receipt_returns_unknown_and_orphan_cannot_rescue(
    tmp_path: Path,
) -> None:
    """Missing even one receipt returns 'unknown'; orphan/old run.json on disk cannot rescue."""
    records = []
    # 2 runs declared in slot 0, but only 1 receipt provided
    run_0 = "run-covered-0"
    run_1 = "run-missing-receipt-1"

    b_dir_0 = tmp_path / run_0
    b_dir_0.mkdir(parents=True, exist_ok=True)
    r_bytes = json.dumps({
        "run_id": run_0,
        "run_content_hash": "a" * 64,
        "timing": {"completed_at": "2026-09-29T10:00:00.000000Z"},
    }).encode("utf-8")
    (b_dir_0 / "run.json").write_bytes(r_bytes)

    # Orphan run.json created in an unreferenced directory (simulating glob rescue attempt)
    orphan_dir = tmp_path / "orphan_runs"
    orphan_dir.mkdir(parents=True, exist_ok=True)
    (orphan_dir / "run.json").write_text(
        json.dumps({
            "run_id": run_1,
            "run_content_hash": "b" * 64,
            "timing": {"completed_at": "2026-09-29T10:59:59.000000Z"},
        }),
        encoding="utf-8",
    )

    records.append({
        "ordinal": 0,
        "run_refs": [
            {"run_id": run_0, "content_hash": "a" * 64},
            {"run_id": run_1, "content_hash": "b" * 64},
        ],
        "verified_result_store_receipts": [
            {
                "run": {"object_id": run_0, "content_hash": "a" * 64},
                "bundle_location": str(b_dir_0),
                "bundle_file_sha256": {"run.json": hashlib.sha256(r_bytes).hexdigest()},
            },
            # run_1 receipt intentionally omitted!
        ],
    })

    completed_at, source = recover_round_execution_timing(records)
    assert completed_at == "unknown"
    assert "missing verified receipt for declared run_ref(s)" in source
    assert run_1 in source
    # Must NOT have picked up orphan_dir timestamp
    assert "10:59:59" not in completed_at


def test_recover_round_execution_timing_invalid_or_missing_timing_returns_unknown(tmp_path: Path) -> None:
    """Non-UTC, missing, or malformed timing.completed_at fails closed to unknown."""
    run_id = "run-bad-timing"
    b_dir = tmp_path / run_id
    b_dir.mkdir(parents=True, exist_ok=True)
    raw_bytes = json.dumps({
        "run_id": run_id,
        "run_content_hash": "a" * 64,
        "timing": {"completed_at": "2026-09-29 10:00:00"},  # Invalid: missing Z/offset and T
    }).encode("utf-8")
    (b_dir / "run.json").write_bytes(raw_bytes)

    records = [{
        "ordinal": 0,
        "run_refs": [{"run_id": run_id, "content_hash": "a" * 64}],
        "verified_result_store_receipts": [{
            "run": {"object_id": run_id, "content_hash": "a" * 64},
            "bundle_location": str(b_dir),
            "bundle_file_sha256": {"run.json": hashlib.sha256(raw_bytes).hexdigest()},
        }],
    }]

    completed_at, source = recover_round_execution_timing(records)
    assert completed_at == "unknown"
    assert "invalid timing.completed_at format" in source


def test_recover_round_execution_timing_duplicate_run_ref_returns_unknown(tmp_path: Path) -> None:
    """Duplicate run_id declaration fails closed to unknown."""
    run_id = "run-dup-id"
    records = [
        {
            "ordinal": 0,
            "run_refs": [{"run_id": run_id}],
            "verified_result_store_receipts": [],
        },
        {
            "ordinal": 1,
            "run_refs": [{"run_id": run_id}],
            "verified_result_store_receipts": [],
        },
    ]
    completed_at, source = recover_round_execution_timing(records)
    assert completed_at == "unknown"
    assert "duplicate run_ref declared across slots" in source


def test_recover_round_execution_timing_chronological_datetime_comparison_counterexample(
    tmp_path: Path,
) -> None:
    """Reviewer counterexample: 2026-09-29T10:35:07Z vs 2026-09-29T10:35:07.123456Z compares chronologically by datetime, not ASCII."""
    # Run A: 2026-09-29T10:35:07Z (ASCII string is higher because 'Z' > '.')
    # Run B: 2026-09-29T10:35:07.123456Z (chronologically later by 123.456ms)
    # Run C: 2026-09-29T10:35:07.050+00:00 (offset format, earlier than B)
    # Run D: 2026-09-29T10:35:07.999Z (later than B)
    # Run E: 2026-09-29T10:35:08+00:00 (latest across all)

    specs = [
        ("run-a", "2026-09-29T10:35:07Z"),
        ("run-b", "2026-09-29T10:35:07.123456Z"),
        ("run-c", "2026-09-29T10:35:07.050+00:00"),
        ("run-d", "2026-09-29T10:35:07.999Z"),
        ("run-e", "2026-09-29T10:35:08+00:00"),
    ]

    s_runs = []
    s_receipts = []
    for rid, c_time in specs:
        b_dir = tmp_path / rid
        b_dir.mkdir(parents=True, exist_ok=True)
        r_file = b_dir / "run.json"
        chash = hashlib.sha256(rid.encode("utf-8")).hexdigest()
        raw_bytes = json.dumps({
            "run_id": rid,
            "run_content_hash": chash,
            "timing": {"completed_at": c_time},
        }).encode("utf-8")
        r_file.write_bytes(raw_bytes)

        s_runs.append({"run_id": rid, "content_hash": chash})
        s_receipts.append({
            "run": {"object_id": rid, "content_hash": chash},
            "bundle_location": str(b_dir),
            "bundle_file_sha256": {"run.json": hashlib.sha256(raw_bytes).hexdigest()},
        })

    # Test pair A vs B directly: pure ASCII string would wrongly select Run A because 'Z' > '.'
    pair_ab_record = [{
        "ordinal": 0,
        "run_refs": s_runs[:2],
        "verified_result_store_receipts": s_receipts[:2],
    }]
    cat_ab, _ = recover_round_execution_timing(pair_ab_record)
    assert cat_ab == "2026-09-29T10:35:07.123456Z"
    assert cat_ab != "2026-09-29T10:35:07Z"

    # Test all 5 mixed precision/offsets: Run E (2026-09-29T10:35:08+00:00) must be selected
    all_5_record = [{
        "ordinal": 0,
        "run_refs": s_runs,
        "verified_result_store_receipts": s_receipts,
    }]
    cat_all, _ = recover_round_execution_timing(all_5_record)
    assert cat_all == "2026-09-29T10:35:08+00:00"


def test_recover_round_execution_timing_real_r1_and_r2_receipts_regression() -> None:
    """Existing real Round 1 (40 runs) and Round 2 (60 runs) receipts maintain 100% verification with zero regression."""
    r1_path = Path("artifacts/stage2_real_runs/run_20260929_stage2_universal_r1_real_v1/round_1/ROUND1_FULL_EVIDENCE.json")
    if r1_path.exists():
        r1_data = json.loads(r1_path.read_text(encoding="utf-8"))
        integrations = r1_data.get("integrations", [])
        assert len(integrations) == 10
        total_runs = sum(len(item.get("run_refs", [])) for item in integrations)
        assert total_runs == 40

        # Test both offline receipt recovery and ResultStore re-verification
        c_at, src = recover_round_execution_timing(integrations)
        assert c_at == "2026-09-29T10:35:07.281286Z"
        assert src == "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"

        r1_store = ResultStore(ResearchLabConfig(root=r1_path.parent / "store"))
        c_at_store, src_store = recover_round_execution_timing(integrations, result_store=r1_store)
        assert c_at_store == "2026-09-29T10:35:07.281286Z"
        assert src_store == "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"

    r2_path = Path("artifacts/stage2_real_runs/run_20260929_stage2_universal_r1_real_v1/round_2_real_v1/ROUND2_FULL_EVIDENCE.json")
    if r2_path.exists():
        r2_data = json.loads(r2_path.read_text(encoding="utf-8"))
        integrations = r2_data.get("integrations", [])
        assert len(integrations) == 10
        total_runs = sum(len(item.get("run_refs", [])) for item in integrations)
        assert total_runs == 60

        c_at, src = recover_round_execution_timing(integrations)
        assert c_at == "2026-09-29T10:53:19.031509Z"
        assert src == "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"

        r2_store = ResultStore(ResearchLabConfig(root=r2_path.parent / "store"))
        c_at_store, src_store = recover_round_execution_timing(integrations, result_store=r2_store)
        assert c_at_store == "2026-09-29T10:53:19.031509Z"
        assert src_store == "recovered from immutable result store execution receipts (latest run.json:timing.completed_at)"
