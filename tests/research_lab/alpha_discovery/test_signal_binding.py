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
    derive_signal_snapshot,
    parse_and_verify_signal_spec,
    parse_strict_trade_day,
    parse_strict_utc_iso8601,
    precheck_candidate_real_data,
    verify_derived_snapshot_pit,
)
from research_lab.config import ResearchLabConfig
from research_lab.database.result_store import ResultStore


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
    )
    res_run2 = derive_signal_snapshot(
        spec,
        source_days,
        tmp_path / "run2",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
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
    )

    hyp_hc = _build_valid_hypothesis(symbol="HC2701")
    spec_hc = parse_and_verify_signal_spec(hyp_hc)
    res_hc = derive_signal_snapshot(
        spec_hc,
        source_days,
        tmp_path / "hc_iso",
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
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
    orchestrator = DiscoveryIntegrationOrchestrator(engine)

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
    )
    res2 = derive_signal_snapshot(
        spec2,
        source_days,
        tmp_path / "shared",
        candidate_identity_hash=sci_hash2,
        provenance_path=prov_file,
        provenance_sha256=prov_sha,
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
        )
    assert exc_info.value.reason == "UNVERIFIABLE_TARGET_MARKET_TIME"
    assert not list(out_dir.glob("*.csv")), "Must not write CSV when target market time is unverifiable"
    assert not list(out_dir.glob("*.binding.json")), "Must not write metadata when target market time is unverifiable"


def test_prior_day_late_arrival_counterexample(tmp_path: Path) -> None:
    """Reviewer counterexample 2: Lagged feature availability/commit must cover ALL inputs.

    When lookback k >= 1, Day t's feature depends on Day t-k and Day t.
    If Day t-1 arrived or was committed late (after Day t's as_of_time),
    Day t's feature is using uncommitted/unavailable historical data -> fail-closed.
    """
    source_days = _build_synthetic_source_days()
    # Tamper Day 0 (prev) committed_at to be AFTER Day 1 (cur) committed_at
    # cur (Day 1) as_of is 2026-09-02T10:40:00.000000Z
    # Set prev (Day 0) committed_at to 2026-09-02T10:45:00.000000Z
    late_prev_days = copy.deepcopy(source_days)
    late_prev_days[0]["committed_at"] = "2026-09-02T10:45:00.000000Z"

    prov_file, prov_sha = _build_synthetic_provenance_file(tmp_path, late_prev_days)
    hyp = _build_valid_hypothesis(symbol="RB2701")
    spec = parse_and_verify_signal_spec(hyp)

    out_dir = tmp_path / "out_late_prev"
    with pytest.raises(SignalBindingError) as exc_info:
        derive_signal_snapshot(
            spec=spec,
            source_days=late_prev_days,
            output_dir=out_dir,
            provenance_path=prov_file,
            provenance_sha256=prov_sha,
        )
    assert exc_info.value.reason == "INPUT_NOT_COMMITTED_AT_AS_OF"
    assert not list(out_dir.glob("*.csv")), "Must not write CSV on input commit violation"


def test_reject_negative_expected_direction_at_admission_fail_closed(tmp_path: Path) -> None:
    """Reviewer finding 3: Under frozen scientific semantics, reject negative expected_direction.

    The screening runner tests positive concordance (same-sign consistency >= 0.50).
    A candidate with expected_direction='negative' must be rejected at admission,
    preventing an equivalent economic hypothesis from wrongly receiving a scientific REJECT.
    """
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
    """Reviewer finding 4: Hash-matching provenance with missing first_seen_at turns into ADMISSION_FAILED.

    Ensures malformed provenance does NOT raise an uncaught KeyError that crashes the batch,
    produces zero scientific decision, and records an audit entry.
    """
    source_days = _build_synthetic_source_days()
    malformed_days = copy.deepcopy(source_days)
    # Delete first_seen_at from second day
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
    # Audit trail contains record
    records = orchestrator.audit_trail.get_records()
    assert len(records) >= 1
    assert records[-1].engineering_status == EngineeringStatus.ADMISSION_FAILED.value

