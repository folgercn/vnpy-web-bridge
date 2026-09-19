"""Focused tests for AlphaHypothesis contract, canonicalization, and dedup boundaries (#563).

Covers all 17 required verification items defined in the #563 specification.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
    compute_semantic_hash,
    compute_structured_key,
    create_revision,
    is_exact_duplicate,
    is_potentially_related,
    is_valid_revision,
    validate_hypothesis,
)


@pytest.fixture
def valid_hypothesis_data() -> dict[str, Any]:
    """A valid, representative AlphaHypothesis fixture."""
    data = {
        "schema_version": "research_lab.alpha_hypothesis.v1",
        "hash_profile": "research-json-v1",
        "hypothesis_id": "hypo-momentum-breakout-20d",
        "revision": "rev.1",
        "title": "20-day high breakout momentum signal",
        "economic_rationale": "Sustained buying pressure breaking prior resistance reflects underreaction to fundamental shifts.",
        "signal_family": "momentum",
        "signal_definition": "(close - ts_min(low, 20)) / (ts_max(high, 20) - ts_min(low, 20) + 1e-6)",
        "source_features": ["close", "high", "low"],
        "target": "forward_return_5d",
        "expected_direction": "positive",
        "holding_horizon": "5d",
        "universe": "commodity_active",
        "frequency": "1d",
        "known_risks": [
            "Low-volatility chop generates frequent false breakouts and whipsaws.",
            "Structural trend exhaustion at extreme macro resistance.",
        ],
        "falsification_conditions": [
            "Information coefficient (IC) mean is less than or equal to 0 across observation window.",
            "Directional consistency is below 50% over rolling 60-day periods.",
            "Long-short spread disappears after accounting for execution slippage.",
        ],
        "proposed_screening_methods": [
            "data_quality_check",
            "cross_sectional_ic_test",
            "monotonicity_analysis",
            "cost_sensitivity_check",
        ],
        "provenance": {
            "origin_type": "human",
            "origin_ref": "research_notes/2026-09-trend_breakout.md",
            "created_by": "fujun",
            "created_at": "2026-09-19T08:00:00.000000Z",
        },
        "related_hypothesis_refs": [],
    }
    data["hypothesis_content_hash"] = compute_hypothesis_content_hash(data)
    return data


# 1. 合法 hypothesis
def test_valid_hypothesis(valid_hypothesis_data: dict[str, Any]):
    validated = validate_hypothesis(valid_hypothesis_data)
    assert validated["hypothesis_id"] == "hypo-momentum-breakout-20d"
    assert validated["revision"] == "rev.1"
    assert len(validated["hypothesis_content_hash"]) == 64

    # Direct Pydantic model validation & semantic hash computation
    model = AlphaHypothesis.model_validate(valid_hypothesis_data)
    assert model.hypothesis_id == "hypo-momentum-breakout-20d"
    sem_hash = compute_semantic_hash(valid_hypothesis_data)
    assert len(sem_hash) == 64
    assert compute_structured_key(valid_hypothesis_data).startswith("family=momentum")


# 2. content hash 稳定
def test_content_hash_stability(valid_hypothesis_data: dict[str, Any]):
    hash1 = compute_hypothesis_content_hash(valid_hypothesis_data)
    hash2 = compute_hypothesis_content_hash(valid_hypothesis_data)
    assert hash1 == hash2
    assert hash1 == valid_hypothesis_data["hypothesis_content_hash"]

    # Re-serialization via JSON retains stable hash
    dumped = json.dumps(valid_hypothesis_data)
    loaded = json.loads(dumped)
    assert compute_hypothesis_content_hash(loaded) == hash1


# 3. 字段顺序改变 hash 不变
def test_field_reordering_invariance(valid_hypothesis_data: dict[str, Any]):
    keys = list(valid_hypothesis_data.keys())
    reversed_keys = list(reversed(keys))
    reordered_data = {k: valid_hypothesis_data[k] for k in reversed_keys}

    original_hash = compute_hypothesis_content_hash(valid_hypothesis_data)
    reordered_hash = compute_hypothesis_content_hash(reordered_data)
    assert original_hash == reordered_hash


# 4. 修改 signal_definition hash 改变
def test_modify_signal_definition_changes_hash(valid_hypothesis_data: dict[str, Any]):
    modified = copy.deepcopy(valid_hypothesis_data)
    modified["signal_definition"] = "(close - ts_mean(close, 20)) / ts_std(close, 20)"
    new_hash = compute_hypothesis_content_hash(modified)
    assert new_hash != valid_hypothesis_data["hypothesis_content_hash"]


# 5. 修改 target hash 改变
def test_modify_target_changes_hash(valid_hypothesis_data: dict[str, Any]):
    modified = copy.deepcopy(valid_hypothesis_data)
    modified["target"] = "forward_return_10d"
    new_hash = compute_hypothesis_content_hash(modified)
    assert new_hash != valid_hypothesis_data["hypothesis_content_hash"]


# 6. 修改 horizon hash 改变
def test_modify_horizon_changes_hash(valid_hypothesis_data: dict[str, Any]):
    modified = copy.deepcopy(valid_hypothesis_data)
    modified["holding_horizon"] = "10d"
    new_hash = compute_hypothesis_content_hash(modified)
    assert new_hash != valid_hypothesis_data["hypothesis_content_hash"]


# 7. exact duplicate 能识别
def test_exact_duplicate_identification(valid_hypothesis_data: dict[str, Any]):
    # Exact duplicate with same content
    dup1 = copy.deepcopy(valid_hypothesis_data)
    assert is_exact_duplicate(valid_hypothesis_data, dup1)

    # Duplicate with different ID and title, but identical scientific proposition
    dup2 = copy.deepcopy(valid_hypothesis_data)
    dup2["hypothesis_id"] = "hypo-momentum-copy-clone"
    dup2["title"] = "Different title for the exact same scientific idea"
    dup2["provenance"]["created_at"] = "2026-09-19T09:30:00.000000Z"
    dup2["hypothesis_content_hash"] = compute_hypothesis_content_hash(dup2)

    assert is_exact_duplicate(valid_hypothesis_data, dup2)


# 8. 不同核心 hypothesis 不误判为 duplicate
def test_different_hypothesis_not_duplicate(valid_hypothesis_data: dict[str, Any]):
    other = copy.deepcopy(valid_hypothesis_data)
    other["signal_definition"] = "(open - close) / open"
    other["signal_family"] = "mean_reversion"
    other["economic_rationale"] = "Intraday overreaction leads to mean reversion."
    other["hypothesis_id"] = "hypo-intraday-reversion"
    other["hypothesis_content_hash"] = compute_hypothesis_content_hash(other)

    assert not is_exact_duplicate(valid_hypothesis_data, other)


# 9. revision 合法例
def test_valid_revision(valid_hypothesis_data: dict[str, Any]):
    updates = {
        "title": "20-day high breakout momentum signal (revised with clearer risks)",
        "known_risks": [
            "Low-volatility chop generates frequent false breakouts and whipsaws.",
            "Structural trend exhaustion at extreme macro resistance.",
            "Illiquid contracts may face prohibitive transaction friction.",
        ],
    }
    child = create_revision(
        valid_hypothesis_data,
        updates,
        created_by="fujun",
        origin_ref="risk clarification review",
    )

    is_valid, msg = is_valid_revision(valid_hypothesis_data, child)
    assert is_valid, msg
    assert child["revision"] == "rev.2"
    assert child["parent_hypothesis_ref"]["hypothesis_id"] == valid_hypothesis_data["hypothesis_id"]
    assert child["parent_hypothesis_ref"]["content_hash"] == valid_hypothesis_data["hypothesis_content_hash"]


# 10. 应属于新 hypothesis 的变化不能冒充 revision
def test_core_change_cannot_disguise_as_revision(valid_hypothesis_data: dict[str, Any]):
    # Mutating signal_definition
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_definition'"):
        create_revision(
            valid_hypothesis_data,
            {"signal_definition": "close / ts_mean(close, 60)"},
            created_by="fujun",
        )

    # Mutating signal_family
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_family'"):
        create_revision(
            valid_hypothesis_data,
            {"signal_family": "mean_reversion"},
            created_by="fujun",
        )

    # Mutating hypothesis_id
    with pytest.raises(ValueError, match="Cannot change hypothesis_id in revision"):
        create_revision(
            valid_hypothesis_data,
            {"hypothesis_id": "hypo-other-id"},
            created_by="fujun",
        )

    # Manually constructed child with mutated target
    fake_child = copy.deepcopy(valid_hypothesis_data)
    fake_child["revision"] = "rev.2"
    fake_child["target"] = "forward_return_20d"  # Core change!
    fake_child["parent_hypothesis_ref"] = {
        "hypothesis_id": valid_hypothesis_data["hypothesis_id"],
        "revision": "rev.1",
        "content_hash": valid_hypothesis_data["hypothesis_content_hash"],
    }
    fake_child["hypothesis_content_hash"] = compute_hypothesis_content_hash(fake_child)

    is_valid, msg = is_valid_revision(valid_hypothesis_data, fake_child)
    assert not is_valid
    assert "Core scientific field 'target' changed" in msg

    # Manually constructed child with mutated signal_family
    fake_child_family = copy.deepcopy(valid_hypothesis_data)
    fake_child_family["revision"] = "rev.2"
    fake_child_family["signal_family"] = "mean_reversion"  # Core change!
    fake_child_family["parent_hypothesis_ref"] = {
        "hypothesis_id": valid_hypothesis_data["hypothesis_id"],
        "revision": "rev.1",
        "content_hash": valid_hypothesis_data["hypothesis_content_hash"],
    }
    fake_child_family["hypothesis_content_hash"] = compute_hypothesis_content_hash(fake_child_family)

    is_valid_fam, msg_fam = is_valid_revision(valid_hypothesis_data, fake_child_family)
    assert not is_valid_fam
    assert "Core scientific field 'signal_family' changed" in msg_fam


def test_omitted_optional_fields_hash_and_idempotency(valid_hypothesis_data: dict[str, Any]):
    """Test that omitting optional fields like related_hypothesis_refs maintains content hash integrity and validator idempotency."""
    minimal = copy.deepcopy(valid_hypothesis_data)
    del minimal["related_hypothesis_refs"]
    minimal["hypothesis_content_hash"] = compute_hypothesis_content_hash(minimal)

    # First validation pass
    validated_once = validate_hypothesis(minimal)
    assert "related_hypothesis_refs" not in validated_once
    assert validated_once["hypothesis_content_hash"] == minimal["hypothesis_content_hash"]

    # Second validation pass (idempotency check)
    validated_twice = validate_hypothesis(validated_once)
    assert validated_twice == validated_once


# 11. 缺 economic_rationale 拒绝
def test_missing_economic_rationale_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["economic_rationale"]
    with pytest.raises(ValueError, match="economic_rationale"):
        validate_hypothesis(invalid)


# 12. 缺 signal_definition 拒绝
def test_missing_signal_definition_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["signal_definition"]
    with pytest.raises(ValueError, match="signal_definition"):
        validate_hypothesis(invalid)


# 13. 缺 falsification_conditions 拒绝
def test_missing_falsification_conditions_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["falsification_conditions"]
    with pytest.raises(ValueError, match="falsification_conditions"):
        validate_hypothesis(invalid)

    invalid_empty = copy.deepcopy(valid_hypothesis_data)
    invalid_empty["falsification_conditions"] = []
    with pytest.raises(ValueError, match="falsification_conditions"):
        validate_hypothesis(invalid_empty)


# 14. hypothesis 中不能混入 Run/Evidence/metrics 类字段
@pytest.mark.parametrize("forbidden_field", [
    "run_id",
    "spec_id",
    "evidence_id",
    "sharpe",
    "ic",
    "score",
    "recommendation",
    "gate_decision",
    "metrics",
    "execution_engine",
])
def test_forbidden_fields_rejected(valid_hypothesis_data: dict[str, Any], forbidden_field: str):
    invalid = copy.deepcopy(valid_hypothesis_data)
    invalid[forbidden_field] = "forbidden_value"
    with pytest.raises(ValueError, match="Forbidden.*field"):
        validate_hypothesis(invalid)


def test_forbidden_result_claim_in_text_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    invalid["economic_rationale"] = "History shows Sharpe=2.5 and this is guaranteed to work."
    with pytest.raises(ValueError, match="Result or evidence claim forbidden"):
        validate_hypothesis(invalid)


# 15. malformed provenance 拒绝
def test_malformed_provenance_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    invalid["provenance"]["origin_type"] = "unsupported_origin"
    with pytest.raises(ValueError):
        validate_hypothesis(invalid)

    invalid_time = copy.deepcopy(valid_hypothesis_data)
    invalid_time["provenance"]["created_at"] = "2026-09-19 12:00:00"  # Not UTC ISO formatted
    with pytest.raises(ValueError, match="UTC timestamp"):
        validate_hypothesis(invalid_time)


# 16. unknown schema/profile fail closed
def test_unknown_schema_or_profile_fail_closed(valid_hypothesis_data: dict[str, Any]):
    invalid_schema = copy.deepcopy(valid_hypothesis_data)
    invalid_schema["schema_version"] = "unknown.schema.v99"
    with pytest.raises(ValueError, match="schema_version"):
        validate_hypothesis(invalid_schema)

    invalid_profile = copy.deepcopy(valid_hypothesis_data)
    invalid_profile["hash_profile"] = "custom-hash-v2"
    with pytest.raises(ValueError, match="hash_profile"):
        validate_hypothesis(invalid_profile)

    # Extra unknown top-level field
    invalid_extra = copy.deepcopy(valid_hypothesis_data)
    invalid_extra["unexpected_custom_tag"] = "test"
    with pytest.raises(ValueError, match="Forbidden extra fields"):
        validate_hypothesis(invalid_extra)


# 17. Structured similarity key (potentially_related, NOT duplicate)
def test_structured_similarity_key(valid_hypothesis_data: dict[str, Any]):
    related = copy.deepcopy(valid_hypothesis_data)
    related["hypothesis_id"] = "hypo-momentum-ema-breakout"
    # Different formula and features, but same family, target, dir, horizon, universe, freq
    related["signal_definition"] = "(close - ta_ema(close, 20)) / ta_atr(14)"
    related["economic_rationale"] = "Exponential moving average breakout indicates momentum trend continuation."
    related["hypothesis_content_hash"] = compute_hypothesis_content_hash(related)

    assert is_potentially_related(valid_hypothesis_data, related)
    assert not is_exact_duplicate(valid_hypothesis_data, related)
