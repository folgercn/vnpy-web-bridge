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


# P1-1: 缺失、空字符串、错误/篡改 hash 均 fail closed；合法生成/验证保持幂等
def test_hypothesis_content_hash_fail_closed_and_idempotent(valid_hypothesis_data: dict[str, Any]):
    # 1. 缺失 hypothesis_content_hash
    missing = copy.deepcopy(valid_hypothesis_data)
    del missing["hypothesis_content_hash"]
    with pytest.raises(ValueError, match="Missing required field: 'hypothesis_content_hash'"):
        validate_hypothesis(missing)

    # 2. 空字符串 hypothesis_content_hash
    empty_hash = copy.deepcopy(valid_hypothesis_data)
    empty_hash["hypothesis_content_hash"] = ""
    with pytest.raises(ValueError, match="hypothesis_content_hash must be non-empty string"):
        validate_hypothesis(empty_hash)

    # 3. 非法格式 hash (非 64 字符十六进制)
    invalid_format = copy.deepcopy(valid_hypothesis_data)
    invalid_format["hypothesis_content_hash"] = "not-a-valid-sha256"
    with pytest.raises(ValueError, match="64-character lowercase hex SHA-256 digest"):
        validate_hypothesis(invalid_format)

    # 4. 篡改/不匹配 hash
    tampered = copy.deepcopy(valid_hypothesis_data)
    tampered["hypothesis_content_hash"] = "0" * 64
    with pytest.raises(ValueError, match="hypothesis_content_hash mismatch"):
        validate_hypothesis(tampered)

    # 5. 合法生成与多次验证保持严格幂等
    first_pass = validate_hypothesis(valid_hypothesis_data)
    second_pass = validate_hypothesis(first_pass)
    third_pass = validate_hypothesis(second_pass)
    assert first_pass == valid_hypothesis_data
    assert second_pass == first_pass
    assert third_pass == second_pass


# P1-2: 统一 Exact Duplicate 科学身份与 CORE_SCIENTIFIC_FIELDS
def test_falsification_revision_preserves_scientific_identity(valid_hypothesis_data: dict[str, Any]):
    """Modifying falsification_conditions is a valid revision that preserves exact scientific identity."""
    original_sem_hash = compute_semantic_hash(valid_hypothesis_data)
    original_content_hash = valid_hypothesis_data["hypothesis_content_hash"]

    # Create revision modifying only falsification_conditions and known_risks
    revised = create_revision(
        valid_hypothesis_data,
        {
            "falsification_conditions": [
                "Information coefficient (IC) mean is <= 0 across window.",
                "Directional consistency is below 45% over rolling 90-day periods.",
                "Trading friction and fees exceed 80% of gross alpha.",
            ],
            "known_risks": [
                "Low-volatility chop generates frequent false breakouts.",
                "Structural trend exhaustion at extreme resistance.",
                "Execution slippage in stressed liquidity regimes.",
            ],
        },
        created_by="fujun",
        origin_ref="falsification criteria clarification",
    )

    # 1. Revision is valid
    is_valid, msg = is_valid_revision(valid_hypothesis_data, revised)
    assert is_valid, msg

    # 2. Revision record content hash changes (different record snapshot)
    assert revised["hypothesis_content_hash"] != original_content_hash

    # 3. Scientific identity hash remains identical (same Alpha Idea)
    assert compute_semantic_hash(revised) == original_sem_hash

    # 4. Exact duplicate recognises them as the same scientific proposition
    assert is_exact_duplicate(valid_hypothesis_data, revised)


def test_core_field_mutation_changes_identity_and_rejects_revision(valid_hypothesis_data: dict[str, Any]):
    """Mutating any CORE_SCIENTIFIC_FIELDS changes scientific identity and cannot disguise as revision."""
    original_sem_hash = compute_semantic_hash(valid_hypothesis_data)

    core_mutations = [
        ("signal_family", "mean_reversion"),
        ("signal_definition", "(close - ts_mean(close, 10)) / ts_std(close, 10)"),
        ("source_features", ["close", "volume"]),
        ("target", "forward_return_20d"),
        ("expected_direction", "negative"),
        ("holding_horizon", "20d"),
        ("universe", "equity_index_futures"),
        ("frequency", "1h"),
        ("economic_rationale", "Completely different macro causal theory."),
        ("signal_type", "signed_scalar"),
    ]

    for field_name, new_val in core_mutations:
        # Cannot disguise as revision via create_revision
        with pytest.raises(ValueError, match=f"Cannot mutate core scientific field {field_name!r}"):
            create_revision(
                valid_hypothesis_data,
                {field_name: new_val},
                created_by="fujun",
            )

        # Manually constructed child fails is_valid_revision
        fake_child = copy.deepcopy(valid_hypothesis_data)
        fake_child["revision"] = "rev.2"
        fake_child[field_name] = new_val
        fake_child["parent_hypothesis_ref"] = {
            "hypothesis_id": valid_hypothesis_data["hypothesis_id"],
            "revision": "rev.1",
            "content_hash": valid_hypothesis_data["hypothesis_content_hash"],
        }
        fake_child["hypothesis_content_hash"] = compute_hypothesis_content_hash(fake_child)

        is_valid, msg = is_valid_revision(valid_hypothesis_data, fake_child)
        assert not is_valid
        assert f"Core scientific field {field_name!r} changed" in msg

        # Scientific identity hash must change
        assert compute_semantic_hash(fake_child) != original_sem_hash

        # Not an exact duplicate
        assert not is_exact_duplicate(valid_hypothesis_data, fake_child)


# 11. 缺 economic_rationale 拒绝
def test_missing_economic_rationale_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["economic_rationale"]
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="economic_rationale"):
        validate_hypothesis(invalid)


# 12. 缺 signal_definition 拒绝
def test_missing_signal_definition_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["signal_definition"]
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="signal_definition"):
        validate_hypothesis(invalid)


# 13. 缺 falsification_conditions 拒绝
def test_missing_falsification_conditions_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    del invalid["falsification_conditions"]
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="falsification_conditions"):
        validate_hypothesis(invalid)

    invalid_empty = copy.deepcopy(valid_hypothesis_data)
    invalid_empty["falsification_conditions"] = []
    invalid_empty["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid_empty)
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
    # Even with hash matching, forbidden field must be rejected
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="Forbidden.*field"):
        validate_hypothesis(invalid)


def test_forbidden_result_claim_in_text_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    invalid["economic_rationale"] = "History shows Sharpe=2.5 and this is guaranteed to work."
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError, match="Result or evidence claim forbidden"):
        validate_hypothesis(invalid)


# 15. malformed provenance 拒绝
def test_malformed_provenance_rejected(valid_hypothesis_data: dict[str, Any]):
    invalid = copy.deepcopy(valid_hypothesis_data)
    invalid["provenance"]["origin_type"] = "unsupported_origin"
    invalid["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid)
    with pytest.raises(ValueError):
        validate_hypothesis(invalid)

    invalid_time = copy.deepcopy(valid_hypothesis_data)
    invalid_time["provenance"]["created_at"] = "2026-09-19 12:00:00"  # Not UTC ISO formatted
    invalid_time["hypothesis_content_hash"] = compute_hypothesis_content_hash(invalid_time)
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


def test_signal_type_is_frozen_core_scientific_field_and_revision_fails_closed(valid_hypothesis_data: dict[str, Any]):
    """P1: signal_type belongs to CORE_SCIENTIFIC_FIELDS and is frozen; cannot mutate across revisions."""
    # 1. Base hypothesis with signal_type="unspecified"
    base_unspecified = copy.deepcopy(valid_hypothesis_data)
    base_unspecified["signal_type"] = "unspecified"
    base_unspecified["hypothesis_content_hash"] = compute_hypothesis_content_hash(base_unspecified)
    validate_hypothesis(base_unspecified)

    # 1a. Attempt revision from unspecified -> signed_scalar via create_revision must fail closed
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_type' in a revision"):
        create_revision(base_unspecified, {"signal_type": "signed_scalar"}, created_by="fujun")

    # 1b. Attempt revision from None -> signed_scalar via create_revision must fail closed
    base_none = copy.deepcopy(valid_hypothesis_data)
    assert base_none.get("signal_type") is None
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_type' in a revision"):
        create_revision(base_none, {"signal_type": "signed_scalar"}, created_by="fujun")

    # 2. Base hypothesis with signal_type="signed_scalar"
    base_signed = copy.deepcopy(valid_hypothesis_data)
    base_signed["signal_type"] = "signed_scalar"
    base_signed["hypothesis_content_hash"] = compute_hypothesis_content_hash(base_signed)
    validate_hypothesis(base_signed)

    # 2a. Attempt revision from signed_scalar -> unspecified must fail closed
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_type' in a revision"):
        create_revision(base_signed, {"signal_type": "unspecified"}, created_by="fujun")

    # 2b. Attempt revision from signed_scalar -> None must fail closed
    with pytest.raises(ValueError, match="Cannot mutate core scientific field 'signal_type' in a revision"):
        create_revision(base_signed, {"signal_type": None}, created_by="fujun")

    # 2c. Manually constructed child bypassing create_revision is rejected by is_valid_revision
    fake_child = copy.deepcopy(base_signed)
    fake_child["revision"] = "rev.2"
    fake_child["signal_type"] = "unspecified"
    fake_child["parent_hypothesis_ref"] = {
        "hypothesis_id": base_signed["hypothesis_id"],
        "revision": "rev.1",
        "content_hash": base_signed["hypothesis_content_hash"],
    }
    fake_child["hypothesis_content_hash"] = compute_hypothesis_content_hash(fake_child)
    is_valid, msg = is_valid_revision(base_signed, fake_child)
    assert not is_valid
    assert "Core scientific field 'signal_type' changed: cannot disguise as revision" in msg

    # 3. Legitimate non-core revision with identical signal_type succeeds
    legal_rev_signed = create_revision(
        base_signed,
        {"title": "Updated Title for Same Idea", "signal_type": "signed_scalar"},
        created_by="fujun",
    )
    is_valid, msg = is_valid_revision(base_signed, legal_rev_signed)
    assert is_valid, msg
    assert compute_semantic_hash(base_signed) == compute_semantic_hash(legal_rev_signed)

    # 4. Semantic hash differentiates signal_type variants (distinct scientific identities)
    hash_none = compute_semantic_hash(base_none)
    hash_unspecified = compute_semantic_hash(base_unspecified)
    hash_signed = compute_semantic_hash(base_signed)
    assert hash_signed != hash_unspecified
    assert hash_signed != hash_none
    assert hash_unspecified != hash_none

    # 5. Pydantic model instance entrypoint validation cannot bypass
    model_signed = AlphaHypothesis.model_validate(base_signed)
    is_valid_model, msg_model = is_valid_revision(model_signed.model_dump(exclude_none=True), fake_child)
    assert not is_valid_model
    assert "Core scientific field 'signal_type' changed" in msg_model
