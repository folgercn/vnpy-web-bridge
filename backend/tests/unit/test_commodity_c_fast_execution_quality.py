from __future__ import annotations

import ast
import base64
import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeDTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
    CFastVirtualIntentPlanDTO,
    CFastVirtualIntentPolicyDTO,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services import commodity_c_fast_execution_quality as execution_quality
from app.services.commodity_c_fast_execution_policy import (
    PLACEHOLDER_SIGNATURE,
    unsigned_execution_policy_freeze_payload,
    verify_execution_policy_freeze,
)
from app.services.commodity_c_fast_execution_quality import (
    CFastExecutionQualityFoundationError,
    compile_virtual_intent_plan,
    reload_and_verify_virtual_intent_plan,
    virtual_intent_policy_hash,
    virtual_intent_plan_hash,
)
from app.services.commodity_c_fast_shadow import (
    C_FAST_PRODUCT_SPECS_V1,
    C_FAST_SECTOR_MAP_V1,
    PRODUCTS,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    formula_target_binding_sha256,
    sha256_json,
    unsigned_snapshot_payload,
)


def policy(*, maximum: int = 3) -> CFastVirtualIntentPolicyDTO:
    return CFastVirtualIntentPolicyDTO(
        schema_version="commodity_c_fast_virtual_intent_policy_v1",
        policy_id="c-fast-virtual-policy-foundation",
        max_child_order_lots=maximum,
        horizon_schedule_ms=(250, 1_000, 5_000, 30_000, 60_000),
        decision_book_levels=5,
        protected_price_rule="DEFERRED_TO_DECISION_SNAPSHOT",
        passive_fill_mode="BOUNDS_ONLY_NO_POINT_PROBABILITY",
        policy_authority_state=(
            "UNSIGNED_FOUNDATION_INPUT_REQUIRES_SEPARATE_FREEZE"
        ),
        foundation_only=True,
        collection_authorized=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def test_verified_policy_freeze_still_compiles_non_activatable_plan() -> None:
    private_key = Ed25519PrivateKey.generate()
    frozen_policy = policy()
    core = {
        "schema_version": "commodity_c_fast_execution_policy_freeze_v1",
        "freeze_id": "c-fast-policy-freeze-integration-v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "policy_scope": "EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY",
        "policy": frozen_policy.model_dump(mode="json"),
        "policy_hash": virtual_intent_policy_hash(frozen_policy),
        "frozen_at_utc": "2026-07-24T15:30:00Z",
        "reviewer_role": "human_execution_policy_reviewer",
        "human_reviewed": True,
        "policy_frozen": True,
        "protected_price_rule_state": "DEFERRED_NOT_COLLECTION_READY",
        "p0_pass_required_before_collection": True,
        "foundation_only": True,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
        "signer_key_id": "c-fast-policy-freeze-signer-1",
        "signature": PLACEHOLDER_SIGNATURE,
    }
    draft = CFastExecutionPolicyFreezeDTO.model_validate(core)
    signed = draft.model_dump(mode="json")
    signed["signature"] = base64.b64encode(
        private_key.sign(
            canonical_json(
                unsigned_execution_policy_freeze_payload(draft)
            )
        )
    ).decode("ascii")
    freeze = CFastExecutionPolicyFreezeDTO.model_validate(signed)
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    receipt = verify_execution_policy_freeze(
        freeze,
        trusted_public_keys={
            freeze.signer_key_id: {
                "public_key_base64": public_key,
                "purpose": "execution_quality_policy_freeze_signer",
            }
        },
    )
    accepted_snapshot, snapshot_hash = snapshot(
        {"cu": (None, 0, "SHFE.cu2612", 4)}
    )

    plan = compile_virtual_intent_plan(
        snapshot=accepted_snapshot,
        snapshot_hash=snapshot_hash,
        policy=freeze.policy,
    )

    assert receipt.policy_hash == plan.policy_hash
    assert receipt.policy_frozen is True
    assert receipt.collection_authorized is False
    assert plan.activation_state == "FOUNDATION_ONLY_NOT_ACTIVATABLE"
    assert plan.collection_authorized is False
    assert plan.dispatch_allowed is False


def snapshot(
    changes: dict[str, tuple[str | None, int, str, int]] | None = None,
) -> tuple[CommodityCFastShadowDTO, str]:
    changes = changes or {}
    targets = []
    for product in PRODUCTS:
        spec = C_FAST_PRODUCT_SPECS_V1[product]
        default_contract = f"{spec['exchange']}.{product}2612"
        previous_contract, previous_quantity, exact_contract, target_quantity = (
            changes.get(product, (None, 0, default_contract, 0))
        )
        targets.append(
            {
                "product": product,
                "sector": C_FAST_SECTOR_MAP_V1[product],
                "trend_21_sign": 0,
                "trend_63_sign": 0,
                "trend_126_sign": 0,
                "source_score": 0.0,
                "vol60_annualized": 0.2,
                "raw_risk_score": 0.0,
                "source_target_weight": 0.0,
                "buffered_target_weight": 0.0,
                "previous_exact_contract": previous_contract,
                "exact_contract": exact_contract,
                "previous_target_quantity": previous_quantity,
                "target_quantity": target_quantity,
                "reference_open_price": 100.0,
                "reference_price_field": "official_open",
                "reference_price_observed_at_utc": "2026-09-01T01:01:00Z",
                "reference_price_source_sha256": "f" * 64,
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "pit_main_exact_contract": exact_contract,
                "pit_main_dte": 100,
                "pit_main_official_last_trading_day": "2026-12-15",
                "pit_main_following_official_day": "2026-09-02",
                "pit_main_following_dte": 99,
                "pit_main_target_position_allowed": True,
                "pit_main_roll": bool(
                    previous_contract
                    and previous_contract != exact_contract
                ),
            }
        )
    payload = {
        "schema_version": "commodity_c_fast_cross_section_neutral_shadow_v1",
        "snapshot_id": "c-fast-2026-08-foundation",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "frozen_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "frozen_rule_sha256": (
            "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
        ),
        "mode": "shadow_only",
        "execution_lane": "official_forward",
        "frequency": "MONTHLY",
        "pit_main_definition": "DAILY_PIT_OI_MAIN",
        "trend_horizons_official_days": [21, 63, 126],
        "volatility_lookback_official_days": 60,
        "volatility_floor": 0.05,
        "virtual_nav_cny": 20_000_000,
        "source_month": "2026-08",
        "source_official_day": "2026-08-31",
        "execution_day": "2026-09-01",
        "input_cutoff_at_utc": "2026-08-31T07:00:00Z",
        "snapshot_created_at_utc": "2026-09-01T01:02:00Z",
        "source_is_month_last_official_day": True,
        "execution_is_next_cross_month_official_day": True,
        "input_cutoff_after_source_close": True,
        "calendar_alignment": "SIGNED_ASSERTION_NOT_RUNTIME_VERIFIED",
        "allocator_output_validation": (
            "SIGNED_ALLOCATOR_OUTPUT_NOT_RECOMPUTED"
        ),
        "daily_roll_alignment": (
            "SIGNED_DAILY_ROLL_ASSERTION_NOT_RUNTIME_VERIFIED"
        ),
        "previous_snapshot_hash": None,
        "research_bindings": {
            "research_contract_sha256": (
                "c1639d5f7714fd3989da799ece2743ca392ac8a8edad64a7f1238dd2e51c9d31"
            ),
            "formula_builder_sha256": (
                "7ebe1529173b46cbae17680d872680c7bb7bae39863d09b2d9a37183828a43a9"
            ),
            "target_builder_sha256": (
                "40fd1a27bb1e6dedf483a4c7dcec6d181d325d9c9958d6620f79f04fbdb696db"
            ),
            "historical_fresh_exact_runner_sha256": (
                "7e75ad73a8b037b80937cb449b863305753ec7b2860568422906fd55bb2a2fbe"
            ),
            "snapshot_producer_status": (
                "NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY"
            ),
            "research_manifest_sha256": "c" * 64,
            "calendar_authority_sha256": (
                "57b5341b45cb92d7e991f028d780580ab712e87c9cc86c7036917b638cddc76f"
            ),
            "allocator_runner_sha256": (
                "66497283d1c35383d620ef3c92f2c23316046a9b4b0cbe6f1dcf3f361041f307"
            ),
            "guardband_runner_sha256": (
                "e9871b26af4f0ebebed6e697e8fa1c3064bc3d6557df739bcef9b80697eab353"
            ),
            "allocator_manifest_sha256": (
                "8595fb3d4df57e4b6db0e8a64b02bbc0e90d243d0e6a93060837f5a748c8057f"
            ),
            "allocation_evidence_sha256": "a" * 64,
            "daily_roll_evidence_sha256": "b" * 64,
        },
        "guardrails": {
            "source_product_abs_cap": 0.2,
            "source_sector_gross_cap": 0.35,
            "source_portfolio_gross_cap": 1.0,
            "source_target_net": 0.0,
            "buffered_product_abs_cap": 0.12,
            "buffered_sector_gross_cap": 0.27,
            "buffered_portfolio_gross_cap": 0.8,
            "buffered_target_net": 0.0,
            "integer_product_abs_hard_cap": 0.15,
            "integer_sector_gross_hard_cap": 0.35,
            "integer_portfolio_gross_hard_cap": 1.0,
            "integer_abs_net_hard_cap": 0.1,
        },
        "allocator": {
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": 2,
            "beam_width": 2048,
            "net_error_penalty": 1.0,
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
        },
        "formula_target_binding_sha256": "0" * 64,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "dynamic_selection_allowed": False,
        "production_allowed": False,
        "targets": targets,
        "signer_key_id": "c-fast-research-1",
        "signature": "A" * 88,
    }
    draft = CommodityCFastShadowDTO.model_validate(payload)
    payload["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(draft)
    )
    result = CommodityCFastShadowDTO.model_validate(payload)
    return result, sha256_json(unsigned_snapshot_payload(result))


def test_compiler_preserves_close_before_open_split_and_replay_identity() -> None:
    source, source_hash = snapshot(
        {
            "ag": ("SHFE.ag2612", 7, "SHFE.ag2612", -4),
            "al": ("SHFE.al2612", 4, "SHFE.al2612", 1),
            "cu": ("SHFE.cu2611", -5, "SHFE.cu2612", 2),
            "rb": ("SHFE.rb2612", -2, "SHFE.rb2612", -5),
        }
    )

    result = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(maximum=3),
    )
    repeated = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(maximum=3),
    )

    assert result == repeated
    assert result.plan_hash == virtual_intent_plan_hash(result)
    assert result.activation_state == "FOUNDATION_ONLY_NOT_ACTIVATABLE"
    assert result.collection_authorized is False
    assert result.dispatch_allowed is False
    assert len({row.intent_id for row in result.intents}) == len(result.intents)
    phases = [row.phase for row in result.intents]
    assert phases == sorted(
        phases, key={"virtual_close": 0, "virtual_open": 1}.get
    )

    legs = {}
    for row in result.intents:
        legs.setdefault(row.leg_id, []).append(row)
        assert row.lots <= 3
        assert row.virtual_only is True
        assert row.authority_granted is False
    reconstructed = {
        (
            rows[0].product,
            rows[0].phase,
            rows[0].exact_contract,
        ): sum(row.signed_quantity_delta for row in rows)
        for rows in legs.values()
    }
    assert reconstructed == {
        ("ag", "virtual_close", "SHFE.ag2612"): -7,
        ("al", "virtual_close", "SHFE.al2612"): -3,
        ("cu", "virtual_close", "SHFE.cu2611"): 5,
        ("ag", "virtual_open", "SHFE.ag2612"): -4,
        ("cu", "virtual_open", "SHFE.cu2612"): 2,
        ("rb", "virtual_open", "SHFE.rb2612"): -3,
    }


def test_zero_delta_snapshot_produces_deterministic_empty_plan() -> None:
    source, source_hash = snapshot()

    result = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(),
    )

    assert result.intents == ()
    assert result.plan_hash == virtual_intent_plan_hash(result)


def test_policy_is_bound_into_intents_and_plan_hash() -> None:
    source, source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 7)}
    )

    small = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(maximum=2),
    )
    large = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(maximum=4),
    )

    assert small.policy_hash != large.policy_hash
    assert small.plan_hash != large.plan_hash
    assert [row.lots for row in small.intents] == [2, 2, 2, 1]
    assert [row.lots for row in large.intents] == [4, 3]


def test_compiler_rejects_snapshot_receipt_hash_mismatch() -> None:
    source, _source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 1)}
    )

    with pytest.raises(
        CFastExecutionQualityFoundationError,
        match="SNAPSHOT_HASH_MISMATCH",
    ) as exc_info:
        compile_virtual_intent_plan(
            snapshot=source,
            snapshot_hash="0" * 64,
            policy=policy(),
        )

    assert exc_info.value.code == "SNAPSHOT_HASH_MISMATCH"


def test_compiler_rejects_formula_binding_mismatch() -> None:
    source, _source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 1)}
    )
    tampered = source.model_copy(
        update={"formula_target_binding_sha256": "0" * 64}
    )
    tampered_hash = sha256_json(unsigned_snapshot_payload(tampered))

    with pytest.raises(
        CFastExecutionQualityFoundationError,
        match="FORMULA_TARGET_BINDING_MISMATCH",
    ) as exc_info:
        compile_virtual_intent_plan(
            snapshot=tampered,
            snapshot_hash=tampered_hash,
            policy=policy(),
        )

    assert exc_info.value.code == "FORMULA_TARGET_BINDING_MISMATCH"


@pytest.mark.parametrize(
    "target_change",
    [
        (None, 0, "SHFE.ag2612", 1_000_000_000),
        ("SHFE.ag2612", -501, "SHFE.ag2612", 0),
    ],
)
def test_quantity_limit_fails_before_child_split(
    monkeypatch: pytest.MonkeyPatch,
    target_change: tuple[str | None, int, str, int],
) -> None:
    source, source_hash = snapshot({"ag": target_change})
    split_called = False

    def forbidden_split(*_args) -> tuple[int, ...]:
        nonlocal split_called
        split_called = True
        raise AssertionError("quantity bound must run before child split")

    monkeypatch.setattr(
        execution_quality,
        "_split_lots",
        forbidden_split,
    )

    with pytest.raises(
        CFastExecutionQualityFoundationError,
        match="TARGET_QUANTITY_LIMIT",
    ) as exc_info:
        compile_virtual_intent_plan(
            snapshot=source,
            snapshot_hash=source_hash,
            policy=policy(maximum=1),
        )

    assert exc_info.value.code == "TARGET_QUANTITY_LIMIT"
    assert split_called is False


def test_strict_dtos_reject_order_adjacent_fields_and_authority_escalation() -> None:
    source, source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 1)}
    )
    plan = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(),
    )
    intent_payload = plan.intents[0].model_dump(mode="json")
    intent_payload["reference"] = "must-not-be-order-compatible"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CFastVirtualIntentDTO.model_validate(intent_payload)

    policy_payload = policy().model_dump(mode="json")
    policy_payload["dispatch_allowed"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        CFastVirtualIntentPolicyDTO.model_validate(policy_payload)


def test_plan_hash_detects_post_compile_tampering() -> None:
    source, source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 1)}
    )
    plan = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(),
    )
    tampered_intent = plan.intents[0].model_copy(
        update={
            "exact_contract": "SHFE.ag2613",
            "intent_id": (
                "cfast-virtual-intent-v1-" + "1" * 64
            ),
        }
    )
    tampered_plan = plan.model_copy(update={"intents": (tampered_intent,)})

    assert virtual_intent_plan_hash(tampered_plan) != plan.plan_hash


def reloadable_plan_payload() -> dict:
    source, source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 4)}
    )
    plan = compile_virtual_intent_plan(
        snapshot=source,
        snapshot_hash=source_hash,
        policy=policy(),
    )
    return json.loads(plan.model_dump_json())


def test_json_dump_reload_revalidates_all_hash_bindings() -> None:
    payload = reloadable_plan_payload()

    reloaded = CFastVirtualIntentPlanDTO.model_validate(payload)

    assert reloaded.model_dump(mode="json") == payload
    assert reloaded.plan_hash == virtual_intent_plan_hash(reloaded)


def test_derivation_reload_accepts_exact_recompiled_plan() -> None:
    source, source_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 4)}
    )
    payload = reloadable_plan_payload()

    reloaded = reload_and_verify_virtual_intent_plan(
        payload,
        accepted_snapshot=source,
        snapshot_receipt=source_hash,
        frozen_policy=policy(),
    )

    assert reloaded.model_dump(mode="json") == payload


def test_derivation_reload_rejects_other_self_consistent_snapshot_plan() -> None:
    accepted, accepted_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 4)}
    )
    other, other_hash = snapshot(
        {"ag": (None, 0, "SHFE.ag2612", 5)}
    )
    other_plan = compile_virtual_intent_plan(
        snapshot=other,
        snapshot_hash=other_hash,
        policy=policy(),
    )
    payload = json.loads(other_plan.model_dump_json())
    assert CFastVirtualIntentPlanDTO.model_validate(payload) == other_plan

    with pytest.raises(
        CFastExecutionQualityFoundationError,
        match="PLAN_DERIVATION_MISMATCH",
    ) as exc_info:
        reload_and_verify_virtual_intent_plan(
            payload,
            accepted_snapshot=accepted,
            snapshot_receipt=accepted_hash,
            frozen_policy=policy(),
        )

    assert exc_info.value.code == "PLAN_DERIVATION_MISMATCH"


def test_json_reload_rejects_policy_hash_tamper() -> None:
    payload = reloadable_plan_payload()
    payload["policy_hash"] = "1" * 64

    with pytest.raises(ValidationError, match="policy_hash mismatch"):
        CFastVirtualIntentPlanDTO.model_validate(payload)


def test_json_reload_rejects_leg_id_tamper() -> None:
    payload = reloadable_plan_payload()
    payload["intents"][0]["leg_id"] = (
        "cfast-virtual-leg-v1-" + "1" * 64
    )

    with pytest.raises(ValidationError, match="leg_id hash mismatch"):
        CFastVirtualIntentPlanDTO.model_validate(payload)


def test_json_reload_rejects_intent_id_tamper() -> None:
    payload = reloadable_plan_payload()
    payload["intents"][0]["intent_id"] = (
        "cfast-virtual-intent-v1-" + "1" * 64
    )

    with pytest.raises(ValidationError, match="intent_id hash mismatch"):
        CFastVirtualIntentPlanDTO.model_validate(payload)


def test_json_reload_rejects_plan_hash_tamper() -> None:
    payload = reloadable_plan_payload()
    payload["plan_hash"] = "1" * 64

    with pytest.raises(ValidationError, match="plan_hash mismatch"):
        CFastVirtualIntentPlanDTO.model_validate(payload)


def test_json_reload_rejects_more_than_ten_thousand_intents() -> None:
    payload = reloadable_plan_payload()
    payload["intents"] = [payload["intents"][0]] * 10_001

    with pytest.raises(ValidationError, match="at most 10000 items"):
        CFastVirtualIntentPlanDTO.model_validate(payload)


def test_foundation_service_has_no_runtime_or_execution_imports() -> None:
    service_path = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "services"
        / "commodity_c_fast_execution_quality.py"
    )
    tree = ast.parse(service_path.read_text(encoding="utf-8"))
    imports = {
        (
            node.module
            if isinstance(node, ast.ImportFrom)
            else alias.name
        )
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden = {
        "app.services.commodity_simnow",
        "app.services.market_data_service",
        "app.services.tick_persistence",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "psycopg",
        "questdb",
    }

    assert imports.isdisjoint(forbidden)
    assert not any(
        isinstance(node, (ast.AsyncFunctionDef, ast.Await))
        for node in ast.walk(tree)
    )


def test_fixture_datetime_is_timezone_aware() -> None:
    source, _source_hash = snapshot()

    assert source.snapshot_created_at_utc == datetime(
        2026, 9, 1, 1, 2, tzinfo=timezone.utc
    )
    assert source.execution_day == date(2026, 9, 1)
