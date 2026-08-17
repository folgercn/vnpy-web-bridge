from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.execution import (
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
)
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    build_static_core_equal_keyless_target_decision,
)
from app.execution.final_runtime import (
    FinalExecutionRuntime,
    InMemoryTargetPlanRepository,
)
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
)
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    TargetPlan,
    before_position_projection_hash,
    build_trusted_keyless_target_plan,
    build_trusted_keyless_target_plan_v2,
    sha256_json,
    target_position_projection_hash,
)
from shared.trust_contracts.v1 import canonical_json_line

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_relative_vol_snapshot_producer as thermostat_producer
import commodity_static_core_equal_pure_producer as static_producer
from test_commodity_relative_vol_snapshot_producer import (
    source_view as thermostat_source_view,
)
from test_commodity_static_core_equal_pure_producer import (
    source_view as static_source_view,
)


def _position(*, volume: int = 1) -> dict[str, dict]:
    return {
        "rb2601.SHFE.LONG": {
            "gateway_name": "CTP",
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": volume,
        }
    }


def _plan_fields() -> dict:
    before = before_position_projection_hash(
        {}, account_scope="account:windows", environment="SIMNOW"
    )
    after = target_position_projection_hash(
        _position(), account_scope="account:windows", environment="SIMNOW"
    )
    return {
        "plan_id": "static-core-keyless-plan-0001",
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "gateway_name": "CTP",
        "scope": TRUSTED_KEYLESS_SIMNOW_SCOPE,
        "generated_at": "2030-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "phase": "OPEN",
        "expected_before_position_hash": before,
        "expected_after_position_hash": after,
        "orders": [
            {
                "symbol": "rb2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0,
                "offset": "OPEN",
                "reference": "static-core-order-0001",
                "gateway_name": "CTP",
            }
        ],
    }


def _v2_plan() -> dict:
    return build_trusted_keyless_target_plan_v2(
        **_plan_fields(),
        lineage={
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": "c" * 64,
        },
    )


@lru_cache(maxsize=1)
def _static_outputs() -> tuple[dict, dict, dict]:
    result = static_producer.produce_research_artifacts(static_source_view())
    return (
        dict(result.producer_projection),
        json.loads(result.artifacts["freeze_contract"]),
        json.loads(result.artifacts["target_evidence"]),
    )


def _position_manager_snapshot(
    target_evidence: dict, *, selected: dict[str, int] | None = None
) -> dict:
    selected = {"ag": 1, "au": -1} if selected is None else selected
    rows = []
    for baseline in target_evidence["targets"]:
        product = baseline["product"]
        rows.append(
            {
                "product": product,
                "exact_contract": baseline["exact_contract"],
                "baseline_target_quantity": baseline["target_quantity"],
                "shadow_target_quantity": selected.get(
                    product, baseline["target_quantity"]
                ),
                "baseline_source_target_weight": baseline["source_target_weight"],
                "shadow_source_target_weight": baseline["source_target_weight"],
                "baseline_buffered_target_weight": baseline["buffered_target_weight"],
                "shadow_buffered_target_weight": baseline["buffered_target_weight"],
                "reference_open_price": baseline["reference_open_price"],
                "multiplier": baseline["multiplier"],
                "price_tick": baseline["price_tick"],
            }
        )
    return {
        "schema_version": "commodity_relative_vol_position_manager_shadow_v2",
        "snapshot_id": "relative-vol-shadow-20300101-a01",
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "sector_map_id": "POSITION_MANAGER_SECTOR_MAP_V1",
        "mode": "shadow_only",
        "execution_lane": "simnow_shakedown",
        "countable_forward": False,
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "baseline_batch_hash": "f" * 64,
        "source_month": "2030-01",
        "execution_day": target_evidence["execution_day"],
        "input_cutoff_day": "2029-12-31",
        "fast_lookback_days": 21,
        "slow_lookback_days": 126,
        "annualization_days": 252,
        "fast_annual_vol": 0.2,
        "slow_annual_vol": 0.2,
        "scale_min": 0.8,
        "scale_max": 1.2,
        "raw_scale": 1.0,
        "continuity_mode": "genesis",
        "previous_snapshot_hash": None,
        "previous_smoothed_scale": 1.0,
        "smoothing_alpha": 0.5,
        "smoothed_scale": 1.0,
        "daily_auto_reweight": False,
        "guardband_reapplied": True,
        "authority_granted": False,
        "dispatch_allowed": False,
        "targets": rows,
        "signer_key_id": "not-signed-runtime-input",
    }


@lru_cache(maxsize=1)
def _actual_thermostat_result():
    _projection, _freeze, target = _static_outputs()
    source = thermostat_source_view(
        source_month="2026-07",
        execution_day=date(2026, 8, 3),
        execution_lane="simnow_shakedown",
    )
    source["baseline_batch"]["targets"] = [
        {
            "product": row["product"],
            "previous_exact_contract": None,
            "previous_target_quantity": 0,
            "exact_contract": row["exact_contract"],
            "target_quantity": row["target_quantity"],
            "source_target_weight": row["source_target_weight"],
            "buffered_target_weight": row["buffered_target_weight"],
            "reference_open_price": row["reference_open_price"],
            "multiplier": row["multiplier"],
            "price_tick": row["price_tick"],
        }
        for row in target["targets"]
    ]
    source["baseline_batch_hash"] = hashlib.sha256(
        thermostat_producer.canonical_json(
            {
                key: value
                for key, value in source["baseline_batch"].items()
                if key != "signature"
            }
        )
    ).hexdigest()
    return source, thermostat_producer.produce_snapshot(source)


def _snapshot(positions: dict[str, dict] | None = None) -> GatewaySnapshot:
    rows = {} if positions is None else positions
    return GatewaySnapshot(
        snapshot_id="snapshot-issue353-0001",
        generation=1,
        connected=True,
        active_order_count=0,
        position_snapshot_hash=sha256_json(rows),
        orders={},
        positions=rows,
        account_scope="account:windows",
        environment="SIMNOW",
        fresh=True,
    )


def _projection_with_artifact(projection: dict, *, role: str, payload: dict) -> dict:
    rebound = json.loads(canonical_json_line(projection))
    for item in rebound["artifact_digests"]:
        if item["role"] == role:
            item["sha256"] = sha256_json(payload)
            return rebound
    raise AssertionError(f"missing fixture artifact role: {role}")


def _decision(
    *,
    product: str = "ag",
    positions: dict[str, dict] | None = None,
    run_id: str = "issue353-run-0001",
    selected: dict[str, int] | None = None,
):
    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=selected)
    return build_static_core_equal_keyless_target_decision(
        static_core_equal_projection=projection,
        static_core_equal_freeze_contract=freeze,
        static_core_equal_target_evidence=target,
        position_manager_snapshot=manager,
        position_manager_sha256=sha256_json(manager),
        current_facts=_snapshot(positions),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        product=product,
        run_id=run_id,
        expires_at="2099-01-01T00:00:00Z",
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )


def test_v1_replay_is_byte_identical_and_v2_has_only_the_exact_new_lineage() -> None:
    v1_fields = _plan_fields()
    v1_fields["plan_id"] = "keyless-target-plan-0001"
    v1_fields["orders"][0].update(
        {
            "symbol": "rb2601",
            "price": 3500.0,
            "reference": "keyless-order-0001",
        }
    )
    v1 = build_trusted_keyless_target_plan(
        **v1_fields,
        lineage={"map_sha256": "a" * 64, "c_fast_sha256": "b" * 64},
    )
    assert v1["schema_version"] == KEYLESS_TARGET_PLAN_SCHEMA_VERSION
    assert v1["plan_hash"] == (
        "8b9b7389fa6e16180f952de2f3af9cef9c00a3725100fe9dd5bbf5889c26ebfb"
    )
    assert hashlib.sha256(canonical_json_line(v1)).hexdigest() == (
        "d8aab27d88f1b4e1e6bc0357f27fff6a728ea905b273d75c65dfa16f2c53e0af"
    )

    v2 = _v2_plan()
    assert v2["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert set(v2["lineage"]) == {
        "static_core_equal_sha256",
        "position_manager_sha256",
        "final_target_sha256",
    }
    assert TargetPlan.from_mapping(v2).as_dict() == v2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda lineage: lineage.pop("position_manager_sha256"),
        lambda lineage: lineage.__setitem__("map_sha256", "d" * 64),
        lambda lineage: lineage.__setitem__("final_target_sha256", "D" * 64),
    ],
)
def test_v2_rejects_missing_extra_and_noncanonical_lineage(mutation) -> None:
    raw = _v2_plan()
    mutation(raw["lineage"])
    raw["plan_hash"] = sha256_json(
        {key: value for key, value in raw.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="lineage"):
        TargetPlan.from_mapping(raw)


def test_v2_rejects_lineage_tamper_without_rehash_and_false_flag_promotion() -> None:
    tampered = _v2_plan()
    tampered["lineage"]["final_target_sha256"] = "d" * 64
    with pytest.raises(CommodityExecutionContractError, match="plan hash mismatch"):
        TargetPlan.from_mapping(tampered)

    promoted = _v2_plan()
    promoted["production_allowed"] = True
    promoted["plan_hash"] = sha256_json(
        {key: value for key, value in promoted.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="remain false"):
        TargetPlan.from_mapping(promoted)


class _ExecutionCustody:
    def __init__(self, service: ArtifactCustodyService) -> None:
        self.service = service

    def receipt(self, receipt_id: str):
        return self.service.receipt(receipt_id)

    def artifact(self, artifact_id: str):
        return self.service.artifact_for_execution(artifact_id)

    def probe(self):
        return None


def test_v2_custody_and_execution_preview_roundtrip_preserves_schema(
    tmp_path: Path,
) -> None:
    service = ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            "control-secret",
            frozenset({"control-api"}),
            {
                name: CustodyPolicy(str(tmp_path / f"{name}.json"), "0" * 64, "unused")
                for name in (
                    "map_acceptance",
                    "c_fast_acceptance",
                    "runtime_authorization",
                )
            },
            "execution-read-secret",
            None,
            True,
        )
    )
    plan = _v2_plan()
    artifact = new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="static-core-equal-executable-target-adapter",
        producer_version="v2",
        schema_ref=KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        payload=plan,
        generated_at=plan["generated_at"],
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )
    receipt = service.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key="issue353-v2-publish-0001",
            expected_custody_version=0,
            correlation_id="issue353-v2-correlation-0001",
            artifact=artifact,
        ),
        principal="control-api",
    )
    assert receipt["schema_ref"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert receipt["production_allowed"] is False
    assert receipt["live_trading_authorized"] is False
    assert receipt["countable_forward"] is False

    orchestrator = ExecutionOrchestrator(
        InMemoryExecutionRepository(scope="account:windows"),
        InMemoryGateway(account_scope="account:windows", environment="SIMNOW"),
        scope="account:windows",
        environment="SIMNOW",
        test_mode=True,
    )
    runtime = FinalExecutionRuntime(
        orchestrator,
        plans=InMemoryTargetPlanRepository(),
        custody=_ExecutionCustody(service),
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_trusted_keyless_simnow=True,
    )
    installed = runtime.preview_from_custody(receipt["receipt_id"])
    assert installed.raw["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert installed.plan_hash == plan["plan_hash"]

    mismatched = new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="static-core-equal-executable-target-adapter",
        producer_version="v2",
        schema_ref=KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
        payload=plan,
        generated_at=plan["generated_at"],
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )
    with pytest.raises(WorkflowAdapterError, match="tuple is invalid"):
        service.publish_trusted_keyless_target_plan(
            TrustedKeylessTargetPlanUploadDTO(
                idempotency_key="issue353-v2-splice-0001",
                expected_custody_version=2,
                correlation_id="issue353-v2-splice-correlation-0001",
                artifact=mismatched,
            ),
            principal="control-api",
        )


def test_v2_plan_canonical_hash_is_stable() -> None:
    first = _v2_plan()
    second = json.loads(canonical_json_line(first))
    assert second == first
    assert first["plan_hash"] == sha256_json(
        {key: value for key, value in first.items() if key != "plan_hash"}
    )


def test_phase_c_client_keeps_the_control_api_image_boundary() -> None:
    source = (ROOT / "backend/app/phase_c/client.py").read_text(encoding="utf-8")
    assert "from shared.commodity_execution" not in source
    assert "TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS" in source


def test_full_static_core_and_thermostat_are_bound_before_execution_mask() -> None:
    ag = _decision(product="ag")
    au = _decision(product="au")

    assert ag.noop is False and ag.handoff is not None
    assert au.noop is False and au.handoff is not None
    assert ag.final_target_projection == au.final_target_projection
    assert ag.final_target_sha256 == au.final_target_sha256
    assert len(ag.final_target_projection["targets"]) == 10
    assert [row["product"] for row in ag.final_target_projection["targets"]] == [
        "ag",
        "al",
        "au",
        "bu",
        "cu",
        "rb",
        "ru",
        "sc",
        "sp",
        "zn",
    ]
    assert ag.final_target_projection | {"targets": "checked-separately"} == {
        "schema_version": ("commodity_static_core_equal_final_target_projection_v1"),
        "strategy_id": "STATIC_CORE_EQUAL",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "c_sleeve_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "c_map_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
        "d_sleeve_id": "D_DONCHIAN20_EXIT10_NEUTRAL",
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "sector_map_id": "COMMODITY_FROZEN_SECTOR_MAP_V1",
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "source_month": "2030-01",
        "execution_day": "2026-08-03",
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "targets": "checked-separately",
    }
    for decision, expected_product in ((ag, "ag"), (au, "au")):
        plan = decision.handoff.target_plan
        assert plan["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
        assert plan["lineage"] == {
            "static_core_equal_sha256": decision.static_core_equal_sha256,
            "position_manager_sha256": decision.position_manager_sha256,
            "final_target_sha256": decision.final_target_sha256,
        }
        assert len(plan["orders"]) == 1
        assert plan["orders"][0]["symbol"].lower().startswith(expected_product)
        assert plan["production_allowed"] is False
        assert plan["live_trading_authorized"] is False
        assert plan["countable_forward"] is False
    envelope = ag.handoff.trusted_keyless_custody_artifact()
    assert envelope["producer_id"] == ("static-core-equal-final-target-adapter")
    assert envelope["schema_ref"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION


def test_full_strategy_is_deterministic_and_missing_c_or_d_fails_closed() -> None:
    first = _decision()
    second = _decision()
    assert first == second

    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target)
    broken_freeze = json.loads(canonical_json_line(freeze))
    broken_freeze["candidate_weights"].pop("D")
    broken_projection = _projection_with_artifact(
        projection, role="freeze_contract", payload=broken_freeze
    )
    with pytest.raises(ExecutableTargetAdapterError, match="frozen identity"):
        build_static_core_equal_keyless_target_decision(
            static_core_equal_projection=broken_projection,
            static_core_equal_freeze_contract=broken_freeze,
            static_core_equal_target_evidence=target,
            position_manager_snapshot=manager,
            position_manager_sha256=sha256_json(manager),
            current_facts=_snapshot(),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            product="ag",
            run_id="issue353-run-0001",
            expires_at="2099-01-01T00:00:00Z",
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )

    missing_c = json.loads(canonical_json_line(freeze))
    missing_c["C_candidate_id"] = ""
    missing_c_projection = _projection_with_artifact(
        projection, role="freeze_contract", payload=missing_c
    )
    with pytest.raises(ExecutableTargetAdapterError, match="frozen identity"):
        build_static_core_equal_keyless_target_decision(
            static_core_equal_projection=missing_c_projection,
            static_core_equal_freeze_contract=missing_c,
            static_core_equal_target_evidence=target,
            position_manager_snapshot=manager,
            position_manager_sha256=sha256_json(manager),
            current_facts=_snapshot(),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            product="ag",
            run_id="issue353-run-0001",
            expires_at="2099-01-01T00:00:00Z",
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )


def test_fresh_run_id_changes_only_execution_identity() -> None:
    first = _decision(run_id="issue353-run-0001")
    second = _decision(run_id="issue353-run-0002")
    assert first.handoff is not None and second.handoff is not None
    assert first.static_core_equal_sha256 == second.static_core_equal_sha256
    assert first.position_manager_sha256 == second.position_manager_sha256
    assert first.final_target_sha256 == second.final_target_sha256
    assert first.final_target_projection == second.final_target_projection
    assert first.handoff.target_plan["plan_id"] != second.handoff.target_plan["plan_id"]
    assert (
        first.handoff.target_plan["orders"][0]["reference"]
        != second.handoff.target_plan["orders"][0]["reference"]
    )


def test_minimum_nonzero_target_tie_is_masked_only_after_full_hash() -> None:
    selected = {"ag": -2, "au": -2, "sc": 2}
    ag = _decision(product="ag", selected=selected)
    au = _decision(product="au", selected=selected)
    sc = _decision(product="sc", selected=selected)

    assert ag.handoff is not None and au.handoff is not None and sc.handoff is not None
    assert ag.final_target_projection == au.final_target_projection == sc.final_target_projection
    assert ag.final_target_sha256 == au.final_target_sha256 == sc.final_target_sha256
    assert {ag.selected_target_quantity, au.selected_target_quantity, sc.selected_target_quantity} == {
        -2,
        2,
    }
    for decision in (ag, au, sc):
        assert len(decision.handoff.target_plan["orders"]) == 2
        assert {order["volume"] for order in decision.handoff.target_plan["orders"]} == {1}
        references = [order["reference"] for order in decision.handoff.target_plan["orders"]]
        assert len(references) == len(set(references)) == 2
        assert {len(reference) for reference in references} == {64}
    sc_order = sc.handoff.target_plan["orders"][0]
    expected_sc_positions = {
        f"{sc_order['symbol']}.{sc_order['exchange']}.{sc_order['direction']}.CTP.target-v1": {
            "gateway_name": "CTP",
            "symbol": sc_order["symbol"],
            "exchange": sc_order["exchange"],
            "direction": sc_order["direction"],
            "volume": 2,
        }
    }
    assert sc.handoff.target_plan["expected_after_position_hash"] == (
        target_position_projection_hash(
            expected_sc_positions,
            account_scope="account:windows",
            environment="SIMNOW",
        )
    )

    with pytest.raises(
        ExecutableTargetAdapterError, match="not a minimum nonzero target"
    ):
        _decision(product="al", selected=selected)


def test_all_zero_final_target_stops_without_execution_mask() -> None:
    zero_targets = {product: 0 for product in ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")}
    decision = _decision(product="ag", selected=zero_targets)

    assert decision.stopped is True
    assert decision.stop_reason == "no_nonzero_target"
    assert decision.handoff is None
    assert len(decision.final_target_projection["targets"]) == 10


def test_real_frozen_producers_form_one_deterministic_static_to_thermostat_chain() -> (
    None
):
    source, first = _actual_thermostat_result()
    second = thermostat_producer.produce_snapshot(
        thermostat_producer.canonical_json(source)
    )
    assert first == second

    _projection, _freeze, target = _static_outputs()
    snapshot = json.loads(first.snapshot_draft)
    assert snapshot["position_manager_id"] == ("MONTHLY_RELATIVE_VOL_THERMOSTAT_V1")
    assert snapshot["baseline_scheduler_id"] == "STATIC_CORE_EQUAL"
    assert snapshot["execution_lane"] == "simnow_shakedown"
    assert snapshot["authority_granted"] is False
    assert snapshot["dispatch_allowed"] is False
    assert snapshot["countable_forward"] is False
    assert len(snapshot["targets"]) == 10
    assert [
        (
            row["product"],
            row["exact_contract"],
            row["baseline_target_quantity"],
            row["baseline_source_target_weight"],
            row["baseline_buffered_target_weight"],
        )
        for row in snapshot["targets"]
    ] == [
        (
            row["product"],
            row["exact_contract"],
            row["target_quantity"],
            row["source_target_weight"],
            row["buffered_target_weight"],
        )
        for row in target["targets"]
    ]
    assert (
        first.snapshot_draft_sha256 == hashlib.sha256(first.snapshot_draft).hexdigest()
    )

    projection, freeze, target = _static_outputs()
    decision = build_static_core_equal_keyless_target_decision(
        static_core_equal_projection=projection,
        static_core_equal_freeze_contract=freeze,
        static_core_equal_target_evidence=target,
        position_manager_snapshot=snapshot,
        position_manager_sha256=first.snapshot_draft_sha256,
        current_facts=_snapshot(),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        product="au",
        run_id="issue353-run-0001",
        expires_at="2099-01-01T00:00:00Z",
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert decision.stopped is False
    assert decision.handoff is not None
    assert decision.selected_target_quantity == 3
    assert len(decision.handoff.target_plan["orders"]) == 3


def test_cross_splice_baseline_tamper_and_authority_promotion_fail_closed() -> None:
    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target)
    common = {
        "static_core_equal_projection": projection,
        "static_core_equal_freeze_contract": freeze,
        "static_core_equal_target_evidence": target,
        "position_manager_snapshot": manager,
        "position_manager_sha256": sha256_json(manager),
        "current_facts": _snapshot(),
        "reconciliation": {"state": "RECONCILED", "unknown_outcomes": 0},
        "product": "ag",
        "run_id": "issue353-run-0001",
        "expires_at": "2099-01-01T00:00:00Z",
        "now": datetime(2030, 1, 1, tzinfo=timezone.utc),
    }

    spliced_target = json.loads(canonical_json_line(target))
    spliced_target["targets"][0]["target_quantity"] += 1
    with pytest.raises(ExecutableTargetAdapterError, match="cross-spliced"):
        build_static_core_equal_keyless_target_decision(
            **(common | {"static_core_equal_target_evidence": spliced_target})
        )

    baseline_tamper = json.loads(canonical_json_line(manager))
    baseline_tamper["targets"][0]["baseline_target_quantity"] += 1
    with pytest.raises(ExecutableTargetAdapterError, match="baseline is not bound"):
        build_static_core_equal_keyless_target_decision(
            **(
                common
                | {
                    "position_manager_snapshot": baseline_tamper,
                    "position_manager_sha256": sha256_json(baseline_tamper),
                }
            )
        )

    promoted = json.loads(canonical_json_line(freeze))
    promoted["execution_authorized"] = True
    promoted_projection = _projection_with_artifact(
        projection, role="freeze_contract", payload=promoted
    )
    with pytest.raises(ExecutableTargetAdapterError, match="grant authority"):
        build_static_core_equal_keyless_target_decision(
            **(
                common
                | {
                    "static_core_equal_projection": promoted_projection,
                    "static_core_equal_freeze_contract": promoted,
                }
            )
        )


def test_matching_two_lot_strategy_target_is_noop_without_plan_or_mutation() -> None:
    selected = {"ag": 2, "au": -2, "sc": 2}
    matching = {
        "ag2612.SHFE.LONG": {
            "gateway_name": "CTP",
            "symbol": "ag2612",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 2,
            "yd_volume": 0,
        }
    }
    decision = _decision(product="ag", positions=matching, selected=selected)
    assert decision.noop is True
    assert decision.handoff is None
    assert decision.selected_target_quantity == 2
    assert decision.current_quantity == 2
    assert len(decision.final_target_projection["targets"]) == 10

    one_lot = json.loads(canonical_json_line(matching))
    one_lot["ag2612.SHFE.LONG"]["volume"] = 1
    with pytest.raises(ExecutableTargetAdapterError, match="requires a flat account"):
        _decision(product="ag", positions=one_lot, selected=selected)

    split_lots = json.loads(canonical_json_line(matching))
    split_lots["ag2612.SHFE.LONG"]["volume"] = 1
    split_lots["ag2612.SHFE.LONG.second"] = {
        **split_lots["ag2612.SHFE.LONG"],
        "volume": 1,
    }
    with pytest.raises(ExecutableTargetAdapterError, match="canonical target position"):
        _decision(product="ag", positions=split_lots, selected=selected)


@pytest.mark.parametrize(
    ("decision_kind", "execute"),
    [("noop", True), ("noop", False), ("stopped", True)],
)
def test_formal_runner_non_action_performs_zero_custody_or_execution_mutation(
    monkeypatch: pytest.MonkeyPatch, decision_kind: str, execute: bool
) -> None:
    stopped_targets = [
        {"product": product, "target_quantity": 14 if product == "ag" else 2}
        for product in ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    ]
    path = ROOT / "scripts" / "simnow_run_once.py"
    spec = importlib.util.spec_from_file_location("issue353_runner_noop", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args = module.build_parser().parse_args(
        [
            "--static-core-source",
            "static.json",
            "--position-manager-source",
            "thermostat.json",
            "--peek-current-facts",
            "peek.json",
            "--reconciliation-state",
            "reconcile.json",
            "--product",
            "ag",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--principal",
            "runner-admin",
            "--operator",
            "runner-admin",
            "--idempotency-suffix",
            "noop-0001",
            "--expected-custody-version",
            "0",
            *(["--execute"] if execute else []),
        ]
    )
    monkeypatch.setattr(module, "_source_bytes", lambda *_args: b"source")
    monkeypatch.setattr(
        module,
        "produce_static_core_equal",
        lambda _raw: SimpleNamespace(
            producer_projection={},
            artifacts={"freeze_contract": b"{}", "target_evidence": b"{}"},
        ),
    )
    monkeypatch.setattr(
        module,
        "produce_position_manager_snapshot",
        lambda _raw: SimpleNamespace(
            snapshot_draft=b"{}", snapshot_draft_sha256="b" * 64
        ),
    )
    monkeypatch.setattr(
        module,
        "_object",
        lambda _path, label: (
            {"state": "RECONCILED", "unknown_outcomes": 0}
            if label == "reconciliation state"
            else {"execution": {"orders": {}}}
        ),
    )
    monkeypatch.setattr(module, "_generated_object", lambda *_args: {})
    monkeypatch.setattr(
        module,
        "peek_current_facts_to_snapshot",
        lambda *_args, **_kwargs: SimpleNamespace(
            snapshot=SimpleNamespace(position_snapshot_hash="d" * 64)
        ),
    )
    monkeypatch.setattr(
        module,
        "build_static_core_equal_keyless_target_decision",
        lambda **_kwargs: SimpleNamespace(
            noop=decision_kind == "noop",
            stopped=decision_kind == "stopped",
            stop_reason=("no_nonzero_target" if decision_kind == "stopped" else None),
            handoff=None,
            static_core_equal_sha256="a" * 64,
            position_manager_sha256="b" * 64,
            final_target_sha256="c" * 64,
            final_target_projection={"targets": stopped_targets},
            selected_product="ag",
            selected_target_quantity=(14 if decision_kind == "stopped" else 1),
            current_quantity=(0 if decision_kind == "stopped" else 1),
        ),
    )

    class ReadOnlyExecution:
        async def status(self):
            return SimpleNamespace(
                as_dict=lambda: {
                    "state_version": 0,
                    "lifecycle": "READY",
                    "broker": {
                        "connected": True,
                        "active_order_count": 0,
                        "position_snapshot_hash": "d" * 64,
                        "last_snapshot_at": "2030-01-01T00:00:00Z",
                    },
                    "reconciliation": {
                        "state": "RECONCILED",
                        "unknown_outcomes": 0,
                        "last_completed_at": "2030-01-01T00:00:00Z",
                    },
                    "send_intents": [],
                }
            )

        async def submit(self, _envelope):
            raise AssertionError("NOOP must not submit an Execution command")

    def forbidden_custody_client():
        raise AssertionError("NOOP must not construct a custody client")

    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", forbidden_custody_client)
    monkeypatch.setattr(module, "ExecutionClient", ReadOnlyExecution)
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    result = asyncio.run(module.run(args))

    expected = {
        "static_core_equal_sha256": "a" * 64,
        "position_manager_sha256": "b" * 64,
        "final_target_sha256": "c" * 64,
        "selected_product": "ag",
        "selected_target_quantity": (14 if decision_kind == "stopped" else 1),
        "current_quantity": (0 if decision_kind == "stopped" else 1),
        "executed": False,
        "completed": decision_kind == "noop" and execute,
        "archived": False,
        "custody_mutated": False,
        "execution_mutated": False,
    }
    if decision_kind == "stopped":
        expected.update(
            {
                "stopped": True,
                "reason": "no_nonzero_target",
                "final_targets": stopped_targets,
            }
        )
    else:
        expected.update(
            {
                "noop": True,
                "reason": "target_already_satisfied",
                "actual_execution_validated": execute,
            }
        )
    assert result == expected
