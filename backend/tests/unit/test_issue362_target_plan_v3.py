from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from app.execution import (
    ExecutionOrchestrator,
    InMemoryExecutionRepository,
    InMemoryGateway,
)
from app.execution.final_runtime import (
    FinalExecutionRuntime,
    InMemoryTargetPlanRepository,
)
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.client import RemotePhaseCWorkflowClient
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
)
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    CommodityExecutionContractError,
    TargetPlan,
    TrustedKeylessCustodyReceipt,
    V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
    build_trusted_keyless_target_plan_v3,
    sha256_json,
    trusted_keyless_target_plan_v3_plan_id,
)
from test_issue353_static_core_keyless import _v2_plan


class _ExecutionCustody:
    def __init__(self, service: ArtifactCustodyService) -> None:
        self.service = service

    def receipt(self, receipt_id: str):
        return self.service.receipt(receipt_id)

    def receipt_by_idempotency(self, idempotency_key: str):
        return self.service.receipt_by_idempotency(idempotency_key)

    def artifact(self, artifact_id: str):
        return self.service.artifact_for_execution(artifact_id)

    def probe(self) -> None:
        return None


def _v3_fields() -> dict:
    return {
        "execution_run_id": "issue362-v3-run-0001",
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "gateway_name": "CTP",
        "lineage": {
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": "c" * 64,
        },
        "scope": dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        "creation_quote_proof": {
            "schema_version": FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
            "validated_at_utc": "2030-01-01T00:00:00Z",
            "max_age_seconds": V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
            "future_skew_seconds": 2,
            "journal_authenticated": False,
            "start_authorized": False,
            "bindings": {
                "SHFE.ag2609": {
                    "source": "windows-tick-wire-v1",
                    "vt_symbol": "ag2609.SHFE",
                    "price_side": "ask",
                    "stream_generation": "formal-generation-0001",
                    "ingest_id": "formal-ingest-0001",
                    "ingest_seq": 1,
                    "event_hash": "d" * 64,
                    "received_at_utc": "2030-01-01T00:00:00Z",
                    "reference_price": 5000.0,
                    "price_tick": 1.0,
                }
            },
        },
        "generated_at": "2030-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "phase": "OPEN",
        "expected_before_position_hash": "e" * 64,
        "expected_after_position_hash": "f" * 64,
        "orders": [
            {
                "symbol": "ag2609",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 5001.0,
                "offset": "OPEN",
                "reference": "issue362-v3-order-0001",
                "gateway_name": "CTP",
            }
        ],
    }


def _v3_plan(**overrides: object) -> dict:
    fields = _v3_fields()
    fields.update(overrides)
    return build_trusted_keyless_target_plan_v3(**fields)


def _rebuild(raw: dict) -> dict:
    fields = deepcopy(raw)
    fields.pop("plan_id", None)
    fields.pop("plan_hash", None)
    return build_trusted_keyless_target_plan_v3(**fields)


def _service(tmp_path: Path) -> ArtifactCustodyService:
    return ArtifactCustodyService(
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


def test_v2_exact_replay_is_unchanged_and_rejects_a_v3_extension() -> None:
    v2 = _v2_plan()
    assert v2["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert v2["plan_hash"] == (
        "483bf6c9259640d77019582fdc55e698af6b73850f25811f89346d226bce081d"
    )

    extra = deepcopy(v2)
    extra["execution_run_id"] = "issue362-v2-extra-0001"
    extra["plan_hash"] = sha256_json(
        {key: value for key, value in extra.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="fields are not exact"):
        TargetPlan.from_mapping(extra)


def test_v3_is_strict_authority_negative_and_recomputes_identity_from_payload() -> None:
    plan = _v3_plan()
    parsed = TargetPlan.from_mapping(plan)

    assert parsed.as_dict() == plan
    assert plan["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert trusted_keyless_target_plan_v3_plan_id(plan) == plan["plan_id"]
    assert plan["plan_hash"] == sha256_json(
        {key: value for key, value in plan.items() if key != "plan_hash"}
    )
    assert plan["production_allowed"] is False
    assert plan["live_trading_authorized"] is False
    assert plan["countable_forward"] is False
    assert (
        plan["creation_quote_proof"]["max_age_seconds"]
        == V3_FORMAL_QUOTE_MAX_AGE_SECONDS
    )
    assert plan["creation_quote_proof"]["journal_authenticated"] is False
    assert plan["creation_quote_proof"]["start_authorized"] is False


def test_v3_creation_quote_age_policy_is_exact_hash_bound_and_not_tunable() -> None:
    plan = _v3_plan()
    tampered = deepcopy(plan)
    tampered["creation_quote_proof"]["max_age_seconds"] = 2.0

    assert plan["plan_hash"] != sha256_json(
        {key: value for key, value in tampered.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="policy is invalid"):
        TargetPlan.from_mapping(tampered)

    fields = _v3_fields()
    fields["creation_quote_proof"]["max_age_seconds"] = 2.0
    with pytest.raises(CommodityExecutionContractError, match="policy is invalid"):
        build_trusted_keyless_target_plan_v3(**fields)


def test_v3_run_and_quote_material_change_identity_and_tamper_fails_closed() -> None:
    first = _v3_plan()
    second = _v3_plan(execution_run_id="issue362-v3-run-0002")
    quote_changed = deepcopy(first)
    quote_changed["creation_quote_proof"]["bindings"]["SHFE.ag2609"]["event_hash"] = (
        "1" * 64
    )

    with pytest.raises(CommodityExecutionContractError, match="plan_id mismatch"):
        TargetPlan.from_mapping(quote_changed)

    rebuilt = _rebuild(quote_changed)
    assert len({first["plan_id"], second["plan_id"], rebuilt["plan_id"]}) == 3
    assert len({first["plan_hash"], second["plan_hash"], rebuilt["plan_hash"]}) == 3


@pytest.mark.parametrize(
    "mutate",
    [
        lambda fields: fields["creation_quote_proof"].pop("validated_at_utc"),
        lambda fields: fields["creation_quote_proof"].__setitem__("extra", False),
        lambda fields: fields["creation_quote_proof"].__setitem__(
            "journal_authenticated", True
        ),
        lambda fields: fields["creation_quote_proof"]["bindings"][
            "SHFE.ag2609"
        ].__setitem__("price_side", "bid"),
        lambda fields: fields["orders"][0].__setitem__("price", 5002.0),
    ],
)
def test_v3_creation_quote_proof_rejects_missing_extra_authority_and_splice(
    mutate,
) -> None:
    fields = _v3_fields()
    mutate(fields)
    with pytest.raises(CommodityExecutionContractError):
        build_trusted_keyless_target_plan_v3(**fields)


def test_v3_rejects_invalid_run_id_and_extra_top_level_field() -> None:
    with pytest.raises(CommodityExecutionContractError, match="execution_run_id"):
        _v3_plan(execution_run_id="bad:id")

    extra = _v3_plan()
    extra["startable"] = False
    extra["plan_hash"] = sha256_json(
        {key: value for key, value in extra.items() if key != "plan_hash"}
    )
    with pytest.raises(CommodityExecutionContractError, match="fields are not exact"):
        TargetPlan.from_mapping(extra)


def test_phase_c_v3_roundtrip_and_schema_splice(tmp_path: Path) -> None:
    service = _service(tmp_path)
    plan = _v3_plan()
    artifact = new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="static-core-equal-final-target-adapter",
        producer_version="v3",
        schema_ref=KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        payload=plan,
        generated_at=plan["generated_at"],
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )
    receipt = service.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key="issue362-v3-publish-0001",
            expected_custody_version=0,
            correlation_id="issue362-v3-correlation-0001",
            artifact=artifact,
        ),
        principal="control-api",
    )

    assert receipt["schema_ref"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert TrustedKeylessCustodyReceipt.from_mapping(receipt).as_dict() == receipt
    assert (
        RemotePhaseCWorkflowClient._custody_receipt(receipt).schema_ref
        == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    projection = service.target_plan_publication("issue362-v3-publish-0001")
    assert projection.state == "INSTALLED"
    assert projection.artifact_schema_ref == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert projection.plan_schema_version == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert projection.plan_id == plan["plan_id"]
    assert projection.plan_hash == plan["plan_hash"]
    assert service.receipt(receipt["receipt_id"])["schema_ref"] == (
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    assert (
        service.receipt_by_idempotency("issue362-v3-publish-0001")["schema_ref"]
        == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    recovered = service.artifact_for_execution(artifact["artifact_id"])
    assert recovered is not None
    assert recovered["artifact"] == artifact

    gateway = InMemoryGateway(account_scope="account:windows", environment="SIMNOW")
    runtime = FinalExecutionRuntime(
        ExecutionOrchestrator(
            InMemoryExecutionRepository(scope="account:windows"),
            gateway,
            scope="account:windows",
            environment="SIMNOW",
            test_mode=True,
        ),
        plans=InMemoryTargetPlanRepository(),
        custody=_ExecutionCustody(service),
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_trusted_keyless_simnow=True,
    )
    installed = runtime.preview_from_custody(receipt["receipt_id"])
    assert installed.as_dict() == plan
    assert gateway.send_calls == []
    assert runtime.plans.get(plan["plan_id"]) == installed

    spliced = new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="static-core-equal-final-target-adapter",
        producer_version="v3",
        schema_ref=KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        payload=plan,
        generated_at=plan["generated_at"],
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )
    with pytest.raises(WorkflowAdapterError, match="invalid"):
        service.publish_trusted_keyless_target_plan(
            TrustedKeylessTargetPlanUploadDTO(
                idempotency_key="issue362-v3-splice-0001",
                expected_custody_version=2,
                correlation_id="issue362-v3-splice-correlation-0001",
                artifact=spliced,
            ),
            principal="control-api",
        )
