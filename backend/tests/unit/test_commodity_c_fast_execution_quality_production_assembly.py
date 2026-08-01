from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services.commodity_c_fast_execution_quality_production_assembly import (
    CommodityCFastExecutionQualityProductionAssembly,
)
from app.services.commodity_c_fast_execution_quality_readonly_repository import (
    CFastExecutionQualityReadonlyRepositoryError,
    CommodityCFastExecutionQualityReadonlyRepository,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    JournalRecord,
    SidecarState,
)


NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def revalidation(
    trigger: str,
    observed_at_utc: datetime,
) -> CFastExecutionQualityRuntimeRevalidationDTO:
    core = {
        "schema_version": (
            "commodity_c_fast_execution_quality_runtime_revalidation_v1"
        ),
        "trigger": trigger,
        "revalidated_at_utc": observed_at_utc.isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (observed_at_utc + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
        "exact_contracts": ["SHFE.ag2612"],
        "signed_p0_acceptance_sha256": "1" * 64,
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
        "p0_acceptance_state": "VERIFIED",
        "collection_admission_state": "VERIFIED",
        "execution_policy_state": "VERIFIED",
        "signed_snapshot_state": "VERIFIED",
        "virtual_intent_plan_state": "VERIFIED",
        "contract_spec_state": "VERIFIED",
        "custody_state": "VERIFIED",
        **FALSE_AUTHORITY,
    }
    return CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
        {**core, "receipt_sha256": _sha256_json(core)}
    )


class FakeAdmissionConsumer:
    def __init__(self) -> None:
        self.receipts: list[str] = []

    def verify_for_receipt(self, receipt):
        self.receipts.append(receipt.receipt_sha256)
        return SimpleNamespace(
            admission=SimpleNamespace(
                admission_id=(
                    "cfast-execution-quality-runtime-admission-v1-" + "a" * 64
                )
            ),
            admission_raw_sha256="b" * 64,
        )


def empty_state() -> SidecarState:
    return SidecarState(
        records=(),
        intents={},
        anchors={},
        snapshots=(),
        evidence={},
    )


def runtime(*, enabled: bool) -> CommodityCFastExecutionQualityRuntime:
    subject = CommodityCFastExecutionQualityRuntime(
        settings=Settings(commodity_c_fast_execution_quality_runtime_enabled=enabled),
        clock=lambda: NOW,
    )
    subject.bind_full_revalidation_verifier(revalidation)
    return subject


def test_default_off_never_consumes_admission_or_repository() -> None:
    consumer = FakeAdmissionConsumer()
    repository_calls = 0

    def load() -> SidecarState:
        nonlocal repository_calls
        repository_calls += 1
        return empty_state()

    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=runtime(enabled=False),
        admission_consumer=consumer,
    )
    assembly.bind_readonly_repository(
        CommodityCFastExecutionQualityReadonlyRepository(load)
    )

    status = assembly.start()

    assert status["assembly_state"] == "DISABLED_DEFAULT_OFF"
    assert consumer.receipts == []
    assert repository_calls == 0
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert all(status[field] is False for field in FALSE_AUTHORITY)


def test_every_lifecycle_revalidates_admission_and_readonly_repository() -> None:
    consumer = FakeAdmissionConsumer()
    repository = CommodityCFastExecutionQualityReadonlyRepository(empty_state)
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=runtime(enabled=True),
        admission_consumer=consumer,
    )
    assembly.bind_readonly_repository(repository)

    for generation, operation in enumerate(
        (assembly.start, assembly.reload, assembly.recover),
        start=1,
    ):
        status = operation()
        assert status["assembly_state"] == (
            "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
        )
        assert status["signed_runtime_admission_verified"] is True
        assert status["revalidation_generation"] == generation
        assert status["readonly_repository"]["recovery_generation"] == generation
        assert status["runtime_active"] is False
        assert status["execution_quality_implemented"] is False
        assert status["orders_sent"] == 0
        assert status["positions_modified"] == 0

    assert len(consumer.receipts) == 3


def test_repository_failure_blocks_only_assembly_and_is_retryable() -> None:
    dependency_healthy = False
    unrelated_shadow_state = {"running": True}

    def load() -> SidecarState:
        if not dependency_healthy:
            raise OSError("sidecar journal unavailable")
        return empty_state()

    repository = CommodityCFastExecutionQualityReadonlyRepository(load)
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=runtime(enabled=True),
        admission_consumer=FakeAdmissionConsumer(),
    )
    assembly.bind_readonly_repository(repository)

    failed = assembly.start()
    assert failed["assembly_state"] == "BLOCKED_READONLY_REPOSITORY_FAILED"
    assert failed["full_revalidation_complete"] is True
    assert failed["runtime_active"] is False
    assert failed["orders_sent"] == 0
    assert unrelated_shadow_state == {"running": True}

    dependency_healthy = True
    recovered = assembly.reload()
    assert recovered["assembly_state"] == (
        "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
    )
    assert recovered["readonly_repository"]["blocked_fail_closed"] is False
    assert unrelated_shadow_state == {"running": True}


def test_readonly_repository_returns_detached_deterministic_projections() -> None:
    intent_record = JournalRecord(
        sequence=1,
        operation_id="intent:test",
        previous_record_hash="0" * 64,
        record_hash="1" * 64,
        payload={
            "intent": {
                "intent_id": "intent-00000001",
                "exact_contract": "SHFE.ag2612",
            }
        },
    )
    anchor_record = JournalRecord(
        sequence=2,
        operation_id="anchor:test",
        previous_record_hash="1" * 64,
        record_hash="2" * 64,
        payload={"durably_created_at_utc": "2026-09-01T01:00:00Z"},
    )
    evidence_record = JournalRecord(
        sequence=3,
        operation_id="evidence:test",
        previous_record_hash="2" * 64,
        record_hash="3" * 64,
        payload={
            "intent_id": "intent-00000001",
            "target_key": "decision",
            "completion_state": "SEALED_MISSING_NOT_IMPUTED",
        },
    )
    state = SidecarState(
        records=(intent_record, anchor_record, evidence_record),
        intents={"intent-00000001": intent_record},
        anchors={"intent-00000001": anchor_record},
        snapshots=(),
        evidence={("intent-00000001", "decision"): evidence_record},
    )
    repository = CommodityCFastExecutionQualityReadonlyRepository(lambda: state)

    status = repository.recover()
    intents = repository.intents()
    evidence = repository.execution_quality()
    intents[0]["intent"]["exact_contract"] = "MUTATED"

    assert status["intent_count"] == 1
    assert status["execution_quality_record_count"] == 1
    assert repository.intents()[0]["intent"]["exact_contract"] == ("SHFE.ag2612")
    assert evidence[0]["completion_state"] == ("SEALED_MISSING_NOT_IMPUTED")
    assert not hasattr(repository, "append")
    assert not hasattr(repository, "write")


def test_blocked_repository_requires_explicit_recovery() -> None:
    repository = CommodityCFastExecutionQualityReadonlyRepository(
        lambda: (_ for _ in ()).throw(OSError("unavailable"))
    )
    assert repository.recover()["blocked_fail_closed"] is True
    with pytest.raises(
        CFastExecutionQualityReadonlyRepositoryError,
        match="READONLY_REPOSITORY_BLOCKED_REQUIRES_EXPLICIT_RECOVERY",
    ):
        repository.intents()


def test_assembly_and_repository_have_zero_trading_capability() -> None:
    service_root = Path(__file__).resolve().parents[2] / "app/services"
    trees = [
        ast.parse((service_root / name).read_text(encoding="utf-8"))
        for name in (
            "commodity_c_fast_execution_quality_production_assembly.py",
            "commodity_c_fast_execution_quality_readonly_repository.py",
        )
    ]
    imports = {
        node.module or ""
        for tree in trees
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    names = {
        node.id
        for tree in trees
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
    }

    assert imports.isdisjoint(
        {
            "app.services.commodity_simnow",
            "app.services.market_data_service",
            "app.services.tick_persistence",
            "app.services.trade_service",
            "app.services.vnpy_rpc_service",
            "psycopg",
            "questdb",
        }
    )
    assert names.isdisjoint(
        {"TradeService", "cancel_order", "rpc_service", "send_order"}
    )
