from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services import (
    commodity_c_fast_execution_quality_production_assembly as assembly_module,
)
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    CFastExecutionQualityEvidenceExportError,
    CreateOnlyExecutionQualityEvidenceExportStore,
)
from app.services.commodity_c_fast_execution_quality_production_assembly import (
    CFastExecutionQualityProductionAssemblyError,
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
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)

NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]
SIDECAR_TEST_PATH = (
    ROOT / "backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py"
)
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


def _load_test_helpers(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SIDECAR = _load_test_helpers("production_assembly_sidecar_helpers", SIDECAR_TEST_PATH)


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
        "exact_contracts": ["SHFE.cu2612"],
        "signed_p0_acceptance_sha256": "1" * 64,
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
        "verified_signer_domains": {
            "signed_p0_acceptance": ["8" * 64],
            "collection_admission": ["9" * 64],
            "execution_policy": ["a" * 64],
            "signed_snapshot": ["b" * 64],
            "virtual_intent_plan": ["c" * 64],
            "contract_spec_set": ["d" * 64],
            "custody_binding": ["e" * 64],
        },
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


class FakeAdmissionVerifier:
    def __init__(self) -> None:
        self.receipts: list[str] = []

    def verify_for_revalidation(self, receipt):
        self.receipts.append(receipt.receipt_sha256)
        return SimpleNamespace(
            admission=SimpleNamespace(
                admission_id=(
                    "cfast-execution-quality-runtime-admission-v1-" + "a" * 64
                ),
                not_before_utc=NOW - timedelta(minutes=1),
                expires_at_utc=NOW + timedelta(minutes=10),
            ),
            admission_raw_sha256="b" * 64,
        )


def runtime(*, enabled: bool) -> CommodityCFastExecutionQualityRuntime:
    subject = CommodityCFastExecutionQualityRuntime(
        settings=Settings(commodity_c_fast_execution_quality_runtime_enabled=enabled),
        clock=lambda: NOW,
    )
    subject.bind_full_revalidation_verifier(revalidation)
    return subject


def registered_sidecar(tmp_path: Path) -> OfflineExecutionQualitySidecar:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = SIDECAR.sidecar(tmp_path)
    SIDECAR.register(source)
    return source


def export_store(tmp_path: Path) -> CreateOnlyExecutionQualityEvidenceExportStore:
    root = tmp_path / "evidence-exports"
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return CreateOnlyExecutionQualityEvidenceExportStore(root)


def assembly_with_components(
    tmp_path: Path,
    *,
    enabled: bool = True,
) -> tuple[
    CommodityCFastExecutionQualityProductionAssembly,
    OfflineExecutionQualitySidecar,
    CreateOnlyExecutionQualityEvidenceExportStore,
    FakeAdmissionVerifier,
]:
    verifier = FakeAdmissionVerifier()
    source = registered_sidecar(tmp_path / "source")
    store = export_store(tmp_path)
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=runtime(enabled=enabled),
        admission_verifier=verifier,
    )
    assembly.bind_readonly_components(
        sidecar=source,
        repository=CommodityCFastExecutionQualityReadonlyRepository(source),
        evidence_export_store=store,
    )
    return assembly, source, store, verifier


def test_default_off_never_verifies_or_replays_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly, source, _, verifier = assembly_with_components(
        tmp_path,
        enabled=False,
    )
    recover = source.recover
    calls = 0

    def observed_recover():
        nonlocal calls
        calls += 1
        return recover()

    monkeypatch.setattr(source, "recover", observed_recover)
    status = assembly.start()

    assert status["assembly_state"] == "DISABLED_DEFAULT_OFF"
    assert verifier.receipts == []
    assert calls == 0
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert all(status[field] is False for field in FALSE_AUTHORITY)


def test_enabled_global_factory_binds_fixed_components_before_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_root = tmp_path / "journal"
    evidence_root = tmp_path / "exports"
    for root in (journal_root, evidence_root):
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    configured_runtime = CommodityCFastExecutionQualityRuntime(
        settings=Settings(
            commodity_c_fast_execution_quality_runtime_enabled=True,
            commodity_c_fast_execution_quality_journal_root=str(journal_root),
            commodity_c_fast_execution_quality_evidence_export_root=str(
                evidence_root
            ),
        ),
        clock=lambda: NOW,
    )
    monkeypatch.setattr(
        assembly_module,
        "commodity_c_fast_execution_quality_runtime",
        configured_runtime,
    )
    monkeypatch.setattr(
        assembly_module,
        "commodity_c_fast_execution_quality_runtime_admission_verifier",
        FakeAdmissionVerifier(),
    )

    assembly = assembly_module._build_production_assembly()
    status = assembly.status()

    assert status["assembly_lifecycle_started"] is False
    assert status["capabilities"]["durable_sidecar_runtime_bound"] is True
    assert status["capabilities"]["readonly_repository_bound"] is True
    assert status["capabilities"]["evidence_export_store_bound"] is True
    assert status["capabilities"]["questdb_evidence_adapter_bound"] is False
    with pytest.raises(
        CFastExecutionQualityProductionAssemblyError,
        match="PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE",
    ):
        assembly.intents()


def test_every_lifecycle_revalidates_replays_and_create_only_publishes(
    tmp_path: Path,
) -> None:
    assembly, _, store, verifier = assembly_with_components(tmp_path)

    states = []
    for generation, operation in enumerate(
        (assembly.start, assembly.reload, assembly.recover),
        start=1,
    ):
        status = operation()
        states.append(status["evidence_export"]["latest_artifact_state"])
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

    assert states == ["CREATED", "ALREADY_PRESENT", "ALREADY_PRESENT"]
    assert len(list(store.root.glob("*.json"))) == 1
    assert len(verifier.receipts) == 3
    assert len(set(verifier.receipts)) == 3


def test_repository_failure_blocks_only_assembly_and_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly, source, _, _ = assembly_with_components(tmp_path)
    real_recover = source.recover
    dependency_healthy = False
    unrelated_systems = {
        "baseline": "running",
        "position_manager_shadow": "running",
        "simnow": "running",
    }

    def recover():
        if not dependency_healthy:
            raise OSError("sidecar journal unavailable")
        return real_recover()

    monkeypatch.setattr(source, "recover", recover)
    failed = assembly.start()

    assert failed["assembly_state"] == "BLOCKED_READONLY_REPOSITORY_FAILED"
    assert failed["full_revalidation_complete"] is True
    assert failed["runtime_active"] is False
    assert failed["orders_sent"] == 0
    assert unrelated_systems == {
        "baseline": "running",
        "position_manager_shadow": "running",
        "simnow": "running",
    }

    dependency_healthy = True
    recovered = assembly.reload()
    assert recovered["assembly_state"] == (
        "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
    )
    assert recovered["readonly_repository"]["blocked_fail_closed"] is False


def test_export_failure_fuses_only_c_fast_and_recovery_is_duplicate_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly, _, store, _ = assembly_with_components(tmp_path)
    publish = store.publish
    unrelated_tick_persistence = {"running": True, "rows": 41}

    def fail_publish(_source):
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_INJECTED_FAILURE"
        )

    monkeypatch.setattr(store, "publish", fail_publish)
    failed = assembly.start()

    assert failed["assembly_state"] == "BLOCKED_EVIDENCE_EXPORT_FAILED"
    assert failed["assembly_last_error"] == "EVIDENCE_EXPORT_INJECTED_FAILURE"
    assert unrelated_tick_persistence == {"running": True, "rows": 41}
    assert not list(store.root.glob("*.json"))

    monkeypatch.setattr(store, "publish", publish)
    assert assembly.recover()["evidence_export"]["latest_artifact_state"] == "CREATED"
    assert assembly.reload()["evidence_export"]["latest_artifact_state"] == (
        "ALREADY_PRESENT"
    )
    assert len(list(store.root.glob("*.json"))) == 1


def test_success_then_failed_reload_or_stop_cannot_serve_stale_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly, source, _, _ = assembly_with_components(tmp_path)
    assert assembly.start()["assembly_last_error"] is None
    assert len(assembly.intents()) == 1

    monkeypatch.setattr(
        source,
        "recover",
        lambda: (_ for _ in ()).throw(OSError("injected reload failure")),
    )
    assert assembly.reload()["assembly_state"] == ("BLOCKED_READONLY_REPOSITORY_FAILED")
    with pytest.raises(
        CFastExecutionQualityProductionAssemblyError,
        match="PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE",
    ):
        assembly.intents()

    monkeypatch.undo()
    assert assembly.recover()["assembly_last_error"] is None
    assert len(assembly.intents()) == 1
    assembly.stop()
    with pytest.raises(
        CFastExecutionQualityProductionAssemblyError,
        match="PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE",
    ):
        assembly.execution_quality()


def test_repository_export_tip_drift_blocks_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly, source, store, _ = assembly_with_components(tmp_path)
    publish = store.publish

    def append_between_replays(sidecar):
        source.append_preverified_snapshot(SIDECAR.SCORER.book(0))
        return publish(sidecar)

    monkeypatch.setattr(store, "publish", append_between_replays)
    status = assembly.start()

    assert status["assembly_state"] == "BLOCKED_READONLY_EXPORT_SNAPSHOT_DRIFT"
    assert status["assembly_last_error"] == ("READONLY_REPOSITORY_EXPORT_TIP_MISMATCH")
    assert status["readonly_repository"]["source_journal_record_count"] == 2
    assert status["evidence_export"]["latest_artifact_filename"] is None
    assert len(list(store.root.glob("*.json"))) == 1
    with pytest.raises(
        CFastExecutionQualityProductionAssemblyError,
        match="PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE",
    ):
        assembly.evidence_export()


def test_restart_reopens_same_journal_and_immutable_export(
    tmp_path: Path,
) -> None:
    first, source, store, _ = assembly_with_components(tmp_path)
    assert first.start()["evidence_export"]["latest_artifact_state"] == "CREATED"
    expected = first.evidence_export()

    restarted_source = OfflineExecutionQualitySidecar(
        CreateOnlyExecutionQualityJournal(source.journal.root),
        clock=lambda: NOW,
    )
    restarted_store = CreateOnlyExecutionQualityEvidenceExportStore(store.root)
    restarted = CommodityCFastExecutionQualityProductionAssembly(
        runtime=runtime(enabled=True),
        admission_verifier=FakeAdmissionVerifier(),
    )
    restarted.bind_readonly_components(
        sidecar=restarted_source,
        repository=CommodityCFastExecutionQualityReadonlyRepository(restarted_source),
        evidence_export_store=restarted_store,
    )

    status = restarted.start()

    assert status["evidence_export"]["latest_artifact_state"] == "ALREADY_PRESENT"
    assert restarted.evidence_export() == {
        **expected,
        "artifact_state": "ALREADY_PRESENT",
    }
    assert len(list(store.root.glob("*.json"))) == 1


def test_repository_returns_detached_exact_typed_projections(
    tmp_path: Path,
) -> None:
    source = registered_sidecar(tmp_path)
    repository = CommodityCFastExecutionQualityReadonlyRepository(source)

    status = repository.recover()
    intents = repository.intents()
    intents[0]["intent"]["exact_contract"] = "MUTATED"

    assert status["intent_count"] == 1
    assert status["execution_quality_record_count"] == 0
    assert status["exact_contracts"] == ["SHFE.cu2612"]
    assert repository.intents()[0]["intent"]["exact_contract"] == "SHFE.cu2612"
    assert repository.execution_quality() == ()
    assert not hasattr(repository, "append")
    assert not hasattr(repository, "write")


def test_blocked_repository_requires_explicit_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = registered_sidecar(tmp_path)
    repository = CommodityCFastExecutionQualityReadonlyRepository(source)
    monkeypatch.setattr(
        source,
        "recover",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
    )

    assert repository.recover()["blocked_fail_closed"] is True
    with pytest.raises(
        CFastExecutionQualityReadonlyRepositoryError,
        match="READONLY_REPOSITORY_BLOCKED_REQUIRES_EXPLICIT_RECOVERY",
    ):
        repository.intents()


def test_unexpected_runtime_lifecycle_exception_is_blocked_at_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    underlying_runtime = runtime(enabled=True)
    monkeypatch.setattr(
        underlying_runtime,
        "start",
        lambda: (_ for _ in ()).throw(OSError("unexpected dependency failure")),
    )
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=underlying_runtime,
        admission_verifier=FakeAdmissionVerifier(),
    )

    status = assembly.start()

    assert status["assembly_state"] == "BLOCKED_LIFECYCLE_OPERATION_FAILED"
    assert status["assembly_last_error"] == "OSError"
    assert status["runtime_active"] is False
    assert all(status[field] is False for field in FALSE_AUTHORITY)


def test_unexpected_runtime_stop_exception_is_blocked_at_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    underlying_runtime = runtime(enabled=True)
    monkeypatch.setattr(
        underlying_runtime,
        "stop",
        lambda: (_ for _ in ()).throw(OSError("unexpected shutdown failure")),
    )
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=underlying_runtime,
        admission_verifier=FakeAdmissionVerifier(),
    )

    status = assembly.stop()

    assert status["assembly_state"] == "BLOCKED_LIFECYCLE_OPERATION_FAILED"
    assert status["assembly_last_error"] == "OSError"
    assert status["assembly_lifecycle_started"] is False
    assert status["runtime_active"] is False
    assert all(status[field] is False for field in FALSE_AUTHORITY)


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
