from __future__ import annotations

import json
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
    RevalidationTrigger,
)
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    CreateOnlyExecutionQualityEvidenceExportStore,
)
from app.services.commodity_c_fast_execution_quality_horizon_worker import (
    PreverifiedTickHorizonWorker,
)
from app.services.commodity_c_fast_execution_quality_artifact_revalidation import (
    ARTIFACT_ROLES,
    CommodityCFastExecutionQualityArtifactRevalidator,
)
from app.services.commodity_c_fast_execution_quality_production_verifier import (
    CommodityCFastExecutionQualityProductionArtifactVerifier,
)
from app.services.commodity_c_fast_execution_quality_readonly_repository import (
    CommodityCFastExecutionQualityReadonlyRepository,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
    commodity_c_fast_execution_quality_runtime,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (
    VerifiedCFastExecutionQualityRuntimeAdmission,
    commodity_c_fast_execution_quality_runtime_admission_verifier,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CreateOnlyExecutionQualityJournal,
    OfflineExecutionQualitySidecar,
)
from app.services.commodity_c_fast_execution_quality_tick_fanout import (
    CommodityCFastExecutionQualityTickFanout,
    commodity_c_fast_execution_quality_tick_fanout,
)

_FALSE_AUTHORITY = {
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
_DENIED_CAPABILITIES = (
    "account",
    "cancel_order",
    "gateway",
    "position",
    "rpc",
    "send_order",
    "trade_service",
)


class CFastExecutionQualityProductionAssemblyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RuntimeAdmissionVerifier(Protocol):
    def verify_for_revalidation(
        self,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> VerifiedCFastExecutionQualityRuntimeAdmission: ...


class CommodityCFastExecutionQualityProductionAssembly:
    """Default-off assembly for one fixed, read-only durable sidecar chain.

    When configured, the source sidecar, exact typed repository and immutable
    export store are bound as one identity before application startup. Every
    lifecycle freshly verifies signed scope, replays the same journal, and
    create-only publishes its evidence projection. No component has database
    write, RPC, account, order or position capability.
    """

    def __init__(
        self,
        *,
        runtime: CommodityCFastExecutionQualityRuntime,
        admission_verifier: RuntimeAdmissionVerifier,
    ) -> None:
        if type(runtime) is not CommodityCFastExecutionQualityRuntime:
            raise TypeError("PRODUCTION_ASSEMBLY_RUNTIME_TYPE_INVALID")
        if not callable(getattr(admission_verifier, "verify_for_revalidation", None)):
            raise TypeError("PRODUCTION_ASSEMBLY_ADMISSION_VERIFIER_INVALID")
        self._runtime = runtime
        self._admission_verifier = admission_verifier
        self._lock = RLock()
        self._state = "CREATED_DEFAULT_OFF"
        self._started = False
        self._last_trigger: RevalidationTrigger | None = None
        self._last_error: str | None = None
        self._admission: VerifiedCFastExecutionQualityRuntimeAdmission | None = None
        self._sidecar: OfflineExecutionQualitySidecar | None = None
        self._readonly_repository: (
            CommodityCFastExecutionQualityReadonlyRepository | None
        ) = None
        self._evidence_export_store: (
            CreateOnlyExecutionQualityEvidenceExportStore | None
        ) = None
        self._horizon_worker: PreverifiedTickHorizonWorker | None = None
        self._tick_fanout: CommodityCFastExecutionQualityTickFanout | None = None
        self._registered_input_identity: (
            tuple[str, str, str, tuple[str, ...]] | None
        ) = None
        self._verified_inputs_sha256: str | None = None
        self._component_binding_error: str | None = None
        self._last_export_receipt: dict[str, object] | None = None
        self._projection_revalidation_generation: int | None = None
        self._projection_receipt_sha256: str | None = None

    def bind_readonly_components(
        self,
        *,
        sidecar: OfflineExecutionQualitySidecar,
        repository: CommodityCFastExecutionQualityReadonlyRepository,
        evidence_export_store: CreateOnlyExecutionQualityEvidenceExportStore,
    ) -> None:
        if type(sidecar) is not OfflineExecutionQualitySidecar:
            raise TypeError("PRODUCTION_ASSEMBLY_SIDECAR_TYPE_INVALID")
        if type(repository) is not CommodityCFastExecutionQualityReadonlyRepository:
            raise TypeError("PRODUCTION_ASSEMBLY_READONLY_REPOSITORY_TYPE_INVALID")
        if (
            type(evidence_export_store)
            is not CreateOnlyExecutionQualityEvidenceExportStore
        ):
            raise TypeError("PRODUCTION_ASSEMBLY_EVIDENCE_EXPORT_STORE_TYPE_INVALID")
        if not repository.is_bound_to(sidecar):
            raise CFastExecutionQualityProductionAssemblyError(
                "PRODUCTION_ASSEMBLY_REPOSITORY_SOURCE_MISMATCH"
            )
        with self._lock:
            if self._started:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_COMPONENT_BIND_AFTER_START_FORBIDDEN"
                )
            current = (
                self._sidecar,
                self._readonly_repository,
                self._evidence_export_store,
            )
            requested = (sidecar, repository, evidence_export_store)
            if any(value is not None for value in current) and current != requested:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_COMPONENTS_ALREADY_BOUND"
                )
            self._sidecar = sidecar
            self._readonly_repository = repository
            self._evidence_export_store = evidence_export_store
            self._component_binding_error = None

    def bind_tick_runtime_components(
        self,
        *,
        horizon_worker: PreverifiedTickHorizonWorker,
        tick_fanout: CommodityCFastExecutionQualityTickFanout,
    ) -> None:
        if type(horizon_worker) is not PreverifiedTickHorizonWorker:
            raise TypeError("PRODUCTION_ASSEMBLY_HORIZON_WORKER_TYPE_INVALID")
        if type(tick_fanout) is not CommodityCFastExecutionQualityTickFanout:
            raise TypeError("PRODUCTION_ASSEMBLY_TICK_FANOUT_TYPE_INVALID")
        with self._lock:
            if self._started:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_TICK_COMPONENT_BIND_AFTER_START_FORBIDDEN"
                )
            if self._sidecar is None or not horizon_worker.is_bound_to(self._sidecar):
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_WORKER_SOURCE_MISMATCH"
                )
            current = (self._horizon_worker, self._tick_fanout)
            requested = (horizon_worker, tick_fanout)
            if any(value is not None for value in current) and current != requested:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_TICK_COMPONENTS_ALREADY_BOUND"
                )
            self._horizon_worker = horizon_worker
            self._tick_fanout = tick_fanout
            self._component_binding_error = None

    def record_component_binding_failure(self, exc: BaseException) -> None:
        with self._lock:
            if self._started:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_COMPONENT_FAILURE_AFTER_START_FORBIDDEN"
                )
            self._component_binding_error = str(
                getattr(exc, "code", type(exc).__name__)
            )
            self._state = "BLOCKED_READONLY_COMPONENT_BINDING_FAILED"
            self._last_error = self._component_binding_error

    def start(self) -> dict[str, object]:
        return self._run_lifecycle("startup")

    def reload(self) -> dict[str, object]:
        return self._run_lifecycle("reload")

    def recover(self) -> dict[str, object]:
        return self._run_lifecycle("recovery")

    def stop(self) -> dict[str, object]:
        with self._lock:
            self._started = False
            self._admission = None
            self._last_export_receipt = None
            self._projection_revalidation_generation = None
            self._projection_receipt_sha256 = None
            self._verified_inputs_sha256 = None
            self._state = "STOPPED_NO_CAPABILITY"
            self._last_error = None
            if self._tick_fanout is not None:
                try:
                    fanout_status = self._tick_fanout.stop()
                    if fanout_status["worker_thread_running"] is True:
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_TICK_FANOUT_STOP_FAILED"
                        )
                except Exception as exc:
                    self._state = "BLOCKED_TICK_FANOUT_STOP_FAILED"
                    self._last_error = str(
                        getattr(exc, "code", type(exc).__name__)
                    )
            try:
                self._runtime.stop()
            except Exception as exc:
                self._state = "BLOCKED_LIFECYCLE_OPERATION_FAILED"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
            return self._status_locked()

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def intents(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            repository = self._require_current_projection_locked()
            return repository.intents()

    def execution_quality(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            repository = self._require_current_projection_locked()
            return repository.execution_quality()

    def evidence_export(self) -> dict[str, Any]:
        with self._lock:
            self._require_current_projection_locked()
            source = self._sidecar
            store = self._evidence_export_store
            receipt = self._last_export_receipt
            if source is None or store is None or receipt is None:
                raise CFastExecutionQualityProductionAssemblyError(
                    "PRODUCTION_ASSEMBLY_EVIDENCE_EXPORT_UNAVAILABLE"
                )
            filename = str(receipt["artifact_filename"])
            exported = store.load(filename, source=source)
            return {
                "artifact_filename": filename,
                "artifact_state": str(receipt["artifact_state"]),
                "export": exported.model_dump(mode="json"),
            }

    def _require_current_projection_locked(
        self,
    ) -> CommodityCFastExecutionQualityReadonlyRepository:
        repository = self._readonly_repository
        admission = self._admission
        if (
            repository is None
            or not self._started
            or admission is None
            or self._state
            not in {
                "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE",
                "SIGNED_ADMISSION_VERIFIED_READONLY_TICK_RUNTIME_BOUND",
            }
            or self._last_export_receipt is None
            or self._projection_revalidation_generation is None
            or self._projection_receipt_sha256 is None
        ):
            raise CFastExecutionQualityProductionAssemblyError(
                "PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE"
            )
        try:
            runtime_status = self._runtime.status()
            receipt = self._runtime.current_revalidation_receipt()
            now = self._runtime.clock()
            if (
                now.tzinfo is None
                or now.utcoffset() is None
                or now.utcoffset().total_seconds() != 0
                or runtime_status["revalidation_generation"]
                != self._projection_revalidation_generation
                or receipt.receipt_sha256 != self._projection_receipt_sha256
                or not receipt.revalidated_at_utc <= now < receipt.valid_until_utc
                or not admission.admission.not_before_utc
                <= now
                < admission.admission.expires_at_utc
            ):
                raise ValueError
        except Exception as exc:
            raise CFastExecutionQualityProductionAssemblyError(
                "PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_EXPIRED_OR_DRIFTED"
            ) from exc
        return repository

    def _run_lifecycle(
        self,
        trigger: RevalidationTrigger,
    ) -> dict[str, object]:
        with self._lock:
            self._started = True
            self._last_trigger = trigger
            self._admission = None
            self._last_export_receipt = None
            self._projection_revalidation_generation = None
            self._projection_receipt_sha256 = None
            self._verified_inputs_sha256 = None
            if self._tick_fanout is not None:
                try:
                    fanout_stop = self._tick_fanout.stop()
                    if fanout_stop["worker_thread_running"] is True:
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_TICK_FANOUT_STOP_FAILED"
                        )
                except Exception as exc:
                    self._state = "BLOCKED_TICK_FANOUT_STOP_FAILED"
                    self._last_error = str(
                        getattr(exc, "code", type(exc).__name__)
                    )
                    return self._status_locked()
            operation = {
                "startup": self._runtime.start,
                "reload": self._runtime.reload,
                "recovery": self._runtime.recover,
            }[trigger]
            try:
                runtime_status = operation()
                configured_enabled = runtime_status["configured_enabled"]
                revalidation_complete = runtime_status["full_revalidation_complete"]
                runtime_error = runtime_status["last_error"]
            except Exception as exc:
                self._state = "BLOCKED_LIFECYCLE_OPERATION_FAILED"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            if configured_enabled is False:
                self._state = "DISABLED_DEFAULT_OFF"
                self._last_error = None
                return self._status_locked()
            if revalidation_complete is not True:
                self._state = "BLOCKED_FULL_REVALIDATION_INCOMPLETE"
                self._last_error = str(runtime_error or "FULL_REVALIDATION_INCOMPLETE")
                return self._status_locked()
            try:
                receipt = self._runtime.current_revalidation_receipt()
                self._admission = self._admission_verifier.verify_for_revalidation(
                    receipt
                )
            except Exception as exc:
                self._state = "BLOCKED_SIGNED_RUNTIME_ADMISSION_INVALID"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            if self._component_binding_error is not None:
                self._state = "BLOCKED_READONLY_COMPONENT_BINDING_FAILED"
                self._last_error = self._component_binding_error
                return self._status_locked()
            source = self._sidecar
            repository = self._readonly_repository
            export_store = self._evidence_export_store
            if source is None or repository is None or export_store is None:
                self._state = "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
                self._last_error = None
                return self._status_locked()
            worker = self._horizon_worker
            fanout = self._tick_fanout
            if (worker is None) != (fanout is None):
                self._state = "BLOCKED_TICK_RUNTIME_COMPONENT_SET_INCOMPLETE"
                self._last_error = "TICK_RUNTIME_COMPONENT_SET_INCOMPLETE"
                return self._status_locked()
            tick_runtime_bound = worker is not None and fanout is not None
            if tick_runtime_bound:
                try:
                    verified_inputs = self._runtime.current_verified_runtime_inputs()
                    if (
                        verified_inputs.revalidation_receipt.receipt_sha256
                        != receipt.receipt_sha256
                    ):
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_TYPED_INPUT_RECEIPT_DRIFT"
                        )
                    input_identity = (
                        verified_inputs.preverified_plan.plan_hash,
                        verified_inputs.source_snapshot_receipt_sha256,
                        verified_inputs.score_policy_hash,
                        tuple(
                            spec.contract_spec_hash
                            for spec in verified_inputs.contract_specs
                        ),
                    )
                    if self._registered_input_identity is None:
                        worker.register_preverified_plan(
                            preverified_plan=verified_inputs.preverified_plan,
                            source_snapshot_receipt_sha256=(
                                verified_inputs.source_snapshot_receipt_sha256
                            ),
                            score_policy=verified_inputs.score_policy,
                            score_policy_hash=verified_inputs.score_policy_hash,
                            contract_specs=verified_inputs.contract_specs,
                        )
                        self._registered_input_identity = input_identity
                    elif self._registered_input_identity != input_identity:
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_FROZEN_TYPED_INPUT_DRIFT"
                        )
                    worker_status = worker.recover()
                    if worker_status["blocked_fail_closed"] is not False:
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_HORIZON_WORKER_RECOVERY_FAILED"
                        )
                    fanout_status = fanout.status()
                    if fanout_status["preverified_worker_bound"] is True:
                        fanout.refresh_preverified_subscription(
                            worker=worker,
                            revalidation_receipt=receipt,
                        )
                    else:
                        fanout.bind_preverified_subscription(
                            worker=worker,
                            revalidation_receipt=receipt,
                        )
                    self._verified_inputs_sha256 = (
                        verified_inputs.verified_inputs_sha256
                    )
                except Exception as exc:
                    self._state = "BLOCKED_TYPED_TICK_RUNTIME_ASSEMBLY_FAILED"
                    self._last_error = str(
                        getattr(exc, "code", type(exc).__name__)
                    )
                    return self._status_locked()
            try:
                repository_status = repository.recover()
            except Exception as exc:
                self._state = "BLOCKED_READONLY_REPOSITORY_FAILED"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            if repository_status["blocked_fail_closed"] is not False:
                self._state = "BLOCKED_READONLY_REPOSITORY_FAILED"
                self._last_error = str(repository_status["last_error"])
                return self._status_locked()
            if tuple(repository_status["exact_contracts"]) != receipt.exact_contracts:
                self._state = "BLOCKED_READONLY_REPOSITORY_SCOPE_MISMATCH"
                self._last_error = "READONLY_REPOSITORY_EXACT_CONTRACTS_MISMATCH"
                return self._status_locked()
            try:
                export_receipt = export_store.publish(source)
            except Exception as exc:
                self._state = "BLOCKED_EVIDENCE_EXPORT_FAILED"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            if (
                export_receipt["source_journal_record_count"]
                != repository_status["source_journal_record_count"]
                or export_receipt["source_journal_tip_record_hash"]
                != repository_status["source_journal_tip_record_hash"]
            ):
                self._state = "BLOCKED_READONLY_EXPORT_SNAPSHOT_DRIFT"
                self._last_error = "READONLY_REPOSITORY_EXPORT_TIP_MISMATCH"
                return self._status_locked()
            self._last_export_receipt = export_receipt
            self._projection_revalidation_generation = int(
                runtime_status["revalidation_generation"]
            )
            self._projection_receipt_sha256 = receipt.receipt_sha256
            if tick_runtime_bound:
                try:
                    started_fanout = fanout.start()
                    if (
                        started_fanout["blocked_fail_closed"] is not False
                        or started_fanout["worker_thread_running"] is not True
                        or started_fanout["tick_input_accepting"] is not True
                    ):
                        raise CFastExecutionQualityProductionAssemblyError(
                            "PRODUCTION_ASSEMBLY_TICK_FANOUT_START_FAILED"
                        )
                except Exception as exc:
                    self._state = "BLOCKED_TICK_FANOUT_START_FAILED"
                    self._last_error = str(
                        getattr(exc, "code", type(exc).__name__)
                    )
                    return self._status_locked()
                self._state = (
                    "SIGNED_ADMISSION_VERIFIED_READONLY_TICK_RUNTIME_BOUND"
                )
            else:
                self._state = (
                    "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
                )
            self._last_error = None
            return self._status_locked()

    def _status_locked(self) -> dict[str, object]:
        runtime_status = self._runtime.status()
        admission = self._admission
        repository_status = (
            self._readonly_repository.status()
            if self._readonly_repository is not None
            else None
        )
        export_receipt = self._last_export_receipt
        worker_status = (
            self._horizon_worker.status()
            if self._horizon_worker is not None
            else None
        )
        fanout_status = (
            self._tick_fanout.status() if self._tick_fanout is not None else None
        )
        tick_runtime_ready = bool(
            worker_status is not None
            and worker_status["blocked_fail_closed"] is False
            and worker_status["registered_intent_count"]
            and worker_status["exact_contract_subscription_frozen"] is True
            and fanout_status is not None
            and fanout_status["blocked_fail_closed"] is False
            and fanout_status["preverified_worker_bound"] is True
            and fanout_status["worker_thread_running"] is True
            and fanout_status["tick_input_accepting"] is True
        )
        durable_components_bound = all(
            value is not None
            for value in (
                self._sidecar,
                self._readonly_repository,
                self._evidence_export_store,
            )
        )
        return {
            **runtime_status,
            "schema_version": (
                "commodity_c_fast_execution_quality_production_assembly_status_v1"
            ),
            "assembly_state": self._state,
            "assembly_lifecycle_started": self._started,
            "assembly_last_trigger": self._last_trigger,
            "assembly_last_error": self._last_error,
            "readonly_component_binding_error": self._component_binding_error,
            "signed_runtime_admission_verified": admission is not None,
            "runtime_admission_id": (
                admission.admission.admission_id if admission is not None else None
            ),
            "runtime_admission_raw_sha256": (
                admission.admission_raw_sha256 if admission is not None else None
            ),
            "verified_runtime_inputs_sha256": self._verified_inputs_sha256,
            "tick_runtime_ready": tick_runtime_ready,
            "horizon_worker": worker_status,
            "tick_fanout": fanout_status,
            "readonly_repository": repository_status,
            "evidence_export": {
                "store_bound": self._evidence_export_store is not None,
                "latest_artifact_filename": (
                    str(export_receipt["artifact_filename"])
                    if export_receipt is not None
                    else None
                ),
                "latest_artifact_state": (
                    str(export_receipt["artifact_state"])
                    if export_receipt is not None
                    else None
                ),
                "immutable_create_only": True,
            },
            "runtime_active": False,
            "execution_quality_implemented": False,
            "capabilities": {
                **dict(runtime_status["capabilities"]),
                "signed_runtime_admission_verifier_bound": True,
                "signed_runtime_admission_verified": admission is not None,
                "tick_input_bound": bool(
                    fanout_status is not None
                    and fanout_status["preverified_worker_bound"] is True
                ),
                "tick_subscription_built": bool(
                    fanout_status is not None
                    and fanout_status["local_exact_contract_subscription_built"]
                    is True
                ),
                "horizon_worker_built": bool(
                    worker_status is not None
                    and worker_status["registered_intent_count"]
                ),
                "tick_runtime_ready": tick_runtime_ready,
                "durable_sidecar_runtime_bound": durable_components_bound,
                "readonly_repository_bound": self._readonly_repository is not None,
                "questdb_evidence_adapter_bound": False,
                "evidence_export_store_bound": self._evidence_export_store is not None,
                "api_projection_bound": durable_components_bound,
                "monitoring_projection_bound": True,
            },
            "denied_capabilities": list(_DENIED_CAPABILITIES),
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }


def _build_production_assembly() -> CommodityCFastExecutionQualityProductionAssembly:
    assembly = CommodityCFastExecutionQualityProductionAssembly(
        runtime=commodity_c_fast_execution_quality_runtime,
        admission_verifier=(
            commodity_c_fast_execution_quality_runtime_admission_verifier
        ),
    )
    settings = commodity_c_fast_execution_quality_runtime.settings
    if not settings.commodity_c_fast_execution_quality_runtime_enabled:
        return assembly
    try:
        artifact_paths_raw = json.loads(
            settings.commodity_c_fast_execution_quality_artifact_paths_json
        )
        if (
            not isinstance(artifact_paths_raw, dict)
            or set(artifact_paths_raw) != set(ARTIFACT_ROLES)
            or any(
                not isinstance(value, str) or not value
                for value in artifact_paths_raw.values()
            )
        ):
            raise CFastExecutionQualityProductionAssemblyError(
                "PRODUCTION_ASSEMBLY_ARTIFACT_PATH_SET_INVALID"
            )
        artifact_paths = {
            role: Path(artifact_paths_raw[role]).expanduser() for role in ARTIFACT_ROLES
        }
        revalidator = CommodityCFastExecutionQualityArtifactRevalidator(
            artifact_paths=artifact_paths,
            artifact_bundle_verifier=(
                CommodityCFastExecutionQualityProductionArtifactVerifier(
                    settings=settings
                )
            ),
            custody_root=Path(
                settings.commodity_c_fast_execution_quality_artifact_custody_root
            ).expanduser(),
            expected_custody_root_path_sha256=(
                settings.commodity_c_fast_execution_quality_artifact_expected_root_path_sha256
            ),
            expected_custody_identity_sha256=(
                settings.commodity_c_fast_execution_quality_artifact_expected_identity_sha256
            ),
            expected_owner_uid=(
                settings.commodity_c_fast_execution_quality_artifact_expected_owner_uid
            ),
        )
        sidecar = OfflineExecutionQualitySidecar(
            CreateOnlyExecutionQualityJournal(
                Path(settings.commodity_c_fast_execution_quality_journal_root)
            )
        )
        repository = CommodityCFastExecutionQualityReadonlyRepository(sidecar)
        export_store = CreateOnlyExecutionQualityEvidenceExportStore(
            Path(settings.commodity_c_fast_execution_quality_evidence_export_root)
        )
        assembly.bind_readonly_components(
            sidecar=sidecar,
            repository=repository,
            evidence_export_store=export_store,
        )
        assembly.bind_tick_runtime_components(
            horizon_worker=PreverifiedTickHorizonWorker(sidecar),
            tick_fanout=commodity_c_fast_execution_quality_tick_fanout,
        )
        # Publish the verifier capability only after every read-only component
        # has been constructed and bound successfully.  A later constructor
        # failure must not leave the process-global runtime half configured.
        commodity_c_fast_execution_quality_runtime.bind_full_revalidation_verifier(
            revalidator
        )
    except Exception as exc:
        assembly.record_component_binding_failure(exc)
    return assembly


commodity_c_fast_execution_quality_production_assembly = _build_production_assembly()


__all__ = [
    "CFastExecutionQualityProductionAssemblyError",
    "CommodityCFastExecutionQualityProductionAssembly",
    "RuntimeAdmissionVerifier",
    "commodity_c_fast_execution_quality_production_assembly",
]
