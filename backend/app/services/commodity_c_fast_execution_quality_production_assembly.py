from __future__ import annotations

from threading import RLock
from typing import Protocol

from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
    RevalidationTrigger,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
    commodity_c_fast_execution_quality_runtime,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (
    VerifiedCFastExecutionQualityRuntimeAdmission,
    commodity_c_fast_execution_quality_runtime_admission_consumer,
)
from app.services.commodity_c_fast_execution_quality_readonly_repository import (
    CommodityCFastExecutionQualityReadonlyRepository,
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


class RuntimeAdmissionConsumer(Protocol):
    def verify_for_receipt(
        self,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> VerifiedCFastExecutionQualityRuntimeAdmission: ...


class CommodityCFastExecutionQualityProductionAssembly:
    """Default-off production assembly gate for the read-only sidecar.

    This first assembly slice verifies a fresh full-revalidation receipt and
    its independently signed runtime admission on every lifecycle transition.
    Tick, repository, export and monitoring components are intentionally not
    represented as built until later slices bind the complete capability. The
    admission is not an irreversible one-shot consume token in this slice.
    """

    def __init__(
        self,
        *,
        runtime: CommodityCFastExecutionQualityRuntime,
        admission_consumer: RuntimeAdmissionConsumer,
    ) -> None:
        if type(runtime) is not CommodityCFastExecutionQualityRuntime:
            raise TypeError("PRODUCTION_ASSEMBLY_RUNTIME_TYPE_INVALID")
        if not callable(getattr(admission_consumer, "verify_for_receipt", None)):
            raise TypeError("PRODUCTION_ASSEMBLY_ADMISSION_CONSUMER_INVALID")
        self._runtime = runtime
        self._admission_consumer = admission_consumer
        self._lock = RLock()
        self._state = "CREATED_DEFAULT_OFF"
        self._started = False
        self._last_trigger: RevalidationTrigger | None = None
        self._last_error: str | None = None
        self._admission: VerifiedCFastExecutionQualityRuntimeAdmission | None = None
        self._readonly_repository: (
            CommodityCFastExecutionQualityReadonlyRepository | None
        ) = None

    def bind_readonly_repository(
        self,
        repository: CommodityCFastExecutionQualityReadonlyRepository,
    ) -> None:
        if type(repository) is not CommodityCFastExecutionQualityReadonlyRepository:
            raise TypeError("PRODUCTION_ASSEMBLY_READONLY_REPOSITORY_TYPE_INVALID")
        with self._lock:
            if self._started:
                raise RuntimeError(
                    "PRODUCTION_ASSEMBLY_REPOSITORY_BIND_AFTER_START_FORBIDDEN"
                )
            if (
                self._readonly_repository is not None
                and self._readonly_repository is not repository
            ):
                raise RuntimeError(
                    "PRODUCTION_ASSEMBLY_READONLY_REPOSITORY_ALREADY_BOUND"
                )
            self._readonly_repository = repository

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
            self._state = "STOPPED_NO_CAPABILITY"
            self._last_error = None
            self._runtime.stop()
            return self._status_locked()

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def _run_lifecycle(
        self,
        trigger: RevalidationTrigger,
    ) -> dict[str, object]:
        with self._lock:
            self._started = True
            self._last_trigger = trigger
            self._admission = None
            operation = {
                "startup": self._runtime.start,
                "reload": self._runtime.reload,
                "recovery": self._runtime.recover,
            }[trigger]
            runtime_status = operation()
            if runtime_status["configured_enabled"] is False:
                self._state = "DISABLED_DEFAULT_OFF"
                self._last_error = None
                return self._status_locked()
            if runtime_status["full_revalidation_complete"] is not True:
                self._state = "BLOCKED_FULL_REVALIDATION_INCOMPLETE"
                self._last_error = str(
                    runtime_status["last_error"] or "FULL_REVALIDATION_INCOMPLETE"
                )
                return self._status_locked()
            try:
                receipt = self._runtime.current_revalidation_receipt()
                self._admission = self._admission_consumer.verify_for_receipt(receipt)
            except Exception as exc:
                self._state = "BLOCKED_SIGNED_RUNTIME_ADMISSION_INVALID"
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            if self._readonly_repository is not None:
                repository_status = self._readonly_repository.recover()
                if repository_status["blocked_fail_closed"] is not False:
                    self._state = "BLOCKED_READONLY_REPOSITORY_FAILED"
                    self._last_error = str(repository_status["last_error"])
                    return self._status_locked()
            self._state = "SIGNED_ADMISSION_VERIFIED_ASSEMBLY_COMPONENTS_INCOMPLETE"
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
        return {
            **runtime_status,
            "schema_version": (
                "commodity_c_fast_execution_quality_production_assembly_status_v1"
            ),
            "assembly_state": self._state,
            "assembly_lifecycle_started": self._started,
            "assembly_last_trigger": self._last_trigger,
            "assembly_last_error": self._last_error,
            "signed_runtime_admission_verified": admission is not None,
            "runtime_admission_id": (
                admission.admission.admission_id if admission is not None else None
            ),
            "runtime_admission_raw_sha256": (
                admission.admission_raw_sha256 if admission is not None else None
            ),
            "readonly_repository": repository_status,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "capabilities": {
                **dict(runtime_status["capabilities"]),
                "signed_runtime_admission_consumer_bound": True,
                "signed_runtime_admission_verified": admission is not None,
                "tick_input_bound": False,
                "tick_subscription_built": False,
                "horizon_worker_built": False,
                "durable_sidecar_runtime_bound": False,
                "readonly_repository_bound": (self._readonly_repository is not None),
                "questdb_evidence_adapter_bound": False,
                "evidence_export_store_bound": False,
                "api_projection_bound": False,
                "monitoring_projection_bound": False,
            },
            "denied_capabilities": list(_DENIED_CAPABILITIES),
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }


commodity_c_fast_execution_quality_production_assembly = (
    CommodityCFastExecutionQualityProductionAssembly(
        runtime=commodity_c_fast_execution_quality_runtime,
        admission_consumer=(
            commodity_c_fast_execution_quality_runtime_admission_consumer
        ),
    )
)


__all__ = [
    "CommodityCFastExecutionQualityProductionAssembly",
    "RuntimeAdmissionConsumer",
    "commodity_c_fast_execution_quality_production_assembly",
]
