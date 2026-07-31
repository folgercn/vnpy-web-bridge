from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from typing import Callable, Protocol

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
    RevalidationTrigger,
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
_REQUIRED_REVALIDATION_CHECKS = (
    "signed_p0_acceptance",
    "collection_admission",
    "execution_policy",
    "signed_snapshot",
    "virtual_intent_plan",
    "contract_spec_set",
    "custody_binding",
)
_DENIED_CAPABILITIES = (
    "account",
    "cancel_order",
    "gateway",
    "position",
    "rpc",
    "send_order",
    "trade_service",
)


class CFastExecutionQualityRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FullExecutionQualityRevalidationVerifier(Protocol):
    """Future adapter that independently replays every signed authority."""

    def __call__(
        self,
        trigger: RevalidationTrigger,
        observed_at_utc: datetime,
    ) -> CFastExecutionQualityRuntimeRevalidationDTO: ...


class CommodityCFastExecutionQualityRuntime:
    """Default-off lifecycle and revalidation boundary for Issue #217.

    The foundation deliberately has no Tick, repository, RPC or trading
    dependency.  Enabling the setting can only request revalidation; it cannot
    activate collection or claim the complete execution-quality capability.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._full_revalidation_verifier: (
            FullExecutionQualityRevalidationVerifier | None
        ) = None
        self._runtime_state = "CREATED_DEFAULT_OFF"
        self._started = False
        self._generation = 0
        self._last_trigger: RevalidationTrigger | None = None
        self._last_error: str | None = None
        self._receipt: (
            CFastExecutionQualityRuntimeRevalidationDTO | None
        ) = None

    def bind_full_revalidation_verifier(
        self,
        verifier: FullExecutionQualityRevalidationVerifier,
    ) -> None:
        if not callable(verifier):
            raise CFastExecutionQualityRuntimeError(
                "FULL_REVALIDATION_VERIFIER_INVALID"
            )
        with self._lock:
            if self._started:
                raise CFastExecutionQualityRuntimeError(
                    "FULL_REVALIDATION_BIND_AFTER_START_FORBIDDEN"
                )
            if (
                self._full_revalidation_verifier is not None
                and self._full_revalidation_verifier is not verifier
            ):
                raise CFastExecutionQualityRuntimeError(
                    "FULL_REVALIDATION_VERIFIER_ALREADY_BOUND"
                )
            self._full_revalidation_verifier = verifier

    def start(self) -> dict[str, object]:
        return self._run_lifecycle_revalidation("startup")

    def reload(self) -> dict[str, object]:
        return self._run_lifecycle_revalidation("reload")

    def recover(self) -> dict[str, object]:
        return self._run_lifecycle_revalidation("recovery")

    def stop(self) -> dict[str, object]:
        with self._lock:
            self._started = False
            self._receipt = None
            self._runtime_state = "STOPPED_NO_CAPABILITY"
            return self._status_locked()

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def _run_lifecycle_revalidation(
        self,
        trigger: RevalidationTrigger,
    ) -> dict[str, object]:
        with self._lock:
            self._started = True
            self._receipt = None
            self._last_trigger = trigger
            if not self.settings.commodity_c_fast_execution_quality_runtime_enabled:
                self._runtime_state = "DISABLED_DEFAULT_OFF"
                self._last_error = None
                return self._status_locked()
            if self._full_revalidation_verifier is None:
                self._runtime_state = (
                    "BLOCKED_FULL_REVALIDATION_VERIFIER_NOT_BOUND"
                )
                self._last_error = "FULL_REVALIDATION_VERIFIER_NOT_BOUND"
                return self._status_locked()

            try:
                observed_at_utc = self._utc_now()
                candidate = self._full_revalidation_verifier(
                    trigger,
                    observed_at_utc,
                )
                receipt = (
                    CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
                        candidate
                    )
                )
                self._validate_receipt(
                    receipt,
                    trigger=trigger,
                    observed_at_utc=observed_at_utc,
                )
            except Exception as exc:
                self._runtime_state = "BLOCKED_FULL_REVALIDATION_FAILED"
                self._last_error = (
                    exc.code
                    if isinstance(exc, CFastExecutionQualityRuntimeError)
                    else type(exc).__name__
                )
                return self._status_locked()

            self._receipt = receipt
            self._generation += 1
            self._runtime_state = (
                "REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT"
            )
            self._last_error = None
            return self._status_locked()

    def _validate_receipt(
        self,
        receipt: CFastExecutionQualityRuntimeRevalidationDTO,
        *,
        trigger: RevalidationTrigger,
        observed_at_utc: datetime,
    ) -> None:
        if receipt.trigger != trigger:
            raise CFastExecutionQualityRuntimeError(
                "REVALIDATION_TRIGGER_MISMATCH"
            )
        if receipt.revalidated_at_utc != observed_at_utc:
            raise CFastExecutionQualityRuntimeError(
                "REVALIDATION_CLOCK_BINDING_MISMATCH"
            )
        if receipt.valid_until_utc <= observed_at_utc:
            raise CFastExecutionQualityRuntimeError(
                "REVALIDATION_RECEIPT_EXPIRED"
            )

    def _utc_now(self) -> datetime:
        value = self.clock()
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise CFastExecutionQualityRuntimeError(
                "RUNTIME_CLOCK_MUST_USE_UTC"
            )
        return value

    def _status_locked(self) -> dict[str, object]:
        receipt = self._receipt
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_runtime_status_v1"
            ),
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "runtime_state": self._runtime_state,
            "configured_enabled": (
                self.settings.commodity_c_fast_execution_quality_runtime_enabled
            ),
            "lifecycle_started": self._started,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "full_revalidation_complete": receipt is not None,
            "revalidation_generation": self._generation,
            "last_revalidation_trigger": self._last_trigger,
            "last_error": self._last_error,
            "revalidation_receipt_sha256": (
                receipt.receipt_sha256 if receipt is not None else None
            ),
            "revalidation_valid_until_utc": (
                receipt.valid_until_utc.isoformat().replace("+00:00", "Z")
                if receipt is not None
                else None
            ),
            "exact_contracts": (
                list(receipt.exact_contracts)
                if receipt is not None
                else []
            ),
            "required_revalidation_checks": list(
                _REQUIRED_REVALIDATION_CHECKS
            ),
            "revalidation_checks": {
                name: "VERIFIED" if receipt is not None else "NOT_VERIFIED"
                for name in _REQUIRED_REVALIDATION_CHECKS
            },
            "revalidation_bindings_sha256": {
                "signed_p0_acceptance": (
                    receipt.signed_p0_acceptance_sha256
                    if receipt is not None
                    else None
                ),
                "collection_admission": (
                    receipt.collection_admission_sha256
                    if receipt is not None
                    else None
                ),
                "execution_policy": (
                    receipt.execution_policy_sha256
                    if receipt is not None
                    else None
                ),
                "signed_snapshot": (
                    receipt.signed_snapshot_sha256
                    if receipt is not None
                    else None
                ),
                "virtual_intent_plan": (
                    receipt.virtual_intent_plan_sha256
                    if receipt is not None
                    else None
                ),
                "contract_spec_set": (
                    receipt.contract_spec_set_sha256
                    if receipt is not None
                    else None
                ),
                "custody_binding": (
                    receipt.custody_binding_sha256
                    if receipt is not None
                    else None
                ),
            },
            "capabilities": {
                "full_revalidation_verifier_bound": (
                    self._full_revalidation_verifier is not None
                ),
                "tick_input_bound": False,
                "tick_subscription_built": False,
                "horizon_worker_built": False,
                "durable_sidecar_runtime_bound": False,
                "readonly_repository_bound": False,
                "questdb_evidence_adapter_bound": False,
            },
            "denied_capabilities": list(_DENIED_CAPABILITIES),
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }


commodity_c_fast_execution_quality_runtime = (
    CommodityCFastExecutionQualityRuntime()
)
