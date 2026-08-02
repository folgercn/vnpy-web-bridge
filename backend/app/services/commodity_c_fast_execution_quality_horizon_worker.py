from __future__ import annotations

from threading import RLock
from typing import Any

from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionQualityCollectionPolicyV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPlanDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
    CFastL1L5BookSnapshotDTO,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    CFastExecutionQualitySidecarError,
    OfflineExecutionQualitySidecar,
    SidecarState,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


_TARGET_KEYS = ("decision", "250", "1000", "5000", "30000", "60000")
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


class CFastExecutionQualityHorizonWorkerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PreverifiedTickHorizonWorker:
    """Synchronous code-only driver for the durable Research Plane sidecar.

    The worker accepts only already typed, caller-preverified plans, policies,
    contract specs and L1-L5 snapshots. It neither verifies external
    signatures nor obtains Tick, repository, RPC or trading capabilities.
    """

    def __init__(self, sidecar: OfflineExecutionQualitySidecar) -> None:
        if type(sidecar) is not OfflineExecutionQualitySidecar:
            raise CFastExecutionQualityHorizonWorkerError(
                "PREVERIFIED_SIDECAR_TYPE_INVALID"
            )
        self._sidecar = sidecar
        self._lock = RLock()
        self._worker_state = "CREATED_CODE_ONLY_NOT_ACTIVATED"
        self._last_error: str | None = None
        self._blocked = False
        self._frozen_exact_contracts: tuple[str, ...] | None = None

    def is_bound_to(self, sidecar: OfflineExecutionQualitySidecar) -> bool:
        """Prove identity with the durable source owned by the assembly."""

        return self._sidecar is sidecar

    def register_preverified_plan(
        self,
        *,
        preverified_plan: CFastVirtualIntentPlanDTO,
        source_snapshot_receipt_sha256: str,
        score_policy: CFastExecutionQualityCollectionPolicyV2DTO,
        score_policy_hash: str,
        contract_specs: tuple[CFastExecutionQualityContractSpecDTO, ...],
    ) -> dict[str, Any]:
        """Durably register every virtual intent after a complete type join."""

        with self._lock:
            if self._frozen_exact_contracts is not None:
                raise CFastExecutionQualityHorizonWorkerError(
                    "PREVERIFIED_EXACT_CONTRACTS_FROZEN"
                )
            try:
                plan = self._revalidate_model(
                    preverified_plan,
                    CFastVirtualIntentPlanDTO,
                    "PREVERIFIED_PLAN_TYPE_INVALID",
                )
                policy = self._revalidate_model(
                    score_policy,
                    CFastExecutionQualityCollectionPolicyV2DTO,
                    "PREVERIFIED_SCORE_POLICY_TYPE_INVALID",
                )
                specs = self._revalidate_specs(contract_specs)
                if not plan.intents:
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_PLAN_HAS_NO_INTENTS"
                    )
                if source_snapshot_receipt_sha256 != plan.snapshot_hash:
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_SNAPSHOT_RECEIPT_MISMATCH"
                    )
                expected_policy_hash = sha256_json(
                    policy.model_dump(mode="json")
                )
                if (
                    score_policy_hash != expected_policy_hash
                    or policy.foundation_policy_hash != plan.policy_hash
                ):
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_SCORE_POLICY_BINDING_MISMATCH"
                    )
                spec_by_contract = {
                    spec.exact_contract: spec for spec in specs
                }
                if len(spec_by_contract) != len(specs):
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_CONTRACT_SPEC_DUPLICATE"
                    )
                exact_contracts = {
                    intent.exact_contract for intent in plan.intents
                }
                if set(spec_by_contract) != exact_contracts:
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_CONTRACT_SPEC_SET_MISMATCH"
                    )
                existing = self._sidecar.recover()
                self._require_incomplete_plan_recovery_matches(
                    existing,
                    plan,
                )

                anchors: dict[str, str] = {}
                for intent in plan.intents:
                    anchor = self._sidecar.register_preverified_intent(
                        preverified_plan=plan,
                        intent_id=intent.intent_id,
                        source_snapshot_receipt_sha256=(
                            source_snapshot_receipt_sha256
                        ),
                        score_policy=policy,
                        score_policy_hash=score_policy_hash,
                        contract_spec=spec_by_contract[
                            intent.exact_contract
                        ],
                    )
                    anchors[intent.intent_id] = anchor.isoformat().replace(
                        "+00:00", "Z"
                    )
                created_evidence = self._seal_all_ready_locked()
            except (
                CFastExecutionQualityHorizonWorkerError,
                CFastExecutionQualitySidecarError,
                ValidationError,
            ) as exc:
                self._block(exc)
                if isinstance(
                    exc, CFastExecutionQualityHorizonWorkerError
                ):
                    raise
                raise self._translate(exc) from exc

            self._worker_state = (
                "PREVERIFIED_INPUTS_DURABLE_CODE_ONLY_NOT_ACTIVATED"
            )
            self._blocked = False
            self._last_error = None
            return {
                "schema_version": (
                    "commodity_c_fast_execution_quality_horizon_worker_"
                    "registration_v1"
                ),
                "plan_hash": plan.plan_hash,
                "registered_intent_ids": list(anchors),
                "durable_anchors_utc": anchors,
                "accepted_exact_contracts": sorted(exact_contracts),
                "created_evidence_count": created_evidence,
                "runtime_active": False,
                "execution_quality_implemented": False,
                "orders_sent": 0,
                "positions_modified": 0,
                **_FALSE_AUTHORITY,
            }

    def accept_preverified_tick(
        self,
        snapshot: CFastL1L5BookSnapshotDTO,
    ) -> dict[str, Any]:
        """Append one accepted exact-contract tick and seal ready horizons."""

        with self._lock:
            self._require_unblocked()
            try:
                tick = self._revalidate_model(
                    snapshot,
                    CFastL1L5BookSnapshotDTO,
                    "PREVERIFIED_TICK_TYPE_INVALID",
                )
                before = self._sidecar.recover()
                self._require_complete_plan_state(before)
                if (
                    self._frozen_exact_contracts is not None
                    and self._accepted_exact_contracts(before)
                    != self._frozen_exact_contracts
                ):
                    raise CFastExecutionQualityHorizonWorkerError(
                        "DURABLE_EXACT_CONTRACT_SET_DRIFT"
                    )
                affected_intents = self._intent_ids_for_contract(
                    before,
                    tick.exact_contract,
                )
                if not affected_intents:
                    return {
                        "schema_version": (
                            "commodity_c_fast_execution_quality_horizon_"
                            "worker_tick_v1"
                        ),
                        "tick_state": (
                            "IGNORED_OUTSIDE_DURABLY_ACCEPTED_EXACT_CONTRACTS"
                        ),
                        "book_snapshot_hash": tick.book_snapshot_hash,
                        "exact_contract": tick.exact_contract,
                        "affected_intent_ids": [],
                        "snapshot_created": False,
                        "created_evidence_count": 0,
                        "runtime_active": False,
                        "execution_quality_implemented": False,
                        "orders_sent": 0,
                        "positions_modified": 0,
                        **_FALSE_AUTHORITY,
                    }
                existing_record_hashes = {
                    row.record_hash for row in before.snapshots
                }
                record = self._sidecar.append_preverified_snapshot(tick)
                created_evidence = 0
                for intent_id in affected_intents:
                    created_evidence += len(
                        self._sidecar.seal_ready_evidence(intent_id)
                    )
            except (
                CFastExecutionQualityHorizonWorkerError,
                CFastExecutionQualitySidecarError,
                ValidationError,
            ) as exc:
                self._block(exc)
                if isinstance(
                    exc, CFastExecutionQualityHorizonWorkerError
                ):
                    raise
                raise self._translate(exc) from exc

            self._worker_state = (
                "PREVERIFIED_TICK_PROCESSED_CODE_ONLY_NOT_ACTIVATED"
            )
            self._last_error = None
            return {
                "schema_version": (
                    "commodity_c_fast_execution_quality_horizon_worker_tick_v1"
                ),
                "tick_state": "PREVERIFIED_TICK_DURABLY_PROCESSED",
                "book_snapshot_hash": tick.book_snapshot_hash,
                "snapshot_record_hash": record.record_hash,
                "exact_contract": tick.exact_contract,
                "affected_intent_ids": affected_intents,
                "snapshot_created": (
                    record.record_hash not in existing_record_hashes
                ),
                "created_evidence_count": created_evidence,
                "runtime_active": False,
                "execution_quality_implemented": False,
                "orders_sent": 0,
                "positions_modified": 0,
                **_FALSE_AUTHORITY,
            }

    def freeze_preverified_exact_contracts(
        self,
        exact_contracts: tuple[str, ...],
    ) -> dict[str, Any]:
        """Freeze one caller-preverified local subscription contract set."""

        if (
            type(exact_contracts) is not tuple
            or not exact_contracts
            or any(
                not isinstance(exact_contract, str) or not exact_contract
                for exact_contract in exact_contracts
            )
            or len(set(exact_contracts)) != len(exact_contracts)
            or tuple(sorted(exact_contracts)) != exact_contracts
        ):
            raise CFastExecutionQualityHorizonWorkerError(
                "PREVERIFIED_EXACT_CONTRACT_FREEZE_INPUT_INVALID"
            )
        with self._lock:
            self._require_unblocked()
            state = self._sidecar.recover()
            self._require_complete_plan_state(state)
            accepted = self._accepted_exact_contracts(state)
            if accepted != exact_contracts:
                raise CFastExecutionQualityHorizonWorkerError(
                    "PREVERIFIED_EXACT_CONTRACT_FREEZE_MISMATCH"
                )
            if self._frozen_exact_contracts is not None:
                if self._frozen_exact_contracts != exact_contracts:
                    raise CFastExecutionQualityHorizonWorkerError(
                        "PREVERIFIED_EXACT_CONTRACT_FREEZE_ALREADY_BOUND"
                    )
            else:
                self._frozen_exact_contracts = exact_contracts
            self._worker_state = (
                "PREVERIFIED_EXACT_CONTRACTS_FROZEN_CODE_ONLY_NOT_ACTIVATED"
            )
            return {
                "schema_version": (
                    "commodity_c_fast_execution_quality_horizon_worker_"
                    "exact_contract_freeze_v1"
                ),
                "frozen_exact_contracts": list(exact_contracts),
                "tick_subscription_frozen": True,
                "runtime_active": False,
                "execution_quality_implemented": False,
                "orders_sent": 0,
                "positions_modified": 0,
                **_FALSE_AUTHORITY,
            }

    def recover(self) -> dict[str, Any]:
        """Replay the journal and seal work made ready before a restart."""

        with self._lock:
            try:
                created_evidence = self._seal_all_ready_locked()
            except (
                CFastExecutionQualityHorizonWorkerError,
                CFastExecutionQualitySidecarError,
                ValidationError,
            ) as exc:
                self._block(exc)
                if isinstance(
                    exc, CFastExecutionQualityHorizonWorkerError
                ):
                    raise
                raise self._translate(exc) from exc
            self._blocked = False
            self._worker_state = "RECOVERED_CODE_ONLY_NOT_ACTIVATED"
            self._last_error = None
            return {
                **self._status_locked(),
                "created_evidence_count": created_evidence,
            }

    def status(self) -> dict[str, Any]:
        with self._lock:
            try:
                return self._status_locked()
            except Exception as exc:
                self._block(exc)
                return self._blocked_status_locked()

    def _seal_all_ready_locked(self) -> int:
        state = self._sidecar.recover()
        self._require_complete_plan_state(state)
        created = 0
        intent_records = sorted(
            state.intents.values(),
            key=lambda record: record.sequence,
        )
        for record in intent_records:
            intent_id = str(record.payload["intent"]["intent_id"])
            created += len(self._sidecar.seal_ready_evidence(intent_id))
        return created

    @staticmethod
    def _require_complete_plan_state(state: SidecarState) -> None:
        incomplete = PreverifiedTickHorizonWorker._incomplete_plan_hashes(
            state
        )
        if incomplete:
            raise CFastExecutionQualityHorizonWorkerError(
                "DURABLE_PLAN_INTENT_SET_INCOMPLETE"
            )

    def _status_locked(self) -> dict[str, Any]:
        state = self._sidecar.recover()
        self._require_complete_plan_state(state)
        accepted_contracts = list(self._accepted_exact_contracts(state))
        completion_counts = {
            "SEALED_SELECTED_EVIDENCE": 0,
            "SEALED_MISSING_NOT_IMPUTED": 0,
            "PENDING_NOT_SEALED": 0,
        }
        for intent_id in state.anchors:
            for target_key in _TARGET_KEYS:
                record = state.evidence.get((intent_id, target_key))
                completion = (
                    str(record.payload["completion_state"])
                    if record is not None
                    else "PENDING_NOT_SEALED"
                )
                completion_counts[completion] += 1
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_horizon_worker_status_v1"
            ),
            "worker_state": self._worker_state,
            "blocked_fail_closed": self._blocked,
            "last_error": self._last_error,
            "registered_intent_count": len(state.anchors),
            "accepted_exact_contracts": accepted_contracts,
            "exact_contract_subscription_frozen": (
                self._frozen_exact_contracts is not None
            ),
            "frozen_exact_contracts": list(
                self._frozen_exact_contracts or ()
            ),
            "snapshot_record_count": len(state.snapshots),
            "evidence_record_count": len(state.evidence),
            "completion_counts": completion_counts,
            "horizon_schedule_ms": [250, 1_000, 5_000, 30_000, 60_000],
            "input_contract": (
                "CALLER_PREVERIFIED_STRONG_TYPES_ONLY_NO_SIGNATURE_AUTHORITY"
            ),
            "tick_subscription_built": False,
            "settings_or_startup_bound": False,
            "external_repository_bound": False,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }

    @staticmethod
    def _require_incomplete_plan_recovery_matches(
        state: SidecarState,
        plan: CFastVirtualIntentPlanDTO,
    ) -> None:
        incomplete = PreverifiedTickHorizonWorker._incomplete_plan_hashes(
            state
        )
        if not incomplete:
            return
        expected_by_plan, _ = (
            PreverifiedTickHorizonWorker._durable_plan_intent_sets(state)
        )
        incoming_expected = tuple(
            intent.intent_id for intent in plan.intents
        )
        if (
            incomplete != {plan.plan_hash}
            or expected_by_plan.get(plan.plan_hash) != incoming_expected
        ):
            raise CFastExecutionQualityHorizonWorkerError(
                "INCOMPLETE_PLAN_RECOVERY_MISMATCH"
            )

    @staticmethod
    def _incomplete_plan_hashes(state: SidecarState) -> set[str]:
        expected_by_plan, actual_by_plan = (
            PreverifiedTickHorizonWorker._durable_plan_intent_sets(state)
        )
        incomplete = {
            plan_hash
            for plan_hash, expected_ids in expected_by_plan.items()
            if actual_by_plan.get(plan_hash, ()) != expected_ids
        }
        for intent_id, record in state.intents.items():
            if intent_id not in state.anchors:
                incomplete.add(
                    str(record.payload["preverified_plan_hash"])
                )
        return incomplete

    @staticmethod
    def _durable_plan_intent_sets(
        state: SidecarState,
    ) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
        expected_by_plan: dict[str, tuple[str, ...]] = {}
        actual_lists: dict[str, list[str]] = {}
        for record in sorted(
            state.intents.values(),
            key=lambda item: item.sequence,
        ):
            plan_hash = str(record.payload["preverified_plan_hash"])
            expected_ids = tuple(
                str(intent_id)
                for intent_id in record.payload["expected_plan_intent_ids"]
            )
            prior_expected = expected_by_plan.get(plan_hash)
            if prior_expected is not None and prior_expected != expected_ids:
                raise CFastExecutionQualityHorizonWorkerError(
                    "DURABLE_PLAN_EXPECTED_SET_MISMATCH"
                )
            expected_by_plan[plan_hash] = expected_ids
            actual_lists.setdefault(plan_hash, []).append(
                str(record.payload["intent"]["intent_id"])
            )
        return expected_by_plan, {
            plan_hash: tuple(intent_ids)
            for plan_hash, intent_ids in actual_lists.items()
        }

    def _blocked_status_locked(self) -> dict[str, Any]:
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_horizon_worker_status_v1"
            ),
            "worker_state": "BLOCKED_FAIL_CLOSED",
            "blocked_fail_closed": True,
            "last_error": self._last_error,
            "registered_intent_count": None,
            "accepted_exact_contracts": [],
            "exact_contract_subscription_frozen": (
                self._frozen_exact_contracts is not None
            ),
            "frozen_exact_contracts": list(
                self._frozen_exact_contracts or ()
            ),
            "snapshot_record_count": None,
            "evidence_record_count": None,
            "completion_counts": None,
            "horizon_schedule_ms": [250, 1_000, 5_000, 30_000, 60_000],
            "input_contract": (
                "CALLER_PREVERIFIED_STRONG_TYPES_ONLY_NO_SIGNATURE_AUTHORITY"
            ),
            "tick_subscription_built": False,
            "settings_or_startup_bound": False,
            "external_repository_bound": False,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }

    @staticmethod
    def _accepted_exact_contracts(
        state: SidecarState,
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    str(record.payload["intent"]["exact_contract"])
                    for intent_id, record in state.intents.items()
                    if intent_id in state.anchors
                }
            )
        )

    @staticmethod
    def _intent_ids_for_contract(
        state: SidecarState,
        exact_contract: str,
    ) -> list[str]:
        return [
            str(record.payload["intent"]["intent_id"])
            for record in sorted(
                state.intents.values(),
                key=lambda item: item.sequence,
            )
            if record.payload["intent"]["exact_contract"] == exact_contract
            and record.payload["intent"]["intent_id"] in state.anchors
        ]

    @staticmethod
    def _revalidate_specs(
        contract_specs: tuple[CFastExecutionQualityContractSpecDTO, ...],
    ) -> tuple[CFastExecutionQualityContractSpecDTO, ...]:
        if type(contract_specs) is not tuple or any(
            type(spec) is not CFastExecutionQualityContractSpecDTO
            for spec in contract_specs
        ):
            raise CFastExecutionQualityHorizonWorkerError(
                "PREVERIFIED_CONTRACT_SPEC_TYPE_INVALID"
            )
        try:
            return tuple(
                CFastExecutionQualityContractSpecDTO.model_validate(
                    spec.model_dump(mode="json")
                )
                for spec in contract_specs
            )
        except ValidationError as exc:
            raise CFastExecutionQualityHorizonWorkerError(
                "PREVERIFIED_CONTRACT_SPEC_TYPE_INVALID"
            ) from exc

    @staticmethod
    def _revalidate_model(value: Any, expected_type: type, code: str):
        if type(value) is not expected_type:
            raise CFastExecutionQualityHorizonWorkerError(code)
        try:
            return expected_type.model_validate(value.model_dump(mode="json"))
        except ValidationError as exc:
            raise CFastExecutionQualityHorizonWorkerError(code) from exc

    def _require_unblocked(self) -> None:
        if self._blocked:
            raise CFastExecutionQualityHorizonWorkerError(
                "WORKER_BLOCKED_REQUIRES_EXPLICIT_RECOVERY"
            )

    def _block(self, exc: Exception) -> None:
        self._blocked = True
        self._worker_state = "BLOCKED_FAIL_CLOSED"
        self._last_error = getattr(exc, "code", type(exc).__name__)

    @staticmethod
    def _translate(exc: Exception) -> CFastExecutionQualityHorizonWorkerError:
        if isinstance(exc, CFastExecutionQualityHorizonWorkerError):
            return exc
        return CFastExecutionQualityHorizonWorkerError(
            getattr(exc, "code", type(exc).__name__)
        )
