"""Issue #291 Phase A Execution Orchestrator core.

The class in this module owns the final Linux-side execution state.  It does
not import the legacy FastAPI singleton or any strategy/worker service.  The
only gateway calls are made after durable intent persistence and a fresh
leader/fencing admission check.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import uuid4

from .errors import (
    AuthorityRejected,
    CommandValidationError,
    ExpectedVersionConflict,
    FencingError,
    GatewayTimeout,
    GatewayUnavailable,
    IdempotencyConflictError,
    MutationRejected,
    PlanRejected,
    RepositoryUnavailableError,
    RestartReconciliationRequired,
    SnapshotRejected,
    UnknownOutcomeError,
)
from .fencing import LeaderFencer
from .gateway import (
    ExecutionGateway,
    GatewaySnapshot,
    InMemoryGateway,
    MutationContext,
    NullGateway,
)
from .models import (
    EPOCH_TIMESTAMP,
    SERVICE,
    UNKNOWN_ID,
    ZERO_HASH,
    AuthorityState,
    BrokerState,
    CommandEnvelope,
    CommandReceipt,
    LeaderToken,
    PlanState,
    SendIntent,
    canonical_json,
    format_utc,
    parse_utc,
    sha256_json,
    utc_now,
    validate_idempotency_key,
    validate_identifier,
    validate_sha256,
)
from .repository import DurableExecutionRepository, InMemoryExecutionRepository

MUTATING_COMMANDS = {
    "preview",
    "enable",
    "revoke",
    "start",
    "stop",
    "reconcile",
    "drain",
}
ACTIVE_INTENT_STATES = {
    "PERSISTED",
    "SUBMITTED",
    "ACKNOWLEDGED",
    "CANCEL_REQUESTED",
}


class CommandResponse(dict[str, Any]):
    """Mapping response with convenient attribute access for Python callers."""

    @property
    def receipt(self) -> dict[str, Any]:
        return self["receipt"]

    @property
    def result(self) -> dict[str, Any]:
        return self["result"]

    @property
    def reused(self) -> bool:
        return bool(self.get("reused", False))

    @property
    def state_version(self) -> int:
        return int(self["receipt"]["state_version"])


class ExecutionOrchestrator:
    """Durable, single-writer execution state machine."""

    service = SERVICE
    service_version = "phase-a-v1"

    def __init__(
        self,
        repository: DurableExecutionRepository | None = None,
        gateway: ExecutionGateway | None = None,
        *,
        scope: str = "account:default",
        environment: str = "test",
        service_version: str | None = None,
        lease_seconds: float = 15.0,
        now: datetime | None = None,
        test_mode: bool | None = None,
    ) -> None:
        self.repository = repository or InMemoryExecutionRepository(scope=scope)
        if self.repository.scope != scope:
            raise ValueError("repository scope and orchestrator scope differ")
        self.gateway: ExecutionGateway = gateway or NullGateway()
        self.scope = scope
        self.environment = environment
        self.test_mode = (
            isinstance(self.repository, InMemoryExecutionRepository)
            or isinstance(self.gateway, InMemoryGateway)
            if test_mode is None
            else bool(test_mode)
        )
        if not self.test_mode and scope == "account:default":
            raise ValueError("non-test Execution requires an explicit account scope")
        if not self.test_mode and isinstance(
            self.gateway, (NullGateway, InMemoryGateway)
        ):
            raise ValueError(
                "Null/InMemory gateway is only allowed in explicit test mode"
            )
        if service_version:
            self.service_version = service_version
        self.fencer = LeaderFencer(
            self.repository, scope=scope, lease_seconds=lease_seconds
        )
        self._command_lock = RLock()
        self._mutation_lock = RLock()
        self._local_halted = False
        self._last_observed_at = now or utc_now()
        self._bootstrap_halted(now=now)

    def start(self) -> None:
        starter = getattr(self.gateway, "start", None)
        if callable(starter):
            starter()

    def stop(self) -> None:
        stopper = getattr(self.gateway, "stop", None)
        try:
            if callable(stopper):
                stopper()
        finally:
            self._local_halted = True

    close = stop
    shutdown = stop

    # ------------------------------------------------------------------
    # Lifecycle and projections
    # ------------------------------------------------------------------
    def _bootstrap_halted(self, *, now: datetime | None = None) -> None:
        """Restart always enters HALTED_RECONCILE_REQUIRED.

        A malformed or unavailable durable state is not replaced by an empty
        projection; the repository exception is propagated to the caller.
        """

        current = now or utc_now()

        def writer(candidate: dict[str, Any]) -> None:
            unknown = candidate["unknown_outcomes"]
            for intent_id, raw in candidate["send_intents"].items():
                if not isinstance(raw, dict) or str(intent_id).startswith("key:"):
                    continue
                if raw.get("state") in ACTIVE_INTENT_STATES:
                    raw["state"] = "UNKNOWN_OUTCOME"
                    raw["unknown_reason"] = (
                        "process restart requires same-intent reconciliation"
                    )
                    unknown[intent_id] = {"reason": raw["unknown_reason"]}
            if unknown:
                lifecycle = "HALTED_UNKNOWN_OUTCOME"
                reconciliation_state = "UNKNOWN"
            else:
                lifecycle = "HALTED_RECONCILE_REQUIRED"
                reconciliation_state = "REQUIRED"
            candidate["lifecycle"] = lifecycle
            candidate["reconciliation"].update(
                {"state": reconciliation_state, "unknown_outcomes": len(unknown)}
            )

        # Persist the restart fence even when the prior lifecycle was already
        # halted; a fresh process must still verify the durable high-water.
        self.repository.mutate(writer)
        self._last_observed_at = current

    @property
    def lifecycle(self) -> str:
        return str(self.repository.snapshot()["lifecycle"])

    def acquire_leader(
        self, owner_id: str, *, now: datetime | None = None
    ) -> LeaderToken:
        token = self.fencer.acquire(owner_id, now=now)
        self._last_observed_at = now or utc_now()
        return token

    def renew_leader(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> LeaderToken:
        return self.fencer.renew(token, now=now)

    def release_leader(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> None:
        self.fencer.release(token, now=now)

    def leader_acquire(
        self, owner_id: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        return self.acquire_leader(owner_id, now=now).as_dict()

    def leader_renew(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        return self.renew_leader(token, now=now).as_dict()

    def leader_status(self) -> dict[str, Any]:
        return self.fencer.current_lease()

    def get_receipt(
        self, idempotency_key: str, *, service: str = "control-api"
    ) -> dict[str, Any] | None:
        validate_idempotency_key(idempotency_key)
        return self.repository.get_receipt(service, idempotency_key)

    receipt = get_receipt

    def status(self, *, observed_at: datetime | None = None) -> dict[str, Any]:
        state = self.repository.snapshot()
        observed = observed_at or utc_now()
        self._last_observed_at = observed
        return self._projection(state, observed)

    overview = status
    status_projection = status
    get_status = status

    def fail_closed_halt(self, reason: str) -> dict[str, Any]:
        """Public internal safety brake used when a plan runner cannot continue."""

        if not isinstance(reason, str) or not reason or len(reason) > 500:
            raise MutationRejected("fail-closed halt reason is invalid")

        def writer(state: dict[str, Any]) -> None:
            state["lifecycle"] = "HALTED_RECONCILE_REQUIRED"
            state["reconciliation"]["state"] = "REQUIRED"
            state["audit"].append(
                {
                    "kind": "fail_closed_halt",
                    "reason": reason,
                    "observed_at": format_utc(utc_now()),
                }
            )

        self.repository.mutate(writer)
        return self.status()

    def _projection(
        self, state: Mapping[str, Any], observed_at: datetime
    ) -> dict[str, Any]:
        lease = dict(state["lease"])
        owner = str(lease.get("owner_id") or UNKNOWN_ID)
        try:
            expiry = parse_utc(
                lease.get("lease_expires_at", EPOCH_TIMESTAMP),
                field_name="lease_expires_at",
            )
            held = bool(lease.get("owner_id")) and _timestamp(
                expiry
            ) > observed_at.astimezone(timezone.utc)
        except (CommandValidationError, TypeError, ValueError):
            held = False
            expiry = EPOCH_TIMESTAMP
        leader = {
            "scope": str(lease.get("scope", self.scope)),
            "owner_id": owner if _is_identifier(owner) else UNKNOWN_ID,
            "held": held,
            "epoch": _nonnegative_int(lease.get("epoch", 0)),
            "fencing_token": _nonnegative_int(lease.get("fencing_token", 0)),
            "lease_expires_at": expiry,
        }
        intents = []
        for intent_id, raw in state.get("send_intents", {}).items():
            # ``intent_keys`` is a separate idempotency index; older state
            # documents may still contain a key alias, which must not appear as
            # a second durable intent in the status projection.
            if isinstance(intent_id, str) and intent_id.startswith("key:"):
                continue
            if isinstance(raw, Mapping):
                intents.append(self._intent_projection(raw))
        intents.sort(
            key=lambda item: (
                item.get("created_at", EPOCH_TIMESTAMP),
                item.get("intent_id", ""),
            )
        )
        authority = _authority_projection(state.get("authority", {}))
        plan = _plan_projection(state.get("plan", {}))
        reconciliation = _reconciliation_projection(state.get("reconciliation", {}))
        broker = _broker_projection(state.get("broker", {}))
        return {
            "schema_version": "web_bridge_execution_status_v1",
            "service": SERVICE,
            "service_version": self.service_version,
            "observed_at": format_utc(observed_at),
            "lifecycle": str(state.get("lifecycle", "HALTED_RECONCILE_REQUIRED")),
            "state_version": _nonnegative_int(state.get("state_version", 0)),
            "leader": leader,
            "authority": authority,
            "plan": plan,
            "send_intents": intents,
            "reconciliation": reconciliation,
            "safe_to_restart": self._safe_to_restart_state(state),
            "broker": broker,
        }

    @staticmethod
    def _intent_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            "intent_id": str(raw.get("intent_id", UNKNOWN_ID)),
            "idempotency_key": str(raw.get("idempotency_key", "unknown-idempotency")),
            "state": str(raw.get("state", "PERSISTED")),
            "plan_id": str(raw.get("plan_id", UNKNOWN_ID)),
            "plan_hash": str(raw.get("plan_hash", ZERO_HASH)),
            "leader_epoch": _nonnegative_int(raw.get("leader_epoch", 0)),
            "fencing_token": _nonnegative_int(raw.get("fencing_token", 0)),
            "created_at": str(raw.get("created_at", EPOCH_TIMESTAMP)),
        }
        if raw.get("broker_order_id") is not None:
            result["broker_order_id"] = str(raw["broker_order_id"])
        return result

    def _safe_to_restart_state(self, state: Mapping[str, Any]) -> bool:
        if self._local_halted:
            return False
        reconciliation = state.get("reconciliation", {})
        plan = state.get("plan", {})
        broker = state.get("broker", {})
        return bool(
            state.get("lifecycle") in {"READY", "DEGRADED", "DRAINING"}
            and reconciliation.get("state") == "RECONCILED"
            and int(reconciliation.get("unknown_outcomes", 0)) == 0
            and not state.get("unknown_outcomes")
            and plan.get("state") in {"IDLE", "TERMINAL"}
            and int(broker.get("active_order_count", 0)) == 0
        )

    # ------------------------------------------------------------------
    # Typed command endpoint
    # ------------------------------------------------------------------
    def process_command(
        self, command: CommandEnvelope | Mapping[str, Any]
    ) -> CommandResponse:
        envelope = (
            command
            if isinstance(command, CommandEnvelope)
            else CommandEnvelope.from_mapping(command)
        )
        with self._command_lock:
            return self._process_envelope(envelope)

    handle_command = process_command
    execute_command = process_command
    submit_command = process_command

    def _process_envelope(self, envelope: CommandEnvelope) -> CommandResponse:
        command_key = f"{envelope.actor.service}:{envelope.idempotency_key}"
        command_hash = envelope.command_hash()
        state = self.repository.snapshot()
        existing = state.get("receipts", {}).get(command_key)
        if existing is not None:
            if existing.get("command_hash") != command_hash:
                raise IdempotencyConflictError(
                    "idempotency key was reused with a different command"
                )
            return CommandResponse(
                receipt=deepcopy(existing),
                result=deepcopy(existing.get("result", {})),
                reused=True,
            )

        expected_version = envelope.expected.state_version
        actual_version = int(state["state_version"])
        if expected_version != actual_version:
            raise ExpectedVersionConflict(expected_version, actual_version)

        # Reconciliation performs read-only gateway queries before its durable
        # state transaction.  A failed/uncertain read leaves no command receipt
        # and therefore cannot be mistaken for a completed reconcile.
        if envelope.command == "reconcile":
            return self._reconcile_command(envelope)

        if envelope.command in {"stop", "revoke", "drain"}:
            try:
                self._prepare_control_cancellation()
            except Exception:
                if envelope.command == "revoke":
                    # Revoke remains fail-closed even if a cancellation result
                    # is unknown; never leave effective authority enabled.
                    self._force_revoke_after_cancel_failure()
                raise
            # Internal cancel intents are durable state changes made under the
            # command lock; use their post-CAS version for the state transition.
            expected_version = self.repository.state_version

        key = f"{envelope.actor.service}:{envelope.idempotency_key}"

        def writer(candidate: dict[str, Any]) -> dict[str, Any]:
            status = "COMPLETED"
            try:
                result = self._apply_command(candidate, envelope)
            except MutationRejected as exc:
                # Rejected state transitions are durable audit facts, but they
                # do not call the gateway.  Keep expected-version semantics
                # intact while recording the same command receipt transaction.
                status = "REJECTED"
                result = {
                    "accepted": False,
                    "error": type(exc).__name__,
                    "detail": str(exc),
                }
            receipt = self._receipt_for_candidate(
                candidate,
                envelope,
                command_hash,
                result,
                status=status,
            )
            candidate["receipts"][key] = receipt
            candidate["audit"].append({"kind": "command_receipt", **receipt})
            return result

        result, final_state = self.repository.mutate(
            writer, expected_version=expected_version
        )
        return CommandResponse(
            receipt=deepcopy(final_state["receipts"][key]),
            result=deepcopy(dict(result)),
            reused=False,
        )

    @staticmethod
    def _receipt_for_candidate(
        candidate: dict[str, Any],
        envelope: CommandEnvelope,
        command_hash: str,
        result: Mapping[str, Any],
        *,
        status: str,
    ) -> dict[str, Any]:
        receipt = CommandReceipt(
            service=envelope.actor.service,
            idempotency_key=envelope.idempotency_key,
            command_hash=command_hash,
            command_id=envelope.command_id,
            correlation_id=envelope.correlation_id,
            actor=envelope.actor.as_dict(),
            status=status,
            state_version=int(candidate["state_version"]) + 1,
            result=deepcopy(dict(result)),
            observed_at=format_utc(utc_now()),
        )
        return receipt.as_dict()

    def _apply_command(
        self, state: dict[str, Any], envelope: CommandEnvelope
    ) -> dict[str, Any]:
        command = envelope.command
        payload = envelope.payload
        self._check_expected_projection(state, envelope)
        if command in ("status", "overview"):
            return {"status": self._projection(state, utc_now())}
        if command == "safe_to_restart":
            safe = self._safe_to_restart_state(state)
            return {"safe_to_restart": safe, "lifecycle": state["lifecycle"]}
        if command == "preview":
            plan_id = f"preview-{payload['plan_hash'][:16]}"
            prior_version = int(state["plan"].get("version", 0))
            state["plan"] = PlanState(
                "PREVIEWED", plan_id, payload["plan_hash"], prior_version + 1
            ).as_dict()
            return {"accepted": True, "plan": deepcopy(state["plan"])}
        if command == "enable":
            expiry = _timestamp(payload["expires_at"])
            if expiry <= utc_now():
                raise AuthorityRejected("authority expiry is not in the future")
            state["authority"] = AuthorityState(
                "ENABLED",
                payload["authority_artifact_id"],
                payload["authority_hash"],
                payload["expires_at"],
            ).as_dict()
            if state["lifecycle"] == "STARTING":
                state["lifecycle"] = "HALTED_RECONCILE_REQUIRED"
            return {"accepted": True, "authority": deepcopy(state["authority"])}
        if command == "revoke":
            current = state["authority"]
            state["authority"] = AuthorityState(
                "REVOKED",
                current.get("artifact_id", UNKNOWN_ID),
                current.get("artifact_hash", ZERO_HASH),
                current.get("expires_at", EPOCH_TIMESTAMP),
            ).as_dict()
            return {"accepted": True, "authority": deepcopy(state["authority"])}
        if command == "start":
            self._require_authority(state)
            if state["lifecycle"] in {
                "HALTED_RECONCILE_REQUIRED",
                "HALTED_UNKNOWN_OUTCOME",
                "DRAINING",
                "STOPPING",
            }:
                raise RestartReconciliationRequired(
                    "fresh broker reconciliation is required before start"
                )
            if state["reconciliation"].get("state") != "RECONCILED":
                raise RestartReconciliationRequired("reconciliation is not complete")
            payload_hash = payload["plan_hash"]
            state["plan"] = PlanState(
                "ACTIVE",
                payload["plan_id"],
                payload_hash,
                int(state["plan"].get("version", 0)) + 1,
            ).as_dict()
            state["lifecycle"] = "READY"
            return {"accepted": True, "plan": deepcopy(state["plan"])}
        if command == "stop":
            plan = state["plan"]
            prior_plan_state = str(plan.get("state", "IDLE"))
            state["plan"] = PlanState(
                "TERMINAL",
                plan.get("plan_id", UNKNOWN_ID),
                plan.get("plan_hash", ZERO_HASH),
                int(plan.get("version", 0)) + 1,
            ).as_dict()
            if prior_plan_state != "TERMINAL":
                state["terminal_archive"].append(
                    {
                        "kind": "plan_terminal",
                        "plan_id": plan.get("plan_id", UNKNOWN_ID),
                        "plan_hash": plan.get("plan_hash", ZERO_HASH),
                        "plan_version": int(plan.get("version", 0)),
                        "archived_at": format_utc(utc_now()),
                    }
                )
            if state["lifecycle"] not in {
                "HALTED_UNKNOWN_OUTCOME",
                "HALTED_RECONCILE_REQUIRED",
            }:
                state["lifecycle"] = "READY"
            return {"accepted": True, "plan": deepcopy(state["plan"])}
        if command == "drain":
            state["lifecycle"] = "DRAINING"
            return {
                "accepted": True,
                "drain_id": payload["drain_id"],
                "lifecycle": "DRAINING",
            }
        raise CommandValidationError(f"unsupported command {command}")

    def _prepare_control_cancellation(self) -> None:
        state = self.repository.snapshot()
        active_ids = [
            str(intent_id)
            for intent_id, raw in state.get("send_intents", {}).items()
            if not str(intent_id).startswith("key:")
            and isinstance(raw, Mapping)
            and raw.get("action", "send") == "send"
            and raw.get("state") in ACTIVE_INTENT_STATES
        ]
        if active_ids:
            token = self.fencer.token
            if token is None:
                raise FencingError(
                    "active-order cancellation requires the current leader token"
                )
            for target_id in active_ids:
                cancel_key = f"cancel-{target_id}-{token.fencing_token}"
                result = self.cancel_order(
                    target_id,
                    idempotency_key=cancel_key,
                    leader_epoch=token.epoch,
                    fencing_token=token.fencing_token,
                    token=token,
                )
                if not self._cancel_result_is_terminal(result):
                    self._mark_cancel_failure(
                        target_id,
                        reason="gateway cancellation was not explicitly terminal/cancelled",
                    )
                    raise MutationRejected(
                        "gateway cancellation did not reach a terminal state"
                    )
        try:
            snapshot = self._coerce_snapshot(self.gateway.snapshot())
            state_after = self.repository.snapshot()
            self._validate_reconcile_snapshot(state_after, snapshot)
            if snapshot.active_order_count != 0:
                raise SnapshotRejected(
                    "broker still reports active orders after cancellation"
                )
            run_id = str(state_after["reconciliation"].get("run_id", UNKNOWN_ID))
            self.repository.mutate(
                lambda candidate: self._apply_snapshot(candidate, snapshot, run_id)
            )
        except Exception as exc:
            self._mark_cancel_failure(
                "all", reason=f"post-cancel reconciliation failed: {exc}"
            )
            raise

    @staticmethod
    def _cancel_result_is_terminal(result: Mapping[str, Any]) -> bool:
        if not isinstance(result, Mapping):
            return False
        if result.get("accepted") is False or result.get("cancelled") is False:
            return False
        return str(result.get("state", "")).upper() in {
            "CANCELLED",
            "TERMINAL",
            "RECONCILED",
        }

    def _mark_cancel_failure(self, target_id: str, *, reason: str) -> None:
        def writer(state: dict[str, Any]) -> None:
            state["lifecycle"] = "HALTED_RECONCILE_REQUIRED"
            state["reconciliation"].update(
                {
                    "state": "REQUIRED",
                    "unknown_outcomes": len(state["unknown_outcomes"]),
                }
            )
            state["audit"].append(
                {
                    "kind": "cancel_rejected",
                    "target_intent_id": target_id,
                    "reason": reason,
                    "observed_at": format_utc(utc_now()),
                }
            )

        try:
            self.repository.mutate(writer)
        except RepositoryUnavailableError:
            self._local_halted = True

    def _force_revoke_after_cancel_failure(self) -> None:
        def writer(state: dict[str, Any]) -> None:
            authority = state["authority"]
            authority["state"] = "REVOKED"
            if state.get("lifecycle") != "HALTED_RECONCILE_REQUIRED":
                state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"

        try:
            self.repository.mutate(writer)
        except RepositoryUnavailableError:
            self._local_halted = True

    def emergency_stop(self, *, reason: str = "emergency stop") -> dict[str, Any]:
        """Cancel all active intents under the current fence, then revoke."""

        try:
            self._prepare_control_cancellation()
        except Exception:
            self._force_revoke_after_cancel_failure()
            raise

        def writer(state: dict[str, Any]) -> None:
            authority = state["authority"]
            authority["state"] = "REVOKED"
            plan = state["plan"]
            if plan.get("state") != "TERMINAL":
                state["terminal_archive"].append(
                    {
                        "kind": "plan_terminal",
                        "plan_id": plan.get("plan_id", UNKNOWN_ID),
                        "plan_hash": plan.get("plan_hash", ZERO_HASH),
                        "plan_version": int(plan.get("version", 0)),
                        "archived_at": format_utc(utc_now()),
                    }
                )
                plan["state"] = "TERMINAL"
                plan["version"] = int(plan.get("version", 0)) + 1
            state["lifecycle"] = "READY"
            state["audit"].append(
                {
                    "kind": "emergency_stop",
                    "reason": reason,
                    "observed_at": format_utc(utc_now()),
                }
            )

        self.repository.mutate(writer)
        return self.status()

    def _check_expected_projection(
        self, state: Mapping[str, Any], envelope: CommandEnvelope
    ) -> None:
        expected = envelope.expected
        if (
            expected.plan_hash is not None
            and state["plan"].get("plan_hash") != expected.plan_hash
        ):
            raise ExpectedVersionConflict(
                expected.state_version, int(state["state_version"])
            )
        if (
            expected.authority_hash is not None
            and state["authority"].get("artifact_hash") != expected.authority_hash
        ):
            raise ExpectedVersionConflict(
                expected.state_version, int(state["state_version"])
            )
        lease = state["lease"]
        if (
            expected.leader_epoch is not None
            and lease.get("epoch") != expected.leader_epoch
        ):
            raise FencingError("expected leader epoch does not match durable state")
        if (
            expected.fencing_token is not None
            and lease.get("fencing_token") != expected.fencing_token
        ):
            raise FencingError("expected fencing token does not match durable state")

    def _reconcile_command(self, envelope: CommandEnvelope) -> CommandResponse:
        # Read-only snapshot/query calls are safe without a leader token.  They
        # never construct a new send/cancel intent.
        try:
            snapshot = self._coerce_snapshot(self.gateway.snapshot())
        except Exception as exc:
            if isinstance(
                exc, (GatewayUnavailable, GatewayTimeout, TimeoutError, ConnectionError)
            ):
                raise
            raise GatewayUnavailable(f"gateway snapshot failed: {exc}") from exc
        state = self.repository.snapshot()
        if snapshot.snapshot_id != envelope.payload["snapshot_id"]:
            self._mark_reconcile_halted(
                reason="snapshot id does not match reconcile command"
            )
            raise SnapshotRejected(
                "broker snapshot id does not match reconcile command"
            )
        try:
            self._validate_reconcile_snapshot(state, snapshot)
        except SnapshotRejected:
            self._mark_reconcile_halted(
                reason="snapshot failed connected/scope/freshness/closure validation"
            )
            raise
        unknown_ids = list(state.get("unknown_outcomes", {}).keys())
        outcomes: dict[str, Any] = {}
        for intent_id in unknown_ids:
            raw_intent = state.get("send_intents", {}).get(intent_id)
            if not isinstance(raw_intent, Mapping):
                continue
            intent = self._intent_from_dict(raw_intent)
            context = self._context_from_intent(intent)
            try:
                outcome = self.gateway.query_intent(intent, context)
            except Exception as exc:  # noqa: BLE001 - any gateway exception leaves outcome unknown
                outcomes[intent_id] = {"state": "UNKNOWN", "error": str(exc)}
                continue
            outcomes[intent_id] = dict(outcome)

        expected = envelope.expected.state_version

        def writer(candidate: dict[str, Any]) -> dict[str, Any]:
            if int(candidate["state_version"]) != expected:
                raise ExpectedVersionConflict(expected, int(candidate["state_version"]))
            self._apply_snapshot(
                candidate, snapshot, envelope.payload["reconciliation_run_id"]
            )
            for intent_id, outcome in outcomes.items():
                raw = candidate["send_intents"].get(intent_id)
                if not isinstance(raw, dict):
                    continue
                if _outcome_is_unknown(outcome):
                    raw["state"] = "UNKNOWN_OUTCOME"
                    candidate["unknown_outcomes"][intent_id] = {
                        "reason": outcome.get("error", "outcome remains unknown")
                    }
                else:
                    raw["state"] = "RECONCILED"
                    candidate["unknown_outcomes"].pop(intent_id, None)
            unknown_count = len(candidate["unknown_outcomes"])
            candidate["reconciliation"].update(
                {
                    "state": "RECONCILED" if unknown_count == 0 else "UNKNOWN",
                    "run_id": envelope.payload["reconciliation_run_id"],
                    "last_completed_at": format_utc(utc_now())
                    if unknown_count == 0
                    else candidate["reconciliation"].get(
                        "last_completed_at", EPOCH_TIMESTAMP
                    ),
                    "unknown_outcomes": unknown_count,
                    "fresh_snapshot_id": envelope.payload["snapshot_id"],
                }
            )
            candidate["lifecycle"] = (
                "READY" if unknown_count == 0 else "HALTED_UNKNOWN_OUTCOME"
            )
            result = {
                "accepted": unknown_count == 0,
                "snapshot_id": envelope.payload["snapshot_id"],
                "unknown_outcomes": unknown_count,
                "lifecycle": candidate["lifecycle"],
            }
            key = f"{envelope.actor.service}:{envelope.idempotency_key}"
            receipt = self._receipt_for_candidate(
                candidate,
                envelope,
                envelope.command_hash(),
                result,
                status="COMPLETED" if unknown_count == 0 else "REJECTED",
            )
            candidate["receipts"][key] = receipt
            candidate["audit"].append({"kind": "command_receipt", **receipt})
            return result

        result, state_after = self.repository.mutate(writer, expected_version=expected)
        key = f"{envelope.actor.service}:{envelope.idempotency_key}"
        return CommandResponse(
            receipt=deepcopy(state_after["receipts"][key]),
            result=deepcopy(dict(result)),
            reused=False,
        )

    def _apply_snapshot(
        self, state: dict[str, Any], snapshot: GatewaySnapshot, run_id: str
    ) -> None:
        state["broker"] = BrokerState(
            connected=snapshot.connected,
            generation=snapshot.generation,
            active_order_count=snapshot.active_order_count,
            position_snapshot_hash=snapshot.position_snapshot_hash,
            last_snapshot_at=snapshot.observed_at,
            orders=_detached_json(snapshot.orders),
            positions=_detached_json(snapshot.positions),
        ).as_dict()
        state["reconciliation"].update(
            {
                "run_id": run_id,
                "fresh_snapshot_id": snapshot.snapshot_id,
            }
        )

    # ------------------------------------------------------------------
    # Order mutations (not Control commands)
    # ------------------------------------------------------------------
    def send_order(
        self,
        request: Mapping[str, Any],
        *,
        idempotency_key: str,
        plan_id: str | None = None,
        plan_hash: str | None = None,
        leader_epoch: int | None = None,
        fencing_token: int | None = None,
        token: LeaderToken | Mapping[str, Any] | None = None,
        intent_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        return self._mutate_order(
            "send",
            request,
            idempotency_key=idempotency_key,
            plan_id=plan_id,
            plan_hash=plan_hash,
            leader_epoch=leader_epoch,
            fencing_token=fencing_token,
            token=token,
            intent_id=intent_id,
            now=now,
        )

    send = send_order

    def cancel_order(
        self,
        target_intent_id: str,
        *,
        idempotency_key: str,
        request: Mapping[str, Any] | None = None,
        plan_id: str | None = None,
        plan_hash: str | None = None,
        leader_epoch: int | None = None,
        fencing_token: int | None = None,
        token: LeaderToken | Mapping[str, Any] | None = None,
        intent_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        target_intent_id = validate_identifier(target_intent_id, "target_intent_id")
        state = self.repository.snapshot()
        target = state.get("send_intents", {}).get(target_intent_id)
        if not isinstance(target, Mapping):
            raise MutationRejected("target send intent does not exist")
        raw_request = dict(request or {})
        raw_request.setdefault("target_intent_id", target_intent_id)
        if target.get("broker_order_id") is not None:
            raw_request.setdefault("broker_order_id", target["broker_order_id"])
        return self._mutate_order(
            "cancel",
            raw_request,
            idempotency_key=idempotency_key,
            plan_id=plan_id or str(target.get("plan_id")),
            plan_hash=plan_hash or str(target.get("plan_hash")),
            leader_epoch=leader_epoch,
            fencing_token=fencing_token,
            token=token,
            intent_id=intent_id,
            target_intent_id=target_intent_id,
            now=now,
        )

    cancel = cancel_order

    def _mutate_order(
        self,
        action: str,
        request: Mapping[str, Any],
        *,
        idempotency_key: str,
        plan_id: str | None,
        plan_hash: str | None,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None,
        intent_id: str | None,
        target_intent_id: str | None = None,
        now: datetime | None,
    ) -> dict[str, Any]:
        with self._mutation_lock:
            current = now or utc_now()
            key = validate_idempotency_key(idempotency_key)
            if not isinstance(request, Mapping):
                raise MutationRejected("order request must be an object")
            detached_request = _detached_json(request)
            request_hash = sha256_json(detached_request)
            state = self.repository.snapshot()
            existing_ref = state.get("intent_keys", {}).get(key)
            existing = (
                state.get("send_intents", {}).get(existing_ref)
                if isinstance(existing_ref, str)
                else existing_ref
            )
            if existing is None:
                # Read old offline documents without writing a compatibility
                # alias back into the canonical intent collection.
                existing = state.get("send_intents", {}).get(f"key:{key}")
            if isinstance(existing, Mapping):
                if (
                    existing.get("request_hash") != request_hash
                    or existing.get("action") != action
                ):
                    raise IdempotencyConflictError(
                        "order idempotency key was reused with different payload"
                    )
                return {
                    "accepted": existing.get("state") not in {"UNKNOWN_OUTCOME"},
                    "reused": True,
                    "intent_id": existing.get("intent_id"),
                    "state": existing.get("state"),
                    "broker_order_id": existing.get("broker_order_id"),
                }
            # Every precondition is evaluated before intent persistence.  This
            # keeps stale/missing/foreign/expired/uncertain requests at zero
            # gateway calls and zero durable intent side effects.
            self._mutation_preflight(
                state,
                plan_id=plan_id,
                plan_hash=plan_hash,
                leader_epoch=leader_epoch,
                fencing_token=fencing_token,
                token=token,
                now=current,
                action=action,
                target_intent_id=target_intent_id,
            )
            expected_state_version = int(state["state_version"])
            active_plan = state["plan"]
            actual_plan_id = str(plan_id or active_plan.get("plan_id"))
            actual_plan_hash = str(plan_hash or active_plan.get("plan_hash"))
            actual_intent_id = validate_identifier(
                intent_id or f"intent-{uuid4().hex[:24]}", "intent_id"
            )
            receipt_id = validate_identifier(
                f"receipt-{actual_intent_id}", "receipt_id"
            )
            receipt_hash = sha256_json(
                {
                    "account_scope": self.scope,
                    "environment": self.environment,
                    "intent_id": actual_intent_id,
                    "idempotency_key": key,
                    "plan_id": actual_plan_id,
                    "plan_hash": actual_plan_hash,
                    "request_hash": request_hash,
                    "action": action,
                }
            )
            admission = self.fencer.admission(
                leader_epoch=leader_epoch,
                fencing_token=fencing_token,
                token=token,
                now=current,
            )
            context = MutationContext(
                account_scope=self.scope,
                leader_epoch=admission.epoch,
                fencing_token=admission.fencing_token,
                plan_id=actual_plan_id,
                plan_hash=actual_plan_hash,
                intent_id=actual_intent_id,
                idempotency_key=key,
                action=action,
                environment=self.environment,
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
                request_hash=request_hash,
            )
            intent = SendIntent(
                intent_id=actual_intent_id,
                idempotency_key=key,
                state="PERSISTED" if action == "send" else "CANCEL_REQUESTED",
                plan_id=actual_plan_id,
                plan_hash=actual_plan_hash,
                leader_epoch=admission.epoch,
                fencing_token=admission.fencing_token,
                created_at=format_utc(current),
                action=action,
                request_hash=request_hash,
                target_intent_id=target_intent_id,
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
            )

            def persist_intent(candidate: dict[str, Any]) -> None:
                candidate["send_intents"][actual_intent_id] = {
                    **intent.as_dict(),
                    "action": action,
                    "request_hash": request_hash,
                    "target_intent_id": target_intent_id,
                    "receipt_id": receipt_id,
                    "receipt_hash": receipt_hash,
                }
                candidate["intent_keys"][key] = actual_intent_id

            # No gateway call is made if the intent cannot be proven durable.
            def persist_with_cas(candidate: dict[str, Any]) -> None:
                # Repeat every safety predicate against the same candidate that
                # receives the intent write.  A lease/authority/plan change
                # between the read preflight and this CAS therefore admits no
                # gateway call.
                self._mutation_preflight(
                    candidate,
                    plan_id=plan_id,
                    plan_hash=plan_hash,
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                    now=current,
                    action=action,
                    target_intent_id=target_intent_id,
                    transaction_candidate=True,
                )
                persist_intent(candidate)

            self.repository.mutate(
                persist_with_cas, expected_version=expected_state_version
            )

            # The durable intent write is not itself a broker admission.  A
            # second process may have renewed/replaced the lease or revoked
            # authority between that write and this call, so re-read the
            # durable state and repeat every predicate immediately before the
            # only gateway mutation.
            latest_before_gateway = self.repository.snapshot()
            self._mutation_preflight(
                latest_before_gateway,
                plan_id=plan_id,
                plan_hash=plan_hash,
                leader_epoch=leader_epoch,
                fencing_token=fencing_token,
                token=token,
                now=utc_now(),
                action=action,
                target_intent_id=target_intent_id,
            )

            try:
                if action == "send":
                    result = self.gateway.send_order(detached_request, context)
                else:
                    result = self.gateway.cancel_order(detached_request, context)
                result = dict(result or {})
            except Exception as exc:
                self._mark_unknown(
                    actual_intent_id, reason=f"gateway {action} outcome unknown: {exc}"
                )
                raise GatewayTimeout(f"gateway {action} outcome unknown") from exc
            try:
                # The remote Windows admission is authoritative, but the
                # Linux lease must also still be current when its response is
                # accepted.  A response racing a lease loss is unknown, never
                # an acknowledgement under the old fence.
                self.fencer.admission(
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                    now=utc_now(),
                )
            except Exception as exc:
                self._mark_unknown(
                    actual_intent_id,
                    reason=f"local fence changed after gateway {action}: {exc}",
                )
                raise GatewayTimeout(
                    f"local fence changed after gateway {action}"
                ) from exc
            self._mark_intent_result(actual_intent_id, result)
            if (
                action == "cancel"
                and target_intent_id
                and self._cancel_result_is_terminal(result)
            ):
                self._mark_cancelled_target(target_intent_id)
            latest = self.repository.snapshot()
            latest_intent = latest["send_intents"].get(actual_intent_id, {})
            return {
                "accepted": bool(
                    result.get(
                        "accepted",
                        str(result.get("state", "")).upper()
                        not in {"REJECTED", "TERMINAL"},
                    )
                ),
                "reused": False,
                "intent_id": actual_intent_id,
                "state": latest_intent.get("state", "ACKNOWLEDGED"),
                "broker_order_id": latest_intent.get("broker_order_id"),
                "gateway": result,
            }

    def _mark_cancelled_target(self, target_intent_id: str) -> None:
        def writer(state: dict[str, Any]) -> None:
            target = state["send_intents"].get(target_intent_id)
            if isinstance(target, dict) and target.get("state") != "TERMINAL":
                state["terminal_archive"].append(
                    {
                        "kind": "intent_terminal",
                        "intent_id": target_intent_id,
                        "idempotency_key": target.get("idempotency_key"),
                        "broker_order_id": target.get("broker_order_id"),
                        "archived_at": format_utc(utc_now()),
                    }
                )
                target["state"] = "TERMINAL"

        self.repository.mutate(writer)

    def _mutation_preflight(
        self,
        state: Mapping[str, Any],
        *,
        plan_id: str | None,
        plan_hash: str | None,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None,
        now: datetime,
        action: str,
        target_intent_id: str | None,
        transaction_candidate: bool = False,
    ) -> None:
        if self._local_halted:
            raise RestartReconciliationRequired("orchestrator is halted fail closed")
        if state.get("unknown_outcomes"):
            raise UnknownOutcomeError("unknown broker outcome requires query/reconcile")
        if state.get("lifecycle") in {
            "HALTED_RECONCILE_REQUIRED",
            "HALTED_UNKNOWN_OUTCOME",
        }:
            raise RestartReconciliationRequired(
                "orchestrator lifecycle does not admit mutation"
            )
        if action != "cancel" and state.get("lifecycle") in {"DRAINING", "STOPPING"}:
            raise RestartReconciliationRequired(
                "orchestrator lifecycle does not admit mutation"
            )
        if not state.get("reconciliation", {}).get("state") == "RECONCILED":
            raise RestartReconciliationRequired("fresh broker reconciliation required")
        if action == "cancel" and target_intent_id:
            target = state.get("send_intents", {}).get(target_intent_id)
            if not isinstance(target, Mapping):
                raise MutationRejected("target send intent does not exist")
            if target.get(
                "state"
            ) == "UNKNOWN_OUTCOME" or target_intent_id in state.get(
                "unknown_outcomes", {}
            ):
                raise UnknownOutcomeError("cannot cancel an unresolved intent")
        if transaction_candidate:
            self.fencer.validate_against_state(
                state,
                leader_epoch=leader_epoch,
                fencing_token=fencing_token,
                token=token,
                now=now,
            )
        else:
            self.fencer.admission(
                leader_epoch=leader_epoch,
                fencing_token=fencing_token,
                token=token,
                now=now,
            )
        self._require_authority(state, now=now)
        active_plan = state.get("plan", {})
        if active_plan.get("state") != "ACTIVE":
            raise PlanRejected("no active plan admits broker mutation")
        if plan_id is not None and active_plan.get("plan_id") != plan_id:
            raise PlanRejected("plan id does not match active plan")
        if plan_hash is not None and active_plan.get("plan_hash") != plan_hash:
            raise PlanRejected("plan hash does not match active plan")

    def _require_authority(
        self, state: Mapping[str, Any], *, now: datetime | None = None
    ) -> None:
        authority = state.get("authority", {})
        if authority.get("state") != "ENABLED":
            raise AuthorityRejected("effective authority is not enabled")
        try:
            if _timestamp(str(authority.get("expires_at", EPOCH_TIMESTAMP))) <= (
                now or utc_now()
            ):
                raise AuthorityRejected("effective authority is expired")
        except ValueError as exc:
            raise AuthorityRejected("effective authority expiry is invalid") from exc

    def _mark_intent_result(self, intent_id: str, result: Mapping[str, Any]) -> None:
        raw_state = result.get("state")
        if not isinstance(raw_state, str) or raw_state.upper() in {
            "",
            "UNKNOWN",
            "UNKNOWN_OUTCOME",
            "PENDING",
        }:
            self._mark_unknown(
                intent_id, reason="gateway returned an unknown outcome state"
            )
            raise GatewayTimeout("gateway returned an unknown outcome state")
        state_name = raw_state.upper()
        if state_name.upper() == "REJECTED":
            state_name = "TERMINAL"
        if state_name not in {
            "SUBMITTED",
            "ACKNOWLEDGED",
            "TERMINAL",
            "RECONCILED",
            "CANCEL_REQUESTED",
            "CANCELLED",
        }:
            self._mark_unknown(
                intent_id, reason="gateway returned an unsupported execution state"
            )
            raise GatewayTimeout("gateway returned an unsupported execution state")
        broker_order_id = result.get("broker_order_id")

        def writer(state: dict[str, Any]) -> None:
            raw = state["send_intents"].get(intent_id)
            if not isinstance(raw, dict):
                raise RepositoryUnavailableError(
                    "intent disappeared after gateway call"
                )
            prior_state = raw.get("state")
            raw["state"] = state_name
            if broker_order_id is not None:
                raw["broker_order_id"] = str(broker_order_id)
            if state_name in {"TERMINAL", "CANCELLED"} and prior_state not in {
                "TERMINAL",
                "CANCELLED",
            }:
                state["terminal_archive"].append(
                    {
                        "kind": "intent_terminal",
                        "intent_id": intent_id,
                        "idempotency_key": raw.get("idempotency_key"),
                        "broker_order_id": raw.get("broker_order_id"),
                        "archived_at": format_utc(utc_now()),
                    }
                )
            if state_name == "UNKNOWN_OUTCOME":
                state["unknown_outcomes"][intent_id] = {
                    "reason": "gateway returned unknown"
                }

        try:
            self.repository.mutate(writer)
        except Exception as exc:
            self._local_halted = True
            raise RepositoryUnavailableError(
                "cannot durably record gateway result"
            ) from exc

    def _mark_unknown(self, intent_id: str, *, reason: str) -> None:
        def writer(state: dict[str, Any]) -> None:
            raw = state["send_intents"].get(intent_id)
            if not isinstance(raw, dict):
                raise RepositoryUnavailableError(
                    "intent disappeared while marking unknown"
                )
            raw["state"] = "UNKNOWN_OUTCOME"
            raw["unknown_reason"] = reason
            state["unknown_outcomes"][intent_id] = {"reason": reason}
            state["reconciliation"].update(
                {"state": "UNKNOWN", "unknown_outcomes": len(state["unknown_outcomes"])}
            )
            state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"

        try:
            self.repository.mutate(writer)
        except Exception:  # noqa: BLE001 - inability to persist unknown is itself a fail-closed halt
            self._local_halted = True

    def query_intent(self, intent_id: str) -> dict[str, Any]:
        intent_id = validate_identifier(intent_id, "intent_id")
        state = self.repository.snapshot()
        raw = state.get("send_intents", {}).get(intent_id)
        if not isinstance(raw, Mapping):
            raise MutationRejected("intent does not exist")
        intent = self._intent_from_dict(raw)
        context = self._context_from_intent(intent)
        try:
            result = dict(self.gateway.query_intent(intent, context) or {})
        except Exception as exc:  # noqa: BLE001 - query failures remain unknown and are never replayed
            return {
                "intent_id": intent_id,
                "state": "UNKNOWN_OUTCOME",
                "error": str(exc),
            }
        if not _outcome_is_unknown(result):
            self._mark_intent_result(intent_id, result)
            self._close_unknown_if_resolved(intent_id)
        return {"intent_id": intent_id, **result}

    def _close_unknown_if_resolved(self, intent_id: str) -> None:
        def writer(state: dict[str, Any]) -> None:
            state["unknown_outcomes"].pop(intent_id, None)
            raw = state["send_intents"].get(intent_id)
            if isinstance(raw, dict):
                raw["state"] = "RECONCILED"
            count = len(state["unknown_outcomes"])
            state["reconciliation"]["unknown_outcomes"] = count
            if count == 0:
                state["reconciliation"]["state"] = "RECONCILED"
                if state["lifecycle"] == "HALTED_UNKNOWN_OUTCOME":
                    state["lifecycle"] = "READY"

        self.repository.mutate(writer)

    def _coerce_snapshot(
        self, value: GatewaySnapshot | Mapping[str, Any]
    ) -> GatewaySnapshot:
        if isinstance(value, GatewaySnapshot):
            return value
        if not isinstance(value, Mapping):
            raise GatewayUnavailable("gateway returned an invalid snapshot")
        try:
            snapshot_id = validate_identifier(value["snapshot_id"], "snapshot_id")
            generation = value["generation"]
            connected = value["connected"]
            active_order_count = value.get("active_order_count", 0)
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or isinstance(active_order_count, bool)
                or not isinstance(active_order_count, int)
                or not isinstance(connected, bool)
            ):
                raise TypeError("snapshot integer/boolean field has the wrong type")
            position_snapshot_hash = validate_sha256(
                value.get("position_snapshot_hash", ZERO_HASH), "position_snapshot_hash"
            )
            observed_at = value.get("observed_at", format_utc(utc_now()))
            parse_utc(observed_at, field_name="snapshot.observed_at")
            account_scope = value.get("account_scope", "")
            environment = value.get("environment", "")
            if not isinstance(account_scope, str) or not isinstance(environment, str):
                raise TypeError("snapshot scope/environment must be strings")
            if not isinstance(value.get("orders", {}), Mapping) or not isinstance(
                value.get("positions", {}), Mapping
            ):
                raise TypeError("snapshot orders/positions must be objects")
            fresh = value.get("fresh", True)
            if not isinstance(fresh, bool):
                raise TypeError("snapshot.fresh must be boolean")
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayUnavailable("gateway returned an invalid snapshot") from exc
        return GatewaySnapshot(
            snapshot_id=snapshot_id,
            generation=generation,
            connected=connected,
            active_order_count=active_order_count,
            position_snapshot_hash=position_snapshot_hash,
            observed_at=observed_at,
            orders=value.get("orders", {}),
            positions=value.get("positions", {}),
            account_scope=account_scope,
            environment=environment,
            fresh=fresh,
        )

    def _validate_reconcile_snapshot(
        self,
        state: Mapping[str, Any],
        snapshot: GatewaySnapshot,
    ) -> None:
        if not isinstance(snapshot.snapshot_id, str) or not _is_identifier(
            snapshot.snapshot_id
        ):
            raise SnapshotRejected("broker snapshot id is invalid")
        if (
            isinstance(snapshot.generation, bool)
            or not isinstance(snapshot.generation, int)
            or snapshot.generation < 0
        ):
            raise SnapshotRejected("broker snapshot generation is invalid")
        if not isinstance(snapshot.connected, bool) or not isinstance(
            snapshot.fresh, bool
        ):
            raise SnapshotRejected(
                "broker snapshot connection/freshness flags are invalid"
            )
        try:
            validate_sha256(
                snapshot.position_snapshot_hash, "snapshot.position_snapshot_hash"
            )
            observed_at = _timestamp(snapshot.observed_at)
        except (CommandValidationError, TypeError, ValueError) as exc:
            raise SnapshotRejected("broker snapshot timestamp/hash is invalid") from exc
        if not snapshot.connected:
            raise SnapshotRejected("broker snapshot is disconnected")
        if not snapshot.fresh:
            raise SnapshotRejected("broker snapshot is not fresh")
        now = utc_now()
        if observed_at > now or (now - observed_at).total_seconds() > 60:
            raise SnapshotRejected("broker snapshot timestamp is not fresh")
        if snapshot.account_scope and snapshot.account_scope != self.scope:
            raise SnapshotRejected("broker snapshot account scope mismatch")
        if snapshot.environment and snapshot.environment != self.environment:
            raise SnapshotRejected("broker snapshot environment mismatch")
        if (
            self.scope != "account:default" and snapshot.account_scope != self.scope
        ) or (self.environment != "test" and snapshot.environment != self.environment):
            raise SnapshotRejected("broker snapshot must bind account and environment")
        if not self.test_mode and (
            snapshot.account_scope != self.scope
            or snapshot.environment != self.environment
        ):
            raise SnapshotRejected(
                "production snapshot must bind account and environment"
            )
        current_broker = state.get("broker", {})
        previous_generation = int(current_broker.get("generation", 0))
        previous_snapshot_at = str(
            current_broker.get("last_snapshot_at", EPOCH_TIMESTAMP)
        )
        initial_snapshot = previous_snapshot_at == EPOCH_TIMESTAMP and not bool(
            current_broker.get("connected")
        )
        if initial_snapshot:
            if snapshot.generation < previous_generation:
                raise SnapshotRejected("broker snapshot generation regressed")
        elif snapshot.generation <= previous_generation:
            raise SnapshotRejected("broker snapshot generation is stale")
        if _timestamp(snapshot.observed_at) < _timestamp(previous_snapshot_at):
            raise SnapshotRejected("broker snapshot timestamp rolled back")
        if not isinstance(snapshot.orders, Mapping) or not isinstance(
            snapshot.positions, Mapping
        ):
            raise SnapshotRejected("broker orders/positions facts must be objects")
        try:
            _detached_json(snapshot.orders)
            _detached_json(snapshot.positions)
        except MutationRejected as exc:
            raise SnapshotRejected(
                "broker orders/positions facts are not canonical JSON"
            ) from exc
        if (
            isinstance(snapshot.active_order_count, bool)
            or not isinstance(snapshot.active_order_count, int)
            or snapshot.active_order_count < 0
            or snapshot.active_order_count != len(snapshot.orders)
        ):
            raise SnapshotRejected(
                "active order count does not close against broker facts"
            )
        intent_values = [
            raw
            for intent_id, raw in state.get("send_intents", {}).items()
            if not str(intent_id).startswith("key:") and isinstance(raw, Mapping)
        ]
        known_values: set[str] = set()
        for raw in intent_values:
            if raw.get("action", "send") != "send" or raw.get("state") in {
                "TERMINAL",
                "RECONCILED",
                "CANCELLED",
            }:
                continue
            for field in ("intent_id", "idempotency_key", "broker_order_id"):
                value = raw.get(field)
                if value:
                    known_values.add(str(value))
        for key, raw in snapshot.orders.items():
            if not isinstance(raw, Mapping):
                raise SnapshotRejected("broker order fact is not an object")
            candidates = {str(key)} | {
                str(raw.get(field))
                for field in (
                    "intent_id",
                    "send_intent_id",
                    "idempotency_key",
                    "broker_order_id",
                )
                if raw.get(field)
            }
            if not candidates.intersection(known_values):
                raise SnapshotRejected("broker active order has no durable send intent")
        if (
            snapshot.positions
            and sha256_json(_detached_json(snapshot.positions))
            != snapshot.position_snapshot_hash
        ):
            raise SnapshotRejected(
                "broker position facts do not match their canonical hash"
            )

    def _mark_reconcile_halted(self, *, reason: str) -> None:
        def writer(state: dict[str, Any]) -> None:
            state["lifecycle"] = "HALTED_RECONCILE_REQUIRED"
            state["reconciliation"].update(
                {
                    "state": "REQUIRED",
                    "unknown_outcomes": len(state["unknown_outcomes"]),
                }
            )
            state["audit"].append(
                {
                    "kind": "reconcile_rejected",
                    "reason": reason,
                    "observed_at": format_utc(utc_now()),
                }
            )

        try:
            self.repository.mutate(writer)
        except RepositoryUnavailableError:
            self._local_halted = True

    @staticmethod
    def _intent_from_dict(raw: Mapping[str, Any]) -> SendIntent:
        return SendIntent(
            intent_id=str(raw["intent_id"]),
            idempotency_key=str(raw["idempotency_key"]),
            state=str(raw["state"]),
            plan_id=str(raw["plan_id"]),
            plan_hash=str(raw["plan_hash"]),
            leader_epoch=int(raw["leader_epoch"]),
            fencing_token=int(raw["fencing_token"]),
            created_at=str(raw["created_at"]),
            action=str(raw.get("action", "send")),
            broker_order_id=raw.get("broker_order_id"),
            request_hash=str(raw.get("request_hash", ZERO_HASH)),
            target_intent_id=raw.get("target_intent_id"),
            unknown_reason=raw.get("unknown_reason"),
            receipt_id=raw.get("receipt_id"),
            receipt_hash=raw.get("receipt_hash"),
        )

    def _context_from_intent(self, intent: SendIntent) -> MutationContext:
        return MutationContext(
            account_scope=self.scope,
            leader_epoch=intent.leader_epoch,
            fencing_token=intent.fencing_token,
            plan_id=intent.plan_id,
            plan_hash=intent.plan_hash,
            intent_id=intent.intent_id,
            idempotency_key=intent.idempotency_key,
            action=intent.action,
            environment=self.environment,
            receipt_id=str(intent.receipt_id or ""),
            receipt_hash=str(intent.receipt_hash or ""),
            request_hash=intent.request_hash,
        )


def _timestamp(value: str) -> datetime:
    parse_utc(value, field_name="timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _detached_json(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        import json

        return json.loads(canonical_json(dict(value)))
    except Exception as exc:
        raise MutationRejected("order request must be canonical JSON") from exc


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        value = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, value)


def _is_identifier(value: str) -> bool:
    try:
        validate_identifier(value)
    except (CommandValidationError, TypeError, ValueError):
        return False
    return True


def _authority_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": str(raw.get("state", "UNKNOWN")),
        "artifact_id": str(raw.get("artifact_id", UNKNOWN_ID)),
        "artifact_hash": str(raw.get("artifact_hash", ZERO_HASH)),
        "expires_at": str(raw.get("expires_at", EPOCH_TIMESTAMP)),
    }


def _plan_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": str(raw.get("state", "UNKNOWN")),
        "plan_id": str(raw.get("plan_id", UNKNOWN_ID)),
        "plan_hash": str(raw.get("plan_hash", ZERO_HASH)),
        "version": _nonnegative_int(raw.get("version", 0)),
    }


def _reconciliation_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": str(raw.get("state", "UNKNOWN")),
        "run_id": str(raw.get("run_id", UNKNOWN_ID)),
        "last_completed_at": str(raw.get("last_completed_at", EPOCH_TIMESTAMP)),
        "unknown_outcomes": _nonnegative_int(raw.get("unknown_outcomes", 0)),
        "fresh_snapshot_id": str(raw.get("fresh_snapshot_id", UNKNOWN_ID)),
    }


def _broker_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "connected": bool(raw.get("connected", False)),
        "generation": _nonnegative_int(raw.get("generation", 0)),
        "active_order_count": _nonnegative_int(raw.get("active_order_count", 0)),
        "position_snapshot_hash": str(raw.get("position_snapshot_hash", ZERO_HASH)),
        "last_snapshot_at": str(raw.get("last_snapshot_at", EPOCH_TIMESTAMP)),
    }


def _outcome_is_unknown(value: Mapping[str, Any]) -> bool:
    state = str(value.get("state", "UNKNOWN")).upper()
    return state in {
        "",
        "UNKNOWN",
        "UNKNOWN_OUTCOME",
        "PENDING",
        "NOT_FOUND",
    } and not bool(value.get("resolved", False))
