"""Issue #291 Phase A Execution Orchestrator core.

The class in this module owns the final Linux-side execution state.  It does
not import the legacy FastAPI singleton or any strategy/worker service.  The
only gateway calls are made after durable intent persistence and a fresh
leader/fencing admission check.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re
from threading import RLock
from typing import Any
from uuid import uuid4

from shared.commodity_execution import (
    CommodityExecutionContractError,
    before_position_projection_hash,
    target_position_projection_hash,
)

from .clock import FUTURE_SKEW_SECONDS, SNAPSHOT_STALE_SECONDS
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
from .start_quote_proof import (
    require_quote_proof_order_request,
    validate_execution_start_quote_proof,
)

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
    ) -> LeaderToken:
        return self.fencer.release(token, now=now)

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
        if token is None:
            raise FencingError("explicit renew fencing token is required")
        if isinstance(token, Mapping):
            token_fields = {
                "scope",
                "owner_id",
                "epoch",
                "fencing_token",
                "lease_expires_at",
                "instance_id",
            }
            if set(token) != token_fields:
                raise FencingError("renew fencing token fields are not exact")
        return self.renew_leader(token, now=now).as_dict()

    def leader_release(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if token is None:
            raise FencingError("explicit release fencing token is required")
        if isinstance(token, Mapping):
            token_fields = {
                "scope",
                "owner_id",
                "epoch",
                "fencing_token",
                "lease_expires_at",
                "instance_id",
            }
            if set(token) != token_fields:
                raise FencingError("release fencing token fields are not exact")
        released = self.release_leader(token, now=now)
        return {
            "scope": released.scope,
            "owner_id": "",
            "held": False,
            "epoch": released.epoch,
            "fencing_token": released.fencing_token,
            "lease_expires_at": EPOCH_TIMESTAMP,
            "instance_id": "",
            "state": "RELEASED",
        }

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

    def account_facts_projection(
        self,
        snapshot: GatewaySnapshot | Mapping[str, Any],
        *,
        observed_at: datetime | None = None,
        projection_version: int = 2,
    ) -> dict[str, Any]:
        """Return one fresh, full-account, read-only broker fact projection.

        The HTTP adapter obtains ``snapshot`` through the bounded
        :class:`GatewayReadinessProbe`; this method independently closes the
        full position/order rows and binds them to one durable Execution state
        snapshot.  Final-validation ``snapshot-peek-<sha256>`` ids include
        admission metadata that may change without a portfolio change, so
        generation and both canonical fact-set hashes define equivalent facts
        while durable time may not move into the future.  It never persists
        the broker facts or calls a gateway.
        """

        current = self._coerce_snapshot(snapshot)
        observed = observed_at or utc_now()
        try:
            validate_identifier(current.snapshot_id, "snapshot_id")
            snapshot_observed = _timestamp(current.observed_at)
            positions = _detached_json(current.positions)
            active_orders = _detached_json(current.orders)
            if current.snapshot_id.startswith("snapshot-peek-"):
                validate_sha256(
                    current.snapshot_id.removeprefix("snapshot-peek-"),
                    "snapshot peek facts hash",
                )
        except (CommandValidationError, MutationRejected, TypeError, ValueError) as exc:
            raise SnapshotRejected("full-account facts are invalid") from exc
        if any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for facts in (positions, active_orders)
            for key, row in facts.items()
        ):
            raise SnapshotRejected("full-account fact rows are invalid")
        if (
            current.connected is not True
            or current.fresh is not True
            or current.account_scope != self.scope
            or current.environment != self.environment
        ):
            raise SnapshotRejected(
                "full-account facts failed connection/scope/freshness binding"
            )
        if (snapshot_observed - observed).total_seconds() > FUTURE_SKEW_SECONDS or (
            observed - snapshot_observed
        ).total_seconds() > SNAPSHOT_STALE_SECONDS:
            raise SnapshotRejected("full-account facts timestamp is stale")
        if (
            isinstance(current.generation, bool)
            or not isinstance(current.generation, int)
            or current.generation < 0
            or isinstance(current.active_order_count, bool)
            or not isinstance(current.active_order_count, int)
            or current.active_order_count < 0
            or current.active_order_count != len(active_orders)
        ):
            raise SnapshotRejected("full-account facts generation/order closure failed")
        expected_position_hash = sha256_json(positions)
        active_orders_sha256 = sha256_json(active_orders)
        if current.position_snapshot_hash != expected_position_hash:
            raise SnapshotRejected("full-account position hash does not close")

        state = self.repository.snapshot()
        try:
            durable_active_orders = _detached_json(state["broker"]["orders"])
            durable_positions = _detached_json(state["broker"]["positions"])
        except (KeyError, MutationRejected, TypeError, ValueError) as exc:
            raise SnapshotRejected(
                "durable full-account broker facts are invalid"
            ) from exc
        if any(
            not isinstance(fact_id, str) or not isinstance(row, Mapping)
            for facts in (durable_active_orders, durable_positions)
            for fact_id, row in facts.items()
        ):
            raise SnapshotRejected("durable full-account broker rows are invalid")
        durable_active_orders_sha256 = sha256_json(durable_active_orders)
        durable_positions_sha256 = sha256_json(durable_positions)
        status = self._projection(state, observed)
        status_binding = {
            "status_schema_version": status["schema_version"],
            "state_version": status["state_version"],
            "status_observed_at": status["observed_at"],
            "lifecycle": status["lifecycle"],
            "reconciliation": deepcopy(status["reconciliation"]),
            "broker": deepcopy(status["broker"]),
            "durable_active_orders_sha256": durable_active_orders_sha256,
            "durable_positions_sha256": durable_positions_sha256,
            "snapshot_identity_mode": "GENERATION_FACT_HASH_EQUIVALENT",
        }
        durable_broker = status_binding["broker"]
        reconciliation = status_binding["reconciliation"]
        try:
            durable_snapshot_observed = _timestamp(durable_broker["last_snapshot_at"])
        except (CommandValidationError, TypeError, ValueError) as exc:
            raise SnapshotRejected("durable broker snapshot time is invalid") from exc
        if (
            reconciliation["state"] != "RECONCILED"
            or reconciliation["unknown_outcomes"] != 0
            or durable_broker["connected"] is not True
            or durable_broker["generation"] != current.generation
            or durable_broker["position_snapshot_hash"] != expected_position_hash
            or durable_positions_sha256 != expected_position_hash
            or durable_broker["active_order_count"] != current.active_order_count
            or durable_broker["active_order_count"] != len(durable_active_orders)
            or durable_active_orders_sha256 != active_orders_sha256
            or durable_snapshot_observed > snapshot_observed
        ):
            raise SnapshotRejected(
                "full-account facts are not bound to the reconciled Execution status"
            )
        if projection_version not in {1, 2}:
            raise SnapshotRejected("full-account facts projection version is invalid")
        preimage = {
            "schema_version": f"web_bridge_execution_account_facts_v{projection_version}",
            "service": SERVICE,
            "service_version": self.service_version,
            "account_scope": self.scope,
            "environment": self.environment,
            "snapshot_id": current.snapshot_id,
            "generation": current.generation,
            "observed_at": current.observed_at,
            "connected": True,
            "fresh": True,
            "position_snapshot_hash": expected_position_hash,
            "positions": positions,
            "active_order_count": current.active_order_count,
            "active_orders_sha256": active_orders_sha256,
            "active_orders": active_orders,
            "status_binding": status_binding,
        }
        if projection_version == 2:
            send_intents = _detached_json(state["send_intents"])
            terminal_states = {"RECONCILED", "CANCELLED", "TERMINAL"}
            nonterminal_count = sum(
                not isinstance(raw, Mapping) or raw.get("state") not in terminal_states
                for raw in send_intents.values()
            )
            plan_state = status["plan"]["state"]
            if (
                status["lifecycle"] != "READY"
                or plan_state not in {"IDLE", "TERMINAL"}
                or current.active_order_count != 0
                or active_orders
                or nonterminal_count != 0
            ):
                raise SnapshotRejected(
                    "full-account facts are not execution-planner ready"
                )
            preimage["execution_binding"] = {
                "state_version": status["state_version"],
                "plan_state": plan_state,
                "send_intents": send_intents,
                "send_intents_sha256": sha256_json(send_intents),
                "nonterminal_send_intent_count": nonterminal_count,
            }
        return {**preimage, "account_facts_sha256": sha256_json(preimage)}

    def account_facts_projection_v1(
        self,
        snapshot: GatewaySnapshot | Mapping[str, Any],
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Retain the historical v1 projection for non-#362 consumers."""

        return self.account_facts_projection(
            snapshot,
            observed_at=observed_at,
            projection_version=1,
        )

    def reconciliation_snapshot_projection(
        self,
        snapshot: GatewaySnapshot | Mapping[str, Any],
        *,
        expected_state_version: int,
        expected_durable_broker_generation: int,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Project fresh broker facts beside one read-only durable state version.

        Unlike :meth:`account_facts_projection`, this diagnostic/recovery view
        deliberately does not require the durable reconciliation to have
        completed or the plan to be idle.  It lets a caller see the broker
        facts needed to reconcile an interrupted ACTIVE plan while preserving
        the lifecycle/reconciliation values from one immutable repository
        snapshot.  It never calls the gateway and never writes durable state.
        """

        current = self._coerce_snapshot(snapshot)
        observed = observed_at or utc_now()
        try:
            validate_identifier(current.snapshot_id, "snapshot_id")
            snapshot_observed = _timestamp(current.observed_at)
            positions = _detached_json(current.positions)
            active_orders = _detached_json(current.orders)
        except (CommandValidationError, MutationRejected, TypeError, ValueError) as exc:
            raise SnapshotRejected("reconciliation snapshot facts are invalid") from exc
        if any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for facts in (positions, active_orders)
            for key, row in facts.items()
        ):
            raise SnapshotRejected("reconciliation snapshot rows are invalid")
        if (
            current.connected is not True
            or current.fresh is not True
            or current.account_scope != self.scope
            or current.environment != self.environment
        ):
            raise SnapshotRejected(
                "reconciliation snapshot failed connection/scope/freshness binding"
            )
        if (snapshot_observed - observed).total_seconds() > FUTURE_SKEW_SECONDS or (
            observed - snapshot_observed
        ).total_seconds() > SNAPSHOT_STALE_SECONDS:
            raise SnapshotRejected("reconciliation snapshot timestamp is stale")
        if (
            isinstance(current.generation, bool)
            or not isinstance(current.generation, int)
            or current.generation < 0
            or isinstance(current.active_order_count, bool)
            or not isinstance(current.active_order_count, int)
            or current.active_order_count < 0
            or current.active_order_count != len(active_orders)
        ):
            raise SnapshotRejected(
                "reconciliation snapshot generation/order closure failed"
            )
        position_snapshot_hash = sha256_json(positions)
        active_orders_sha256 = sha256_json(active_orders)
        if current.position_snapshot_hash != position_snapshot_hash:
            raise SnapshotRejected(
                "reconciliation snapshot position hash does not close"
            )

        if (
            isinstance(expected_state_version, bool)
            or not isinstance(expected_state_version, int)
            or expected_state_version < 0
            or isinstance(expected_durable_broker_generation, bool)
            or not isinstance(expected_durable_broker_generation, int)
            or expected_durable_broker_generation < 0
        ):
            raise SnapshotRejected("reconciliation snapshot durable binding is invalid")
        state = self.repository.snapshot()
        status = self._projection(state, observed)
        durable_generation = status["broker"]["generation"]
        if (
            status["state_version"] != expected_state_version
            or durable_generation != expected_durable_broker_generation
        ):
            raise SnapshotRejected(
                "reconciliation snapshot durable state changed during read"
            )
        if current.generation < durable_generation:
            raise SnapshotRejected("reconciliation snapshot generation regressed")
        preimage = {
            "schema_version": "web_bridge_execution_reconciliation_snapshot_v1",
            "service": SERVICE,
            "service_version": self.service_version,
            "account_scope": self.scope,
            "environment": self.environment,
            "snapshot_id": current.snapshot_id,
            "generation": current.generation,
            "observed_at": current.observed_at,
            "connected": True,
            "fresh": True,
            "position_snapshot_hash": position_snapshot_hash,
            "positions": positions,
            "active_order_count": current.active_order_count,
            "active_orders_sha256": active_orders_sha256,
            "active_orders": active_orders,
            "state_binding": {
                "state_version": status["state_version"],
                "durable_broker_generation": durable_generation,
                "lifecycle": status["lifecycle"],
                "reconciliation": deepcopy(status["reconciliation"]),
            },
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "official_forward_claimed": False,
        }
        return {
            **preimage,
            "reconciliation_snapshot_sha256": sha256_json(preimage),
        }

    def stable_reconciliation_snapshot_projection(
        self,
        probe: Callable[[], GatewaySnapshot],
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Run one bounded probe only while the durable version stays stable."""

        if not callable(probe):
            raise SnapshotRejected("reconciliation snapshot probe is invalid")
        before = self.repository.snapshot()
        snapshot = probe()
        after = self.repository.snapshot()
        if before["state_version"] != after["state_version"]:
            raise SnapshotRejected(
                "reconciliation snapshot durable state changed during probe"
            )
        return self.reconciliation_snapshot_projection(
            snapshot,
            expected_state_version=int(after["state_version"]),
            expected_durable_broker_generation=int(after["broker"]["generation"]),
            observed_at=observed_at,
        )

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
        self,
        command: CommandEnvelope | Mapping[str, Any],
        *,
        preview_evidence: Mapping[str, Any] | None = None,
        start_evidence: Mapping[str, Any] | None = None,
        finalization_evidence: Mapping[str, Any] | None = None,
        rollover_evidence: Mapping[str, Any] | None = None,
    ) -> CommandResponse:
        """Apply a typed Control command.

        Evidence arguments are an internal FinalExecutionRuntime seam; they
        are deliberately not part of ``CommandEnvelope`` and therefore cannot
        be supplied through the HTTP/Control command schema.
        """

        envelope = (
            command
            if isinstance(command, CommandEnvelope)
            else CommandEnvelope.from_mapping(command)
        )
        preview = self._validated_preview_evidence(envelope, preview_evidence)
        start = self._validated_start_evidence(envelope, start_evidence)
        finalization = self._validated_finalization_evidence(
            envelope, finalization_evidence
        )
        rollover = self._validated_rollover_evidence(envelope, rollover_evidence)
        with self._command_lock:
            return self._process_envelope(
                envelope, preview, start, finalization, rollover
            )

    handle_command = process_command
    execute_command = process_command
    submit_command = process_command

    @staticmethod
    def _validated_rollover_evidence(
        envelope: CommandEnvelope, evidence: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if evidence is None:
            return None
        if envelope.command != "reconcile" or not isinstance(evidence, Mapping):
            raise MutationRejected(
                "internal trading-day rollover evidence is limited to reconcile"
            )
        raw = deepcopy(dict(evidence))
        if set(raw) != {
            "schema_version",
            "plan_id",
            "plan_hash",
            "intent_trading_day",
            "time_condition",
            "intent_ids",
        } or raw["schema_version"] != "execution_gfd_rollover_evidence_v1":
            raise MutationRejected("internal trading-day rollover evidence is invalid")
        validate_identifier(raw["plan_id"], "rollover_evidence.plan_id")
        validate_sha256(raw["plan_hash"], "rollover_evidence.plan_hash")
        if (
            raw["time_condition"] != "GFD"
            or not isinstance(raw["intent_trading_day"], str)
            or re.fullmatch(r"[0-9]{8}", raw["intent_trading_day"]) is None
            or not isinstance(raw["intent_ids"], list)
            or raw["intent_ids"] != sorted(set(raw["intent_ids"]))
        ):
            raise MutationRejected("internal trading-day rollover evidence is invalid")
        for intent_id in raw["intent_ids"]:
            validate_identifier(intent_id, "rollover_evidence.intent_id")
        return raw

    @staticmethod
    def _validated_preview_evidence(
        envelope: CommandEnvelope, evidence: Mapping[str, Any] | None
    ) -> dict[str, str] | None:
        if evidence is None:
            if (
                envelope.command == "preview"
                and envelope.payload.get("mode") == "simnow_preview"
            ):
                raise MutationRejected(
                    "SIMNOW preview requires verified internal evidence"
                )
            return None
        if (
            envelope.command != "preview"
            or envelope.payload.get("mode") != "simnow_preview"
        ):
            raise MutationRejected(
                "internal preview evidence is limited to SIMNOW preview"
            )
        if not isinstance(evidence, Mapping):
            raise MutationRejected("internal preview evidence is invalid")
        raw = deepcopy(dict(evidence))
        fields = {
            "plan_hash",
            "receipt_id",
            "receipt_sha256",
            "artifact_id",
            "artifact_sha256",
        }
        if set(raw) != fields:
            raise MutationRejected("internal preview evidence fields are not exact")
        validate_sha256(raw["plan_hash"], "preview_evidence.plan_hash")
        validate_identifier(raw["receipt_id"], "preview_evidence.receipt_id")
        validate_sha256(raw["receipt_sha256"], "preview_evidence.receipt_sha256")
        validate_identifier(raw["artifact_id"], "preview_evidence.artifact_id")
        validate_sha256(raw["artifact_sha256"], "preview_evidence.artifact_sha256")
        if (
            raw["plan_hash"] != envelope.payload["plan_hash"]
            or raw["receipt_id"] != envelope.payload["receipt_id"]
            or raw["artifact_sha256"] != envelope.payload["artifact_hash"]
        ):
            raise MutationRejected("internal preview evidence does not bind command")
        return raw

    @staticmethod
    def _validated_finalization_evidence(
        envelope: CommandEnvelope, evidence: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if evidence is None:
            return None
        if envelope.command != "reconcile":
            raise MutationRejected(
                "internal finalization evidence is limited to reconciliation"
            )
        if not isinstance(evidence, Mapping):
            raise MutationRejected("internal finalization evidence is invalid")
        raw = deepcopy(dict(evidence))
        fields = {
            "plan_id",
            "plan_hash",
            "expected_after_position_hash",
            "authority_artifact_id",
            "authority_artifact_sha256",
            "authority_receipt_id",
            "authority_receipt_sha256",
            "preview_receipt_id",
            "preview_receipt_sha256",
            "preview_artifact_id",
            "preview_artifact_sha256",
            "expected_send_intent_bindings",
        }
        v3_proof_fields = {
            "execution_run_id",
            "creation_quote_proof_sha256",
            "start_quote_proof_sha256",
        }
        raw_fields = set(raw)
        if raw_fields not in {frozenset(fields), frozenset(fields | v3_proof_fields)}:
            raise MutationRejected(
                "internal finalization evidence fields are not exact"
            )
        for field in (
            "plan_id",
            "authority_artifact_id",
            "authority_receipt_id",
            "preview_receipt_id",
            "preview_artifact_id",
        ):
            validate_identifier(raw[field], f"finalization_evidence.{field}")
        if "execution_run_id" in raw:
            validate_identifier(
                raw["execution_run_id"], "finalization_evidence.execution_run_id"
            )
        for field in raw_fields.difference(
            {
                "plan_id",
                "authority_artifact_id",
                "authority_receipt_id",
                "preview_receipt_id",
                "preview_artifact_id",
                "expected_send_intent_bindings",
                "execution_run_id",
            }
        ):
            validate_sha256(raw[field], f"finalization_evidence.{field}")
        expected_bindings = raw["expected_send_intent_bindings"]
        binding_fields = {
            "intent_id",
            "idempotency_key",
            "request_hash",
            "receipt_id",
            "receipt_hash",
            "action",
            "target_intent_id",
            "plan_id",
            "plan_hash",
        }
        if (
            not isinstance(expected_bindings, list)
            or not expected_bindings
            or any(
                not isinstance(binding, Mapping) or set(binding) != binding_fields
                for binding in expected_bindings
            )
        ):
            raise MutationRejected(
                "internal finalization expected intent bindings are invalid"
            )
        intent_ids: list[str] = []
        idempotency_keys: list[str] = []
        for binding in expected_bindings:
            for field in ("intent_id", "receipt_id"):
                validate_identifier(binding[field], f"finalization_evidence.{field}")
            validate_idempotency_key(binding["idempotency_key"])
            for field in ("request_hash", "receipt_hash", "plan_hash"):
                validate_sha256(binding[field], f"finalization_evidence.{field}")
            if (
                binding["action"] != "send"
                or binding["target_intent_id"] is not None
                or binding["plan_id"] != raw["plan_id"]
                or binding["plan_hash"] != raw["plan_hash"]
            ):
                raise MutationRejected(
                    "internal finalization expected intent binding mismatches plan"
                )
            validate_identifier(
                binding["plan_id"], "finalization_evidence.binding.plan_id"
            )
            intent_ids.append(str(binding["intent_id"]))
            idempotency_keys.append(str(binding["idempotency_key"]))
        if len(set(intent_ids)) != len(intent_ids) or len(set(idempotency_keys)) != len(
            idempotency_keys
        ):
            raise MutationRejected(
                "internal finalization expected intent bindings are not unique"
            )
        return raw

    @staticmethod
    def _validated_start_evidence(
        envelope: CommandEnvelope, evidence: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if evidence is None:
            return None
        if envelope.command != "start":
            raise MutationRejected("internal start quote evidence is limited to start")
        try:
            raw = validate_execution_start_quote_proof(evidence)
        except ValueError as exc:
            raise MutationRejected("internal start quote evidence is invalid") from exc
        if (
            raw["plan_id"] != envelope.payload["plan_id"]
            or raw["plan_hash"] != envelope.payload["plan_hash"]
        ):
            raise MutationRejected(
                "internal start quote evidence does not bind command"
            )
        return raw

    def _process_envelope(
        self,
        envelope: CommandEnvelope,
        preview_evidence: Mapping[str, str] | None,
        start_evidence: Mapping[str, Any] | None,
        finalization_evidence: Mapping[str, Any] | None,
        rollover_evidence: Mapping[str, Any] | None,
    ) -> CommandResponse:
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
            return self._reconcile_command(
                envelope, finalization_evidence, rollover_evidence
            )

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
                result = self._apply_command(
                    candidate, envelope, preview_evidence, start_evidence
                )
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
        self,
        state: dict[str, Any],
        envelope: CommandEnvelope,
        preview_evidence: Mapping[str, str] | None = None,
        start_evidence: Mapping[str, Any] | None = None,
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
            if preview_evidence is not None:
                proof = preview_evidence
            else:
                proof = {
                    "receipt_id": payload.get("receipt_id", UNKNOWN_ID),
                    "receipt_sha256": ZERO_HASH,
                    "artifact_id": UNKNOWN_ID,
                    "artifact_sha256": ZERO_HASH,
                }
            state["plan"] = PlanState(
                "PREVIEWED",
                plan_id,
                payload["plan_hash"],
                prior_version + 1,
                payload["mode"],
                proof["receipt_id"],
                proof["receipt_sha256"],
                proof["artifact_id"],
                proof["artifact_sha256"],
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
                str(state["plan"].get("preview_mode", "")),
                str(state["plan"].get("preview_receipt_id", UNKNOWN_ID)),
                str(state["plan"].get("preview_receipt_sha256", ZERO_HASH)),
                str(state["plan"].get("preview_artifact_id", UNKNOWN_ID)),
                str(state["plan"].get("preview_artifact_sha256", ZERO_HASH)),
            ).as_dict()
            state["lifecycle"] = "READY"
            result = {"accepted": True, "plan": deepcopy(state["plan"])}
            if start_evidence is not None:
                result["execution_start_quote_proof"] = deepcopy(dict(start_evidence))
            return result
        if command == "stop":
            plan = state["plan"]
            prior_plan_state = str(plan.get("state", "IDLE"))
            state["plan"] = PlanState(
                "TERMINAL",
                plan.get("plan_id", UNKNOWN_ID),
                plan.get("plan_hash", ZERO_HASH),
                int(plan.get("version", 0)) + 1,
                str(plan.get("preview_mode", "")),
                str(plan.get("preview_receipt_id", UNKNOWN_ID)),
                str(plan.get("preview_receipt_sha256", ZERO_HASH)),
                str(plan.get("preview_artifact_id", UNKNOWN_ID)),
                str(plan.get("preview_artifact_sha256", ZERO_HASH)),
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

    def _prepare_control_cancellation(
        self, *, emergency_stop_only: bool = False
    ) -> None:
        state = self.repository.snapshot()
        active_ids = [
            str(intent_id)
            for intent_id, raw in state.get("send_intents", {}).items()
            if not str(intent_id).startswith("key:")
            and isinstance(raw, Mapping)
            and raw.get("action", "send") == "send"
            and (
                raw.get("state") == "ACKNOWLEDGED"
                if emergency_stop_only
                else raw.get("state") in ACTIVE_INTENT_STATES
            )
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
                    _emergency_stop_only=emergency_stop_only,
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
            snapshot = self._coerce_snapshot(self.gateway.readiness_snapshot())
            state_after = self.repository.snapshot()
            self._validate_reconcile_snapshot(
                state_after,
                snapshot,
                require_generation_advance=(
                    self.gateway.readiness_snapshot_uses_durable_generation()
                ),
            )
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
            self._prepare_control_cancellation(emergency_stop_only=True)
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
            state["lifecycle"] = (
                "HALTED_UNKNOWN_OUTCOME" if state.get("unknown_outcomes") else "READY"
            )
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

    def _reconcile_command(
        self,
        envelope: CommandEnvelope,
        finalization_evidence: Mapping[str, Any] | None = None,
        rollover_evidence: Mapping[str, Any] | None = None,
    ) -> CommandResponse:
        # Read-only snapshot/query calls are safe without a leader token.  They
        # never construct a new send/cancel intent.  Reuse the readiness
        # snapshot source so final validation binds reconcile to its pure peek.
        try:
            snapshot = self._coerce_snapshot(self.gateway.readiness_snapshot())
        except Exception as exc:
            if isinstance(
                exc, (GatewayUnavailable, GatewayTimeout, TimeoutError, ConnectionError)
            ):
                raise
            raise GatewayUnavailable(f"gateway snapshot failed: {exc}") from exc
        state = self.repository.snapshot()
        if snapshot.snapshot_id != envelope.payload["snapshot_id"]:
            requested_id = envelope.payload["snapshot_id"]
            binding = envelope.payload.get("snapshot_fact_binding")
            try:
                current_before_position_hash = before_position_projection_hash(
                    snapshot.positions,
                    account_scope=snapshot.account_scope,
                    environment=snapshot.environment,
                )
            except CommodityExecutionContractError:
                current_before_position_hash = None
            peek_equivalent = (
                requested_id.startswith("snapshot-peek-")
                and snapshot.snapshot_id.startswith("snapshot-peek-")
                and isinstance(binding, Mapping)
                and binding["generation"] == snapshot.generation
                and binding["position_snapshot_hash"]
                == current_before_position_hash
                and binding["active_order_count"] == snapshot.active_order_count
                and binding["active_orders_sha256"] == sha256_json(snapshot.orders)
                and binding["state_version"] == envelope.expected.state_version
                and binding["state_version"] == state["state_version"]
                and binding["durable_broker_generation"]
                == state["broker"]["generation"]
            )
            if not peek_equivalent:
                self._mark_reconcile_halted(
                    reason="snapshot id does not match reconcile command"
                )
                raise SnapshotRejected(
                    "broker snapshot id does not match reconcile command"
                )
        try:
            self._validate_reconcile_snapshot(
                state,
                snapshot,
                require_generation_advance=(
                    self.gateway.readiness_snapshot_uses_durable_generation()
                ),
            )
        except SnapshotRejected:
            self._mark_reconcile_halted(
                reason="snapshot failed connected/scope/freshness/closure validation"
            )
            raise
        unknown_ids = list(state.get("unknown_outcomes", {}).keys())
        unknown_id_set = set(unknown_ids)
        submitted_ids = [
            intent_id
            for intent_id, raw_intent in state.get("send_intents", {}).items()
            if intent_id not in unknown_id_set
            and isinstance(raw_intent, Mapping)
            and raw_intent.get("state") == "SUBMITTED"
        ]
        recovery_modes = {
            **{intent_id: "unknown" for intent_id in unknown_ids},
            **{intent_id: "submitted" for intent_id in submitted_ids},
        }
        outcomes: dict[str, Any] = {}
        for intent_id in recovery_modes:
            raw_intent = state.get("send_intents", {}).get(intent_id)
            if not isinstance(raw_intent, Mapping):
                continue
            intent = self._intent_from_dict(raw_intent)
            context = self._context_from_intent(intent)
            try:
                outcome = self.gateway.query_intent(intent, context)
                if not isinstance(outcome, Mapping):
                    raise GatewayUnavailable(
                        "gateway returned an invalid intent outcome"
                    )
            except Exception as exc:  # noqa: BLE001 - any gateway exception leaves outcome unknown
                outcomes[intent_id] = {"state": "UNKNOWN", "error": str(exc)}
                continue
            outcomes[intent_id] = dict(outcome)

        rollover_ids = self._trading_day_rollover_terminal_ids(
            state, snapshot, outcomes, rollover_evidence
        )

        expected = envelope.expected.state_version

        def writer(candidate: dict[str, Any]) -> dict[str, Any]:
            if int(candidate["state_version"]) != expected:
                raise ExpectedVersionConflict(expected, int(candidate["state_version"]))
            self._apply_remote_fence_high_water_floor(candidate, snapshot)
            self._apply_snapshot(
                candidate, snapshot, envelope.payload["reconciliation_run_id"]
            )
            for intent_id, outcome in outcomes.items():
                raw = candidate["send_intents"].get(intent_id)
                if not isinstance(raw, dict):
                    continue
                if _outcome_is_unknown(outcome):
                    if intent_id in rollover_ids:
                        self._apply_intent_result_transition(
                            candidate,
                            intent_id,
                            state_name="RECONCILED",
                            broker_order_id=raw.get("broker_order_id"),
                        )
                        raw["unknown_reason"] = (
                            "RECONCILED_BY_TRADING_DAY_ROLLOVER"
                        )
                        candidate["unknown_outcomes"].pop(intent_id, None)
                        continue
                    raw["state"] = "UNKNOWN_OUTCOME"
                    candidate["unknown_outcomes"][intent_id] = {
                        "reason": outcome.get("error", "outcome remains unknown")
                    }
                    continue
                if recovery_modes[intent_id] == "unknown":
                    raw["state"] = "RECONCILED"
                    candidate["unknown_outcomes"].pop(intent_id, None)
                    continue
                state_name = str(outcome.get("state", "")).upper()
                if state_name == "REJECTED":
                    state_name = "TERMINAL"
                if state_name in {"TERMINAL", "RECONCILED", "CANCELLED"}:
                    self._apply_intent_result_transition(
                        candidate,
                        intent_id,
                        state_name=state_name,
                        broker_order_id=outcome.get("broker_order_id"),
                    )
                elif state_name not in {
                    "SUBMITTED",
                    "ACKNOWLEDGED",
                    "CANCEL_REQUESTED",
                }:
                    raw["state"] = "UNKNOWN_OUTCOME"
                    candidate["unknown_outcomes"][intent_id] = {
                        "reason": "gateway returned an unsupported execution state"
                    }
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
            if rollover_ids:
                result["trading_day_rollover_reconciled_intent_count"] = len(
                    rollover_ids
                )
            status = "COMPLETED" if unknown_count == 0 else "REJECTED"
            if unknown_count == 0 and finalization_evidence is not None:
                finalization = self._apply_finalization_evidence(
                    candidate, finalization_evidence
                )
                result["finalization"] = finalization
                result["lifecycle"] = candidate["lifecycle"]
                if finalization["state"] == "POSITION_MISMATCH":
                    result["accepted"] = False
                    status = "REJECTED"
            key = f"{envelope.actor.service}:{envelope.idempotency_key}"
            receipt = self._receipt_for_candidate(
                candidate,
                envelope,
                envelope.command_hash(),
                result,
                status=status,
            )
            candidate["receipts"][key] = receipt
            candidate["audit"].append({"kind": "command_receipt", **receipt})
            return result

        try:
            result, state_after = self.repository.mutate(
                writer, expected_version=expected
            )
        except SnapshotRejected as exc:
            self._mark_reconcile_halted(reason=str(exc))
            raise
        key = f"{envelope.actor.service}:{envelope.idempotency_key}"
        return CommandResponse(
            receipt=deepcopy(state_after["receipts"][key]),
            result=deepcopy(dict(result)),
            reused=False,
        )

    @staticmethod
    def _trading_day_rollover_terminal_ids(
        state: Mapping[str, Any],
        snapshot: GatewaySnapshot,
        outcomes: Mapping[str, Mapping[str, Any]],
        evidence: Mapping[str, Any] | None,
    ) -> set[str]:
        if evidence is None:
            return set()
        active = state.get("plan", {})
        old_day = evidence["intent_trading_day"]
        current_day = snapshot.broker_trading_day
        if (
            active.get("state") != "ACTIVE"
            or active.get("plan_id") != evidence["plan_id"]
            or active.get("plan_hash") != evidence["plan_hash"]
            or not isinstance(current_day, str)
            or re.fullmatch(r"[0-9]{8}", current_day) is None
            or current_day <= old_day
            or snapshot.broker_limit_time_condition != "GFD"
            or snapshot.active_order_count != 0
            or bool(snapshot.orders)
        ):
            return set()
        shanghai = timezone(timedelta(hours=8))
        eligible: set[str] = set()
        allowed_ids = set(evidence["intent_ids"])
        for intent_id, outcome in outcomes.items():
            raw = state.get("send_intents", {}).get(intent_id)
            if (
                intent_id not in allowed_ids
                or not isinstance(raw, Mapping)
                or raw.get("action") != "send"
                or raw.get("plan_id") != evidence["plan_id"]
                or raw.get("plan_hash") != evidence["plan_hash"]
                or not _outcome_is_unknown(outcome)
            ):
                continue
            created_at = raw.get("created_at")
            try:
                parse_utc(created_at, field_name="intent.created_at")
                local = datetime.fromisoformat(
                    created_at.removesuffix("Z") + "+00:00"
                ).astimezone(shanghai)
            except (AttributeError, TypeError, ValueError):
                continue
            minute = local.hour * 60 + local.minute
            if (
                local.strftime("%Y%m%d") == old_day
                and 8 * 60 + 30 <= minute < 15 * 60
            ):
                eligible.add(intent_id)
        return eligible

    def _apply_finalization_evidence(
        self, state: dict[str, Any], evidence: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Apply final-plan completion in the same durable reconcile write."""

        plan = state["plan"]
        authority = state["authority"]
        proof_fields = (
            "preview_receipt_id",
            "preview_receipt_sha256",
            "preview_artifact_id",
            "preview_artifact_sha256",
        )
        if (
            plan.get("state") != "ACTIVE"
            or plan.get("plan_id") != evidence["plan_id"]
            or plan.get("plan_hash") != evidence["plan_hash"]
            or plan.get("preview_mode") != "simnow_preview"
            or any(plan.get(field) != evidence[field] for field in proof_fields)
            or authority.get("state") != "ENABLED"
            or authority.get("artifact_id") != evidence["authority_artifact_id"]
            or authority.get("artifact_hash") != evidence["authority_artifact_sha256"]
        ):
            raise PlanRejected(
                "internal finalization evidence does not bind active plan"
            )
        terminal_states = {"TERMINAL", "RECONCILED", "CANCELLED"}
        plan_send_intents = {
            str(intent_id): raw
            for intent_id, raw in state["send_intents"].items()
            if isinstance(raw, Mapping)
            and raw.get("action") == "send"
            and raw.get("plan_id") == evidence["plan_id"]
            and raw.get("plan_hash") == evidence["plan_hash"]
        }
        expected_bindings = {
            str(binding["intent_id"]): binding
            for binding in evidence["expected_send_intent_bindings"]
        }
        expected_intent_ids = set(expected_bindings)
        actual_intent_ids = set(plan_send_intents)
        if not actual_intent_ids.issubset(expected_intent_ids):
            raise PlanRejected("active plan contains a non-deterministic send intent")
        if (
            actual_intent_ids != expected_intent_ids
            or any(
                any(
                    plan_send_intents[intent_id].get(field) != value
                    for field, value in expected_bindings[intent_id].items()
                )
                for intent_id in expected_intent_ids
            )
            or any(
                plan_send_intents[intent_id].get("state") not in terminal_states
                for intent_id in expected_intent_ids
            )
            or int(state["broker"].get("active_order_count", 0)) != 0
        ):
            return {"state": "PENDING"}
        final_hash = state["broker"].get("position_snapshot_hash")
        positions = state["broker"].get("positions")
        try:
            target_hash = target_position_projection_hash(
                positions, account_scope=self.scope, environment=self.environment
            )
        except CommodityExecutionContractError:
            target_hash = None
        if target_hash != evidence["expected_after_position_hash"]:
            state["lifecycle"] = "HALTED_RECONCILE_REQUIRED"
            state["reconciliation"]["state"] = "REQUIRED"
            state["audit"].append(
                {
                    "kind": "fail_closed_halt",
                    "reason": "SIMNOW final target position does not match immutable target plan",
                    "observed_at": format_utc(utc_now()),
                }
            )
            return {
                "state": "POSITION_MISMATCH",
                "final_position_hash": final_hash,
                "target_position_hash": target_hash,
            }
        completion_archive = {
            "kind": "final_plan_completed",
            "plan_id": evidence["plan_id"],
            "plan_hash": evidence["plan_hash"],
            "plan_version": int(plan.get("version", 0)),
            "receipt_id": evidence["authority_receipt_id"],
            "final_position_hash": final_hash,
            "target_position_hash": target_hash,
            "positions": deepcopy(dict(positions)),
            "archived_at": format_utc(utc_now()),
        }
        if "execution_run_id" in evidence:
            completion_archive.update(
                {
                    field: evidence[field]
                    for field in (
                        "execution_run_id",
                        "creation_quote_proof_sha256",
                        "start_quote_proof_sha256",
                    )
                }
            )
        state["terminal_archive"].append(completion_archive)
        state["plan"] = PlanState(
            "TERMINAL",
            evidence["plan_id"],
            evidence["plan_hash"],
            int(plan.get("version", 0)) + 1,
            "simnow_preview",
            evidence["preview_receipt_id"],
            evidence["preview_receipt_sha256"],
            evidence["preview_artifact_id"],
            evidence["preview_artifact_sha256"],
        ).as_dict()
        state["authority"] = AuthorityState(
            "REVOKED",
            str(authority.get("artifact_id", UNKNOWN_ID)),
            str(authority.get("artifact_hash", ZERO_HASH)),
            str(authority.get("expires_at", EPOCH_TIMESTAMP)),
        ).as_dict()
        state["lifecycle"] = "READY"
        return {
            "state": "COMPLETED",
            "final_position_hash": final_hash,
            "target_position_hash": target_hash,
            "plan": deepcopy(state["plan"]),
        }

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

    @staticmethod
    def _apply_remote_fence_high_water_floor(
        state: dict[str, Any], snapshot: GatewaySnapshot
    ) -> None:
        """Advance an idle local lease floor from verified Windows facts only.

        Final-validation's read-only peek is already bound to the same account
        and environment as reconciliation.  It may reveal a Windows durable
        fence high-water greater than a restarted Execution repository has
        retained.  Never lower local state, and never alter a live lease.
        """

        remote_epoch = snapshot.fence_high_water_epoch
        remote_token = snapshot.fence_high_water_fencing_token
        if remote_epoch is None and remote_token is None:
            return
        if (
            remote_epoch is None
            or remote_token is None
            or isinstance(remote_epoch, bool)
            or not isinstance(remote_epoch, int)
            or remote_epoch < 0
            or isinstance(remote_token, bool)
            or not isinstance(remote_token, int)
            or remote_token < 0
        ):
            raise SnapshotRejected("remote fence high-water is invalid")

        lease = state.get("lease")
        if not isinstance(lease, dict):
            raise SnapshotRejected("durable lease is invalid")
        try:
            local_epoch = int(lease.get("epoch", 0))
            local_token = int(lease.get("fencing_token", 0))
            expires_at = _timestamp(str(lease.get("lease_expires_at", EPOCH_TIMESTAMP)))
        except (TypeError, ValueError, CommandValidationError) as exc:
            raise SnapshotRejected("durable lease is invalid") from exc
        if local_epoch < 0 or local_token < 0:
            raise SnapshotRejected("durable lease is invalid")
        if remote_epoch <= local_epoch and remote_token <= local_token:
            return
        if bool(lease.get("owner_id")) and expires_at > utc_now():
            raise SnapshotRejected(
                "remote fence high-water conflicts with a live local leader"
            )
        lease["epoch"] = max(local_epoch, remote_epoch)
        lease["fencing_token"] = max(local_token, remote_token)

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

    def submit_planned_order(
        self,
        request: Mapping[str, Any],
        *,
        idempotency_key: str,
        plan_id: str,
        plan_hash: str,
        leader_epoch: int,
        fencing_token: int,
        token: LeaderToken | Mapping[str, Any],
        intent_id: str,
        execution_start_quote_proof: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Canonical adapter entry for an immutable target-plan child order.

        ``FinalExecutionRuntime`` may only use this narrow adapter.  The
        mutable core remains the sole owner of intent persistence, fencing,
        UNKNOWN outcome handling, and the gateway send itself.
        """

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
            now=None,
            allow_renewed_lease_snapshot=True,
            execution_start_quote_proof=execution_start_quote_proof,
        )

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
        _emergency_stop_only: bool = False,
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
            emergency_stop_only=_emergency_stop_only,
        )

    cancel = cancel_order

    def cancel_planned_intent(
        self,
        target_intent_id: str,
        *,
        idempotency_key: str,
        plan_id: str,
        plan_hash: str,
        leader_epoch: int,
        fencing_token: int,
        token: LeaderToken | Mapping[str, Any],
        intent_id: str,
    ) -> dict[str, Any]:
        """Canonical adapter entry for cancelling an immutable-plan intent."""

        return self.cancel_order(
            target_intent_id,
            idempotency_key=idempotency_key,
            plan_id=plan_id,
            plan_hash=plan_hash,
            leader_epoch=leader_epoch,
            fencing_token=fencing_token,
            token=token,
            intent_id=intent_id,
        )

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
        emergency_stop_only: bool = False,
        allow_renewed_lease_snapshot: bool = False,
        execution_start_quote_proof: Mapping[str, Any] | None = None,
        _version_conflict_retries: int = 0,
    ) -> dict[str, Any]:
        with self._mutation_lock:
            current = now or utc_now()
            key = validate_idempotency_key(idempotency_key)
            if not isinstance(request, Mapping):
                raise MutationRejected("order request must be an object")
            detached_request = _detached_json(request)
            request_hash = sha256_json(detached_request)
            quote_proof = (
                validate_execution_start_quote_proof(execution_start_quote_proof)
                if execution_start_quote_proof is not None
                else None
            )
            if quote_proof is not None and (
                action != "send"
                or quote_proof["plan_id"] != plan_id
                or quote_proof["plan_hash"] != plan_hash
            ):
                raise MutationRejected(
                    "execution start quote proof does not bind planned order"
                )
            if quote_proof is not None:
                try:
                    require_quote_proof_order_request(quote_proof, detached_request)
                except ValueError as exc:
                    raise MutationRejected(
                        "execution start quote proof does not bind order request"
                    ) from exc
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
                    or (
                        quote_proof is not None
                        and existing.get("execution_start_quote_proof") != quote_proof
                    )
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
                emergency_stop_only=emergency_stop_only,
                allow_renewed_lease_snapshot=allow_renewed_lease_snapshot,
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
            if allow_renewed_lease_snapshot:
                admission = self.fencer.planned_dispatch_admission(
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                )
            else:
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
                if quote_proof is not None:
                    candidate["send_intents"][actual_intent_id][
                        "execution_start_quote_proof"
                    ] = deepcopy(quote_proof)
                    candidate["send_intents"][actual_intent_id][
                        "execution_start_quote_proof_sha256"
                    ] = quote_proof["proof_sha256"]
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
                    emergency_stop_only=emergency_stop_only,
                    allow_renewed_lease_snapshot=allow_renewed_lease_snapshot,
                )
                persist_intent(candidate)

            try:
                self.repository.mutate(
                    persist_with_cas, expected_version=expected_state_version
                )
            except ExpectedVersionConflict:
                # A background renewal is an independent durable versioned
                # write.  If it lands after the read preflight but before this
                # intent CAS, restart the no-side-effect preflight against the
                # new state.  The planned-dispatch fence then admits only the
                # same active identity with a forward expiry; plan, authority,
                # reconciliation, and idempotency are all checked again.
                if not allow_renewed_lease_snapshot or _version_conflict_retries >= 2:
                    raise
                return self._mutate_order(
                    action,
                    request,
                    idempotency_key=idempotency_key,
                    plan_id=plan_id,
                    plan_hash=plan_hash,
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                    intent_id=intent_id,
                    target_intent_id=target_intent_id,
                    now=now,
                    emergency_stop_only=emergency_stop_only,
                    allow_renewed_lease_snapshot=True,
                    execution_start_quote_proof=quote_proof,
                    _version_conflict_retries=_version_conflict_retries + 1,
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
                emergency_stop_only=emergency_stop_only,
                allow_renewed_lease_snapshot=allow_renewed_lease_snapshot,
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
                if allow_renewed_lease_snapshot:
                    self.fencer.planned_dispatch_admission(
                        leader_epoch=leader_epoch,
                        fencing_token=fencing_token,
                        token=token,
                    )
                else:
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
        emergency_stop_only: bool = False,
        allow_renewed_lease_snapshot: bool = False,
    ) -> None:
        if self._local_halted:
            raise RestartReconciliationRequired("orchestrator is halted fail closed")
        emergency_cancel = action == "cancel" and emergency_stop_only
        if state.get("unknown_outcomes") and not emergency_cancel:
            raise UnknownOutcomeError("unknown broker outcome requires query/reconcile")
        if (
            state.get("lifecycle")
            in {
                "HALTED_RECONCILE_REQUIRED",
                "HALTED_UNKNOWN_OUTCOME",
            }
            and not emergency_cancel
        ):
            raise RestartReconciliationRequired(
                "orchestrator lifecycle does not admit mutation"
            )
        if action != "cancel" and state.get("lifecycle") in {"DRAINING", "STOPPING"}:
            raise RestartReconciliationRequired(
                "orchestrator lifecycle does not admit mutation"
            )
        if (
            state.get("reconciliation", {}).get("state") != "RECONCILED"
            and not emergency_cancel
        ):
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
            if emergency_cancel and target.get("state") != "ACKNOWLEDGED":
                raise MutationRejected(
                    "emergency cancellation is limited to acknowledged intents"
                )
        if transaction_candidate:
            if allow_renewed_lease_snapshot:
                self.fencer.validate_planned_dispatch_against_state(
                    state,
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                )
            else:
                self.fencer.validate_against_state(
                    state,
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
                    now=now,
                )
        else:
            if allow_renewed_lease_snapshot:
                self.fencer.planned_dispatch_admission(
                    leader_epoch=leader_epoch,
                    fencing_token=fencing_token,
                    token=token,
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
            self._apply_intent_result_transition(
                state,
                intent_id,
                state_name=state_name,
                broker_order_id=broker_order_id,
            )

        try:
            self.repository.mutate(writer)
        except Exception as exc:
            self._local_halted = True
            raise RepositoryUnavailableError(
                "cannot durably record gateway result"
            ) from exc

    @staticmethod
    def _apply_intent_result_transition(
        state: dict[str, Any],
        intent_id: str,
        *,
        state_name: str,
        broker_order_id: Any,
    ) -> None:
        """Apply the durable result transition inside an existing state write."""

        raw = state["send_intents"].get(intent_id)
        if not isinstance(raw, dict):
            raise RepositoryUnavailableError("intent disappeared after gateway call")
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
        # A cancel result can become UNKNOWN after Windows accepted its target
        # order id but before it returned a cancel receipt.  Query only needs
        # that durable target id as a hint; the mutation context deliberately
        # remains the cancel intent, and this path never sends or cancels.
        if (
            intent.action == "cancel"
            and intent.broker_order_id is None
            and intent.target_intent_id is not None
        ):
            target_raw = state.get("send_intents", {}).get(intent.target_intent_id)
            if isinstance(target_raw, Mapping):
                target_broker_order_id = target_raw.get("broker_order_id")
                if isinstance(target_broker_order_id, str) and target_broker_order_id:
                    intent = replace(intent, broker_order_id=target_broker_order_id)
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
            remote_epoch = value.get("fence_high_water_epoch")
            remote_token = value.get("fence_high_water_fencing_token")
            if remote_epoch is not None and (
                isinstance(remote_epoch, bool)
                or not isinstance(remote_epoch, int)
                or remote_epoch < 0
            ):
                raise TypeError("snapshot fence high-water epoch is invalid")
            if remote_token is not None and (
                isinstance(remote_token, bool)
                or not isinstance(remote_token, int)
                or remote_token < 0
            ):
                raise TypeError("snapshot fence high-water token is invalid")
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
            fence_high_water_epoch=remote_epoch,
            fence_high_water_fencing_token=remote_token,
        )

    def _validate_reconcile_snapshot(
        self,
        state: Mapping[str, Any],
        snapshot: GatewaySnapshot,
        *,
        require_generation_advance: bool = True,
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
        if (observed_at - now).total_seconds() > FUTURE_SKEW_SECONDS or (
            now - observed_at
        ).total_seconds() > SNAPSHOT_STALE_SECONDS:
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
        elif snapshot.generation < previous_generation:
            raise SnapshotRejected("broker snapshot generation regressed")
        elif require_generation_advance and snapshot.generation == previous_generation:
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
            sha256_json(_detached_json(snapshot.positions))
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
