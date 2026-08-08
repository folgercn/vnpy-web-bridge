"""Final, internal-only SIMNOW execution integration.

The runtime is intentionally not an HTTP API.  Control continues to submit
only :class:`CommandEnvelope` lifecycle commands.  This adapter verifies the
custody-backed immutable target plan before delegating every state transition
and every possible broker mutation to the existing ``ExecutionOrchestrator``.
It never imports legacy ``TradeService`` or ``commodity_simnow`` code.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from shared.commodity_execution.v1 import (
    CommodityExecutionContractError,
    TargetPlan,
    VerifiedCustodyReceipt,
    canonical_json,
    sha256_json,
    utc_now,
)

from .errors import AuthorityRejected, MutationRejected, PlanRejected
from .models import CommandEnvelope, LeaderToken, validate_identifier
from .orchestrator import CommandResponse, ExecutionOrchestrator


class TargetPlanRepository(Protocol):
    """Execution-owned plan storage; only exact immutable plan bytes are kept."""

    def put(self, plan: TargetPlan) -> None: ...

    def get(self, plan_id: str) -> TargetPlan | None: ...

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None: ...


class InMemoryTargetPlanRepository:
    """Small repository for offline/unit tests with create-only semantics."""

    def __init__(self) -> None:
        self._plans: dict[str, TargetPlan] = {}
        self._lock = RLock()

    def put(self, plan: TargetPlan) -> None:
        with self._lock:
            prior = self._plans.get(plan.plan_id)
            if prior is not None and prior.plan_hash != plan.plan_hash:
                raise PlanRejected("target plan id is already bound to another hash")
            self._plans.setdefault(plan.plan_id, plan)

    def get(self, plan_id: str) -> TargetPlan | None:
        validate_identifier(plan_id, "plan_id")
        with self._lock:
            return self._plans.get(plan_id)

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None:
        validate_identifier(artifact_id, "artifact_id")
        for plan in tuple(self._plans.values()):
            if (
                plan.raw["artifact_id"] == artifact_id
                and plan.raw["artifact_sha256"] == artifact_sha256
            ):
                return plan
        return None


class DurableTargetPlanRepository:
    """Create-only plan directory that survives an Execution process restart."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        if not self.root.is_absolute():
            raise ValueError("target plan root must be absolute")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            self.root.resolve() != self.root
            or self.root.stat().st_mode & 0o777 != 0o700
        ):
            raise ValueError("target plan root must be pinned mode 0700")
        self._lock_path = self.root / ".target-plan.lock"

    def _path(self, plan_id: str) -> Path:
        validate_identifier(plan_id, "plan_id")
        return self.root / f"{plan_id}.json"

    def _locked(self):
        class _Guard:
            def __init__(self, path: Path) -> None:
                self.path = path
                self.fd = -1

            def __enter__(self):
                self.fd = os.open(
                    self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600
                )
                fcntl.flock(self.fd, fcntl.LOCK_EX)
                return self

            def __exit__(self, *_: object) -> None:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)

        return _Guard(self._lock_path)

    @staticmethod
    def _read(path: Path) -> TargetPlan | None:
        if not path.exists():
            return None
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("target plan file is unsafe")
            raw = path.read_bytes()
            plan = TargetPlan.from_mapping(json.loads(raw))
            if canonical_json(plan.as_dict()) != raw:
                raise ValueError("target plan is not canonical")
            return plan
        except (
            OSError,
            UnicodeDecodeError,
            ValueError,
            CommodityExecutionContractError,
        ) as exc:
            raise PlanRejected("durable target plan is invalid") from exc

    def put(self, plan: TargetPlan) -> None:
        path = self._path(plan.plan_id)
        raw = canonical_json(plan.as_dict())
        with self._locked():
            prior = self._read(path)
            if prior is not None:
                if prior.plan_hash != plan.plan_hash:
                    raise PlanRejected(
                        "target plan id is already bound to another hash"
                    )
                return
            fd, temporary = tempfile.mkstemp(prefix=".target-plan-", dir=self.root)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("target plan write failed")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temporary, path)
                directory_fd = os.open(
                    self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except FileExistsError:
                prior = self._read(path)
                if prior is None or prior.plan_hash != plan.plan_hash:
                    raise PlanRejected(
                        "target plan id is already bound to another hash"
                    )
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def get(self, plan_id: str) -> TargetPlan | None:
        return self._read(self._path(plan_id))

    def find_authority(
        self, artifact_id: str, artifact_sha256: str
    ) -> TargetPlan | None:
        validate_identifier(artifact_id, "artifact_id")
        for path in sorted(self.root.glob("*.json")):
            plan = self._read(path)
            if plan is not None and (
                plan.raw["artifact_id"] == artifact_id
                and plan.raw["artifact_sha256"] == artifact_sha256
            ):
                return plan
        return None


class FinalExecutionRuntime:
    """The sole adapter from verified plans to the established execution core.

    ``allow_simnow_execution`` defaults to false and must be explicitly set by
    deployment code immediately before a separately authorised test.  It is a
    local runtime gate, not an authority encoded in a receipt or plan.
    """

    def __init__(
        self,
        orchestrator: ExecutionOrchestrator,
        *,
        plans: TargetPlanRepository,
        custody_receipt: Callable[[str], Mapping[str, Any] | None],
        allowed_scope: Mapping[str, Any] | None = None,
        allow_simnow_execution: bool = False,
    ) -> None:
        if orchestrator.environment.upper() != "SIMNOW":
            raise ValueError("final execution runtime requires SIMNOW environment")
        self.orchestrator = orchestrator
        self.plans = plans
        self.custody_receipt = custody_receipt
        self.allowed_scope = dict(allowed_scope) if allowed_scope is not None else None
        self.allow_simnow_execution = bool(allow_simnow_execution)

    def _receipt_for(self, plan: TargetPlan) -> VerifiedCustodyReceipt:
        try:
            raw = self.custody_receipt(str(plan.raw["custody_receipt_id"]))
        except Exception as exc:  # custody response is unknown, never assume success
            raise AuthorityRejected(
                "custody receipt lookup outcome is unknown"
            ) from exc
        if raw is None:
            raise AuthorityRejected("custody receipt is unavailable")
        try:
            receipt = VerifiedCustodyReceipt.from_mapping(raw)
        except CommodityExecutionContractError as exc:
            raise AuthorityRejected(
                "custody receipt is not strict verified evidence"
            ) from exc
        expected = {
            "receipt_id": plan.raw["custody_receipt_id"],
            "artifact_id": plan.raw["artifact_id"],
            "artifact_sha256": plan.raw["artifact_sha256"],
            "signer_key_id": plan.raw["signer_key_id"],
            "signer_key_version": plan.raw["signer_key_version"],
            "keyring_raw_sha256": plan.raw["keyring_raw_sha256"],
            "expires_at": plan.raw["expires_at"],
        }
        if (
            receipt.receipt_sha256 != plan.raw["custody_receipt_sha256"]
            or any(receipt.raw[field] != value for field, value in expected.items())
            or receipt.scope != plan.raw["scope"]
            or (self.allowed_scope is not None and receipt.scope != self.allowed_scope)
            or receipt.expires_at() <= utc_now()
        ):
            raise AuthorityRejected(
                "custody receipt does not match immutable target plan"
            )
        return receipt

    def _plan(self, plan_id: str, *, plan_hash: str | None = None) -> TargetPlan:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise PlanRejected("target plan is not installed in Execution")
        if plan_hash is not None and plan.plan_hash != plan_hash:
            raise PlanRejected("target plan hash does not match installed plan")
        if plan.raw["account_scope"] != self.orchestrator.scope:
            raise PlanRejected("target plan account scope does not match Execution")
        if plan.raw["environment"] != "SIMNOW":
            raise PlanRejected("target plan environment is not SIMNOW")
        self._receipt_for(plan)
        return plan

    def install_target_plan(self, raw: Mapping[str, Any]) -> TargetPlan:
        """Verify and retain an immutable plan; this cannot start or send anything."""

        try:
            plan = TargetPlan.from_mapping(raw)
        except CommodityExecutionContractError as exc:
            raise PlanRejected("target plan contract is invalid") from exc
        self._plan_from_value(plan)
        self.plans.put(plan)
        return plan

    def _plan_from_value(self, plan: TargetPlan) -> None:
        if plan.raw["account_scope"] != self.orchestrator.scope:
            raise PlanRejected("target plan account scope does not match Execution")
        if plan.raw["environment"] != "SIMNOW":
            raise PlanRejected("target plan environment is not SIMNOW")
        self._receipt_for(plan)

    def process_command(
        self, command: CommandEnvelope | Mapping[str, Any]
    ) -> CommandResponse:
        """Accept lifecycle commands only, with plan/receipt gates before enable/start."""

        envelope = (
            command
            if isinstance(command, CommandEnvelope)
            else CommandEnvelope.from_mapping(command)
        )
        if envelope.command == "enable":
            plan = self.plans.find_authority(
                envelope.payload["authority_artifact_id"],
                envelope.payload["authority_hash"],
            )
            if plan is None:
                raise AuthorityRejected("no installed target plan binds this authority")
            self._plan_from_value(plan)
            if envelope.payload["expires_at"] != plan.raw["expires_at"]:
                raise AuthorityRejected("enable authority expiry is not receipt-bound")
        elif envelope.command == "start":
            self._plan(
                envelope.payload["plan_id"], plan_hash=envelope.payload["plan_hash"]
            )
        return self.orchestrator.process_command(envelope)

    def _token(
        self, token: LeaderToken | Mapping[str, Any] | None
    ) -> LeaderToken | Mapping[str, Any]:
        if token is None:
            raise MutationRejected(
                "SIMNOW plan mutation requires an explicit leader token"
            )
        return token

    def send_plan_order(
        self,
        plan_id: str,
        order_ref: str,
        *,
        token: LeaderToken | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Submit exactly one plan order through ``ExecutionOrchestrator.send_order``."""

        if not self.allow_simnow_execution:
            raise AuthorityRejected("SIMNOW execution is locally disabled")
        plan = self._plan(plan_id)
        order = plan.order(order_ref)
        intent_seed = sha256_json(
            {
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "order_ref": order.order_ref,
            }
        )
        idempotency_key = f"send-{intent_seed[:32]}"
        intent_id = f"intent-{intent_seed[:24]}"
        status = self.orchestrator.status()
        # A halted lifecycle must never admit a *new* send.  The exact same
        # deterministic intent is still handed to the core, which returns its
        # durable UNKNOWN_OUTCOME/reconciled result without replaying the RPC.
        existing = self.orchestrator.repository.snapshot()["intent_keys"].get(
            idempotency_key
        )
        if (
            status["lifecycle"] != "READY"
            or status["plan"]["state"] != "ACTIVE"
            or status["plan"]["plan_id"] != plan.plan_id
            or status["plan"]["plan_hash"] != plan.plan_hash
        ) and existing != intent_id:
            raise PlanRejected(
                "target plan is not the active reconciled execution plan"
            )
        leader = self._token(token)
        return self.orchestrator.send_order(
            order.request,
            idempotency_key=idempotency_key,
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            leader_epoch=int(
                leader.epoch if isinstance(leader, LeaderToken) else leader["epoch"]
            ),
            fencing_token=int(
                leader.fencing_token
                if isinstance(leader, LeaderToken)
                else leader["fencing_token"]
            ),
            token=leader,
            intent_id=intent_id,
        )

    def cancel_plan_intent(
        self,
        plan_id: str,
        intent_id: str,
        *,
        token: LeaderToken | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Cancel a plan-owned intent through the existing fenced core path."""

        plan = self._plan(plan_id)
        intent_id = validate_identifier(intent_id, "intent_id")
        raw = self.orchestrator.repository.snapshot()["send_intents"].get(intent_id)
        if not isinstance(raw, Mapping) or (
            raw.get("plan_id") != plan.plan_id or raw.get("plan_hash") != plan.plan_hash
        ):
            raise PlanRejected("intent is not owned by this immutable target plan")
        leader = self._token(token)
        cancel_seed = sha256_json(
            {
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "intent_id": intent_id,
            }
        )
        return self.orchestrator.cancel_order(
            intent_id,
            idempotency_key=f"cancel-{cancel_seed[:30]}",
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            leader_epoch=int(
                leader.epoch if isinstance(leader, LeaderToken) else leader["epoch"]
            ),
            fencing_token=int(
                leader.fencing_token
                if isinstance(leader, LeaderToken)
                else leader["fencing_token"]
            ),
            token=leader,
            intent_id=f"cancel-{cancel_seed[:24]}",
        )


__all__ = [
    "DurableTargetPlanRepository",
    "FinalExecutionRuntime",
    "InMemoryTargetPlanRepository",
    "TargetPlanRepository",
]
