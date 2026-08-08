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
from shared.trust_contracts.v1 import canonical_json_line, sha256_bytes

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

    def probe(self) -> None: ...


class CustodyReadClient(Protocol):
    """Read-only custody protocol; it has no publish, sign, or revoke method."""

    def receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...

    def artifact(self, artifact_id: str) -> Mapping[str, Any] | None: ...

    def probe(self) -> None: ...


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
                plan.raw["authority_artifact_id"] == artifact_id
                and plan.raw["authority_artifact_sha256"] == artifact_sha256
            ):
                return plan
        return None

    def probe(self) -> None:
        with self._lock:
            for plan in self._plans.values():
                TargetPlan.from_mapping(plan.as_dict())


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
                plan.raw["authority_artifact_id"] == artifact_id
                and plan.raw["authority_artifact_sha256"] == artifact_sha256
            ):
                return plan
        return None

    def probe(self) -> None:
        with self._locked():
            for path in self.root.glob("*.json"):
                if self._read(path) is None:
                    raise PlanRejected("durable target plan disappeared during probe")


class _CallableCustodyClient:
    """Compatibility seam for offline tests; it cannot supply an artifact."""

    def __init__(self, receipt: Callable[[str], Mapping[str, Any] | None]) -> None:
        self._receipt = receipt

    def receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        return self._receipt(receipt_id)

    def artifact(self, artifact_id: str) -> Mapping[str, Any] | None:
        return None

    def probe(self) -> None:
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
        custody: CustodyReadClient | None = None,
        custody_receipt: Callable[[str], Mapping[str, Any] | None] | None = None,
        allowed_scope: Mapping[str, Any] | None = None,
        allow_simnow_execution: bool = False,
        max_order_volume: int = 1,
    ) -> None:
        if orchestrator.environment.upper() != "SIMNOW":
            raise ValueError("final execution runtime requires SIMNOW environment")
        self.orchestrator = orchestrator
        self.plans = plans
        if custody is not None and custody_receipt is not None:
            raise ValueError(
                "provide either custody client or custody_receipt callback"
            )
        if custody is None:
            if custody_receipt is None:
                raise ValueError("final execution runtime requires a custody reader")
            custody = _CallableCustodyClient(custody_receipt)
        self.custody = custody
        self.allowed_scope = dict(allowed_scope) if allowed_scope is not None else None
        self.allow_simnow_execution = bool(allow_simnow_execution)
        if (
            not isinstance(max_order_volume, int)
            or isinstance(max_order_volume, bool)
            or max_order_volume < 1
        ):
            raise ValueError("final execution max order volume must be positive")
        self.max_order_volume = max_order_volume

    def _receipt_for(self, plan: TargetPlan) -> VerifiedCustodyReceipt:
        try:
            raw = self.custody.receipt(str(plan.raw["custody_receipt_id"]))
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
            "artifact_id": plan.raw["authority_artifact_id"],
            "artifact_sha256": plan.raw["authority_artifact_sha256"],
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

    def _preview_from_custody(
        self, receipt_id: str
    ) -> tuple[TargetPlan, VerifiedCustodyReceipt]:
        """Fetch, cross-check and install a plan before a SIMNOW preview exists.

        The Control command supplies only a receipt id.  Order requests never
        traverse Control: they are read from the exact custody artifact here.
        """

        try:
            raw_receipt = self.custody.receipt(receipt_id)
        except Exception as exc:
            raise AuthorityRejected(
                "custody receipt lookup outcome is unknown"
            ) from exc
        if raw_receipt is None:
            raise AuthorityRejected("custody receipt is unavailable")
        try:
            receipt = VerifiedCustodyReceipt.from_mapping(raw_receipt)
        except CommodityExecutionContractError as exc:
            raise AuthorityRejected(
                "custody receipt is not strict verified evidence"
            ) from exc
        if receipt.raw["artifact_type"] != "simnow-target-plan":
            raise PlanRejected("SIMNOW preview receipt does not identify a target plan")
        try:
            response = self.custody.artifact(receipt.artifact_id)
        except Exception as exc:
            raise AuthorityRejected(
                "custody artifact lookup outcome is unknown"
            ) from exc
        if response is None:
            raise AuthorityRejected("custody target plan artifact is unavailable")
        if not isinstance(response, Mapping) or set(response) != {
            "artifact_id",
            "artifact_raw_sha256",
            "artifact",
        }:
            raise PlanRejected("custody target plan artifact response is not exact")
        artifact = response["artifact"]
        if not isinstance(artifact, Mapping):
            raise PlanRejected("custody target plan artifact is not an object")
        try:
            artifact_hash = sha256_bytes(canonical_json_line(dict(artifact)))
            payload = artifact.get("payload")
            plan = TargetPlan.from_mapping(
                payload, max_order_volume=self.max_order_volume
            )
        except CommodityExecutionContractError as exc:
            raise PlanRejected("custody target plan artifact is invalid") from exc
        if (
            response["artifact_id"] != receipt.artifact_id
            or response["artifact_raw_sha256"] != artifact_hash
            or receipt.artifact_sha256 != artifact_hash
        ):
            raise PlanRejected("custody target plan artifact/receipt binding mismatch")
        self._plan_from_value(plan)
        self.plans.put(plan)
        return plan, receipt

    def preview_from_custody(self, receipt_id: str) -> TargetPlan:
        """Public internal helper retained for runners/tests; installs no authority."""

        return self._preview_from_custody(receipt_id)[0]

    def readiness(self) -> None:
        """Required-mode readiness proves local state and custody are readable."""

        self.plans.probe()
        try:
            self.custody.probe()
        except Exception as exc:
            raise AuthorityRejected("custody read-only readiness failed") from exc

    def _plan(self, plan_id: str, *, plan_hash: str | None = None) -> TargetPlan:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise PlanRejected("target plan is not installed in Execution")
        if plan_hash is not None and plan.plan_hash != plan_hash:
            raise PlanRejected("target plan hash does not match installed plan")
        try:
            plan = TargetPlan.from_mapping(
                plan.as_dict(), max_order_volume=self.max_order_volume
            )
        except CommodityExecutionContractError as exc:
            raise PlanRejected(
                "installed target plan exceeds local order bound"
            ) from exc
        if plan.raw["account_scope"] != self.orchestrator.scope:
            raise PlanRejected("target plan account scope does not match Execution")
        if plan.raw["environment"] != "SIMNOW":
            raise PlanRejected("target plan environment is not SIMNOW")
        self._receipt_for(plan)
        return plan

    def install_target_plan(self, raw: Mapping[str, Any]) -> TargetPlan:
        """Verify and retain an immutable plan; this cannot start or send anything."""

        try:
            plan = TargetPlan.from_mapping(raw, max_order_volume=self.max_order_volume)
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
        if (
            envelope.command == "preview"
            and envelope.payload["mode"] == "simnow_preview"
        ):
            plan, receipt = self._preview_from_custody(envelope.payload["receipt_id"])
            if (
                envelope.payload["plan_hash"] != plan.plan_hash
                or envelope.payload["artifact_hash"] != receipt.artifact_sha256
            ):
                raise PlanRejected("SIMNOW preview plan/artifact hash mismatch")
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
            if not self.allow_simnow_execution:
                raise AuthorityRejected("SIMNOW execution is locally disabled")
            plan = self._plan(
                envelope.payload["plan_id"], plan_hash=envelope.payload["plan_hash"]
            )
            prior = self.orchestrator.repository.snapshot()
            expected_preview_id = f"preview-{plan.plan_hash[:16]}"
            if (
                prior["plan"].get("state") != "PREVIEWED"
                or prior["plan"].get("plan_id") != expected_preview_id
                or prior["plan"].get("plan_hash") != plan.plan_hash
                or prior["reconciliation"].get("state") != "RECONCILED"
                or prior["broker"].get("position_snapshot_hash")
                != plan.raw["expected_before_position_hash"]
            ):
                raise PlanRejected(
                    "SIMNOW start lacks matching preview/reconciliation/position proof"
                )
            if (
                envelope.expected.leader_epoch is None
                or envelope.expected.fencing_token is None
            ):
                raise MutationRejected("SIMNOW start requires an explicit leader fence")
            self.orchestrator.fencer.admission(
                leader_epoch=envelope.expected.leader_epoch,
                fencing_token=envelope.expected.fencing_token,
                token=self.orchestrator.fencer.token,
            )
            response = self.orchestrator.process_command(envelope)
            if response.result.get("accepted") is True:
                token = self.orchestrator.fencer.token
                if (
                    token is None
                ):  # admission above prevents this; preserve fail-closed behaviour
                    raise MutationRejected("SIMNOW runner lost its leader token")
                for order in plan.orders:
                    try:
                        result = self.send_plan_order(
                            plan.plan_id, order.reference, token=token
                        )
                    except Exception as exc:
                        self.orchestrator.fail_closed_halt(
                            f"SIMNOW runner order {order.reference} failed: {exc}"
                        )
                        raise
                    if result.get("accepted") is not True or str(
                        result.get("state", "")
                    ).upper() not in {"SUBMITTED", "ACKNOWLEDGED"}:
                        self.orchestrator.fail_closed_halt(
                            f"SIMNOW runner order {order.reference} was not accepted"
                        )
                        raise MutationRejected(
                            "SIMNOW runner order was rejected or has unknown outcome"
                        )
            return response
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
                "order_ref": order.reference,
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
            order.as_dict(),
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
    "CustodyReadClient",
    "DurableTargetPlanRepository",
    "FinalExecutionRuntime",
    "InMemoryTargetPlanRepository",
    "TargetPlanRepository",
]
