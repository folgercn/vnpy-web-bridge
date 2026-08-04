from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock, local
from typing import Any

from app.schemas.deployment_drain import (
    DeploymentDrainAcquireDTO,
    DeploymentSafetySnapshotDTO,
    SafeRestartConsumeMarkerDTO,
    SafeRestartReceiptDTO,
    SafeRestartRecheckDTO,
    deployment_snapshot_blockers,
)

STATE_VERSION = "web_bridge_deployment_drain_state_v1"
STATES = {
    "RUNNING",
    "DRAINING",
    "DRAIN_BLOCKED",
    "SAFE_TO_RESTART",
    "RESTARTED_FROZEN",
}
_SERVICE_REGISTRY_LOCK = RLock()
_SERVICE_REGISTRY: dict[Path, DeploymentDrainService] = {}


class DeploymentDrainError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class DeploymentDrainService:
    """Durable, fail-closed primitive for one bound restart attempt.

    This class deliberately has no API, RPC or trading-service dependency.
    Phase 1-pre-A connects the mutation guard to Trade/Risk/CTA admission.
    Commodity admission, live snapshot acquisition and receipt consumption
    remain deliberately inactive until Phase 1-pre-B; deployment stays frozen.
    """

    def __init__(
        self,
        root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        runtime_instance_id: str | None = None,
        allow_initial_bootstrap: bool = False,
        initial_bootstrap_state: str = "RUNNING",
        require_fresh_bootstrap: bool = False,
    ) -> None:
        self.root = Path(root)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.runtime_instance_id = runtime_instance_id or (
            f"runtime-{uuid.uuid4().hex}"
        )
        self.allow_initial_bootstrap = allow_initial_bootstrap
        if initial_bootstrap_state not in {"RUNNING", "RESTARTED_FROZEN"}:
            raise ValueError("initial bootstrap state is invalid")
        self.initial_bootstrap_state = initial_bootstrap_state
        self.require_fresh_bootstrap = require_fresh_bootstrap
        self._process_lock = RLock()
        self._lock_context = local()
        self.receipt_dir = self.root / "receipts"
        self.consume_dir = self.root / "consumes"
        self.lock_path = self.root / ".deployment-drain.lock"
        self.state_path = self.root / "state.json"
        self.epoch_anchor_path = self.root / "epoch-anchor.json"
        self._initialized = False
        self.execution_epoch = 0

    def _ensure_initialized(self) -> None:
        """Activate custody lazily so importing service modules cannot fence runtime."""

        with self._process_lock:
            if self._initialized:
                return
            self._prepare_directory(self.root)
            self._prepare_directory(self.receipt_dir)
            self._prepare_directory(self.consume_dir)
            self._prepare_lock_file()
            with self._exclusive_initialized():
                state = self._load_or_initial_state()
                previous_state = state["state"]
                state["execution_epoch"] += 1
                state["runtime_instance_id"] = self.runtime_instance_id
                state["updated_at"] = self._now().isoformat()
                if previous_state in {
                    "DRAINING",
                    "DRAIN_BLOCKED",
                    "SAFE_TO_RESTART",
                    "RESTARTED_FROZEN",
                }:
                    state["state"] = "RESTARTED_FROZEN"
                    if state["active_receipt_id"] is not None:
                        state["last_invalidated_receipt_id"] = state[
                            "active_receipt_id"
                        ]
                    state["active_receipt_id"] = None
                    state["active_receipt_raw_sha256"] = None
                    state["receipt_consumed"] = False
                    if state.get("freeze_reason") != (
                        "initial_bootstrap_requires_reconciliation"
                    ):
                        state["freeze_reason"] = (
                            "process_restarted_old_receipt_invalidated"
                        )
                self._write_state(state)
                self.execution_epoch = state["execution_epoch"]
            self._initialized = True

    def status(self) -> dict[str, Any]:
        with self._exclusive():
            state = self._load_state()
            if (
                state["runtime_instance_id"] == self.runtime_instance_id
                and state["execution_epoch"] == self.execution_epoch
            ):
                state = self._expire_if_needed(state)
            return self._public_state(state)

    def is_frozen(self) -> bool:
        status = self.status()
        return status["state"] != "RUNNING" or not status["runtime_current"]

    @contextmanager
    def mutation_guard(self) -> Iterator[dict[str, Any]]:
        """Linearize one execution mutation against drain acquisition.

        Lock order is mandatory: deployment gate first, then RPC call lock.
        The caller must keep the final start/enable/send operation inside this
        context; acquiring an RPC lock before this gate is unsupported.
        """

        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            state = self._expire_if_needed(state)
            if state["state"] != "RUNNING":
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_ACTIVE",
                    f"execution mutation rejected while {state['state']}",
                )
            yield self._public_state(state)

    def assert_mutation_allowed(self) -> None:
        status = self.status()
        if status["state"] != "RUNNING" or not status["runtime_current"]:
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_ACTIVE",
                f"execution mutation rejected while {status['state']}",
            )

    def acquire_with_snapshot(
        self,
        request: DeploymentDrainAcquireDTO,
        snapshot_provider: Callable[[], DeploymentSafetySnapshotDTO],
    ) -> dict[str, Any]:
        request_sha = _sha256(_canonical_bytes(request.model_dump(mode="json")))
        if request.issuer_runtime_instance_id != self.runtime_instance_id:
            raise DeploymentDrainError(
                "ISSUER_RUNTIME_INSTANCE_MISMATCH",
                "acquire request does not name the running issuer instance",
            )
        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            state = self._expire_if_needed(state)
            if state["state"] != "RUNNING":
                if (
                    state["active_request_id"] != request.request_id
                    or state["active_request_sha256"] != request_sha
                ):
                    raise DeploymentDrainError(
                        "DEPLOYMENT_DRAIN_CONFLICT",
                        "another drain or frozen restart owns the gate",
                    )
                if state["state"] == "SAFE_TO_RESTART":
                    receipt = self._read_receipt(state["active_receipt_id"])
                    return {
                        "state": self._public_state(state),
                        "receipt": receipt.model_dump(mode="json"),
                        "blockers": [],
                    }
                if state["state"] == "DRAIN_BLOCKED":
                    return {
                        "state": self._public_state(state),
                        "receipt": None,
                        "blockers": list(state["blockers"]),
                    }
                if state["state"] == "RESTARTED_FROZEN":
                    raise DeploymentDrainError(
                        "POST_RESTART_RECONCILIATION_REQUIRED",
                        "restart reconciliation must complete before acquire",
                    )
            else:
                state["drain_epoch"] += 1
                state.update(
                    state="DRAINING",
                    active_request_id=request.request_id,
                    active_request_sha256=request_sha,
                    active_receipt_id=None,
                    active_receipt_raw_sha256=None,
                    receipt_consumed=False,
                    blockers=[],
                    expires_at=None,
                    freeze_reason=None,
                    updated_at=self._now().isoformat(),
                )
                self._write_state(state)

            snapshot = snapshot_provider()
            if not isinstance(snapshot, DeploymentSafetySnapshotDTO):
                raise DeploymentDrainError(
                    "DEPLOYMENT_SNAPSHOT_INVALID",
                    "snapshot provider must return DeploymentSafetySnapshotDTO",
                )
            blockers = list(deployment_snapshot_blockers(snapshot))
            if blockers:
                state.update(
                    state="DRAIN_BLOCKED",
                    blockers=blockers,
                    updated_at=self._now().isoformat(),
                )
                self._write_state(state)
                return {
                    "state": self._public_state(state),
                    "receipt": None,
                    "blockers": blockers,
                }

            issued_at = self._now()
            receipt_core = self._receipt_core(
                request,
                snapshot,
                issued_at=issued_at,
                drain_epoch=state["drain_epoch"],
                execution_epoch=state["execution_epoch"],
            )
            core_sha = _sha256(_canonical_bytes(receipt_core))
            receipt_payload = {
                **receipt_core,
                "receipt_id": f"safe-restart-{core_sha}",
                "receipt_core_sha256": core_sha,
            }
            receipt = SafeRestartReceiptDTO.model_validate(receipt_payload)
            raw = _canonical_bytes(receipt.model_dump(mode="json")) + b"\n"
            raw_sha = _sha256(raw)
            self._write_create_only(
                self._receipt_path(receipt.receipt_id), raw
            )
            state.update(
                state="SAFE_TO_RESTART",
                active_receipt_id=receipt.receipt_id,
                active_receipt_raw_sha256=raw_sha,
                receipt_consumed=False,
                blockers=[],
                expires_at=receipt.expires_at.isoformat(),
                updated_at=issued_at.isoformat(),
            )
            self._write_state(state)
            return {
                "state": self._public_state(state),
                "receipt": receipt.model_dump(mode="json"),
                "blockers": [],
            }

    def consume(
        self,
        recheck: SafeRestartRecheckDTO,
        *,
        consumer_run_id: str,
        operator: str,
    ) -> SafeRestartConsumeMarkerDTO:
        raise DeploymentDrainError(
            "SAFE_RESTART_CONSUMER_INACTIVE_PHASE_1_PRE_A",
            "online recheck and one-shot consumption are not activated",
        )

    def _consume_after_phase_1_pre_b_activation(
        self,
        recheck: SafeRestartRecheckDTO,
        *,
        consumer_run_id: str,
        operator: str,
    ) -> SafeRestartConsumeMarkerDTO:
        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            state = self._expire_if_needed(state)
            if state["state"] != "SAFE_TO_RESTART":
                raise DeploymentDrainError(
                    "SAFE_RESTART_NOT_AVAILABLE",
                    "no live safe restart receipt is available",
                )
            if state["receipt_consumed"]:
                raise DeploymentDrainError(
                    "SAFE_RESTART_ALREADY_CONSUMED",
                    "safe restart receipt is one-shot",
                )
            receipt = self._read_receipt(recheck.receipt_id)
            receipt_raw = self._read_secure_file(
                self._receipt_path(receipt.receipt_id)
            )
            receipt_raw_sha = _sha256(receipt_raw)
            self._verify_recheck(
                state, receipt, receipt_raw_sha, recheck
            )
            consumed_at = self._now()
            if not receipt.issued_at <= consumed_at < receipt.expires_at:
                state = self._expire_receipt(state)
                raise DeploymentDrainError(
                    "SAFE_RESTART_EXPIRED", "safe restart receipt expired"
                )
            if not (
                receipt.issued_at
                <= recheck.snapshot.captured_at
                <= recheck.checked_at
                <= consumed_at
            ):
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_TIME_INVALID",
                    "recheck timestamps are outside the receipt window",
                )
            if consumed_at - recheck.checked_at > timedelta(seconds=30):
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_STALE",
                    "recheck is older than 30 seconds",
                )
            recheck_canonical_sha = _sha256(
                _canonical_bytes(recheck.model_dump(mode="json"))
            )
            marker_core = {
                "schema_version": "web_bridge_safe_restart_consume_v1",
                "purpose": "consume_safe_restart_receipt_once",
                "receipt_id": receipt.receipt_id,
                "receipt_raw_sha256": receipt_raw_sha,
                "receipt_core_sha256": receipt.receipt_core_sha256,
                "deployment_attempt_id": receipt.deployment_attempt_id,
                "release_plan_core_sha256": receipt.release_plan_core_sha256,
                "restart_action_sha256": receipt.restart_action_sha256,
                "drain_epoch": receipt.drain_epoch,
                "execution_epoch": receipt.execution_epoch,
                "consumed_at": _utc_json_timestamp(consumed_at),
                "consumer_run_id": consumer_run_id,
                "operator": operator,
                "recheck_canonical_sha256": recheck_canonical_sha,
                "one_shot_consumed": True,
                "automatic_deploy_allowed": False,
                "production_allowed": False,
                "live_trading_authorized": False,
            }
            core_sha = _sha256(_canonical_bytes(marker_core))
            marker = SafeRestartConsumeMarkerDTO.model_validate(
                {
                    **marker_core,
                    "consume_id": f"safe-restart-consume-{core_sha}",
                    "consume_core_sha256": core_sha,
                }
            )
            self._write_create_only(
                self._consume_path(receipt.receipt_id),
                _canonical_bytes(marker.model_dump(mode="json")) + b"\n",
            )
            state.update(
                receipt_consumed=True,
                consumed_at=consumed_at.isoformat(),
                consume_id=marker.consume_id,
                updated_at=consumed_at.isoformat(),
            )
            self._write_state(state)
            return marker

    def release(
        self,
        *,
        expected_drain_epoch: int,
        request_id: str,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        if not operator or not reason:
            raise ValueError("operator and reason are required")
        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            if state["state"] not in {
                "DRAINING",
                "DRAIN_BLOCKED",
                "SAFE_TO_RESTART",
            }:
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_NOT_RELEASABLE",
                    "current deployment drain cannot be released",
                )
            if (
                state["drain_epoch"] != expected_drain_epoch
                or state["active_request_id"] != request_id
            ):
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_EPOCH_MISMATCH",
                    "release does not own the active drain epoch",
                )
            if state["receipt_consumed"]:
                raise DeploymentDrainError(
                    "SAFE_RESTART_ALREADY_CONSUMED",
                    "a consumed restart must reconcile in the new process",
                )
            state = self._to_running(
                state,
                freeze_reason=f"released:{operator}:{reason}",
            )
            self._write_state(state)
            return self._public_state(state)

    def complete_reconciliation(
        self,
        *,
        expected_execution_epoch: int,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        raise DeploymentDrainError(
            "RECONCILIATION_INACTIVE_PHASE_1_PRE_A",
            "online reconciliation evidence is not activated",
        )

    def _complete_reconciliation_after_phase_1_pre_b_activation(
        self,
        *,
        expected_execution_epoch: int,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        if not operator or not reason:
            raise ValueError("operator and reason are required")
        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            if state["state"] != "RESTARTED_FROZEN":
                raise DeploymentDrainError(
                    "POST_RESTART_NOT_FROZEN",
                    "no restarted frozen state requires reconciliation",
                )
            if state["execution_epoch"] != expected_execution_epoch:
                raise DeploymentDrainError(
                    "EXECUTION_EPOCH_MISMATCH",
                    "reconciliation execution epoch is stale",
                )
            state = self._to_running(
                state,
                freeze_reason=f"reconciled:{operator}:{reason}",
            )
            self._write_state(state)
            return self._public_state(state)

    def _receipt_core(
        self,
        request: DeploymentDrainAcquireDTO,
        snapshot: DeploymentSafetySnapshotDTO,
        *,
        issued_at: datetime,
        drain_epoch: int,
        execution_epoch: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": "web_bridge_safe_restart_receipt_v1",
            "purpose": "authorize_one_bound_web_bridge_restart_attempt",
            "request_id": request.request_id,
            "deployment_attempt_id": request.deployment_attempt_id,
            "release_plan_id": request.release_plan_id,
            "release_plan_core_sha256": request.release_plan_core_sha256,
            "restart_action_sha256": request.restart_action_sha256,
            "unit": "web-bridge",
            "issued_at": _utc_json_timestamp(issued_at),
            "expires_at": (
                issued_at + timedelta(seconds=request.ttl_seconds)
            ).isoformat().replace("+00:00", "Z"),
            "ttl_seconds": request.ttl_seconds,
            "drain_epoch": drain_epoch,
            "execution_epoch": execution_epoch,
            "issuer_source_commit_sha": request.issuer_source_commit_sha,
            "issuer_image_digest": request.issuer_image_digest,
            "issuer_config_sha256": request.issuer_config_sha256,
            "issuer_runtime_instance_id": request.issuer_runtime_instance_id,
            "target_source_commit_sha": request.target_source_commit_sha,
            "target_image_digest": request.target_image_digest,
            "target_config_sha256": request.target_config_sha256,
            "rollback_image_digest": request.rollback_image_digest,
            "rollback_config_sha256": request.rollback_config_sha256,
            "nonce": request.nonce,
            "snapshot": snapshot.model_dump(mode="json"),
            "safe_to_restart": True,
            "one_shot": True,
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
        }

    def _verify_recheck(
        self,
        state: dict[str, Any],
        receipt: SafeRestartReceiptDTO,
        receipt_raw_sha: str,
        recheck: SafeRestartRecheckDTO,
    ) -> None:
        expected = (
            state["active_receipt_id"],
            state["active_receipt_raw_sha256"],
            receipt.deployment_attempt_id,
            receipt.release_plan_core_sha256,
            receipt.restart_action_sha256,
            receipt.drain_epoch,
            receipt.execution_epoch,
        )
        observed = (
            recheck.receipt_id,
            recheck.receipt_raw_sha256,
            recheck.deployment_attempt_id,
            recheck.release_plan_core_sha256,
            recheck.restart_action_sha256,
            recheck.drain_epoch,
            recheck.execution_epoch,
        )
        if observed != expected or receipt_raw_sha != recheck.receipt_raw_sha256:
            raise DeploymentDrainError(
                "SAFE_RESTART_BINDING_MISMATCH",
                "safe restart recheck does not match the active receipt",
            )
        expected_snapshot = receipt.snapshot.model_dump(mode="json")
        observed_snapshot = recheck.snapshot.model_dump(mode="json")
        expected_snapshot.pop("captured_at")
        observed_snapshot.pop("captured_at")
        if observed_snapshot != expected_snapshot:
            raise DeploymentDrainError(
                "SAFE_RESTART_STATE_DRIFT",
                "deployment safety state changed after receipt issue",
            )
        if recheck.snapshot.captured_at < receipt.snapshot.captured_at:
            raise DeploymentDrainError(
                "SAFE_RESTART_CLOCK_ROLLBACK",
                "recheck predates the receipt safety snapshot",
            )
        blockers = deployment_snapshot_blockers(recheck.snapshot)
        if blockers:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_BLOCKED", ",".join(blockers)
            )

    def _expire_if_needed(self, state: dict[str, Any]) -> dict[str, Any]:
        if state["state"] != "SAFE_TO_RESTART" or state["receipt_consumed"]:
            return state
        expires = state.get("expires_at")
        if expires and self._now() >= datetime.fromisoformat(expires):
            return self._expire_receipt(state)
        return state

    def _expire_receipt(self, state: dict[str, Any]) -> dict[str, Any]:
        state.update(
            state="DRAIN_BLOCKED",
            last_invalidated_receipt_id=state["active_receipt_id"],
            active_receipt_id=None,
            active_receipt_raw_sha256=None,
            blockers=["receipt_expired"],
            expires_at=None,
            freeze_reason="receipt_expired_drain_remains_locked",
            updated_at=self._now().isoformat(),
        )
        self._write_state(state)
        return state

    def _to_running(
        self, state: dict[str, Any], *, freeze_reason: str
    ) -> dict[str, Any]:
        state.update(
            state="RUNNING",
            active_request_id=None,
            active_request_sha256=None,
            active_receipt_id=None,
            active_receipt_raw_sha256=None,
            receipt_consumed=False,
            consumed_at=None,
            consume_id=None,
            blockers=[],
            expires_at=None,
            freeze_reason=freeze_reason,
            updated_at=self._now().isoformat(),
        )
        return state

    def _public_state(self, state: dict[str, Any]) -> dict[str, Any]:
        runtime_current = bool(
            state["runtime_instance_id"] == self.runtime_instance_id
            and state["execution_epoch"] == self.execution_epoch
        )
        return {
            **state,
            "runtime_current": runtime_current,
            "deployment_authorized": bool(
                state["state"] == "SAFE_TO_RESTART"
                and state["receipt_consumed"]
                and runtime_current
            ),
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
        }

    def _require_current_runtime(self, state: dict[str, Any]) -> None:
        if (
            state["runtime_instance_id"] != self.runtime_instance_id
            or state["execution_epoch"] != self.execution_epoch
        ):
            raise DeploymentDrainError(
                "EXECUTION_EPOCH_STALE",
                "this process no longer owns the durable execution epoch",
            )

    def _load_or_initial_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            if self.require_fresh_bootstrap:
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_ALREADY_BOOTSTRAPPED",
                    "custody state already exists",
                )
            state = self._load_state()
            self._validate_epoch_anchor(state)
            return state
        if (
            not self.allow_initial_bootstrap
            or self.epoch_anchor_path.exists()
            or any(self.receipt_dir.iterdir())
            or any(self.consume_dir.iterdir())
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_BOOTSTRAP_REQUIRED",
                "missing durable state requires an explicit clean bootstrap",
            )
        now = self._now().isoformat()
        state = {
            "schema_version": STATE_VERSION,
            "state": self.initial_bootstrap_state,
            "drain_epoch": 0,
            "execution_epoch": 0,
            "runtime_instance_id": self.runtime_instance_id,
            "active_request_id": None,
            "active_request_sha256": None,
            "active_receipt_id": None,
            "active_receipt_raw_sha256": None,
            "receipt_consumed": False,
            "consumed_at": None,
            "consume_id": None,
            "last_invalidated_receipt_id": None,
            "blockers": [],
            "expires_at": None,
            "freeze_reason": (
                "initial_bootstrap_requires_reconciliation"
                if self.initial_bootstrap_state == "RESTARTED_FROZEN"
                else None
            ),
            "updated_at": now,
        }
        self._write_state(state)
        return state

    def _load_state(self) -> dict[str, Any]:
        payload = json.loads(self._read_secure_file(self.state_path))
        required = {
            "schema_version",
            "state",
            "drain_epoch",
            "execution_epoch",
            "runtime_instance_id",
            "active_request_id",
            "active_request_sha256",
            "active_receipt_id",
            "active_receipt_raw_sha256",
            "receipt_consumed",
            "consumed_at",
            "consume_id",
            "last_invalidated_receipt_id",
            "blockers",
            "expires_at",
            "freeze_reason",
            "updated_at",
        }
        if set(payload) != required:
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID", "state fields are invalid"
            )
        if (
            payload["schema_version"] != STATE_VERSION
            or payload["state"] not in STATES
            or type(payload["drain_epoch"]) is not int
            or payload["drain_epoch"] < 0
            or type(payload["execution_epoch"]) is not int
            or payload["execution_epoch"] < 0
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID", "state values are invalid"
            )
        return payload

    def _write_state(self, state: dict[str, Any]) -> None:
        self._atomic_write(
            self.state_path, _canonical_bytes(state) + b"\n"
        )
        anchor = {
            "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
            "drain_epoch": state["drain_epoch"],
            "execution_epoch": state["execution_epoch"],
        }
        self._atomic_write(
            self.epoch_anchor_path, _canonical_bytes(anchor) + b"\n"
        )

    def _validate_epoch_anchor(self, state: dict[str, Any]) -> None:
        if not self.epoch_anchor_path.exists():
            if self.allow_initial_bootstrap:
                anchor = {
                    "schema_version": (
                        "web_bridge_deployment_drain_epoch_anchor_v1"
                    ),
                    "drain_epoch": state["drain_epoch"],
                    "execution_epoch": state["execution_epoch"],
                }
                self._atomic_write(
                    self.epoch_anchor_path,
                    _canonical_bytes(anchor) + b"\n",
                )
                return
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_EPOCH_ANCHOR_MISSING",
                "durable state exists without its epoch anchor",
            )
        try:
            anchor = json.loads(self._read_secure_file(self.epoch_anchor_path))
        except (json.JSONDecodeError, OSError) as exc:
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_EPOCH_ANCHOR_INVALID",
                "epoch anchor is unreadable",
            ) from exc
        if (
            set(anchor) != {"schema_version", "drain_epoch", "execution_epoch"}
            or anchor["schema_version"]
            != "web_bridge_deployment_drain_epoch_anchor_v1"
            or type(anchor["drain_epoch"]) is not int
            or type(anchor["execution_epoch"]) is not int
            or state["drain_epoch"] < anchor["drain_epoch"]
            or state["execution_epoch"] < anchor["execution_epoch"]
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_EPOCH_ROLLBACK",
                "durable state epoch is older than its high-water anchor",
            )

    def _read_receipt(self, receipt_id: str | None) -> SafeRestartReceiptDTO:
        if not receipt_id:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_MISSING", "active receipt is missing"
            )
        return SafeRestartReceiptDTO.model_validate_json(
            self._read_secure_file(self._receipt_path(receipt_id))
        )

    def _receipt_path(self, receipt_id: str) -> Path:
        if not receipt_id.startswith("safe-restart-") or "/" in receipt_id:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_ID_INVALID", "invalid receipt id"
            )
        return self.receipt_dir / f"{receipt_id}.json"

    def _consume_path(self, receipt_id: str) -> Path:
        if not receipt_id.startswith("safe-restart-") or "/" in receipt_id:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_ID_INVALID", "invalid receipt id"
            )
        return self.consume_dir / f"{receipt_id}.consumed.json"

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        self._ensure_initialized()
        with self._exclusive_initialized():
            yield

    @contextmanager
    def _exclusive_initialized(self) -> Iterator[None]:
        with self._process_lock:
            depth = int(getattr(self._lock_context, "depth", 0))
            if depth:
                self._lock_context.depth = depth + 1
                try:
                    yield
                finally:
                    self._lock_context.depth = depth
                return
            flags = os.O_RDWR | os.O_NOFOLLOW
            fd = os.open(self.lock_path, flags)
            try:
                self._validate_fd(fd, self.lock_path)
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked = os.fstat(fd)
                current = self.lock_path.lstat()
                if (
                    stat.S_ISLNK(current.st_mode)
                    or locked.st_dev != current.st_dev
                    or locked.st_ino != current.st_ino
                ):
                    raise DeploymentDrainError(
                        "DEPLOYMENT_DRAIN_LOCK_REPLACED",
                        "deployment drain lock path changed during acquisition",
                    )
                self._lock_context.depth = 1
                try:
                    yield
                finally:
                    self._lock_context.depth = 0
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _prepare_directory(self, path: Path) -> None:
        self._reject_symlink_components(path)
        if not path.exists():
            # A fresh checkout has no logs/ directory.  Create the configured
            # custody root without requiring an unrelated bootstrap step;
            # the leaf is still validated below and forced owner-only.
            path.mkdir(mode=0o700, parents=True)
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_PATH_INSECURE",
                f"deployment drain directory is insecure: {path}",
            )

    def _reject_symlink_components(self, path: Path) -> None:
        absolute = path.absolute()
        for candidate in (absolute, *absolute.parents):
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_PATH_INSECURE",
                    f"deployment drain path contains a symlink: {candidate}",
                )

    def _prepare_lock_file(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            self._validate_fd(fd, self.lock_path)
        finally:
            os.close(fd)

    def _read_secure_file(self, path: Path) -> bytes:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            self._validate_fd(fd, path)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            os.close(fd)

    def _validate_fd(self, fd: int, path: Path) -> None:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_PATH_INSECURE",
                f"deployment drain file is insecure: {path}",
            )

    def _atomic_write(self, path: Path, data: bytes) -> None:
        if path.is_symlink():
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_PATH_INSECURE",
                f"deployment drain file is a symlink: {path}",
            )
        if path.exists():
            self._read_secure_file(path)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _write_create_only(self, path: Path, data: bytes) -> None:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(path.parent)

    def _now(self) -> datetime:
        value = self.clock()
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_CLOCK_INVALID", "clock must return UTC"
            )
        return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _utc_json_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while persisting deployment drain")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def deployment_drain_for(
    root: Path | str,
    *,
    clock: Callable[[], datetime] | None = None,
    runtime_instance_id: str | None = None,
    allow_initial_bootstrap: bool = False,
) -> DeploymentDrainService:
    """Return the one process-wide gate for an absolute state-root path.

    ``absolute`` is intentional: resolving symlinks before construction would
    bypass the service's symlink rejection.  Equivalent production callers
    using the same configured path therefore share the same RLock instance.
    """

    key = Path(root).expanduser().absolute()
    with _SERVICE_REGISTRY_LOCK:
        service = _SERVICE_REGISTRY.get(key)
        if service is None:
            service = DeploymentDrainService(
                key,
                clock=clock,
                runtime_instance_id=runtime_instance_id,
                allow_initial_bootstrap=allow_initial_bootstrap,
            )
            _SERVICE_REGISTRY[key] = service
        return service
