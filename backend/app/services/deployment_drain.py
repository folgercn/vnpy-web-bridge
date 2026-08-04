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
    DeploymentOnlineCheckpointDTO,
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentSafetySnapshotDTO,
    SafeRestartConsumeMarkerDTO,
    SafeRestartOnlineRecheckDTO,
    SafeRestartReceiptDTO,
    SafeRestartRecheckDTO,
    deployment_rpc_execution_facts_sha256,
    deployment_snapshot_blockers,
)
from app.services.deployment_online_recheck import (
    DeploymentOnlineRecheckError,
    build_safe_restart_online_recheck,
    verify_safe_restart_online_recheck,
)

STATE_VERSION = "web_bridge_deployment_drain_state_v2"
LEGACY_STATE_VERSION = "web_bridge_deployment_drain_state_v1"
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
    Phase 1-pre-A connects the mutation guard to Trade/Risk/CTA admission;
    A1 adds Commodity lock ordering and A2 adds a durable online checkpoint.
    Receipt consumption and deployment remain deliberately inactive.
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
        allow_untrusted_snapshot_provider: bool = False,
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
        self.allow_untrusted_snapshot_provider = allow_untrusted_snapshot_provider
        self._process_lock = RLock()
        self._lock_context = local()
        self.receipt_dir = self.root / "receipts"
        self.consume_dir = self.root / "consumes"
        self.checkpoint_dir = self.root / "checkpoints"
        self.recheck_dir = self.root / "rechecks"
        self.lock_path = self.root / ".deployment-drain.lock"
        self.state_path = self.root / "state.json"
        self.epoch_anchor_path = self.root / "epoch-anchor.json"
        self._initialized = False
        self.execution_epoch = 0
        self.verified_restart_checkpoint: DeploymentOnlineCheckpointDTO | None = None
        self._online_snapshot_owner: object | None = None
        self._online_snapshot_provider: (
            Callable[[], DeploymentSafetySnapshotDTO] | None
        ) = None
        self._online_recheck_owner: object | None = None
        self._online_recheck_provider: (
            Callable[[], DeploymentOnlineRecheckCheckpointDTO] | None
        ) = None

    def _ensure_initialized(self) -> None:
        """Activate custody lazily so importing service modules cannot fence runtime."""

        with self._process_lock:
            if self._initialized:
                return
            self._prepare_directory(self.root)
            self._prepare_directory(self.receipt_dir)
            self._prepare_directory(self.consume_dir)
            self._prepare_directory(self.checkpoint_dir)
            self._prepare_directory(self.recheck_dir)
            self._prepare_lock_file()
            with self._exclusive_initialized():
                state = self._load_or_initial_state()
                self._verify_active_online_recheck_pointer(state)
                previous_state = state["state"]
                restart_receipt_id = state.get("active_receipt_id")
                if (
                    restart_receipt_id is None
                    and (
                        previous_state == "RESTARTED_FROZEN"
                        or str(state.get("freeze_reason") or "").startswith(
                            "online_snapshot_receipt_expired_"
                        )
                    )
                    and state.get("active_receipt_raw_sha256") is not None
                ):
                    restart_receipt_id = state.get("last_invalidated_receipt_id")
                restart_receipt_raw_sha256 = (
                    state.get("active_receipt_raw_sha256")
                    if restart_receipt_id
                    else None
                )
                state["execution_epoch"] += 1
                state["runtime_instance_id"] = self.runtime_instance_id
                state["updated_at"] = self._now().isoformat()
                self._invalidate_online_recheck(state)
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
                    if restart_receipt_id is None:
                        state["active_receipt_raw_sha256"] = None
                    state["receipt_consumed"] = False
                    if state.get("freeze_reason") not in {
                        "initial_bootstrap_requires_reconciliation",
                        "legacy_v1_consumption_evidence_quarantined",
                    }:
                        state["freeze_reason"] = (
                            "process_restarted_old_receipt_invalidated"
                        )
                self._write_state(state)
                self.execution_epoch = state["execution_epoch"]
                if restart_receipt_id:
                    try:
                        self.verified_restart_checkpoint = (
                            self._load_online_checkpoint_for_receipt(
                                restart_receipt_id,
                                expected_raw_sha256=(restart_receipt_raw_sha256),
                            )
                        )
                    except DeploymentDrainError as exc:
                        state.update(
                            blockers=[f"checkpoint_verification_failed:{exc.code}"],
                            freeze_reason=("restart_checkpoint_verification_failed"),
                            updated_at=self._now().isoformat(),
                        )
                        self._write_state(state)
                        self._initialized = True
                        raise
            self._initialized = True

    def status(self) -> dict[str, Any]:
        with self._exclusive():
            state = self._load_state()
            if (
                state["runtime_instance_id"] == self.runtime_instance_id
                and state["execution_epoch"] == self.execution_epoch
            ):
                state = self._expire_if_needed(state)
            self._verify_active_online_recheck_pointer(state)
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
        if (
            not self.allow_untrusted_snapshot_provider
            and snapshot_provider is not self._online_snapshot_provider
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_PROVIDER_UNTRUSTED",
                "snapshot provider is not bound to the online owner",
            )
        return self._acquire_with_snapshot(request, snapshot_provider)

    def bind_online_snapshot_provider(
        self,
        owner: object,
        provider: Callable[[], DeploymentSafetySnapshotDTO],
    ) -> None:
        if getattr(provider, "__self__", None) is not owner:
            raise TypeError("online snapshot provider must be bound to its owner")
        if (
            self._online_recheck_owner is not None
            and self._online_recheck_owner is not owner
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_OWNER_CONFLICT",
                "online snapshot and recheck must share one owner",
            )
        if self._online_snapshot_owner is None:
            self._online_snapshot_owner = owner
            self._online_snapshot_provider = provider
            return
        if self._online_snapshot_owner is not owner:
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_OWNER_CONFLICT",
                "another process-local owner already owns online snapshots",
            )

    def bind_online_recheck_provider(
        self,
        owner: object,
        provider: Callable[[], DeploymentOnlineRecheckCheckpointDTO],
    ) -> None:
        if getattr(provider, "__self__", None) is not owner:
            raise TypeError("online recheck provider must be bound to its owner")
        if (
            self._online_snapshot_owner is not None
            and self._online_snapshot_owner is not owner
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_OWNER_CONFLICT",
                "online snapshot and recheck must share one owner",
            )
        if self._online_recheck_owner is None:
            self._online_recheck_owner = owner
            self._online_recheck_provider = provider
            return
        if self._online_recheck_owner is not owner:
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_OWNER_CONFLICT",
                "another process-local owner already owns online rechecks",
            )

    def capture_online_recheck(
        self,
        *,
        owner: object,
    ) -> SafeRestartOnlineRecheckDTO:
        provider = self._online_recheck_provider
        if owner is not self._online_recheck_owner or provider is None:
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_OWNER_INVALID",
                "caller does not own the online recheck provider",
            )
        with self._exclusive():
            state = self._load_state()
            self._require_current_runtime(state)
            state = self._expire_if_needed(state)
            if state["state"] != "SAFE_TO_RESTART":
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_NOT_AVAILABLE",
                    "no live safe restart receipt is available",
                )
            if state["active_online_recheck_id"] is not None:
                self._verify_active_online_recheck_pointer(state)
                return self._read_active_online_recheck(state)

            receipt = self._read_receipt(
                state["active_receipt_id"],
                expected_raw_sha256=state["active_receipt_raw_sha256"],
            )
            receipt_raw = self._read_secure_file(
                self._receipt_path(receipt.receipt_id)
            )
            original = self._load_online_checkpoint_for_receipt(
                receipt.receipt_id,
                expected_raw_sha256=state["active_receipt_raw_sha256"],
            )
            if original is None:
                raise DeploymentDrainError(
                    "DEPLOYMENT_RECHECK_CHECKPOINT_REQUIRED",
                    "fresh online recheck requires an A2 checkpoint",
                )
            original_raw = self._read_secure_file(
                self._checkpoint_path(receipt.snapshot.checkpoint_sha256)
            )
            artifact_path = self._online_recheck_path(receipt.receipt_id)
            if artifact_path.exists() or artifact_path.is_symlink():
                state.update(
                    state="DRAIN_BLOCKED",
                    blockers=["online_recheck_orphan_or_collision"],
                    freeze_reason=(
                        "online_snapshot_online_recheck_orphan_or_collision"
                    ),
                    updated_at=self._now().isoformat(),
                )
                self._write_state(state)
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_ORPHAN",
                    "an uncommitted online recheck artifact already exists",
                )

            seed = _sha256(
                b"issue267-b1b-online-recheck-v1\0"
                + receipt_raw
                + original_raw
            )
            context = {
                "request_id": receipt.request_id,
                "runtime_instance_id": original.runtime_instance_id,
                "drain_epoch": receipt.drain_epoch,
                "execution_epoch": receipt.execution_epoch,
                "recheck_id": f"deployment-recheck-{seed}",
                "fresh_challenge": f"fresh-recheck-{seed}",
                "owner_challenge": original.rpc.challenge,
                "original_checkpoint_raw_sha256": _sha256(original_raw),
                "original_server_instance_id": original.rpc.server_instance_id,
                "original_fact_generation": original.rpc.fact_generation,
                "original_execution_facts_canonical_sha256": (
                    deployment_rpc_execution_facts_sha256(original.rpc)
                ),
            }
            self._lock_context.online_recheck_context = context
            try:
                checkpoint = provider()
            except Exception as exc:
                self._block_online_recheck_failure(state, exc.__class__.__name__)
                if isinstance(exc, DeploymentDrainError):
                    raise
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_CAPTURE_FAILED",
                    "trusted online recheck capture failed",
                ) from exc
            finally:
                self._lock_context.online_recheck_context = None
            if not isinstance(checkpoint, DeploymentOnlineRecheckCheckpointDTO):
                self._block_online_recheck_failure(state, "invalid_provider_result")
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_BINDING_MISMATCH",
                    "online recheck provider returned an invalid checkpoint",
                )

            checkpoint_raw = (
                _canonical_bytes(checkpoint.model_dump(mode="json")) + b"\n"
            )
            checkpoint_raw_sha = _sha256(checkpoint_raw)
            checkpoint_path = self._checkpoint_path(checkpoint_raw_sha)
            try:
                self._write_create_only(checkpoint_path, checkpoint_raw)
                if self._read_secure_file(checkpoint_path) != checkpoint_raw:
                    raise DeploymentDrainError(
                        "SAFE_RESTART_RECHECK_READBACK_FAILED",
                        "recheck checkpoint readback did not match",
                    )
                artifact = build_safe_restart_online_recheck(
                    receipt_raw=receipt_raw,
                    original_checkpoint_raw=original_raw,
                    recheck_checkpoint_raw=checkpoint_raw,
                )
                artifact_raw = (
                    _canonical_bytes(artifact.model_dump(mode="json")) + b"\n"
                )
                self._write_create_only(artifact_path, artifact_raw)
                if self._read_secure_file(artifact_path) != artifact_raw:
                    raise DeploymentDrainError(
                        "SAFE_RESTART_RECHECK_READBACK_FAILED",
                        "online recheck artifact readback did not match",
                    )
            except (
                DeploymentDrainError,
                DeploymentOnlineRecheckError,
                OSError,
            ) as exc:
                self._block_online_recheck_failure(state, exc.__class__.__name__)
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_PERSIST_FAILED",
                    "online recheck evidence was not committed",
                ) from exc

            state.update(
                active_online_recheck_id=artifact.online_recheck_id,
                active_online_recheck_raw_sha256=_sha256(artifact_raw),
                active_recheck_checkpoint_raw_sha256=checkpoint_raw_sha,
                online_rechecked_at=artifact.checked_at.isoformat(),
                freeze_reason=(
                    "online_snapshot_online_recheck_durable_consume_inactive"
                ),
                updated_at=self._now().isoformat(),
            )
            try:
                self._write_state(state)
            except (DeploymentDrainError, OSError) as exc:
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECHECK_STATE_COMMIT_FAILED",
                    "online recheck evidence exists but is not active",
                ) from exc
            return artifact

    def online_recheck_capture_context(self) -> dict[str, Any]:
        if int(getattr(self._lock_context, "depth", 0)) <= 0:
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_OUTSIDE_GATE",
                "online recheck must be captured while holding the gate",
            )
        context = getattr(self._lock_context, "online_recheck_context", None)
        if not isinstance(context, dict):
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_CONTEXT_INVALID",
                "online recheck context is unavailable",
            )
        return dict(context)

    def acquire_online_snapshot(
        self,
        request: DeploymentDrainAcquireDTO,
        *,
        owner: object,
    ) -> dict[str, Any]:
        if (
            owner is not self._online_snapshot_owner
            or self._online_snapshot_provider is None
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_OWNER_INVALID",
                "caller does not own the online snapshot provider",
            )
        return self._acquire_with_snapshot(
            request,
            self._online_snapshot_provider,
        )

    def _acquire_with_snapshot(
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
                    try:
                        self._load_online_checkpoint_for_receipt(
                            state["active_receipt_id"],
                            expected_raw_sha256=(state["active_receipt_raw_sha256"]),
                        )
                        receipt = self._read_receipt(
                            state["active_receipt_id"],
                            expected_raw_sha256=(state["active_receipt_raw_sha256"]),
                        )
                    except DeploymentDrainError as exc:
                        online_fenced = str(
                            state.get("freeze_reason") or ""
                        ).startswith("online_snapshot_")
                        state.update(
                            state="DRAIN_BLOCKED",
                            blockers=[f"safe_receipt_verification_failed:{exc.code}"],
                            freeze_reason=(
                                "online_snapshot_safe_receipt_verification_failed"
                                if online_fenced
                                else "safe_receipt_verification_failed"
                            ),
                            updated_at=self._now().isoformat(),
                        )
                        self._write_state(state)
                        raise
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
                    consumed_at=None,
                    consume_id=None,
                    blockers=[],
                    expires_at=None,
                    freeze_reason=(
                        "online_snapshot_windows_fence_pending"
                        if snapshot_provider is self._online_snapshot_provider
                        else None
                    ),
                    updated_at=self._now().isoformat(),
                )
                self._invalidate_online_recheck(state)
                self._write_state(state)

            try:
                snapshot = snapshot_provider()
            except Exception as exc:
                state.update(
                    state="DRAIN_BLOCKED",
                    blockers=[f"snapshot_capture_failed:{exc.__class__.__name__}"],
                    freeze_reason="online_snapshot_capture_failed",
                    updated_at=self._now().isoformat(),
                )
                self._write_state(state)
                if isinstance(exc, DeploymentDrainError):
                    raise
                raise DeploymentDrainError(
                    "DEPLOYMENT_SNAPSHOT_CAPTURE_FAILED",
                    "online deployment snapshot capture failed",
                ) from exc
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
            self._write_create_only(self._receipt_path(receipt.receipt_id), raw)
            state.update(
                state="SAFE_TO_RESTART",
                active_receipt_id=receipt.receipt_id,
                active_receipt_raw_sha256=raw_sha,
                receipt_consumed=False,
                consumed_at=None,
                consume_id=None,
                blockers=[],
                expires_at=receipt.expires_at.isoformat(),
                updated_at=issued_at.isoformat(),
            )
            self._invalidate_online_recheck(state)
            self._write_state(state)
            return {
                "state": self._public_state(state),
                "receipt": receipt.model_dump(mode="json"),
                "blockers": [],
            }

    def snapshot_capture_context(self) -> dict[str, Any]:
        """Return the bound drain identity only inside the active provider."""

        if int(getattr(self._lock_context, "depth", 0)) <= 0:
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_OUTSIDE_GATE",
                "online snapshot must be captured while holding the gate",
            )
        state = self._load_state()
        self._require_current_runtime(state)
        if state["state"] != "DRAINING" or not state["active_request_id"]:
            raise DeploymentDrainError(
                "DEPLOYMENT_SNAPSHOT_CONTEXT_INVALID",
                "online snapshot requires an active DRAINING request",
            )
        return {
            "request_id": state["active_request_id"],
            "drain_epoch": state["drain_epoch"],
            "execution_epoch": state["execution_epoch"],
            "runtime_instance_id": state["runtime_instance_id"],
        }

    def persist_online_checkpoint(
        self,
        checkpoint: DeploymentOnlineCheckpointDTO,
    ) -> str:
        context = self.snapshot_capture_context()
        expected = (
            context["request_id"],
            context["runtime_instance_id"],
            context["drain_epoch"],
            context["execution_epoch"],
        )
        observed = (
            checkpoint.request_id,
            checkpoint.runtime_instance_id,
            checkpoint.drain_epoch,
            checkpoint.execution_epoch,
        )
        if observed != expected:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_BINDING_MISMATCH",
                "online checkpoint does not match the active drain",
            )
        raw = _canonical_bytes(checkpoint.model_dump(mode="json")) + b"\n"
        raw_sha = _sha256(raw)
        path = self._checkpoint_path(raw_sha)
        try:
            self._write_create_only(path, raw)
        except FileExistsError:
            if self._read_secure_file(path) != raw:
                raise DeploymentDrainError(
                    "DEPLOYMENT_CHECKPOINT_COLLISION",
                    "checkpoint path exists with different bytes",
                )
        if self._read_secure_file(path) != raw:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_READBACK_FAILED",
                "durable checkpoint readback did not match",
            )
        return raw_sha

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
        del recheck, consumer_run_id, operator
        raise DeploymentDrainError(
            "SAFE_RESTART_CONSUMER_INACTIVE_PHASE_B1B",
            "state v2 does not activate one-shot consumption",
        )

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
            if str(state.get("freeze_reason") or "").startswith("online_snapshot_"):
                raise DeploymentDrainError(
                    "ONLINE_SNAPSHOT_RELEASE_INACTIVE_PHASE_1_PRE_B_A2",
                    "A2 cannot release a Windows-fenced online drain",
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
            "expires_at": (issued_at + timedelta(seconds=request.ttl_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
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
        online_fenced = str(state.get("freeze_reason") or "").startswith(
            "online_snapshot_"
        )
        state.update(
            state="DRAIN_BLOCKED",
            last_invalidated_receipt_id=state["active_receipt_id"],
            active_receipt_id=None,
            active_receipt_raw_sha256=(
                state.get("active_receipt_raw_sha256") if online_fenced else None
            ),
            blockers=["receipt_expired"],
            expires_at=None,
            freeze_reason=(
                "online_snapshot_receipt_expired_windows_fenced"
                if online_fenced
                else "receipt_expired_drain_remains_locked"
            ),
            updated_at=self._now().isoformat(),
        )
        self._invalidate_online_recheck(state)
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
        self._invalidate_online_recheck(state)
        return state

    @staticmethod
    def _invalidate_online_recheck(state: dict[str, Any]) -> None:
        active_id = state.get("active_online_recheck_id")
        if active_id is not None:
            state["last_invalidated_online_recheck_id"] = active_id
        state["active_online_recheck_id"] = None
        state["active_online_recheck_raw_sha256"] = None
        state["active_recheck_checkpoint_raw_sha256"] = None
        state["online_rechecked_at"] = None

    def _public_state(self, state: dict[str, Any]) -> dict[str, Any]:
        runtime_current = bool(
            state["runtime_instance_id"] == self.runtime_instance_id
            and state["execution_epoch"] == self.execution_epoch
        )
        return {
            **state,
            "runtime_current": runtime_current,
            "deployment_authorized": False,
            "consume_authorized": False,
            "reconciliation_authorized": False,
            "countable_forward": False,
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
            payload = json.loads(self._read_secure_file(self.state_path))
            if not isinstance(payload, dict):
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_STATE_INVALID",
                    "state payload must be an object",
                )
            migrated = payload.get("schema_version") == LEGACY_STATE_VERSION
            if migrated:
                state = self._migrate_v1_state(payload)
            else:
                state = self._validate_state_payload(payload)
            self._validate_epoch_anchor(state)
            if migrated:
                self._write_state(state)
            return state
        if (
            not self.allow_initial_bootstrap
            or self.epoch_anchor_path.exists()
            or any(self.receipt_dir.iterdir())
            or any(self.consume_dir.iterdir())
            or any(self.checkpoint_dir.iterdir())
            or any(self.recheck_dir.iterdir())
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
            "active_online_recheck_id": None,
            "active_online_recheck_raw_sha256": None,
            "active_recheck_checkpoint_raw_sha256": None,
            "online_rechecked_at": None,
            "last_invalidated_online_recheck_id": None,
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
        return self._validate_state_payload(payload)

    def _validate_state_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID",
                "state payload must be an object",
            )
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
            "active_online_recheck_id",
            "active_online_recheck_raw_sha256",
            "active_recheck_checkpoint_raw_sha256",
            "online_rechecked_at",
            "last_invalidated_online_recheck_id",
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
            or payload["receipt_consumed"] is not False
            or payload["consumed_at"] is not None
            or payload["consume_id"] is not None
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID", "state values are invalid"
            )
        recheck_values = (
            payload["active_online_recheck_id"],
            payload["active_online_recheck_raw_sha256"],
            payload["active_recheck_checkpoint_raw_sha256"],
            payload["online_rechecked_at"],
        )
        if any(value is None for value in recheck_values) != all(
            value is None for value in recheck_values
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID",
                "online recheck pointers must be all present or all absent",
            )
        if all(value is not None for value in recheck_values):
            recheck_id, raw_sha, checkpoint_raw_sha, rechecked_at = recheck_values
            if (
                not _is_prefixed_sha256(
                    recheck_id, "safe-restart-online-recheck-"
                )
                or not _is_sha256(raw_sha)
                or not _is_sha256(checkpoint_raw_sha)
                or not isinstance(rechecked_at, str)
            ):
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_STATE_INVALID",
                    "online recheck pointer values are invalid",
                )
            try:
                parsed_rechecked_at = datetime.fromisoformat(
                    rechecked_at.replace("Z", "+00:00")
                )
                if (
                    parsed_rechecked_at.tzinfo is None
                    or parsed_rechecked_at.utcoffset() is None
                    or parsed_rechecked_at.utcoffset().total_seconds() != 0
                ):
                    raise ValueError("timestamp is not UTC")
            except (AttributeError, ValueError) as exc:
                raise DeploymentDrainError(
                    "DEPLOYMENT_DRAIN_STATE_INVALID",
                    "online recheck timestamp is invalid",
                ) from exc
        invalidated_id = payload["last_invalidated_online_recheck_id"]
        if invalidated_id is not None and (
            not _is_prefixed_sha256(
                invalidated_id, "safe-restart-online-recheck-"
            )
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID",
                "last invalidated online recheck id is invalid",
            )
        return payload

    def _migrate_v1_state(self, payload: dict[str, Any]) -> dict[str, Any]:
        legacy_required = {
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
        if set(payload) != legacy_required:
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID",
                "legacy state fields are invalid",
            )
        if (
            payload["state"] not in STATES
            or type(payload["drain_epoch"]) is not int
            or payload["drain_epoch"] < 0
            or type(payload["execution_epoch"]) is not int
            or payload["execution_epoch"] < 0
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_STATE_INVALID",
                "legacy state values are invalid",
            )
        migrated = {
            **payload,
            "schema_version": STATE_VERSION,
            "active_online_recheck_id": None,
            "active_online_recheck_raw_sha256": None,
            "active_recheck_checkpoint_raw_sha256": None,
            "online_rechecked_at": None,
            "last_invalidated_online_recheck_id": None,
        }
        has_consumption_evidence = bool(
            payload["receipt_consumed"]
            or payload["consumed_at"] is not None
            or payload["consume_id"] is not None
            or any(self.consume_dir.iterdir())
        )
        migrated["receipt_consumed"] = False
        migrated["consumed_at"] = None
        migrated["consume_id"] = None
        if has_consumption_evidence:
            if migrated["active_receipt_id"] is not None:
                migrated["last_invalidated_receipt_id"] = migrated["active_receipt_id"]
            migrated.update(
                state="RESTARTED_FROZEN",
                active_request_id=None,
                active_request_sha256=None,
                active_receipt_id=None,
                active_receipt_raw_sha256=None,
                blockers=["legacy_v1_consumption_evidence_quarantined"],
                expires_at=None,
                freeze_reason=("legacy_v1_consumption_evidence_quarantined"),
                updated_at=self._now().isoformat(),
            )
        return self._validate_state_payload(migrated)

    def _write_state(self, state: dict[str, Any]) -> None:
        self._validate_state_payload(state)
        self._atomic_write(self.state_path, _canonical_bytes(state) + b"\n")
        anchor = {
            "schema_version": "web_bridge_deployment_drain_epoch_anchor_v1",
            "drain_epoch": state["drain_epoch"],
            "execution_epoch": state["execution_epoch"],
        }
        self._atomic_write(self.epoch_anchor_path, _canonical_bytes(anchor) + b"\n")

    def _validate_epoch_anchor(self, state: dict[str, Any]) -> None:
        if not self.epoch_anchor_path.exists():
            if self.allow_initial_bootstrap:
                anchor = {
                    "schema_version": ("web_bridge_deployment_drain_epoch_anchor_v1"),
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
            or anchor["schema_version"] != "web_bridge_deployment_drain_epoch_anchor_v1"
            or type(anchor["drain_epoch"]) is not int
            or type(anchor["execution_epoch"]) is not int
            or state["drain_epoch"] < anchor["drain_epoch"]
            or state["execution_epoch"] < anchor["execution_epoch"]
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_DRAIN_EPOCH_ROLLBACK",
                "durable state epoch is older than its high-water anchor",
            )

    def _read_receipt(
        self,
        receipt_id: str | None,
        *,
        expected_raw_sha256: str | None = None,
    ) -> SafeRestartReceiptDTO:
        if not receipt_id:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_MISSING", "active receipt is missing"
            )
        raw = self._read_secure_file(self._receipt_path(receipt_id))
        if expected_raw_sha256 is not None and _sha256(raw) != expected_raw_sha256:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH",
                "restart receipt exact bytes do not match durable state",
            )
        return SafeRestartReceiptDTO.model_validate_json(raw)

    def _load_online_checkpoint_for_receipt(
        self,
        receipt_id: str,
        *,
        expected_raw_sha256: str | None,
    ) -> DeploymentOnlineCheckpointDTO | None:
        try:
            receipt_raw = self._read_secure_file(self._receipt_path(receipt_id))
            if (
                expected_raw_sha256 is None
                or _sha256(receipt_raw) != expected_raw_sha256
            ):
                raise DeploymentDrainError(
                    "SAFE_RESTART_RECEIPT_RAW_HASH_MISMATCH",
                    "restart receipt exact bytes do not match durable state",
                )
            receipt = SafeRestartReceiptDTO.model_validate_json(receipt_raw)
        except DeploymentDrainError:
            raise
        except Exception as exc:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_INVALID",
                "restart receipt is invalid or unreadable",
            ) from exc
        if (
            receipt.snapshot.state_version
            != "web_bridge_deployment_online_checkpoint_v1"
        ):
            return None
        try:
            raw = self._read_secure_file(
                self._checkpoint_path(receipt.snapshot.checkpoint_sha256)
            )
        except OSError as exc:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_MISSING",
                "restart checkpoint is missing or unreadable",
            ) from exc
        if _sha256(raw) != receipt.snapshot.checkpoint_sha256:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_HASH_MISMATCH",
                "restart checkpoint bytes do not match the receipt",
            )
        try:
            checkpoint = DeploymentOnlineCheckpointDTO.model_validate_json(raw)
        except Exception as exc:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_INVALID",
                "restart checkpoint schema or hash bindings are invalid",
            ) from exc
        expected = (
            receipt.request_id,
            receipt.issuer_runtime_instance_id,
            receipt.drain_epoch,
            receipt.execution_epoch,
            receipt.snapshot.execution_plan_status,
            receipt.snapshot.execution_plan_hash,
            receipt.snapshot.plan_version,
            receipt.snapshot.state_sha256,
            receipt.snapshot.active_orders_snapshot_sha256,
            receipt.snapshot.positions_snapshot_sha256,
            receipt.snapshot.rpc_generation,
            receipt.snapshot.web_trade_enabled,
            receipt.snapshot.execution_authority_revoked,
            receipt.snapshot.auto_dispatch_stopped,
            receipt.snapshot.active_orders,
            receipt.snapshot.unknown_outcome,
            receipt.snapshot.reconcile_required,
            receipt.nonce,
        )
        observed = (
            checkpoint.request_id,
            checkpoint.runtime_instance_id,
            checkpoint.drain_epoch,
            checkpoint.execution_epoch,
            checkpoint.execution_plan_status,
            checkpoint.execution_plan_hash,
            checkpoint.plan_version,
            checkpoint.state_sha256,
            checkpoint.active_orders_snapshot_sha256,
            checkpoint.positions_snapshot_sha256,
            checkpoint.rpc.fact_generation,
            checkpoint.web_trade_enabled,
            checkpoint.execution_authority_revoked,
            checkpoint.auto_dispatch_stopped,
            checkpoint.active_orders,
            checkpoint.unknown_outcome,
            checkpoint.reconcile_required,
            checkpoint.rpc.challenge,
        )
        if observed != expected:
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_RECEIPT_MISMATCH",
                "restart checkpoint does not match its receipt snapshot",
            )
        return checkpoint

    def _block_online_recheck_failure(
        self, state: dict[str, Any], detail: str
    ) -> None:
        state.update(
            state="DRAIN_BLOCKED",
            blockers=[f"online_recheck_failed:{detail}"],
            freeze_reason=(
                "online_snapshot_online_recheck_failed_windows_remains_fenced"
            ),
            updated_at=self._now().isoformat(),
        )
        self._invalidate_online_recheck(state)
        self._write_state(state)

    def _read_active_online_recheck(
        self, state: dict[str, Any]
    ) -> SafeRestartOnlineRecheckDTO:
        receipt_id = state.get("active_receipt_id")
        raw = self._read_secure_file(self._online_recheck_path(receipt_id))
        if _sha256(raw) != state["active_online_recheck_raw_sha256"]:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_RAW_HASH_MISMATCH",
                "online recheck exact bytes do not match durable state",
            )
        try:
            artifact = SafeRestartOnlineRecheckDTO.model_validate_json(raw)
        except Exception as exc:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_INVALID",
                "online recheck artifact is invalid",
            ) from exc
        state_rechecked_at = datetime.fromisoformat(
            state["online_rechecked_at"].replace("Z", "+00:00")
        )
        if (
            artifact.online_recheck_id != state["active_online_recheck_id"]
            or artifact.receipt_id != receipt_id
            or artifact.recheck_checkpoint_raw_sha256
            != state["active_recheck_checkpoint_raw_sha256"]
            or artifact.checked_at != state_rechecked_at
        ):
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_BINDING_MISMATCH",
                "online recheck artifact does not match durable state",
            )
        return artifact

    def _verify_active_online_recheck_pointer(
        self, state: dict[str, Any]
    ) -> None:
        if state.get("active_online_recheck_id") is None:
            return
        artifact = self._read_active_online_recheck(state)
        checkpoint_raw = self._read_secure_file(
            self._checkpoint_path(artifact.recheck_checkpoint_raw_sha256)
        )
        if _sha256(checkpoint_raw) != artifact.recheck_checkpoint_raw_sha256:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_CHECKPOINT_HASH_MISMATCH",
                "recheck checkpoint exact bytes do not match the artifact",
            )
        try:
            checkpoint = DeploymentOnlineRecheckCheckpointDTO.model_validate_json(
                checkpoint_raw
            )
        except Exception as exc:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_CHECKPOINT_INVALID",
                "recheck checkpoint is invalid",
            ) from exc
        if checkpoint.original_checkpoint_raw_sha256 != (
            artifact.original_checkpoint_raw_sha256
        ):
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_BINDING_MISMATCH",
                "recheck checkpoint does not match the original checkpoint",
            )
        receipt = self._read_receipt(
            state.get("active_receipt_id"),
            expected_raw_sha256=state.get("active_receipt_raw_sha256"),
        )
        receipt_raw = self._read_secure_file(self._receipt_path(receipt.receipt_id))
        original = self._load_online_checkpoint_for_receipt(
            receipt.receipt_id,
            expected_raw_sha256=state.get("active_receipt_raw_sha256"),
        )
        if original is None:
            raise DeploymentDrainError(
                "DEPLOYMENT_RECHECK_CHECKPOINT_REQUIRED",
                "active online recheck requires an A2 checkpoint",
            )
        original_raw = self._read_secure_file(
            self._checkpoint_path(receipt.snapshot.checkpoint_sha256)
        )
        artifact_raw = self._read_secure_file(
            self._online_recheck_path(receipt.receipt_id)
        )
        try:
            verify_safe_restart_online_recheck(
                artifact_raw=artifact_raw,
                receipt_raw=receipt_raw,
                original_checkpoint_raw=original_raw,
                recheck_checkpoint_raw=checkpoint_raw,
            )
        except DeploymentOnlineRecheckError as exc:
            raise DeploymentDrainError(
                "SAFE_RESTART_RECHECK_CHAIN_INVALID",
                "online recheck exact-byte chain is invalid",
            ) from exc

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

    def _online_recheck_path(self, receipt_id: str | None) -> Path:
        if (
            not receipt_id
            or not receipt_id.startswith("safe-restart-")
            or "/" in receipt_id
        ):
            raise DeploymentDrainError(
                "SAFE_RESTART_RECEIPT_ID_INVALID", "invalid receipt id"
            )
        return self.recheck_dir / f"{receipt_id}.online-recheck.json"

    def _checkpoint_path(self, checkpoint_sha256: str) -> Path:
        if (
            len(checkpoint_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in checkpoint_sha256
            )
            or not checkpoint_sha256.strip("0")
        ):
            raise DeploymentDrainError(
                "DEPLOYMENT_CHECKPOINT_ID_INVALID",
                "invalid online checkpoint sha256",
            )
        return self.checkpoint_dir / f"checkpoint-{checkpoint_sha256}.json"

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


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and value.strip("0")
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_prefixed_sha256(value: object, prefix: str) -> bool:
    return bool(
        isinstance(value, str)
        and value.startswith(prefix)
        and _is_sha256(value.removeprefix(prefix))
    )


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
