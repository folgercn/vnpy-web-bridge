from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

MAX_SAFE_RESTART_TTL = timedelta(seconds=300)


def _nonzero_hex(value: str) -> str:
    if not value.strip("0"):
        raise ValueError("zero identity is forbidden")
    return value


Sha256 = Annotated[
    str, Field(pattern=r"^[0-9a-f]{64}$"), AfterValidator(_nonzero_hex)
]
CommitSha = Annotated[
    str, Field(pattern=r"^[0-9a-f]{40}$"), AfterValidator(_nonzero_hex)
]
ImageDigest = Annotated[
    str,
    Field(pattern=r"^sha256:[0-9a-f]{64}$"),
    AfterValidator(lambda value: "sha256:" + _nonzero_hex(value[7:])),
]
Identifier = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
]
PlanId = Annotated[
    str,
    Field(pattern=r"^release-plan-[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_prefixed(value, "release-plan-")),
]
ReceiptId = Annotated[
    str,
    Field(pattern=r"^safe-restart-[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_prefixed(value, "safe-restart-")),
]
ConsumeId = Annotated[
    str,
    Field(pattern=r"^safe-restart-consume-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-consume-")
    ),
]
RecheckId = Annotated[
    str,
    Field(pattern=r"^deployment-recheck-[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_prefixed(value, "deployment-recheck-")),
]
OnlineRecheckId = Annotated[
    str,
    Field(pattern=r"^safe-restart-online-recheck-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-online-recheck-")
    ),
]
Nonce = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9_-]{16,128}$"),
    AfterValidator(lambda value: value if value.strip("0") else _raise_zero_nonce()),
]


def _raise_zero_nonce() -> str:
    raise ValueError("zero nonce is forbidden")


def _nonzero_prefixed(value: str, prefix: str) -> str:
    _nonzero_hex(value.removeprefix(prefix))
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_order_status(value: object) -> str:
    raw = str(value or "").strip()
    return {
        "提交中": "submitting",
        "未成交": "not_traded",
        "部分成交": "part_traded",
        "全部成交": "all_traded",
        "已撤销": "cancelled",
        "拒单": "rejected",
    }.get(raw, raw.lower().replace(" ", "_").replace("-", "_"))


class StrictDeploymentDrainModel(BaseModel):
    """Semantic DTOs normalize UTC inputs; emitted artifact JSON is canonical Z."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
    )


class DeploymentSafetySnapshotDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_deployment_safety_snapshot_v1"]
    captured_at: datetime
    execution_plan_status: str = Field(min_length=1, max_length=64)
    execution_plan_hash: Sha256 | None
    plan_version: int = Field(strict=True, ge=0)
    state_version: str = Field(min_length=1, max_length=128)
    state_sha256: Sha256
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    checkpoint_sha256: Sha256
    rpc_generation: int = Field(strict=True, ge=0)
    web_trade_enabled: bool
    execution_authority_revoked: bool
    auto_dispatch_stopped: bool
    active_orders: int = Field(strict=True, ge=0)
    unknown_outcome: bool
    reconcile_required: bool
    checkpoint_durable: bool

    @model_validator(mode="after")
    def validate_snapshot(self) -> DeploymentSafetySnapshotDTO:
        _require_utc(self.captured_at, "captured_at")
        return self


class DeploymentRpcFactsDTO(StrictDeploymentDrainModel):
    schema_version: Literal["windows_rpc_deployment_safety_snapshot_v1"]
    request_id: Identifier
    challenge: Nonce
    server_instance_id: Identifier
    fact_generation: int = Field(strict=True, ge=0)
    captured_at: datetime
    execution_admission_frozen: Literal[True]
    pending_send_outcomes: int = Field(strict=True, ge=0)
    strategy_execution_enabled: Literal[False]
    account_hashes: list[Sha256]
    orders: list[dict[str, Any]]
    active_orders: list[dict[str, Any]]
    trades: list[dict[str, Any]]
    positions: list[dict[str, Any]]

    @model_validator(mode="after")
    def validate_facts(self) -> DeploymentRpcFactsDTO:
        _require_utc(self.captured_at, "rpc captured_at")
        _strict_canonical_sha256(self.model_dump(mode="json"))
        if self.account_hashes != sorted(set(self.account_hashes)):
            raise ValueError("account hashes must be unique and sorted")
        for name in ("orders", "active_orders", "trades", "positions"):
            rows = getattr(self, name)
            canonical = [
                json.dumps(
                    row,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for row in rows
            ]
            if canonical != sorted(canonical):
                raise ValueError(f"{name} must be canonically sorted")
            if len(canonical) != len(set(canonical)):
                raise ValueError(f"{name} must not contain duplicate facts")
        order_facts = {
            json.dumps(
                row,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for row in self.orders
        }
        active_facts = {
            json.dumps(
                row,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for row in self.active_orders
        }
        active_statuses = {
            "submitting",
            "submitting_order",
            "not_traded",
            "part_traded",
        }
        for row in self.active_orders:
            encoded = json.dumps(
                row,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if encoded not in order_facts:
                raise ValueError("active order is missing from all orders")
            if _normalize_order_status(row.get("status")) not in active_statuses:
                raise ValueError("active order has a non-active status")
        for row in self.orders:
            if _normalize_order_status(row.get("status")) in active_statuses:
                encoded = json.dumps(
                    row,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if encoded not in active_facts:
                    raise ValueError("active all-order is missing from active orders")
        return self


def deployment_rpc_execution_facts_sha256(
    facts: DeploymentRpcFactsDTO,
) -> str:
    """Hash only normalized execution facts, excluding request metadata."""

    return _strict_canonical_sha256(
        {
            "execution_admission_frozen": (facts.execution_admission_frozen),
            "pending_send_outcomes": facts.pending_send_outcomes,
            "strategy_execution_enabled": facts.strategy_execution_enabled,
            "account_hashes": facts.account_hashes,
            "orders": facts.orders,
            "active_orders": facts.active_orders,
            "trades": facts.trades,
            "positions": facts.positions,
        }
    )


class DeploymentRpcRecheckFactsDTO(StrictDeploymentDrainModel):
    schema_version: Literal["windows_rpc_deployment_safety_recheck_v1"]
    request_id: Identifier
    owner_challenge: Nonce
    recheck_id: RecheckId
    fresh_challenge: Nonce
    original_server_instance_id: Identifier
    original_fact_generation: int = Field(strict=True, ge=0)
    original_execution_facts_canonical_sha256: Sha256
    server_instance_id: Identifier
    fact_generation: int = Field(strict=True, ge=0)
    execution_facts_canonical_sha256: Sha256
    captured_at: datetime
    execution_admission_frozen: Literal[True]
    pending_send_outcomes: int = Field(strict=True, ge=0)
    strategy_execution_enabled: Literal[False]
    account_hashes: list[Sha256]
    orders: list[dict[str, Any]]
    active_orders: list[dict[str, Any]]
    trades: list[dict[str, Any]]
    positions: list[dict[str, Any]]

    @model_validator(mode="after")
    def validate_recheck_facts(self) -> DeploymentRpcRecheckFactsDTO:
        if self.fresh_challenge == self.owner_challenge:
            raise ValueError("recheck challenge must be fresh")
        if self.fact_generation < self.original_fact_generation:
            raise ValueError("recheck RPC generation rolled back")
        facts = DeploymentRpcFactsDTO.model_validate(
            {
                "schema_version": ("windows_rpc_deployment_safety_snapshot_v1"),
                "request_id": self.request_id,
                "challenge": self.owner_challenge,
                "server_instance_id": self.server_instance_id,
                "fact_generation": self.fact_generation,
                "captured_at": self.captured_at,
                "execution_admission_frozen": (self.execution_admission_frozen),
                "pending_send_outcomes": self.pending_send_outcomes,
                "strategy_execution_enabled": (self.strategy_execution_enabled),
                "account_hashes": self.account_hashes,
                "orders": self.orders,
                "active_orders": self.active_orders,
                "trades": self.trades,
                "positions": self.positions,
            }
        )
        if self.execution_facts_canonical_sha256 != (
            deployment_rpc_execution_facts_sha256(facts)
        ):
            raise ValueError("recheck execution facts hash mismatch")
        return self


class DeploymentOnlineCheckpointDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_deployment_online_checkpoint_v1"]
    request_id: Identifier
    runtime_instance_id: Identifier
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    execution_plan_status: str = Field(min_length=1, max_length=64)
    execution_plan_hash: Sha256 | None
    plan_version: int = Field(strict=True, ge=0)
    state_version: Literal["web_bridge_deployment_online_checkpoint_v1"]
    state: dict[str, Any]
    state_sha256: Sha256
    rpc: DeploymentRpcFactsDTO
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    web_trade_enabled: bool
    execution_authority_revoked: bool
    auto_dispatch_stopped: bool
    active_orders: int = Field(strict=True, ge=0)
    unknown_outcome: bool
    reconcile_required: bool
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]

    @model_validator(mode="after")
    def validate_hash_bindings(self) -> DeploymentOnlineCheckpointDTO:
        if self.rpc.request_id != self.request_id:
            raise ValueError("checkpoint RPC request binding mismatch")
        if self.state_sha256 != _strict_canonical_sha256(self.state):
            raise ValueError("checkpoint state hash mismatch")
        if self.active_orders_snapshot_sha256 != _strict_canonical_sha256(
            self.rpc.active_orders
        ):
            raise ValueError("checkpoint active-orders hash mismatch")
        if self.positions_snapshot_sha256 != _strict_canonical_sha256(
            self.rpc.positions
        ):
            raise ValueError("checkpoint positions hash mismatch")
        if self.active_orders != len(self.rpc.active_orders):
            raise ValueError("checkpoint active-orders count mismatch")
        return self


class DeploymentOnlineRecheckCheckpointDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_deployment_online_recheck_checkpoint_v1"]
    checkpoint_role: Literal["RECHECK"]
    recheck_id: RecheckId
    original_checkpoint_raw_sha256: Sha256
    request_id: Identifier
    runtime_instance_id: Identifier
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    state_version: Literal["web_bridge_deployment_online_recheck_checkpoint_v1"]
    state: dict[str, Any]
    state_sha256: Sha256
    rpc: DeploymentRpcRecheckFactsDTO
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    captured_at: datetime
    deployment_authorized: Literal[False]
    one_shot_consume_allowed: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_hash_bindings(
        self,
    ) -> DeploymentOnlineRecheckCheckpointDTO:
        _require_utc(self.captured_at, "recheck checkpoint captured_at")
        if self.rpc.captured_at > self.captured_at:
            raise ValueError("recheck RPC cannot be captured after checkpoint")
        if self.rpc.request_id != self.request_id:
            raise ValueError("recheck checkpoint RPC request binding mismatch")
        if self.rpc.recheck_id != self.recheck_id:
            raise ValueError("recheck checkpoint id binding mismatch")
        if self.state_sha256 != _strict_canonical_sha256(self.state):
            raise ValueError("recheck checkpoint state hash mismatch")
        if self.active_orders_snapshot_sha256 != _strict_canonical_sha256(
            self.rpc.active_orders
        ):
            raise ValueError("recheck active-orders hash mismatch")
        if self.positions_snapshot_sha256 != _strict_canonical_sha256(
            self.rpc.positions
        ):
            raise ValueError("recheck positions hash mismatch")
        return self


class SafeRestartOnlineRecheckDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_safe_restart_online_recheck_v1"]
    purpose: Literal["record_non_authorizing_fresh_online_restart_recheck"]
    online_recheck_id: OnlineRecheckId
    recheck_core_sha256: Sha256
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    original_checkpoint_raw_sha256: Sha256
    recheck_checkpoint_raw_sha256: Sha256
    request_id: Identifier
    runtime_instance_id: Identifier
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    windows_server_instance_id: Identifier
    owner_challenge_sha256: Sha256
    fresh_challenge_sha256: Sha256
    original_rpc_generation: int = Field(strict=True, ge=0)
    recheck_rpc_generation: int = Field(strict=True, ge=0)
    original_execution_facts_canonical_sha256: Sha256
    recheck_execution_facts_canonical_sha256: Sha256
    original_state_sha256: Sha256
    recheck_state_sha256: Sha256
    original_active_orders_snapshot_sha256: Sha256
    recheck_active_orders_snapshot_sha256: Sha256
    original_positions_snapshot_sha256: Sha256
    recheck_positions_snapshot_sha256: Sha256
    checked_at: datetime
    semantic_safety_unchanged: Literal[True]
    one_shot_consume_allowed: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_recheck(self) -> SafeRestartOnlineRecheckDTO:
        _require_utc(self.checked_at, "online recheck checked_at")
        if self.recheck_rpc_generation != self.original_rpc_generation:
            raise ValueError("online recheck generation changed")
        if self.recheck_execution_facts_canonical_sha256 != (
            self.original_execution_facts_canonical_sha256
        ):
            raise ValueError("online recheck execution facts changed")
        if self.owner_challenge_sha256 == self.fresh_challenge_sha256:
            raise ValueError("online recheck challenge was not fresh")
        for original, rechecked in (
            (self.original_state_sha256, self.recheck_state_sha256),
            (
                self.original_active_orders_snapshot_sha256,
                self.recheck_active_orders_snapshot_sha256,
            ),
            (
                self.original_positions_snapshot_sha256,
                self.recheck_positions_snapshot_sha256,
            ),
        ):
            if original != rechecked:
                raise ValueError("online recheck safety hash changed")
        if self.recheck_checkpoint_raw_sha256 == (self.original_checkpoint_raw_sha256):
            raise ValueError("online recheck must use a fresh checkpoint")
        core = self.model_dump(mode="json")
        core.pop("online_recheck_id")
        core.pop("recheck_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.recheck_core_sha256 != expected:
            raise ValueError("online recheck core hash mismatch")
        if self.online_recheck_id != (f"safe-restart-online-recheck-{expected}"):
            raise ValueError("online recheck id does not match core hash")
        return self


class DeploymentDrainAcquireDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_deployment_drain_acquire_v1"]
    request_id: Identifier
    deployment_attempt_id: Identifier
    release_plan_id: PlanId
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    issuer_source_commit_sha: CommitSha
    issuer_image_digest: ImageDigest
    issuer_config_sha256: Sha256
    issuer_runtime_instance_id: Identifier
    target_source_commit_sha: CommitSha
    target_image_digest: ImageDigest
    target_config_sha256: Sha256
    rollback_image_digest: ImageDigest
    rollback_config_sha256: Sha256
    nonce: Nonce
    ttl_seconds: int = Field(strict=True, ge=1, le=300)
    operator: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=512)


class SafeRestartReceiptDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_safe_restart_receipt_v1"]
    purpose: Literal["authorize_one_bound_web_bridge_restart_attempt"]
    receipt_id: ReceiptId
    receipt_core_sha256: Sha256
    request_id: Identifier
    deployment_attempt_id: Identifier
    release_plan_id: PlanId
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    unit: Literal["web-bridge"]
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int = Field(strict=True, ge=1, le=300)
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    issuer_source_commit_sha: CommitSha
    issuer_image_digest: ImageDigest
    issuer_config_sha256: Sha256
    issuer_runtime_instance_id: Identifier
    target_source_commit_sha: CommitSha
    target_image_digest: ImageDigest
    target_config_sha256: Sha256
    rollback_image_digest: ImageDigest
    rollback_config_sha256: Sha256
    nonce: Nonce
    snapshot: DeploymentSafetySnapshotDTO
    safe_to_restart: Literal[True]
    one_shot: Literal[True]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]

    @model_validator(mode="after")
    def validate_window(self) -> SafeRestartReceiptDTO:
        _require_utc(self.issued_at, "issued_at")
        _require_utc(self.expires_at, "expires_at")
        if self.expires_at - self.issued_at != timedelta(
            seconds=self.ttl_seconds
        ):
            raise ValueError("receipt TTL does not match its time window")
        if self.expires_at - self.issued_at > MAX_SAFE_RESTART_TTL:
            raise ValueError("safe restart receipt lifetime exceeds 300 seconds")
        if self.snapshot.captured_at > self.issued_at:
            raise ValueError("receipt snapshot cannot be captured after issue")
        if deployment_snapshot_blockers(self.snapshot):
            raise ValueError("receipt contains an unsafe deployment snapshot")
        core = self.model_dump(mode="json")
        core.pop("receipt_id")
        core.pop("receipt_core_sha256")
        expected = _canonical_sha256(core)
        if self.receipt_core_sha256 != expected:
            raise ValueError("receipt core hash mismatch")
        if self.receipt_id != f"safe-restart-{expected}":
            raise ValueError("receipt id does not match core hash")
        return self


class SafeRestartRecheckDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_safe_restart_recheck_v1"]
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    checked_at: datetime
    snapshot: DeploymentSafetySnapshotDTO

    @model_validator(mode="after")
    def validate_checked_at(self) -> SafeRestartRecheckDTO:
        _require_utc(self.checked_at, "checked_at")
        if self.snapshot.captured_at > self.checked_at:
            raise ValueError("recheck snapshot cannot be captured after check")
        return self


class SafeRestartConsumeMarkerDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_safe_restart_consume_v1"]
    purpose: Literal["consume_safe_restart_receipt_once"]
    consume_id: ConsumeId
    consume_core_sha256: Sha256
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    receipt_core_sha256: Sha256
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    consumed_at: datetime
    consumer_run_id: Identifier
    operator: str = Field(min_length=1, max_length=128)
    recheck_canonical_sha256: Sha256
    one_shot_consumed: Literal[True]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]

    @model_validator(mode="after")
    def validate_consumed_at(self) -> SafeRestartConsumeMarkerDTO:
        _require_utc(self.consumed_at, "consumed_at")
        core = self.model_dump(mode="json")
        core.pop("consume_id")
        core.pop("consume_core_sha256")
        expected = _canonical_sha256(core)
        if self.consume_core_sha256 != expected:
            raise ValueError("consume marker core hash mismatch")
        if self.consume_id != f"safe-restart-consume-{expected}":
            raise ValueError("consume id does not match core hash")
        return self


def _require_utc(value: datetime, name: str) -> None:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError(f"{name} must be UTC")


def deployment_snapshot_blockers(
    snapshot: DeploymentSafetySnapshotDTO,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if snapshot.execution_plan_status != "IDLE":
        blockers.append("execution_plan_not_idle")
    if snapshot.execution_plan_hash is not None:
        blockers.append("active_execution_plan_hash")
    if snapshot.web_trade_enabled:
        blockers.append("web_trade_enabled")
    if not snapshot.execution_authority_revoked:
        blockers.append("execution_authority_not_revoked")
    if not snapshot.auto_dispatch_stopped:
        blockers.append("auto_dispatch_not_stopped")
    if snapshot.active_orders:
        blockers.append("active_orders")
    if snapshot.unknown_outcome:
        blockers.append("unknown_outcome")
    if snapshot.reconcile_required:
        blockers.append("reconcile_required")
    if not snapshot.checkpoint_durable:
        blockers.append("checkpoint_not_durable")
    return tuple(blockers)
