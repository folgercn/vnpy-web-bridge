from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)

MAX_SAFE_RESTART_TTL = timedelta(seconds=300)


def _nonzero_hex(value: str) -> str:
    if not value.strip("0"):
        raise ValueError("zero identity is forbidden")
    return value


Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$"), AfterValidator(_nonzero_hex)]
CommitSha = Annotated[
    str, Field(pattern=r"^[0-9a-f]{40}$"), AfterValidator(_nonzero_hex)
]
ImageDigest = Annotated[
    str,
    Field(pattern=r"^sha256:[0-9a-f]{64}$"),
    AfterValidator(lambda value: "sha256:" + _nonzero_hex(value[7:])),
]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")]
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
    AfterValidator(lambda value: _nonzero_prefixed(value, "safe-restart-consume-")),
]
ConsumeIntentId = Annotated[
    str,
    Field(pattern=r"^safe-restart-consume-intent-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-consume-intent-")
    ),
]
ConsumeMarkerId = Annotated[
    str,
    Field(pattern=r"^safe-restart-consume-marker-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-consume-marker-")
    ),
]
RecheckId = Annotated[
    str,
    Field(pattern=r"^deployment-recheck-[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_prefixed(value, "deployment-recheck-")),
]
PostRestartCheckpointId = Annotated[
    str,
    Field(pattern=r"^deployment-post-restart-checkpoint-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "deployment-post-restart-checkpoint-")
    ),
]
ReconciliationEvidenceId = Annotated[
    str,
    Field(pattern=r"^safe-restart-reconciliation-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-reconciliation-")
    ),
]
InitialBaselineCheckpointId = Annotated[
    str,
    Field(pattern=r"^deployment-initial-baseline-checkpoint-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "deployment-initial-baseline-checkpoint-"
        )
    ),
]
InitialBaselineCommodityCheckpointId = Annotated[
    str,
    Field(
        pattern=r"^deployment-initial-baseline-commodity-checkpoint-[0-9a-f]{64}$"
    ),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "deployment-initial-baseline-commodity-checkpoint-"
        )
    ),
]
InitialBaselineEvidenceId = Annotated[
    str,
    Field(pattern=r"^initial-baseline-reconciliation-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "initial-baseline-reconciliation-")
    ),
]
LegacyMigrationInventoryId = Annotated[
    str,
    Field(pattern=r"^legacy-migration-empty-inventory-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "legacy-migration-empty-inventory-"
        )
    ),
]
LegacyMigrationCommodityCheckpointId = Annotated[
    str,
    Field(
        pattern=(
            r"^deployment-legacy-migration-commodity-checkpoint-[0-9a-f]{64}$"
        )
    ),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "deployment-legacy-migration-commodity-checkpoint-"
        )
    ),
]
LegacyMigrationCheckpointId = Annotated[
    str,
    Field(pattern=r"^deployment-legacy-migration-checkpoint-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "deployment-legacy-migration-checkpoint-"
        )
    ),
]
LegacyMigrationEvidenceId = Annotated[
    str,
    Field(pattern=r"^legacy-migration-reconciliation-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(
            value, "legacy-migration-reconciliation-"
        )
    ),
]
OnlineRecheckId = Annotated[
    str,
    Field(pattern=r"^safe-restart-online-recheck-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "safe-restart-online-recheck-")
    ),
]
StateCommitmentId = Annotated[
    str,
    Field(pattern=r"^deployment-drain-state-commitment-[0-9a-f]{64}$"),
    AfterValidator(
        lambda value: _nonzero_prefixed(value, "deployment-drain-state-commitment-")
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


class DeploymentDrainStateCommitmentDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_deployment_drain_state_commitment_v1"]
    purpose: Literal["commit_exact_non_authorizing_deployment_drain_state"]
    commitment_id: StateCommitmentId
    state_commitment_core_sha256: Sha256
    state_generation: int = Field(strict=True, ge=1)
    previous_state_commitment_raw_sha256: Sha256 | None
    state_raw_sha256: Sha256
    state: dict[str, Any]
    created_at: datetime
    genesis_source: Literal["fresh_bootstrap", "v1_migration", "v2_migration"] | None
    source_state_raw_sha256: Sha256 | None
    source_epoch_anchor_raw_sha256: Sha256 | None
    deployment_authorized: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    countable_forward: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]

    @model_validator(mode="after")
    def validate_commitment(self) -> DeploymentDrainStateCommitmentDTO:
        _require_utc(self.created_at, "state commitment created_at")
        if self.state.get("schema_version") != ("web_bridge_deployment_drain_state_v3"):
            raise ValueError("committed deployment drain state must be v3")
        if self.state.get("state_generation") != self.state_generation:
            raise ValueError("state commitment generation binding mismatch")
        if self.state.get("previous_state_commitment_raw_sha256") != (
            self.previous_state_commitment_raw_sha256
        ):
            raise ValueError("state commitment previous-link binding mismatch")
        state_updated_at = self.state.get("updated_at")
        if not isinstance(state_updated_at, str):
            raise ValueError("committed state updated_at must be a timestamp")
        try:
            parsed_updated_at = datetime.fromisoformat(
                state_updated_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("committed state updated_at is invalid") from exc
        _require_utc(parsed_updated_at, "committed state updated_at")
        if parsed_updated_at != self.created_at:
            raise ValueError("state commitment created_at binding mismatch")

        state_raw = (
            json.dumps(
                self.state,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if self.state_raw_sha256 != hashlib.sha256(state_raw).hexdigest():
            raise ValueError("committed state raw hash mismatch")

        if self.previous_state_commitment_raw_sha256 is None:
            if self.state_generation != 1 or self.genesis_source is None:
                raise ValueError("genesis commitment metadata is incomplete")
            if self.genesis_source == "fresh_bootstrap":
                if (
                    self.source_state_raw_sha256 is not None
                    or self.source_epoch_anchor_raw_sha256 is not None
                ):
                    raise ValueError("fresh bootstrap cannot name migration sources")
            elif (
                self.source_state_raw_sha256 is None
                or self.source_epoch_anchor_raw_sha256 is None
            ):
                raise ValueError("migration genesis must bind both source files")
        elif (
            self.state_generation == 1
            or self.genesis_source is not None
            or self.source_state_raw_sha256 is not None
            or self.source_epoch_anchor_raw_sha256 is not None
        ):
            raise ValueError("non-genesis commitment cannot carry genesis metadata")

        core = self.model_dump(mode="json")
        core.pop("commitment_id")
        core.pop("state_commitment_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.state_commitment_core_sha256 != expected:
            raise ValueError("state commitment core hash mismatch")
        if self.commitment_id != (f"deployment-drain-state-commitment-{expected}"):
            raise ValueError("state commitment id does not match core hash")
        return self


class SafeRestartConsumeStateProjectionDTO(StrictDeploymentDrainModel):
    schema_version: Literal["web_bridge_safe_restart_consume_state_projection_v1"]
    state: Literal["SAFE_TO_RESTART"]
    receipt_consumed: Literal[True]
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    online_recheck_id: OnlineRecheckId
    online_recheck_raw_sha256: Sha256
    preconsume_state_commitment_raw_sha256: Sha256
    preconsume_state_generation: int = Field(strict=True, ge=1)
    runtime_instance_id: Identifier
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    consumer_run_id: Identifier
    operator: str = Field(min_length=1, max_length=128)
    planned_consumed_at: datetime
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_projection(self) -> SafeRestartConsumeStateProjectionDTO:
        _require_utc(
            self.planned_consumed_at,
            "consume state projection planned_consumed_at",
        )
        return self


def _require_consume_projection_bindings(
    owner: object,
    projection: SafeRestartConsumeStateProjectionDTO,
) -> None:
    for field in (
        "receipt_id",
        "receipt_raw_sha256",
        "online_recheck_id",
        "online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
        "preconsume_state_generation",
        "runtime_instance_id",
        "drain_epoch",
        "execution_epoch",
        "consumer_run_id",
        "operator",
    ):
        if getattr(owner, field) != getattr(projection, field):
            raise ValueError("consume state projection outer binding mismatch")


class SafeRestartConsumeIntentDTO(StrictDeploymentDrainModel):
    """Durable WAL prepare record; it grants no restart authority."""

    schema_version: Literal["web_bridge_safe_restart_consume_intent_v1"]
    purpose: Literal["prepare_one_shot_safe_restart_consumption"]
    consume_intent_id: ConsumeIntentId
    consume_intent_core_sha256: Sha256
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    receipt_core_sha256: Sha256
    online_recheck_id: OnlineRecheckId
    online_recheck_raw_sha256: Sha256
    online_recheck_core_sha256: Sha256
    preconsume_state_commitment_id: StateCommitmentId
    preconsume_state_commitment_raw_sha256: Sha256
    preconsume_state_generation: int = Field(strict=True, ge=1)
    consume_state_projection: SafeRestartConsumeStateProjectionDTO
    consume_state_projection_sha256: Sha256
    request_id: Identifier
    runtime_instance_id: Identifier
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    prepared_at: datetime
    consume_not_after: datetime
    consumer_run_id: Identifier
    operator: str = Field(min_length=1, max_length=128)
    consume_intent_prepared: Literal[True]
    one_shot_consume_committed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_intent(self) -> SafeRestartConsumeIntentDTO:
        _require_utc(self.prepared_at, "consume intent prepared_at")
        _require_utc(self.consume_not_after, "consume intent consume_not_after")
        if self.prepared_at > self.consume_not_after:
            raise ValueError("consume intent window ends before it is prepared")
        if not (
            self.prepared_at
            <= self.consume_state_projection.planned_consumed_at
            <= self.consume_not_after
        ):
            raise ValueError("consume state projection falls outside intent window")
        _require_consume_projection_bindings(self, self.consume_state_projection)
        if self.consume_state_projection_sha256 != _strict_canonical_sha256(
            self.consume_state_projection.model_dump(mode="json")
        ):
            raise ValueError("consume intent state projection hash mismatch")
        core = self.model_dump(mode="json")
        core.pop("consume_intent_id")
        core.pop("consume_intent_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.consume_intent_core_sha256 != expected:
            raise ValueError("consume intent core hash mismatch")
        if self.consume_intent_id != f"safe-restart-consume-intent-{expected}":
            raise ValueError("consume intent id does not match core hash")
        return self


class SafeRestartConsumeCommitMarkerDTO(StrictDeploymentDrainModel):
    """Irreversible one-shot commit marker; it does not start a restart."""

    schema_version: Literal["web_bridge_safe_restart_consume_marker_v1"]
    purpose: Literal["commit_one_shot_safe_restart_consumption"]
    consume_marker_id: ConsumeMarkerId
    consume_marker_core_sha256: Sha256
    consume_intent_id: ConsumeIntentId
    consume_intent_raw_sha256: Sha256
    consume_intent_core_sha256: Sha256
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    receipt_core_sha256: Sha256
    online_recheck_id: OnlineRecheckId
    online_recheck_raw_sha256: Sha256
    online_recheck_core_sha256: Sha256
    preconsume_state_commitment_id: StateCommitmentId
    preconsume_state_commitment_raw_sha256: Sha256
    preconsume_state_generation: int = Field(strict=True, ge=1)
    consume_state_projection: SafeRestartConsumeStateProjectionDTO
    consume_state_projection_sha256: Sha256
    request_id: Identifier
    runtime_instance_id: Identifier
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=1)
    execution_epoch: int = Field(strict=True, ge=1)
    committed_at: datetime
    consume_not_after: datetime
    consumer_run_id: Identifier
    operator: str = Field(min_length=1, max_length=128)
    one_shot_consume_committed: Literal[True]
    restart_execution_started: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_marker(self) -> SafeRestartConsumeCommitMarkerDTO:
        _require_utc(self.committed_at, "consume marker committed_at")
        _require_utc(self.consume_not_after, "consume marker consume_not_after")
        if self.committed_at > self.consume_not_after:
            raise ValueError("consume marker was committed after its deadline")
        if self.committed_at < self.consume_state_projection.planned_consumed_at:
            raise ValueError("consume marker precedes its prepared state projection")
        _require_consume_projection_bindings(self, self.consume_state_projection)
        if self.consume_state_projection_sha256 != _strict_canonical_sha256(
            self.consume_state_projection.model_dump(mode="json")
        ):
            raise ValueError("consume marker state projection hash mismatch")
        core = self.model_dump(mode="json")
        core.pop("consume_marker_id")
        core.pop("consume_marker_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.consume_marker_core_sha256 != expected:
            raise ValueError("consume marker core hash mismatch")
        if self.consume_marker_id != f"safe-restart-consume-marker-{expected}":
            raise ValueError("consume marker id does not match core hash")
        return self


class DeploymentPostRestartCheckpointDTO(StrictDeploymentDrainModel):
    """Non-authorizing C1a checkpoint captured by the restarted process."""

    schema_version: Literal["web_bridge_deployment_post_restart_checkpoint_v1"]
    purpose: Literal["record_non_authorizing_planned_restart_reconciliation_checkpoint"]
    mode: Literal["PLANNED_RESTART"]
    reconciliation_run_id: Identifier
    checkpoint_id: PostRestartCheckpointId
    checkpoint_core_sha256: Sha256
    consume_intent_id: ConsumeIntentId
    consume_intent_raw_sha256: Sha256
    consume_intent_core_sha256: Sha256
    consume_marker_id: ConsumeMarkerId
    consume_marker_raw_sha256: Sha256
    consume_marker_core_sha256: Sha256
    receipt_id: ReceiptId
    receipt_raw_sha256: Sha256
    receipt_core_sha256: Sha256
    online_recheck_id: OnlineRecheckId
    online_recheck_raw_sha256: Sha256
    online_recheck_core_sha256: Sha256
    request_id: Identifier
    deployment_attempt_id: Identifier
    release_plan_core_sha256: Sha256
    restart_action_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=1)
    previous_runtime_instance_id: Identifier
    previous_execution_epoch: int = Field(strict=True, ge=1)
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=2)
    consumed_windows_server_instance_id: Identifier
    consumed_owner_challenge_sha256: Sha256
    consumed_recheck_id: RecheckId
    consumed_fresh_challenge_sha256: Sha256
    consumed_rpc_generation: int = Field(strict=True, ge=0)
    consumed_execution_facts_canonical_sha256: Sha256
    consumed_execution_state_sha256: Sha256
    consumed_active_orders_snapshot_sha256: Sha256
    consumed_positions_snapshot_sha256: Sha256
    current_state_commitment_id: StateCommitmentId
    current_state_commitment_raw_sha256: Sha256
    current_epoch_anchor_raw_sha256: Sha256
    current_state_generation: int = Field(strict=True, ge=1)
    current_drain_state: dict[str, Any]
    current_drain_state_raw_sha256: Sha256
    post_restart_recheck_id: RecheckId
    post_restart_fresh_challenge_sha256: Sha256
    windows_rpc: DeploymentRpcRecheckFactsDTO
    current_active_orders_snapshot_sha256: Sha256
    current_positions_snapshot_sha256: Sha256
    captured_at: datetime
    windows_execution_admission_frozen: Literal[True]
    semantic_safety_unchanged: Literal[True]
    target_runtime_verified: Literal[False]
    execution_facts_reconciliation_completed: Literal[True]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_checkpoint(self) -> DeploymentPostRestartCheckpointDTO:
        _require_utc(self.captured_at, "post-restart checkpoint captured_at")
        if self.windows_rpc.captured_at > self.captured_at:
            raise ValueError("Windows recheck cannot follow checkpoint capture")
        if self.current_runtime_instance_id == self.previous_runtime_instance_id:
            raise ValueError("planned restart must use a new runtime instance")
        if self.current_execution_epoch <= self.previous_execution_epoch:
            raise ValueError("planned restart must advance the execution epoch")
        if self.captured_at - self.windows_rpc.captured_at > timedelta(seconds=30):
            raise ValueError("post-restart Windows recheck is stale")
        if (
            self.windows_rpc.request_id != self.request_id
            or self.windows_rpc.recheck_id != self.post_restart_recheck_id
            or hashlib.sha256(
                self.windows_rpc.owner_challenge.encode("utf-8")
            ).hexdigest()
            != self.consumed_owner_challenge_sha256
            or hashlib.sha256(
                self.windows_rpc.fresh_challenge.encode("utf-8")
            ).hexdigest()
            != self.post_restart_fresh_challenge_sha256
            or self.windows_rpc.server_instance_id
            != self.consumed_windows_server_instance_id
            or self.windows_rpc.original_server_instance_id
            != self.consumed_windows_server_instance_id
            or self.windows_rpc.fact_generation != self.consumed_rpc_generation
            or self.windows_rpc.original_fact_generation != self.consumed_rpc_generation
            or self.windows_rpc.execution_facts_canonical_sha256
            != self.consumed_execution_facts_canonical_sha256
            or self.windows_rpc.original_execution_facts_canonical_sha256
            != self.consumed_execution_facts_canonical_sha256
        ):
            raise ValueError("post-restart Windows facts changed")
        if (
            self.post_restart_recheck_id == self.consumed_recheck_id
            or self.post_restart_fresh_challenge_sha256
            == self.consumed_fresh_challenge_sha256
        ):
            raise ValueError("post-restart Windows recheck was replayed")
        if self.windows_rpc.pending_send_outcomes != 0:
            raise ValueError("post-restart checkpoint has pending send outcomes")
        if self.windows_rpc.active_orders:
            raise ValueError("post-restart checkpoint has active orders")
        current_state_raw = (
            json.dumps(
                self.current_drain_state,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if (
            self.current_drain_state_raw_sha256
            != hashlib.sha256(current_state_raw).hexdigest()
        ):
            raise ValueError("post-restart drain state raw hash mismatch")
        if self.current_drain_state.get("state_generation") != (
            self.current_state_generation
        ):
            raise ValueError("post-restart drain state generation mismatch")
        if self.current_active_orders_snapshot_sha256 != (
            _strict_canonical_sha256(self.windows_rpc.active_orders)
        ) or self.current_active_orders_snapshot_sha256 != (
            self.consumed_active_orders_snapshot_sha256
        ):
            raise ValueError("post-restart active-order facts changed")
        if self.current_positions_snapshot_sha256 != _strict_canonical_sha256(
            self.windows_rpc.positions
        ) or self.current_positions_snapshot_sha256 != (
            self.consumed_positions_snapshot_sha256
        ):
            raise ValueError("post-restart position facts changed")
        core = self.model_dump(mode="json")
        core.pop("checkpoint_id")
        core.pop("checkpoint_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.checkpoint_core_sha256 != expected:
            raise ValueError("post-restart checkpoint core hash mismatch")
        if self.checkpoint_id != (f"deployment-post-restart-checkpoint-{expected}"):
            raise ValueError("post-restart checkpoint id does not match core hash")
        return self


class SafeRestartReconciliationEvidenceDTO(StrictDeploymentDrainModel):
    """C1a evidence only; it neither verifies the target image nor unfreezes."""

    schema_version: Literal["web_bridge_safe_restart_reconciliation_v1"]
    purpose: Literal["record_non_authorizing_planned_restart_reconciliation_evidence"]
    mode: Literal["PLANNED_RESTART"]
    reconciliation_id: ReconciliationEvidenceId
    reconciliation_core_sha256: Sha256
    checkpoint_id: PostRestartCheckpointId
    checkpoint_raw_sha256: Sha256
    checkpoint_core_sha256: Sha256
    consume_intent_id: ConsumeIntentId
    consume_intent_raw_sha256: Sha256
    consume_marker_id: ConsumeMarkerId
    consume_marker_raw_sha256: Sha256
    receipt_id: ReceiptId
    online_recheck_id: OnlineRecheckId
    online_recheck_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=2)
    reconciled_at: datetime
    post_restart_reconciliation_verified: Literal[True]
    windows_execution_admission_frozen: Literal[True]
    target_runtime_verified: Literal[False]
    execution_facts_reconciliation_completed: Literal[True]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_evidence(self) -> SafeRestartReconciliationEvidenceDTO:
        _require_utc(self.reconciled_at, "restart reconciliation reconciled_at")
        core = self.model_dump(mode="json")
        core.pop("reconciliation_id")
        core.pop("reconciliation_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.reconciliation_core_sha256 != expected:
            raise ValueError("restart reconciliation core hash mismatch")
        if self.reconciliation_id != f"safe-restart-reconciliation-{expected}":
            raise ValueError("restart reconciliation id does not match core hash")
        return self


class CommodityInitialBaselineStateDTO(StrictDeploymentDrainModel):
    """Exact safe projection captured from durable Commodity owner state."""

    schema_version: Literal["web_bridge_initial_baseline_commodity_state_v1"]
    commodity_state_version: Literal["commodity-simnow-v1"]
    commodity_state_checkpoint_sha256: Sha256
    execution_plan_status: Literal["IDLE"]
    execution_plan_hash: Literal[None]
    plan_version: Literal[0]
    web_trade_enabled: Literal[False]
    execution_authority_revoked: Literal[True]
    auto_dispatch_stopped: Literal[True]
    unknown_outcome: Literal[False]
    reconcile_required: Literal[False]
    rpc_generation: int = Field(strict=True, ge=0)
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256


class DeploymentInitialBaselineCommodityCheckpointDTO(StrictDeploymentDrainModel):
    """Exact Commodity owner projection for the first frozen execution baseline."""

    schema_version: Literal[
        "web_bridge_deployment_initial_baseline_commodity_checkpoint_v1"
    ]
    purpose: Literal["record_exact_non_authorizing_commodity_initial_baseline"]
    mode: Literal["INITIAL_BASELINE"]
    reconciliation_run_id: Identifier
    checkpoint_id: InitialBaselineCommodityCheckpointId
    checkpoint_core_sha256: Sha256
    genesis_commitment_raw_sha256: Sha256
    current_state_commitment_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=2)
    captured_at: datetime
    execution_plan_status: Literal["IDLE"]
    execution_plan_hash: Literal[None]
    plan_version: Literal[0]
    state_version: Literal["web_bridge_initial_baseline_commodity_state_v1"]
    state: CommodityInitialBaselineStateDTO
    state_sha256: Sha256
    initial_rpc: DeploymentRpcFactsDTO
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    web_trade_enabled: Literal[False]
    execution_authority_revoked: Literal[True]
    auto_dispatch_stopped: Literal[True]
    active_orders: Literal[0]
    unknown_outcome: Literal[False]
    reconcile_required: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_checkpoint(
        self,
    ) -> DeploymentInitialBaselineCommodityCheckpointDTO:
        _require_utc(self.captured_at, "initial Commodity checkpoint captured_at")
        if self.initial_rpc.captured_at > self.captured_at:
            raise ValueError("initial RPC cannot follow Commodity checkpoint")
        if self.initial_rpc.pending_send_outcomes or self.initial_rpc.active_orders:
            raise ValueError("initial Commodity checkpoint is not frozen and idle")
        if self.state_sha256 != _strict_canonical_sha256(
            self.state.model_dump(mode="json")
        ):
            raise ValueError("initial Commodity state hash mismatch")
        if self.active_orders_snapshot_sha256 != _strict_canonical_sha256(
            self.initial_rpc.active_orders
        ) or self.positions_snapshot_sha256 != _strict_canonical_sha256(
            self.initial_rpc.positions
        ):
            raise ValueError("initial Commodity execution snapshot hash mismatch")
        if (
            self.state.execution_plan_status != self.execution_plan_status
            or self.state.execution_plan_hash != self.execution_plan_hash
            or self.state.plan_version != self.plan_version
            or self.state.web_trade_enabled != self.web_trade_enabled
            or self.state.execution_authority_revoked
            != self.execution_authority_revoked
            or self.state.auto_dispatch_stopped != self.auto_dispatch_stopped
            or self.state.unknown_outcome != self.unknown_outcome
            or self.state.reconcile_required != self.reconcile_required
            or self.state.rpc_generation != self.initial_rpc.fact_generation
            or self.state.active_orders_snapshot_sha256
            != self.active_orders_snapshot_sha256
            or self.state.positions_snapshot_sha256
            != self.positions_snapshot_sha256
        ):
            raise ValueError("initial Commodity state projection mismatch")
        core = self.model_dump(mode="json")
        core.pop("checkpoint_id")
        core.pop("checkpoint_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.checkpoint_core_sha256 != expected or self.checkpoint_id != (
            f"deployment-initial-baseline-commodity-checkpoint-{expected}"
        ):
            raise ValueError("initial Commodity checkpoint identity mismatch")
        return self


class DeploymentInitialBaselineDrainStateDTO(StrictDeploymentDrainModel):
    """Exact pristine frozen state accepted by the C1b checkpoint DTO."""

    schema_version: Literal["web_bridge_deployment_drain_state_v3"]
    state_generation: int = Field(strict=True, ge=3)
    previous_state_commitment_raw_sha256: Sha256
    state: Literal["RESTARTED_FROZEN"]
    drain_epoch: Literal[0]
    execution_epoch: int = Field(strict=True, ge=2)
    runtime_instance_id: Identifier
    active_request_id: Literal[None]
    active_request_sha256: Literal[None]
    active_receipt_id: Literal[None]
    active_receipt_raw_sha256: Literal[None]
    receipt_consumed: Literal[False]
    consumed_at: Literal[None]
    consume_id: Literal[None]
    consumed_receipt_id: Literal[None]
    consume_intent_raw_sha256: Literal[None]
    consume_marker_raw_sha256: Literal[None]
    consume_state_projection_sha256: Literal[None]
    consumed_online_recheck_id: Literal[None]
    consumed_online_recheck_raw_sha256: Literal[None]
    preconsume_state_commitment_raw_sha256: Literal[None]
    active_online_recheck_id: Literal[None]
    active_online_recheck_raw_sha256: Literal[None]
    active_recheck_checkpoint_raw_sha256: Literal[None]
    online_rechecked_at: Literal[None]
    last_invalidated_online_recheck_id: Literal[None]
    last_invalidated_receipt_id: Literal[None]
    blockers: list[str]
    expires_at: Literal[None]
    freeze_reason: Literal["initial_bootstrap_requires_reconciliation"]
    updated_at: datetime

    @field_serializer("updated_at", when_used="json")
    def serialize_updated_at(self, value: datetime) -> str:
        """Preserve the drain service's committed ``+00:00`` representation."""

        return value.isoformat()

    @model_validator(mode="after")
    def validate_state(self) -> DeploymentInitialBaselineDrainStateDTO:
        _require_utc(self.updated_at, "initial baseline drain state updated_at")
        if self.blockers:
            raise ValueError("initial baseline drain state blockers must be empty")
        return self


class DeploymentInitialBaselineCheckpointDTO(StrictDeploymentDrainModel):
    """Non-authorizing C1b checkpoint rooted in fresh bootstrap custody."""

    schema_version: Literal["web_bridge_deployment_initial_baseline_checkpoint_v1"]
    purpose: Literal["record_non_authorizing_fresh_initial_execution_baseline"]
    mode: Literal["INITIAL_BASELINE"]
    reconciliation_run_id: Identifier
    checkpoint_id: InitialBaselineCheckpointId
    checkpoint_core_sha256: Sha256
    genesis_commitment_id: StateCommitmentId
    genesis_commitment_raw_sha256: Sha256
    genesis_commitment_core_sha256: Sha256
    genesis_state_raw_sha256: Sha256
    current_state_commitment_id: StateCommitmentId
    current_state_commitment_raw_sha256: Sha256
    current_state_commitment_core_sha256: Sha256
    current_state_generation: int = Field(strict=True, ge=3)
    state_commitment_chain_sha256: Sha256
    current_epoch_anchor_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=2)
    current_drain_state: DeploymentInitialBaselineDrainStateDTO
    current_drain_state_raw_sha256: Sha256
    expected_account_hash: Sha256
    commodity_checkpoint_id: InitialBaselineCommodityCheckpointId
    commodity_checkpoint_raw_sha256: Sha256
    commodity_checkpoint_core_sha256: Sha256
    commodity_checkpoint: DeploymentInitialBaselineCommodityCheckpointDTO
    fresh_rpc: DeploymentRpcRecheckFactsDTO
    initial_execution_facts_canonical_sha256: Sha256
    fresh_execution_facts_canonical_sha256: Sha256
    orders_snapshot_sha256: Sha256
    active_orders_snapshot_sha256: Sha256
    trades_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    captured_at: datetime
    fresh_genesis_lineage_verified: Literal[True]
    custody_inventory_verified: Literal[False]
    prior_execution_facts_available: Literal[False]
    comparison_to_prebootstrap_facts_performed: Literal[False]
    initial_execution_facts_baseline_recorded: Literal[True]
    execution_facts_reconciliation_completed: Literal[True]
    semantic_safety_unchanged: Literal[False]
    target_runtime_verified: Literal[False]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_checkpoint(self) -> DeploymentInitialBaselineCheckpointDTO:
        _require_utc(self.captured_at, "initial baseline checkpoint captured_at")
        if self.fresh_rpc.captured_at > self.captured_at:
            raise ValueError("fresh RPC capture cannot follow checkpoint capture")
        if (
            self.commodity_checkpoint.initial_rpc.request_id
            != self.fresh_rpc.request_id
            or self.commodity_checkpoint.initial_rpc.challenge
            != self.fresh_rpc.owner_challenge
            or self.commodity_checkpoint.initial_rpc.server_instance_id
            != self.fresh_rpc.original_server_instance_id
            or self.commodity_checkpoint.initial_rpc.fact_generation
            != self.fresh_rpc.original_fact_generation
            or self.initial_execution_facts_canonical_sha256
            != self.fresh_rpc.original_execution_facts_canonical_sha256
            or self.fresh_execution_facts_canonical_sha256
            != self.fresh_rpc.execution_facts_canonical_sha256
        ):
            raise ValueError("initial baseline RPC chain is not exact")
        if self.commodity_checkpoint.initial_rpc.account_hashes != [
            self.expected_account_hash
        ] or (
            self.fresh_rpc.account_hashes != [self.expected_account_hash]
        ):
            raise ValueError("initial baseline account scope changed")
        initial_execution_sha = deployment_rpc_execution_facts_sha256(
            self.commodity_checkpoint.initial_rpc
        )
        if (
            self.initial_execution_facts_canonical_sha256
            != initial_execution_sha
            or self.fresh_execution_facts_canonical_sha256
            != self.fresh_rpc.execution_facts_canonical_sha256
            or self.fresh_execution_facts_canonical_sha256
            != initial_execution_sha
            or self.commodity_checkpoint.initial_rpc.orders != self.fresh_rpc.orders
            or self.commodity_checkpoint.initial_rpc.active_orders
            != self.fresh_rpc.active_orders
            or self.commodity_checkpoint.initial_rpc.trades != self.fresh_rpc.trades
            or self.commodity_checkpoint.initial_rpc.positions
            != self.fresh_rpc.positions
            or self.orders_snapshot_sha256
            != _strict_canonical_sha256(self.fresh_rpc.orders)
            or self.active_orders_snapshot_sha256
            != _strict_canonical_sha256(self.fresh_rpc.active_orders)
            or self.trades_snapshot_sha256
            != _strict_canonical_sha256(self.fresh_rpc.trades)
            or self.positions_snapshot_sha256
            != _strict_canonical_sha256(self.fresh_rpc.positions)
        ):
            raise ValueError("initial baseline execution facts hash mismatch")
        if (
            self.commodity_checkpoint.initial_rpc.pending_send_outcomes != 0
            or self.fresh_rpc.pending_send_outcomes != 0
            or self.commodity_checkpoint.initial_rpc.active_orders
            or self.fresh_rpc.active_orders
            or self.commodity_checkpoint.initial_rpc.captured_at
            > self.commodity_checkpoint.captured_at
            or self.commodity_checkpoint.captured_at > self.fresh_rpc.captured_at
            or self.fresh_rpc.captured_at > self.captured_at
            or self.captured_at - self.commodity_checkpoint.initial_rpc.captured_at
            > timedelta(seconds=30)
        ):
            raise ValueError("initial baseline facts are unsafe or stale")
        if (
            self.commodity_checkpoint.checkpoint_id != self.commodity_checkpoint_id
            or self.commodity_checkpoint.checkpoint_core_sha256
            != self.commodity_checkpoint_core_sha256
            or self.commodity_checkpoint.active_orders_snapshot_sha256
            != self.active_orders_snapshot_sha256
            or self.commodity_checkpoint.positions_snapshot_sha256
            != self.positions_snapshot_sha256
        ):
            raise ValueError("initial Commodity baseline projection is unsafe")
        current_state_raw = (
            json.dumps(
                self.current_drain_state.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if self.current_drain_state_raw_sha256 != hashlib.sha256(
            current_state_raw
        ).hexdigest():
            raise ValueError("initial baseline drain state raw hash mismatch")
        if (
            self.current_drain_state.state_generation
            != self.current_state_generation
            or self.current_drain_state.runtime_instance_id
            != self.current_runtime_instance_id
            or self.current_drain_state.execution_epoch
            != self.current_execution_epoch
        ):
            raise ValueError("initial baseline drain state identity mismatch")
        core = self.model_dump(mode="json")
        core.pop("checkpoint_id")
        core.pop("checkpoint_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.checkpoint_core_sha256 != expected or self.checkpoint_id != (
            f"deployment-initial-baseline-checkpoint-{expected}"
        ):
            raise ValueError("initial baseline checkpoint identity mismatch")
        return self


class InitialBaselineReconciliationEvidenceDTO(StrictDeploymentDrainModel):
    """C1b evidence only; C2 still owns real custody capture and activation."""

    schema_version: Literal["web_bridge_initial_baseline_reconciliation_v1"]
    purpose: Literal["record_non_authorizing_fresh_initial_baseline_evidence"]
    mode: Literal["INITIAL_BASELINE"]
    reconciliation_id: InitialBaselineEvidenceId
    reconciliation_core_sha256: Sha256
    checkpoint_id: InitialBaselineCheckpointId
    checkpoint_raw_sha256: Sha256
    checkpoint_core_sha256: Sha256
    commodity_checkpoint_raw_sha256: Sha256
    genesis_commitment_raw_sha256: Sha256
    current_state_commitment_raw_sha256: Sha256
    current_epoch_anchor_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=2)
    expected_account_hash: Sha256
    reconciled_at: datetime
    fresh_initial_baseline_verified: Literal[True]
    custody_inventory_verified: Literal[False]
    initial_execution_facts_baseline_recorded: Literal[True]
    execution_facts_reconciliation_completed: Literal[True]
    semantic_safety_unchanged: Literal[False]
    target_runtime_verified: Literal[False]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_evidence(self) -> InitialBaselineReconciliationEvidenceDTO:
        _require_utc(self.reconciled_at, "initial baseline reconciled_at")
        core = self.model_dump(mode="json")
        core.pop("reconciliation_id")
        core.pop("reconciliation_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.reconciliation_core_sha256 != expected or self.reconciliation_id != (
            f"initial-baseline-reconciliation-{expected}"
        ):
            raise ValueError("initial baseline evidence identity mismatch")
        return self


class _LegacyMigrationSourceStateBase(StrictDeploymentDrainModel):
    """Common exact, inactive fields accepted from a clean legacy source."""

    state: Literal["RUNNING"]
    drain_epoch: int = Field(strict=True, ge=0)
    execution_epoch: int = Field(strict=True, ge=0)
    runtime_instance_id: Identifier
    active_request_id: Literal[None]
    active_request_sha256: Literal[None]
    active_receipt_id: Literal[None]
    active_receipt_raw_sha256: Literal[None]
    receipt_consumed: Literal[False]
    consumed_at: Literal[None]
    consume_id: Literal[None]
    last_invalidated_receipt_id: Literal[None]
    blockers: list[str]
    expires_at: Literal[None]
    freeze_reason: Literal[None]
    updated_at: datetime

    @field_serializer("updated_at", when_used="json")
    def serialize_updated_at(self, value: datetime) -> str:
        return value.isoformat()

    @model_validator(mode="after")
    def validate_source_state(self) -> _LegacyMigrationSourceStateBase:
        _require_utc(self.updated_at, "legacy migration source updated_at")
        if self.blockers:
            raise ValueError("legacy migration source blockers must be empty")
        return self


class LegacyMigrationSourceStateV1DTO(_LegacyMigrationSourceStateBase):
    """Strict clean v1 source eligible for C1c baseline reconciliation."""

    schema_version: Literal["web_bridge_deployment_drain_state_v1"]


class LegacyMigrationSourceStateV2DTO(_LegacyMigrationSourceStateBase):
    """Strict clean v2 source eligible for C1c baseline reconciliation."""

    schema_version: Literal["web_bridge_deployment_drain_state_v2"]
    active_online_recheck_id: Literal[None]
    active_online_recheck_raw_sha256: Literal[None]
    active_recheck_checkpoint_raw_sha256: Literal[None]
    online_rechecked_at: Literal[None]
    last_invalidated_online_recheck_id: Literal[None]


class LegacyEpochAnchorV1DTO(StrictDeploymentDrainModel):
    """Exact legacy high-water anchor accepted by the clean C1c path."""

    schema_version: Literal["web_bridge_deployment_drain_epoch_anchor_v1"]
    drain_epoch: int = Field(strict=True, ge=0)
    execution_epoch: int = Field(strict=True, ge=0)


class DeploymentEpochAnchorV2DTO(StrictDeploymentDrainModel):
    """Exact current anchor embedded by self-contained reconciliation DTOs."""

    schema_version: Literal["web_bridge_deployment_drain_epoch_anchor_v2"]
    state_generation: int = Field(strict=True, ge=1)
    state_commitment_raw_sha256: Sha256
    drain_epoch: int = Field(strict=True, ge=0)
    execution_epoch: int = Field(strict=True, ge=0)


class LegacyMigrationEmptyInventoryDTO(StrictDeploymentDrainModel):
    """Content-addressed declaration; C2 still verifies the live inventory."""

    schema_version: Literal["web_bridge_legacy_migration_empty_inventory_v1"]
    purpose: Literal["bind_declared_empty_legacy_migration_inventory"]
    mode: Literal["LEGACY_MIGRATION_BASELINE"]
    inventory_id: LegacyMigrationInventoryId
    inventory_core_sha256: Sha256
    source_schema_version: Literal[
        "web_bridge_deployment_drain_state_v1",
        "web_bridge_deployment_drain_state_v2",
    ]
    source_state_raw_sha256: Sha256
    source_epoch_anchor_raw_sha256: Sha256
    receipts: list[dict[str, Any]]
    consumes: list[dict[str, Any]]
    checkpoints: list[dict[str, Any]]
    rechecks: list[dict[str, Any]]
    inventory_declared_empty: Literal[True]
    custody_inventory_verified: Literal[False]
    deployment_authorized: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_inventory(self) -> LegacyMigrationEmptyInventoryDTO:
        if self.receipts or self.consumes or self.checkpoints or self.rechecks:
            raise ValueError("legacy migration clean inventory must be empty")
        core = self.model_dump(mode="json")
        core.pop("inventory_id")
        core.pop("inventory_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.inventory_core_sha256 != expected or self.inventory_id != (
            f"legacy-migration-empty-inventory-{expected}"
        ):
            raise ValueError("legacy migration inventory identity mismatch")
        return self


class DeploymentLegacyMigrationDrainStateDTO(StrictDeploymentDrainModel):
    """Exact frozen v3 state accepted after a clean v1/v2 migration."""

    schema_version: Literal["web_bridge_deployment_drain_state_v3"]
    state_generation: int = Field(strict=True, ge=2)
    previous_state_commitment_raw_sha256: Sha256
    state: Literal["RESTARTED_FROZEN"]
    drain_epoch: int = Field(strict=True, ge=0)
    execution_epoch: int = Field(strict=True, ge=1)
    runtime_instance_id: Identifier
    active_request_id: Literal[None]
    active_request_sha256: Literal[None]
    active_receipt_id: Literal[None]
    active_receipt_raw_sha256: Literal[None]
    receipt_consumed: Literal[False]
    consumed_at: Literal[None]
    consume_id: Literal[None]
    consumed_receipt_id: Literal[None]
    consume_intent_raw_sha256: Literal[None]
    consume_marker_raw_sha256: Literal[None]
    consume_state_projection_sha256: Literal[None]
    consumed_online_recheck_id: Literal[None]
    consumed_online_recheck_raw_sha256: Literal[None]
    preconsume_state_commitment_raw_sha256: Literal[None]
    active_online_recheck_id: Literal[None]
    active_online_recheck_raw_sha256: Literal[None]
    active_recheck_checkpoint_raw_sha256: Literal[None]
    online_rechecked_at: Literal[None]
    last_invalidated_online_recheck_id: Literal[None]
    last_invalidated_receipt_id: Literal[None]
    blockers: list[str]
    expires_at: Literal[None]
    freeze_reason: Literal["legacy_state_migrated_to_v3_requires_reconciliation"]
    updated_at: datetime

    @field_serializer("updated_at", when_used="json")
    def serialize_updated_at(self, value: datetime) -> str:
        return value.isoformat()

    @model_validator(mode="after")
    def validate_state(self) -> DeploymentLegacyMigrationDrainStateDTO:
        _require_utc(self.updated_at, "legacy migration drain state updated_at")
        if self.blockers != ["legacy_state_migrated_to_v3_requires_reconciliation"]:
            raise ValueError("legacy migration drain blockers are invalid")
        return self


class DeploymentLegacyMigrationCommodityCheckpointDTO(StrictDeploymentDrainModel):
    """Exact owner projection for a clean legacy migration baseline."""

    schema_version: Literal[
        "web_bridge_deployment_legacy_migration_commodity_checkpoint_v1"
    ]
    purpose: Literal["record_exact_non_authorizing_legacy_migration_commodity_baseline"]
    mode: Literal["LEGACY_MIGRATION_BASELINE"]
    reconciliation_run_id: Identifier
    checkpoint_id: LegacyMigrationCommodityCheckpointId
    checkpoint_core_sha256: Sha256
    source_schema_version: Literal[
        "web_bridge_deployment_drain_state_v1",
        "web_bridge_deployment_drain_state_v2",
    ]
    source_state_raw_sha256: Sha256
    source_epoch_anchor_raw_sha256: Sha256
    inventory_id: LegacyMigrationInventoryId
    inventory_raw_sha256: Sha256
    inventory_core_sha256: Sha256
    genesis_commitment_raw_sha256: Sha256
    current_state_commitment_raw_sha256: Sha256
    current_epoch_anchor_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=1)
    expected_account_hash: Sha256
    captured_at: datetime
    execution_plan_status: Literal["IDLE"]
    execution_plan_hash: Literal[None]
    plan_version: Literal[0]
    state_version: Literal["web_bridge_initial_baseline_commodity_state_v1"]
    state: CommodityInitialBaselineStateDTO
    state_sha256: Sha256
    initial_rpc: DeploymentRpcFactsDTO
    active_orders_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    web_trade_enabled: Literal[False]
    execution_authority_revoked: Literal[True]
    auto_dispatch_stopped: Literal[True]
    active_orders: Literal[0]
    unknown_outcome: Literal[False]
    reconcile_required: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_checkpoint(
        self,
    ) -> DeploymentLegacyMigrationCommodityCheckpointDTO:
        _require_utc(self.captured_at, "legacy migration Commodity captured_at")
        if self.initial_rpc.captured_at > self.captured_at:
            raise ValueError("initial RPC cannot follow Commodity checkpoint")
        if (
            self.initial_rpc.pending_send_outcomes
            or self.initial_rpc.active_orders
            or self.initial_rpc.account_hashes != [self.expected_account_hash]
        ):
            raise ValueError("legacy migration Commodity RPC is not frozen and scoped")
        state = self.state
        if self.state_sha256 != _strict_canonical_sha256(
            state.model_dump(mode="json")
        ):
            raise ValueError("legacy migration Commodity state hash mismatch")
        active_sha = _strict_canonical_sha256(self.initial_rpc.active_orders)
        positions_sha = _strict_canonical_sha256(self.initial_rpc.positions)
        if (
            self.active_orders_snapshot_sha256 != active_sha
            or self.positions_snapshot_sha256 != positions_sha
            or state.execution_plan_status != self.execution_plan_status
            or state.execution_plan_hash != self.execution_plan_hash
            or state.plan_version != self.plan_version
            or state.web_trade_enabled != self.web_trade_enabled
            or state.execution_authority_revoked != self.execution_authority_revoked
            or state.auto_dispatch_stopped != self.auto_dispatch_stopped
            or state.unknown_outcome != self.unknown_outcome
            or state.reconcile_required != self.reconcile_required
            or state.rpc_generation != self.initial_rpc.fact_generation
            or state.active_orders_snapshot_sha256 != active_sha
            or state.positions_snapshot_sha256 != positions_sha
        ):
            raise ValueError("legacy migration Commodity projection mismatch")
        core = self.model_dump(mode="json")
        core.pop("checkpoint_id")
        core.pop("checkpoint_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.checkpoint_core_sha256 != expected or self.checkpoint_id != (
            f"deployment-legacy-migration-commodity-checkpoint-{expected}"
        ):
            raise ValueError("legacy migration Commodity identity mismatch")
        return self


class DeploymentLegacyMigrationCheckpointDTO(StrictDeploymentDrainModel):
    """Non-authorizing C1c checkpoint for a clean legacy migration."""

    schema_version: Literal["web_bridge_deployment_legacy_migration_checkpoint_v1"]
    purpose: Literal["record_non_authorizing_clean_legacy_migration_baseline"]
    mode: Literal["LEGACY_MIGRATION_BASELINE"]
    reconciliation_run_id: Identifier
    checkpoint_id: LegacyMigrationCheckpointId
    checkpoint_core_sha256: Sha256
    source_schema_version: Literal[
        "web_bridge_deployment_drain_state_v1",
        "web_bridge_deployment_drain_state_v2",
    ]
    source_state_raw_sha256: Sha256
    source_epoch_anchor_raw_sha256: Sha256
    source_state: LegacyMigrationSourceStateV1DTO | LegacyMigrationSourceStateV2DTO
    source_epoch_anchor: LegacyEpochAnchorV1DTO
    inventory_id: LegacyMigrationInventoryId
    inventory_raw_sha256: Sha256
    inventory_core_sha256: Sha256
    inventory: LegacyMigrationEmptyInventoryDTO
    genesis_source: Literal["v1_migration", "v2_migration"]
    genesis_commitment_id: StateCommitmentId
    genesis_commitment_raw_sha256: Sha256
    genesis_commitment_core_sha256: Sha256
    genesis_state_raw_sha256: Sha256
    current_state_commitment_id: StateCommitmentId
    current_state_commitment_raw_sha256: Sha256
    current_state_commitment_core_sha256: Sha256
    current_state_generation: int = Field(strict=True, ge=2)
    state_commitment_chain_sha256: Sha256
    state_commitment_raw_sha256s: list[Sha256]
    state_commitments: list[DeploymentDrainStateCommitmentDTO]
    current_epoch_anchor_raw_sha256: Sha256
    current_epoch_anchor: DeploymentEpochAnchorV2DTO
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=1)
    current_drain_state: DeploymentLegacyMigrationDrainStateDTO
    current_drain_state_raw_sha256: Sha256
    expected_account_hash: Sha256
    commodity_checkpoint_id: LegacyMigrationCommodityCheckpointId
    commodity_checkpoint_raw_sha256: Sha256
    commodity_checkpoint_core_sha256: Sha256
    commodity_checkpoint: DeploymentLegacyMigrationCommodityCheckpointDTO
    fresh_rpc: DeploymentRpcRecheckFactsDTO
    initial_execution_facts_canonical_sha256: Sha256
    fresh_execution_facts_canonical_sha256: Sha256
    orders_snapshot_sha256: Sha256
    active_orders_snapshot_sha256: Sha256
    trades_snapshot_sha256: Sha256
    positions_snapshot_sha256: Sha256
    captured_at: datetime
    legacy_source_exact_bytes_verified: Literal[True]
    legacy_migration_baseline_verified: Literal[True]
    initial_execution_facts_baseline_recorded: Literal[True]
    execution_facts_reconciliation_completed: Literal[True]
    semantic_safety_unchanged: Literal[False]
    external_high_water_verified: Literal[False]
    custody_inventory_verified: Literal[False]
    target_runtime_verified: Literal[False]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_checkpoint(self) -> DeploymentLegacyMigrationCheckpointDTO:
        _require_utc(self.captured_at, "legacy migration checkpoint captured_at")
        source = self.source_state
        expected_genesis_source = (
            "v1_migration"
            if isinstance(source, LegacyMigrationSourceStateV1DTO)
            else "v2_migration"
        )
        if (
            source.schema_version != self.source_schema_version
            or self.genesis_source != expected_genesis_source
            or source.drain_epoch != self.source_epoch_anchor.drain_epoch
            or source.execution_epoch != self.source_epoch_anchor.execution_epoch
        ):
            raise ValueError("legacy migration source and anchor are inconsistent")
        source_raw = (
            json.dumps(
                source.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        source_anchor_raw = (
            json.dumps(
                self.source_epoch_anchor.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if (
            self.source_state_raw_sha256
            != hashlib.sha256(source_raw).hexdigest()
            or self.source_epoch_anchor_raw_sha256
            != hashlib.sha256(source_anchor_raw).hexdigest()
        ):
            raise ValueError("legacy migration embedded source hash mismatch")
        inventory = self.inventory
        if (
            inventory.inventory_id != self.inventory_id
            or inventory.inventory_core_sha256 != self.inventory_core_sha256
            or inventory.source_schema_version != self.source_schema_version
            or inventory.source_state_raw_sha256 != self.source_state_raw_sha256
            or inventory.source_epoch_anchor_raw_sha256
            != self.source_epoch_anchor_raw_sha256
        ):
            raise ValueError("legacy migration inventory binding mismatch")
        inventory_raw = (
            json.dumps(
                inventory.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if self.inventory_raw_sha256 != hashlib.sha256(inventory_raw).hexdigest():
            raise ValueError("legacy migration inventory raw hash mismatch")
        commodity = self.commodity_checkpoint
        for observed, expected in (
            (commodity.reconciliation_run_id, self.reconciliation_run_id),
            (commodity.source_schema_version, self.source_schema_version),
            (commodity.source_state_raw_sha256, self.source_state_raw_sha256),
            (
                commodity.source_epoch_anchor_raw_sha256,
                self.source_epoch_anchor_raw_sha256,
            ),
            (commodity.inventory_id, self.inventory_id),
            (commodity.inventory_raw_sha256, self.inventory_raw_sha256),
            (commodity.inventory_core_sha256, self.inventory_core_sha256),
            (
                commodity.genesis_commitment_raw_sha256,
                self.genesis_commitment_raw_sha256,
            ),
            (
                commodity.current_state_commitment_raw_sha256,
                self.current_state_commitment_raw_sha256,
            ),
            (
                commodity.current_epoch_anchor_raw_sha256,
                self.current_epoch_anchor_raw_sha256,
            ),
            (commodity.current_runtime_instance_id, self.current_runtime_instance_id),
            (commodity.current_execution_epoch, self.current_execution_epoch),
            (commodity.expected_account_hash, self.expected_account_hash),
        ):
            if observed != expected:
                raise ValueError("legacy migration Commodity binding mismatch")
        commodity_raw = (
            json.dumps(
                commodity.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if self.commodity_checkpoint_raw_sha256 != hashlib.sha256(
            commodity_raw
        ).hexdigest():
            raise ValueError("legacy migration Commodity raw hash mismatch")
        if (
            len(self.state_commitments) != self.current_state_generation
            or len(self.state_commitment_raw_sha256s)
            != self.current_state_generation
            or self.current_state_generation < 2
        ):
            raise ValueError("legacy migration commitment inventory is incomplete")
        computed_commitment_hashes: list[str] = []
        previous_raw_sha256: str | None = None
        previous_created_at: datetime | None = None
        seen_runtimes = {source.runtime_instance_id}
        for expected_generation, commitment in enumerate(
            self.state_commitments, start=1
        ):
            commitment_raw = (
                json.dumps(
                    commitment.model_dump(mode="json"),
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            commitment_raw_sha256 = hashlib.sha256(commitment_raw).hexdigest()
            computed_commitment_hashes.append(commitment_raw_sha256)
            if (
                commitment.state_generation != expected_generation
                or commitment.previous_state_commitment_raw_sha256
                != previous_raw_sha256
                or commitment.state.get("updated_at")
                != commitment.created_at.isoformat()
                or (
                    previous_created_at is not None
                    and commitment.created_at < previous_created_at
                )
            ):
                raise ValueError("legacy migration commitment chain is invalid")
            if expected_generation > 1:
                migrated_state = DeploymentLegacyMigrationDrainStateDTO.model_validate(
                    commitment.state
                )
                if (
                    commitment.state != migrated_state.model_dump(mode="json")
                    or migrated_state.drain_epoch != source.drain_epoch
                    or migrated_state.execution_epoch
                    != source.execution_epoch + expected_generation - 1
                    or migrated_state.runtime_instance_id in seen_runtimes
                ):
                    raise ValueError("legacy migration runtime lineage is invalid")
                seen_runtimes.add(migrated_state.runtime_instance_id)
            previous_raw_sha256 = commitment_raw_sha256
            previous_created_at = commitment.created_at
        if (
            computed_commitment_hashes != self.state_commitment_raw_sha256s
            or self.state_commitment_chain_sha256
            != _strict_canonical_sha256(computed_commitment_hashes)
        ):
            raise ValueError("legacy migration commitment hashes mismatch")
        genesis = self.state_commitments[0]
        current_commitment = self.state_commitments[-1]
        expected_genesis_state = source.model_dump(mode="json")
        if isinstance(source, LegacyMigrationSourceStateV1DTO):
            expected_genesis_state.update(
                active_online_recheck_id=None,
                active_online_recheck_raw_sha256=None,
                active_recheck_checkpoint_raw_sha256=None,
                online_rechecked_at=None,
                last_invalidated_online_recheck_id=None,
            )
        expected_genesis_state.update(
            schema_version="web_bridge_deployment_drain_state_v3",
            state_generation=1,
            previous_state_commitment_raw_sha256=None,
            consumed_receipt_id=None,
            consume_intent_raw_sha256=None,
            consume_marker_raw_sha256=None,
            consume_state_projection_sha256=None,
            consumed_online_recheck_id=None,
            consumed_online_recheck_raw_sha256=None,
            preconsume_state_commitment_raw_sha256=None,
            state="RESTARTED_FROZEN",
            blockers=["legacy_state_migrated_to_v3_requires_reconciliation"],
            expires_at=None,
            freeze_reason="legacy_state_migrated_to_v3_requires_reconciliation",
            updated_at=genesis.created_at.isoformat(),
        )
        if (
            genesis.genesis_source != self.genesis_source
            or genesis.source_state_raw_sha256 != self.source_state_raw_sha256
            or genesis.source_epoch_anchor_raw_sha256
            != self.source_epoch_anchor_raw_sha256
            or genesis.commitment_id != self.genesis_commitment_id
            or genesis.state_commitment_core_sha256
            != self.genesis_commitment_core_sha256
            or genesis.state_raw_sha256 != self.genesis_state_raw_sha256
            or computed_commitment_hashes[0]
            != self.genesis_commitment_raw_sha256
            or genesis.created_at < source.updated_at
            or genesis.state != expected_genesis_state
            or current_commitment.commitment_id
            != self.current_state_commitment_id
            or current_commitment.state_commitment_core_sha256
            != self.current_state_commitment_core_sha256
            or computed_commitment_hashes[-1]
            != self.current_state_commitment_raw_sha256
            or current_commitment.state
            != self.current_drain_state.model_dump(mode="json")
        ):
            raise ValueError("legacy migration commitment endpoint mismatch")
        current_anchor_raw = (
            json.dumps(
                self.current_epoch_anchor.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if (
            self.current_epoch_anchor_raw_sha256
            != hashlib.sha256(current_anchor_raw).hexdigest()
            or self.current_epoch_anchor.state_generation
            != self.current_state_generation
            or self.current_epoch_anchor.state_commitment_raw_sha256
            != self.current_state_commitment_raw_sha256
            or self.current_epoch_anchor.drain_epoch
            != self.current_drain_state.drain_epoch
            or self.current_epoch_anchor.execution_epoch
            != self.current_execution_epoch
        ):
            raise ValueError("legacy migration current anchor does not bind the head")
        initial = commodity.initial_rpc
        fresh = self.fresh_rpc
        initial_sha = deployment_rpc_execution_facts_sha256(initial)
        identity_core = {
            "mode": "LEGACY_MIGRATION_BASELINE",
            "reconciliation_run_id": self.reconciliation_run_id,
            "source_schema_version": self.source_schema_version,
            "source_state_raw_sha256": self.source_state_raw_sha256,
            "source_epoch_anchor_raw_sha256": (
                self.source_epoch_anchor_raw_sha256
            ),
            "inventory_raw_sha256": self.inventory_raw_sha256,
            "genesis_commitment_raw_sha256": (
                self.genesis_commitment_raw_sha256
            ),
            "current_state_commitment_raw_sha256": (
                self.current_state_commitment_raw_sha256
            ),
            "current_epoch_anchor_raw_sha256": (
                self.current_epoch_anchor_raw_sha256
            ),
            "current_runtime_instance_id": self.current_runtime_instance_id,
            "current_execution_epoch": self.current_execution_epoch,
            "expected_account_hash": self.expected_account_hash,
        }
        owner_digest = _strict_canonical_sha256(
            {**identity_core, "capture": "INITIAL"}
        )
        fresh_digest = _strict_canonical_sha256(
            {**identity_core, "capture": "FRESH_RECHECK"}
        )
        if (
            initial.request_id != f"legacy-baseline-{owner_digest}"
            or initial.challenge != f"legacy-owner-{owner_digest}"
            or fresh.request_id != f"legacy-baseline-{owner_digest}"
            or fresh.owner_challenge != f"legacy-owner-{owner_digest}"
            or fresh.recheck_id != f"deployment-recheck-{fresh_digest}"
            or fresh.fresh_challenge != f"legacy-fresh-{fresh_digest}"
            or initial.server_instance_id != fresh.original_server_instance_id
            or initial.server_instance_id != fresh.server_instance_id
            or initial.fact_generation != fresh.original_fact_generation
            or initial.fact_generation != fresh.fact_generation
            or fresh.original_execution_facts_canonical_sha256 != initial_sha
            or fresh.execution_facts_canonical_sha256 != initial_sha
            or initial.account_hashes != [self.expected_account_hash]
            or fresh.account_hashes != [self.expected_account_hash]
            or initial.pending_send_outcomes != 0
            or fresh.pending_send_outcomes != 0
            or initial.active_orders
            or fresh.active_orders
            or initial.orders != fresh.orders
            or initial.trades != fresh.trades
            or initial.positions != fresh.positions
        ):
            raise ValueError("legacy migration Windows facts are not stable")
        if (
            self.initial_execution_facts_canonical_sha256 != initial_sha
            or self.fresh_execution_facts_canonical_sha256 != initial_sha
            or self.orders_snapshot_sha256
            != _strict_canonical_sha256(fresh.orders)
            or self.active_orders_snapshot_sha256
            != _strict_canonical_sha256(fresh.active_orders)
            or self.trades_snapshot_sha256
            != _strict_canonical_sha256(fresh.trades)
            or self.positions_snapshot_sha256
            != _strict_canonical_sha256(fresh.positions)
        ):
            raise ValueError("legacy migration execution fact hashes mismatch")
        if (
            initial.captured_at < current_commitment.created_at
            or initial.captured_at > commodity.captured_at
            or commodity.captured_at > fresh.captured_at
            or fresh.captured_at > self.captured_at
            or self.captured_at - initial.captured_at > timedelta(seconds=30)
        ):
            raise ValueError("legacy migration facts are stale or misordered")
        if (
            commodity.checkpoint_id != self.commodity_checkpoint_id
            or commodity.checkpoint_core_sha256
            != self.commodity_checkpoint_core_sha256
            or commodity.active_orders_snapshot_sha256
            != self.active_orders_snapshot_sha256
            or commodity.positions_snapshot_sha256
            != self.positions_snapshot_sha256
        ):
            raise ValueError("legacy migration Commodity artifact mismatch")
        current_state_raw = (
            json.dumps(
                self.current_drain_state.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if (
            self.current_drain_state_raw_sha256
            != hashlib.sha256(current_state_raw).hexdigest()
            or self.current_drain_state.state_generation
            != self.current_state_generation
            or self.current_drain_state.runtime_instance_id
            != self.current_runtime_instance_id
            or self.current_drain_state.execution_epoch
            != self.current_execution_epoch
            or self.current_drain_state.drain_epoch != source.drain_epoch
        ):
            raise ValueError("legacy migration current drain state mismatch")
        core = self.model_dump(mode="json")
        core.pop("checkpoint_id")
        core.pop("checkpoint_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.checkpoint_core_sha256 != expected or self.checkpoint_id != (
            f"deployment-legacy-migration-checkpoint-{expected}"
        ):
            raise ValueError("legacy migration checkpoint identity mismatch")
        return self


class LegacyMigrationReconciliationEvidenceDTO(StrictDeploymentDrainModel):
    """C1c evidence only; C2/D retain custody, fence, and authority control."""

    schema_version: Literal["web_bridge_legacy_migration_reconciliation_v1"]
    purpose: Literal["record_non_authorizing_clean_legacy_migration_evidence"]
    mode: Literal["LEGACY_MIGRATION_BASELINE"]
    reconciliation_id: LegacyMigrationEvidenceId
    reconciliation_core_sha256: Sha256
    checkpoint_id: LegacyMigrationCheckpointId
    checkpoint_raw_sha256: Sha256
    checkpoint_core_sha256: Sha256
    checkpoint: DeploymentLegacyMigrationCheckpointDTO
    inventory_id: LegacyMigrationInventoryId
    inventory_raw_sha256: Sha256
    commodity_checkpoint_id: LegacyMigrationCommodityCheckpointId
    commodity_checkpoint_raw_sha256: Sha256
    source_schema_version: Literal[
        "web_bridge_deployment_drain_state_v1",
        "web_bridge_deployment_drain_state_v2",
    ]
    source_state_raw_sha256: Sha256
    source_epoch_anchor_raw_sha256: Sha256
    genesis_commitment_raw_sha256: Sha256
    current_state_commitment_raw_sha256: Sha256
    current_epoch_anchor_raw_sha256: Sha256
    current_runtime_instance_id: Identifier
    current_execution_epoch: int = Field(strict=True, ge=1)
    expected_account_hash: Sha256
    reconciled_at: datetime
    legacy_source_exact_bytes_verified: Literal[True]
    legacy_migration_baseline_verified: Literal[True]
    initial_execution_facts_baseline_recorded: Literal[True]
    execution_facts_reconciliation_completed: Literal[True]
    semantic_safety_unchanged: Literal[False]
    external_high_water_verified: Literal[False]
    custody_inventory_verified: Literal[False]
    target_runtime_verified: Literal[False]
    reconciliation_completed: Literal[False]
    windows_fence_released: Literal[False]
    authority_restore_allowed: Literal[False]
    consume_authorized: Literal[False]
    reconciliation_authorized: Literal[False]
    deployment_authorized: Literal[False]
    automatic_deploy_allowed: Literal[False]
    production_allowed: Literal[False]
    live_trading_authorized: Literal[False]
    countable_forward: Literal[False]

    @model_validator(mode="after")
    def validate_evidence(self) -> LegacyMigrationReconciliationEvidenceDTO:
        _require_utc(self.reconciled_at, "legacy migration reconciled_at")
        checkpoint_raw = (
            json.dumps(
                self.checkpoint.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        checkpoint = self.checkpoint
        for observed, expected in (
            (self.checkpoint_id, checkpoint.checkpoint_id),
            (self.checkpoint_core_sha256, checkpoint.checkpoint_core_sha256),
            (self.checkpoint_raw_sha256, hashlib.sha256(checkpoint_raw).hexdigest()),
            (self.inventory_id, checkpoint.inventory_id),
            (self.inventory_raw_sha256, checkpoint.inventory_raw_sha256),
            (self.commodity_checkpoint_id, checkpoint.commodity_checkpoint_id),
            (
                self.commodity_checkpoint_raw_sha256,
                checkpoint.commodity_checkpoint_raw_sha256,
            ),
            (self.source_schema_version, checkpoint.source_schema_version),
            (self.source_state_raw_sha256, checkpoint.source_state_raw_sha256),
            (
                self.source_epoch_anchor_raw_sha256,
                checkpoint.source_epoch_anchor_raw_sha256,
            ),
            (
                self.genesis_commitment_raw_sha256,
                checkpoint.genesis_commitment_raw_sha256,
            ),
            (
                self.current_state_commitment_raw_sha256,
                checkpoint.current_state_commitment_raw_sha256,
            ),
            (
                self.current_epoch_anchor_raw_sha256,
                checkpoint.current_epoch_anchor_raw_sha256,
            ),
            (
                self.current_runtime_instance_id,
                checkpoint.current_runtime_instance_id,
            ),
            (self.current_execution_epoch, checkpoint.current_execution_epoch),
            (self.expected_account_hash, checkpoint.expected_account_hash),
            (self.reconciled_at, checkpoint.captured_at),
        ):
            if observed != expected:
                raise ValueError("legacy migration evidence binding mismatch")
        core = self.model_dump(mode="json")
        core.pop("reconciliation_id")
        core.pop("reconciliation_core_sha256")
        expected = _strict_canonical_sha256(core)
        if self.reconciliation_core_sha256 != expected or self.reconciliation_id != (
            f"legacy-migration-reconciliation-{expected}"
        ):
            raise ValueError("legacy migration evidence identity mismatch")
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
        if self.expires_at - self.issued_at != timedelta(seconds=self.ttl_seconds):
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
