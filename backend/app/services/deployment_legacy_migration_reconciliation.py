"""Pure, non-authorizing C1c legacy migration reconciliation contracts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    CommodityInitialBaselineStateDTO,
    DeploymentLegacyMigrationCheckpointDTO,
    DeploymentLegacyMigrationCommodityCheckpointDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    LegacyEpochAnchorV1DTO,
    LegacyMigrationEmptyInventoryDTO,
    LegacyMigrationReconciliationEvidenceDTO,
    LegacyMigrationSourceStateV1DTO,
    LegacyMigrationSourceStateV2DTO,
    deployment_rpc_execution_facts_sha256,
)
from app.services.deployment_restart_reconciliation import (
    DeploymentRestartReconciliationError,
    _artifact_bytes,
    _canonical_bytes,
    _parse_exact_epoch_anchor,
    _require_exact_state_v3,
    _sha256,
    _utc_timestamp,
)
from app.services.deployment_state_commitment import (
    DeploymentStateCommitmentError,
    parse_exact_state_commitment,
)


class DeploymentLegacyMigrationError(RuntimeError):
    """Legacy migration evidence is invalid or cannot prove a clean baseline."""


_EMPTY_STATE_FIELDS = {
    "active_request_id",
    "active_request_sha256",
    "active_receipt_id",
    "active_receipt_raw_sha256",
    "consumed_at",
    "consume_id",
    "consumed_receipt_id",
    "consume_intent_raw_sha256",
    "consume_marker_raw_sha256",
    "consume_state_projection_sha256",
    "consumed_online_recheck_id",
    "consumed_online_recheck_raw_sha256",
    "preconsume_state_commitment_raw_sha256",
    "active_online_recheck_id",
    "active_online_recheck_raw_sha256",
    "active_recheck_checkpoint_raw_sha256",
    "online_rechecked_at",
    "last_invalidated_online_recheck_id",
    "last_invalidated_receipt_id",
    "expires_at",
}
_MIGRATION_REASON = "legacy_state_migrated_to_v3_requires_reconciliation"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _strict_model_input(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    return value


def _parse_exact(raw: bytes, model: type, label: str):
    if not isinstance(raw, bytes):
        raise DeploymentLegacyMigrationError(f"{label} raw value must be bytes")
    try:
        value = model.model_validate_json(raw)
        expected = _artifact_bytes(value.model_dump(mode="json"))
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(f"{label} is invalid") from exc
    if raw != expected:
        raise DeploymentLegacyMigrationError(f"{label} bytes are not canonical")
    return value


def _parse_exact_source(raw: bytes):
    if not isinstance(raw, bytes):
        raise DeploymentLegacyMigrationError(
            "legacy source state raw value must be bytes"
        )
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy source state is invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise DeploymentLegacyMigrationError(
            "legacy source state must be an object"
        )
    version = payload.get("schema_version")
    if version == "web_bridge_deployment_drain_state_v1":
        model = LegacyMigrationSourceStateV1DTO
    elif version == "web_bridge_deployment_drain_state_v2":
        model = LegacyMigrationSourceStateV2DTO
    else:
        raise DeploymentLegacyMigrationError(
            "legacy source state version is unsupported"
        )
    source = _parse_exact(raw, model, "legacy source state")
    return version, source


def canonical_legacy_migration_inventory_bytes(
    inventory: LegacyMigrationEmptyInventoryDTO,
) -> bytes:
    try:
        value = LegacyMigrationEmptyInventoryDTO.model_validate(inventory)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration inventory is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_legacy_migration_commodity_checkpoint_bytes(
    checkpoint: DeploymentLegacyMigrationCommodityCheckpointDTO,
) -> bytes:
    try:
        value = DeploymentLegacyMigrationCommodityCheckpointDTO.model_validate(
            checkpoint
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration Commodity checkpoint is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_legacy_migration_checkpoint_bytes(
    checkpoint: DeploymentLegacyMigrationCheckpointDTO,
) -> bytes:
    try:
        value = DeploymentLegacyMigrationCheckpointDTO.model_validate(checkpoint)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration checkpoint is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_legacy_migration_evidence_bytes(
    evidence: LegacyMigrationReconciliationEvidenceDTO,
) -> bytes:
    try:
        value = LegacyMigrationReconciliationEvidenceDTO.model_validate(evidence)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration evidence is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def build_legacy_migration_empty_inventory(
    *,
    source_state_raw: bytes,
    source_epoch_anchor_raw: bytes,
) -> LegacyMigrationEmptyInventoryDTO:
    source_version, _source = _parse_exact_source(source_state_raw)
    _parse_exact(
        source_epoch_anchor_raw,
        LegacyEpochAnchorV1DTO,
        "legacy source epoch anchor",
    )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_legacy_migration_empty_inventory_v1",
        "purpose": "bind_declared_empty_legacy_migration_inventory",
        "mode": "LEGACY_MIGRATION_BASELINE",
        "source_schema_version": source_version,
        "source_state_raw_sha256": _sha256(source_state_raw),
        "source_epoch_anchor_raw_sha256": _sha256(source_epoch_anchor_raw),
        "receipts": [],
        "consumes": [],
        "checkpoints": [],
        "rechecks": [],
        "inventory_declared_empty": True,
        "custody_inventory_verified": False,
        "deployment_authorized": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    digest = _sha256(_canonical_bytes(core))
    try:
        return LegacyMigrationEmptyInventoryDTO.model_validate(
            {
                **core,
                "inventory_id": f"legacy-migration-empty-inventory-{digest}",
                "inventory_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration empty inventory could not be built"
        ) from exc


def derive_legacy_migration_rpc_identity(
    *,
    reconciliation_run_id: str,
    source_schema_version: str,
    source_state_raw_sha256: str,
    source_epoch_anchor_raw_sha256: str,
    inventory_raw_sha256: str,
    genesis_commitment_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_epoch_anchor_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
) -> tuple[str, str, str, str]:
    core = {
        "mode": "LEGACY_MIGRATION_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "source_schema_version": source_schema_version,
        "source_state_raw_sha256": source_state_raw_sha256,
        "source_epoch_anchor_raw_sha256": source_epoch_anchor_raw_sha256,
        "inventory_raw_sha256": inventory_raw_sha256,
        "genesis_commitment_raw_sha256": genesis_commitment_raw_sha256,
        "current_state_commitment_raw_sha256": (
            current_state_commitment_raw_sha256
        ),
        "current_epoch_anchor_raw_sha256": current_epoch_anchor_raw_sha256,
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "expected_account_hash": expected_account_hash,
    }
    owner_digest = _sha256(_canonical_bytes({**core, "capture": "INITIAL"}))
    fresh_digest = _sha256(
        _canonical_bytes({**core, "capture": "FRESH_RECHECK"})
    )
    return (
        f"legacy-baseline-{owner_digest}",
        f"legacy-owner-{owner_digest}",
        f"deployment-recheck-{fresh_digest}",
        f"legacy-fresh-{fresh_digest}",
    )


def _expected_migration_genesis_state(source: object, updated_at: str) -> dict[str, Any]:
    value = source.model_dump(mode="json")
    if value["schema_version"] == "web_bridge_deployment_drain_state_v1":
        value.update(
            active_online_recheck_id=None,
            active_online_recheck_raw_sha256=None,
            active_recheck_checkpoint_raw_sha256=None,
            online_rechecked_at=None,
            last_invalidated_online_recheck_id=None,
        )
    value.update(
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
        blockers=[_MIGRATION_REASON],
        expires_at=None,
        freeze_reason=_MIGRATION_REASON,
        updated_at=updated_at,
    )
    return value


def _require_clean_migration_state(state: dict[str, Any], drain_epoch: int) -> None:
    if (
        state["state"] != "RESTARTED_FROZEN"
        or state["drain_epoch"] != drain_epoch
        or state["receipt_consumed"] is not False
        or any(state[field] is not None for field in _EMPTY_STATE_FIELDS)
        or state["blockers"] != [_MIGRATION_REASON]
        or state["freeze_reason"] != _MIGRATION_REASON
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration lineage is not clean and frozen"
        )


def _verify_legacy_migration_chain(
    *,
    source_state_raw: bytes,
    source_epoch_anchor_raw: bytes,
    inventory_manifest_raw: bytes,
    genesis_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
):
    source_version, source = _parse_exact_source(source_state_raw)
    anchor = _parse_exact(
        source_epoch_anchor_raw,
        LegacyEpochAnchorV1DTO,
        "legacy source epoch anchor",
    )
    inventory = _parse_exact(
        inventory_manifest_raw,
        LegacyMigrationEmptyInventoryDTO,
        "legacy migration inventory",
    )
    if (
        anchor.drain_epoch != source.drain_epoch
        or anchor.execution_epoch != source.execution_epoch
    ):
        raise DeploymentLegacyMigrationError(
            "legacy source epoch does not exactly match its anchor"
        )
    if (
        inventory.source_schema_version != source_version
        or inventory.source_state_raw_sha256 != _sha256(source_state_raw)
        or inventory.source_epoch_anchor_raw_sha256
        != _sha256(source_epoch_anchor_raw)
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration inventory is not bound to the source"
        )
    if len(state_commitment_chain_raw) < 2 or (
        state_commitment_chain_raw[0] != genesis_state_commitment_raw
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration chain must include genesis and runtime takeover"
        )

    commitments = []
    previous_raw: bytes | None = None
    previous_created_at: datetime | None = None
    try:
        for expected_generation, raw in enumerate(
            state_commitment_chain_raw, start=1
        ):
            commitment = parse_exact_state_commitment(raw)
            state = _require_exact_state_v3(commitment.state)
            if (
                commitment.state_generation != expected_generation
                or (
                    previous_raw is None
                    and commitment.previous_state_commitment_raw_sha256 is not None
                )
                or (
                    previous_raw is not None
                    and commitment.previous_state_commitment_raw_sha256
                    != _sha256(previous_raw)
                )
                or (
                    previous_created_at is not None
                    and commitment.created_at < previous_created_at
                )
                or state["updated_at"] != commitment.created_at.isoformat()
            ):
                raise DeploymentLegacyMigrationError(
                    "legacy migration commitment chain is not contiguous"
                )
            _require_clean_migration_state(state, source.drain_epoch)
            commitments.append(commitment)
            previous_raw = raw
            previous_created_at = commitment.created_at
    except (
        DeploymentLegacyMigrationError,
        DeploymentRestartReconciliationError,
        DeploymentStateCommitmentError,
    ) as exc:
        if isinstance(exc, DeploymentLegacyMigrationError):
            raise
        raise DeploymentLegacyMigrationError(
            "legacy migration commitment chain is invalid"
        ) from exc

    genesis = commitments[0]
    expected_genesis_source = (
        "v1_migration"
        if source_version == "web_bridge_deployment_drain_state_v1"
        else "v2_migration"
    )
    source_updated_at = source.updated_at
    if (
        genesis.genesis_source != expected_genesis_source
        or genesis.source_state_raw_sha256 != _sha256(source_state_raw)
        or genesis.source_epoch_anchor_raw_sha256
        != _sha256(source_epoch_anchor_raw)
        or genesis.created_at < source_updated_at
        or genesis.state
        != _expected_migration_genesis_state(
            source, genesis.state["updated_at"]
        )
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration genesis projection is invalid"
        )

    previous_state = genesis.state
    seen_runtimes = {source.runtime_instance_id}
    for commitment in commitments[1:]:
        state = commitment.state
        if (
            state["execution_epoch"] != previous_state["execution_epoch"] + 1
            or state["runtime_instance_id"] in seen_runtimes
        ):
            raise DeploymentLegacyMigrationError(
                "legacy migration runtime transition is invalid"
            )
        seen_runtimes.add(state["runtime_instance_id"])
        previous_state = state
    current = commitments[-1]
    if (
        current.state["runtime_instance_id"] != current_runtime_instance_id
        or current.state["execution_epoch"] != current_execution_epoch
        or current_runtime_instance_id == source.runtime_instance_id
    ):
        raise DeploymentLegacyMigrationError(
            "current runtime does not bind the legacy migration head"
        )
    try:
        current_anchor = _parse_exact_epoch_anchor(current_epoch_anchor_raw)
    except DeploymentRestartReconciliationError as exc:
        raise DeploymentLegacyMigrationError(
            "current epoch anchor is invalid"
        ) from exc
    if (
        current_anchor["state_generation"] != current.state_generation
        or current_anchor["state_commitment_raw_sha256"]
        != _sha256(state_commitment_chain_raw[-1])
        or current_anchor["drain_epoch"] != current.state["drain_epoch"]
        or current_anchor["execution_epoch"] != current.state["execution_epoch"]
    ):
        raise DeploymentLegacyMigrationError(
            "current epoch anchor does not bind the migration head"
        )
    return source_version, source, inventory, genesis, current


def _build_legacy_migration_commodity_checkpoint(
    *,
    reconciliation_run_id: str,
    source_schema_version: str,
    source_state_raw_sha256: str,
    source_epoch_anchor_raw_sha256: str,
    inventory_raw_sha256: str,
    inventory_id: str,
    inventory_core_sha256: str,
    genesis_commitment_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_epoch_anchor_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
    commodity_state: CommodityInitialBaselineStateDTO | dict[str, Any],
    initial_rpc: DeploymentRpcFactsDTO | dict[str, Any],
    captured_at: datetime | str,
) -> DeploymentLegacyMigrationCommodityCheckpointDTO:
    try:
        initial = DeploymentRpcFactsDTO.model_validate(
            _strict_model_input(initial_rpc)
        )
        state = CommodityInitialBaselineStateDTO.model_validate(
            _strict_model_input(commodity_state)
        )
        captured = _utc_timestamp(captured_at, "legacy Commodity captured_at")
    except (
        DeploymentRestartReconciliationError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration Commodity inputs are invalid"
        ) from exc
    expected_request, expected_owner, _recheck, _fresh = (
        derive_legacy_migration_rpc_identity(
            reconciliation_run_id=reconciliation_run_id,
            source_schema_version=source_schema_version,
            source_state_raw_sha256=source_state_raw_sha256,
            source_epoch_anchor_raw_sha256=source_epoch_anchor_raw_sha256,
            inventory_raw_sha256=inventory_raw_sha256,
            genesis_commitment_raw_sha256=genesis_commitment_raw_sha256,
            current_state_commitment_raw_sha256=current_state_commitment_raw_sha256,
            current_epoch_anchor_raw_sha256=current_epoch_anchor_raw_sha256,
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
            expected_account_hash=expected_account_hash,
        )
    )
    if (
        initial.request_id != expected_request
        or initial.challenge != expected_owner
        or initial.account_hashes != [expected_account_hash]
        or initial.pending_send_outcomes != 0
        or initial.active_orders
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration Commodity RPC is not safely bound"
        )
    core: dict[str, Any] = {
        "schema_version": (
            "web_bridge_deployment_legacy_migration_commodity_checkpoint_v1"
        ),
        "purpose": (
            "record_exact_non_authorizing_legacy_migration_commodity_baseline"
        ),
        "mode": "LEGACY_MIGRATION_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "source_schema_version": source_schema_version,
        "source_state_raw_sha256": source_state_raw_sha256,
        "source_epoch_anchor_raw_sha256": source_epoch_anchor_raw_sha256,
        "inventory_raw_sha256": inventory_raw_sha256,
        "inventory_id": inventory_id,
        "inventory_core_sha256": inventory_core_sha256,
        "genesis_commitment_raw_sha256": genesis_commitment_raw_sha256,
        "current_state_commitment_raw_sha256": (
            current_state_commitment_raw_sha256
        ),
        "current_epoch_anchor_raw_sha256": current_epoch_anchor_raw_sha256,
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "expected_account_hash": expected_account_hash,
        "captured_at": captured,
        "execution_plan_status": "IDLE",
        "execution_plan_hash": None,
        "plan_version": 0,
        "state_version": "web_bridge_initial_baseline_commodity_state_v1",
        "state": state.model_dump(mode="json"),
        "state_sha256": _sha256(_canonical_bytes(state.model_dump(mode="json"))),
        "initial_rpc": initial.model_dump(mode="json"),
        "active_orders_snapshot_sha256": _sha256(
            _canonical_bytes(initial.active_orders)
        ),
        "positions_snapshot_sha256": _sha256(
            _canonical_bytes(initial.positions)
        ),
        "web_trade_enabled": False,
        "execution_authority_revoked": True,
        "auto_dispatch_stopped": True,
        "active_orders": 0,
        "unknown_outcome": False,
        "reconcile_required": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    digest = _sha256(_canonical_bytes(core))
    try:
        return DeploymentLegacyMigrationCommodityCheckpointDTO.model_validate(
            {
                **core,
                "checkpoint_id": (
                    f"deployment-legacy-migration-commodity-checkpoint-{digest}"
                ),
                "checkpoint_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration Commodity checkpoint could not be built"
        ) from exc


def build_legacy_migration_commodity_checkpoint(
    **kwargs,
) -> DeploymentLegacyMigrationCommodityCheckpointDTO:
    return _build_legacy_migration_commodity_checkpoint(
        captured_at=_utc_now(), **kwargs
    )


def _verify_stable_facts(
    *,
    reconciliation_run_id: str,
    source_schema_version: str,
    source_state_raw_sha256: str,
    source_epoch_anchor_raw_sha256: str,
    inventory_raw_sha256: str,
    inventory_id: str,
    inventory_core_sha256: str,
    genesis_commitment_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_epoch_anchor_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
    commodity_checkpoint_raw: bytes,
    fresh_rpc: DeploymentRpcRecheckFactsDTO | dict[str, Any],
    current_created_at: datetime,
    captured_at: datetime | str,
):
    try:
        commodity = _parse_exact(
            commodity_checkpoint_raw,
            DeploymentLegacyMigrationCommodityCheckpointDTO,
            "legacy migration Commodity checkpoint",
        )
        fresh = DeploymentRpcRecheckFactsDTO.model_validate(
            _strict_model_input(fresh_rpc)
        )
    except (
        DeploymentLegacyMigrationError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration safety facts are invalid"
        ) from exc
    initial = commodity.initial_rpc
    expected_request, expected_owner, expected_recheck, expected_fresh = (
        derive_legacy_migration_rpc_identity(
            reconciliation_run_id=reconciliation_run_id,
            source_schema_version=source_schema_version,
            source_state_raw_sha256=source_state_raw_sha256,
            source_epoch_anchor_raw_sha256=source_epoch_anchor_raw_sha256,
            inventory_raw_sha256=inventory_raw_sha256,
            genesis_commitment_raw_sha256=genesis_commitment_raw_sha256,
            current_state_commitment_raw_sha256=current_state_commitment_raw_sha256,
            current_epoch_anchor_raw_sha256=current_epoch_anchor_raw_sha256,
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
            expected_account_hash=expected_account_hash,
        )
    )
    execution_sha = deployment_rpc_execution_facts_sha256(initial)
    expected_bindings = {
        "reconciliation_run_id": reconciliation_run_id,
        "source_schema_version": source_schema_version,
        "source_state_raw_sha256": source_state_raw_sha256,
        "source_epoch_anchor_raw_sha256": source_epoch_anchor_raw_sha256,
        "inventory_raw_sha256": inventory_raw_sha256,
        "inventory_id": inventory_id,
        "inventory_core_sha256": inventory_core_sha256,
        "genesis_commitment_raw_sha256": genesis_commitment_raw_sha256,
        "current_state_commitment_raw_sha256": current_state_commitment_raw_sha256,
        "current_epoch_anchor_raw_sha256": current_epoch_anchor_raw_sha256,
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "expected_account_hash": expected_account_hash,
    }
    if any(getattr(commodity, key) != value for key, value in expected_bindings.items()):
        raise DeploymentLegacyMigrationError(
            "legacy migration Commodity bindings changed"
        )
    if (
        initial.request_id != expected_request
        or initial.challenge != expected_owner
        or fresh.request_id != expected_request
        or fresh.owner_challenge != expected_owner
        or fresh.recheck_id != expected_recheck
        or fresh.fresh_challenge != expected_fresh
        or fresh.original_server_instance_id != initial.server_instance_id
        or fresh.server_instance_id != initial.server_instance_id
        or fresh.original_fact_generation != initial.fact_generation
        or fresh.fact_generation != initial.fact_generation
        or fresh.original_execution_facts_canonical_sha256 != execution_sha
        or fresh.execution_facts_canonical_sha256 != execution_sha
        or initial.account_hashes != [expected_account_hash]
        or fresh.account_hashes != [expected_account_hash]
        or initial.pending_send_outcomes != 0
        or fresh.pending_send_outcomes != 0
        or initial.active_orders
        or fresh.active_orders
        or initial.orders != fresh.orders
        or initial.trades != fresh.trades
        or initial.positions != fresh.positions
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration Windows facts are not stable and bound"
        )
    try:
        captured = _utc_timestamp(captured_at, "legacy migration captured_at")
    except DeploymentRestartReconciliationError as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration checkpoint timestamp is invalid"
        ) from exc
    captured_datetime = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    if (
        initial.captured_at < current_created_at
        or commodity.captured_at < initial.captured_at
        or fresh.captured_at < commodity.captured_at
        or captured_datetime < fresh.captured_at
        or captured_datetime - initial.captured_at > timedelta(seconds=30)
    ):
        raise DeploymentLegacyMigrationError(
            "legacy migration capture ordering or freshness is invalid"
        )
    return commodity, fresh, captured, execution_sha


def _build_legacy_migration_checkpoint(
    *,
    source_state_raw: bytes,
    source_epoch_anchor_raw: bytes,
    inventory_manifest_raw: bytes,
    genesis_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    reconciliation_run_id: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
    commodity_checkpoint_raw: bytes,
    fresh_rpc: DeploymentRpcRecheckFactsDTO | dict[str, Any],
    captured_at: datetime | str,
) -> DeploymentLegacyMigrationCheckpointDTO:
    source_version, source, inventory, genesis, current = (
        _verify_legacy_migration_chain(
            source_state_raw=source_state_raw,
            source_epoch_anchor_raw=source_epoch_anchor_raw,
            inventory_manifest_raw=inventory_manifest_raw,
            genesis_state_commitment_raw=genesis_state_commitment_raw,
            state_commitment_chain_raw=state_commitment_chain_raw,
            current_epoch_anchor_raw=current_epoch_anchor_raw,
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
        )
    )
    current_raw = state_commitment_chain_raw[-1]
    commodity, fresh, captured, execution_sha = _verify_stable_facts(
        reconciliation_run_id=reconciliation_run_id,
        source_schema_version=source_version,
        source_state_raw_sha256=_sha256(source_state_raw),
        source_epoch_anchor_raw_sha256=_sha256(source_epoch_anchor_raw),
        inventory_raw_sha256=_sha256(inventory_manifest_raw),
        inventory_id=inventory.inventory_id,
        inventory_core_sha256=inventory.inventory_core_sha256,
        genesis_commitment_raw_sha256=_sha256(genesis_state_commitment_raw),
        current_state_commitment_raw_sha256=_sha256(current_raw),
        current_epoch_anchor_raw_sha256=_sha256(current_epoch_anchor_raw),
        current_runtime_instance_id=current_runtime_instance_id,
        current_execution_epoch=current_execution_epoch,
        expected_account_hash=expected_account_hash,
        commodity_checkpoint_raw=commodity_checkpoint_raw,
        fresh_rpc=fresh_rpc,
        current_created_at=current.created_at,
        captured_at=captured_at,
    )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_deployment_legacy_migration_checkpoint_v1",
        "purpose": "record_non_authorizing_clean_legacy_migration_baseline",
        "mode": "LEGACY_MIGRATION_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "source_schema_version": source_version,
        "source_state_raw_sha256": _sha256(source_state_raw),
        "source_epoch_anchor_raw_sha256": _sha256(source_epoch_anchor_raw),
        "source_state": source.model_dump(mode="json"),
        "source_epoch_anchor": _parse_exact(
            source_epoch_anchor_raw,
            LegacyEpochAnchorV1DTO,
            "legacy source epoch anchor",
        ).model_dump(mode="json"),
        "inventory_id": inventory.inventory_id,
        "inventory_core_sha256": inventory.inventory_core_sha256,
        "inventory_raw_sha256": _sha256(inventory_manifest_raw),
        "inventory": inventory.model_dump(mode="json"),
        "genesis_source": genesis.genesis_source,
        "genesis_commitment_id": genesis.commitment_id,
        "genesis_commitment_raw_sha256": _sha256(genesis_state_commitment_raw),
        "genesis_commitment_core_sha256": genesis.state_commitment_core_sha256,
        "genesis_state_raw_sha256": genesis.state_raw_sha256,
        "current_state_commitment_id": current.commitment_id,
        "current_state_commitment_raw_sha256": _sha256(current_raw),
        "current_state_commitment_core_sha256": current.state_commitment_core_sha256,
        "current_state_generation": current.state_generation,
        "state_commitment_chain_sha256": _sha256(
            _canonical_bytes([_sha256(raw) for raw in state_commitment_chain_raw])
        ),
        "state_commitment_raw_sha256s": [
            _sha256(raw) for raw in state_commitment_chain_raw
        ],
        "state_commitments": [
            parse_exact_state_commitment(raw).model_dump(mode="json")
            for raw in state_commitment_chain_raw
        ],
        "current_epoch_anchor_raw_sha256": _sha256(current_epoch_anchor_raw),
        "current_epoch_anchor": _parse_exact_epoch_anchor(current_epoch_anchor_raw),
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "current_drain_state": current.state,
        "current_drain_state_raw_sha256": current.state_raw_sha256,
        "expected_account_hash": expected_account_hash,
        "commodity_checkpoint_id": commodity.checkpoint_id,
        "commodity_checkpoint_raw_sha256": _sha256(commodity_checkpoint_raw),
        "commodity_checkpoint_core_sha256": commodity.checkpoint_core_sha256,
        "commodity_checkpoint": commodity.model_dump(mode="json"),
        "fresh_rpc": fresh.model_dump(mode="json"),
        "initial_execution_facts_canonical_sha256": execution_sha,
        "fresh_execution_facts_canonical_sha256": execution_sha,
        "orders_snapshot_sha256": _sha256(_canonical_bytes(fresh.orders)),
        "active_orders_snapshot_sha256": _sha256(
            _canonical_bytes(fresh.active_orders)
        ),
        "trades_snapshot_sha256": _sha256(_canonical_bytes(fresh.trades)),
        "positions_snapshot_sha256": _sha256(_canonical_bytes(fresh.positions)),
        "captured_at": captured,
        "legacy_source_exact_bytes_verified": True,
        "legacy_migration_baseline_verified": True,
        "initial_execution_facts_baseline_recorded": True,
        "execution_facts_reconciliation_completed": True,
        "semantic_safety_unchanged": False,
        "external_high_water_verified": False,
        "custody_inventory_verified": False,
        "target_runtime_verified": False,
        "reconciliation_completed": False,
        "windows_fence_released": False,
        "authority_restore_allowed": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    digest = _sha256(_canonical_bytes(core))
    try:
        return DeploymentLegacyMigrationCheckpointDTO.model_validate(
            {
                **core,
                "checkpoint_id": f"deployment-legacy-migration-checkpoint-{digest}",
                "checkpoint_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration checkpoint could not be built"
        ) from exc


def build_legacy_migration_checkpoint(
    **kwargs,
) -> DeploymentLegacyMigrationCheckpointDTO:
    return _build_legacy_migration_checkpoint(captured_at=_utc_now(), **kwargs)


def verify_legacy_migration_checkpoint(
    *, checkpoint_raw: bytes, **kwargs
) -> DeploymentLegacyMigrationCheckpointDTO:
    checkpoint = _parse_exact(
        checkpoint_raw,
        DeploymentLegacyMigrationCheckpointDTO,
        "legacy migration checkpoint",
    )
    expected = _build_legacy_migration_checkpoint(
        captured_at=checkpoint.captured_at, **kwargs
    )
    if checkpoint != expected:
        raise DeploymentLegacyMigrationError(
            "legacy migration checkpoint does not match exact inputs"
        )
    return checkpoint


def build_legacy_migration_reconciliation_evidence(
    *, checkpoint_raw: bytes, **kwargs
) -> LegacyMigrationReconciliationEvidenceDTO:
    checkpoint = verify_legacy_migration_checkpoint(
        checkpoint_raw=checkpoint_raw, **kwargs
    )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_legacy_migration_reconciliation_v1",
        "purpose": "record_non_authorizing_clean_legacy_migration_evidence",
        "mode": "LEGACY_MIGRATION_BASELINE",
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint_raw_sha256": _sha256(checkpoint_raw),
        "checkpoint_core_sha256": checkpoint.checkpoint_core_sha256,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "inventory_id": checkpoint.inventory_id,
        "source_schema_version": checkpoint.source_schema_version,
        "source_state_raw_sha256": checkpoint.source_state_raw_sha256,
        "source_epoch_anchor_raw_sha256": (
            checkpoint.source_epoch_anchor_raw_sha256
        ),
        "inventory_raw_sha256": checkpoint.inventory_raw_sha256,
        "commodity_checkpoint_id": checkpoint.commodity_checkpoint_id,
        "genesis_commitment_raw_sha256": (
            checkpoint.genesis_commitment_raw_sha256
        ),
        "current_state_commitment_raw_sha256": (
            checkpoint.current_state_commitment_raw_sha256
        ),
        "current_epoch_anchor_raw_sha256": (
            checkpoint.current_epoch_anchor_raw_sha256
        ),
        "commodity_checkpoint_raw_sha256": (
            checkpoint.commodity_checkpoint_raw_sha256
        ),
        "current_runtime_instance_id": checkpoint.current_runtime_instance_id,
        "current_execution_epoch": checkpoint.current_execution_epoch,
        "expected_account_hash": checkpoint.expected_account_hash,
        "reconciled_at": checkpoint.captured_at.isoformat().replace("+00:00", "Z"),
        "legacy_source_exact_bytes_verified": True,
        "legacy_migration_baseline_verified": True,
        "initial_execution_facts_baseline_recorded": True,
        "execution_facts_reconciliation_completed": True,
        "semantic_safety_unchanged": False,
        "external_high_water_verified": False,
        "custody_inventory_verified": False,
        "target_runtime_verified": False,
        "reconciliation_completed": False,
        "windows_fence_released": False,
        "authority_restore_allowed": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    digest = _sha256(_canonical_bytes(core))
    try:
        return LegacyMigrationReconciliationEvidenceDTO.model_validate(
            {
                **core,
                "reconciliation_id": f"legacy-migration-reconciliation-{digest}",
                "reconciliation_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentLegacyMigrationError(
            "legacy migration evidence could not be built"
        ) from exc


def verify_legacy_migration_reconciliation_evidence(
    *, evidence_raw: bytes, checkpoint_raw: bytes, **kwargs
) -> LegacyMigrationReconciliationEvidenceDTO:
    evidence = _parse_exact(
        evidence_raw,
        LegacyMigrationReconciliationEvidenceDTO,
        "legacy migration reconciliation evidence",
    )
    expected = build_legacy_migration_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw, **kwargs
    )
    if evidence != expected:
        raise DeploymentLegacyMigrationError(
            "legacy migration evidence does not match exact inputs"
        )
    return evidence
