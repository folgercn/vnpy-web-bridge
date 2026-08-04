from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    CommodityInitialBaselineStateDTO,
    DeploymentInitialBaselineCommodityCheckpointDTO,
    DeploymentInitialBaselineCheckpointDTO,
    DeploymentRpcFactsDTO,
    DeploymentRpcRecheckFactsDTO,
    InitialBaselineReconciliationEvidenceDTO,
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


class DeploymentInitialBaselineError(RuntimeError):
    """C1b fresh initial-baseline evidence is invalid or inconsistently bound."""


_BASELINE_EMPTY_FIELDS = {
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_exact(raw: bytes, model: type, label: str):
    if not isinstance(raw, bytes):
        raise DeploymentInitialBaselineError(f"{label} raw value must be bytes")
    try:
        value = model.model_validate_json(raw)
        expected = _artifact_bytes(value.model_dump(mode="json"))
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(f"{label} is invalid") from exc
    if raw != expected:
        raise DeploymentInitialBaselineError(f"{label} bytes are not canonical")
    return value


def _strict_model_input(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    return value


def canonical_initial_baseline_checkpoint_bytes(
    checkpoint: DeploymentInitialBaselineCheckpointDTO,
) -> bytes:
    try:
        value = DeploymentInitialBaselineCheckpointDTO.model_validate(checkpoint)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline checkpoint is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_initial_baseline_commodity_checkpoint_bytes(
    checkpoint: DeploymentInitialBaselineCommodityCheckpointDTO,
) -> bytes:
    try:
        value = DeploymentInitialBaselineCommodityCheckpointDTO.model_validate(
            checkpoint
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial Commodity baseline checkpoint is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_initial_baseline_evidence_bytes(
    evidence: InitialBaselineReconciliationEvidenceDTO,
) -> bytes:
    try:
        value = InitialBaselineReconciliationEvidenceDTO.model_validate(evidence)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline evidence is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def derive_initial_baseline_rpc_identity(
    *,
    reconciliation_run_id: str,
    genesis_commitment_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
) -> tuple[str, str, str, str]:
    core = {
        "mode": "INITIAL_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "genesis_commitment_raw_sha256": genesis_commitment_raw_sha256,
        "current_state_commitment_raw_sha256": (
            current_state_commitment_raw_sha256
        ),
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "expected_account_hash": expected_account_hash,
    }
    owner_digest = _sha256(_canonical_bytes({**core, "capture": "INITIAL"}))
    fresh_digest = _sha256(_canonical_bytes({**core, "capture": "FRESH_RECHECK"}))
    return (
        f"initial-baseline-{owner_digest}",
        f"baseline-owner-{owner_digest}",
        f"deployment-recheck-{fresh_digest}",
        f"baseline-fresh-{fresh_digest}",
    )


def _build_initial_baseline_commodity_checkpoint(
    *,
    reconciliation_run_id: str,
    genesis_commitment_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    expected_account_hash: str,
    commodity_state: CommodityInitialBaselineStateDTO | dict[str, Any],
    initial_rpc: DeploymentRpcFactsDTO | dict[str, Any],
    captured_at: datetime | str,
) -> DeploymentInitialBaselineCommodityCheckpointDTO:
    try:
        initial = DeploymentRpcFactsDTO.model_validate(
            _strict_model_input(initial_rpc)
        )
        state = CommodityInitialBaselineStateDTO.model_validate(
            _strict_model_input(commodity_state)
        )
        captured = _utc_timestamp(captured_at, "initial Commodity captured_at")
    except (DeploymentRestartReconciliationError, TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial Commodity baseline inputs are invalid"
        ) from exc
    expected_request, expected_owner, _recheck, _fresh = (
        derive_initial_baseline_rpc_identity(
            reconciliation_run_id=reconciliation_run_id,
            genesis_commitment_raw_sha256=genesis_commitment_raw_sha256,
            current_state_commitment_raw_sha256=current_state_commitment_raw_sha256,
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
        raise DeploymentInitialBaselineError(
            "initial Commodity baseline RPC is not safely bound"
        )
    core: dict[str, Any] = {
        "schema_version": (
            "web_bridge_deployment_initial_baseline_commodity_checkpoint_v1"
        ),
        "purpose": "record_exact_non_authorizing_commodity_initial_baseline",
        "mode": "INITIAL_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "genesis_commitment_raw_sha256": genesis_commitment_raw_sha256,
        "current_state_commitment_raw_sha256": (
            current_state_commitment_raw_sha256
        ),
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
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
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    try:
        digest = _sha256(_canonical_bytes(core))
        return DeploymentInitialBaselineCommodityCheckpointDTO.model_validate(
            {
                **core,
                "checkpoint_id": (
                    f"deployment-initial-baseline-commodity-checkpoint-{digest}"
                ),
                "checkpoint_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial Commodity baseline checkpoint core is invalid"
        ) from exc


def build_initial_baseline_commodity_checkpoint(
    **kwargs,
) -> DeploymentInitialBaselineCommodityCheckpointDTO:
    return _build_initial_baseline_commodity_checkpoint(
        captured_at=_utc_now(), **kwargs
    )


def _verify_fresh_bootstrap_chain(
    *,
    genesis_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
):
    if len(state_commitment_chain_raw) < 3 or (
        state_commitment_chain_raw[0] != genesis_state_commitment_raw
    ):
        raise DeploymentInitialBaselineError(
            "fresh bootstrap chain must include genesis and online takeover"
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
            ):
                raise DeploymentInitialBaselineError(
                    "fresh bootstrap commitment chain is not contiguous"
                )
            if (
                state["state"] != "RESTARTED_FROZEN"
                or state["drain_epoch"] != 0
                or state["receipt_consumed"] is not False
                or any(state[field] is not None for field in _BASELINE_EMPTY_FIELDS)
                or state["blockers"] != []
                or state["freeze_reason"]
                != "initial_bootstrap_requires_reconciliation"
            ):
                raise DeploymentInitialBaselineError(
                    "fresh bootstrap state lineage is not pristine and frozen"
                )
            commitments.append(commitment)
            previous_raw = raw
            previous_created_at = commitment.created_at
    except (
        DeploymentRestartReconciliationError,
        DeploymentStateCommitmentError,
    ) as exc:
        raise DeploymentInitialBaselineError(
            "fresh bootstrap commitment chain is invalid"
        ) from exc

    genesis = commitments[0]
    if (
        genesis.genesis_source != "fresh_bootstrap"
        or genesis.source_state_raw_sha256 is not None
        or genesis.source_epoch_anchor_raw_sha256 is not None
        or genesis.state["execution_epoch"] != 0
        or genesis.state["runtime_instance_id"] != "bootstrap-frozen-runtime"
    ):
        raise DeploymentInitialBaselineError("fresh bootstrap genesis is invalid")
    bootstrap_activation = commitments[1].state
    if (
        bootstrap_activation["execution_epoch"] != 1
        or bootstrap_activation["runtime_instance_id"]
        != "bootstrap-frozen-runtime"
    ):
        raise DeploymentInitialBaselineError(
            "fresh bootstrap activation transition is invalid"
        )
    previous_state = bootstrap_activation
    for commitment in commitments[2:]:
        state = commitment.state
        if (
            state["execution_epoch"] != previous_state["execution_epoch"] + 1
            or state["runtime_instance_id"] == previous_state["runtime_instance_id"]
        ):
            raise DeploymentInitialBaselineError(
                "fresh bootstrap online runtime transition is invalid"
            )
        previous_state = state
    current = commitments[-1]
    if (
        current.state["runtime_instance_id"] != current_runtime_instance_id
        or current.state["execution_epoch"] != current_execution_epoch
        or current_runtime_instance_id == "bootstrap-frozen-runtime"
        or current_execution_epoch < 2
    ):
        raise DeploymentInitialBaselineError(
            "current online runtime does not bind the bootstrap chain head"
        )
    try:
        anchor = _parse_exact_epoch_anchor(current_epoch_anchor_raw)
    except DeploymentRestartReconciliationError as exc:
        raise DeploymentInitialBaselineError("current epoch anchor is invalid") from exc
    if (
        anchor["state_generation"] != current.state_generation
        or anchor["state_commitment_raw_sha256"]
        != _sha256(state_commitment_chain_raw[-1])
        or anchor["drain_epoch"] != current.state["drain_epoch"]
        or anchor["execution_epoch"] != current.state["execution_epoch"]
    ):
        raise DeploymentInitialBaselineError(
            "current epoch anchor does not bind the bootstrap chain head"
        )
    return genesis, current


def _verify_stable_baseline_facts(
    *,
    genesis_raw_sha256: str,
    current_raw_sha256: str,
    reconciliation_run_id: str,
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
            DeploymentInitialBaselineCommodityCheckpointDTO,
            "initial Commodity baseline checkpoint",
        )
        fresh = DeploymentRpcRecheckFactsDTO.model_validate(
            _strict_model_input(fresh_rpc)
        )
    except (
        DeploymentInitialBaselineError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline safety facts are invalid"
        ) from exc
    initial = commodity.initial_rpc
    expected_request, expected_owner, expected_recheck, expected_fresh = (
        derive_initial_baseline_rpc_identity(
            reconciliation_run_id=reconciliation_run_id,
            genesis_commitment_raw_sha256=genesis_raw_sha256,
            current_state_commitment_raw_sha256=current_raw_sha256,
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
            expected_account_hash=expected_account_hash,
        )
    )
    initial_execution_sha = deployment_rpc_execution_facts_sha256(initial)
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
        or fresh.original_execution_facts_canonical_sha256
        != initial_execution_sha
        or fresh.execution_facts_canonical_sha256 != initial_execution_sha
        or initial.account_hashes != [expected_account_hash]
        or fresh.account_hashes != [expected_account_hash]
        or initial.pending_send_outcomes != 0
        or fresh.pending_send_outcomes != 0
        or initial.active_orders
        or fresh.active_orders
        or initial.orders != fresh.orders
        or initial.trades != fresh.trades
        or initial.positions != fresh.positions
        or commodity.reconciliation_run_id != reconciliation_run_id
        or commodity.genesis_commitment_raw_sha256 != genesis_raw_sha256
        or commodity.current_state_commitment_raw_sha256 != current_raw_sha256
        or commodity.current_runtime_instance_id != current_runtime_instance_id
        or commodity.current_execution_epoch != current_execution_epoch
    ):
        raise DeploymentInitialBaselineError(
            "initial and fresh Windows baseline facts are not stable and bound"
        )
    try:
        captured = _utc_timestamp(captured_at, "initial baseline captured_at")
    except DeploymentRestartReconciliationError as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline checkpoint timestamp is invalid"
        ) from exc
    captured_datetime = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    if (
        initial.captured_at < current_created_at
        or commodity.captured_at < initial.captured_at
        or fresh.captured_at < commodity.captured_at
        or captured_datetime < fresh.captured_at
        or captured_datetime - initial.captured_at > timedelta(seconds=30)
    ):
        raise DeploymentInitialBaselineError(
            "initial baseline capture ordering or freshness is invalid"
        )
    return commodity, initial, fresh, captured, initial_execution_sha


def _build_initial_baseline_checkpoint(
    *,
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
) -> DeploymentInitialBaselineCheckpointDTO:
    genesis, current = _verify_fresh_bootstrap_chain(
        genesis_state_commitment_raw=genesis_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
        current_runtime_instance_id=current_runtime_instance_id,
        current_execution_epoch=current_execution_epoch,
    )
    current_raw = state_commitment_chain_raw[-1]
    commodity, initial, fresh, captured, execution_sha = (
        _verify_stable_baseline_facts(
            genesis_raw_sha256=_sha256(genesis_state_commitment_raw),
            current_raw_sha256=_sha256(current_raw),
            reconciliation_run_id=reconciliation_run_id,
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
            expected_account_hash=expected_account_hash,
            commodity_checkpoint_raw=commodity_checkpoint_raw,
            fresh_rpc=fresh_rpc,
            current_created_at=current.created_at,
            captured_at=captured_at,
        )
    )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_deployment_initial_baseline_checkpoint_v1",
        "purpose": "record_non_authorizing_fresh_initial_execution_baseline",
        "mode": "INITIAL_BASELINE",
        "reconciliation_run_id": reconciliation_run_id,
        "genesis_commitment_id": genesis.commitment_id,
        "genesis_commitment_raw_sha256": _sha256(genesis_state_commitment_raw),
        "genesis_commitment_core_sha256": genesis.state_commitment_core_sha256,
        "genesis_state_raw_sha256": genesis.state_raw_sha256,
        "current_state_commitment_id": current.commitment_id,
        "current_state_commitment_raw_sha256": _sha256(current_raw),
        "current_state_commitment_core_sha256": (
            current.state_commitment_core_sha256
        ),
        "current_state_generation": current.state_generation,
        "state_commitment_chain_sha256": _sha256(
            _canonical_bytes([_sha256(raw) for raw in state_commitment_chain_raw])
        ),
        "current_epoch_anchor_raw_sha256": _sha256(current_epoch_anchor_raw),
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
        "fresh_genesis_lineage_verified": True,
        "custody_inventory_verified": False,
        "prior_execution_facts_available": False,
        "comparison_to_prebootstrap_facts_performed": False,
        "initial_execution_facts_baseline_recorded": True,
        "execution_facts_reconciliation_completed": True,
        "semantic_safety_unchanged": False,
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
    try:
        digest = _sha256(_canonical_bytes(core))
        return DeploymentInitialBaselineCheckpointDTO.model_validate(
            {
                **core,
                "checkpoint_id": f"deployment-initial-baseline-checkpoint-{digest}",
                "checkpoint_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline checkpoint core is invalid"
        ) from exc


def build_initial_baseline_checkpoint(**kwargs) -> DeploymentInitialBaselineCheckpointDTO:
    """Build fresh-bootstrap C1b evidence with this module's trusted clock."""

    return _build_initial_baseline_checkpoint(captured_at=_utc_now(), **kwargs)


def verify_initial_baseline_checkpoint(
    *, checkpoint_raw: bytes, **kwargs
) -> DeploymentInitialBaselineCheckpointDTO:
    checkpoint = _parse_exact(
        checkpoint_raw,
        DeploymentInitialBaselineCheckpointDTO,
        "initial baseline checkpoint",
    )
    expected = _build_initial_baseline_checkpoint(
        captured_at=checkpoint.captured_at, **kwargs
    )
    if checkpoint != expected:
        raise DeploymentInitialBaselineError(
            "initial baseline checkpoint does not match exact inputs"
        )
    return checkpoint


def build_initial_baseline_reconciliation_evidence(
    *, checkpoint_raw: bytes, **kwargs
) -> InitialBaselineReconciliationEvidenceDTO:
    checkpoint = verify_initial_baseline_checkpoint(
        checkpoint_raw=checkpoint_raw, **kwargs
    )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_initial_baseline_reconciliation_v1",
        "purpose": "record_non_authorizing_fresh_initial_baseline_evidence",
        "mode": "INITIAL_BASELINE",
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint_raw_sha256": _sha256(checkpoint_raw),
        "checkpoint_core_sha256": checkpoint.checkpoint_core_sha256,
        "commodity_checkpoint_raw_sha256": (
            checkpoint.commodity_checkpoint_raw_sha256
        ),
        "genesis_commitment_raw_sha256": (
            checkpoint.genesis_commitment_raw_sha256
        ),
        "current_state_commitment_raw_sha256": (
            checkpoint.current_state_commitment_raw_sha256
        ),
        "current_epoch_anchor_raw_sha256": (
            checkpoint.current_epoch_anchor_raw_sha256
        ),
        "current_runtime_instance_id": checkpoint.current_runtime_instance_id,
        "current_execution_epoch": checkpoint.current_execution_epoch,
        "expected_account_hash": checkpoint.expected_account_hash,
        "reconciled_at": checkpoint.captured_at.isoformat().replace("+00:00", "Z"),
        "fresh_initial_baseline_verified": True,
        "custody_inventory_verified": False,
        "initial_execution_facts_baseline_recorded": True,
        "execution_facts_reconciliation_completed": True,
        "semantic_safety_unchanged": False,
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
    try:
        digest = _sha256(_canonical_bytes(core))
        return InitialBaselineReconciliationEvidenceDTO.model_validate(
            {
                **core,
                "reconciliation_id": f"initial-baseline-reconciliation-{digest}",
                "reconciliation_core_sha256": digest,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentInitialBaselineError(
            "initial baseline evidence core is invalid"
        ) from exc


def verify_initial_baseline_reconciliation_evidence(
    *, evidence_raw: bytes, checkpoint_raw: bytes, **kwargs
) -> InitialBaselineReconciliationEvidenceDTO:
    evidence = _parse_exact(
        evidence_raw,
        InitialBaselineReconciliationEvidenceDTO,
        "initial baseline reconciliation evidence",
    )
    expected = build_initial_baseline_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw, **kwargs
    )
    if evidence != expected:
        raise DeploymentInitialBaselineError(
            "initial baseline evidence does not match exact inputs"
        )
    return evidence
