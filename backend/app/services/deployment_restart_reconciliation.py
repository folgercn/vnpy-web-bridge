from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    DeploymentOnlineRecheckCheckpointDTO,
    DeploymentPostRestartCheckpointDTO,
    DeploymentRpcRecheckFactsDTO,
    SafeRestartReceiptDTO,
    SafeRestartReconciliationEvidenceDTO,
)
from app.services.deployment_consume_wal import (
    DeploymentConsumeWalError,
    parse_exact_consume_intent,
    parse_exact_consume_marker,
)
from app.services.deployment_online_recheck import (
    DeploymentOnlineRecheckError,
    verify_safe_restart_online_recheck,
)
from app.services.deployment_state_commitment import (
    DeploymentStateCommitmentError,
    parse_exact_state_commitment,
)


class DeploymentRestartReconciliationError(RuntimeError):
    """C1a planned-restart evidence is malformed or inconsistently bound."""


_STATE_V3_FIELDS = {
    "schema_version",
    "state_generation",
    "previous_state_commitment_raw_sha256",
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
    "blockers",
    "expires_at",
    "freeze_reason",
    "updated_at",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _artifact_bytes(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_exact_state_v3(state: object) -> dict[str, Any]:
    if not isinstance(state, dict) or set(state) != _STATE_V3_FIELDS:
        raise DeploymentRestartReconciliationError(
            "deployment drain state v3 fields are invalid"
        )
    if (
        state.get("schema_version") != "web_bridge_deployment_drain_state_v3"
        or type(state.get("state_generation")) is not int
        or state["state_generation"] < 1
        or type(state.get("drain_epoch")) is not int
        or state["drain_epoch"] < 0
        or type(state.get("execution_epoch")) is not int
        or state["execution_epoch"] < 0
        or state.get("state")
        not in {
            "RUNNING",
            "DRAINING",
            "DRAIN_BLOCKED",
            "SAFE_TO_RESTART",
            "RESTARTED_FROZEN",
        }
        or not isinstance(state.get("runtime_instance_id"), str)
        or not _IDENTIFIER_RE.fullmatch(state["runtime_instance_id"])
        or not isinstance(state.get("blockers"), list)
        or any(not isinstance(value, str) or not value for value in state["blockers"])
    ):
        raise DeploymentRestartReconciliationError(
            "deployment drain state v3 values are invalid"
        )
    updated_at = state.get("updated_at")
    if not isinstance(updated_at, str):
        raise DeploymentRestartReconciliationError(
            "deployment drain state timestamp is invalid"
        )
    _utc_timestamp(updated_at, "deployment drain state updated_at")
    for field in (
        "active_request_id",
        "active_receipt_id",
        "consume_id",
        "consumed_receipt_id",
        "consumed_online_recheck_id",
        "active_online_recheck_id",
        "last_invalidated_online_recheck_id",
        "last_invalidated_receipt_id",
    ):
        value = state[field]
        if value is not None and (
            not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value)
        ):
            raise DeploymentRestartReconciliationError(
                f"deployment drain state {field} is invalid"
            )
    for field in (
        "active_request_sha256",
        "active_receipt_raw_sha256",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
        "active_online_recheck_raw_sha256",
        "active_recheck_checkpoint_raw_sha256",
    ):
        value = state[field]
        if value is not None and (
            not isinstance(value, str)
            or not _SHA256_RE.fullmatch(value)
            or value == "0" * 64
        ):
            raise DeploymentRestartReconciliationError(
                f"deployment drain state {field} is invalid"
            )
    for field in ("consumed_at", "online_rechecked_at", "expires_at"):
        value = state[field]
        if value is not None:
            _utc_timestamp(value, f"deployment drain state {field}")
    if state["freeze_reason"] is not None and (
        not isinstance(state["freeze_reason"], str) or not state["freeze_reason"]
    ):
        raise DeploymentRestartReconciliationError(
            "deployment drain state freeze_reason is invalid"
        )
    if type(state["receipt_consumed"]) is not bool:
        raise DeploymentRestartReconciliationError(
            "deployment drain state receipt_consumed is invalid"
        )
    previous = state.get("previous_state_commitment_raw_sha256")
    if (state["state_generation"] == 1 and previous is not None) or (
        state["state_generation"] > 1
        and (not isinstance(previous, str) or not _SHA256_RE.fullmatch(previous))
    ):
        raise DeploymentRestartReconciliationError(
            "deployment drain state predecessor is invalid"
        )
    return state


def _parse_exact_epoch_anchor(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise DeploymentRestartReconciliationError(
            "epoch anchor raw value must be bytes"
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentRestartReconciliationError("epoch anchor is invalid") from exc
    expected_fields = {
        "schema_version",
        "state_generation",
        "state_commitment_raw_sha256",
        "drain_epoch",
        "execution_epoch",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("schema_version") != "web_bridge_deployment_drain_epoch_anchor_v2"
        or type(value.get("state_generation")) is not int
        or value["state_generation"] < 1
        or not isinstance(value.get("state_commitment_raw_sha256"), str)
        or not _SHA256_RE.fullmatch(value["state_commitment_raw_sha256"])
        or type(value.get("drain_epoch")) is not int
        or type(value.get("execution_epoch")) is not int
        or raw != _artifact_bytes(value)
    ):
        raise DeploymentRestartReconciliationError("epoch anchor is invalid")
    return value


def derive_post_restart_recheck_identity(
    *,
    reconciliation_run_id: str,
    receipt_id: str,
    consume_marker_raw_sha256: str,
    current_state_commitment_raw_sha256: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
) -> tuple[str, str]:
    """Derive an epoch-bound recheck identity without granting authority."""

    core = {
        "mode": "PLANNED_RESTART",
        "reconciliation_run_id": reconciliation_run_id,
        "receipt_id": receipt_id,
        "consume_marker_raw_sha256": consume_marker_raw_sha256,
        "current_state_commitment_raw_sha256": (current_state_commitment_raw_sha256),
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
    }
    digest = _sha256(_canonical_bytes(core))
    return f"deployment-recheck-{digest}", f"post-restart-{digest}"


def _utc_timestamp(value: datetime | str, field: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DeploymentRestartReconciliationError(f"{field} is invalid") from exc
    else:
        raise DeploymentRestartReconciliationError(f"{field} must be a UTC timestamp")
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
    ):
        raise DeploymentRestartReconciliationError(f"{field} must be UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def _parse_exact(raw: bytes, model: type, label: str):
    if not isinstance(raw, bytes):
        raise DeploymentRestartReconciliationError(f"{label} raw value must be bytes")
    try:
        value = model.model_validate_json(raw)
        expected = _artifact_bytes(value.model_dump(mode="json"))
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(f"{label} is invalid") from exc
    if raw != expected:
        raise DeploymentRestartReconciliationError(f"{label} bytes are not canonical")
    return value


def canonical_post_restart_checkpoint_bytes(
    checkpoint: DeploymentPostRestartCheckpointDTO,
) -> bytes:
    try:
        value = DeploymentPostRestartCheckpointDTO.model_validate(checkpoint)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(
            "post-restart checkpoint is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def canonical_restart_reconciliation_bytes(
    evidence: SafeRestartReconciliationEvidenceDTO,
) -> bytes:
    try:
        value = SafeRestartReconciliationEvidenceDTO.model_validate(evidence)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(
            "restart reconciliation evidence is invalid"
        ) from exc
    return _artifact_bytes(value.model_dump(mode="json"))


def _verify_current_commitment_chain(
    *,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
):
    if not state_commitment_chain_raw:
        raise DeploymentRestartReconciliationError("state commitment chain is empty")
    if state_commitment_chain_raw[0] != preconsume_state_commitment_raw:
        raise DeploymentRestartReconciliationError(
            "state commitment chain does not start at the preconsume commitment"
        )
    parsed = []
    previous_raw: bytes | None = None
    previous_generation: int | None = None
    previous_created_at: datetime | None = None
    try:
        for raw in state_commitment_chain_raw:
            commitment = parse_exact_state_commitment(raw)
            _require_exact_state_v3(commitment.state)
            if previous_raw is not None and (
                commitment.previous_state_commitment_raw_sha256 != _sha256(previous_raw)
                or commitment.state_generation != previous_generation + 1
                or commitment.created_at < previous_created_at
            ):
                raise DeploymentRestartReconciliationError(
                    "state commitment chain is not contiguous"
                )
            parsed.append(commitment)
            previous_raw = raw
            previous_generation = commitment.state_generation
            previous_created_at = commitment.created_at
    except DeploymentStateCommitmentError as exc:
        raise DeploymentRestartReconciliationError(
            "state commitment chain is invalid"
        ) from exc
    return parsed, parsed[0], parsed[-1], state_commitment_chain_raw[-1]


def _verify_consumed_restart_transitions(
    *,
    commitments: list[Any],
    prestate: dict[str, Any],
    marker: Any,
    online: Any,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
) -> None:
    if len(commitments) < 3:
        raise DeploymentRestartReconciliationError(
            "consumed restart commitment chain is incomplete"
        )
    states = [_require_exact_state_v3(commitment.state) for commitment in commitments]
    consumed = states[1]
    unchanged_on_consume = _STATE_V3_FIELDS - {
        "state_generation",
        "previous_state_commitment_raw_sha256",
        "receipt_consumed",
        "consumed_at",
        "consume_id",
        "consumed_receipt_id",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_id",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
        "freeze_reason",
        "updated_at",
    }
    if any(consumed[field] != prestate[field] for field in unchanged_on_consume) or (
        consumed["state"] != "SAFE_TO_RESTART"
        or consumed["receipt_consumed"] is not True
        or consumed["consumed_at"] != marker.committed_at.isoformat()
        or consumed["consume_id"] != marker.consume_marker_id
        or consumed["consumed_receipt_id"] != marker.receipt_id
        or consumed["consume_intent_raw_sha256"] != _sha256(consume_intent_raw)
        or consumed["consume_marker_raw_sha256"] != _sha256(consume_marker_raw)
        or consumed["consume_state_projection_sha256"]
        != marker.consume_state_projection_sha256
        or consumed["consumed_online_recheck_id"] != online.online_recheck_id
        or consumed["consumed_online_recheck_raw_sha256"]
        != _sha256(consumed_online_recheck_raw)
        or consumed["preconsume_state_commitment_raw_sha256"]
        != _sha256(preconsume_state_commitment_raw)
        or consumed["freeze_reason"]
        != "safe_restart_consumed_deployment_still_inactive"
    ):
        raise DeploymentRestartReconciliationError(
            "consume transition is not the exact durable consumed state"
        )

    frozen_invariants = {
        "state": "RESTARTED_FROZEN",
        "drain_epoch": marker.drain_epoch,
        "active_request_id": marker.request_id,
        "active_request_sha256": prestate["active_request_sha256"],
        "active_receipt_id": None,
        "active_receipt_raw_sha256": marker.receipt_raw_sha256,
        "receipt_consumed": True,
        "consumed_at": marker.committed_at.isoformat(),
        "consume_id": marker.consume_marker_id,
        "consumed_receipt_id": marker.receipt_id,
        "consume_intent_raw_sha256": _sha256(consume_intent_raw),
        "consume_marker_raw_sha256": _sha256(consume_marker_raw),
        "consume_state_projection_sha256": marker.consume_state_projection_sha256,
        "consumed_online_recheck_id": online.online_recheck_id,
        "consumed_online_recheck_raw_sha256": _sha256(consumed_online_recheck_raw),
        "preconsume_state_commitment_raw_sha256": _sha256(
            preconsume_state_commitment_raw
        ),
        "active_online_recheck_id": None,
        "active_online_recheck_raw_sha256": None,
        "active_recheck_checkpoint_raw_sha256": None,
        "online_rechecked_at": None,
        "last_invalidated_online_recheck_id": marker.online_recheck_id,
        "last_invalidated_receipt_id": marker.receipt_id,
        "blockers": ["process_restarted_consumed_receipt_requires_reconciliation"],
        "expires_at": prestate["expires_at"],
        "freeze_reason": (
            "process_restarted_consumed_receipt_requires_reconciliation"
        ),
    }
    previous = consumed
    for state in states[2:]:
        if (
            any(state[field] != value for field, value in frozen_invariants.items())
            or state["execution_epoch"] != previous["execution_epoch"] + 1
            or state["runtime_instance_id"] == previous["runtime_instance_id"]
        ):
            raise DeploymentRestartReconciliationError(
                "post-consume restart transition lineage is invalid"
            )
        previous = state


def _build_post_restart_checkpoint(
    *,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    reconciliation_run_id: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    windows_rpc: DeploymentRpcRecheckFactsDTO | dict[str, Any],
    captured_at: datetime | str,
) -> DeploymentPostRestartCheckpointDTO:
    """Build C1a PLANNED_RESTART evidence without granting any authority."""

    try:
        intent = parse_exact_consume_intent(consume_intent_raw)
        marker = parse_exact_consume_marker(
            consume_marker_raw,
            intent_raw=consume_intent_raw,
        )
    except DeploymentConsumeWalError as exc:
        raise DeploymentRestartReconciliationError(
            "consume WAL chain is invalid"
        ) from exc
    try:
        online = verify_safe_restart_online_recheck(
            artifact_raw=consumed_online_recheck_raw,
            receipt_raw=receipt_raw,
            original_checkpoint_raw=original_checkpoint_raw,
            recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        )
    except DeploymentOnlineRecheckError as exc:
        raise DeploymentRestartReconciliationError(
            "consumed online recheck chain is invalid"
        ) from exc
    consumed_checkpoint = _parse_exact(
        consumed_recheck_checkpoint_raw,
        DeploymentOnlineRecheckCheckpointDTO,
        "consumed recheck checkpoint",
    )
    receipt = _parse_exact(receipt_raw, SafeRestartReceiptDTO, "safe restart receipt")
    if (
        marker.online_recheck_id != online.online_recheck_id
        or marker.online_recheck_raw_sha256 != _sha256(consumed_online_recheck_raw)
        or marker.online_recheck_core_sha256 != online.recheck_core_sha256
    ):
        raise DeploymentRestartReconciliationError(
            "consume marker does not bind the exact online recheck"
        )
    commitments, precommit, current_commitment, current_commitment_raw = (
        _verify_current_commitment_chain(
            preconsume_state_commitment_raw=preconsume_state_commitment_raw,
            state_commitment_chain_raw=state_commitment_chain_raw,
        )
    )
    prestate = _require_exact_state_v3(precommit.state)
    current_state = _require_exact_state_v3(current_commitment.state)
    _verify_consumed_restart_transitions(
        commitments=commitments,
        prestate=prestate,
        marker=marker,
        online=online,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
    )
    anchor = _parse_exact_epoch_anchor(current_epoch_anchor_raw)
    if (
        marker.receipt_raw_sha256 != _sha256(receipt_raw)
        or marker.receipt_id != receipt.receipt_id
        or marker.receipt_core_sha256 != receipt.receipt_core_sha256
        or marker.request_id != receipt.request_id
        or marker.deployment_attempt_id != receipt.deployment_attempt_id
        or marker.release_plan_core_sha256 != receipt.release_plan_core_sha256
        or marker.restart_action_sha256 != receipt.restart_action_sha256
        or marker.drain_epoch != receipt.drain_epoch
        or marker.execution_epoch != receipt.execution_epoch
        or marker.runtime_instance_id != receipt.issuer_runtime_instance_id
        or marker.preconsume_state_commitment_id != precommit.commitment_id
        or marker.preconsume_state_commitment_raw_sha256
        != _sha256(preconsume_state_commitment_raw)
        or marker.preconsume_state_generation != precommit.state_generation
        or prestate["state"] != "SAFE_TO_RESTART"
        or prestate["receipt_consumed"] is not False
        or any(
            prestate[field] is not None
            for field in (
                "consumed_at",
                "consume_id",
                "consumed_receipt_id",
                "consume_intent_raw_sha256",
                "consume_marker_raw_sha256",
                "consume_state_projection_sha256",
                "consumed_online_recheck_id",
                "consumed_online_recheck_raw_sha256",
                "preconsume_state_commitment_raw_sha256",
            )
        )
        or prestate["active_request_id"] != marker.request_id
        or prestate["active_receipt_id"] != marker.receipt_id
        or prestate["active_receipt_raw_sha256"] != marker.receipt_raw_sha256
        or prestate["active_online_recheck_id"] != marker.online_recheck_id
        or prestate["active_online_recheck_raw_sha256"]
        != marker.online_recheck_raw_sha256
        or prestate["active_recheck_checkpoint_raw_sha256"]
        != online.recheck_checkpoint_raw_sha256
        or prestate["online_rechecked_at"] != online.checked_at.isoformat()
        or prestate["runtime_instance_id"] != marker.runtime_instance_id
        or prestate["drain_epoch"] != marker.drain_epoch
        or prestate["execution_epoch"] != marker.execution_epoch
    ):
        raise DeploymentRestartReconciliationError(
            "consume marker does not bind the exact preconsume commitment"
        )
    if (
        anchor["state_generation"] != current_commitment.state_generation
        or anchor["state_commitment_raw_sha256"] != _sha256(current_commitment_raw)
        or anchor["drain_epoch"] != current_state["drain_epoch"]
        or anchor["execution_epoch"] != current_state["execution_epoch"]
    ):
        raise DeploymentRestartReconciliationError(
            "epoch anchor does not bind the current state commitment"
        )
    expected_current_consumption = (
        current_state.get("state") == "RESTARTED_FROZEN"
        and current_state.get("runtime_instance_id") == current_runtime_instance_id
        and current_state.get("execution_epoch") == current_execution_epoch
        and current_state.get("drain_epoch") == marker.drain_epoch
        and current_state.get("active_request_id") == marker.request_id
        and current_state.get("active_request_sha256")
        == prestate["active_request_sha256"]
        and current_state.get("active_receipt_id") is None
        and current_state.get("active_receipt_raw_sha256") == marker.receipt_raw_sha256
        and current_state.get("active_online_recheck_id") is None
        and current_state.get("active_online_recheck_raw_sha256") is None
        and current_state.get("active_recheck_checkpoint_raw_sha256") is None
        and current_state.get("online_rechecked_at") is None
        and current_state.get("last_invalidated_receipt_id") == marker.receipt_id
        and current_state.get("last_invalidated_online_recheck_id")
        == marker.online_recheck_id
        and current_state.get("receipt_consumed") is True
        and current_state.get("consumed_at") == marker.committed_at.isoformat()
        and current_state.get("consume_id") == marker.consume_marker_id
        and current_state.get("consumed_receipt_id") == marker.receipt_id
        and current_state.get("consume_intent_raw_sha256")
        == _sha256(consume_intent_raw)
        and current_state.get("consume_marker_raw_sha256")
        == _sha256(consume_marker_raw)
        and current_state.get("consume_state_projection_sha256")
        == marker.consume_state_projection_sha256
        and current_state.get("consumed_online_recheck_id") == online.online_recheck_id
        and current_state.get("consumed_online_recheck_raw_sha256")
        == _sha256(consumed_online_recheck_raw)
        and current_state.get("preconsume_state_commitment_raw_sha256")
        == _sha256(preconsume_state_commitment_raw)
        and current_state.get("blockers")
        == ["process_restarted_consumed_receipt_requires_reconciliation"]
        and current_state.get("freeze_reason")
        == "process_restarted_consumed_receipt_requires_reconciliation"
        and current_state.get("expires_at") == prestate["expires_at"]
        and current_state.get("expires_at") == receipt.expires_at.isoformat()
    )
    if not expected_current_consumption:
        raise DeploymentRestartReconciliationError(
            "current committed drain state does not bind the consumed restart"
        )
    try:
        rpc = DeploymentRpcRecheckFactsDTO.model_validate(windows_rpc)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(
            "post-restart Windows recheck is invalid"
        ) from exc
    if (
        rpc.recheck_id == consumed_checkpoint.rpc.recheck_id
        or rpc.fresh_challenge == consumed_checkpoint.rpc.fresh_challenge
    ):
        raise DeploymentRestartReconciliationError(
            "post-restart Windows recheck must use a fresh id and challenge"
        )
    if (
        _sha256(rpc.owner_challenge.encode("utf-8")) != online.owner_challenge_sha256
        or rpc.request_id != online.request_id
        or rpc.server_instance_id != online.windows_server_instance_id
        or rpc.original_server_instance_id != online.windows_server_instance_id
        or rpc.fact_generation != online.recheck_rpc_generation
        or rpc.original_fact_generation != online.recheck_rpc_generation
        or rpc.execution_facts_canonical_sha256
        != online.recheck_execution_facts_canonical_sha256
        or rpc.original_execution_facts_canonical_sha256
        != online.recheck_execution_facts_canonical_sha256
    ):
        raise DeploymentRestartReconciliationError(
            "post-restart Windows facts differ from consumed evidence"
        )
    if rpc.pending_send_outcomes or rpc.active_orders:
        raise DeploymentRestartReconciliationError(
            "post-restart Windows facts are not safe"
        )
    if len(rpc.account_hashes) != 1:
        raise DeploymentRestartReconciliationError(
            "post-restart Windows account scope is not singular"
        )
    expected_recheck_id, expected_fresh_challenge = (
        derive_post_restart_recheck_identity(
            reconciliation_run_id=reconciliation_run_id,
            receipt_id=marker.receipt_id,
            consume_marker_raw_sha256=_sha256(consume_marker_raw),
            current_state_commitment_raw_sha256=_sha256(current_commitment_raw),
            current_runtime_instance_id=current_runtime_instance_id,
            current_execution_epoch=current_execution_epoch,
        )
    )
    if (
        rpc.recheck_id != expected_recheck_id
        or rpc.fresh_challenge != expected_fresh_challenge
    ):
        raise DeploymentRestartReconciliationError(
            "post-restart Windows recheck identity is not epoch-bound"
        )
    captured = _utc_timestamp(captured_at, "post-restart checkpoint captured_at")
    captured_datetime = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    if rpc.captured_at < max(current_commitment.created_at, marker.committed_at):
        raise DeploymentRestartReconciliationError(
            "post-restart Windows facts predate the current runtime"
        )
    if captured_datetime < max(current_commitment.created_at, marker.committed_at):
        raise DeploymentRestartReconciliationError(
            "post-restart checkpoint clock precedes its durable evidence"
        )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_deployment_post_restart_checkpoint_v1",
        "purpose": ("record_non_authorizing_planned_restart_reconciliation_checkpoint"),
        "mode": "PLANNED_RESTART",
        "reconciliation_run_id": reconciliation_run_id,
        "consume_intent_id": intent.consume_intent_id,
        "consume_intent_raw_sha256": _sha256(consume_intent_raw),
        "consume_intent_core_sha256": intent.consume_intent_core_sha256,
        "consume_marker_id": marker.consume_marker_id,
        "consume_marker_raw_sha256": _sha256(consume_marker_raw),
        "consume_marker_core_sha256": marker.consume_marker_core_sha256,
        "receipt_id": marker.receipt_id,
        "receipt_raw_sha256": marker.receipt_raw_sha256,
        "receipt_core_sha256": marker.receipt_core_sha256,
        "online_recheck_id": online.online_recheck_id,
        "online_recheck_raw_sha256": _sha256(consumed_online_recheck_raw),
        "online_recheck_core_sha256": online.recheck_core_sha256,
        "request_id": marker.request_id,
        "deployment_attempt_id": marker.deployment_attempt_id,
        "release_plan_core_sha256": marker.release_plan_core_sha256,
        "restart_action_sha256": marker.restart_action_sha256,
        "drain_epoch": marker.drain_epoch,
        "previous_runtime_instance_id": marker.runtime_instance_id,
        "previous_execution_epoch": marker.execution_epoch,
        "current_runtime_instance_id": current_runtime_instance_id,
        "current_execution_epoch": current_execution_epoch,
        "consumed_windows_server_instance_id": online.windows_server_instance_id,
        "consumed_owner_challenge_sha256": online.owner_challenge_sha256,
        "consumed_recheck_id": consumed_checkpoint.rpc.recheck_id,
        "consumed_fresh_challenge_sha256": _sha256(
            consumed_checkpoint.rpc.fresh_challenge.encode("utf-8")
        ),
        "consumed_rpc_generation": online.recheck_rpc_generation,
        "consumed_execution_facts_canonical_sha256": (
            online.recheck_execution_facts_canonical_sha256
        ),
        "consumed_execution_state_sha256": online.recheck_state_sha256,
        "consumed_active_orders_snapshot_sha256": (
            online.recheck_active_orders_snapshot_sha256
        ),
        "consumed_positions_snapshot_sha256": (
            online.recheck_positions_snapshot_sha256
        ),
        "current_state_commitment_id": current_commitment.commitment_id,
        "current_state_commitment_raw_sha256": _sha256(current_commitment_raw),
        "current_epoch_anchor_raw_sha256": _sha256(current_epoch_anchor_raw),
        "current_state_generation": current_commitment.state_generation,
        "current_drain_state": current_state,
        "current_drain_state_raw_sha256": current_commitment.state_raw_sha256,
        "post_restart_recheck_id": rpc.recheck_id,
        "post_restart_fresh_challenge_sha256": _sha256(
            rpc.fresh_challenge.encode("utf-8")
        ),
        "windows_rpc": rpc.model_dump(mode="json"),
        "current_active_orders_snapshot_sha256": _sha256(
            _canonical_bytes(rpc.active_orders)
        ),
        "current_positions_snapshot_sha256": _sha256(_canonical_bytes(rpc.positions)),
        "captured_at": captured,
        "windows_execution_admission_frozen": True,
        "semantic_safety_unchanged": True,
        "target_runtime_verified": False,
        "execution_facts_reconciliation_completed": True,
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
        core_sha = _sha256(_canonical_bytes(core))
        return DeploymentPostRestartCheckpointDTO.model_validate(
            {
                **core,
                "checkpoint_id": f"deployment-post-restart-checkpoint-{core_sha}",
                "checkpoint_core_sha256": core_sha,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(
            "post-restart checkpoint core is invalid"
        ) from exc


def build_post_restart_checkpoint(
    *,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    reconciliation_run_id: str,
    current_runtime_instance_id: str,
    current_execution_epoch: int,
    windows_rpc: DeploymentRpcRecheckFactsDTO | dict[str, Any],
) -> DeploymentPostRestartCheckpointDTO:
    """Build C1a evidence using this module's trusted UTC clock."""

    return _build_post_restart_checkpoint(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        consumed_recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
        reconciliation_run_id=reconciliation_run_id,
        current_runtime_instance_id=current_runtime_instance_id,
        current_execution_epoch=current_execution_epoch,
        windows_rpc=windows_rpc,
        captured_at=_utc_now(),
    )


def parse_exact_post_restart_checkpoint(
    raw: bytes,
) -> DeploymentPostRestartCheckpointDTO:
    return _parse_exact(
        raw,
        DeploymentPostRestartCheckpointDTO,
        "post-restart checkpoint",
    )


def verify_post_restart_checkpoint(
    *,
    checkpoint_raw: bytes,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
) -> DeploymentPostRestartCheckpointDTO:
    checkpoint = parse_exact_post_restart_checkpoint(checkpoint_raw)
    expected = _build_post_restart_checkpoint(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        consumed_recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
        reconciliation_run_id=checkpoint.reconciliation_run_id,
        current_runtime_instance_id=checkpoint.current_runtime_instance_id,
        current_execution_epoch=checkpoint.current_execution_epoch,
        windows_rpc=checkpoint.windows_rpc,
        captured_at=checkpoint.captured_at,
    )
    if canonical_post_restart_checkpoint_bytes(expected) != checkpoint_raw:
        raise DeploymentRestartReconciliationError(
            "post-restart checkpoint does not match its exact evidence chain"
        )
    return checkpoint


def _build_restart_reconciliation_evidence(
    *,
    checkpoint_raw: bytes,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
    reconciled_at: datetime | str,
) -> SafeRestartReconciliationEvidenceDTO:
    checkpoint = verify_post_restart_checkpoint(
        checkpoint_raw=checkpoint_raw,
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        consumed_recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
    )
    reconciled = _utc_timestamp(reconciled_at, "restart reconciled_at")
    if datetime.fromisoformat(reconciled.replace("Z", "+00:00")) < (
        checkpoint.captured_at
    ):
        raise DeploymentRestartReconciliationError(
            "restart reconciliation predates its checkpoint"
        )
    core = {
        "schema_version": "web_bridge_safe_restart_reconciliation_v1",
        "purpose": ("record_non_authorizing_planned_restart_reconciliation_evidence"),
        "mode": "PLANNED_RESTART",
        "checkpoint_id": checkpoint.checkpoint_id,
        "checkpoint_raw_sha256": _sha256(checkpoint_raw),
        "checkpoint_core_sha256": checkpoint.checkpoint_core_sha256,
        "consume_intent_id": checkpoint.consume_intent_id,
        "consume_intent_raw_sha256": checkpoint.consume_intent_raw_sha256,
        "consume_marker_id": checkpoint.consume_marker_id,
        "consume_marker_raw_sha256": checkpoint.consume_marker_raw_sha256,
        "receipt_id": checkpoint.receipt_id,
        "online_recheck_id": checkpoint.online_recheck_id,
        "online_recheck_raw_sha256": checkpoint.online_recheck_raw_sha256,
        "current_runtime_instance_id": checkpoint.current_runtime_instance_id,
        "current_execution_epoch": checkpoint.current_execution_epoch,
        "reconciled_at": reconciled,
        "post_restart_reconciliation_verified": True,
        "windows_execution_admission_frozen": True,
        "target_runtime_verified": False,
        "execution_facts_reconciliation_completed": True,
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
        core_sha = _sha256(_canonical_bytes(core))
        return SafeRestartReconciliationEvidenceDTO.model_validate(
            {
                **core,
                "reconciliation_id": f"safe-restart-reconciliation-{core_sha}",
                "reconciliation_core_sha256": core_sha,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentRestartReconciliationError(
            "restart reconciliation core is invalid"
        ) from exc


def build_restart_reconciliation_evidence(
    *,
    checkpoint_raw: bytes,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
) -> SafeRestartReconciliationEvidenceDTO:
    return _build_restart_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw,
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        consumed_recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
        reconciled_at=datetime.now(timezone.utc),
    )


def parse_exact_restart_reconciliation(
    raw: bytes,
) -> SafeRestartReconciliationEvidenceDTO:
    return _parse_exact(
        raw,
        SafeRestartReconciliationEvidenceDTO,
        "restart reconciliation evidence",
    )


def verify_restart_reconciliation_evidence(
    *,
    evidence_raw: bytes,
    checkpoint_raw: bytes,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    consumed_recheck_checkpoint_raw: bytes,
    consume_intent_raw: bytes,
    consume_marker_raw: bytes,
    consumed_online_recheck_raw: bytes,
    preconsume_state_commitment_raw: bytes,
    state_commitment_chain_raw: list[bytes],
    current_epoch_anchor_raw: bytes,
) -> SafeRestartReconciliationEvidenceDTO:
    evidence = parse_exact_restart_reconciliation(evidence_raw)
    expected = _build_restart_reconciliation_evidence(
        checkpoint_raw=checkpoint_raw,
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        consumed_recheck_checkpoint_raw=consumed_recheck_checkpoint_raw,
        consume_intent_raw=consume_intent_raw,
        consume_marker_raw=consume_marker_raw,
        consumed_online_recheck_raw=consumed_online_recheck_raw,
        preconsume_state_commitment_raw=preconsume_state_commitment_raw,
        state_commitment_chain_raw=state_commitment_chain_raw,
        current_epoch_anchor_raw=current_epoch_anchor_raw,
        reconciled_at=evidence.reconciled_at,
    )
    if canonical_restart_reconciliation_bytes(expected) != evidence_raw:
        raise DeploymentRestartReconciliationError(
            "restart reconciliation does not match its exact evidence chain"
        )
    return evidence
