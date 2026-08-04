from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    DeploymentOnlineCheckpointDTO,
    DeploymentOnlineRecheckCheckpointDTO,
    SafeRestartOnlineRecheckDTO,
    SafeRestartReceiptDTO,
    deployment_rpc_execution_facts_sha256,
)


class DeploymentOnlineRecheckError(RuntimeError):
    """A fresh online recheck did not preserve the original safety facts."""


MAX_RECHECK_AGE = timedelta(seconds=30)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_exact(raw: bytes, model: type):
    try:
        value = model.model_validate_json(raw)
    except (UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise DeploymentOnlineRecheckError("recheck artifact is invalid") from exc
    expected = _canonical_bytes(value.model_dump(mode="json")) + b"\n"
    if raw != expected:
        raise DeploymentOnlineRecheckError("recheck artifact bytes are not canonical")
    return value


def _build_safe_restart_online_recheck(
    *,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    recheck_checkpoint_raw: bytes,
    checked_at: datetime,
) -> SafeRestartOnlineRecheckDTO:
    """Verify three exact-byte artifacts and emit non-authorizing evidence.

    B1a deliberately performs no I/O and grants no consume, reconciliation,
    restart, deployment, production, or trading authority.
    """

    receipt = _parse_exact(receipt_raw, SafeRestartReceiptDTO)
    original = _parse_exact(original_checkpoint_raw, DeploymentOnlineCheckpointDTO)
    recheck = _parse_exact(recheck_checkpoint_raw, DeploymentOnlineRecheckCheckpointDTO)
    now = checked_at
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or now.utcoffset() != timezone.utc.utcoffset(now)
    ):
        raise DeploymentOnlineRecheckError("checked_at must be UTC")

    receipt_sha = _sha256(receipt_raw)
    original_sha = _sha256(original_checkpoint_raw)
    recheck_sha = _sha256(recheck_checkpoint_raw)
    if receipt.snapshot.checkpoint_sha256 != original_sha:
        raise DeploymentOnlineRecheckError(
            "receipt does not bind the original checkpoint bytes"
        )
    snapshot_bindings = (
        receipt.snapshot.execution_plan_status,
        receipt.snapshot.execution_plan_hash,
        receipt.snapshot.plan_version,
        receipt.snapshot.state_version,
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
    )
    original_bindings = (
        original.execution_plan_status,
        original.execution_plan_hash,
        original.plan_version,
        original.state_version,
        original.state_sha256,
        original.active_orders_snapshot_sha256,
        original.positions_snapshot_sha256,
        original.rpc.fact_generation,
        original.web_trade_enabled,
        original.execution_authority_revoked,
        original.auto_dispatch_stopped,
        original.active_orders,
        original.unknown_outcome,
        original.reconcile_required,
    )
    if snapshot_bindings != original_bindings:
        raise DeploymentOnlineRecheckError(
            "receipt safety snapshot differs from original checkpoint"
        )
    if (
        receipt.snapshot.captured_at < original.rpc.captured_at
        or receipt.snapshot.captured_at > receipt.issued_at
        or receipt.snapshot.captured_at - original.rpc.captured_at
        > MAX_RECHECK_AGE
    ):
        raise DeploymentOnlineRecheckError(
            "receipt snapshot and original checkpoint timestamps differ"
        )
    if recheck.original_checkpoint_raw_sha256 != original_sha:
        raise DeploymentOnlineRecheckError(
            "recheck checkpoint does not bind the original checkpoint bytes"
        )
    if not receipt.issued_at <= now < receipt.expires_at:
        raise DeploymentOnlineRecheckError("safe restart receipt is not live")
    if (
        recheck.rpc.captured_at < receipt.issued_at
        or original.rpc.captured_at > recheck.rpc.captured_at
        or recheck.rpc.captured_at > recheck.captured_at
        or recheck.captured_at > now
        or now - recheck.rpc.captured_at > MAX_RECHECK_AGE
    ):
        raise DeploymentOnlineRecheckError(
            "recheck capture timestamps are not monotonic"
        )

    common = (
        receipt.request_id,
        receipt.issuer_runtime_instance_id,
        receipt.drain_epoch,
        receipt.execution_epoch,
    )
    if (
        original.request_id,
        original.runtime_instance_id,
        original.drain_epoch,
        original.execution_epoch,
    ) != common or (
        recheck.request_id,
        recheck.runtime_instance_id,
        recheck.drain_epoch,
        recheck.execution_epoch,
    ) != common:
        raise DeploymentOnlineRecheckError(
            "receipt and checkpoint owner bindings differ"
        )

    original_facts_sha = deployment_rpc_execution_facts_sha256(original.rpc)
    rpc = recheck.rpc
    if (
        rpc.owner_challenge != original.rpc.challenge
        or rpc.original_server_instance_id != original.rpc.server_instance_id
        or rpc.server_instance_id != original.rpc.server_instance_id
        or rpc.original_fact_generation != original.rpc.fact_generation
        or rpc.fact_generation != original.rpc.fact_generation
        or rpc.original_execution_facts_canonical_sha256 != original_facts_sha
        or rpc.execution_facts_canonical_sha256 != original_facts_sha
    ):
        raise DeploymentOnlineRecheckError(
            "Windows server, generation, challenge, or execution facts changed"
        )
    if (
        recheck.state_sha256 != original.state_sha256
        or recheck.active_orders_snapshot_sha256
        != original.active_orders_snapshot_sha256
        or recheck.positions_snapshot_sha256 != original.positions_snapshot_sha256
    ):
        raise DeploymentOnlineRecheckError(
            "Web Bridge state or execution snapshots changed"
        )

    core = {
        "schema_version": "web_bridge_safe_restart_online_recheck_v1",
        "purpose": "record_non_authorizing_fresh_online_restart_recheck",
        "receipt_id": receipt.receipt_id,
        "receipt_raw_sha256": receipt_sha,
        "original_checkpoint_raw_sha256": original_sha,
        "recheck_checkpoint_raw_sha256": recheck_sha,
        "request_id": receipt.request_id,
        "runtime_instance_id": receipt.issuer_runtime_instance_id,
        "drain_epoch": receipt.drain_epoch,
        "execution_epoch": receipt.execution_epoch,
        "deployment_attempt_id": receipt.deployment_attempt_id,
        "release_plan_core_sha256": receipt.release_plan_core_sha256,
        "restart_action_sha256": receipt.restart_action_sha256,
        "windows_server_instance_id": original.rpc.server_instance_id,
        "owner_challenge_sha256": _sha256(
            original.rpc.challenge.encode("utf-8")
        ),
        "fresh_challenge_sha256": _sha256(
            rpc.fresh_challenge.encode("utf-8")
        ),
        "original_rpc_generation": original.rpc.fact_generation,
        "recheck_rpc_generation": rpc.fact_generation,
        "original_execution_facts_canonical_sha256": original_facts_sha,
        "recheck_execution_facts_canonical_sha256": (
            rpc.execution_facts_canonical_sha256
        ),
        "original_state_sha256": original.state_sha256,
        "recheck_state_sha256": recheck.state_sha256,
        "original_active_orders_snapshot_sha256": (
            original.active_orders_snapshot_sha256
        ),
        "recheck_active_orders_snapshot_sha256": (
            recheck.active_orders_snapshot_sha256
        ),
        "original_positions_snapshot_sha256": (
            original.positions_snapshot_sha256
        ),
        "recheck_positions_snapshot_sha256": (
            recheck.positions_snapshot_sha256
        ),
        "checked_at": now.isoformat().replace("+00:00", "Z"),
        "semantic_safety_unchanged": True,
        "one_shot_consume_allowed": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    core_sha = _sha256(_canonical_bytes(core))
    return SafeRestartOnlineRecheckDTO.model_validate(
        {
            **core,
            "online_recheck_id": f"safe-restart-online-recheck-{core_sha}",
            "recheck_core_sha256": core_sha,
        }
    )


def build_safe_restart_online_recheck(
    *,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    recheck_checkpoint_raw: bytes,
) -> SafeRestartOnlineRecheckDTO:
    """Build fresh evidence using only this module's trusted UTC clock."""

    return _build_safe_restart_online_recheck(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        recheck_checkpoint_raw=recheck_checkpoint_raw,
        checked_at=_utc_now(),
    )


def verify_safe_restart_online_recheck(
    *,
    artifact_raw: bytes,
    receipt_raw: bytes,
    original_checkpoint_raw: bytes,
    recheck_checkpoint_raw: bytes,
) -> SafeRestartOnlineRecheckDTO:
    """Rebuild an existing exact-byte artifact at its recorded capture time."""

    artifact = _parse_exact(artifact_raw, SafeRestartOnlineRecheckDTO)
    expected = _build_safe_restart_online_recheck(
        receipt_raw=receipt_raw,
        original_checkpoint_raw=original_checkpoint_raw,
        recheck_checkpoint_raw=recheck_checkpoint_raw,
        checked_at=artifact.checked_at,
    )
    expected_raw = _canonical_bytes(expected.model_dump(mode="json")) + b"\n"
    if expected_raw != artifact_raw:
        raise DeploymentOnlineRecheckError(
            "online recheck artifact does not match its evidence chain"
        )
    return artifact
