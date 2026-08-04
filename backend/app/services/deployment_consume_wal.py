from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    SafeRestartConsumeCommitMarkerDTO,
    SafeRestartConsumeIntentDTO,
    SafeRestartConsumeStateProjectionDTO,
)


class DeploymentConsumeWalError(RuntimeError):
    """A safe-restart consume WAL artifact is malformed or inconsistent."""


_INTENT_IDENTITY_FIELDS = frozenset(
    {"consume_intent_id", "consume_intent_core_sha256"}
)
_MARKER_BOUND_FIELDS = (
    "receipt_id",
    "receipt_raw_sha256",
    "receipt_core_sha256",
    "online_recheck_id",
    "online_recheck_raw_sha256",
    "online_recheck_core_sha256",
    "preconsume_state_commitment_id",
    "preconsume_state_commitment_raw_sha256",
    "preconsume_state_generation",
    "consume_state_projection",
    "consume_state_projection_sha256",
    "request_id",
    "runtime_instance_id",
    "deployment_attempt_id",
    "release_plan_core_sha256",
    "restart_action_sha256",
    "drain_epoch",
    "execution_epoch",
    "consume_not_after",
    "consumer_run_id",
    "operator",
)


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


def _utc_timestamp(value: datetime | str, field: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DeploymentConsumeWalError(f"{field} is invalid") from exc
    else:
        raise DeploymentConsumeWalError(f"{field} must be a UTC timestamp")
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise DeploymentConsumeWalError(f"{field} must be UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def canonical_consume_intent_bytes(
    intent: SafeRestartConsumeIntentDTO,
) -> bytes:
    try:
        validated = SafeRestartConsumeIntentDTO.model_validate(intent)
        return _artifact_bytes(validated.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentConsumeWalError("consume intent is invalid") from exc


def canonical_consume_marker_bytes(
    marker: SafeRestartConsumeCommitMarkerDTO,
) -> bytes:
    try:
        validated = SafeRestartConsumeCommitMarkerDTO.model_validate(marker)
        return _artifact_bytes(validated.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentConsumeWalError("consume marker is invalid") from exc


def build_consume_intent(core: dict[str, Any]) -> SafeRestartConsumeIntentDTO:
    """Build a non-authorizing prepare record from an explicit core object."""

    if not isinstance(core, dict):
        raise DeploymentConsumeWalError("consume intent core must be an object")
    if _INTENT_IDENTITY_FIELDS.intersection(core):
        raise DeploymentConsumeWalError(
            "consume intent core cannot supply derived identity fields"
        )
    normalized = dict(core)
    try:
        normalized["prepared_at"] = _utc_timestamp(
            normalized.get("prepared_at"), "consume intent prepared_at"
        )
        normalized["consume_not_after"] = _utc_timestamp(
            normalized.get("consume_not_after"),
            "consume intent consume_not_after",
        )
        normalized["consume_state_projection"] = (
            SafeRestartConsumeStateProjectionDTO.model_validate(
                normalized.get("consume_state_projection")
            ).model_dump(mode="json")
        )
        projection_sha = _sha256(
            _canonical_bytes(normalized["consume_state_projection"])
        )
        supplied_projection_sha = normalized.get(
            "consume_state_projection_sha256"
        )
        if supplied_projection_sha not in (None, projection_sha):
            raise DeploymentConsumeWalError(
                "consume state projection hash does not match its object"
            )
        normalized["consume_state_projection_sha256"] = projection_sha
        core_sha = _sha256(_canonical_bytes(normalized))
        return SafeRestartConsumeIntentDTO.model_validate(
            {
                **normalized,
                "consume_intent_id": f"safe-restart-consume-intent-{core_sha}",
                "consume_intent_core_sha256": core_sha,
            }
        )
    except DeploymentConsumeWalError:
        raise
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentConsumeWalError("consume intent core is invalid") from exc


def parse_exact_consume_intent(raw: bytes) -> SafeRestartConsumeIntentDTO:
    """Parse canonical JSON followed by exactly one LF byte."""

    if not isinstance(raw, bytes):
        raise DeploymentConsumeWalError("consume intent raw value must be bytes")
    try:
        value = SafeRestartConsumeIntentDTO.model_validate_json(raw)
        expected = canonical_consume_intent_bytes(value)
    except (TypeError, ValueError, ValidationError, DeploymentConsumeWalError) as exc:
        raise DeploymentConsumeWalError("consume intent artifact is invalid") from exc
    if raw != expected:
        raise DeploymentConsumeWalError(
            "consume intent artifact bytes are not canonical"
        )
    return value


def build_consume_marker(
    intent_raw: bytes,
    *,
    committed_at: datetime | str,
) -> SafeRestartConsumeCommitMarkerDTO:
    """Build the irreversible marker from one exact canonical intent artifact."""

    intent = parse_exact_consume_intent(intent_raw)
    intent_value = intent.model_dump(mode="json")
    normalized_committed_at = _utc_timestamp(
        committed_at, "consume marker committed_at"
    )
    if datetime.fromisoformat(normalized_committed_at.replace("Z", "+00:00")) < (
        intent.prepared_at
    ):
        raise DeploymentConsumeWalError(
            "consume marker cannot precede its consume intent"
        )
    if datetime.fromisoformat(normalized_committed_at.replace("Z", "+00:00")) > (
        intent.consume_not_after
    ):
        raise DeploymentConsumeWalError(
            "consume marker cannot be committed after its deadline"
        )
    core: dict[str, Any] = {
        "schema_version": "web_bridge_safe_restart_consume_marker_v1",
        "purpose": "commit_one_shot_safe_restart_consumption",
        "consume_intent_id": intent.consume_intent_id,
        "consume_intent_raw_sha256": _sha256(intent_raw),
        "consume_intent_core_sha256": intent.consume_intent_core_sha256,
        **{field: intent_value[field] for field in _MARKER_BOUND_FIELDS},
        "committed_at": normalized_committed_at,
        "one_shot_consume_committed": True,
        "restart_execution_started": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "deployment_authorized": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    try:
        marker_sha = _sha256(_canonical_bytes(core))
        return SafeRestartConsumeCommitMarkerDTO.model_validate(
            {
                **core,
                "consume_marker_id": f"safe-restart-consume-marker-{marker_sha}",
                "consume_marker_core_sha256": marker_sha,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentConsumeWalError("consume marker core is invalid") from exc


def parse_exact_consume_marker(
    raw: bytes,
    *,
    intent_raw: bytes,
) -> SafeRestartConsumeCommitMarkerDTO:
    """Parse a canonical marker and prove all of its exact intent bindings."""

    if not isinstance(raw, bytes):
        raise DeploymentConsumeWalError("consume marker raw value must be bytes")
    intent = parse_exact_consume_intent(intent_raw)
    try:
        marker = SafeRestartConsumeCommitMarkerDTO.model_validate_json(raw)
        expected_raw = canonical_consume_marker_bytes(marker)
    except (TypeError, ValueError, ValidationError, DeploymentConsumeWalError) as exc:
        raise DeploymentConsumeWalError("consume marker artifact is invalid") from exc
    if raw != expected_raw:
        raise DeploymentConsumeWalError(
            "consume marker artifact bytes are not canonical"
        )
    intent_value = intent.model_dump(mode="json")
    marker_value = marker.model_dump(mode="json")
    if (
        marker.consume_intent_id != intent.consume_intent_id
        or marker.consume_intent_core_sha256
        != intent.consume_intent_core_sha256
        or marker.consume_intent_raw_sha256 != _sha256(intent_raw)
        or any(
            marker_value[field] != intent_value[field]
            for field in _MARKER_BOUND_FIELDS
        )
        or marker.committed_at < intent.prepared_at
    ):
        raise DeploymentConsumeWalError(
            "consume marker does not bind the exact consume intent"
        )
    return marker
