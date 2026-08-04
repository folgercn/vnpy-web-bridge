from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import ValidationError

from app.schemas.deployment_drain import DeploymentDrainStateCommitmentDTO


class DeploymentStateCommitmentError(RuntimeError):
    """The deployment-drain state commitment is malformed or inconsistent."""


GenesisSource = Literal["fresh_bootstrap", "v1_migration", "v2_migration"]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalized_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return the exact JSON value committed by both the state and artifact."""

    if not isinstance(state, dict):
        raise DeploymentStateCommitmentError(
            "deployment drain state must be an object"
        )
    try:
        normalized = json.loads(_canonical_bytes(state))
    except (TypeError, ValueError) as exc:
        raise DeploymentStateCommitmentError(
            "deployment drain state is not strict JSON"
        ) from exc
    if not isinstance(normalized, dict):  # pragma: no cover - guarded above
        raise DeploymentStateCommitmentError(
            "deployment drain state must be an object"
        )
    return normalized


def _normalized_utc_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise DeploymentStateCommitmentError(
            "deployment drain state updated_at must be a UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeploymentStateCommitmentError(
            "deployment drain state updated_at is invalid"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise DeploymentStateCommitmentError(
            "deployment drain state updated_at must be UTC"
        )
    return parsed.isoformat().replace("+00:00", "Z")


def build_state_commitment(
    state: dict[str, Any],
    genesis_source: GenesisSource | None = None,
    source_state_raw_sha256: str | None = None,
    source_epoch_anchor_raw_sha256: str | None = None,
) -> DeploymentDrainStateCommitmentDTO:
    """Build non-authorizing evidence for one exact canonical state generation."""

    normalized = _normalized_state(state)
    state_raw = _canonical_bytes(normalized) + b"\n"
    core = {
        "schema_version": "web_bridge_deployment_drain_state_commitment_v1",
        "purpose": "commit_exact_non_authorizing_deployment_drain_state",
        "state_generation": normalized.get("state_generation"),
        "previous_state_commitment_raw_sha256": normalized.get(
            "previous_state_commitment_raw_sha256"
        ),
        "state_raw_sha256": _sha256(state_raw),
        "state": normalized,
        "created_at": _normalized_utc_timestamp(normalized.get("updated_at")),
        "genesis_source": genesis_source,
        "source_state_raw_sha256": source_state_raw_sha256,
        "source_epoch_anchor_raw_sha256": source_epoch_anchor_raw_sha256,
        "deployment_authorized": False,
        "consume_authorized": False,
        "reconciliation_authorized": False,
        "countable_forward": False,
        "automatic_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
    }
    try:
        core_sha = _sha256(_canonical_bytes(core))
        return DeploymentDrainStateCommitmentDTO.model_validate(
            {
                **core,
                "commitment_id": (
                    f"deployment-drain-state-commitment-{core_sha}"
                ),
                "state_commitment_core_sha256": core_sha,
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentStateCommitmentError(
            "deployment drain state commitment is invalid"
        ) from exc


def parse_exact_state_commitment(
    raw: bytes,
) -> DeploymentDrainStateCommitmentDTO:
    """Parse only canonical JSON followed by exactly one LF byte."""

    if not isinstance(raw, bytes):
        raise DeploymentStateCommitmentError(
            "state commitment raw value must be bytes"
        )
    try:
        value = DeploymentDrainStateCommitmentDTO.model_validate_json(raw)
        expected = _canonical_bytes(value.model_dump(mode="json")) + b"\n"
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError) as exc:
        raise DeploymentStateCommitmentError(
            "state commitment artifact is invalid"
        ) from exc
    if raw != expected:
        raise DeploymentStateCommitmentError(
            "state commitment artifact bytes are not canonical"
        )
    return value
