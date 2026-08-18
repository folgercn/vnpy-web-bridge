"""Typed DTOs at the Control API/Execution boundary.

The command and status schemas are private service contracts.  Keeping the
validation entry points in this small module gives the Control API and its
tests one import surface while the actual command semantics remain owned by
``app.execution.models``.  No legacy trading service is imported here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from shared.commodity_execution import KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION

from app.execution.models import (
    EPOCH_TIMESTAMP,
    IDENTIFIER_RE,
    SHA256_RE,
    UTC_RE,
    CommandEnvelope,
)

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "schemas"
    / "web-bridge-execution-status-v1.schema.json"
)


def _load_status_validator() -> Draft202012Validator:
    """Load the frozen status schema without depending on the process cwd."""

    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        # Images copy the public schema into ``/app/docs``.  The fallback is
        # intentionally explicit instead of accepting arbitrary dictionaries;
        # it keeps health/status fail closed when packaging is incomplete.
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schema_version",
                "service",
                "service_version",
                "observed_at",
                "lifecycle",
                "state_version",
                "leader",
                "authority",
                "plan",
                "send_intents",
                "reconciliation",
                "safe_to_restart",
                "broker",
            ],
            "properties": {
                "schema_version": {"const": "web_bridge_execution_status_v1"},
                "service": {"const": "execution-orchestrator"},
                "service_version": {"type": "string"},
                "observed_at": {"type": "string"},
                "lifecycle": {"type": "string"},
                "state_version": {"type": "integer", "minimum": 0},
                "leader": {"type": "object"},
                "authority": {"type": "object"},
                "plan": {"type": "object"},
                "send_intents": {"type": "array"},
                "reconciliation": {"type": "object"},
                "safe_to_restart": {"type": "boolean"},
                "broker": {"type": "object"},
            },
        }
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


_STATUS_VALIDATOR = _load_status_validator()


_LEADER_TOKEN_FIELDS = frozenset(
    {
        "scope",
        "owner_id",
        "held",
        "epoch",
        "fencing_token",
        "lease_expires_at",
        "instance_id",
    }
)
_LEADER_STATUS_FIELDS = _LEADER_TOKEN_FIELDS | {"state"}
_LEADER_STATES = frozenset({"ACTIVE", "EXPIRED_BOUND", "RELEASED"})


def _detached_object(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    try:
        return json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} is not canonical JSON") from exc


def _validate_leader_common(
    candidate: dict[str, Any], *, fields: frozenset[str]
) -> None:
    if set(candidate) != fields:
        raise ValueError("execution leader fields are not exact")
    if (
        not isinstance(candidate["scope"], str)
        or IDENTIFIER_RE.fullmatch(candidate["scope"]) is None
    ):
        raise ValueError("execution leader scope is invalid")
    owner_id = candidate["owner_id"]
    instance_id = candidate["instance_id"]
    if owner_id and (
        not isinstance(owner_id, str) or IDENTIFIER_RE.fullmatch(owner_id) is None
    ):
        raise ValueError("execution leader owner_id is invalid")
    if not isinstance(owner_id, str):
        raise ValueError("execution leader owner_id is invalid")
    if owner_id:
        if (
            not isinstance(instance_id, str)
            or IDENTIFIER_RE.fullmatch(instance_id) is None
        ):
            raise ValueError("execution leader instance_id is invalid")
    elif instance_id != "":
        raise ValueError("released execution leader retains an instance_id")
    for field in ("epoch", "fencing_token"):
        value = candidate[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"execution leader {field} is invalid")
    if not isinstance(candidate["held"], bool):
        raise ValueError("execution leader held is invalid")
    if (
        not isinstance(candidate["lease_expires_at"], str)
        or UTC_RE.fullmatch(candidate["lease_expires_at"]) is None
    ):
        raise ValueError("execution leader lease_expires_at is invalid")
    if owner_id and (candidate["epoch"] < 1 or candidate["fencing_token"] < 1):
        raise ValueError("owned execution leader is missing a fence")


@dataclass(frozen=True, slots=True)
class ExecutionLeaderTokenProjection:
    """Strict Control-side projection of one currently held lease token."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionLeaderTokenProjection:
        candidate = _detached_object(value, name="execution leader token")
        _validate_leader_common(candidate, fields=_LEADER_TOKEN_FIELDS)
        if (
            candidate["held"] is not True
            or not candidate["owner_id"]
            or not candidate["instance_id"]
            or candidate["lease_expires_at"] == EPOCH_TIMESTAMP
        ):
            raise ValueError("execution leader token is not held")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionLeaderTokenProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def token_dict(self) -> dict[str, Any]:
        token = self.model_dump()
        token.pop("held")
        return token

    @property
    def owner_id(self) -> str:
        return str(self.value["owner_id"])

    @property
    def instance_id(self) -> str:
        return str(self.value["instance_id"])

    @property
    def scope(self) -> str:
        return str(self.value["scope"])

    @property
    def epoch(self) -> int:
        return int(self.value["epoch"])

    @property
    def fencing_token(self) -> int:
        return int(self.value["fencing_token"])


@dataclass(frozen=True, slots=True)
class ExecutionLeaderStatusProjection:
    """Strict read-only lease status with an explicit durable binding state."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionLeaderStatusProjection:
        candidate = _detached_object(value, name="execution leader status")
        _validate_leader_common(candidate, fields=_LEADER_STATUS_FIELDS)
        state = candidate["state"]
        if not isinstance(state, str) or state not in _LEADER_STATES:
            raise ValueError("execution leader state is invalid")
        owner_id = candidate["owner_id"]
        instance_id = candidate["instance_id"]
        expiry = candidate["lease_expires_at"]
        if state == "ACTIVE":
            valid = (
                candidate["held"] is True
                and bool(owner_id)
                and bool(instance_id)
                and expiry != EPOCH_TIMESTAMP
            )
        elif state == "EXPIRED_BOUND":
            valid = (
                candidate["held"] is False
                and bool(owner_id)
                and bool(instance_id)
                and expiry != EPOCH_TIMESTAMP
            )
        else:
            valid = (
                candidate["held"] is False
                and owner_id == ""
                and instance_id == ""
                and expiry == EPOCH_TIMESTAMP
            )
        if not valid:
            raise ValueError("execution leader status has mixed state bindings")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionLeaderStatusProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    @property
    def held(self) -> bool:
        return bool(self.value["held"])

    @property
    def state(self) -> str:
        return str(self.value["state"])

    @property
    def owner_id(self) -> str:
        return str(self.value["owner_id"])

    @property
    def instance_id(self) -> str:
        return str(self.value["instance_id"])

    @property
    def scope(self) -> str:
        return str(self.value["scope"])

    @property
    def epoch(self) -> int:
        return int(self.value["epoch"])

    @property
    def fencing_token(self) -> int:
        return int(self.value["fencing_token"])


@dataclass(frozen=True, slots=True)
class ExecutionStatusProjection:
    """A read-only, schema-validated Execution projection.

    The projection stores a detached JSON value.  Control code can safely
    retain it for an audit/receipt projection without gaining a writable
    reference to Execution durable state.
    """

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionStatusProjection:
        if not isinstance(value, Mapping):
            raise TypeError("execution status projection must be an object")
        candidate = json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
        errors = sorted(
            _STATUS_VALIDATOR.iter_errors(candidate), key=lambda e: list(e.path)
        )
        if errors:
            first = errors[0]
            path = ".".join(str(item) for item in first.path)
            location = f" at {path}" if path else ""
            raise ValueError(
                f"invalid execution status projection{location}: {first.message}"
            )
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionStatusProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @property
    def lifecycle(self) -> str:
        return str(self.value["lifecycle"])

    @property
    def state_version(self) -> int:
        return int(self.value["state_version"])

    @property
    def safe_to_restart(self) -> bool:
        return bool(self.value["safe_to_restart"])


_COMPLETION_FIELDS = frozenset(
    {
        "plan_id",
        "plan_hash",
        "schema_version",
        "phase",
        "lineage",
        "expected_after_position_hash",
        "target_position_hash",
        "archived_at",
    }
)
_COMPLETION_LINEAGE_FIELDS = frozenset(
    {
        "static_core_equal_sha256",
        "position_manager_sha256",
        "final_target_sha256",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionCompletionProjection:
    """Strict read-only projection of one completed TargetPlan v2.

    This DTO intentionally excludes archived broker rows, receipts, authority
    material and every other mutable Execution field.  It is sufficient to
    identify an already-completed immutable target without turning Control
    into another Execution state store.
    """

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionCompletionProjection:
        if not isinstance(value, Mapping):
            raise TypeError("execution completion projection must be an object")
        candidate = json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
        if set(candidate) != _COMPLETION_FIELDS:
            raise ValueError("execution completion projection fields are not exact")
        if (
            not isinstance(candidate["plan_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["plan_id"]) is None
        ):
            raise ValueError("execution completion plan_id is invalid")
        for field in (
            "plan_hash",
            "expected_after_position_hash",
            "target_position_hash",
        ):
            if (
                not isinstance(candidate[field], str)
                or SHA256_RE.fullmatch(candidate[field]) is None
            ):
                raise ValueError(f"execution completion {field} is invalid")
        if candidate["schema_version"] != KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION:
            raise ValueError("execution completion schema_version is not v2")
        if candidate["phase"] not in {"CLOSE", "OPEN"}:
            raise ValueError("execution completion phase is invalid")
        lineage = candidate["lineage"]
        if not isinstance(lineage, Mapping) or set(lineage) != (
            _COMPLETION_LINEAGE_FIELDS
        ):
            raise ValueError("execution completion lineage fields are not exact")
        for field in _COMPLETION_LINEAGE_FIELDS:
            if (
                not isinstance(lineage[field], str)
                or SHA256_RE.fullmatch(lineage[field]) is None
            ):
                raise ValueError(f"execution completion lineage {field} is invalid")
        if (
            candidate["target_position_hash"]
            != candidate["expected_after_position_hash"]
        ):
            raise ValueError("execution completion target position binding mismatches")
        if (
            not isinstance(candidate["archived_at"], str)
            or UTC_RE.fullmatch(candidate["archived_at"]) is None
        ):
            raise ValueError("execution completion archived_at is invalid")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionCompletionProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @property
    def plan_id(self) -> str:
        return str(self.value["plan_id"])

    @property
    def target_position_hash(self) -> str:
        return str(self.value["target_position_hash"])


# Explicit aliases make the boundary discoverable to callers that use the
# conventional DTO naming while retaining the shared execution model.
ControlExecutionCommandDTO = CommandEnvelope
CommandEnvelopeDTO = CommandEnvelope
ExecutionStatusDTO = ExecutionStatusProjection
ExecutionStatusProjectionDTO = ExecutionStatusProjection
ExecutionCompletionDTO = ExecutionCompletionProjection
ExecutionCompletionProjectionDTO = ExecutionCompletionProjection
ExecutionLeaderStatusDTO = ExecutionLeaderStatusProjection
ExecutionLeaderTokenDTO = ExecutionLeaderTokenProjection


__all__ = [
    "CommandEnvelope",
    "CommandEnvelopeDTO",
    "ControlExecutionCommandDTO",
    "ExecutionCompletionDTO",
    "ExecutionCompletionProjection",
    "ExecutionCompletionProjectionDTO",
    "ExecutionLeaderStatusDTO",
    "ExecutionLeaderStatusProjection",
    "ExecutionLeaderTokenDTO",
    "ExecutionLeaderTokenProjection",
    "ExecutionStatusDTO",
    "ExecutionStatusProjection",
    "ExecutionStatusProjectionDTO",
]
