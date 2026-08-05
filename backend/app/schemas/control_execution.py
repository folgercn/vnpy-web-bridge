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

from app.execution.models import CommandEnvelope

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


# Explicit aliases make the boundary discoverable to callers that use the
# conventional DTO naming while retaining the shared execution model.
ControlExecutionCommandDTO = CommandEnvelope
CommandEnvelopeDTO = CommandEnvelope
ExecutionStatusDTO = ExecutionStatusProjection
ExecutionStatusProjectionDTO = ExecutionStatusProjection


__all__ = [
    "CommandEnvelope",
    "CommandEnvelopeDTO",
    "ControlExecutionCommandDTO",
    "ExecutionStatusDTO",
    "ExecutionStatusProjection",
    "ExecutionStatusProjectionDTO",
]
