"""Control-owned, durable and strictly bound Execution projections."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

from app.execution.models import (
    CommandEnvelope,
    parse_utc,
    validate_idempotency_key,
    validate_sha256,
)
from app.schemas.control_execution import ExecutionStatusProjection

_JOURNAL_SCHEMA = "web_bridge_control_receipt_projection_v1"
_TERMINAL_STATUSES = {"COMPLETED", "REJECTED"}


class ReceiptProjectionError(ValueError):
    """A receipt is malformed or is not bound to the submitted command."""


@dataclass(frozen=True, slots=True)
class ReceiptProjection:
    service: str
    idempotency_key: str
    command_hash: str
    command_id: str
    correlation_id: str
    command: str
    actor: dict[str, str]
    expected: dict[str, Any]
    status: str
    result_state_version: int | None
    result: dict[str, Any]
    observed_at: str

    def as_dict(self) -> dict[str, Any]:
        return json.loads(
            json.dumps(
                {
                    "service": self.service,
                    "idempotency_key": self.idempotency_key,
                    "command_hash": self.command_hash,
                    "command_id": self.command_id,
                    "correlation_id": self.correlation_id,
                    "command": self.command,
                    "actor": self.actor,
                    "expected": self.expected,
                    "status": self.status,
                    "result_state_version": self.result_state_version,
                    "result": self.result,
                    "observed_at": self.observed_at,
                },
                ensure_ascii=False,
                allow_nan=False,
            )
        )

    @classmethod
    def from_mapping(cls, value: Any) -> ReceiptProjection:
        if not isinstance(value, Mapping):
            raise ReceiptProjectionError("receipt projection must be an object")
        required = {
            "service",
            "idempotency_key",
            "command_hash",
            "command_id",
            "correlation_id",
            "command",
            "actor",
            "expected",
            "status",
            "result_state_version",
            "result",
            "observed_at",
        }
        if set(value) != required:
            raise ReceiptProjectionError("receipt projection fields are invalid")
        if value["service"] != "control-api":
            raise ReceiptProjectionError("receipt service is invalid")
        try:
            validate_idempotency_key(value["idempotency_key"])
            validate_sha256(value["command_hash"], "command_hash")
            parse_utc(value["observed_at"], field_name="observed_at")
            envelope = CommandEnvelope.model_validate(
                {
                    "schema_version": "web_bridge_control_execution_command_v1",
                    "command_id": value["command_id"],
                    "idempotency_key": value["idempotency_key"],
                    "correlation_id": value["correlation_id"],
                    "issued_at": value["observed_at"],
                    "actor": value["actor"],
                    "command": value["command"],
                    "expected": value["expected"],
                    "payload": _placeholder_payload(str(value["command"])),
                }
            )
        except (TypeError, ValueError) as exc:
            raise ReceiptProjectionError(str(exc)) from exc
        del envelope
        status = value["status"]
        if status not in _TERMINAL_STATUSES | {"UNKNOWN"}:
            raise ReceiptProjectionError("receipt status is invalid")
        version = value["result_state_version"]
        if status == "UNKNOWN":
            if version is not None:
                raise ReceiptProjectionError(
                    "UNKNOWN receipt cannot claim a result state version"
                )
        elif isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise ReceiptProjectionError(
                "terminal receipt result state version is invalid"
            )
        if not isinstance(value["result"], Mapping):
            raise ReceiptProjectionError("receipt result must be an object")
        return cls(
            service="control-api",
            idempotency_key=str(value["idempotency_key"]),
            command_hash=str(value["command_hash"]),
            command_id=str(value["command_id"]),
            correlation_id=str(value["correlation_id"]),
            command=str(value["command"]),
            actor=dict(value["actor"]),
            expected=dict(value["expected"]),
            status=str(status),
            result_state_version=version,
            result=json.loads(json.dumps(dict(value["result"]), allow_nan=False)),
            observed_at=str(value["observed_at"]),
        )


def validate_execution_receipt(value: Any) -> dict[str, Any]:
    """Validate the Execution-owned portion before Control trusts it."""

    if not isinstance(value, Mapping):
        raise ReceiptProjectionError("Execution receipt must be an object")
    required = {
        "service",
        "idempotency_key",
        "command_hash",
        "command_id",
        "correlation_id",
        "actor",
        "status",
        "state_version",
        "result",
        "observed_at",
    }
    if set(value) != required:
        raise ReceiptProjectionError("Execution receipt fields are invalid")
    if value["service"] != "control-api" or value["status"] not in _TERMINAL_STATUSES:
        raise ReceiptProjectionError("Execution receipt service/status is invalid")
    try:
        validate_idempotency_key(value["idempotency_key"])
        validate_sha256(value["command_hash"], "command_hash")
        parse_utc(value["observed_at"], field_name="observed_at")
    except (TypeError, ValueError) as exc:
        raise ReceiptProjectionError(str(exc)) from exc
    actor = value["actor"]
    if not isinstance(actor, Mapping) or set(actor) != {
        "service",
        "principal",
        "operator",
        "role",
    }:
        raise ReceiptProjectionError("Execution receipt actor is invalid")
    if any(not isinstance(item, str) or not item for item in actor.values()):
        raise ReceiptProjectionError("Execution receipt actor is invalid")
    version = value["state_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ReceiptProjectionError("Execution receipt state_version is invalid")
    if not isinstance(value["result"], Mapping):
        raise ReceiptProjectionError("Execution receipt result must be an object")
    return json.loads(json.dumps(dict(value), allow_nan=False))


def validate_command_response(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"receipt", "result", "reused"}:
        raise ReceiptProjectionError("Execution command response fields are invalid")
    receipt = validate_execution_receipt(value["receipt"])
    if (
        not isinstance(value["result"], Mapping)
        or dict(value["result"]) != receipt["result"]
    ):
        raise ReceiptProjectionError(
            "Execution command result is not bound to its receipt"
        )
    if not isinstance(value["reused"], bool):
        raise ReceiptProjectionError("Execution command reused flag is invalid")
    return {
        "receipt": receipt,
        "result": dict(value["result"]),
        "reused": value["reused"],
    }


class ControlProjectionStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = RLock()
        self._receipts: dict[str, ReceiptProjection] = {}
        self._status: ExecutionStatusProjection | None = None
        self._restore()

    def record_unknown(
        self, envelope: CommandEnvelope, *, error_code: str, observed_at: str
    ) -> ReceiptProjection:
        projection = ReceiptProjection(
            service="control-api",
            idempotency_key=envelope.idempotency_key,
            command_hash=envelope.command_hash(),
            command_id=envelope.command_id,
            correlation_id=envelope.correlation_id,
            command=envelope.command,
            actor=envelope.actor.as_dict(),
            expected=envelope.expected.as_dict(),
            status="UNKNOWN",
            result_state_version=None,
            result={"error_code": error_code, "query_same_intent_only": True},
            observed_at=observed_at,
        )
        return self._record(projection)

    def record_response(
        self, envelope: CommandEnvelope, response: Mapping[str, Any]
    ) -> ReceiptProjection:
        body = validate_command_response(response)
        return self._record(self._bind_execution_receipt(envelope, body["receipt"]))

    def resolve_receipt(
        self, pending: ReceiptProjection, receipt: Mapping[str, Any]
    ) -> ReceiptProjection:
        raw = validate_execution_receipt(receipt)
        projection = ReceiptProjection(
            **{
                **pending.as_dict(),
                "status": raw["status"],
                "result_state_version": raw["state_version"],
                "result": raw["result"],
                "observed_at": raw["observed_at"],
            }
        )
        self._assert_binding(projection, raw)
        return self._record(projection)

    def get_receipt(self, idempotency_key: str) -> ReceiptProjection | None:
        validate_idempotency_key(idempotency_key)
        with self._lock:
            return self._receipts.get(idempotency_key)

    def record_status(self, status: ExecutionStatusProjection) -> None:
        with self._lock:
            self._status = status

    def latest_status(self) -> ExecutionStatusProjection | None:
        with self._lock:
            return self._status

    def _bind_execution_receipt(
        self, envelope: CommandEnvelope, raw: Mapping[str, Any]
    ) -> ReceiptProjection:
        projection = ReceiptProjection(
            service="control-api",
            idempotency_key=envelope.idempotency_key,
            command_hash=envelope.command_hash(),
            command_id=envelope.command_id,
            correlation_id=envelope.correlation_id,
            command=envelope.command,
            actor=envelope.actor.as_dict(),
            expected=envelope.expected.as_dict(),
            status=str(raw["status"]),
            result_state_version=int(raw["state_version"]),
            result=dict(raw["result"]),
            observed_at=str(raw["observed_at"]),
        )
        self._assert_binding(projection, raw)
        return projection

    @staticmethod
    def _assert_binding(projection: ReceiptProjection, raw: Mapping[str, Any]) -> None:
        bindings = {
            "service": projection.service,
            "idempotency_key": projection.idempotency_key,
            "command_hash": projection.command_hash,
            "command_id": projection.command_id,
            "correlation_id": projection.correlation_id,
            "actor": projection.actor,
        }
        if any(raw[name] != expected for name, expected in bindings.items()):
            raise ReceiptProjectionError("Execution receipt binding mismatch")

    def _record(self, projection: ReceiptProjection) -> ReceiptProjection:
        # Validate the complete Control projection before it reaches disk.
        projection = ReceiptProjection.from_mapping(projection.as_dict())
        with self._lock:
            previous = self._receipts.get(projection.idempotency_key)
            if previous is not None:
                for field in (
                    "service",
                    "idempotency_key",
                    "command_hash",
                    "command_id",
                    "correlation_id",
                    "command",
                    "actor",
                    "expected",
                ):
                    if getattr(previous, field) != getattr(projection, field):
                        raise ReceiptProjectionError(
                            "receipt projection binding changed"
                        )
                if (
                    previous.status in _TERMINAL_STATUSES
                    and previous.as_dict() != projection.as_dict()
                ):
                    raise ReceiptProjectionError("terminal receipt projection changed")
            self._append(projection)
            self._receipts[projection.idempotency_key] = projection
        return projection

    def _restore(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    raise ReceiptProjectionError(
                        f"empty receipt journal record at line {line_number}"
                    )
                record = json.loads(line)
                if not isinstance(record, Mapping) or set(record) != {
                    "schema_version",
                    "kind",
                    "value",
                }:
                    raise ReceiptProjectionError(
                        f"invalid receipt journal record at line {line_number}"
                    )
                if (
                    record["schema_version"] != _JOURNAL_SCHEMA
                    or record["kind"] != "receipt"
                ):
                    raise ReceiptProjectionError(
                        f"unknown receipt journal record at line {line_number}"
                    )
                projection = ReceiptProjection.from_mapping(record["value"])
                previous = self._receipts.get(projection.idempotency_key)
                if (
                    previous is not None
                    and previous.status in _TERMINAL_STATUSES
                    and previous.as_dict() != projection.as_dict()
                ):
                    raise ReceiptProjectionError(
                        "terminal receipt journal entry changed"
                    )
                self._receipts[projection.idempotency_key] = projection
        except (OSError, json.JSONDecodeError, ReceiptProjectionError) as exc:
            raise RuntimeError("Control receipt projection journal is corrupt") from exc

    def _append(self, projection: ReceiptProjection) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {
                "schema_version": _JOURNAL_SCHEMA,
                "kind": "receipt",
                "value": projection.as_dict(),
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        with self.path.open("a", encoding="utf-8") as file:
            file.write(f"{line}\n")
            file.flush()
            os.fsync(file.fileno())


def _placeholder_payload(command: str) -> dict[str, Any]:
    # Receipt projections retain the validated expected/actor/command binding,
    # not the potentially sensitive command payload.  These placeholders let
    # the shared model validate the remaining command-specific shape.
    hash_value = "0" * 64
    return {
        "status": {},
        "overview": {},
        "preview": {
            "plan_hash": hash_value,
            "artifact_hash": hash_value,
            "mode": "offline_preview",
        },
        "enable": {
            "authority_artifact_id": "unknown00",
            "authority_hash": hash_value,
            "expires_at": "1970-01-01T00:00:00Z",
            "reason": "receipt projection",
        },
        "revoke": {"reason": "receipt projection"},
        "start": {
            "plan_id": "unknown00",
            "plan_hash": hash_value,
            "reason": "receipt projection",
        },
        "stop": {"reason": "receipt projection"},
        "reconcile": {
            "reconciliation_run_id": "unknown00",
            "snapshot_id": "unknown00",
            "reason": "receipt projection",
        },
        "drain": {"drain_id": "unknown00", "reason": "receipt projection"},
        "safe_to_restart": {"receipt_id": "unknown00", "reason": "receipt projection"},
    }.get(command, {})


_projection_path = os.getenv("CONTROL_AUDIT_PROJECTION_PATH", "").strip()
projection_store = ControlProjectionStore(
    Path(_projection_path) if _projection_path else None
)


__all__ = [
    "ControlProjectionStore",
    "ReceiptProjection",
    "ReceiptProjectionError",
    "projection_store",
    "validate_command_response",
    "validate_execution_receipt",
]
