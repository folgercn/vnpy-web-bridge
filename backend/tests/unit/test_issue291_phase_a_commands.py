from __future__ import annotations

import pytest
from app.execution import (
    CommandEnvelope,
    ExecutionOrchestrator,
    InMemoryExecutionRepository,
)
from app.execution.errors import (
    CommandValidationError,
    ExpectedVersionConflict,
    IdempotencyConflictError,
)

HASH = "a" * 64


def envelope(command: str, key: str, version: int, payload: dict) -> dict:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"command-{key[-8:]}",
        "idempotency_key": key,
        "correlation_id": f"correlation-{key[-8:]}",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "unit-test",
            "operator": "unit-test",
            "role": "admin",
        },
        "command": command,
        "expected": {"state_version": version},
        "payload": payload,
    }


def test_command_envelope_is_strict_and_canonical() -> None:
    raw = envelope("status", "status-key-0000001", 0, {})
    parsed = CommandEnvelope.model_validate(raw)
    assert parsed.model_dump(mode="json")["payload"] == {}
    assert parsed.command_hash() == parsed.fingerprint()
    raw["unknown"] = True
    with pytest.raises(CommandValidationError):
        CommandEnvelope.model_validate(raw)


def test_same_idempotency_key_reuses_receipt_and_conflict_rejects() -> None:
    repository = InMemoryExecutionRepository()
    service = ExecutionOrchestrator(repository=repository)
    first = service.process_command(
        envelope(
            "enable",
            "enable-key-0000001",
            1,
            {
                "authority_artifact_id": "artifact-1",
                "authority_hash": HASH,
                "expires_at": "2030-01-01T00:00:00Z",
                "reason": "unit test authority",
            },
        )
    )
    retry = service.process_command(
        envelope(
            "enable",
            "enable-key-0000001",
            1,
            {
                "authority_artifact_id": "artifact-1",
                "authority_hash": HASH,
                "expires_at": "2030-01-01T00:00:00Z",
                "reason": "unit test authority",
            },
        )
    )
    assert retry.reused is True
    assert retry.receipt == first.receipt
    conflict = envelope(
        "revoke", "enable-key-0000001", 1, {"reason": "different command"}
    )
    with pytest.raises(IdempotencyConflictError):
        service.process_command(conflict)


def test_expected_version_conflict_has_no_side_effect() -> None:
    repository = InMemoryExecutionRepository()
    service = ExecutionOrchestrator(repository=repository)
    before = repository.snapshot()
    with pytest.raises(ExpectedVersionConflict):
        service.process_command(envelope("status", "status-key-0000002", 0, {}))
    assert repository.snapshot()["state_version"] == before["state_version"]
