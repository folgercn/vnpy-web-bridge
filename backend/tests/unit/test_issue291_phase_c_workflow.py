from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.control_api import app
from app.core.security import CurrentUser, create_access_token
from app.phase_c.adapters import (
    ExpectedVersionError,
    OfflineFakeWorkflowAdapter,
    UnknownOutcomeError,
)
from app.phase_c.client import OfflineFakeWorkflowClient
from app.phase_c.models import AuthorizationCommandDTO, SignedArtifactUploadDTO
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from shared.phase_c_workflow.v1 import build_signing_request


def _headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def _artifact() -> dict:
    return {
        "artifact_id": "artifact-" + "a" * 64,
        "artifact_type": "runtime-authorization",
        "payload": {
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
    }


def _signed() -> dict:
    return {
        "schema_version": "web-bridge-signed-artifact-v1",
        "request_id": "request-0001",
        "domain": "runtime_authorization",
        "signer_key_id": "offline-test-key",
        "signer_key_version": "v1",
        "requested_at": "2026-08-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "artifact": _artifact(),
        "signature": "offline-test-signature",
    }


def _upload(version: int = 0, key: str = "upload-key-0001") -> SignedArtifactUploadDTO:
    return SignedArtifactUploadDTO(
        idempotency_key=key,
        expected_custody_version=version,
        signing_request_id="request-0001",
        signed_artifact=_signed(),
    )


def _command(receipt_id: str, version: int = 0, key: str = "enable-key-0001") -> AuthorizationCommandDTO:
    return AuthorizationCommandDTO(
        command_id="command-0001",
        idempotency_key=key,
        expected_version=version,
        action="enable",
        authorization_artifact_id=_artifact()["artifact_id"],
        custody_receipt_id=receipt_id,
        reason="offline workflow contract test",
    )


def test_signing_request_is_export_only_and_rejects_true_authority() -> None:
    exported = build_signing_request(
        artifact=_artifact(),
        domain="runtime_authorization",
        request_id="request-0001",
        requested_by="admin",
    )
    assert exported["browser_signing"] is False
    assert exported["private_key_access"] is False
    assert all(exported[name] is False for name in ("production_allowed", "live_trading_authorized", "countable_forward"))


def test_phase_c_schemas_are_strict_draft202012_contracts() -> None:
    root = Path(__file__).resolve().parents[3]
    for name in (
        "issue-291-phase-c-signing-request-v1.schema.json",
        "issue-291-phase-c-authorization-command-v1.schema.json",
    ):
        schema = json.loads((root / "docs/schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


def test_offline_fake_full_chain_is_idempotent_versioned_and_never_effective() -> None:
    adapter = OfflineFakeWorkflowAdapter()
    client = OfflineFakeWorkflowClient(adapter)
    receipt = client.install(_upload())
    assert receipt.verified is True and receipt.installed is True
    assert client.install(_upload()).receipt_id == receipt.receipt_id
    with pytest.raises(ExpectedVersionError):
        client.install(_upload(version=0, key="upload-key-0002"))

    result = client.authorization_command(_command(receipt.receipt_id))
    assert result.requested_state == "ENABLE_REQUESTED"
    assert result.effective_state == "DISABLED"
    assert result.runtime_mutation_allowed is False
    assert client.authorization_command(_command(receipt.receipt_id)).version == result.version
    with pytest.raises(ExpectedVersionError):
        client.authorization_command(_command(receipt.receipt_id, version=0, key="enable-key-0002"))
    projection = client.execution_projection()
    assert projection.execution_mutation_allowed is False
    assert projection.audit and projection.archive


def test_unknown_outcome_is_durable_and_same_key_can_be_queried_or_retried() -> None:
    adapter = OfflineFakeWorkflowAdapter()
    adapter.execution.unknown_outcome_once = True
    client = OfflineFakeWorkflowClient(adapter)
    receipt = client.install(_upload())
    command = _command(receipt.receipt_id)
    with pytest.raises(UnknownOutcomeError):
        client.authorization_command(command)
    resolved = client.authorization_receipt(command.idempotency_key)
    assert resolved is not None and resolved.version == 1
    assert client.authorization_command(command).version == 1


def test_api_enforces_rbac_and_exposes_only_fake_safe_projections(monkeypatch) -> None:
    import app.api.routes_phase_c_workflow as routes

    monkeypatch.setattr(routes, "phase_c_workflow_client", OfflineFakeWorkflowClient())
    with TestClient(app) as http:
        assert http.get("/api/phase-c/workflow/status", headers=_headers("viewer")).status_code == 200
        export = http.post(
            "/api/phase-c/signing-requests/export",
            headers=_headers("viewer"),
            json={"request_id": "request-0001", "domain": "runtime_authorization", "artifact": _artifact()},
        )
        assert export.status_code == 403
        upload = http.post(
            "/api/phase-c/artifacts/upload-install",
            headers=_headers("admin"),
            json=_upload().model_dump(mode="json"),
        )
        assert upload.status_code == 200
        receipt = upload.json()["data"]
        command = http.post(
            "/api/phase-c/authorization/commands",
            headers=_headers("admin"),
            json=_command(receipt["receipt_id"]).model_dump(mode="json"),
        )
        assert command.status_code == 200
        assert command.json()["data"]["runtime_mutation_allowed"] is False
        execution = http.get("/api/phase-c/execution/audit", headers=_headers("viewer"))
        assert execution.status_code == 200
        assert execution.json()["data"]["execution_mutation_allowed"] is False
