from __future__ import annotations

import base64
from pathlib import Path

import pytest
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyPolicy,
    CustodySettings,
)
from app.phase_c.execution_service import (
    ExecutionSettings,
    PhaseCExecutionService,
    create_app,
)
from app.phase_c.models import SignedArtifactUploadDTO
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.phase_c_workflow.v1 import PhaseCWorkflowError, build_signing_request
from shared.trust_contracts.v1 import (
    build_signed_artifact,
    canonical_json_line,
    sha256_bytes,
    signing_bytes,
)


def artifact(payload: dict | None = None) -> dict:
    return new_artifact_envelope(
        artifact_type="runtime-authorization", trust_domain="runtime_authorization",
        producer_id="phase-c-test", producer_version="v1", schema_ref="phase-c-runtime-authorization-v1",
        generated_at="2026-08-08T00:00:00Z", scope={}, predecessor_refs=[], lineage=[],
        payload=payload or {"production_allowed": False, "live_trading_authorized": False, "countable_forward": False},
    )


def signed_and_service(tmp_path: Path) -> tuple[dict, ArtifactCustodyService]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyring = {"schema_version": "web-bridge-trust-keyring-v1", "domain": "runtime_authorization", "key_version": "v1", "keys": [{"key_id": "phase-c-test-key", "domain": "runtime_authorization", "purpose": "phase-c-runtime-authorization", "public_key_base64": base64.b64encode(public).decode(), "status": "active"}]}
    raw = canonical_json_line(keyring); keyring_path = tmp_path / "keyring.json"; keyring_path.write_bytes(raw); keyring_path.chmod(0o600)
    request = build_signing_request(artifact=artifact(), domain="runtime_authorization", key_id="phase-c-test-key", key_version="v1", request_id="request-0001", requested_at="2026-08-08T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    unsigned = {"schema_version": "web-bridge-signed-artifact-v1", "request_id": request["request_id"], "domain": request["domain"], "signer_key_id": request["key_id"], "signer_key_version": request["key_version"], "requested_at": request["requested_at"], "expires_at": request["expires_at"], "artifact": request["artifact"]}
    signed = build_signed_artifact(request, signature_base64=base64.b64encode(private.sign(signing_bytes(unsigned))).decode())
    policies = {domain: CustodyPolicy(str(keyring_path), sha256_bytes(raw), purpose) for domain, (_kind, _schema, purpose) in {"map_acceptance": ("", "", "unused"), "c_fast_acceptance": ("", "", "unused"), "runtime_authorization": ("", "", "phase-c-runtime-authorization")}.items()}
    # Only the runtime policy is reached in this fixture; the other roots are deliberately invalid if selected.
    service = ArtifactCustodyService(CustodySettings(tmp_path / "custody", "artifact-custody", 1, "test-secret", frozenset({"control-api"}), policies))
    return signed, service


def test_custody_verifies_public_key_signature_request_binding_and_durable_install(tmp_path: Path) -> None:
    signed, service = signed_and_service(tmp_path)
    receipt = service.publish_install(SignedArtifactUploadDTO(idempotency_key="custody-key-0001", expected_custody_version=0, signing_request_id="request-0001", correlation_id="correlation-0001", signed_artifact=signed), principal="control-api")
    assert receipt.receipt_type == "install" and receipt.custody_version == 2
    assert service.receipt(receipt.receipt_id) == receipt
    with pytest.raises(WorkflowAdapterError):
        service.publish_install(SignedArtifactUploadDTO(idempotency_key="custody-key-0002", expected_custody_version=2, signing_request_id="wrong-request", correlation_id="correlation-0002", signed_artifact=signed), principal="control-api")


def test_sensitive_fields_cannot_be_exported() -> None:
    with pytest.raises(PhaseCWorkflowError):
        build_signing_request(artifact=artifact({"secret": "no", "production_allowed": False, "live_trading_authorized": False, "countable_forward": False}), domain="runtime_authorization", key_id="key", key_version="v1", request_id="request-0001", requested_at="2026-08-08T00:00:00Z", expires_at="2099-01-01T00:00:00Z")


def test_execution_service_consumes_only_custody_receipt_and_keeps_runtime_disabled(tmp_path: Path) -> None:
    receipt = {"receipt_id": "custody-install-1", "receipt_type": "install", "artifact_id": "artifact-1"}
    service = PhaseCExecutionService(ExecutionSettings(tmp_path / "state.json", "execution-secret", "http://custody", "custody-secret"), receipt_lookup=lambda _: receipt)
    from fastapi.testclient import TestClient
    app = create_app(service)
    payload = {"command_id": "command-0001", "idempotency_key": "idem-key-0001", "expected_version": 0, "action": "enable", "authorization_artifact_id": "artifact-1", "custody_receipt_id": "custody-install-1", "reason": "offline only"}
    with TestClient(app) as client:
        response = client.post("/internal/v1/authorization/commands", json=payload, headers={"X-Phase-C-Principal": "control-api", "X-Phase-C-Execution-Secret": "execution-secret"})
        assert response.status_code == 200
        assert response.json()["effective_state"] == "DISABLED"
        assert response.json()["runtime_mutation_allowed"] is False
    state = tmp_path / "state.json"
    tampered = state.read_bytes().replace(b"ENABLE_REQUESTED", b"ENABLE_REQUESTEDX")
    state.write_bytes(tampered)
    with pytest.raises(WorkflowAdapterError, match="durable state"):
        service.status()
