from __future__ import annotations

import httpx
import pytest
from app.phase_c.adapters import UnknownOutcomeError
from app.phase_c.client import PhaseCRemoteSettings, RemotePhaseCWorkflowClient
from app.phase_c.models import (
    SignedArtifactUploadDTO,
    TrustedKeylessTargetPlanUploadDTO,
)


def test_remote_mutation_timeout_is_explicit_unknown_outcome() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(handler),
    )
    payload = SignedArtifactUploadDTO(
        idempotency_key="custody-key-0001",
        expected_custody_version=0,
        signing_request_id="request-0001",
        correlation_id="correlation-0001",
        signed_artifact={},
    )
    with pytest.raises(UnknownOutcomeError) as exc:
        client.install(payload)
    assert exc.value.code == "PHASE_C_UNKNOWN_OUTCOME"
    assert exc.value.status_code == 503


def test_remote_keyless_publish_uses_dedicated_custody_contract() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/v1/publish-keyless-simnow-target-plan"
        assert request.method == "POST"
        return httpx.Response(
            200,
            json={
                "receipt_id": "keyless-install-0001",
                "receipt_type": "install",
                "artifact_id": "artifact-keyless-0001",
                "artifact_type": "simnow-target-plan",
                "trust_domain": "runtime_authorization",
                "schema_ref": "web-bridge-simnow-keyless-target-plan-v1",
                "artifact_sha256": "a" * 64,
                "scope": {"account_scope": "account:windows", "environment": "SIMNOW", "gateway_name": "CTP"},
                "expires_at": "2099-01-01T00:00:00Z",
                "custody_version": 2,
                "idempotency_key": "keyless-publish-0001",
                "verified": True,
                "installed": True,
                "custody_writer": "artifact-custody",
                "production_allowed": False,
                "live_trading_authorized": False,
                "countable_forward": False,
            },
        )

    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(handler),
    )
    receipt = client.install_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key="keyless-publish-0001",
            expected_custody_version=0,
            correlation_id="keyless-correlation-0001",
            artifact={},
        )
    )
    assert receipt.schema_ref == "web-bridge-simnow-keyless-target-plan-v1"
