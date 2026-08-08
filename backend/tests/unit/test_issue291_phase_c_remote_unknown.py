from __future__ import annotations

import httpx
import pytest
from app.phase_c.adapters import UnknownOutcomeError
from app.phase_c.client import PhaseCRemoteSettings, RemotePhaseCWorkflowClient
from app.phase_c.models import SignedArtifactUploadDTO


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
