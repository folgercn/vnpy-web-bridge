from __future__ import annotations

import httpx
import pytest
from app.phase_c.adapters import UnknownOutcomeError, WorkflowAdapterError
from app.phase_c.client import PhaseCRemoteSettings, RemotePhaseCWorkflowClient
from app.phase_c.models import (
    SignedArtifactUploadDTO,
    TrustedKeylessTargetPlanInstallContinuationDTO,
    TrustedKeylessTargetPlanUploadDTO,
)
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution.v1 import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    build_trusted_keyless_target_plan_v2,
    target_position_projection_hash,
)


def _artifact() -> dict[str, object]:
    positions = {
        "rb2601.SHFE.LONG.CTP.full": {
            "gateway_name": "CTP",
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }
    plan = build_trusted_keyless_target_plan_v2(
        plan_id="static-core-equal-remote-open-0001",
        account_scope="account:windows",
        environment="SIMNOW",
        gateway_name="CTP",
        lineage={
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": "c" * 64,
        },
        scope=dict(TRUSTED_KEYLESS_SIMNOW_SCOPE),
        generated_at="2026-08-18T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        phase="OPEN",
        expected_before_position_hash=before_position_projection_hash(
            {}, account_scope="account:windows", environment="SIMNOW"
        ),
        expected_after_position_hash=target_position_projection_hash(
            positions, account_scope="account:windows", environment="SIMNOW"
        ),
        orders=[
            {
                "symbol": "rb2601",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0,
                "offset": "OPEN",
                "reference": "issue362-remote-open-order-0001",
                "gateway_name": "CTP",
            }
        ],
    )
    return new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="issue362-remote-recovery",
        producer_version="v1",
        schema_ref=KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        payload=plan,
        generated_at=str(plan["generated_at"]),
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
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
    artifact = _artifact()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/v1/publish-keyless-simnow-target-plan"
        assert request.method == "POST"
        return httpx.Response(
            200,
            json={
                "receipt_id": "keyless-install-remote-0001",
                "receipt_type": "install",
                "artifact_id": artifact["artifact_id"],
                "artifact_type": "simnow-target-plan",
                "trust_domain": "runtime_authorization",
                "schema_ref": artifact["schema_ref"],
                "artifact_sha256": artifact["raw_sha256"],
                "scope": artifact["scope"],
                "expires_at": "2099-01-01T00:00:00Z",
                "custody_version": 2,
                "idempotency_key": "install-keyless-publish-0001",
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
            artifact=artifact,
        )
    )
    assert receipt.schema_ref == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION


def _continuation(
    artifact: dict[str, object] | None = None,
) -> TrustedKeylessTargetPlanInstallContinuationDTO:
    return TrustedKeylessTargetPlanInstallContinuationDTO(
        idempotency_key="keyless-publish-0001",
        correlation_id="keyless-correlation-0001",
        publish_receipt_id="receipt-" + "a" * 64,
        publish_receipt_sha256="b" * 64,
        publish_expected_custody_version=0,
        publish_resulting_custody_version=1,
        artifact=artifact or {},
    )


def test_remote_install_only_transport_unknown_requires_exact_query() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(UnknownOutcomeError) as caught:
        client.install_published_trusted_keyless_target_plan(_continuation())
    assert caught.value.retryable is False
    assert caught.value.detail == {
        "query_path": (
            "/internal/v1/target-plan-publications/by-idempotency/keyless-publish-0001"
        ),
        "query_same_intent_only": True,
    }


def test_remote_install_only_preserves_structured_stop_retry_error() -> None:
    detail = {
        "code": "PHASE_C_CUSTODY_WRITER_BUSY",
        "message": "custody writer is temporarily busy",
        "retryable": True,
    }
    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(503, json={"detail": detail})
        ),
    )
    with pytest.raises(WorkflowAdapterError) as caught:
        client.install_published_trusted_keyless_target_plan(_continuation())
    assert caught.value.code == detail["code"]
    assert str(caught.value) == detail["message"]
    assert caught.value.retryable is True
    assert caught.value.detail == detail


def test_remote_publication_rejects_foreign_response_key() -> None:
    requested = "keyless-publish-0001"
    foreign = "keyless-publish-foreign-0002"
    response = {
        "schema_version": "phase-c-target-plan-publication-v1",
        "state": "NOT_PUBLISHED",
        "idempotency_key": foreign,
        "install_idempotency_key": f"install-{foreign}",
        "observed_custody_version": 0,
        "custody_state_owner": "artifact-custody",
        "publisher_principal": None,
        "correlation_id": None,
        "artifact_id": None,
        "artifact_canonical_sha256": None,
        "artifact_raw_sha256": None,
        "artifact_schema_ref": None,
        "plan_schema_version": None,
        "plan_id": None,
        "plan_hash": None,
        "plan_phase": None,
        "publish_receipt_id": None,
        "publish_receipt_sha256": None,
        "publish_expected_custody_version": None,
        "publish_resulting_custody_version": None,
        "install_receipt_id": None,
        "install_receipt_sha256": None,
        "install_expected_custody_version": None,
        "install_resulting_custody_version": None,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(WorkflowAdapterError) as caught:
        client.target_plan_publication(requested)
    assert caught.value.code == "PHASE_C_RESPONSE_BINDING_INVALID"
    assert caught.value.retryable is False


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"receipt_id": "malformed"}),
    ],
    ids=["invalid-json", "non-object", "invalid-dto"],
)
def test_remote_install_only_2xx_unclassifiable_is_unknown_query_only(
    response: httpx.Response,
) -> None:
    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(lambda _: response),
    )
    with pytest.raises(UnknownOutcomeError) as caught:
        client.install_published_trusted_keyless_target_plan(_continuation())
    assert caught.value.retryable is False
    assert caught.value.detail == {
        "query_path": (
            "/internal/v1/target-plan-publications/by-idempotency/keyless-publish-0001"
        ),
        "query_same_intent_only": True,
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("idempotency_key", "install-keyless-publish-foreign-0002"),
        ("artifact_id", "artifact-keyless-foreign-0002"),
        ("artifact_sha256", "f" * 64),
        ("schema_ref", "web-bridge-simnow-keyless-target-plan-v1"),
        (
            "scope",
            {
                "account_scope": "account:foreign",
                "environment": "SIMNOW",
                "gateway_name": "CTP",
            },
        ),
    ],
)
def test_remote_install_only_2xx_foreign_receipt_is_unknown_query_only(
    field: str, replacement: object
) -> None:
    artifact = _artifact()
    response = {
        "receipt_id": "keyless-install-remote-0001",
        "receipt_type": "install",
        "artifact_id": artifact["artifact_id"],
        "artifact_type": "simnow-target-plan",
        "trust_domain": "runtime_authorization",
        "schema_ref": artifact["schema_ref"],
        "artifact_sha256": artifact["raw_sha256"],
        "scope": artifact["scope"],
        "expires_at": "2099-01-01T00:00:00Z",
        "custody_version": 2,
        "idempotency_key": "install-keyless-publish-0001",
        "verified": True,
        "installed": True,
        "custody_writer": "artifact-custody",
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    response[field] = replacement
    client = RemotePhaseCWorkflowClient(
        PhaseCRemoteSettings("http://custody", "http://execution", "c", "e"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(UnknownOutcomeError) as caught:
        client.install_published_trusted_keyless_target_plan(_continuation(artifact))
    assert caught.value.retryable is False
    assert caught.value.detail["query_same_intent_only"] is True
