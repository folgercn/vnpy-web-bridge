from __future__ import annotations

import json
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from copy import deepcopy
from pathlib import Path
from threading import Barrier, Event, Lock

import pytest
from app.phase_c.adapters import (
    ExpectedVersionError,
    IdempotencyConflictError,
    WorkflowAdapterError,
)
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyEvidenceReadError,
    CustodySettings,
    CustodyWriterBusyError,
    create_app,
)
from app.phase_c.models import (
    TargetPlanPublicationProjectionDTO,
    TrustedKeylessTargetPlanInstallContinuationDTO,
    TrustedKeylessTargetPlanUploadDTO,
)
from fastapi.testclient import TestClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.artifact_custody.v1 import ArtifactCustody
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    build_trusted_keyless_target_plan_v2,
    target_position_projection_hash,
)
from shared.trust_contracts.v1 import canonical_json_line


PUBLISH_KEY = "issue362-phase-open-0001"
CORRELATION_ID = "issue362-event-open-0001"
HEADERS = {
    "X-Phase-C-Principal": "control-api",
    "X-Phase-C-Custody-Secret": "issue362-control-secret",
}


def _tree(root: Path) -> dict[str, tuple[str, bytes | None]]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): (
            "dir" if path.is_dir() else "file",
            None if path.is_dir() else path.read_bytes(),
        )
        for path in sorted(root.rglob("*"))
    }


def _service(tmp_path: Path) -> ArtifactCustodyService:
    return ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            HEADERS["X-Phase-C-Custody-Secret"],
            frozenset({"control-api"}),
            {},
            "issue362-execution-read-secret",
            None,
            True,
        )
    )


def _artifact(sequence: int = 1) -> dict[str, object]:
    symbol = f"rb26{sequence:02d}"
    positions = {
        f"{symbol}.SHFE.LONG.CTP.full": {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }
    plan = build_trusted_keyless_target_plan_v2(
        plan_id=f"static-core-equal-open-{sequence:04d}",
        account_scope="account:windows",
        environment="SIMNOW",
        gateway_name="CTP",
        lineage={
            "static_core_equal_sha256": "a" * 64,
            "position_manager_sha256": "b" * 64,
            "final_target_sha256": f"{sequence:x}" * 64,
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
                "symbol": symbol,
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 3500.0 + sequence,
                "offset": "OPEN",
                "reference": f"issue362-phase-open-order-{sequence:04d}",
                "gateway_name": "CTP",
            }
        ],
    )
    return new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="issue362-phase-c-recovery",
        producer_version="v1",
        schema_ref=KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        payload=plan,
        generated_at=str(plan["generated_at"]),
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )


def _publish_only(
    service: ArtifactCustodyService,
    artifact: dict[str, object],
    *,
    key: str = PUBLISH_KEY,
    correlation_id: str = CORRELATION_ID,
    expected_version: int = 0,
) -> dict[str, object]:
    with service._custody() as custody:
        return custody.publish(
            artifact,
            actor_id="control-api",
            idempotency_key=key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )


def _continuation(
    projection: TargetPlanPublicationProjectionDTO,
    base_artifact: dict[str, object],
    **changes: object,
) -> TrustedKeylessTargetPlanInstallContinuationDTO:
    raw: dict[str, object] = {
        "idempotency_key": projection.idempotency_key,
        "correlation_id": projection.correlation_id,
        "publish_receipt_id": projection.publish_receipt_id,
        "publish_receipt_sha256": projection.publish_receipt_sha256,
        "publish_expected_custody_version": (
            projection.publish_expected_custody_version
        ),
        "publish_resulting_custody_version": (
            projection.publish_resulting_custody_version
        ),
        "artifact": base_artifact,
    }
    raw.update(changes)
    return TrustedKeylessTargetPlanInstallContinuationDTO.model_validate(raw)


def test_publication_projection_is_authenticated_and_zero_write_when_absent(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    root = service.settings.root
    app = create_app(service)
    path = (
        "/internal/v1/target-plan-publications/by-idempotency/"
        "issue362-phase-missing-0001"
    )
    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        response = client.get(path, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["state"] == "NOT_PUBLISHED"
    assert response.json()["observed_custody_version"] == 0
    assert response.json()["production_allowed"] is False
    assert not root.exists()


def test_publication_projection_allows_only_dedicated_execution_read_credential(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    before = _tree(service.settings.root)
    path = "/internal/v1/target-plan-publications/by-idempotency/" + PUBLISH_KEY
    execution_headers = {
        "X-Phase-C-Principal": "execution-orchestrator",
        "X-Phase-C-Custody-Secret": "issue362-execution-read-secret",
    }
    with TestClient(create_app(service)) as client:
        missing_secret = client.get(
            path,
            headers={"X-Phase-C-Principal": "execution-orchestrator"},
        )
        wrong_secret = client.get(
            path,
            headers={
                **execution_headers,
                "X-Phase-C-Custody-Secret": HEADERS["X-Phase-C-Custody-Secret"],
            },
        )
        wrong_principal = client.get(
            path,
            headers={
                "X-Phase-C-Principal": "phase-c-execution",
                "X-Phase-C-Custody-Secret": "issue362-execution-read-secret",
            },
        )
        response = client.get(path, headers=execution_headers)

    assert missing_secret.status_code == 401
    assert wrong_secret.status_code == 401
    assert wrong_principal.status_code == 401
    assert response.status_code == 200
    projection = response.json()
    assert projection["state"] == "PUBLISHED_NOT_INSTALLED"
    assert projection["publisher_principal"] == "control-api"
    assert projection["correlation_id"] == CORRELATION_ID
    assert projection["artifact_schema_ref"] == projection["plan_schema_version"]
    assert "artifact" not in projection
    assert "orders" not in projection
    assert _tree(service.settings.root) == before


def test_existing_incomplete_root_is_retryable_not_false_unpublished(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    service.settings.root.mkdir(mode=0o700)
    before = _tree(service.settings.root)

    with pytest.raises(WorkflowAdapterError) as raised:
        service.target_plan_publication("issue362-phase-missing-0001")

    assert raised.value.status_code == 503
    assert _tree(service.settings.root) == before


def test_crash_after_publish_projects_exact_evidence_without_writing(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    published = _publish_only(service, artifact)
    before = _tree(service.settings.root)

    projection = service.target_plan_publication(PUBLISH_KEY)

    assert projection.state == "PUBLISHED_NOT_INSTALLED"
    assert projection.publish_receipt_id == published["receipt_id"]
    assert projection.publish_expected_custody_version == 0
    assert projection.publish_resulting_custody_version == 1
    assert projection.artifact_id == artifact["artifact_id"]
    assert projection.artifact_canonical_sha256 == artifact["canonical_sha256"]
    assert projection.artifact_raw_sha256 == artifact["raw_sha256"]
    assert projection.artifact_schema_ref == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert projection.plan_id == artifact["payload"]["plan_id"]  # type: ignore[index]
    assert projection.plan_hash == artifact["payload"]["plan_hash"]  # type: ignore[index]
    assert projection.plan_phase == "OPEN"
    assert projection.install_receipt_id is None
    assert _tree(service.settings.root) == before


def test_install_only_continues_once_and_response_lost_retry_is_exact(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    request = _continuation(service.target_plan_publication(PUBLISH_KEY), artifact)

    first = service.install_published_trusted_keyless_target_plan(
        request, principal="control-api"
    )
    after_first = _tree(service.settings.root)
    second = service.install_published_trusted_keyless_target_plan(
        request, principal="control-api"
    )

    assert second == first
    assert first["idempotency_key"] == f"install-{PUBLISH_KEY}"
    assert first["custody_version"] == 2
    assert _tree(service.settings.root) == after_first
    installed = service.target_plan_publication(PUBLISH_KEY)
    assert installed.state == "INSTALLED"
    assert installed.install_receipt_id == first["receipt_id"]
    assert installed.install_expected_custody_version == 1
    assert installed.install_resulting_custody_version == 2


def test_concurrent_install_only_busy_retry_converges_without_duplicate_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    request = _continuation(service.target_plan_publication(PUBLISH_KEY), artifact)
    original_projection = service.target_plan_publication
    original_record = ArtifactCustody.record
    projection_barrier = Barrier(2)
    projection_lock = Lock()
    projection_calls = 0
    record_lock = Lock()
    record_held = False
    record_entered = Event()
    release_record = Event()

    def synchronized_projection(
        idempotency_key: str,
    ) -> TargetPlanPublicationProjectionDTO:
        nonlocal projection_calls
        result = original_projection(idempotency_key)
        with projection_lock:
            projection_calls += 1
            synchronize = projection_calls <= 2
        if synchronize:
            projection_barrier.wait(timeout=5)
        return result

    def held_first_install(
        custody: ArtifactCustody,
        receipt_type: str,
        artifact_id: str,
        **kwargs: object,
    ) -> dict[str, object]:
        nonlocal record_held
        hold = False
        if (
            receipt_type == "install"
            and kwargs.get("idempotency_key") == f"install-{PUBLISH_KEY}"
        ):
            with record_lock:
                if not record_held:
                    record_held = True
                    hold = True
        if hold:
            record_entered.set()
            assert release_record.wait(timeout=5)
        return original_record(  # type: ignore[return-value]
            custody,
            receipt_type,
            artifact_id,
            **kwargs,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(service, "target_plan_publication", synchronized_projection)
    monkeypatch.setattr(ArtifactCustody, "record", held_first_install)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.install_published_trusted_keyless_target_plan,
                request,
                principal="control-api",
            )
            for _ in range(2)
        ]
        assert record_entered.wait(timeout=5)
        done, pending = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
        assert len(done) == 1
        busy = done.pop()
        with pytest.raises(CustodyWriterBusyError) as raised:
            busy.result()
        assert raised.value.code == "PHASE_C_CUSTODY_WRITER_BUSY"
        assert raised.value.status_code == 503
        release_record.set()
        assert len(pending) == 1
        installed = pending.pop().result(timeout=5)

    after_install = _tree(service.settings.root)
    retried = service.install_published_trusted_keyless_target_plan(
        request, principal="control-api"
    )

    assert retried == installed
    assert retried["custody_version"] == 2
    assert _tree(service.settings.root) == after_install
    assert len(list((service.settings.root / "receipts").iterdir())) == 2


def test_install_only_http_writer_contention_is_retryable(tmp_path: Path) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    request = _continuation(service.target_plan_publication(PUBLISH_KEY), artifact)
    path = "/internal/v1/install-published-keyless-simnow-target-plan"
    before = _tree(service.settings.root)

    with service._custody():
        with TestClient(create_app(service)) as client:
            response = client.post(
                path, json=request.model_dump(mode="json"), headers=HEADERS
            )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "PHASE_C_CUSTODY_WRITER_BUSY",
        "message": ("custody writer is temporarily busy; retry the exact same intent"),
        "retryable": True,
    }
    assert _tree(service.settings.root) == before

    with TestClient(create_app(service)) as client:
        retried = client.post(
            path, json=request.model_dump(mode="json"), headers=HEADERS
        )
    assert retried.status_code == 200
    assert retried.json()["custody_version"] == 2


def test_install_only_exact_retry_recovers_an_already_installed_publication(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    installed = service.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key=PUBLISH_KEY,
            expected_custody_version=0,
            correlation_id=CORRELATION_ID,
            artifact=artifact,
        ),
        principal="control-api",
    )
    projection = service.target_plan_publication(PUBLISH_KEY)
    before = _tree(service.settings.root)

    recovered = service.install_published_trusted_keyless_target_plan(
        _continuation(projection, artifact), principal="control-api"
    )

    assert recovered == installed
    assert _tree(service.settings.root) == before


def test_install_only_rejects_unknown_and_all_cross_spliced_bindings(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    unknown = TrustedKeylessTargetPlanInstallContinuationDTO(
        idempotency_key=PUBLISH_KEY,
        correlation_id=CORRELATION_ID,
        publish_receipt_id="receipt-" + "a" * 64,
        publish_receipt_sha256="b" * 64,
        publish_expected_custody_version=0,
        publish_resulting_custody_version=1,
        artifact=artifact,
    )
    with pytest.raises(WorkflowAdapterError, match="does not exist"):
        service.install_published_trusted_keyless_target_plan(
            unknown, principal="control-api"
        )
    assert not service.settings.root.exists()

    _publish_only(service, artifact)
    projection = service.target_plan_publication(PUBLISH_KEY)
    before = _tree(service.settings.root)
    mismatches = (
        {"artifact": _artifact(2)},
        {"publish_receipt_id": "receipt-" + "c" * 64},
        {"publish_receipt_sha256": "d" * 64},
        {
            "publish_expected_custody_version": 7,
            "publish_resulting_custody_version": 8,
        },
        {"correlation_id": "issue362-event-open-cross-splice"},
    )
    for changes in mismatches:
        with pytest.raises(IdempotencyConflictError):
            service.install_published_trusted_keyless_target_plan(
                _continuation(projection, artifact, **changes),
                principal="control-api",
            )

    wrong_schema = deepcopy(artifact)
    wrong_schema["schema_ref"] = KEYLESS_TARGET_PLAN_SCHEMA_VERSION
    with pytest.raises(WorkflowAdapterError, match="tuple is invalid"):
        service.install_published_trusted_keyless_target_plan(
            _continuation(projection, wrong_schema), principal="control-api"
        )
    assert _tree(service.settings.root) == before


def test_install_only_fails_closed_on_custody_version_drift(tmp_path: Path) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    projection = service.target_plan_publication(PUBLISH_KEY)
    _publish_only(
        service,
        _artifact(2),
        key="issue362-phase-open-unrelated-0002",
        correlation_id="issue362-event-open-unrelated-0002",
        expected_version=1,
    )
    before = _tree(service.settings.root)

    with pytest.raises(ExpectedVersionError):
        service.install_published_trusted_keyless_target_plan(
            _continuation(projection, artifact), principal="control-api"
        )

    assert _tree(service.settings.root) == before
    assert service.target_plan_publication(PUBLISH_KEY).state == (
        "PUBLISHED_NOT_INSTALLED"
    )


def test_tampered_publication_evidence_fails_closed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _publish_only(service, _artifact())
    receipt_path = next((service.settings.root / "receipts").iterdir())
    record = json.loads(receipt_path.read_text(encoding="utf-8"))
    record["receipt"]["artifact_raw_sha256"] = "f" * 64
    receipt_path.write_bytes(canonical_json_line(record))
    before = _tree(service.settings.root)

    with pytest.raises(CustodyEvidenceReadError):
        service.target_plan_publication(PUBLISH_KEY)

    assert _tree(service.settings.root) == before


def test_install_only_http_is_authenticated_and_never_republishes(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    _publish_only(service, artifact)
    request = _continuation(service.target_plan_publication(PUBLISH_KEY), artifact)
    path = "/internal/v1/install-published-keyless-simnow-target-plan"

    with TestClient(create_app(service)) as client:
        assert (
            client.post(path, json=request.model_dump(mode="json")).status_code == 401
        )
        response = client.post(
            path, json=request.model_dump(mode="json"), headers=HEADERS
        )

    assert response.status_code == 200
    assert response.json()["idempotency_key"] == f"install-{PUBLISH_KEY}"
    assert service.current_version().version == 2


def test_install_only_http_exposes_stop_vs_retry_contract(tmp_path: Path) -> None:
    service = _service(tmp_path)
    artifact = _artifact()
    unknown = TrustedKeylessTargetPlanInstallContinuationDTO(
        idempotency_key=PUBLISH_KEY,
        correlation_id=CORRELATION_ID,
        publish_receipt_id="receipt-" + "a" * 64,
        publish_receipt_sha256="b" * 64,
        publish_expected_custody_version=0,
        publish_resulting_custody_version=1,
        artifact=artifact,
    )
    path = "/internal/v1/install-published-keyless-simnow-target-plan"

    with TestClient(create_app(service)) as client:
        response = client.post(
            path, json=unknown.model_dump(mode="json"), headers=HEADERS
        )

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "PHASE_C_TARGET_PLAN_PUBLICATION_NOT_FOUND",
        "message": "target-plan publication does not exist; install cannot continue",
        "retryable": False,
    }
