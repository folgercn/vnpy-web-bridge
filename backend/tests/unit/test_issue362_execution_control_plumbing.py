from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
    ExecutionRejectedError,
)
from app.execution import (
    DurableExecutionRepository,
    ExecutionOrchestrator,
    FencingError,
    InMemoryExecutionRepository,
)
from app.execution_orchestrator import create_app as create_execution_app
from app.phase_c.adapters import WorkflowAdapterError
from app.phase_c.client import PhaseCRemoteSettings, RemotePhaseCWorkflowClient
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodySettings,
    create_app as create_custody_app,
)
from fastapi.testclient import TestClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.artifact_custody.v1 import ArtifactCustody, CustodyError


EXECUTION_SECRET = "issue362-execution-secret"
EXECUTION_HEADERS = {
    "X-Control-Service": "control-api",
    "X-Control-Execution-Secret": EXECUTION_SECRET,
}
CUSTODY_HEADERS = {
    "X-Phase-C-Principal": "control-api",
    "X-Phase-C-Custody-Secret": "issue362-custody-secret",
}


def _persisted_leader_token(token: object) -> dict[str, object]:
    value = token.as_dict()  # type: ignore[attr-defined]
    value.pop("held")
    return value


def _execution_service(
    repository: InMemoryExecutionRepository | DurableExecutionRepository | None = None,
) -> ExecutionOrchestrator:
    scope = "account:issue362"
    return ExecutionOrchestrator(
        repository or InMemoryExecutionRepository(scope=scope),
        scope=scope,
        test_mode=True,
    )


def _custody_service(root: Path, *, writer_epoch: int = 1) -> ArtifactCustodyService:
    return ArtifactCustodyService(
        CustodySettings(
            root,
            "artifact-custody",
            writer_epoch,
            CUSTODY_HEADERS["X-Phase-C-Custody-Secret"],
            frozenset({"control-api"}),
            {},
            "issue362-execution-read-secret",
            None,
            True,
        )
    )


def _tree_contents(root: Path) -> dict[str, tuple[str, bytes | None]]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): (
            "dir" if path.is_dir() else "file",
            None if path.is_dir() else path.read_bytes(),
        )
        for path in sorted(root.rglob("*"))
    }


def test_execution_client_typed_leader_lifecycle_and_http_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    service = _execution_service()
    app = create_execution_app(service)
    with TestClient(app) as http:
        assert (
            http.post(
                "/internal/v1/leader/acquire", json={"owner_id": "runner-owner-0001"}
            ).status_code
            == 401
        )

    async def lifecycle() -> None:
        client = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution", shared_secret=EXECUTION_SECRET
            ),
            transport=httpx.ASGITransport(app=app),
        )
        acquired = await client.acquire_leader("runner-owner-0001")
        assert acquired.owner_id == "runner-owner-0001"
        active = await client.leader_status()
        assert active.held is True
        assert active.state == "ACTIVE"
        renewed = await client.renew_leader(acquired)
        assert renewed.epoch == acquired.epoch
        assert renewed.fencing_token == acquired.fencing_token
        released = await client.release_leader(renewed)
        assert released.held is False
        assert released.state == "RELEASED"
        assert released.epoch == renewed.epoch
        assert released.fencing_token == renewed.fencing_token
        final = await client.leader_status()
        assert final.held is False
        assert final.state == "RELEASED"

    asyncio.run(lifecycle())


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("scope", "account:foreign"),
        ("owner_id", "runner-owner-foreign"),
        ("epoch", 999),
        ("fencing_token", 999),
        ("lease_expires_at", "2099-01-01T00:00:00Z"),
        ("instance_id", "leader-instance-foreign-0001"),
    ],
)
def test_leader_release_rejects_every_foreign_or_stale_binding_without_mutation(
    monkeypatch: pytest.MonkeyPatch, field: str, replacement: str | int
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    service = _execution_service()
    token = service.acquire_leader("runner-owner-0001").as_dict()
    before = service.repository.snapshot()
    forged = deepcopy(token)
    forged.pop("held")
    forged[field] = replacement
    with TestClient(create_execution_app(service)) as client:
        response = client.post(
            "/internal/v1/leader/release",
            headers=EXECUTION_HEADERS,
            json={"token": forged},
        )
    assert response.status_code == 409
    assert response.json()["detail"]["retryable"] is False
    assert service.repository.snapshot() == before
    assert service.leader_status()["held"] is True


def test_leader_release_exact_replay_fails_closed_and_restart_can_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    path = tmp_path / "execution.json"
    first = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    token = _persisted_leader_token(first.acquire_leader("runner-owner-0001"))
    restarted = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    app = create_execution_app(restarted)
    with TestClient(app) as client:
        before_release = restarted.repository.snapshot()
        assert (
            client.post(
                "/internal/v1/leader/release",
                headers=EXECUTION_HEADERS,
                json={"token": None},
            ).status_code
            == 409
        )
        extra_token = {**token, "unexpected": True}
        assert (
            client.post(
                "/internal/v1/leader/release",
                headers=EXECUTION_HEADERS,
                json={"token": extra_token},
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/internal/v1/leader/release",
                headers=EXECUTION_HEADERS,
                json={"token": token, "retry": True},
            ).status_code
            == 409
        )
        assert restarted.repository.snapshot() == before_release
        released = client.post(
            "/internal/v1/leader/release",
            headers=EXECUTION_HEADERS,
            json={"token": token},
        )
        assert released.status_code == 200
        assert released.json()["held"] is False
        assert released.json()["state"] == "RELEASED"
        after_release = restarted.repository.snapshot()
        replay = client.post(
            "/internal/v1/leader/release",
            headers=EXECUTION_HEADERS,
            json={"token": token},
        )
    assert replay.status_code == 409
    assert replay.json()["detail"]["retryable"] is False
    assert restarted.repository.snapshot() == after_release
    assert restarted.leader_status()["held"] is False


def test_leader_status_has_three_explicit_states_and_expired_release_is_fenced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    observed = now
    monkeypatch.setattr("app.execution.fencing.utc_now", lambda: observed)

    path = tmp_path / "expired-release.json"
    first = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    token = _persisted_leader_token(first.acquire_leader("runner-owner-0001", now=now))
    assert first.leader_status()["state"] == "ACTIVE"

    observed = now + timedelta(seconds=20)
    expired = first.leader_status()
    assert expired["state"] == "EXPIRED_BOUND"
    assert expired["held"] is False
    assert expired["owner_id"] == token["owner_id"]
    assert expired["instance_id"] == token["instance_id"]

    restarted = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    released = restarted.leader_release(token, now=observed)
    assert released["state"] == "RELEASED"
    assert restarted.leader_status()["state"] == "RELEASED"

    path = tmp_path / "successor.json"
    original = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    stale = _persisted_leader_token(
        original.acquire_leader("runner-owner-0001", now=now)
    )
    successor = _execution_service(
        DurableExecutionRepository(path, scope="account:issue362")
    )
    live = successor.acquire_leader("runner-owner-0002", now=observed)
    with pytest.raises(FencingError):
        successor.leader_release(stale, now=observed)
    assert successor.leader_status()["state"] == "ACTIVE"
    assert successor.leader_status()["owner_id"] == live.owner_id


def test_leader_http_requests_require_exact_outer_and_token_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    service = _execution_service()
    app = create_execution_app(service)
    with TestClient(app) as client:
        for payload in (
            {"owner_id": 123},
            {"owner_id": "runner-owner-0001", "unexpected": True},
        ):
            response = client.post(
                "/internal/v1/leader/acquire",
                headers=EXECUTION_HEADERS,
                json=payload,
            )
            assert response.status_code == 409

        acquired = client.post(
            "/internal/v1/leader/acquire",
            headers=EXECUTION_HEADERS,
            json={"owner_id": "runner-owner-0001"},
        ).json()
        token = dict(acquired)
        token.pop("held")
        for payload in (
            {"token": token, "unexpected": True},
            {"token": {**token, "unexpected": True}},
            {"token": {**token, "held": True}},
            {"token": None},
        ):
            response = client.post(
                "/internal/v1/leader/renew",
                headers=EXECUTION_HEADERS,
                json=payload,
            )
            assert response.status_code == 409

        release = client.post(
            "/internal/v1/leader/release",
            headers=EXECUTION_HEADERS,
            json={"token": acquired},
        )
        assert release.status_code == 409
        exact = client.post(
            "/internal/v1/leader/release",
            headers=EXECUTION_HEADERS,
            json={"token": token},
        )
        assert exact.status_code == 200


def test_leader_client_preserves_retryable_503_and_rejects_non_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    repository = InMemoryExecutionRepository(scope="account:issue362")
    service = _execution_service(repository)
    app = create_execution_app(service)

    async def unavailable() -> None:
        client = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution", shared_secret=EXECUTION_SECRET
            ),
            transport=httpx.ASGITransport(app=app),
        )
        token = await client.acquire_leader("runner-owner-0001")
        repository.mark_unavailable()
        with pytest.raises(ExecutionRejectedError) as status_caught:
            await client.leader_status()
        assert status_caught.value.status_code == 503
        assert status_caught.value.detail == {
            "code": "EXECUTION_LEADER_REPOSITORY_UNAVAILABLE",
            "message": "durable execution repository unavailable",
            "retryable": True,
        }
        with pytest.raises(ExecutionRejectedError) as caught:
            await client.release_leader(token)
        assert caught.value.status_code == 503
        assert caught.value.detail["retryable"] is True

    asyncio.run(unavailable())

    token = {
        "scope": "account:issue362",
        "owner_id": "runner-owner-0001",
        "held": True,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "2099-01-01T00:00:00Z",
        "instance_id": "leader-instance-00000001",
    }
    bad = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="not-json")),
    )
    with pytest.raises(ExecutionProtocolError, match="非 JSON"):
        asyncio.run(bad.release_leader(token))


def test_leader_client_rejects_acquire_for_a_different_owner() -> None:
    foreign = {
        "scope": "account:issue362",
        "owner_id": "runner-owner-foreign",
        "held": True,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "2099-01-01T00:00:00Z",
        "instance_id": "leader-instance-00000001",
    }
    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=foreign)),
    )
    with pytest.raises(ExecutionProtocolError, match="acquire"):
        asyncio.run(client.acquire_leader("runner-owner-0001"))


def test_leader_client_status_accepts_expired_binding_and_rejects_mixed_states() -> (
    None
):
    expired = {
        "scope": "account:issue362",
        "owner_id": "runner-owner-0001",
        "held": False,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "2026-08-18T00:00:00Z",
        "instance_id": "leader-instance-00000001",
        "state": "EXPIRED_BOUND",
    }
    valid = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=expired)),
    )
    status = asyncio.run(valid.leader_status())
    assert status.state == "EXPIRED_BOUND"
    assert status.held is False
    assert status.owner_id == "runner-owner-0001"

    for mixed in (
        expired | {"state": "ACTIVE"},
        expired | {"state": "RELEASED"},
        expired | {"owner_id": "", "instance_id": ""},
    ):
        invalid = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution"),
            transport=httpx.MockTransport(
                lambda _, response=mixed: httpx.Response(200, json=response)
            ),
        )
        with pytest.raises(ExecutionProtocolError, match="leader status"):
            asyncio.run(invalid.leader_status())


@pytest.mark.parametrize(
    "change",
    [
        {"owner_id": "runner-owner-foreign"},
        {"fencing_token": 2},
        {"instance_id": "leader-instance-foreign-0001"},
    ],
)
def test_leader_client_renew_preserves_exact_lease_identity(
    change: dict[str, object],
) -> None:
    token = {
        "scope": "account:issue362",
        "owner_id": "runner-owner-0001",
        "held": True,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "2099-01-01T00:00:00Z",
        "instance_id": "leader-instance-00000001",
    }
    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json=token | change)
        ),
    )
    with pytest.raises(ExecutionProtocolError, match="renew"):
        asyncio.run(client.renew_leader(token))


@pytest.mark.parametrize(
    "change",
    [
        {
            "owner_id": "runner-owner-0001",
            "instance_id": "leader-instance-00000001",
        },
        {"lease_expires_at": "2099-01-01T00:00:00Z"},
        {"fencing_token": 2},
    ],
)
def test_leader_client_rejects_false_release_with_retained_lease_binding(
    change: dict[str, object],
) -> None:
    token = {
        "scope": "account:issue362",
        "owner_id": "runner-owner-0001",
        "held": True,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "2099-01-01T00:00:00Z",
        "instance_id": "leader-instance-00000001",
    }
    false_release = {
        "scope": "account:issue362",
        "owner_id": "",
        "held": False,
        "epoch": 1,
        "fencing_token": 1,
        "lease_expires_at": "1970-01-01T00:00:00Z",
        "instance_id": "",
        "state": "RELEASED",
    } | change
    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json=false_release)
        ),
    )
    with pytest.raises(ExecutionProtocolError, match="leader"):
        asyncio.run(client.release_leader(token))


def test_custody_current_version_empty_is_zero_authenticated_and_zero_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    service = _custody_service(root)
    app = create_custody_app(service)
    with TestClient(app) as client:
        assert client.get("/internal/v1/current-version").status_code == 401
        before = _tree_contents(root)
        response = client.get("/internal/v1/current-version", headers=CUSTODY_HEADERS)
        after = _tree_contents(root)
    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "phase-c-custody-current-version-v1",
        "version": 0,
        "custody_state_owner": "artifact-custody",
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    assert before == after == {}

    root.mkdir(mode=0o700)
    assert service.current_version().version == 0
    assert _tree_contents(root) == {}


def test_custody_current_version_uses_audited_ledger_and_survives_restart(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    service = _custody_service(root)
    artifact = new_artifact_envelope(
        artifact_type="runtime-authorization",
        trust_domain="runtime_authorization",
        producer_id="issue362-test",
        producer_version="v1",
        schema_ref="phase-c-runtime-authorization-v1",
        generated_at="2030-01-01T00:00:00Z",
        scope={},
        predecessor_refs=[],
        lineage=[],
        payload={"purpose": "version-test"},
    )
    with service._custody() as custody:
        custody.publish(
            artifact,
            actor_id="control-api",
            idempotency_key="issue362-version-publish-0001",
            correlation_id="issue362-version-correlation-0001",
            expected_version=0,
        )
    before = _tree_contents(root)
    assert service.current_version().version == 1
    assert _custody_service(root, writer_epoch=2).current_version().version == 1
    assert _tree_contents(root) == before

    receipt = next((root / "receipts").iterdir())
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with TestClient(create_custody_app(_custody_service(root))) as client:
        failed = client.get("/internal/v1/current-version", headers=CUSTODY_HEADERS)
    assert failed.status_code == 503
    assert failed.json()["detail"] == {
        "code": "PHASE_C_CUSTODY_VERSION_UNAVAILABLE",
        "message": "custody durable state is unavailable",
        "retryable": True,
    }


def test_remote_custody_version_client_is_strict_and_preserves_error_detail() -> None:
    settings = PhaseCRemoteSettings(
        "http://custody",
        "http://execution",
        CUSTODY_HEADERS["X-Phase-C-Custody-Secret"],
        "execution-secret",
    )

    valid = RemotePhaseCWorkflowClient(
        settings,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "schema_version": "phase-c-custody-current-version-v1",
                    "version": 7,
                    "custody_state_owner": "artifact-custody",
                    "production_allowed": False,
                    "live_trading_authorized": False,
                    "countable_forward": False,
                },
            )
        ),
    )
    assert valid.custody_current_version().version == 7

    detail = {
        "code": "PHASE_C_CUSTODY_VERSION_UNAVAILABLE",
        "message": "durable custody unavailable",
        "retryable": True,
    }
    unavailable = RemotePhaseCWorkflowClient(
        settings,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503, json={"detail": detail})
        ),
    )
    with pytest.raises(WorkflowAdapterError) as caught:
        unavailable.custody_current_version()
    assert caught.value.status_code == 503
    assert caught.value.detail == detail

    non_json = RemotePhaseCWorkflowClient(
        settings,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="not-json")),
    )
    with pytest.raises(WorkflowAdapterError, match="response is invalid") as caught:
        non_json.custody_current_version()
    assert caught.value.status_code == 502

    extra = RemotePhaseCWorkflowClient(
        settings,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "schema_version": "phase-c-custody-current-version-v1",
                    "version": 7,
                    "custody_state_owner": "artifact-custody",
                    "production_allowed": False,
                    "live_trading_authorized": False,
                    "countable_forward": False,
                    "receipt_count": 7,
                },
            )
        ),
    )
    with pytest.raises(WorkflowAdapterError, match="version response is invalid"):
        extra.custody_current_version()


def test_artifact_custody_read_only_flag_requires_an_exact_bool(tmp_path: Path) -> None:
    with pytest.raises(CustodyError, match="CUSTODY_READ_ONLY_FLAG_INVALID"):
        ArtifactCustody(
            tmp_path / "custody",
            writer_id="artifact-custody",
            writer_epoch=1,
            schema_registry={"test-schema-v1": lambda _: None},
            read_only="true",  # type: ignore[arg-type]
        )
    assert not (tmp_path / "custody").exists()
