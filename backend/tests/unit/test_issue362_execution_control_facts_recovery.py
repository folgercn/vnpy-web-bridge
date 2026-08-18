from __future__ import annotations

import asyncio
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Iterator

import httpx
import pytest
from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientSettings,
    ExecutionProtocolError,
)
from app.execution import (
    DurableTargetPlanRepository,
    ExecutionOrchestrator,
    GatewaySnapshot,
    GatewayConfigurationError,
    InMemoryExecutionRepository,
    InMemoryGateway,
    AuthorityRejected,
    PlanRejected,
    SnapshotRejected,
)
from app.execution.final_runtime import CustodyReadClient, FinalExecutionRuntime
from app.execution_orchestrator import (
    _HttpCustodyReadClient,
    create_app as create_execution_app,
)
from app.phase_c.custody_service import (
    ArtifactCustodyService,
    CustodyEvidenceReadError,
    CustodySettings,
    create_app as create_custody_app,
)
from app.phase_c.models import TrustedKeylessTargetPlanUploadDTO
from fastapi.testclient import TestClient

from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    before_position_projection_hash,
    build_trusted_keyless_target_plan_v2,
    sha256_json,
    target_position_projection_hash,
)


SCOPE = "account:windows"
ENVIRONMENT = "SIMNOW"
EXECUTION_SECRET = "issue362-facts-recovery-execution-secret"
EXECUTION_HEADERS = {
    "X-Control-Service": "control-api",
    "X-Control-Execution-Secret": EXECUTION_SECRET,
}
CUSTODY_PUBLISH_KEY = "issue362-recovery-publish-0001"


@contextmanager
def _serve_phase_c_http(app: object) -> Iterator[str]:
    """Expose the real Phase-C ASGI routes to urllib over a local TCP hop."""

    with TestClient(app) as phase_c:

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP hook
                response = phase_c.get(
                    self.path,
                    headers={key: value for key, value in self.headers.items()},
                )
                raw = response.content
                self.send_response(response.status_code)
                self.send_header(
                    "Content-Type",
                    response.headers.get("content-type", "application/json"),
                )
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, _format: str, *_args: object) -> None:
                return None

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            yield f"http://{host}:{port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def _positions() -> dict[str, dict[str, object]]:
    return {
        "rb2601.SHFE.LONG.CTP.full": {
            "gateway_name": "CTP",
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "volume": 1,
        }
    }


def _active_orders() -> dict[str, dict[str, object]]:
    return {
        "order-active-full-account-0001": {
            "gateway_name": "CTP",
            "symbol": "rb2601",
            "exchange": "SHFE",
            "direction": "LONG",
            "offset": "OPEN",
            "volume": 1,
            "status": "NOTTRADED",
        }
    }


def _orchestrator(
    snapshot: GatewaySnapshot, *, reconciled: bool = True
) -> ExecutionOrchestrator:
    gateway = InMemoryGateway(account_scope=SCOPE, environment=ENVIRONMENT)
    gateway.snapshots.append(snapshot)
    service = ExecutionOrchestrator(
        InMemoryExecutionRepository(scope=SCOPE),
        gateway,
        scope=SCOPE,
        environment=ENVIRONMENT,
        test_mode=True,
    )
    if reconciled:
        service.repository.mutate(
            lambda state: (
                state.update({"lifecycle": "READY"}),
                state["broker"].update(
                    {
                        "connected": True,
                        "generation": snapshot.generation,
                        "active_order_count": snapshot.active_order_count,
                        "position_snapshot_hash": snapshot.position_snapshot_hash,
                        "last_snapshot_at": snapshot.observed_at,
                        "orders": dict(snapshot.orders),
                        "positions": dict(snapshot.positions),
                    }
                ),
                state["reconciliation"].update(
                    {
                        "state": "RECONCILED",
                        "run_id": "issue362-account-facts-reconcile-0001",
                        "last_completed_at": snapshot.observed_at,
                        "unknown_outcomes": 0,
                        "fresh_snapshot_id": snapshot.snapshot_id,
                    }
                ),
            )
        )
    return service


def _fresh_snapshot(*, with_active_order: bool = False) -> GatewaySnapshot:
    positions = _positions()
    orders = _active_orders() if with_active_order else {}
    return GatewaySnapshot(
        snapshot_id="snapshot-issue362-full-account-0001",
        generation=4,
        connected=True,
        active_order_count=len(orders),
        position_snapshot_hash=sha256_json(positions),
        observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        orders=orders,
        positions=positions,
        account_scope=SCOPE,
        environment=ENVIRONMENT,
        fresh=True,
    )


def test_account_facts_is_authenticated_full_closed_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    service = _orchestrator(_fresh_snapshot())
    before = service.repository.snapshot()
    app = create_execution_app(service)
    with TestClient(app) as client:
        assert client.get("/internal/v1/account-facts").status_code == 401
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["account_scope"] == SCOPE
    assert body["environment"] == ENVIRONMENT
    assert body["connected"] is True and body["fresh"] is True
    assert body["positions"] == _positions()
    assert body["schema_version"] == "web_bridge_execution_account_facts_v2"
    assert body["active_orders"] == {}
    assert body["position_snapshot_hash"] == sha256_json(_positions())
    assert body["active_orders_sha256"] == sha256_json({})
    assert body["account_facts_sha256"] == sha256_json(
        {key: value for key, value in body.items() if key != "account_facts_sha256"}
    )
    assert body["status_binding"]["state_version"] == before["state_version"]
    assert body["status_binding"]["reconciliation"] == before["reconciliation"]
    assert body["status_binding"]["broker"]["generation"] == body["generation"]
    assert (
        body["status_binding"]["durable_active_orders_sha256"]
        == body["active_orders_sha256"]
    )
    assert (
        body["status_binding"]["durable_positions_sha256"]
        == body["position_snapshot_hash"]
    )
    assert (
        body["status_binding"]["snapshot_identity_mode"]
        == "GENERATION_FACT_HASH_EQUIVALENT"
    )
    assert body["execution_binding"] == {
        "state_version": before["state_version"],
        "plan_state": "IDLE",
        "send_intents": {},
        "send_intents_sha256": sha256_json({}),
        "nonterminal_send_intent_count": 0,
    }
    assert service.repository.snapshot() == before

    async def read_with_client() -> dict[str, object]:
        execution = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution", shared_secret=EXECUTION_SECRET
            ),
            transport=httpx.ASGITransport(app=app),
        )
        return (await execution.account_facts()).as_dict()

    assert asyncio.run(read_with_client())["snapshot_id"] == body["snapshot_id"]


def test_account_facts_v2_binds_terminal_execution_state_and_preserves_v1() -> None:
    snapshot = _fresh_snapshot()
    active = _orchestrator(snapshot)
    active.repository.mutate(
        lambda state: state["plan"].update(
            {
                "state": "ACTIVE",
                "plan_id": "issue362-active-plan-0001",
                "plan_hash": "a" * 64,
            }
        )
    )

    with pytest.raises(SnapshotRejected, match="planner ready"):
        active.account_facts_projection(snapshot)
    v1 = active.account_facts_projection_v1(snapshot)
    assert v1["schema_version"] == "web_bridge_execution_account_facts_v1"
    assert "execution_binding" not in v1

    terminal = _orchestrator(snapshot)
    intent_id = "issue362-terminal-intent-0001"
    idempotency_key = "issue362-terminal-intent-key-0001"
    intent = {
        "intent_id": intent_id,
        "idempotency_key": idempotency_key,
        "state": "TERMINAL",
        "plan_id": "issue362-terminal-plan-0001",
        "plan_hash": "b" * 64,
        "leader_epoch": 1,
        "fencing_token": 1,
        "created_at": snapshot.observed_at,
    }
    terminal.repository.mutate(
        lambda state: (
            state["send_intents"].update({intent_id: intent}),
            state["intent_keys"].update({idempotency_key: intent_id}),
        )
    )
    facts = terminal.account_facts_projection(snapshot)
    assert facts["execution_binding"]["send_intents"] == {intent_id: intent}
    assert facts["execution_binding"]["send_intents_sha256"] == sha256_json(
        {intent_id: intent}
    )
    assert facts["execution_binding"]["nonterminal_send_intent_count"] == 0

    pending = _orchestrator(snapshot)
    pending_intent = {**intent, "state": "PERSISTED"}
    pending.repository.mutate(
        lambda state: (
            state["send_intents"].update({intent_id: pending_intent}),
            state["intent_keys"].update({idempotency_key: intent_id}),
        )
    )
    with pytest.raises(SnapshotRejected, match="planner ready"):
        pending.account_facts_projection(snapshot)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"connected": False}, "disconnected"),
        ({"fresh": False}, "not fresh"),
        ({"account_scope": "account:foreign"}, "scope mismatch"),
        ({"active_order_count": 1}, "order closure"),
        ({"position_snapshot_hash": "f" * 64}, "position hash"),
    ],
)
def test_account_facts_missing_or_unclosed_evidence_is_503_without_mutation(
    monkeypatch: pytest.MonkeyPatch, change: dict[str, object], message: str
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot()
    snapshot = GatewaySnapshot(**{**snapshot.as_dict(), **change})
    service = _orchestrator(snapshot)
    before = service.repository.snapshot()
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503, message
    assert response.json()["detail"]["code"] == "EXECUTION_ACCOUNT_FACTS_UNAVAILABLE"
    assert service.repository.snapshot() == before


def test_account_facts_stale_timestamp_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    snapshot = _fresh_snapshot()
    stale = datetime.now(timezone.utc) - timedelta(minutes=5)
    snapshot = GatewaySnapshot(
        **{
            **snapshot.as_dict(),
            "observed_at": stale.isoformat().replace("+00:00", "Z"),
        }
    )
    with TestClient(create_execution_app(_orchestrator(snapshot))) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503


def test_account_facts_rejects_fresh_drift_against_stale_reconciled_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    fresh = _fresh_snapshot()
    service = _orchestrator(fresh, reconciled=False)
    service.repository.mutate(
        lambda state: (
            state.update({"lifecycle": "READY"}),
            state["broker"].update(
                {
                    "connected": True,
                    "generation": fresh.generation - 1,
                    "position_snapshot_hash": "e" * 64,
                    "active_order_count": 0,
                    "last_snapshot_at": fresh.observed_at,
                }
            ),
            state["reconciliation"].update(
                {
                    "state": "RECONCILED",
                    "run_id": "issue362-stale-reconciliation-0001",
                    "last_completed_at": fresh.observed_at,
                    "unknown_outcomes": 0,
                    "fresh_snapshot_id": "snapshot-issue362-stale-0001",
                }
            ),
        )
    )
    before = service.repository.snapshot()
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert (
        "not bound to the reconciled Execution status"
        in response.json()["detail"]["message"]
    )
    assert service.repository.snapshot() == before


def test_account_facts_rejects_same_count_different_durable_active_order_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    fresh = _fresh_snapshot(with_active_order=True)
    service = _orchestrator(fresh)
    service.repository.mutate(
        lambda state: state["broker"].update(
            {
                "active_order_count": 1,
                "orders": {
                    "order-active-full-account-different-0001": {
                        **next(iter(_active_orders().values())),
                        "direction": "SHORT",
                    }
                },
            }
        )
    )
    before = service.repository.snapshot()
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert (
        "not bound to the reconciled Execution status"
        in response.json()["detail"]["message"]
    )
    assert service.repository.snapshot() == before


def test_account_facts_rejects_durable_positions_rows_that_do_not_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    fresh = _fresh_snapshot()
    service = _orchestrator(fresh)
    service.repository.mutate(
        lambda state: state["broker"].update(
            {
                "positions": {
                    "rb2601.SHFE.LONG.CTP.full": {
                        **next(iter(_positions().values())),
                        "volume": 2,
                    }
                }
            }
        )
    )
    before = service.repository.snapshot()
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert service.repository.snapshot() == before


def test_account_facts_requires_exact_stable_peek_snapshot_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    raw = _fresh_snapshot().as_dict()
    fresh = GatewaySnapshot(**{**raw, "snapshot_id": f"snapshot-peek-{'a' * 64}"})
    service = _orchestrator(fresh)
    service.repository.mutate(
        lambda state: state["reconciliation"].update(
            {"fresh_snapshot_id": f"snapshot-peek-{'b' * 64}"}
        )
    )
    before = service.repository.snapshot()
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert service.repository.snapshot() == before


def test_account_facts_accepts_nonstable_id_and_time_when_fact_identity_is_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    durable = _fresh_snapshot()
    service = _orchestrator(durable)
    later = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    current = GatewaySnapshot(
        **{
            **durable.as_dict(),
            "snapshot_id": "snapshot-issue362-equivalent-facts-0002",
            "observed_at": later,
        }
    )
    service.gateway.snapshots[-1] = current
    with TestClient(create_execution_app(service)) as client:
        response = client.get("/internal/v1/account-facts", headers=EXECUTION_HEADERS)
    assert response.status_code == 200
    assert response.json()["status_binding"]["snapshot_identity_mode"] == (
        "GENERATION_FACT_HASH_EQUIVALENT"
    )


def _v2_plan() -> dict[str, object]:
    positions = _positions()
    return build_trusted_keyless_target_plan_v2(
        plan_id="static-core-equal-recovery-open-0001",
        account_scope=SCOPE,
        environment=ENVIRONMENT,
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
            {}, account_scope=SCOPE, environment=ENVIRONMENT
        ),
        expected_after_position_hash=target_position_projection_hash(
            positions, account_scope=SCOPE, environment=ENVIRONMENT
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
                "reference": "issue362-recovery-open-order-0001",
                "gateway_name": "CTP",
            }
        ],
    )


class _CustodyReader:
    def __init__(self, service: ArtifactCustodyService) -> None:
        self.service = service

    def receipt(self, receipt_id: str):
        return self.service.receipt(receipt_id)

    def receipt_by_idempotency(self, idempotency_key: str):
        return self.service.receipt_by_idempotency(idempotency_key)

    def target_plan_publication(self, idempotency_key: str):
        return self.service.target_plan_publication(idempotency_key).model_dump(
            mode="json"
        )

    def target_plan_receipt(self, receipt_id: str):
        evidence = self.service.target_plan_receipt_evidence(receipt_id)
        return evidence.model_dump(mode="json") if evidence is not None else None

    def artifact(self, artifact_id: str):
        return self.service.artifact_for_execution(artifact_id)

    def probe(self) -> None:
        return None


def _empty_custody(tmp_path: Path) -> ArtifactCustodyService:
    return ArtifactCustodyService(
        CustodySettings(
            tmp_path / "custody",
            "artifact-custody",
            1,
            "issue362-control-custody-secret",
            frozenset({"control-api"}),
            {},
            "issue362-execution-custody-read-secret",
            None,
            True,
        )
    )


def _v2_artifact() -> dict[str, object]:
    plan = _v2_plan()
    return new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="issue362-recovery-fixture",
        producer_version="v1",
        schema_ref=KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        payload=plan,
        generated_at=str(plan["generated_at"]),
        scope=plan["scope"],
        predecessor_refs=[],
        lineage=[],
    )


def _custody(tmp_path: Path) -> tuple[ArtifactCustodyService, dict[str, object]]:
    service = _empty_custody(tmp_path)
    artifact = _v2_artifact()
    receipt = service.publish_trusted_keyless_target_plan(
        TrustedKeylessTargetPlanUploadDTO(
            idempotency_key=CUSTODY_PUBLISH_KEY,
            expected_custody_version=0,
            correlation_id="issue362-recovery-correlation-0001",
            artifact=artifact,
        ),
        principal="control-api",
    )
    return service, receipt


def _published_only_custody(
    tmp_path: Path,
) -> tuple[ArtifactCustodyService, dict[str, object], dict[str, object]]:
    service = _empty_custody(tmp_path)
    artifact = _v2_artifact()
    with service._custody() as custody:
        published = custody.publish(
            artifact,
            actor_id="control-api",
            idempotency_key=CUSTODY_PUBLISH_KEY,
            correlation_id="issue362-recovery-correlation-0001",
            expected_version=0,
        )
    return service, artifact, published


def _runtime(
    tmp_path: Path, custody: ArtifactCustodyService
) -> tuple[FinalExecutionRuntime, DurableTargetPlanRepository]:
    return _runtime_with_custody_reader(tmp_path, _CustodyReader(custody))


def _runtime_with_custody_reader(
    tmp_path: Path, custody: CustodyReadClient
) -> tuple[FinalExecutionRuntime, DurableTargetPlanRepository]:
    plans = DurableTargetPlanRepository(tmp_path / "plans")
    runtime = FinalExecutionRuntime(
        ExecutionOrchestrator(
            InMemoryExecutionRepository(scope=SCOPE),
            InMemoryGateway(account_scope=SCOPE, environment=ENVIRONMENT),
            scope=SCOPE,
            environment=ENVIRONMENT,
            test_mode=True,
        ),
        plans=plans,
        custody=custody,
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_trusted_keyless_simnow=True,
    )
    return runtime, plans


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_recovery_publish_only_is_strict_install_only_and_zero_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, artifact, published = _published_only_custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    plan_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    execution_before = runtime.orchestrator.repository.snapshot()

    projection = runtime.recovery_projection(
        custody_idempotency_key=CUSTODY_PUBLISH_KEY
    )

    assert projection["schema_version"] == (
        "web_bridge_execution_target_plan_recovery_v2"
    )
    assert projection["state"] == "CUSTODY_PUBLISHED_NOT_INSTALLED"
    assert projection["publish_receipt_id"] == published["receipt_id"]
    assert projection["publish_expected_custody_version"] == 0
    assert projection["publish_resulting_custody_version"] == 1
    assert projection["observed_custody_version"] == 1
    assert projection["artifact_id"] == artifact["artifact_id"]
    assert projection["artifact_canonical_sha256"] == artifact["canonical_sha256"]
    assert projection["artifact_sha256"] == artifact["raw_sha256"]
    assert projection["artifact_schema_ref"] == artifact["schema_ref"]
    assert projection["plan_id"] == artifact["payload"]["plan_id"]  # type: ignore[index]
    assert projection["plan_hash"] == artifact["payload"]["plan_hash"]  # type: ignore[index]
    assert projection["installed"] is False
    assert projection["install_only_allowed"] is True
    assert projection["recovery_action"] == "INSTALL_ONLY"
    assert projection["production_allowed"] is False
    assert projection["live_trading_authorized"] is False
    assert projection["countable_forward"] is False
    assert projection["recovery_sha256"] == sha256_json(
        {key: value for key, value in projection.items() if key != "recovery_sha256"}
    )
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before
    assert runtime.orchestrator.repository.snapshot() == execution_before

    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution", shared_secret=EXECUTION_SECRET
        ),
        transport=httpx.ASGITransport(app=create_execution_app(runtime)),
    )
    typed = asyncio.run(client.target_plan_recovery(CUSTODY_PUBLISH_KEY))
    assert typed.state == "CUSTODY_PUBLISHED_NOT_INSTALLED"
    assert typed.plan_id == artifact["payload"]["plan_id"]  # type: ignore[index]
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before


def test_recovery_publish_only_version_drift_is_explicit_stop_without_writes(
    tmp_path: Path,
) -> None:
    custody, artifact, _published = _published_only_custody(tmp_path)
    unrelated = new_artifact_envelope(
        artifact_type="simnow-target-plan",
        trust_domain="runtime_authorization",
        producer_id="issue362-unrelated-publisher",
        producer_version="v1",
        schema_ref=str(artifact["schema_ref"]),
        payload=artifact["payload"],
        generated_at=str(artifact["generated_at"]),
        scope=artifact["scope"],  # type: ignore[arg-type]
        predecessor_refs=[],
        lineage=[],
    )
    with custody._custody() as writer:
        writer.publish(
            unrelated,
            actor_id="control-api",
            idempotency_key="issue362-unrelated-publication-0002",
            correlation_id="issue362-unrelated-correlation-0002",
            expected_version=1,
        )
    runtime, plans = _runtime(tmp_path, custody)
    plan_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)

    projection = runtime.recovery_projection(
        custody_idempotency_key=CUSTODY_PUBLISH_KEY
    )

    assert projection["state"] == "CUSTODY_PUBLISHED_NOT_INSTALLED"
    assert projection["observed_custody_version"] == 2
    assert projection["publish_resulting_custody_version"] == 1
    assert projection["install_only_allowed"] is False
    assert projection["recovery_action"] == "STOP_VERSION_DRIFT"
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("artifact_id", "artifact-issue362-cross-splice-0001"),
        ("artifact_canonical_sha256", "d" * 64),
        ("artifact_raw_sha256", "e" * 64),
        ("publisher_principal", "foreign-publisher"),
        ("correlation_id", "issue362-foreign-correlation-0001"),
        ("publish_receipt_id", "receipt-" + "9" * 64),
        ("publish_receipt_sha256", "8" * 64),
        ("publish_expected_custody_version", 4),
        ("publish_resulting_custody_version", 5),
        ("plan_id", "static-core-equal-cross-splice-0001"),
        ("plan_hash", "f" * 64),
        ("plan_phase", "CLOSE"),
    ],
)
def test_recovery_publish_only_rehash_rejects_cross_spliced_pins(
    tmp_path: Path, field: str, replacement: object
) -> None:
    custody, _artifact, _published = _published_only_custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    original = runtime.custody.target_plan_publication

    def cross_spliced(idempotency_key: str):
        return {**original(idempotency_key), field: replacement}

    runtime.custody.target_plan_publication = cross_spliced  # type: ignore[method-assign]
    before = _tree(plans.root)
    with pytest.raises((AuthorityRejected, PlanRejected)):
        runtime.recovery_projection(custody_idempotency_key=CUSTODY_PUBLISH_KEY)
    assert _tree(plans.root) == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("install_receipt_id", "receipt-" + "7" * 64),
        ("install_receipt_sha256", "6" * 64),
        ("install_expected_custody_version", 6),
        ("install_resulting_custody_version", 7),
    ],
)
def test_recovery_installed_rejects_each_cross_spliced_install_receipt_pin(
    tmp_path: Path, field: str, replacement: object
) -> None:
    custody, _receipt = _custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    original = runtime.custody.target_plan_publication

    def cross_spliced(idempotency_key: str):
        return {**original(idempotency_key), field: replacement}

    runtime.custody.target_plan_publication = cross_spliced  # type: ignore[method-assign]
    plan_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    with pytest.raises((AuthorityRejected, PlanRejected)):
        runtime.recovery_projection(custody_idempotency_key=CUSTODY_PUBLISH_KEY)
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before


@pytest.mark.parametrize("install", [False, True], ids=["publish", "install"])
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_id", "receipt-" + "1" * 64),
        ("receipt_sha256", "2" * 64),
        ("receipt_type", "consume"),
        ("artifact_id", "artifact-issue362-receipt-splice-0001"),
        ("artifact_canonical_sha256", "3" * 64),
        ("artifact_raw_sha256", "4" * 64),
        ("artifact_schema_ref", "web-bridge-simnow-keyless-target-plan-v1"),
        ("actor_id", "foreign-publisher"),
        ("idempotency_key", "issue362-foreign-receipt-key-0001"),
        ("correlation_id", "issue362-foreign-receipt-correlation-0001"),
        ("expected_custody_version", 8),
        ("resulting_custody_version", 9),
    ],
)
def test_recovery_rejects_each_tampered_raw_receipt_evidence_pin(
    tmp_path: Path, install: bool, field: str, replacement: object
) -> None:
    if install:
        custody, _receipt = _custody(tmp_path)
    else:
        custody, _artifact, _published = _published_only_custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    projection = runtime.custody.target_plan_publication(CUSTODY_PUBLISH_KEY)
    receipt_id = (
        projection["install_receipt_id"]
        if install
        else projection["publish_receipt_id"]
    )
    original = runtime.custody.target_plan_receipt

    def tampered(wanted_receipt_id: str):
        value = original(wanted_receipt_id)
        assert value is not None
        if wanted_receipt_id == receipt_id:
            return {**value, field: replacement}
        return value

    runtime.custody.target_plan_receipt = tampered  # type: ignore[method-assign]
    plan_before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    with pytest.raises((AuthorityRejected, PlanRejected)):
        runtime.recovery_projection(custody_idempotency_key=CUSTODY_PUBLISH_KEY)
    assert _tree(plans.root) == plan_before
    assert _tree(custody.settings.root) == custody_before
    gateway = runtime.orchestrator.gateway
    assert gateway.send_calls == []  # type: ignore[attr-defined]
    assert gateway.cancel_calls == []  # type: ignore[attr-defined]
    assert gateway.query_calls == []  # type: ignore[attr-defined]


def test_recovery_response_lost_before_preview_projects_original_plan_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, receipt = _custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    before_missing = _tree(plans.root)
    custody_before_missing = _tree(custody.settings.root)
    published = runtime.recovery_projection(custody_idempotency_key=CUSTODY_PUBLISH_KEY)
    assert published["state"] == "CUSTODY_PUBLISHED_NOT_PREVIEWED"
    assert published["installed"] is False
    assert published["receipt_id"] == receipt["receipt_id"]
    assert published["plan_id"] == _v2_plan()["plan_id"]
    assert _tree(plans.root) == before_missing
    assert _tree(custody.settings.root) == custody_before_missing

    app = create_execution_app(runtime)
    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution", shared_secret=EXECUTION_SECRET
        ),
        transport=httpx.ASGITransport(app=app),
    )
    typed_published = asyncio.run(client.target_plan_recovery(CUSTODY_PUBLISH_KEY))
    assert typed_published.state == "CUSTODY_PUBLISHED_NOT_PREVIEWED"
    assert typed_published.plan_id == _v2_plan()["plan_id"]
    assert _tree(plans.root) == before_missing
    assert _tree(custody.settings.root) == custody_before_missing

    installed = runtime.preview_from_custody(str(receipt["receipt_id"]))
    before = _tree(plans.root)
    custody_before = _tree(custody.settings.root)
    projection = runtime.recovery_projection(
        custody_idempotency_key=CUSTODY_PUBLISH_KEY
    )
    assert projection["state"] == "INSTALLED"
    assert projection["installed"] is True
    assert projection["plan_id"] == installed.plan_id
    assert projection["plan_hash"] == installed.plan_hash
    assert projection["phase"] == "OPEN"
    assert (
        projection["expected_before_position_hash"]
        == installed.raw["expected_before_position_hash"]
    )
    assert (
        projection["expected_after_position_hash"]
        == installed.raw["expected_after_position_hash"]
    )
    assert projection["custody_install_idempotency_key"] == (
        f"install-{CUSTODY_PUBLISH_KEY}"
    )
    assert projection["receipt_id"] == receipt["receipt_id"]
    assert projection["artifact_id"] == receipt["artifact_id"]
    assert projection["recovery_sha256"] == sha256_json(
        {key: value for key, value in projection.items() if key != "recovery_sha256"}
    )
    assert projection["production_allowed"] is False
    assert projection["live_trading_authorized"] is False
    assert projection["countable_forward"] is False
    assert _tree(plans.root) == before
    assert _tree(custody.settings.root) == custody_before


def test_recovery_durable_plan_repository_io_fault_is_retryable_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, receipt = _custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    installed = runtime.preview_from_custody(str(receipt["receipt_id"]))
    plan_path = plans._path(installed.plan_id)
    custody_before = _tree(custody.settings.root)
    plans_before = _tree(plans.root)
    original_lstat = Path.lstat

    def unavailable_lstat(path: Path):
        if path == plan_path:
            raise PermissionError("temporary target plan mount fault")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", unavailable_lstat)
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        f"{CUSTODY_PUBLISH_KEY}"
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "EXECUTION_RECOVERY_REPOSITORY_UNAVAILABLE"
    )
    assert response.json()["detail"]["retryable"] is True
    assert _tree(custody.settings.root) == custody_before
    assert _tree(plans.root) == plans_before


def test_recovery_durable_plan_content_tamper_is_nonretryable_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, receipt = _custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    installed = runtime.preview_from_custody(str(receipt["receipt_id"]))
    plan_path = plans._path(installed.plan_id)
    plan_path.write_bytes(plan_path.read_bytes() + b" ")
    custody_before = _tree(custody.settings.root)
    plans_before = _tree(plans.root)
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        f"{CUSTODY_PUBLISH_KEY}"
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "EXECUTION_RECOVERY_EVIDENCE_UNAVAILABLE"
    )
    assert response.json()["detail"]["retryable"] is False
    assert _tree(custody.settings.root) == custody_before
    assert _tree(plans.root) == plans_before


def test_empty_custody_root_read_routes_are_404_without_initializing_state(
    tmp_path: Path,
) -> None:
    custody = _empty_custody(tmp_path)
    assert not custody.settings.root.exists()
    app = create_custody_app(custody)
    headers = {
        "X-Phase-C-Principal": "execution-orchestrator",
        "X-Phase-C-Custody-Secret": "issue362-execution-custody-read-secret",
    }
    with TestClient(app) as client:
        responses = [
            client.get(
                "/internal/v1/receipts/receipt-issue362-missing-0001",
                headers=headers,
            ),
            client.get(
                "/internal/v1/receipts-by-idempotency/issue362-missing-key-0001",
                headers=headers,
            ),
            client.get(
                "/internal/v1/artifacts/artifact-issue362-missing-0001",
                headers=headers,
            ),
        ]
    assert [response.status_code for response in responses] == [404, 404, 404]
    assert not custody.settings.root.exists()


def test_incomplete_custody_root_read_routes_have_stable_503_without_writes(
    tmp_path: Path,
) -> None:
    custody = _empty_custody(tmp_path)
    custody.settings.root.mkdir(mode=0o700)
    before = _tree(custody.settings.root)
    app = create_custody_app(custody)
    headers = {
        "X-Phase-C-Principal": "execution-orchestrator",
        "X-Phase-C-Custody-Secret": "issue362-execution-custody-read-secret",
    }
    cases = [
        (
            "/internal/v1/receipts/receipt-issue362-missing-0001",
            "PHASE_C_CUSTODY_RECEIPT_READ_UNAVAILABLE",
        ),
        (
            "/internal/v1/receipts-by-idempotency/issue362-missing-key-0001",
            "PHASE_C_CUSTODY_IDEMPOTENCY_READ_UNAVAILABLE",
        ),
        (
            "/internal/v1/artifacts/artifact-issue362-missing-0001",
            "PHASE_C_CUSTODY_ARTIFACT_READ_UNAVAILABLE",
        ),
    ]
    with TestClient(app) as client:
        responses = [(client.get(path, headers=headers), code) for path, code in cases]
    for response, code in responses:
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == code
        assert response.json()["detail"]["retryable"] is True
    assert _tree(custody.settings.root) == before


def test_recovery_empty_custody_root_is_before_custody_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody = _empty_custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    plans_before = _tree(plans.root)
    assert not custody.settings.root.exists()
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        "issue362-empty-custody-recovery-0001"
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)
    assert response.status_code == 200
    assert response.json()["state"] == "BEFORE_CUSTODY"
    assert not custody.settings.root.exists()
    assert _tree(plans.root) == plans_before


def test_recovery_incomplete_custody_root_is_retryable_503_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody = _empty_custody(tmp_path)
    custody.settings.root.mkdir(mode=0o700)
    before = _tree(custody.settings.root)
    runtime, _plans = _runtime(tmp_path, custody)
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        "issue362-incomplete-custody-recovery-0001"
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "EXECUTION_RECOVERY_DEPENDENCY_UNAVAILABLE"
    )
    assert response.json()["detail"]["retryable"] is True
    assert _tree(custody.settings.root) == before


def test_phase_c_http_tamper_remains_nonretryable_execution_recovery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, _receipt = _custody(tmp_path)
    receipt_path = next((custody.settings.root / "receipts").iterdir())
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    custody_before = _tree(custody.settings.root)

    with _serve_phase_c_http(create_custody_app(custody)) as custody_url:
        runtime, plans = _runtime_with_custody_reader(
            tmp_path,
            _HttpCustodyReadClient(
                base_url=custody_url,
                secret="issue362-execution-custody-read-secret",
            ),
        )
        plans_before = _tree(plans.root)
        app = create_execution_app(runtime)
        path = (
            "/internal/v1/recovery/target-plans/by-custody-idempotency/"
            f"{CUSTODY_PUBLISH_KEY}"
        )
        with TestClient(app) as client:
            response = client.get(path, headers=EXECUTION_HEADERS)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "EXECUTION_RECOVERY_EVIDENCE_UNAVAILABLE"
    )
    assert response.json()["detail"]["retryable"] is False
    assert (
        "PHASE_C_TARGET_PLAN_PUBLICATION_EVIDENCE_INVALID"
        in (response.json()["detail"]["message"])
    )
    assert _tree(custody.settings.root) == custody_before
    assert _tree(plans.root) == plans_before


@pytest.mark.parametrize(
    "secret", ["issue362-wrong-read-secret", "issue362-rotated-stale-secret"]
)
def test_recovery_custody_auth_rejection_is_nonretryable_and_zero_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, _receipt = _custody(tmp_path)
    custody_before = _tree(custody.settings.root)

    with _serve_phase_c_http(create_custody_app(custody)) as custody_url:
        runtime, plans = _runtime_with_custody_reader(
            tmp_path,
            _HttpCustodyReadClient(base_url=custody_url, secret=secret),
        )
        plans_before = _tree(plans.root)
        execution_before = runtime.orchestrator.repository.snapshot()
        gateway = runtime.orchestrator.gateway
        gateway_before = (
            list(gateway.send_calls),  # type: ignore[attr-defined]
            list(gateway.cancel_calls),  # type: ignore[attr-defined]
            list(gateway.query_calls),  # type: ignore[attr-defined]
        )
        with TestClient(create_execution_app(runtime)) as client:
            response = client.get(
                "/internal/v1/recovery/target-plans/by-custody-idempotency/"
                + CUSTODY_PUBLISH_KEY,
                headers=EXECUTION_HEADERS,
            )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "EXECUTION_RECOVERY_AUTHENTICATION_REJECTED",
        "message": "custody read authentication was rejected",
        "retryable": False,
    }
    assert _tree(custody.settings.root) == custody_before
    assert _tree(plans.root) == plans_before
    assert runtime.orchestrator.repository.snapshot() == execution_before
    assert (
        list(gateway.send_calls),  # type: ignore[attr-defined]
        list(gateway.cancel_calls),  # type: ignore[attr-defined]
        list(gateway.query_calls),  # type: ignore[attr-defined]
    ) == gateway_before


def test_missing_execution_custody_secret_is_permanent_configuration_error() -> None:
    with pytest.raises(GatewayConfigurationError):
        _HttpCustodyReadClient(base_url="http://custody", secret="")


def test_phase_c_http_artifact_contract_damage_remains_nonretryable_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, _receipt = _custody(tmp_path)

    def invalid_artifact_contract(_artifact_id: str) -> None:
        raise CustodyEvidenceReadError(
            "custody artifact is not an execution target plan"
        )

    monkeypatch.setattr(custody, "artifact_for_execution", invalid_artifact_contract)
    custody_before = _tree(custody.settings.root)
    with _serve_phase_c_http(create_custody_app(custody)) as custody_url:
        runtime, plans = _runtime_with_custody_reader(
            tmp_path,
            _HttpCustodyReadClient(
                base_url=custody_url,
                secret="issue362-execution-custody-read-secret",
            ),
        )
        plans_before = _tree(plans.root)
        app = create_execution_app(runtime)
        path = (
            "/internal/v1/recovery/target-plans/by-custody-idempotency/"
            f"{CUSTODY_PUBLISH_KEY}"
        )
        with TestClient(app) as client:
            response = client.get(path, headers=EXECUTION_HEADERS)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "EXECUTION_RECOVERY_EVIDENCE_UNAVAILABLE"
    )
    assert response.json()["detail"]["retryable"] is False
    assert (
        "PHASE_C_CUSTODY_ARTIFACT_EVIDENCE_INVALID"
        in (response.json()["detail"]["message"])
    )
    assert _tree(custody.settings.root) == custody_before
    assert _tree(plans.root) == plans_before


def test_recovery_dependency_unknown_has_stable_retryable_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, _receipt = _custody(tmp_path)
    runtime, _plans = _runtime(tmp_path, custody)

    def unavailable(_: str):
        raise TimeoutError("custody read timed out")

    runtime.custody.target_plan_publication = unavailable  # type: ignore[method-assign]
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        + CUSTODY_PUBLISH_KEY
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "EXECUTION_RECOVERY_DEPENDENCY_UNAVAILABLE",
        "message": "custody publication lookup outcome is unknown",
        "retryable": True,
    }


def test_recovery_tamper_has_stable_nonretryable_stop_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, _receipt = _custody(tmp_path)
    runtime, plans = _runtime(tmp_path, custody)
    original_artifact = runtime.custody.artifact

    def tampered(artifact_id: str):
        value = original_artifact(artifact_id)
        assert value is not None
        return {**value, "artifact_id": "issue362-foreign-artifact-0001"}

    runtime.custody.artifact = tampered  # type: ignore[method-assign]
    before = _tree(plans.root)
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        + CUSTODY_PUBLISH_KEY
    )
    with TestClient(app) as client:
        response = client.get(path, headers=EXECUTION_HEADERS)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "EXECUTION_RECOVERY_EVIDENCE_UNAVAILABLE",
        "message": "custody publication artifact/plan binding mismatches",
        "retryable": False,
    }
    assert _tree(plans.root) == before


def test_custody_idempotency_receipt_allows_only_dedicated_execution_read_auth(
    tmp_path: Path,
) -> None:
    custody, receipt = _custody(tmp_path)
    app = create_custody_app(custody)
    path = f"/internal/v1/receipts-by-idempotency/{CUSTODY_PUBLISH_KEY}"
    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert (
            client.get(
                path,
                headers={
                    "X-Phase-C-Principal": "execution-orchestrator",
                    "X-Phase-C-Custody-Secret": "issue362-control-custody-secret",
                },
            ).status_code
            == 401
        )
        recovered = client.get(
            path,
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": ("issue362-execution-custody-read-secret"),
            },
        )
    assert recovered.status_code == 200
    assert recovered.json()["receipt_id"] == receipt["receipt_id"]
    assert "artifact" not in recovered.json()


def test_recovery_http_is_authenticated_client_validated_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", EXECUTION_SECRET)
    custody, receipt = _custody(tmp_path)
    runtime, _plans = _runtime(tmp_path, custody)
    runtime.preview_from_custody(str(receipt["receipt_id"]))
    before_execution = runtime.orchestrator.repository.snapshot()
    app = create_execution_app(runtime)
    path = (
        "/internal/v1/recovery/target-plans/by-custody-idempotency/"
        + CUSTODY_PUBLISH_KEY
    )
    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        response = client.get(path, headers=EXECUTION_HEADERS)
    assert response.status_code == 200
    assert response.json()["plan_id"] == _v2_plan()["plan_id"]
    assert runtime.orchestrator.repository.snapshot() == before_execution

    async def read_with_client() -> str:
        execution = ExecutionClient(
            ExecutionClientSettings(
                base_url="http://execution", shared_secret=EXECUTION_SECRET
            ),
            transport=httpx.ASGITransport(app=app),
        )
        return (await execution.target_plan_recovery(CUSTODY_PUBLISH_KEY)).plan_id

    assert asyncio.run(read_with_client()) == _v2_plan()["plan_id"]

    missing = CUSTODY_PUBLISH_KEY.replace("0001", "9999")
    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution", shared_secret=EXECUTION_SECRET
        ),
        transport=httpx.ASGITransport(app=app),
    )
    before_custody = asyncio.run(client.target_plan_recovery(missing))
    assert before_custody.state == "BEFORE_CUSTODY"
    assert before_custody.plan_id == ""


def test_clients_reject_extra_or_rehashed_read_model_state() -> None:
    snapshot = _fresh_snapshot()
    facts = _orchestrator(snapshot).account_facts_projection(snapshot)
    facts["secret"] = "must-not-pass"

    def facts_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=facts)

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(facts_handler),
    )
    with pytest.raises(ExecutionProtocolError, match="account facts projection"):
        asyncio.run(client.account_facts())

    for binding_field in (
        "durable_active_orders_sha256",
        "durable_positions_sha256",
    ):
        bound_snapshot = _fresh_snapshot()
        semantically_unbound = _orchestrator(bound_snapshot).account_facts_projection(
            bound_snapshot
        )
        semantically_unbound["status_binding"][binding_field] = "f" * 64
        semantically_unbound["account_facts_sha256"] = sha256_json(
            {
                key: value
                for key, value in semantically_unbound.items()
                if key != "account_facts_sha256"
            }
        )

        def unbound_facts_handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=semantically_unbound)

        unbound_client = ExecutionClient(
            ExecutionClientSettings(base_url="http://execution"),
            transport=httpx.MockTransport(unbound_facts_handler),
        )
        with pytest.raises(ExecutionProtocolError, match="account facts projection"):
            asyncio.run(unbound_client.account_facts())

    future_snapshot = _fresh_snapshot()
    future_durable_time = _orchestrator(future_snapshot).account_facts_projection(
        future_snapshot
    )
    future_durable_time["status_binding"]["broker"]["last_snapshot_at"] = (
        "2099-01-01T00:00:00Z"
    )
    future_durable_time["account_facts_sha256"] = sha256_json(
        {
            key: value
            for key, value in future_durable_time.items()
            if key != "account_facts_sha256"
        }
    )

    def future_facts_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=future_durable_time)

    future_client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(future_facts_handler),
    )
    with pytest.raises(ExecutionProtocolError, match="account facts projection"):
        asyncio.run(future_client.account_facts())

    valid = {
        "schema_version": "web_bridge_execution_target_plan_recovery_v1",
        "state": "INSTALLED",
        "custody_idempotency_key": CUSTODY_PUBLISH_KEY,
        "custody_install_idempotency_key": f"install-{CUSTODY_PUBLISH_KEY}",
        "custody_version": 2,
        "receipt_id": "issue362-recovery-receipt-0001",
        "receipt_sha256": "1" * 64,
        "artifact_id": "issue362-recovery-artifact-0001",
        "artifact_sha256": "2" * 64,
        "artifact_envelope_sha256": "a" * 64,
        "installed": True,
        "target_plan_schema_version": KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        "plan_id": "issue362-recovery-plan-0001",
        "plan_hash": "3" * 64,
        "phase": "OPEN",
        "lineage": {
            "static_core_equal_sha256": "4" * 64,
            "position_manager_sha256": "5" * 64,
            "final_target_sha256": "6" * 64,
        },
        "account_scope": SCOPE,
        "environment": ENVIRONMENT,
        "gateway_name": "CTP",
        "generated_at": "2026-08-18T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_before_position_hash": "7" * 64,
        "expected_after_position_hash": "8" * 64,
        "order_set_sha256": "9" * 64,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    valid["recovery_sha256"] = sha256_json(valid)
    tampered = deepcopy(valid)
    tampered["phase"] = "CLOSE"

    def recovery_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=tampered)

    recovery_client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(recovery_handler),
    )
    with pytest.raises(ExecutionProtocolError, match="recovery projection"):
        asyncio.run(recovery_client.target_plan_recovery(CUSTODY_PUBLISH_KEY))


def test_account_facts_dto_rejects_regex_shaped_impossible_utc() -> None:
    snapshot = _fresh_snapshot()
    facts = _orchestrator(snapshot).account_facts_projection(snapshot)
    facts["observed_at"] = "2026-99-99T25:61:61Z"
    facts["account_facts_sha256"] = sha256_json(
        {key: value for key, value in facts.items() if key != "account_facts_sha256"}
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=facts)

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ExecutionProtocolError, match="account facts projection"):
        asyncio.run(client.account_facts())
