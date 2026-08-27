from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.execution import (
    DurableExecutionRepository,
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
    RepositoryUnavailableError,
)
from app.execution.final_runtime import (
    FinalExecutionRuntime,
    InMemoryTargetPlanRepository,
)
from app.execution.formal_tick_reader import (
    FormalTickBinding,
    FormalTickEvidenceInvalid,
    FormalTickSourceUnavailable,
)
from app.execution.errors import PlanRejected
from app.execution.models import format_utc, sha256_json
from app.execution.start_quote_proof import (
    ExecutionStartQuoteProofV1,
    build_execution_start_quote_proof,
    validate_execution_start_quote_proof,
)
from app.execution_orchestrator import create_app
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    TRUSTED_KEYLESS_SIMNOW_SCOPE,
    TargetPlan,
    V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
    before_position_projection_hash,
)
from shared.trust_contracts.v1 import canonical_json_line, sha256_bytes
from test_issue291_final_execution import command
from test_issue362_execution_control_active_plan_resume import _bound_snapshot, _request
from test_issue362_target_plan_v3 import _v3_plan


SECRET = "issue362-two-proof-secret"
HEADERS = {
    "X-Control-Execution-Secret": SECRET,
    "X-Control-Actor-Principal": "final-test",
    "X-Control-Actor-Role": "admin",
    "X-Control-Service": "control-api",
}
QUOTE_TIME = datetime(2030, 1, 1, 0, 0, 1, tzinfo=timezone.utc)


class _V3Custody:
    def __init__(self, plan: dict) -> None:
        self.artifact_value = new_artifact_envelope(
            artifact_type="simnow-target-plan",
            trust_domain="runtime_authorization",
            producer_id="issue362-two-proof-fixture",
            producer_version="v3",
            schema_ref=KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
            payload=plan,
            generated_at=plan["generated_at"],
            scope=plan["scope"],
            predecessor_refs=[],
            lineage=[],
        )
        self.receipt_value = {
            "receipt_id": "issue362-v3-install-receipt-0001",
            "receipt_type": "install",
            "artifact_id": self.artifact_value["artifact_id"],
            "artifact_type": "simnow-target-plan",
            "trust_domain": "runtime_authorization",
            "schema_ref": KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
            "artifact_sha256": self.artifact_value["raw_sha256"],
            "scope": plan["scope"],
            "expires_at": plan["expires_at"],
            "custody_version": 2,
            "idempotency_key": "issue362-v3-install-idem-0001",
            "verified": True,
            "installed": True,
            "custody_writer": "artifact-custody",
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }

    def receipt(self, receipt_id: str):
        return (
            self.receipt_value
            if receipt_id == self.receipt_value["receipt_id"]
            else None
        )

    def artifact(self, artifact_id: str):
        if artifact_id != self.artifact_value["artifact_id"]:
            return None
        return {
            "artifact_id": artifact_id,
            "artifact_raw_sha256": sha256_bytes(
                canonical_json_line(self.artifact_value)
            ),
            "artifact": self.artifact_value,
        }

    def probe(self) -> None:
        return None


class _Reader:
    def __init__(self, *, reference_price: float = 5000.0) -> None:
        self.reference_price = reference_price
        self.calls: list[tuple] = []
        self.error: Exception | None = None

    def __call__(self, requests: tuple) -> tuple[FormalTickBinding, ...]:
        self.calls.append(requests)
        if self.error is not None:
            raise self.error
        return tuple(
            FormalTickBinding(
                source="windows-tick-wire-v1",
                vt_symbol=request.vt_symbol,
                price_side=request.price_side,
                price_tick=request.price_tick,
                stream_generation=f"generation-{len(self.calls):04d}",
                ingest_id=f"ingest-{len(self.calls):04d}",
                ingest_seq=len(self.calls),
                event_hash=f"{len(self.calls):064x}",
                received_at_utc=format_utc(QUOTE_TIME),
                reference_price=self.reference_price,
            )
            for request in requests
        )


def _plan() -> dict:
    return _v3_plan(
        expected_before_position_hash=before_position_projection_hash(
            {}, account_scope="account:windows", environment="SIMNOW"
        )
    )


def _two_order_plan() -> dict:
    fields = _plan()
    second = deepcopy(fields["orders"][0])
    second["reference"] = "issue362-v3-order-0002"
    return _v3_plan(
        expected_before_position_hash=fields["expected_before_position_hash"],
        orders=[fields["orders"][0], second],
    )


def _day_session_plan() -> dict:
    fields = _plan()
    quote_proof = deepcopy(fields["creation_quote_proof"])
    quote_proof["validated_at_utc"] = "2026-08-26T06:33:00Z"
    for binding in quote_proof["bindings"].values():
        binding["received_at_utc"] = "2026-08-26T06:33:00Z"
    return _v3_plan(
        creation_quote_proof=quote_proof,
        generated_at="2026-08-26T06:33:00Z",
        expected_before_position_hash=fields["expected_before_position_hash"],
    )


def _runtime(plan: dict, reader: _Reader, *, repo=None):
    repo = repo or InMemoryExecutionRepository(scope="account:windows")
    gateway = InMemoryGateway(account_scope="account:windows", environment="SIMNOW")
    core = ExecutionOrchestrator(
        repo,
        gateway,
        scope="account:windows",
        environment="SIMNOW",
        test_mode=True,
    )
    custody = _V3Custody(plan)
    service = FinalExecutionRuntime(
        core,
        plans=InMemoryTargetPlanRepository(),
        custody=custody,
        allowed_scope=TRUSTED_KEYLESS_SIMNOW_SCOPE,
        allow_simnow_execution=True,
        allow_trusted_keyless_simnow=True,
        formal_tick_bindings_reader=reader,
        quote_clock=lambda: QUOTE_TIME,
    )
    return service, core, repo, gateway, custody


def test_v3_day_session_active_plan_builds_exact_gfd_rollover_evidence() -> None:
    plan = _day_session_plan()
    service, _, repo, _, _ = _runtime(plan, _Reader())
    service.plans.put(TargetPlan.from_mapping(plan))

    def activate(state: dict) -> None:
        state["plan"].update(
            {"state": "ACTIVE", "plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]}
        )

    repo.mutate(activate)

    evidence = service._trading_day_rollover_evidence()

    assert evidence is not None
    assert evidence["intent_trading_day"] == "20260826"
    assert evidence["time_condition"] == "GFD"
    assert len(evidence["intent_ids"]) == len(plan["orders"])


def test_expired_revoked_active_plan_suppresses_finalization_only_with_rollover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only immutable expired rollover evidence may skip finalization."""

    template = _day_session_plan()
    plan = _v3_plan(
        generated_at="2026-08-26T06:33:00Z",
        expires_at="2026-08-26T06:52:14Z",
        creation_quote_proof=template["creation_quote_proof"],
        expected_before_position_hash=template["expected_before_position_hash"],
    )
    service, core, repo, _, _ = _runtime(plan, _Reader())
    parsed = TargetPlan.from_mapping(plan)
    service.plans.put(parsed)

    def active_revoked(state: dict) -> None:
        state["plan"].update(
            {
                "state": "ACTIVE",
                "plan_id": plan["plan_id"],
                "plan_hash": plan["plan_hash"],
            }
        )
        state["authority"].update(
            {
                "state": "REVOKED",
                "artifact_id": parsed.authority_id,
                "artifact_hash": parsed.authority_hash,
                "expires_at": plan["expires_at"],
            }
        )

    repo.mutate(active_revoked)
    monkeypatch.setattr(
        "app.execution.final_runtime.utc_now",
        lambda: datetime(2026, 8, 27, tzinfo=timezone.utc),
    )
    rollover = service._trading_day_rollover_evidence()
    assert rollover is not None
    assert service._expired_revoked_rollover_recovery(rollover) is True
    assert service._expired_revoked_rollover_recovery(None) is False

    # Existing finalization behavior stays strict if that rollover evidence is
    # unavailable: a revoked authority still reaches the normal rejection.
    evidence = {
        "plan_id": plan["plan_id"],
        "plan_hash": plan["plan_hash"],
        "expected_after_position_hash": plan["expected_after_position_hash"],
        "authority_artifact_id": parsed.authority_id,
        "authority_artifact_sha256": parsed.authority_hash,
        "authority_receipt_id": "keyless-custody",
        "authority_receipt_sha256": "0" * 64,
        "preview_receipt_id": "preview-receipt-0001",
        "preview_receipt_sha256": "a" * 64,
        "preview_artifact_id": "preview-artifact-0001",
        "preview_artifact_sha256": "b" * 64,
        "expected_send_intent_bindings": [],
    }
    with pytest.raises(PlanRejected, match="does not bind active plan"):
        core._apply_finalization_evidence(repo.snapshot(), evidence)


@pytest.mark.parametrize("with_rollover", [True, False])
def test_expired_revoked_rollover_reconcile_58_unknown_is_query_only(
    monkeypatch: pytest.MonkeyPatch, with_rollover: bool
) -> None:
    """The frozen-size recovery either closes 58 GFD UNKNOWNs or stops."""

    start_time = datetime(2026, 8, 26, 6, 47, tzinfo=timezone.utc)
    rollover_time = datetime(2026, 8, 27, 1, 0, tzinfo=timezone.utc)
    now = {"value": start_time}
    monkeypatch.setattr("app.execution.orchestrator.utc_now", lambda: now["value"])
    monkeypatch.setattr("app.execution.final_runtime.utc_now", lambda: now["value"])
    template = _day_session_plan()
    orders = []
    for index in range(58):
        order = deepcopy(template["orders"][0])
        order["reference"] = f"issue456-rollover-{index:04d}"
        orders.append(order)
    plan = _v3_plan(
        generated_at="2026-08-26T06:33:00Z",
        expires_at="2026-08-26T06:52:14Z",
        creation_quote_proof=template["creation_quote_proof"],
        expected_before_position_hash=template["expected_before_position_hash"],
        orders=orders,
    )
    service, core, repo, gateway, custody = _runtime(plan, _Reader())
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-default",
            generation=1,
            connected=True,
            active_order_count=0,
            position_snapshot_hash=sha256_json({}),
            observed_at="2026-08-26T06:47:00Z",
            positions={},
            account_scope="account:windows",
            environment="SIMNOW",
        )
    )
    _token, start = _prepare(service, core, repo, custody, plan)
    service.process_command(start)
    intent_ids = sorted(repo.snapshot()["send_intents"])
    assert len(intent_ids) == 58
    parsed = TargetPlan.from_mapping(plan)

    def make_unknown_expired(state: dict) -> None:
        for intent_id in intent_ids:
            state["send_intents"][intent_id]["state"] = "UNKNOWN_OUTCOME"
            state["unknown_outcomes"][intent_id] = {"reason": "response lost"}
        state["reconciliation"].update({"state": "UNKNOWN", "unknown_outcomes": 58})
        state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"
        state["authority"].update(
            {
                "state": "REVOKED",
                "artifact_id": parsed.authority_id,
                "artifact_hash": parsed.authority_hash,
                "expires_at": plan["expires_at"],
            }
        )

    repo.mutate(make_unknown_expired)
    for intent_id in intent_ids:
        gateway.intent_outcomes[intent_id] = {"state": "UNKNOWN_OUTCOME"}
    now["value"] = rollover_time
    snapshot_id = "snapshot-rollover-issue456"
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id=snapshot_id,
            generation=2,
            connected=True,
            active_order_count=0,
            position_snapshot_hash=sha256_json({}),
            observed_at="2026-08-27T01:00:00Z",
            positions={},
            account_scope="account:windows",
            environment="SIMNOW",
            broker_trading_day="20260827",
            broker_limit_time_condition="GFD",
        )
    )
    gateway.send_calls.clear()
    gateway.cancel_calls.clear()
    if not with_rollover:
        monkeypatch.setattr(service, "_trading_day_rollover_evidence", lambda: None)

    response = service.process_command(
        command(
            "reconcile",
            f"issue456-rollover-{'pass' if with_rollover else 'stop'}",
            repo.state_version,
            {
                "reconciliation_run_id": (
                    f"issue456-rollover-{'pass' if with_rollover else 'stop'}"
                ),
                "snapshot_id": snapshot_id,
                "reason": "query-only expired GFD rollover reconciliation",
            },
        )
    )
    state = repo.snapshot()
    assert gateway.send_calls == []
    assert gateway.cancel_calls == []
    assert gateway.query_calls[-58:] == intent_ids
    if with_rollover:
        assert response.result["accepted"] is True
        assert response.result["trading_day_rollover_reconciled_intent_count"] == 58
        assert state["unknown_outcomes"] == {}
        assert state["lifecycle"] == "READY"
        assert state["plan"]["state"] == "ACTIVE"
        assert state["authority"]["state"] == "REVOKED"
        assert {
            row["state"] for row in state["send_intents"].values()
        } == {"RECONCILED"}
    else:
        assert response.result["accepted"] is False
        assert response.result["unknown_outcomes"] == 58
        assert state["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"


def _prepare(service, core, repo, custody, plan: dict):
    service.process_command(
        command(
            "preview",
            "preview-v3-two-proof-0001",
            repo.state_version,
            {
                "plan_hash": plan["plan_hash"],
                "artifact_hash": custody.receipt_value["artifact_sha256"],
                "mode": "simnow_preview",
                "receipt_id": custody.receipt_value["receipt_id"],
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "reconcile-v3-two-proof-0001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-v3-two-proof-0001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh v3 two proof account facts",
            },
        )
    )
    service.process_command(
        command(
            "enable",
            "enable-v3-two-proof-0001",
            repo.state_version,
            {
                "authority_artifact_id": plan["plan_id"],
                "authority_hash": plan["plan_hash"],
                "expires_at": plan["expires_at"],
                "reason": "verified v3 two proof authority",
            },
        )
    )
    token = core.acquire_leader("leader-v3-two-proof-0001")
    start = command(
        "start",
        "start-v3-two-proof-0001",
        repo.state_version,
        {
            "plan_id": plan["plan_id"],
            "plan_hash": plan["plan_hash"],
            "reason": "start v3 with fresh formal quotes",
        },
        fence={"leader_epoch": token.epoch, "fencing_token": token.fencing_token},
    )
    return token, start


def _mixed_active_resume_fixture(*, repo=None):
    plan = _two_order_plan()
    reader = _Reader()
    service, core, repo, gateway, custody = _runtime(plan, reader, repo=repo)
    token, start = _prepare(service, core, repo, custody, plan)
    parsed = TargetPlan.from_mapping(plan)
    start_proof = build_execution_start_quote_proof(
        parsed, reader=reader, clock=lambda: QUOTE_TIME
    )
    core.process_command(start, start_evidence=start_proof)
    first = service.send_plan_order(
        plan["plan_id"],
        plan["orders"][0]["reference"],
        token=token,
        execution_start_quote_proof=start_proof,
    )
    repo.mutate(
        lambda state: state["send_intents"][first["intent_id"]].update(
            {"state": "PERSISTED"}
        )
    )
    gateway.send_calls.clear()
    gateway.query_calls.clear()
    return service, core, repo, gateway, reader, token, plan, first["intent_id"]


def test_v3_start_persists_full_proof_and_exact_retry_does_not_reread() -> None:
    plan = _plan()
    reader = _Reader()
    service, core, repo, gateway, custody = _runtime(plan, reader)
    _token, start = _prepare(service, core, repo, custody, plan)

    first = service.process_command(start)
    state = repo.snapshot()
    proof = first.result["execution_start_quote_proof"]
    intent = next(iter(state["send_intents"].values()))

    assert first.result["plan"]["state"] == "ACTIVE"
    assert (
        ExecutionStartQuoteProofV1.from_mapping(
            proof, plan=TargetPlan.from_mapping(plan)
        ).as_dict()
        == proof
    )
    assert first.receipt["result"]["execution_start_quote_proof"] == proof
    assert proof["creation_quote_proof_sha256"] == sha256_json(
        plan["creation_quote_proof"]
    )
    assert proof["max_age_seconds"] == V3_FORMAL_QUOTE_MAX_AGE_SECONDS == 5.0
    assert proof["bindings"][plan["orders"][0]["reference"]]["phase"] == "OPEN"
    assert (
        intent["execution_start_quote_proof_sha256"]
        == (intent["execution_start_quote_proof"]["proof_sha256"])
    )
    assert gateway.send_calls[0][0] == plan["orders"][0]
    assert len(reader.calls) == 1

    replay = service.process_command(start)
    assert replay.reused is True
    assert len(reader.calls) == 1
    assert len(gateway.send_calls) == 1


@pytest.mark.parametrize(
    ("error", "status", "code", "retryable"),
    [
        (
            FormalTickSourceUnavailable("formal mounts unavailable"),
            503,
            "EXECUTION_START_QUOTE_SOURCE_UNAVAILABLE",
            True,
        ),
        (
            FormalTickEvidenceInvalid("formal journal was tampered"),
            409,
            "EXECUTION_START_QUOTE_EVIDENCE_INVALID",
            False,
        ),
    ],
)
def test_v3_start_quote_failure_is_structured_and_zero_write(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status: int,
    code: str,
    retryable: bool,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    plan = _plan()
    reader = _Reader()
    service, core, repo, gateway, custody = _runtime(plan, reader)
    _token, start = _prepare(service, core, repo, custody, plan)
    before = repo.snapshot()
    reader.error = error

    with TestClient(create_app(service)) as client:
        response = client.post("/internal/v1/commands", json=start, headers=HEADERS)

    assert response.status_code == status
    assert response.json()["detail"] == {
        "code": code,
        "message": str(error),
        "retryable": retryable,
        "mutation_admitted": False,
        **({"action": "STOP"} if not retryable else {}),
    }
    assert repo.snapshot() == before
    assert repo.snapshot()["plan"]["state"] == "PREVIEWED"
    assert gateway.send_calls == []


def test_v3_price_change_requires_replan_before_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    plan = _plan()
    reader = _Reader(reference_price=5001.0)
    service, core, repo, gateway, custody = _runtime(plan, reader)
    _token, start = _prepare(service, core, repo, custody, plan)
    before = repo.snapshot()

    with TestClient(create_app(service)) as client:
        response = client.post("/internal/v1/commands", json=start, headers=HEADERS)

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "REPLAN_REQUIRED",
        "message": "fresh protected price differs from immutable order price",
        "retryable": False,
        "mutation_admitted": False,
    }
    assert repo.snapshot() == before
    assert repo.snapshot()["plan"]["state"] == "PREVIEWED"
    assert gateway.send_calls == []


def test_v3_active_missing_intent_rereads_but_existing_intent_never_does() -> None:
    plan = _plan()
    reader = _Reader()
    service, core, repo, gateway, custody = _runtime(plan, reader)
    token, start = _prepare(service, core, repo, custody, plan)
    parsed = TargetPlan.from_mapping(plan)
    start_proof = build_execution_start_quote_proof(
        parsed, reader=reader, clock=lambda: QUOTE_TIME
    )
    accepted = core.process_command(start, start_evidence=start_proof)
    assert accepted.result["accepted"] is True
    assert repo.snapshot()["send_intents"] == {}

    result = service.resume_active_plan(_request(plan, token, _bound_snapshot(service)))
    assert result["new_intent_count"] == 1
    assert len(reader.calls) == 2
    assert len(gateway.send_calls) == 1

    reader.error = AssertionError("existing intent must not read formal quotes")
    intent_id = next(iter(repo.snapshot()["send_intents"]))
    repo.mutate(
        lambda state: state["send_intents"][intent_id].update({"state": "PERSISTED"})
    )
    gateway.intent_outcomes[intent_id] = {"state": "ACKNOWLEDGED"}
    second = service.resume_active_plan(_request(plan, token, _bound_snapshot(service)))
    assert second["new_intent_count"] == 0
    assert len(reader.calls) == 2
    assert gateway.query_calls == [intent_id]


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        (
            "source",
            503,
            "EXECUTION_START_QUOTE_SOURCE_UNAVAILABLE",
        ),
        ("replan", 409, "REPLAN_REQUIRED"),
        ("tamper", 409, "EXECUTION_START_QUOTE_EVIDENCE_INVALID"),
    ],
)
def test_mixed_resume_quote_failure_precedes_query_and_is_zero_write(
    monkeypatch: pytest.MonkeyPatch, failure: str, status: int, code: str
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    service, _core, repo, gateway, reader, token, plan, _intent_id = (
        _mixed_active_resume_fixture()
    )
    payload = _request(plan, token, _bound_snapshot(service))
    before = repo.snapshot()
    if failure == "source":
        reader.error = FormalTickSourceUnavailable("formal mounts unavailable")
    elif failure == "tamper":
        reader.error = FormalTickEvidenceInvalid("formal journal was tampered")
    else:
        reader.reference_price = 5001.0

    with TestClient(create_app(service)) as client:
        response = client.post(
            "/internal/v1/active-plans/resume", json=payload, headers=HEADERS
        )

    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    assert response.json()["detail"]["mutation_admitted"] is False
    assert repo.snapshot() == before
    assert gateway.query_calls == []
    assert gateway.send_calls == []


def test_mixed_resume_query_requires_new_snapshot_then_sends_missing_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    service, _core, repo, gateway, _reader, token, plan, intent_id = (
        _mixed_active_resume_fixture()
    )
    first_payload = _request(plan, token, _bound_snapshot(service))

    with TestClient(create_app(service)) as client:
        first = client.post(
            "/internal/v1/active-plans/resume",
            json=first_payload,
            headers=HEADERS,
        )

    assert first.status_code == 409
    assert first.json()["detail"] == {
        "code": "EXECUTION_ACTIVE_PLAN_RESUME_FRESH_SNAPSHOT_REQUIRED",
        "message": (
            "existing intent query advanced durable state; obtain a fresh "
            "reconciliation snapshot"
        ),
        "retryable": True,
        "order_mutation_admitted": False,
        "repository_mutated": True,
        "retry_with_fresh_snapshot_only": True,
    }
    assert gateway.query_calls == [intent_id]
    assert gateway.send_calls == []

    second_payload = _request(plan, token, _bound_snapshot(service))
    with TestClient(create_app(service)) as client:
        second = client.post(
            "/internal/v1/active-plans/resume",
            json=second_payload,
            headers=HEADERS,
        )

    assert second.status_code == 200
    assert second.json()["new_intent_count"] == 1
    assert second.json()["queried_intent_count"] == 0
    assert len(gateway.query_calls) == 1
    assert len(gateway.send_calls) == 1


def test_mixed_resume_recloses_snapshot_after_quote_read_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", SECRET)
    service, _core, repo, gateway, reader, token, plan, _intent_id = (
        _mixed_active_resume_fixture()
    )
    payload = _request(plan, token, _bound_snapshot(service))
    before = repo.snapshot()

    def racing_reader(requests):
        repo.append_audit({"kind": "test"})
        return reader(requests)

    service.formal_tick_bindings_reader = racing_reader
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/internal/v1/active-plans/resume", json=payload, headers=HEADERS
        )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == (
        "EXECUTION_ACTIVE_PLAN_RESUME_REJECTED"
    )
    assert "snapshot is stale" in response.json()["detail"]["message"]
    after = repo.snapshot()
    assert after["state_version"] == before["state_version"] + 1
    assert after["audit"][:-1] == before["audit"]
    assert after["audit"][-1]["kind"] == "test"
    assert gateway.query_calls == []
    assert gateway.send_calls == []


def test_repository_freezes_existing_intent_quote_creation_facts(tmp_path) -> None:
    path = tmp_path / "execution-state.json"
    durable = DurableExecutionRepository(path, scope="account:windows")
    _service, _core, repo, _gateway, _reader, _token, _plan_raw, intent_id = (
        _mixed_active_resume_fixture(repo=durable)
    )
    before = repo.snapshot()
    before_bytes = path.read_bytes()

    def tamper(candidate: dict) -> None:
        intent = candidate["send_intents"][intent_id]
        proof = intent["execution_start_quote_proof"]
        binding = next(iter(proof["bindings"].values()))
        binding["stream_generation"] = "generation-tampered-0001"
        binding["ingest_id"] = "ingest-tampered-0001"
        binding["ingest_seq"] += 1
        binding["event_hash"] = "f" * 64
        proof["proof_sha256"] = sha256_json(
            {key: value for key, value in proof.items() if key != "proof_sha256"}
        )
        intent["execution_start_quote_proof_sha256"] = proof["proof_sha256"]

    with pytest.raises(RepositoryUnavailableError, match="creation facts changed"):
        repo.mutate(tamper)
    assert repo.snapshot() == before
    assert path.read_bytes() == before_bytes

    repo.mutate(
        lambda candidate: candidate["send_intents"][intent_id].update(
            {"state": "RECONCILED", "broker_order_id": "broker-order-final-0001"}
        )
    )
    after = repo.snapshot()
    assert after["send_intents"][intent_id]["state"] == "RECONCILED"
    assert (
        after["send_intents"][intent_id]["execution_start_quote_proof"]
        == (before["send_intents"][intent_id]["execution_start_quote_proof"])
    )


def test_close_start_proof_cannot_be_spliced_into_open_plan() -> None:
    open_plan = TargetPlan.from_mapping(_plan())
    close_raw = deepcopy(_plan())
    close_raw["phase"] = "CLOSE"
    close_raw["orders"][0]["offset"] = "CLOSE"
    # Rebuilding is intentionally omitted: even a fully rehashed foreign proof
    # must fail the immutable OPEN plan binding below.
    proof = build_execution_start_quote_proof(
        open_plan, reader=_Reader(), clock=lambda: QUOTE_TIME
    )
    proof["phase"] = close_raw["phase"]
    proof["bindings"][open_plan.orders[0].reference]["phase"] = "CLOSE"
    proof["proof_sha256"] = sha256_json(
        {key: value for key, value in proof.items() if key != "proof_sha256"}
    )
    with pytest.raises(ValueError, match="immutable plan"):
        validate_execution_start_quote_proof(proof, plan=open_plan)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda binding: binding.update({"price_tick": 2.0, "reference_price": 4999.0}),
        lambda binding: binding.update({"received_at_utc": "2029-12-31T23:59:55Z"}),
    ],
)
def test_fully_rehashed_tick_or_freshness_splice_is_stop(mutate) -> None:
    plan = TargetPlan.from_mapping(_plan())
    proof = build_execution_start_quote_proof(
        plan, reader=_Reader(), clock=lambda: QUOTE_TIME
    )
    mutate(proof["bindings"][plan.orders[0].reference])
    proof["proof_sha256"] = sha256_json(
        {key: value for key, value in proof.items() if key != "proof_sha256"}
    )
    with pytest.raises(ValueError):
        validate_execution_start_quote_proof(proof, plan=plan)


def test_v3_start_quote_age_policy_is_exact_and_hash_bound() -> None:
    plan = TargetPlan.from_mapping(_plan())
    proof = build_execution_start_quote_proof(
        plan, reader=_Reader(), clock=lambda: QUOTE_TIME
    )
    assert proof["max_age_seconds"] == V3_FORMAL_QUOTE_MAX_AGE_SECONDS == 5.0

    proof["max_age_seconds"] = 2.0
    proof["proof_sha256"] = sha256_json(
        {key: value for key, value in proof.items() if key != "proof_sha256"}
    )
    with pytest.raises(ValueError, match="policy is invalid"):
        validate_execution_start_quote_proof(proof, plan=plan)
