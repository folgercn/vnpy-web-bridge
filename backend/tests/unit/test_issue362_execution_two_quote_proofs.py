from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.execution import (
    DurableExecutionRepository,
    ExecutionOrchestrator,
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
