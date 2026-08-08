"""Phase C fault scenarios executed without a network, broker, or private key.

The harness deliberately drives the shipped Phase A/B implementations instead
of reproducing their safety checks.  Its output is an evidence *claim* for an
offline test run, never a production/trading authorization.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from app.execution import (
    ExecutionOrchestrator,
    InMemoryExecutionRepository,
    InMemoryGateway,
    MutationContext,
)
from app.execution.errors import (
    FencingError,
    GatewayTimeout,
    LeaseNotHeldError,
    UnknownOutcomeError,
)
from app.execution.fencing import LeaderFencer
from app.execution.models import sha256_json

from scripts.phase_c_faults.process_runner import run_process_faults
from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied
from scripts.windows_fence_foundation.final_admission_v1 import (
    WindowsRpcFencedAdmissionV1,
    _receipt_digest,
)
from shared.artifact_contracts import new_artifact_envelope
from shared.artifact_custody import ArtifactCustody, CustodyError

HASH = "b" * 64
SCENARIO_SCHEMA_VERSION = "issue_291_phase_c_fault_scenario_v1"
BUNDLE_SCHEMA_VERSION = "issue_291_phase_c_fault_evidence_bundle_v1"


def _command(command: str, key: str, version: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"command-{key[-12:]}",
        "idempotency_key": key,
        "correlation_id": f"correlation-{key[-12:]}",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "phase-c-harness",
            "operator": "offline-test",
            "role": "admin",
        },
        "command": command,
        "expected": {"state_version": version},
        "payload": payload,
    }


def _ready_service() -> tuple[ExecutionOrchestrator, InMemoryExecutionRepository, InMemoryGateway, object]:
    repo = InMemoryExecutionRepository(scope="account:phase-c")
    gateway = InMemoryGateway(account_scope="account:phase-c", environment="simnow")
    service = ExecutionOrchestrator(
        repo, gateway, scope="account:phase-c", environment="simnow", test_mode=True
    )
    token = service.acquire_leader("leader-phase-c")
    service.process_command(_command("enable", "enable-phase-c-000001", repo.state_version, {
        "authority_artifact_id": "artifact-phase-c-000001", "authority_hash": HASH,
        "expires_at": "2030-01-01T00:00:00Z", "reason": "offline phase-c harness",
    }))
    service.process_command(_command("reconcile", "reconcile-phase-c-001", repo.state_version, {
        "reconciliation_run_id": "run-phase-c-000001", "snapshot_id": "snapshot-default", "reason": "offline fresh snapshot",
    }))
    service.process_command(_command("start", "start-phase-c-000001", repo.state_version, {
        "plan_id": "plan-phase-c-000001", "plan_hash": HASH, "reason": "offline phase-c plan",
    }))
    return service, repo, gateway, token


def _send(service: ExecutionOrchestrator, token: object, key: str) -> dict[str, Any]:
    return service.send_order(
        {"symbol": "RB", "volume": 1}, idempotency_key=key,
        plan_id="plan-phase-c-000001", plan_hash=HASH,
        leader_epoch=token.epoch, fencing_token=token.fencing_token, token=token,
    )


def _cancel(
    service: ExecutionOrchestrator, token: object, target_intent_id: str, key: str
) -> dict[str, Any]:
    return service.cancel_order(
        target_intent_id,
        idempotency_key=key,
        plan_id="plan-phase-c-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )


def _context(action: str, *, epoch: int = 3, token: int = 7) -> MutationContext:
    context = MutationContext(
        account_scope="account:phase-c", environment="simnow", leader_epoch=epoch,
        fencing_token=token, plan_id="plan-phase-c-000001", plan_hash=HASH,
        intent_id=f"intent-phase-c-{action}-001", idempotency_key=f"{action}-phase-c-key-0001",
        action=action, receipt_id=f"receipt-intent-phase-c-{action}-001",
        request_hash=sha256_json({"symbol": "RB", "volume": 1}),
    )
    return replace(context, receipt_hash=_receipt_digest(context.as_dict()))


def _identifiers(value: Any, key: str) -> set[str]:
    if isinstance(value, Mapping):
        found = {str(value[key])} if isinstance(value.get(key), str) else set()
        for child in value.values():
            found.update(_identifiers(child, key))
        return found
    if isinstance(value, list):
        return set().union(*(_identifiers(child, key) for child in value)) if value else set()
    return set()


def _json_evidence(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_evidence(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_evidence(child) for child in value]
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _json_evidence(as_dict())
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported evidence value: {type(value).__name__}")


def _case(case_id: str, observations: list[dict[str, Any]]) -> dict[str, Any]:
    records = []
    for sequence, observation in enumerate(observations, start=1):
        record_type = str(observation["record_type"])
        payload = _json_evidence(dict(observation["payload"]))
        records.append({"record_type": record_type, "sequence": sequence, "payload": payload, "sha256": sha256_json({"record_type": record_type, "sequence": sequence, "payload": payload})})
    timeline = [record["sha256"] for record in records]
    uniqueness = {
        "unique_intent_ids": sorted(_identifiers(records, "intent_id")),
        "unique_receipt_ids": sorted(_identifiers(records, "receipt_id")),
        "gateway_event_count": sum("gateway" in record["record_type"] for record in records),
    }
    derived_sha256 = sha256_json({"case_id": case_id, "timeline": timeline, **uniqueness})
    return {
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "case_id": case_id,
        "status": "passed",
        "execution_mode": "offline_deterministic",
        "production": False,
        "live": False,
        "countable_forward": False,
        "evidence": {"records": records, "timeline": timeline, "derived_sha256": derived_sha256, **uniqueness},
    }


def _leader_faults() -> dict[str, Any]:
    repo = InMemoryExecutionRepository(scope="account:phase-c")
    start = datetime(2030, 1, 1, tzinfo=timezone.utc)
    old = LeaderFencer(repo, scope="account:phase-c", lease_seconds=1)
    first = old.acquire("leader-phase-c", now=start)
    with _raises(LeaseNotHeldError):
        LeaderFencer(repo, scope="account:phase-c").acquire("standby-phase-c", now=start)
    new = LeaderFencer(repo, scope="account:phase-c", lease_seconds=1)
    second = new.acquire("standby-phase-c", now=start + timedelta(seconds=2))
    with _raises(FencingError):
        old.validate(first, now=start + timedelta(seconds=2))
    with _raises(FencingError):
        old.admission(leader_epoch=first.epoch, fencing_token=first.fencing_token, token=first, now=start + timedelta(seconds=2))
    assert second.epoch > first.epoch and second.fencing_token > first.fencing_token
    return _case("double_leader_pause_expiry_partition_rejoin", [
        {"record_type": "first_leader_token", "payload": first.as_dict()},
        {"record_type": "replacement_leader_token", "payload": second.as_dict()},
        {"record_type": "durable_lease", "payload": repo.snapshot()["lease"]},
    ])


def _final_fence_stale_send_cancel() -> dict[str, Any]:
    calls: list[str] = []
    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:phase-c", environment="simnow", current_epoch=3,
        current_fencing_token=7,
        send_handler=lambda *_: calls.append("send") or {"state": "ACKNOWLEDGED", "accepted": True},
        cancel_handler=lambda *_: calls.append("cancel") or {"state": "CANCELLED", "accepted": True, "cancelled": True},
    )
    send, cancel = _context("send"), _context("cancel")
    admission.register_receipt(intent_id=send.intent_id, receipt=send.as_dict())
    admission.register_receipt(intent_id=cancel.intent_id, receipt=cancel.as_dict())
    admission.install_fence(epoch=4, fencing_token=8)
    with _raises(WindowsRpcDurableFenceDenied):
        admission.send_order_fenced_v1({"symbol": "RB", "volume": 1}, send)
    with _raises(WindowsRpcDurableFenceDenied):
        admission.cancel_order_fenced_v1({"symbol": "RB", "volume": 1}, cancel)
    assert calls == []
    return _case("stale_token_send_cancel_final_fence", [
        {"record_type": "windows_final_fence", "payload": admission.snapshot()},
        {"record_type": "native_handler_calls", "payload": {"calls": calls}},
        {"record_type": "send_receipt", "payload": send.as_dict()},
        {"record_type": "cancel_receipt", "payload": cancel.as_dict()},
    ])


def _timeout_no_replay() -> dict[str, Any]:
    service, _repo, gateway, token = _ready_service()
    gateway.fail_send = TimeoutError("offline rpc timeout")
    with _raises(GatewayTimeout):
        _send(service, token, "send-phase-c-timeout-01")
    with _raises(UnknownOutcomeError):
        _send(service, token, "send-phase-c-timeout-02")
    assert len(gateway.send_calls) == 1
    assert service.status()["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    return _case("rpc_timeout_unknown_same_intent_no_replay", [
        {"record_type": "durable_execution_state", "payload": service.repository.snapshot()},
        {"record_type": "gateway_send_calls", "payload": {"calls": gateway.send_calls}},
    ])


def _crash_and_restart() -> dict[str, Any]:
    service, repo, gateway, token = _ready_service()
    repo.mark_unavailable()
    with _raises(Exception):
        _send(service, token, "send-phase-c-before-gateway")
    assert gateway.send_calls == []
    repo.mark_available()
    sent = _send(service, token, "send-phase-c-restart-001")
    observed_cancel_states: list[str] = []

    def cancel_then_timeout(_request: object, context: object) -> dict[str, Any]:
        observed_cancel_states.append(
            repo.snapshot()["send_intents"][context.intent_id]["state"]
        )
        raise TimeoutError("offline crash during cancel gateway call")

    gateway.cancel_order = cancel_then_timeout
    with _raises(GatewayTimeout):
        _cancel(service, token, sent["intent_id"], "cancel-phase-c-restart-001")
    assert observed_cancel_states == ["CANCEL_REQUESTED"]
    restarted = ExecutionOrchestrator(repo, gateway, scope="account:phase-c", environment="simnow", test_mode=True)
    state = repo.snapshot()
    assert restarted.lifecycle == "HALTED_UNKNOWN_OUTCOME"
    assert any(value.get("state") == "UNKNOWN_OUTCOME" for value in state["send_intents"].values())
    with _raises(UnknownOutcomeError):
        _send(restarted, token, "send-phase-c-after-restart")
    return _case("crash_before_after_gateway_and_restart_reconcile", [
        {"record_type": "cancel_boundary_state", "payload": {"states": observed_cancel_states}},
        {"record_type": "durable_execution_state_after_restart", "payload": state},
        {"record_type": "gateway_send_calls", "payload": {"calls": gateway.send_calls}},
    ])


def _delayed_duplicate_callback() -> dict[str, Any]:
    service, repo, gateway, token = _ready_service()
    result = _send(service, token, "send-phase-c-callback-001")
    intent_id = result["intent_id"]
    service._mark_intent_result(intent_id, {"state": "ACKNOWLEDGED", "broker_order_id": "broker-phase-c-001"})
    service._mark_intent_result(intent_id, {"state": "ACKNOWLEDGED", "broker_order_id": "broker-phase-c-001"})
    archive = repo.snapshot()["terminal_archive"]
    assert len(gateway.send_calls) == 1 and not archive
    return _case("delayed_duplicate_callback_idempotent", [
        {"record_type": "durable_execution_state", "payload": repo.snapshot()},
        {"record_type": "gateway_send_calls", "payload": {"calls": gateway.send_calls}},
    ])


def _custody_faults(root: Path) -> dict[str, Any]:
    schemas = {"phase-c-payload-v1": {"type": "object", "additionalProperties": False, "required": ["production", "live", "countable_forward"], "properties": {"production": {"const": False}, "live": {"const": False}, "countable_forward": {"const": False}}}}
    item = new_artifact_envelope(
        artifact_type="phase-c-evidence", trust_domain="research", producer_id="phase-c-harness", producer_version="v1", schema_ref="phase-c-payload-v1",
        payload={"production": False, "live": False, "countable_forward": False}, generated_at="2030-01-01T00:00:00Z",
        scope={"production": False, "live": False, "countable_forward": False}, predecessor_refs=[], lineage=[],
    )
    custody_root = root / "custody"
    with ArtifactCustody(custody_root, writer_id="phase-c-custody", writer_epoch=1, schema_registry=schemas) as store:
        store.publish(item, actor_id="phase-c", idempotency_key="publish-phase-c-001", correlation_id="corr-phase-c-001", expected_version=0)
        with _raises(CustodyError):
            store.publish(item, actor_id="phase-c", idempotency_key="publish-phase-c-001", correlation_id="corr-phase-c-other", expected_version=1)
    receipt_path = next((custody_root / "receipts").glob("*.json"))
    receipt_path.write_bytes(b"{tampered}")
    with _raises(CustodyError):
        ArtifactCustody(custody_root, writer_id="phase-c-custody", writer_epoch=1, schema_registry=schemas)
    swap_root = root / "custody-symlink-swap"
    with ArtifactCustody(swap_root, writer_id="phase-c-custody", writer_epoch=1, schema_registry=schemas) as store:
        store.publish(item, actor_id="phase-c", idempotency_key="publish-phase-c-002", correlation_id="corr-phase-c-002", expected_version=0)
        stored = next((swap_root / "receipts").glob("*.json"))
        replacement = root / "phase-c-replacement-receipt"
        replacement.write_bytes(stored.read_bytes())
        stored.unlink()
        stored.symlink_to(replacement)
        with _raises(CustodyError):
            store.audit()
    return _case("custody_tamper_replay_toctou_receipts", [
        {"record_type": "custody_receipt_path", "payload": {"path": receipt_path.name}},
        {"record_type": "custody_symlink_swap", "payload": {"path": stored.name, "is_symlink": stored.is_symlink()}},
    ])


class _raises:
    def __init__(self, expected: type[BaseException]) -> None:
        self.expected = expected

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool:
        if exc_type is None:
            raise AssertionError(f"expected {self.expected.__name__}")
        return issubclass(exc_type, self.expected)


def run_fault_acceptance(workdir: Path) -> dict[str, Any]:
    """Run every Phase C offline fault scenario and return schema-ready evidence."""
    workdir.mkdir(parents=True, exist_ok=True)
    scenarios = [
        _leader_faults(), _final_fence_stale_send_cancel(), _timeout_no_replay(),
        _crash_and_restart(), _delayed_duplicate_callback(), _custody_faults(workdir),
    ]
    for process_case in run_process_faults(workdir / "process-faults"):
        scenarios.append(_case(process_case["case_id"], [
            {"record_type": str(record["event_type"]), "payload": dict(record)}
            for record in process_case["records"]
        ]))
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "issue": 291,
        "phase": "C",
        "execution_mode": "offline_deterministic",
        "production": False,
        "live": False,
        "countable_forward": False,
        "scenarios": scenarios,
    }
