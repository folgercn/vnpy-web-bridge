from __future__ import annotations

import os

import pytest
from app.execution import (
    DurableExecutionRepository,
    ExecutionOrchestrator,
    GatewaySnapshot,
    InMemoryExecutionRepository,
    InMemoryGateway,
)
from app.execution.errors import (
    GatewayTimeout,
    GatewayUnavailable,
    MutationRejected,
    RepositoryUnavailableError,
    RestartReconciliationRequired,
    SnapshotRejected,
    UnknownOutcomeError,
)

HASH = "b" * 64


def command(command: str, key: str, version: int, payload: dict) -> dict:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": f"command-{key[-8:]}",
        "idempotency_key": key,
        "correlation_id": f"correlation-{key[-8:]}",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "tester",
            "operator": "tester",
            "role": "admin",
        },
        "command": command,
        "expected": {"state_version": version},
        "payload": payload,
    }


def prepare() -> tuple[
    ExecutionOrchestrator, InMemoryExecutionRepository, InMemoryGateway, object
]:
    repo = InMemoryExecutionRepository()
    gateway = InMemoryGateway()
    service = ExecutionOrchestrator(repo, gateway)
    token = service.acquire_leader("leader-0001")
    service.process_command(
        command(
            "enable",
            "enable-key-0000001",
            repo.state_version,
            {
                "authority_artifact_id": "artifact-1",
                "authority_hash": HASH,
                "expires_at": "2030-01-01T00:00:00Z",
                "reason": "durable unit test",
            },
        )
    )
    service.process_command(
        command(
            "reconcile",
            "reconcile-key-000001",
            repo.state_version,
            {
                "reconciliation_run_id": "run-000001",
                "snapshot_id": "snapshot-default",
                "reason": "fresh snapshot",
            },
        )
    )
    service.process_command(
        command(
            "start",
            "start-key-0000001",
            repo.state_version,
            {
                "plan_id": "plan-000001",
                "plan_hash": HASH,
                "reason": "start durable plan",
            },
        )
    )
    return service, repo, gateway, token


def test_send_intent_is_durable_before_gateway_and_restart_halts() -> None:
    repo = InMemoryExecutionRepository()
    gateway = InMemoryGateway()
    service = ExecutionOrchestrator(repo, gateway)
    token = service.acquire_leader("leader-0001")
    # A failed preflight cannot create an intent or call the gateway.
    with pytest.raises(RestartReconciliationRequired):
        service.send_order(
            {"symbol": "RB"},
            idempotency_key="send-key-0000001",
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    assert gateway.send_calls == []

    service, repo, gateway, token = prepare()
    result = service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-0000002",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )
    assert result["state"] == "ACKNOWLEDGED"
    assert len(gateway.send_calls) == 1
    assert len(repo.snapshot()["send_intents"]) == 1


def test_timeout_is_unknown_and_never_replayed() -> None:
    service, _repo, gateway, token = prepare()
    gateway.fail_send = TimeoutError("rpc timeout")
    with pytest.raises(GatewayTimeout):
        service.send_order(
            {"symbol": "CU", "volume": 1},
            idempotency_key="send-key-0000003",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    assert len(gateway.send_calls) == 1
    assert service.status()["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    with pytest.raises(UnknownOutcomeError):
        service.send_order(
            {"symbol": "AL", "volume": 1},
            idempotency_key="send-key-0000004",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    assert len(gateway.send_calls) == 1


def test_post_gateway_fence_loss_persists_unknown_and_never_acknowledges() -> None:
    service, _repo, gateway, token = prepare()
    original_send = gateway.send_order

    def send_then_release(request, context):
        result = original_send(request, context)
        service.release_leader(token)
        return result

    gateway.send_order = send_then_release
    with pytest.raises(GatewayTimeout, match="local fence changed"):
        service.send_order(
            {"symbol": "RB", "volume": 1},
            idempotency_key="send-key-0000006",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    intent = next(
        value
        for key, value in service.repository.snapshot()["send_intents"].items()
        if not str(key).startswith("key:")
    )
    assert intent["state"] == "UNKNOWN_OUTCOME"
    assert service.status()["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"


def test_cancel_rejected_false_keeps_revoke_halted_until_reconciliation() -> None:
    service, _repo, gateway, _token = prepare()
    token = service.fencer.token
    assert token is not None
    service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-0000007",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )
    gateway.cancel_order = lambda _request, _context: {
        "accepted": False,
        "cancelled": False,
        "state": "REJECTED",
    }
    with pytest.raises(MutationRejected, match="did not reach a terminal state"):
        service.emergency_stop(reason="reject cancellation")
    status = service.status()
    assert status["authority"]["state"] == "REVOKED"
    assert status["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_snapshot_rejects_string_boolean_and_terminal_intent_active_order() -> None:
    service, repo, gateway, token = prepare()
    with pytest.raises(GatewayUnavailable):
        service._coerce_snapshot(
            {
                "snapshot_id": "snapshot-string-bool",
                "generation": 1,
                "connected": "false",
            }
        )

    result = service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-0000008",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )
    intent_id = result["intent_id"]

    def mark_terminal(state):
        intent = state["send_intents"][intent_id]
        intent["state"] = "TERMINAL"
        state["terminal_archive"].append(
            {
                "kind": "intent_terminal",
                "intent_id": intent_id,
                "idempotency_key": intent["idempotency_key"],
                "broker_order_id": intent.get("broker_order_id"),
                "archived_at": "2030-01-01T00:00:00Z",
            }
        )

    repo.mutate(mark_terminal)
    snapshot = GatewaySnapshot(
        snapshot_id="snapshot-terminal-active",
        generation=1,
        connected=True,
        active_order_count=1,
        account_scope="account:default",
        environment="test",
        orders={"order-terminal": {"intent_id": intent_id}},
    )
    with pytest.raises(SnapshotRejected, match="no durable send intent"):
        service._validate_reconcile_snapshot(repo.snapshot(), snapshot)
    assert gateway.send_calls


def test_json_repository_restarts_from_durable_state(tmp_path) -> None:
    from app.execution import DurableExecutionRepository

    path = tmp_path / "state.json"
    first_repo = DurableExecutionRepository(path)
    first = ExecutionOrchestrator(first_repo, InMemoryGateway())
    token = first.acquire_leader("leader-0001")
    assert token.epoch == 1
    second = ExecutionOrchestrator(DurableExecutionRepository(path), InMemoryGateway())
    assert second.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"
    assert second.status()["leader"]["epoch"] == 1


def test_reconcile_rejects_stale_or_disconnected_broker_facts() -> None:
    service, repo, gateway, _token = prepare()
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-stale",
            generation=0,
            connected=True,
            account_scope="account:default",
            environment="test",
        )
    )
    with pytest.raises(SnapshotRejected):
        service.process_command(
            command(
                "reconcile",
                "reconcile-key-000002",
                repo.state_version,
                {
                    "reconciliation_run_id": "run-000002",
                    "snapshot_id": "snapshot-stale",
                    "reason": "reject stale snapshot",
                },
            )
        )
    assert service.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"

    fresh_repo = InMemoryExecutionRepository()
    disconnected_gateway = InMemoryGateway()
    disconnected_gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-disconnected",
            generation=1,
            connected=False,
            account_scope="account:default",
            environment="test",
        )
    )
    disconnected = ExecutionOrchestrator(fresh_repo, disconnected_gateway)
    with pytest.raises(SnapshotRejected):
        disconnected.process_command(
            command(
                "reconcile",
                "reconcile-key-000003",
                fresh_repo.state_version,
                {
                    "reconciliation_run_id": "run-000003",
                    "snapshot_id": "snapshot-disconnected",
                    "reason": "reject disconnected snapshot",
                },
            )
        )
    assert disconnected.status()["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_repository_hash_corruption_fails_closed_and_stop_archives_terminal_state(
    tmp_path,
) -> None:
    import json

    path = tmp_path / "state.json"
    repository = DurableExecutionRepository(path)
    repository.append_audit({"kind": "test"})
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["state_hash"] = "0" * 64
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RepositoryUnavailableError):
        DurableExecutionRepository(path)

    service, repo, gateway, token = prepare()
    service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-0000005",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )
    response = service.process_command(
        command(
            "stop",
            "stop-key-0000001",
            repo.state_version,
            {"reason": "archive terminal state"},
        )
    )
    assert response.result["accepted"] is True
    assert gateway.cancel_calls
    assert repo.snapshot()["terminal_archive"]


def test_same_process_repository_rejects_old_file_replacement(tmp_path) -> None:
    import json

    path = tmp_path / "state.json"
    repository = DurableExecutionRepository(path)
    initial = repository.snapshot()
    repository.append_audit({"kind": "test"})
    assert repository.state_version == 1
    path.write_text(json.dumps(initial), encoding="utf-8")
    with pytest.raises(RepositoryUnavailableError, match="version regressed"):
        repository.snapshot()


def test_windows_final_fence_rejects_old_missing_foreign_and_unknown_without_ack() -> (
    None
):
    import pytest
    from app.execution import MutationContext
    from app.execution.models import sha256_json

    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
        _receipt_digest,
    )

    calls: list[str] = []

    def send(_request, _context):
        calls.append("send")
        return {"accepted": True, "state": "ACKNOWLEDGED", "broker_order_id": "order-1"}

    def cancel(_request, _context):
        calls.append("cancel")
        return {"accepted": True, "state": "CANCELLED", "cancelled": True}

    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        current_epoch=3,
        current_fencing_token=7,
        send_handler=send,
        cancel_handler=cancel,
    )
    context = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash=HASH,
        intent_id="intent-000001",
        idempotency_key="send-key-0000099",
        action="send",
        receipt_id="receipt-intent-000001",
        request_hash=sha256_json({"symbol": "RB"}),
    )
    from dataclasses import replace

    context = replace(context, receipt_hash=_receipt_digest(context.as_dict()))
    admission.register_receipt(intent_id=context.intent_id, receipt=context.as_dict())
    response = admission.send_order_fenced_v1({"symbol": "RB"}, context)
    assert response["admission"] == "ACCEPTED"
    assert response["intent_id"] == context.intent_id
    assert calls == ["send"]

    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied

    for forged in (
        replace(context, leader_epoch=2, fencing_token=6),
        replace(context, account_scope="account:other"),
        replace(context, receipt_id="receipt-intent-foreign"),
    ):
        with pytest.raises(WindowsRpcDurableFenceDenied):
            admission.send_order_fenced_v1({"symbol": "RB"}, forged)
    assert calls == ["send"]
    missing = context.as_dict()
    missing.pop("fencing_token")
    with pytest.raises(WindowsRpcDurableFenceDenied):
        admission.send_order_fenced_v1({"symbol": "RB"}, missing)
    assert calls == ["send"]
    with pytest.raises(WindowsRpcDurableFenceDenied, match="hash binding"):
        admission.send_order_fenced_v1({"symbol": "CU"}, context)
    assert calls == ["send"]

    unknown = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        current_epoch=3,
        current_fencing_token=7,
        send_handler=lambda *_: {"state": "UNKNOWN_OUTCOME"},
        cancel_handler=cancel,
    )
    unknown.register_receipt(intent_id=context.intent_id, receipt=context.as_dict())
    with pytest.raises(Exception, match="unknown outcome"):
        unknown.send_order_fenced_v1({"symbol": "RB"}, context)


def test_windows_final_fence_and_receipts_survive_restart_and_reject_old_token(
    tmp_path,
) -> None:
    from dataclasses import replace

    from app.execution import MutationContext
    from app.execution.models import sha256_json

    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
        _receipt_digest,
    )

    native_calls: list[str] = []

    def send(*_args):
        native_calls.append("send")
        return {"accepted": True, "state": "ACKNOWLEDGED"}

    path = tmp_path / "final-admission.json"
    first = WindowsRpcFencedAdmissionV1.bootstrap(
        store_path=str(path),
        account_scope="account:prod",
        environment="simnow",
        send_handler=send,
        cancel_handler=lambda *_: {"state": "CANCELLED"},
    )
    first.install_fence(epoch=5, fencing_token=5)
    old = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=5,
        fencing_token=5,
        plan_id="plan-000001",
        plan_hash=HASH,
        intent_id="intent-old-0001",
        idempotency_key="send-key-old-00001",
        action="send",
        receipt_id="receipt-intent-old-0001",
        request_hash=sha256_json({"symbol": "RB"}),
    )
    old = replace(old, receipt_hash=_receipt_digest(old.as_dict()))
    first.register_receipt(intent_id=old.intent_id, receipt=old.as_dict())

    second = WindowsRpcFencedAdmissionV1.bootstrap(
        store_path=str(path),
        account_scope="account:prod",
        environment="simnow",
        send_handler=send,
        cancel_handler=lambda *_: {"state": "CANCELLED"},
    )
    assert second.current_epoch == second.current_fencing_token == 0
    assert second.snapshot()["high_water_epoch"] == 5
    assert second.snapshot()["high_water_fencing_token"] == 5
    second.install_fence(epoch=6, fencing_token=6)

    with pytest.raises(WindowsRpcDurableFenceDenied):
        first.send_order_fenced_v1({"symbol": "RB"}, old)
    restarted = WindowsRpcFencedAdmissionV1.bootstrap(
        store_path=str(path),
        account_scope="account:prod",
        environment="simnow",
        send_handler=send,
        cancel_handler=lambda *_: {"state": "CANCELLED"},
    )
    assert restarted.current_epoch == restarted.current_fencing_token == 0
    assert restarted.snapshot()["high_water_epoch"] == 6
    assert restarted.snapshot()["high_water_fencing_token"] == 6
    assert old.intent_id in restarted.snapshot()["receipt_intents"]
    with pytest.raises(WindowsRpcDurableFenceDenied):
        restarted.send_order_fenced_v1({"symbol": "RB"}, old)
    assert native_calls == []


def test_windows_final_store_missing_corrupt_and_rollback_fail_closed(tmp_path) -> None:
    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceError
    from scripts.windows_fence_foundation.final_store_v1 import (
        DurableFinalAdmissionStoreV1,
    )

    path = tmp_path / "final-admission.json"
    with pytest.raises(WindowsRpcDurableFenceError, match="missing"):
        DurableFinalAdmissionStoreV1(
            path, account_scope="account:prod", environment="simnow"
        )
    store = DurableFinalAdmissionStoreV1.bootstrap(
        path, account_scope="account:prod", environment="simnow"
    )
    store.mutate(
        lambda state: state.update({"current_epoch": 5, "current_fencing_token": 5})
    )
    old = path.read_bytes()
    store.mutate(
        lambda state: state.update({"current_epoch": 6, "current_fencing_token": 6})
    )
    path.write_bytes(old)
    with pytest.raises(WindowsRpcDurableFenceError, match="rolled back"):
        store.snapshot()
    with pytest.raises(WindowsRpcDurableFenceError, match="rolled back"):
        DurableFinalAdmissionStoreV1(
            path, account_scope="account:prod", environment="simnow"
        )
    path.write_bytes(b"{corrupt")
    with pytest.raises(WindowsRpcDurableFenceError):
        DurableFinalAdmissionStoreV1.bootstrap(
            path, account_scope="account:prod", environment="simnow"
        )
    missing_ledger = tmp_path / "missing-ledger.json"
    DurableFinalAdmissionStoreV1.bootstrap(
        missing_ledger, account_scope="account:prod", environment="simnow"
    )
    missing_ledger.with_name(f"{missing_ledger.name}.ledger").unlink()
    with pytest.raises(WindowsRpcDurableFenceError, match="ledger is missing"):
        DurableFinalAdmissionStoreV1(
            missing_ledger, account_scope="account:prod", environment="simnow"
        )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file semantics")
def test_windows_final_store_native_create_replace_and_restart(tmp_path) -> None:
    from scripts.windows_fence_foundation.final_store_v1 import (
        DurableFinalAdmissionStoreV1,
    )

    path = tmp_path / "final-admission.json"
    store = DurableFinalAdmissionStoreV1.bootstrap(
        path, account_scope="account:prod", environment="simnow"
    )
    assert path.is_file()
    assert path.with_name(f"{path.name}.ledger").is_file()

    store.mutate(
        lambda state: state.update({"current_epoch": 1, "current_fencing_token": 1})
    )
    restarted = DurableFinalAdmissionStoreV1.bootstrap(
        path, account_scope="account:prod", environment="simnow"
    )
    assert restarted.snapshot()["current_epoch"] == 1
    assert restarted.snapshot()["current_fencing_token"] == 1


def test_windows_receipt_is_create_only_and_cross_epoch_idempotency_is_rejected() -> (
    None
):
    from dataclasses import replace

    from app.execution import MutationContext
    from app.execution.models import sha256_json

    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceDenied
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
        _receipt_digest,
    )

    calls: list[str] = []

    def send(_request, _context):
        calls.append("send")
        return {"accepted": True, "state": "ACKNOWLEDGED"}

    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        current_epoch=3,
        current_fencing_token=7,
        send_handler=send,
        cancel_handler=lambda *_: {"accepted": True, "state": "CANCELLED"},
    )
    context = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash=HASH,
        intent_id="intent-000010",
        idempotency_key="send-key-0000010",
        action="send",
        receipt_id="receipt-intent-000010",
        request_hash=sha256_json({"symbol": "RB"}),
    )
    context = replace(context, receipt_hash=_receipt_digest(context.as_dict()))
    with pytest.raises(WindowsRpcDurableFenceDenied, match="not registered"):
        admission.send_order_fenced_v1({"symbol": "RB"}, context)
    assert calls == []
    admission.register_receipt(intent_id=context.intent_id, receipt=context.as_dict())
    assert (
        admission.send_order_fenced_v1({"symbol": "RB"}, context)["state"]
        == "ACKNOWLEDGED"
    )
    admission.install_fence(epoch=4, fencing_token=8)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="stale"):
        admission.send_order_fenced_v1({"symbol": "RB"}, context)
    next_context = replace(
        context,
        leader_epoch=4,
        fencing_token=8,
        intent_id="intent-000011",
        receipt_id="receipt-intent-000011",
    )
    next_context = replace(
        next_context,
        receipt_hash=_receipt_digest(next_context.as_dict()),
    )
    with pytest.raises(WindowsRpcDurableFenceDenied, match="another intent"):
        admission.register_receipt(
            intent_id=next_context.intent_id,
            receipt=next_context.as_dict(),
        )
    assert calls == ["send"]


def test_rejected_accepted_true_is_protocol_unknown_and_never_acknowledged() -> None:
    from dataclasses import replace

    from app.execution import MutationContext
    from app.execution.models import sha256_json

    from scripts.windows_fence_foundation.admission import WindowsRpcDurableFenceError
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
        _receipt_digest,
    )

    calls: list[str] = []

    def send(_request, _context):
        calls.append("send")
        return {"accepted": True, "state": "REJECTED"}

    admission = WindowsRpcFencedAdmissionV1(
        account_scope="account:prod",
        environment="simnow",
        current_epoch=3,
        current_fencing_token=7,
        send_handler=send,
        cancel_handler=lambda *_: {"accepted": True, "state": "CANCELLED"},
    )
    context = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash=HASH,
        intent_id="intent-000012",
        idempotency_key="send-key-0000012",
        action="send",
        receipt_id="receipt-intent-000012",
        request_hash=sha256_json({"symbol": "RB"}),
    )
    context = replace(context, receipt_hash=_receipt_digest(context.as_dict()))
    admission.register_receipt(intent_id=context.intent_id, receipt=context.as_dict())
    with pytest.raises(WindowsRpcDurableFenceError, match="cannot be accepted"):
        admission.send_order_fenced_v1({"symbol": "RB"}, context)
    assert calls == ["send"]


def test_vnpy_snapshot_rejects_coercion_and_noncanonical_facts() -> None:
    from datetime import datetime, timezone

    from app.execution import VnpyWindowsGateway
    from app.execution.errors import GatewayUnavailable
    from app.execution.models import ZERO_HASH, format_utc

    observed_at = format_utc(datetime.now(timezone.utc))

    class Transport:
        def __init__(self):
            self.value = {
                "snapshot_id": "snapshot-000001",
                "generation": 1,
                "connected": True,
                "active_order_count": 0,
                "position_snapshot_hash": ZERO_HASH,
                "observed_at": observed_at,
                "orders": {},
                "positions": {},
                "account_scope": "account:prod",
                "environment": "simnow",
                "fresh": True,
            }

        def start(self):
            return None

        def stop(self):
            return None

        def call(self, method, _payload, _context=None):
            assert method == "get_execution_snapshot_v1"
            return self.value

    transport = Transport()
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="simnow",
        transport=transport,
    )
    gateway.start()
    assert gateway.snapshot().generation == 1
    for field, value in (
        ("connected", "false"),
        ("generation", True),
        ("active_order_count", "0"),
        ("snapshot_id", 1),
        ("orders", []),
    ):
        transport.value[field] = value
        with pytest.raises(GatewayUnavailable):
            gateway.snapshot()
        transport.value[field] = {
            "connected": True,
            "generation": 1,
            "active_order_count": 0,
            "snapshot_id": "snapshot-000001",
            "orders": {},
        }.get(field, transport.value[field])


def test_vnpy_gateway_uses_only_typed_fenced_methods_and_checks_response_binding() -> (
    None
):
    from dataclasses import replace

    from app.execution import MutationContext, VnpyWindowsGateway
    from app.execution.models import sha256_json

    from scripts.windows_fence_foundation.final_admission_v1 import _receipt_digest

    class Transport:
        def __init__(self):
            self.calls = []

        def start(self):
            return None

        def stop(self):
            return None

        def call(self, method, payload, context=None):
            self.calls.append((method, payload, context))
            if method == "install_fence_v1":
                return {
                    "schema_version": "windows_execution_fenced_mutation_v1",
                    "account_scope": "account:prod",
                    "environment": "simnow",
                    "current_epoch": 3,
                    "current_fencing_token": 7,
                }
            if method == "register_receipt_v1":
                return {
                    "schema_version": "windows_execution_fenced_mutation_v1",
                    "admission": "REGISTERED",
                    "account_scope": "account:prod",
                    "environment": "simnow",
                    "intent_id": "intent-000001",
                    "receipt_id": "receipt-intent-000001",
                    "leader_epoch": 3,
                    "fencing_token": 7,
                }
            return {
                "admission": "ACCEPTED",
                "account_scope": "account:prod",
                "environment": "simnow",
                "leader_epoch": 3,
                "fencing_token": 7,
                "intent_id": "intent-000001",
                "receipt_id": "receipt-intent-000001",
                "receipt_hash": context.receipt_hash,
                "request_hash": context.request_hash,
                "plan_id": context.plan_id,
                "plan_hash": context.plan_hash,
                "idempotency_key": context.idempotency_key,
                "operation": "send",
                "state": "ACKNOWLEDGED",
                "accepted": True,
            }

    context = MutationContext(
        account_scope="account:prod",
        environment="simnow",
        leader_epoch=3,
        fencing_token=7,
        plan_id="plan-000001",
        plan_hash=HASH,
        intent_id="intent-000001",
        idempotency_key="send-key-0000100",
        action="send",
        receipt_id="receipt-intent-000001",
        request_hash=sha256_json({"symbol": "RB"}),
    )
    context = replace(context, receipt_hash=_receipt_digest(context.as_dict()))
    transport = Transport()
    gateway = VnpyWindowsGateway(
        req_address="tcp://127.0.0.1:2014",
        pub_address="tcp://127.0.0.1:4102",
        account_scope="account:prod",
        environment="simnow",
        transport=transport,
    )
    gateway.start()
    result = gateway.send_order({"symbol": "RB"}, context)
    assert result["admission"] == "ACCEPTED"
    assert [call[0] for call in transport.calls] == [
        "install_fence_v1",
        "register_receipt_v1",
        "send_order_fenced_v1",
    ]


def test_unknown_gateway_state_is_persisted_and_blocks_second_send() -> None:
    service, repo, gateway, token = prepare()

    def missing_state(_request, context):
        gateway.send_calls.append((dict(_request), context))
        return {"accepted": True, "broker_order_id": "order-without-state"}

    gateway.send_order = missing_state  # type: ignore[method-assign]
    with pytest.raises(GatewayTimeout):
        service.send_order(
            {"symbol": "RB", "volume": 1},
            idempotency_key="send-key-unknown-01",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    state = repo.snapshot()
    assert state["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    assert next(iter(state["send_intents"].values()))["state"] == "UNKNOWN_OUTCOME"
    with pytest.raises(UnknownOutcomeError):
        service.send_order(
            {"symbol": "CU", "volume": 1},
            idempotency_key="send-key-unknown-02",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    assert len(gateway.send_calls) == 1


def test_reconcile_binds_snapshot_id_and_canonical_position_hash() -> None:
    service, repo, gateway, _token = prepare()
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-mismatch",
            generation=1,
            connected=True,
            account_scope="account:default",
            environment="test",
        )
    )
    with pytest.raises(SnapshotRejected, match="does not match"):
        service.process_command(
            command(
                "reconcile",
                "reconcile-bind-0001",
                repo.state_version,
                {
                    "reconciliation_run_id": "run-bind-0001",
                    "snapshot_id": "snapshot-requested",
                    "reason": "bind exact snapshot",
                },
            )
        )

    positions = {"RB.SHFE": {"long": 1, "short": 0}}
    gateway.snapshots.append(
        GatewaySnapshot(
            snapshot_id="snapshot-position",
            generation=2,
            connected=True,
            positions=positions,
            position_snapshot_hash="c" * 64,
            account_scope="account:default",
            environment="test",
        )
    )
    with pytest.raises(SnapshotRejected, match="canonical hash"):
        service.process_command(
            command(
                "reconcile",
                "reconcile-bind-0002",
                repo.state_version,
                {
                    "reconciliation_run_id": "run-bind-0002",
                    "snapshot_id": "snapshot-position",
                    "reason": "verify position hash",
                },
            )
        )


def test_same_process_rejects_valid_old_file_replacement(tmp_path) -> None:
    path = tmp_path / "state.json"
    repository = DurableExecutionRepository(path)
    repository.append_audit({"kind": "test"})
    old = path.read_bytes()
    repository.append_audit({"kind": "test"})
    path.write_bytes(old)
    with pytest.raises(RepositoryUnavailableError, match="regressed"):
        repository.snapshot()


def test_control_stop_requires_explicit_terminal_cancel_and_closed_snapshot() -> None:
    service, repo, gateway, token = prepare()
    service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-cancel-001",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )

    def ambiguous_cancel(request, context):
        gateway.cancel_calls.append((dict(request), context))
        return {"accepted": True, "cancelled": True, "state": "ACKNOWLEDGED"}

    gateway.cancel_order = ambiguous_cancel  # type: ignore[method-assign]
    with pytest.raises(Exception, match="terminal state"):
        service.process_command(
            command(
                "stop",
                "stop-terminal-0001",
                repo.state_version,
                {
                    "reason": "must prove terminal cancellation",
                },
            )
        )
    state = repo.snapshot()
    assert state["plan"]["state"] == "ACTIVE"
    assert state["lifecycle"] == "HALTED_RECONCILE_REQUIRED"


def test_emergency_stop_only_completes_after_cancel_and_reconcile_closure() -> None:
    service, repo, _gateway, token = prepare()
    service.send_order(
        {"symbol": "RB", "volume": 1},
        idempotency_key="send-key-emergency-1",
        plan_id="plan-000001",
        plan_hash=HASH,
        leader_epoch=token.epoch,
        fencing_token=token.fencing_token,
        token=token,
    )
    status = service.emergency_stop(reason="unit emergency")
    assert status["authority"]["state"] == "REVOKED"
    assert status["plan"]["state"] == "TERMINAL"
    assert status["broker"]["active_order_count"] == 0
    assert status["reconciliation"]["state"] == "RECONCILED"
    assert repo.snapshot()["terminal_archive"]


def test_fence_change_between_preflight_and_gateway_response_stays_unknown() -> None:
    service, repo, gateway, token = prepare()
    original_send = gateway.send_order

    def racing_send(request, context):
        result = original_send(request, context)

        def rotate(state):
            state["lease"]["epoch"] += 1
            state["lease"]["fencing_token"] += 1
            state["lease"]["owner_id"] = "leader-raced"
            state["lease"]["instance_id"] = "instance-raced"

        repo.mutate(rotate)
        return result

    gateway.send_order = racing_send  # type: ignore[method-assign]
    with pytest.raises(GatewayTimeout, match="local fence changed"):
        service.send_order(
            {"symbol": "RB", "volume": 1},
            idempotency_key="send-key-racing-001",
            plan_id="plan-000001",
            plan_hash=HASH,
            leader_epoch=token.epoch,
            fencing_token=token.fencing_token,
            token=token,
        )
    state = repo.snapshot()
    assert state["lifecycle"] == "HALTED_UNKNOWN_OUTCOME"
    assert len(gateway.send_calls) == 1
