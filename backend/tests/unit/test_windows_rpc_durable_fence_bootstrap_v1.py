from __future__ import annotations

import inspect
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from test_windows_rpc_durable_fence_admission_v1 import (
    FakeServer,
    Recovery,
    attach_a2_like,
)

import scripts.windows_rpc_durable_fence_v1 as durable_module
from scripts.windows_fence_foundation.admission import (
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
)
from scripts.windows_fence_foundation.bootstrap_v1 import (
    bootstrap_windows_rpc_frozen_v1,
)
from scripts.windows_fence_foundation.store import StoreExpectation
from scripts.windows_rpc_deployment_snapshot_v1 import (
    WindowsRpcDeploymentSnapshotError,
)
from scripts.windows_rpc_durable_fence_v1 import (
    WindowsRpcRuntimeConfigV1,
    launch_windows_rpc_durable_fence_v1,
)


@dataclass
class Calls:
    values: list[str]


class SyncEventEngine:
    def __init__(self) -> None:
        self.handlers: dict[str, list[Any]] = {}

    def register(self, event_type: str, handler: Any) -> None:
        self.handlers.setdefault(event_type, []).append(handler)

    def put(self, event: Any) -> None:
        for handler in tuple(self.handlers.get(event.type, ())):
            handler(event)


class FactSource:
    def __init__(self) -> None:
        self.engines = {"log": None, "oms": None}
        self.apps = {"RpcService": None}

    def get_all_accounts(self) -> list[Any]:
        return [{"accountid": "sim-account", "gateway_name": "CTP"}]

    def get_all_orders(self) -> list[Any]:
        return []

    def get_all_active_orders(self) -> list[Any]:
        return []

    def get_all_trades(self) -> list[Any]:
        return []

    def get_all_positions(self) -> list[Any]:
        return []


def test_bootstrap_validates_store_before_build_connect_and_listen() -> None:
    calls = Calls([])
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))

    def recover(root: Any, *, expected: Any, fs: Any = None) -> Recovery:
        assert (root, expected, fs) == ("store-root", "expected-store", "secure-fs")
        calls.values.append("recover")
        return Recovery()

    def build() -> Any:
        calls.values.append("build")
        return runtime

    def attach(runtime_arg: Any, admission: Any) -> object:
        calls.values.append("attach")
        return attach_a2_like(runtime_arg, admission)

    def connect(runtime_arg: Any) -> None:
        assert runtime_arg is runtime
        calls.values.append("connect")
        assert server.send_calls == server.cancel_calls == 0

    def listen(runtime_arg: Any) -> bool:
        assert runtime_arg is runtime
        calls.values.append("listen")
        server._active = True
        return True

    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=recover,
        build_runtime=build,
        attach_snapshot=attach,
        connect_runtime=connect,
        listen_runtime=listen,
        filesystem="secure-fs",
    )

    assert calls.values == ["recover", "build", "attach", "connect", "listen"]
    assert assembly.runtime is runtime
    assert server.send_calls == server.cancel_calls == 0


def test_public_bootstrap_default_attaches_the_exact_reviewed_a2_extension() -> None:
    server = FakeServer()
    event_engine = SyncEventEngine()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=event_engine,
        fact_source=FactSource(),
        snapshot_kwargs={
            "event_factory": lambda event_type, data: SimpleNamespace(
                type=event_type, data=data
            )
        },
    )

    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=lambda *_args, **_kwargs: Recovery(),
        build_runtime=lambda: runtime,
        connect_runtime=lambda _runtime: None,
        listen_runtime=lambda _runtime: True,
    )

    assert server._functions["get_deployment_safety_snapshot_v1"] is (
        assembly.snapshot_extension.rpc_callable
    )
    assert server._functions["recheck_deployment_safety_snapshot_v1"] is (
        assembly.snapshot_extension.recheck_rpc_callable
    )
    assert assembly.snapshot_extension.durable_fence_binding == {
        "schema_version": "windows_rpc_durable_fence_state_v1",
        "state_id": f"windows-fence-state-{'a' * 64}",
        "store_id": f"windows-fence-store-{'a' * 64}",
        "install_attempt_id": f"windows-fence-install-{'a' * 64}",
        "fence_epoch": 1,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "state_raw_sha256": "a" * 64,
        "inventory_sha256": "a" * 64,
        "handler_identities": {
            "send_order": "vnpy.issue267.windows-fence.final-admission.send-order.v1",
            "cancel_order": "vnpy.issue267.windows-fence.final-admission.cancel-order.v1",
        },
    }
    assert len(assembly.snapshot_extension.durable_fence_binding_sha256) == 64
    with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN_NONE|frozen"):
        server._functions["send_order"](object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0


def test_a2_capture_rejects_final_registry_splice_after_assembly() -> None:
    server = FakeServer()
    event_engine = SyncEventEngine()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=event_engine,
        fact_source=FactSource(),
        snapshot_kwargs={
            "event_factory": lambda event_type, data: SimpleNamespace(
                type=event_type, data=data
            )
        },
    )
    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=lambda *_args, **_kwargs: Recovery(),
        build_runtime=lambda: runtime,
        connect_runtime=lambda _runtime: None,
        listen_runtime=lambda _runtime: True,
    )

    spliced = dict(server._functions)
    spliced["send_order"] = server.original_send
    server._functions = spliced
    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="durable admission"):
        assembly.snapshot_extension.get_deployment_safety_snapshot_v1(
            "request-durable-binding-0001",
            "challenge-durable-binding-0001",
        )


def test_a2_capture_rejects_wrong_bound_method_on_admission_object() -> None:
    server = FakeServer()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=SyncEventEngine(),
        fact_source=FactSource(),
        snapshot_kwargs={
            "event_factory": lambda event_type, data: SimpleNamespace(
                type=event_type, data=data
            )
        },
    )
    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=lambda *_args, **_kwargs: Recovery(),
        build_runtime=lambda: runtime,
        connect_runtime=lambda _runtime: None,
        listen_runtime=lambda _runtime: True,
    )
    spliced = dict(server._functions)
    spliced["send_order"] = assembly.admission.frozen_snapshot
    server._functions = spliced

    with pytest.raises(WindowsRpcDeploymentSnapshotError, match="durable admission"):
        assembly.snapshot_extension.get_deployment_safety_snapshot_v1(
            "request-wrong-bound-method-0001",
            "challenge-wrong-bound-method-0001",
        )


def test_a2_rpc_closures_cannot_be_spliced_through_public_extension() -> None:
    server = FakeServer()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=SyncEventEngine(),
        fact_source=FactSource(),
        snapshot_kwargs={
            "event_factory": lambda event_type, data: SimpleNamespace(
                type=event_type, data=data
            )
        },
    )
    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=lambda *_args, **_kwargs: Recovery(),
        build_runtime=lambda: runtime,
        connect_runtime=lambda _runtime: None,
        listen_runtime=lambda _runtime: True,
    )
    extension = assembly.snapshot_extension
    extension.get_deployment_safety_snapshot_v1 = lambda *_args: {"forged": True}
    extension.recheck_deployment_safety_snapshot_v1 = lambda *_args: {"forged": True}

    snapshot = server._functions["get_deployment_safety_snapshot_v1"](
        "request-method-splice-0001",
        "challenge-method-splice-0001",
    )
    assert snapshot["schema_version"] == "windows_rpc_deployment_safety_snapshot_v1"
    assert "forged" not in snapshot
    recheck = server._functions["recheck_deployment_safety_snapshot_v1"](
        "request-method-splice-0001",
        "challenge-method-splice-0001",
        "recheck-method-splice-0001",
        "fresh-method-splice-0001",
        snapshot["fact_generation"],
    )
    assert recheck["schema_version"] == "windows_rpc_deployment_safety_recheck_v1"
    assert "forged" not in recheck


def test_mutating_a2_downstream_references_cannot_bypass_final_admission() -> None:
    server = FakeServer()
    event_engine = SyncEventEngine()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=event_engine,
        fact_source=FactSource(),
        snapshot_kwargs={
            "event_factory": lambda event_type, data: SimpleNamespace(
                type=event_type, data=data
            )
        },
    )
    assembly = bootstrap_windows_rpc_frozen_v1(
        store_root="store-root",
        store_expectation="expected-store",
        recover_store=lambda *_args, **_kwargs: Recovery(),
        build_runtime=lambda: runtime,
        connect_runtime=lambda _runtime: None,
        listen_runtime=lambda _runtime: True,
    )

    assembly.snapshot_extension._original_send_order = server.original_send
    assembly.snapshot_extension._original_cancel_order = server.original_cancel
    assembly.assert_ready_to_listen()

    for name in ("send_order", "cancel_order"):
        assert getattr(server._functions[name], "__self__", None) is assembly.admission
        with pytest.raises(WindowsRpcDurableFenceDenied):
            server._functions[name](object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0


@pytest.mark.parametrize(
    "recovery",
    [
        Recovery(ready=False, state=None, raw_sha256=None, reason="missing"),
        Recovery(raw_sha256="bad"),
    ],
)
def test_invalid_store_stops_before_runtime_construction(recovery: Recovery) -> None:
    calls: list[str] = []

    def recover(_root: Any, *, expected: Any, fs: Any = None) -> Recovery:
        del expected, fs
        calls.append("recover")
        return recovery

    with pytest.raises(WindowsRpcDurableFenceError):
        bootstrap_windows_rpc_frozen_v1(
            store_root="store-root",
            store_expectation="expected-store",
            recover_store=recover,
            build_runtime=lambda: calls.append("build"),
            attach_snapshot=lambda *_args: calls.append("attach"),
            connect_runtime=lambda _runtime: calls.append("connect"),
            listen_runtime=lambda _runtime: calls.append("listen"),
        )
    assert calls == ["recover"]


def test_attach_failure_stops_before_connect_or_listen() -> None:
    calls: list[str] = []
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))

    with pytest.raises(WindowsRpcDurableFenceError, match="not attached"):
        bootstrap_windows_rpc_frozen_v1(
            store_root="store-root",
            store_expectation="expected-store",
            recover_store=lambda *_args, **_kwargs: Recovery(),
            build_runtime=lambda: runtime,
            attach_snapshot=lambda *_args: None,
            connect_runtime=lambda _runtime: calls.append("connect"),
            listen_runtime=lambda _runtime: calls.append("listen"),
        )
    assert calls == []


def test_registry_drift_after_connect_prevents_listener() -> None:
    calls: list[str] = []
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))

    def connect(_runtime: Any) -> None:
        calls.append("connect")
        server._functions = dict(server._functions)

    with pytest.raises(WindowsRpcDurableFenceError, match="registry object"):
        bootstrap_windows_rpc_frozen_v1(
            store_root="store-root",
            store_expectation="expected-store",
            recover_store=lambda *_args, **_kwargs: Recovery(),
            build_runtime=lambda: runtime,
            attach_snapshot=attach_a2_like,
            connect_runtime=connect,
            listen_runtime=lambda _runtime: calls.append("listen"),
        )
    assert calls == ["connect"]


def test_listener_started_by_connect_is_rejected_before_listen_callback() -> None:
    calls: list[str] = []
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))

    def connect(_runtime: Any) -> None:
        calls.append("connect")
        server._active = True

    with pytest.raises(WindowsRpcDurableFenceError, match="started before"):
        bootstrap_windows_rpc_frozen_v1(
            store_root="store-root",
            store_expectation="expected-store",
            recover_store=lambda *_args, **_kwargs: Recovery(),
            build_runtime=lambda: runtime,
            attach_snapshot=attach_a2_like,
            connect_runtime=connect,
            listen_runtime=lambda _runtime: calls.append("listen"),
        )
    assert calls == ["connect"]


def _expectation() -> StoreExpectation:
    digest = "a" * 64
    return StoreExpectation(
        service_name="VnpyRpcService",
        store_id=f"windows-fence-store-{digest}",
        store_path_sha256=digest,
        store_volume_serial="ABCDEF12",
        store_volume_identity_sha256=digest,
        owner_sid_sha256=digest,
        directory_acl_sddl_sha256=digest,
        state_acl_sddl_sha256=digest,
    )


def _runtime_config() -> WindowsRpcRuntimeConfigV1:
    return WindowsRpcRuntimeConfigV1(
        gateway_setting={"用户名": "redacted-test", "密码": "redacted-test"}
    )


def test_production_launcher_has_no_recovery_a2_or_filesystem_injection() -> None:
    parameters = inspect.signature(launch_windows_rpc_durable_fence_v1).parameters

    assert set(parameters) == {
        "store_root",
        "store_expectation",
        "runtime_config",
    }


@pytest.mark.skipif(os.name == "nt", reason="non-Windows platform guard")
def test_production_launcher_rejects_non_windows_before_build() -> None:
    with pytest.raises(OSError, match="native Windows"):
        launch_windows_rpc_durable_fence_v1(
            store_root="missing",
            store_expectation=_expectation(),
            runtime_config=_runtime_config(),
        )


def test_production_launcher_invalid_store_stops_before_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class MissingFilesystem:
        def list_directory(self, _path: Path) -> Any:
            raise FileNotFoundError

    monkeypatch.setattr(
        "scripts.windows_rpc_durable_fence_v1._production_windows_filesystem",
        MissingFilesystem,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        "scripts.windows_rpc_durable_fence_v1._build_fixed_vnpy_runtime",
        lambda _config: calls.append("build"),
    )

    with pytest.raises(WindowsRpcDurableFenceError, match="not ready"):
        launch_windows_rpc_durable_fence_v1(
            store_root=tmp_path / "missing",
            store_expectation=_expectation(),
            runtime_config=_runtime_config(),
        )

    assert calls == []


def test_runtime_config_is_immutable_canonical_and_listener_scoped() -> None:
    source = {"用户名": "test-user", "密码": "test-password"}
    config = WindowsRpcRuntimeConfigV1(gateway_setting=source)
    digest = config.canonical_sha256()
    source["用户名"] = "changed"

    assert config.gateway_setting["用户名"] == "test-user"
    assert len(digest) == 64
    assert config.canonical_sha256() == digest
    with pytest.raises(TypeError):
        config.gateway_setting["用户名"] = "changed"  # type: ignore[index]
    with pytest.raises(ValueError, match="approved local bind"):
        WindowsRpcRuntimeConfigV1(
            gateway_setting={"user": "x"},
            rep_address="tcp://0.0.0.0:2014",
        )


def test_runtime_closure_hash_includes_package_initializer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = durable_module._runtime_closure_hashes()
    original_read = Path.read_bytes

    def changed_initializer(path: Path) -> bytes:
        raw = original_read(path)
        if (
            path.name == "__init__.py"
            and path.parent.name == "windows_fence_foundation"
        ):
            return raw + b"\n# tampered initializer\n"
        return raw

    monkeypatch.setattr(Path, "read_bytes", changed_initializer)
    changed = durable_module._runtime_closure_hashes()

    assert changed["assembly_sha256"] != baseline["assembly_sha256"]
    assert changed["launcher_sha256"] == baseline["launcher_sha256"]
    assert changed["extension_sha256"] == baseline["extension_sha256"]


def test_fixed_listener_uses_server_activity_not_start_return_value() -> None:
    class Server:
        active = False

        def is_active(self) -> bool:
            return self.active

    server = Server()

    class RpcEngine:
        def __init__(self) -> None:
            self.server = server

        def start(self, _rep: str, _pub: str) -> None:
            server.active = True

    runtime = SimpleNamespace(rpc_engine=RpcEngine(), config=_runtime_config())

    assert durable_module._listen_fixed_vnpy_runtime(runtime) is True


def test_production_launcher_uses_only_fixed_runtime_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _runtime_config()
    state = Recovery().state
    assert state is not None
    state.update(
        {
            "config_sha256": config.canonical_sha256(),
            "gateway_name": config.gateway_name,
            **durable_module._runtime_closure_hashes(),
        }
    )
    calls: list[str] = []
    server = FakeServer()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=SyncEventEngine(),
        fact_source=FactSource(),
    )

    monkeypatch.setattr(
        durable_module, "_production_windows_filesystem", lambda: object()
    )
    monkeypatch.setattr(
        durable_module,
        "recover_frozen_none_store",
        lambda *_args, **_kwargs: Recovery(state=state),
    )
    monkeypatch.setattr(
        durable_module,
        "_build_fixed_vnpy_runtime",
        lambda received: (
            calls.append("build") or runtime if received is config else None
        ),
    )
    monkeypatch.setattr(
        durable_module,
        "_connect_fixed_vnpy_runtime",
        lambda received: calls.append("connect") if received is runtime else None,
    )
    monkeypatch.setattr(
        durable_module,
        "_listen_fixed_vnpy_runtime",
        lambda received: (
            calls.append("listen") or True if received is runtime else False
        ),
    )

    assembly = launch_windows_rpc_durable_fence_v1(
        store_root=tmp_path / "store-root",
        store_expectation=_expectation(),
        runtime_config=config,
    )

    assert calls == ["build", "connect", "listen"]
    assert assembly.runtime is runtime
    assert getattr(server._functions["send_order"], "__self__", None) is (
        assembly.admission
    )
    assert assembly.typed_admission is not None
    assert assembly.typed_admission.snapshot()["receipt_intents"] == []
    assert {
        "install_fence_v1",
        "register_receipt_v1",
        "send_order_fenced_v1",
        "cancel_order_fenced_v1",
        "query_intent_v1",
        "get_execution_snapshot_v1",
        "peek_current_facts_v1",
    }.issubset(server._functions)
    final_store_path = tmp_path / "store-root" / "execution-final-admission-v1.json"
    store_before_peek = final_store_path.read_bytes()
    peek = server._functions["peek_current_facts_v1"](
        {"account_scope": config.account_scope, "environment": config.environment}
    )
    assert peek["schema_version"] == "windows_execution_current_facts_v1"
    assert peek["gateway"] == {
        "gateway_name": config.gateway_name,
        "account_scope": config.account_scope,
        "environment": config.environment,
        "connected": True,
    }
    assert peek["admission"]["snapshot_generation"] == 0
    assert peek["admission"]["fence"] == {
        "active": False,
        "current_epoch": 0,
        "current_fencing_token": 0,
        "high_water_epoch": 0,
        "high_water_fencing_token": 0,
    }
    assert final_store_path.read_bytes() == store_before_peek
    with pytest.raises(WindowsRpcDurableFenceDenied):
        server._functions["peek_current_facts_v1"](
            {"account_scope": "account:foreign", "environment": config.environment}
        )
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied):
            server._functions[name](object(), config.gateway_name)
    assert server.send_calls == server.cancel_calls == 0
    execution_snapshot = server._functions["get_execution_snapshot_v1"](
        {"account_scope": config.account_scope, "environment": config.environment}
    )
    assert execution_snapshot["connected"] is True
    assert execution_snapshot["active_order_count"] == 0
    assert execution_snapshot["account_scope"] == config.account_scope
    assert execution_snapshot["environment"] == config.environment
    with pytest.raises(WindowsRpcDurableFenceDenied):
        server._functions["send_order_fenced_v1"](
            {"symbol": "RB"},
            {
                "account_scope": config.account_scope,
                "environment": config.environment,
                "leader_epoch": 1,
                "fencing_token": 1,
                "plan_id": "plan-000001",
                "plan_hash": "a" * 64,
                "intent_id": "intent-000001",
                "idempotency_key": "send-key-0000001",
                "action": "send",
                "receipt_id": "receipt-intent-000001",
                "receipt_hash": "b" * 64,
                "request_hash": "c" * 64,
            },
        )
    assert server.send_calls == server.cancel_calls == 0


def test_windows_typed_attach_fails_when_facts_rpc_registration_is_dropped(
    tmp_path: Path,
) -> None:
    class DropPeekServer(FakeServer):
        def register(self, handler: Any) -> None:
            if handler.__name__ == "peek_current_facts_v1":
                return
            super().register(handler)

    config = _runtime_config()
    server = DropPeekServer()
    runtime = SimpleNamespace(
        config=config,
        rpc_engine=SimpleNamespace(server=server),
        fact_source=FactSource(),
    )

    with pytest.raises(
        WindowsRpcDurableFenceError, match="execution facts RPC registration"
    ):
        durable_module._attach_fixed_typed_fenced_methods(runtime, config, tmp_path)


def test_public_validation_only_attach_freezes_legacy_rpc_and_exposes_pure_peek(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _runtime_config()
    assert set(
        inspect.signature(
            durable_module.attach_windows_rpc_validation_only_v1
        ).parameters
    ) == {"rpc_engine", "event_engine", "main_engine"}
    server = FakeServer()
    rpc_engine = SimpleNamespace(server=server)
    event_engine = SyncEventEngine()
    main_engine = FactSource()
    store_path = tmp_path / "execution-final-admission-v1.json"
    monkeypatch.setattr(
        durable_module, "_validation_durable_store_path_v1", lambda: store_path
    )
    original_send = server._functions["send_order"]
    original_cancel = server._functions["cancel_order"]

    result = durable_module.attach_windows_rpc_validation_only_v1(
        rpc_engine=rpc_engine,
        event_engine=event_engine,
        main_engine=main_engine,
    )

    assert result is None
    assert server._functions["send_order"] is not original_send
    assert server._functions["cancel_order"] is not original_cancel
    assert set(server._functions).isdisjoint(
        {
            "install_fence_v1",
            "register_receipt_v1",
            "send_order_fenced_v1",
            "cancel_order_fenced_v1",
            "query_intent_v1",
            "get_execution_snapshot_v1",
        }
    )
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied):
            server._functions[name](object(), config.gateway_name)
    assert server.send_calls == server.cancel_calls == 0

    store_before_peek = store_path.read_bytes()
    peek = server._functions["peek_current_facts_v1"](
        {"account_scope": config.account_scope, "environment": config.environment}
    )
    assert peek["gateway"]["gateway_name"] == config.gateway_name
    assert peek["gateway"]["account_scope"] == config.account_scope
    assert peek["gateway"]["environment"] == config.environment
    assert peek["admission"]["snapshot_generation"] == 0
    assert store_path.read_bytes() == store_before_peek
    with pytest.raises(WindowsRpcDurableFenceDenied):
        server._functions["peek_current_facts_v1"](
            {"account_scope": "account:foreign", "environment": config.environment}
        )

    frozen_send = server._functions["send_order"]
    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        durable_module.attach_windows_rpc_validation_only_v1(
            rpc_engine=rpc_engine,
            event_engine=event_engine,
            main_engine=main_engine,
        )
    assert server._functions["send_order"] is frozen_send
    assert server.send_calls == server.cancel_calls == 0


def test_public_reconciliation_only_attach_exposes_only_fixed_readers_and_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _runtime_config()
    assert set(
        inspect.signature(
            durable_module.attach_windows_rpc_reconciliation_only_v1
        ).parameters
    ) == {"rpc_engine", "event_engine", "main_engine"}
    store_path = tmp_path / "execution-final-admission-v1.json"
    monkeypatch.setattr(
        durable_module, "_validation_durable_store_path_v1", lambda: store_path
    )
    server = FakeServer()
    rpc_engine = SimpleNamespace(server=server)
    event_engine = SyncEventEngine()
    main_engine = FactSource()

    assert (
        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=rpc_engine,
            event_engine=event_engine,
            main_engine=main_engine,
        )
        is None
    )
    assert set(server._functions) == {
        "send_order",
        "cancel_order",
        "peek_current_facts_v1",
        "get_execution_snapshot_v1",
    }
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), config.gateway_name)
    assert server.send_calls == server.cancel_calls == 0

    request = {
        "account_scope": config.account_scope,
        "environment": config.environment,
    }
    store_before_peek = store_path.read_bytes()
    peek = server._functions["peek_current_facts_v1"](request)
    assert peek["admission"]["snapshot_generation"] == 0
    assert store_path.read_bytes() == store_before_peek
    first = server._functions["get_execution_snapshot_v1"](request)
    second = server._functions["get_execution_snapshot_v1"](request)
    assert (first["generation"], second["generation"]) == (1, 2)
    assert store_path.read_bytes() != store_before_peek
    with pytest.raises(WindowsRpcDurableFenceDenied, match="scope is foreign"):
        server._functions["get_execution_snapshot_v1"](
            {"account_scope": "account:foreign", "environment": config.environment}
        )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows RpcServer")
def test_windows_reconciliation_only_attach_uses_native_rpc_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vnpy.rpc import RpcServer

    calls: list[str] = []

    def send_order(*_args: Any, **_kwargs: Any) -> None:
        calls.append("send")

    def cancel_order(*_args: Any, **_kwargs: Any) -> None:
        calls.append("cancel")

    store_path = tmp_path / "execution-final-admission-v1.json"
    monkeypatch.setattr(
        durable_module, "_validation_durable_store_path_v1", lambda: store_path
    )
    server = RpcServer()
    try:
        server.register(send_order)
        server.register(cancel_order)
        assert not server.is_active()

        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

        assert not server.is_active()
        assert set(server._functions) == {
            "send_order",
            "cancel_order",
            "peek_current_facts_v1",
            "get_execution_snapshot_v1",
        }
        for name in ("send_order", "cancel_order"):
            with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
                server._functions[name](object(), "CTP")
        assert calls == []

        request = {"account_scope": "account:windows", "environment": "simnow"}
        first = server._functions["get_execution_snapshot_v1"](request)
        second = server._functions["get_execution_snapshot_v1"](request)
        assert (first["generation"], second["generation"]) == (1, 2)
    finally:
        server._socket_rep.close(linger=0)
        server._socket_pub.close(linger=0)
        server._context.destroy(linger=0)


@pytest.mark.parametrize(
    ("first_name", "second_name"),
    [
        ("validation_only", "reconciliation_only"),
        ("reconciliation_only", "validation_only"),
    ],
)
def test_validation_and_reconciliation_attaches_are_mutually_exclusive(
    first_name: str,
    second_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )
    server = FakeServer()
    rpc_engine = SimpleNamespace(server=server)
    attaches = {
        "validation_only": durable_module.attach_windows_rpc_validation_only_v1,
        "reconciliation_only": durable_module.attach_windows_rpc_reconciliation_only_v1,
    }
    attaches[first_name](
        rpc_engine=rpc_engine,
        event_engine=SyncEventEngine(),
        main_engine=FactSource(),
    )
    functions_before = dict(server._functions)
    frozen_handlers = {
        name: server._functions[name] for name in ("send_order", "cancel_order")
    }

    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        attaches[second_name](
            rpc_engine=rpc_engine,
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

    assert server._functions == functions_before
    for name, handler in frozen_handlers.items():
        assert server._functions[name] is handler
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            handler(object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0


def test_reconciliation_only_attach_rejects_started_or_reused_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )
    server = FakeServer()
    server._active = True
    with pytest.raises(WindowsRpcDurableFenceError, match="before rpc_engine.start"):
        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

    server._active = False
    durable_module.attach_windows_rpc_reconciliation_only_v1(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=SyncEventEngine(),
        main_engine=FactSource(),
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )


def test_reconciliation_only_attach_failure_leaves_only_frozen_legacy_denials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )

    def fail_after_registration(runtime: Any, *_args: Any, **_kwargs: Any) -> None:
        runtime.rpc_engine.server._functions["get_execution_snapshot_v1"] = lambda: None
        raise WindowsRpcDurableFenceError(
            "injected reconciliation attach failure", code="RPC_REGISTRY_UNAVAILABLE"
        )

    monkeypatch.setattr(
        durable_module, "_attach_fixed_typed_fenced_methods", fail_after_registration
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="injected reconciliation"):
        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

    assert set(server._functions) == {"send_order", "cancel_order"}
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), "CTP")
    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        durable_module.attach_windows_rpc_reconciliation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )


def test_public_validation_attach_cleans_all_registered_transient_rpc_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )

    def fail_after_registration(runtime: Any, *_args: Any, **_kwargs: Any) -> None:
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS:
            runtime.rpc_engine.server._functions[name] = lambda: None
        raise WindowsRpcDurableFenceError(
            "injected validation attach failure", code="RPC_REGISTRY_UNAVAILABLE"
        )

    monkeypatch.setattr(
        durable_module, "_attach_fixed_typed_fenced_methods", fail_after_registration
    )

    with pytest.raises(WindowsRpcDurableFenceError, match="injected validation"):
        durable_module.attach_windows_rpc_validation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

    assert set(server._functions).isdisjoint(
        durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0


def test_public_validation_attach_failure_clears_transient_rpc_and_keeps_denials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DropPeekServer(FakeServer):
        def register(self, handler: Any) -> None:
            if handler.__name__ == "peek_current_facts_v1":
                return
            super().register(handler)

    store_path = tmp_path / "execution-final-admission-v1.json"
    monkeypatch.setattr(
        durable_module, "_validation_durable_store_path_v1", lambda: store_path
    )
    server = DropPeekServer()

    with pytest.raises(
        WindowsRpcDurableFenceError, match="execution facts RPC registration"
    ):
        durable_module.attach_windows_rpc_validation_only_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=SyncEventEngine(),
            main_engine=FactSource(),
        )

    assert set(server._functions).isdisjoint(
        durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0


@pytest.mark.parametrize(
    ("method", "row"),
    [
        ("get_all_accounts", {"accountid": "sim-account"}),
        ("get_all_positions", {"symbol": "RB2610"}),
        ("get_all_orders", {"vt_orderid": "CTP.1"}),
        ("get_all_active_orders", {"vt_orderid": "CTP.2"}),
        ("get_all_accounts", {"accountid": "sim-account", "gateway_name": "FOREIGN"}),
        ("get_all_positions", {"symbol": "RB2610", "gateway_name": "FOREIGN"}),
        ("get_all_orders", {"vt_orderid": "CTP.1", "gateway_name": "FOREIGN"}),
        (
            "get_all_active_orders",
            {"vt_orderid": "CTP.2", "gateway_name": "FOREIGN"},
        ),
    ],
)
def test_validation_peek_rejects_missing_or_foreign_oms_gateway(
    method: str,
    row: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store_path = tmp_path / "execution-final-admission-v1.json"
    monkeypatch.setattr(
        durable_module, "_validation_durable_store_path_v1", lambda: store_path
    )
    main_engine = FactSource()
    setattr(main_engine, method, lambda: [row])
    server = FakeServer()
    durable_module.attach_windows_rpc_validation_only_v1(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=SyncEventEngine(),
        main_engine=main_engine,
    )

    with pytest.raises(WindowsRpcDurableFenceDenied, match="foreign or missing"):
        server._functions["peek_current_facts_v1"](
            {"account_scope": "account:windows", "environment": "simnow"}
        )


def test_windows_execution_facts_gateway_validation_is_opt_in(tmp_path: Path) -> None:
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
    )

    config = _runtime_config()
    runtime = SimpleNamespace(config=config, fact_source=FactSource())
    admission = WindowsRpcFencedAdmissionV1.bootstrap(
        store_path=str(tmp_path / "execution-final-admission-v1.json"),
        account_scope=config.account_scope,
        environment=config.environment,
        send_handler=lambda *_args: {"state": "ACKNOWLEDGED"},
        cancel_handler=lambda *_args: {"state": "CANCELLED"},
    )
    request = {
        "account_scope": config.account_scope,
        "environment": config.environment,
    }
    permissive = durable_module._WindowsExecutionFactsV1(runtime)
    permissive.bind_admission(admission)
    assert permissive.peek_current_facts_v1(request)["account"]["sim-account"] == {
        "accountid": "sim-account",
        "gateway_name": "CTP",
    }

    runtime.fact_source.get_all_accounts = lambda: [{"accountid": "sim-account"}]
    assert permissive.peek_current_facts_v1(request)["account"]["sim-account"] == {
        "accountid": "sim-account"
    }
    strict = durable_module._WindowsExecutionFactsV1(
        runtime, require_fixed_gateway=True
    )
    strict.bind_admission(admission)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="foreign or missing"):
        strict.peek_current_facts_v1(request)


def test_windows_execution_query_is_bound_to_current_oms_order_facts() -> None:
    config = _runtime_config()

    class OrderFacts(FactSource):
        def get_all_orders(self) -> list[Any]:
            return [
                {
                    "vt_orderid": "CTP.9001",
                    "orderid": "9001",
                    "symbol": "RB2610",
                    "status": "all_traded",
                    "reference": "intent-000001",
                }
            ]

    runtime = SimpleNamespace(config=config, fact_source=OrderFacts())
    facts = durable_module._WindowsExecutionFactsV1(runtime)
    result = facts.query_intent_v1(
        {
            "account_scope": config.account_scope,
            "environment": config.environment,
            "intent_id": "intent-000001",
            "broker_order_id": None,
        },
        None,
    )
    assert result == {
        "intent_id": "intent-000001",
        "state": "TERMINAL",
        "accepted": True,
        "broker_order_id": "CTP.9001",
        "account_scope": config.account_scope,
        "environment": config.environment,
    }


def test_windows_snapshot_generation_survives_restart_and_is_concurrently_unique(
    tmp_path: Path,
) -> None:
    from scripts.windows_fence_foundation.final_admission_v1 import (
        WindowsRpcFencedAdmissionV1,
    )

    config = _runtime_config()
    store_path = tmp_path / "execution-final-admission-v1.json"
    request = {
        "account_scope": config.account_scope,
        "environment": config.environment,
    }

    def build() -> tuple[Any, Any]:
        runtime = SimpleNamespace(config=config, fact_source=FactSource())
        facts = durable_module._WindowsExecutionFactsV1(runtime)
        admission = WindowsRpcFencedAdmissionV1.bootstrap(
            store_path=str(store_path),
            account_scope=config.account_scope,
            environment=config.environment,
            send_handler=lambda *_: {"state": "ACKNOWLEDGED"},
            cancel_handler=lambda *_: {"state": "CANCELLED"},
            query_handler=facts.query_intent_v1,
        )
        facts.bind_admission(admission)
        return facts, admission

    first, _first_admission = build()
    assert first.get_execution_snapshot_v1(request)["generation"] == 1
    assert first.get_execution_snapshot_v1(request)["generation"] == 2

    restarted, _restarted_admission = build()
    third = restarted.get_execution_snapshot_v1(request)
    assert third["generation"] == 3
    assert third["snapshot_id"].startswith("snapshot-0000000000000003-")

    concurrent_peer, _peer_admission = build()
    with ThreadPoolExecutor(max_workers=8) as pool:
        snapshots = list(
            pool.map(
                lambda index: (restarted, concurrent_peer)[
                    index % 2
                ].get_execution_snapshot_v1(request),
                range(8),
            )
        )
    assert sorted(item["generation"] for item in snapshots) == list(range(4, 12))
    assert len({item["snapshot_id"] for item in snapshots}) == 8


def test_windows_typed_bootstrap_is_lazy_without_vnpy_and_mutation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.windows_fence_foundation.final_admission_v1 import (
        _receipt_digest,
        _request_digest,
    )

    config = _runtime_config()
    server = FakeServer()
    runtime = SimpleNamespace(
        config=config,
        rpc_engine=SimpleNamespace(server=server),
        fact_source=FactSource(),
    )
    for name in tuple(sys.modules):
        if name == "vnpy" or name.startswith("vnpy."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "vnpy", None)

    admission = durable_module._attach_fixed_typed_fenced_methods(
        runtime, config, tmp_path
    )
    admission.install_fence(epoch=1, fencing_token=1)
    request = {
        "symbol": "RB2610",
        "exchange": "SHFE",
        "direction": "LONG",
        "type": "LIMIT",
        "volume": 1,
        "price": 3100,
        "offset": "OPEN",
    }
    context = {
        "account_scope": config.account_scope,
        "environment": config.environment,
        "leader_epoch": 1,
        "fencing_token": 1,
        "plan_id": "plan-000001",
        "plan_hash": "a" * 64,
        "intent_id": "intent-lazy-0001",
        "idempotency_key": "send-key-lazy-000001",
        "action": "send",
        "receipt_id": "receipt-intent-lazy-0001",
        "receipt_hash": "",
        "request_hash": _request_digest(request),
    }
    context["receipt_hash"] = _receipt_digest(context)
    admission.register_receipt(intent_id=context["intent_id"], receipt=context)
    with pytest.raises(
        WindowsRpcDurableFenceError, match="request types are unavailable"
    ):
        admission.send_order_fenced_v1(request, context)
    assert server.send_calls == 0


def test_windows_native_request_adapter_binds_fixed_gateway_and_oms_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from enum import Enum

    from scripts.windows_fence_foundation.final_admission_v1 import (
        _receipt_digest,
        _request_digest,
    )

    class Direction(Enum):
        LONG = "LONG"
        SHORT = "SHORT"

    class Exchange(Enum):
        SHFE = "SHFE"

    class Offset(Enum):
        OPEN = "OPEN"
        NONE = "NONE"

    class OrderType(Enum):
        LIMIT = "LIMIT"

    class OrderRequest:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class CancelRequest:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    vnpy_module = ModuleType("vnpy")
    trader_module = ModuleType("vnpy.trader")
    constant_module = ModuleType("vnpy.trader.constant")
    object_module = ModuleType("vnpy.trader.object")
    constant_module.Direction = Direction
    constant_module.Exchange = Exchange
    constant_module.Offset = Offset
    constant_module.OrderType = OrderType
    object_module.OrderRequest = OrderRequest
    object_module.CancelRequest = CancelRequest
    vnpy_module.trader = trader_module
    trader_module.constant = constant_module
    trader_module.object = object_module
    for name, module in {
        "vnpy": vnpy_module,
        "vnpy.trader": trader_module,
        "vnpy.trader.constant": constant_module,
        "vnpy.trader.object": object_module,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    config = _runtime_config()
    calls: list[tuple[str, Any, str]] = []
    confirm_cancel = [True]

    class NativeFacts(FactSource):
        def __init__(self) -> None:
            super().__init__()
            self.orders: list[dict[str, Any]] = []

        def get_all_orders(self) -> list[Any]:
            return self.orders

        def get_all_active_orders(self) -> list[Any]:
            return [row for row in self.orders if row["status"] == "not_traded"]

    facts = NativeFacts()

    def native_send(request: Any, gateway_name: str) -> str:
        assert isinstance(request, OrderRequest)
        assert gateway_name == config.gateway_name
        calls.append(("send", request, gateway_name))
        if request.symbol == "EMPTY":
            return ""
        facts.orders.append(
            {
                "vt_orderid": "CTP.9001",
                "orderid": "9001",
                "symbol": request.symbol,
                "exchange": request.exchange.name,
                "reference": request.reference,
                "gateway_name": gateway_name,
                "status": "not_traded",
            }
        )
        return "CTP.9001"

    def native_cancel(request: Any, gateway_name: str) -> None:
        assert isinstance(request, CancelRequest)
        assert gateway_name == config.gateway_name
        assert request.orderid == "9001"
        calls.append(("cancel", request, gateway_name))
        if confirm_cancel[0]:
            facts.orders[0]["status"] = "cancelled"

    class NativeServer(FakeServer):
        def __init__(self) -> None:
            super().__init__()
            self._functions["send_order"] = native_send
            self._functions["cancel_order"] = native_cancel

    server = NativeServer()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        fact_source=facts,
    )
    admission = durable_module._attach_fixed_typed_fenced_methods(
        runtime, config, tmp_path
    )
    admission.install_fence(epoch=1, fencing_token=1)

    def bound_context(
        *, action: str, intent_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "account_scope": config.account_scope,
            "environment": config.environment,
            "leader_epoch": 1,
            "fencing_token": 1,
            "plan_id": "plan-000001",
            "plan_hash": "a" * 64,
            "intent_id": intent_id,
            "idempotency_key": f"{action}-key-{intent_id}",
            "action": action,
            "receipt_id": f"receipt-{intent_id}",
            "receipt_hash": "",
            "request_hash": _request_digest(request),
        }
        context["receipt_hash"] = _receipt_digest(context)
        return context

    send_request = {
        "symbol": "RB2610",
        "exchange": "SHFE",
        "direction": "LONG",
        "type": "LIMIT",
        "volume": 1,
        "price": 3100,
        "offset": "OPEN",
    }
    send_context = bound_context(
        action="send", intent_id="intent-send-0001", request=send_request
    )
    admission.register_receipt(
        intent_id=send_context["intent_id"], receipt=send_context
    )
    sent = admission.send_order_fenced_v1(send_request, send_context)
    assert sent["state"] == "SUBMITTED"
    assert sent["broker_order_id"] == "CTP.9001"
    assert calls[0][1].reference == send_context["intent_id"]

    cancel_request = {
        "target_intent_id": send_context["intent_id"],
        "broker_order_id": "CTP.9001",
    }
    cancel_context = bound_context(
        action="cancel", intent_id="intent-cancel-001", request=cancel_request
    )
    admission.register_receipt(
        intent_id=cancel_context["intent_id"], receipt=cancel_context
    )
    cancelled = admission.cancel_order_fenced_v1(cancel_request, cancel_context)
    assert cancelled["state"] == "CANCELLED"
    assert [item[0] for item in calls] == ["send", "cancel"]

    foreign_request = {**send_request, "gateway_name": "FOREIGN"}
    foreign_context = bound_context(
        action="send", intent_id="intent-send-0002", request=foreign_request
    )
    admission.register_receipt(
        intent_id=foreign_context["intent_id"], receipt=foreign_context
    )
    with pytest.raises(WindowsRpcDurableFenceDenied, match="foreign gateway"):
        admission.send_order_fenced_v1(foreign_request, foreign_context)
    assert [item[0] for item in calls] == ["send", "cancel"]

    empty_request = {**send_request, "symbol": "EMPTY"}
    empty_context = bound_context(
        action="send", intent_id="intent-send-0003", request=empty_request
    )
    admission.register_receipt(
        intent_id=empty_context["intent_id"], receipt=empty_context
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="unknown outcome"):
        admission.send_order_fenced_v1(empty_request, empty_context)

    facts.orders[0]["status"] = "not_traded"
    confirm_cancel[0] = False
    unknown_cancel_context = bound_context(
        action="cancel", intent_id="intent-cancel-002", request=cancel_request
    )
    admission.register_receipt(
        intent_id=unknown_cancel_context["intent_id"],
        receipt=unknown_cancel_context,
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="unknown outcome"):
        admission.cancel_order_fenced_v1(cancel_request, unknown_cancel_context)
