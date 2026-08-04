from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
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
        store_root="store-root",
        store_expectation=_expectation(),
        runtime_config=config,
    )

    assert calls == ["build", "connect", "listen"]
    assert assembly.runtime is runtime
    assert getattr(server._functions["send_order"], "__self__", None) is (
        assembly.admission
    )
