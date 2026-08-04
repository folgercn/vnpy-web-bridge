from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.windows_fence_foundation.admission import (
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
    WindowsRpcFinalAdmissionV1,
)
from scripts.windows_fence_foundation.assembly import assemble_windows_rpc_frozen_v1

SHA = "a" * 64


@dataclass
class Recovery:
    ready: bool = True
    state: dict[str, Any] | None = None
    raw_sha256: str | None = SHA
    inventory_sha256: str | None = SHA
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.state is None and self.ready:
            self.state = frozen_state()


def frozen_state() -> dict[str, Any]:
    return {
        "schema_version": "windows_rpc_durable_fence_state_v1",
        "state_id": f"windows-fence-state-{SHA}",
        "store_id": f"windows-fence-store-{SHA}",
        "install_attempt_id": f"windows-fence-install-{SHA}",
        "fence_epoch": 1,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "pending_send_outcomes": 0,
        "active_orders": [],
        "authority": {
            "windows_fence_released": False,
            "authority_restore_allowed": False,
            "consume_authorized": False,
            "reconciliation_authorized": False,
            "deployment_authorized": False,
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "send_order_authorized": False,
            "cancel_order_authorized": False,
            "countable_forward": False,
        },
    }


class FakeServer:
    def __init__(self) -> None:
        self.send_calls = 0
        self.cancel_calls = 0
        self._active = False
        self._functions = {
            "send_order": self.original_send,
            "cancel_order": self.original_cancel,
            "get_all_accounts": list,
        }
        self.registered = self._functions

    def original_send(self, *_args: Any, **_kwargs: Any) -> str:
        self.send_calls += 1
        return "CTP.1"

    def original_cancel(self, *_args: Any, **_kwargs: Any) -> bool:
        self.cancel_calls += 1
        return True

    def register(self, handler: Any) -> None:
        self._functions[handler.__name__] = handler

    def is_active(self) -> bool:
        return self._active


def attach_a2_like(runtime: Any, _admission: Any) -> object:
    server = runtime.rpc_engine.server
    send = server._functions["send_order"]
    cancel = server._functions["cancel_order"]

    def send_order(*args: Any, **kwargs: Any) -> Any:
        return send(*args, **kwargs)

    def cancel_order(*args: Any, **kwargs: Any) -> Any:
        return cancel(*args, **kwargs)

    def get_deployment_safety_snapshot_v1(*_args: Any) -> dict[str, Any]:
        return {"execution_admission_frozen": True}

    def recheck_deployment_safety_snapshot_v1(*_args: Any) -> dict[str, Any]:
        return {"execution_admission_frozen": True}

    server.register(send_order)
    server.register(cancel_order)
    server.register(get_deployment_safety_snapshot_v1)
    server.register(recheck_deployment_safety_snapshot_v1)
    return SimpleNamespace(
        rpc_callable=get_deployment_safety_snapshot_v1,
        recheck_rpc_callable=recheck_deployment_safety_snapshot_v1,
    )


def test_final_send_cancel_always_deny_without_underlying_call() -> None:
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))
    assembly = assemble_windows_rpc_frozen_v1(
        recovery=Recovery(),
        build_runtime=lambda: runtime,
        attach_snapshot=attach_a2_like,
    )

    # Assembly performs one non-forwarding probe of each final handler.
    assert server.send_calls == 0
    assert server.cancel_calls == 0
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied) as raised:
            server._functions[name](object(), "CTP")
        assert raised.value.code == "WINDOWS_FENCE_ACTIVE_TOKEN_REQUIRED"
    assert server.send_calls == 0
    assert server.cancel_calls == 0
    assert assembly.admission.frozen_snapshot()["denied_calls"] == {
        "send_order": 2,
        "cancel_order": 2,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("admission_state", "ACTIVE"),
        ("token_state", "ACTIVE"),
        ("staged_token", {"id": "forbidden"}),
        ("active_token_inventory", [{"id": "forbidden"}]),
        ("pending_send_outcomes", 1),
        ("active_orders", [{"vt_orderid": "CTP.1"}]),
    ],
)
def test_admission_rejects_every_non_foundation_state(field: str, value: Any) -> None:
    state = frozen_state()
    state[field] = value
    with pytest.raises(WindowsRpcDurableFenceError):
        WindowsRpcFinalAdmissionV1(Recovery(state=state))


def test_admission_rejects_missing_store_and_any_authority() -> None:
    with pytest.raises(WindowsRpcDurableFenceError, match="not ready"):
        WindowsRpcFinalAdmissionV1(
            Recovery(ready=False, state=None, raw_sha256=None, reason="missing")
        )

    state = frozen_state()
    state["authority"]["send_order_authorized"] = True
    with pytest.raises(WindowsRpcDurableFenceError, match="authority"):
        WindowsRpcFinalAdmissionV1(Recovery(state=state))


def test_final_registry_is_sealed_and_identity_is_rechecked() -> None:
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))
    assembly = assemble_windows_rpc_frozen_v1(
        recovery=Recovery(),
        build_runtime=lambda: runtime,
        attach_snapshot=attach_a2_like,
    )

    assert server.registered is server._functions

    def harmless() -> None:
        return None

    with pytest.raises(WindowsRpcDurableFenceError, match="sealed"):
        server.register(harmless)

    def send_order() -> None:
        return None

    with pytest.raises(WindowsRpcDurableFenceError, match="sealed"):
        server.register(send_order)

    with pytest.raises(WindowsRpcDurableFenceError, match="sealed"):
        server.registered["cancel_order"] = lambda: None

    with pytest.raises(TypeError):
        server.registered |= {"send_order": lambda: None}

    with pytest.raises(TypeError):
        dict.update(server.registered, {"send_order": lambda: None})

    server._functions = dict(server._functions)
    with pytest.raises(WindowsRpcDurableFenceError, match="registry object"):
        assembly.assert_ready_to_listen()


def test_assembly_rejects_forbidden_authority_rpc_and_early_listener() -> None:
    server = FakeServer()
    server._functions["activate_token"] = lambda: True
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))
    with pytest.raises(WindowsRpcDurableFenceError, match="forbidden RPC"):
        assemble_windows_rpc_frozen_v1(
            recovery=Recovery(),
            build_runtime=lambda: runtime,
            attach_snapshot=attach_a2_like,
        )


def test_assembly_rejects_noop_or_spliced_a2_attachment() -> None:
    server = FakeServer()
    runtime = SimpleNamespace(rpc_engine=SimpleNamespace(server=server))
    with pytest.raises(WindowsRpcDurableFenceError, match="exact snapshot"):
        assemble_windows_rpc_frozen_v1(
            recovery=Recovery(),
            build_runtime=lambda: runtime,
            attach_snapshot=lambda *_args: object(),
        )

    active_server = FakeServer()
    active_server._active = True
    active = SimpleNamespace(rpc_engine=SimpleNamespace(server=active_server))
    with pytest.raises(WindowsRpcDurableFenceError, match="already listening"):
        assemble_windows_rpc_frozen_v1(
            recovery=Recovery(),
            build_runtime=lambda: active,
            attach_snapshot=attach_a2_like,
        )
