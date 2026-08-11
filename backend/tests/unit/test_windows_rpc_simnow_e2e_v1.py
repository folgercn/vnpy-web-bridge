from __future__ import annotations

import inspect
import os
import sys
from enum import Enum
from hashlib import sha256
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from test_windows_rpc_durable_fence_admission_v1 import FakeServer

import scripts.windows_rpc_durable_fence_v1 as durable_module
from scripts.windows_fence_foundation.admission import (
    WindowsRpcDurableFenceDenied,
    WindowsRpcDurableFenceError,
)
from scripts.windows_fence_foundation.final_admission_v1 import (
    _receipt_digest,
    _request_digest,
)

SIM_ACCOUNT = "synthetic-issue291-account"


def _gateway_setting() -> dict[str, Any]:
    return {
        "用户名": SIM_ACCOUNT,
        "密码": "test-only-secret",
        "经纪商代码": "9999",
        "交易服务器": "tcp://182.254.243.31:30001",
        "行情服务器": "tcp://182.254.243.31:30011",
        "产品名称": "test-product",
        "授权编码": "test-auth",
        "柜台环境": "实盘",
    }


class FactSource:
    def __init__(
        self,
        *,
        account_username: str = SIM_ACCOUNT,
        td_userid: str = SIM_ACCOUNT,
        md_userid: str = SIM_ACCOUNT,
        td_login_status: bool = True,
        md_login_status: bool = True,
        extra_account_username: str | None = None,
        orders: list[dict[str, Any]] | None = None,
    ) -> None:
        self.gateway = SimpleNamespace(
            td_api=SimpleNamespace(
                userid=td_userid, connect_status=False, login_status=False
            ),
            md_api=SimpleNamespace(
                userid=md_userid, connect_status=False, login_status=False
            ),
        )
        self._td_login_status = td_login_status
        self._md_login_status = md_login_status
        self.account = {
            "accountid": account_username,
            "vt_accountid": f"CTP.{account_username}",
            "gateway_name": "CTP",
        }
        self.oms = SimpleNamespace(
            accounts={self.account["vt_accountid"]: self.account}
        )
        if extra_account_username is not None:
            extra_account = {
                "accountid": extra_account_username,
                "vt_accountid": f"CTP.{extra_account_username}",
                "gateway_name": "CTP",
            }
            self.oms.accounts[extra_account["vt_accountid"]] = extra_account
        self.orders = orders if orders is not None else []
        self.connect_calls: list[tuple[dict[str, Any], str]] = []

    def connect(self, setting: dict[str, Any], gateway_name: str) -> None:
        self.connect_calls.append((dict(setting), gateway_name))
        self.gateway.td_api.connect_status = True
        self.gateway.md_api.connect_status = True
        self.gateway.td_api.login_status = self._td_login_status
        self.gateway.md_api.login_status = self._md_login_status

    def get_gateway(self, gateway_name: str) -> Any:
        return self.gateway if gateway_name == "CTP" else None

    def get_engine(self, engine_name: str) -> Any:
        return self.oms if engine_name == "oms" else None

    def get_all_accounts(self) -> list[Any]:
        return [self.account]

    def get_all_orders(self) -> list[Any]:
        return self.orders

    def get_all_active_orders(self) -> list[Any]:
        return [
            row
            for row in self.orders
            if row.get("status") not in {"cancelled", "all_traded", "rejected"}
        ]

    def get_all_positions(self) -> list[Any]:
        return []


def _attach(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    server: FakeServer,
    *,
    main_engine: FactSource | None = None,
    gateway_setting: dict[str, Any] | None = None,
    pin_test_account_hash: bool = True,
) -> FactSource:
    monkeypatch.setattr(
        durable_module,
        "_simnow_e2e_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )
    if pin_test_account_hash:
        monkeypatch.setattr(
            durable_module,
            "_ISSUE291_SIMNOW_ACCOUNT_SHA256",
            sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest(),
        )
    engine = main_engine or FactSource()
    if (
        getattr(
            engine.gateway,
            durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE,
            None,
        )
        is None
    ):
        durable_module.connect_windows_rpc_simnow_e2e_v1(
            main_engine=engine,
            gateway_setting=gateway_setting or _gateway_setting(),
        )
    durable_module.attach_windows_rpc_simnow_e2e_v1(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=object(),
        main_engine=engine,
        explicit_e2e_authorized=True,
        production_authorized=False,
        live_trading_authorized=False,
        countable_forward=False,
        max_order_volume=1,
    )
    return engine


def _request(volume: Any = 1) -> dict[str, Any]:
    return {
        "symbol": "RB2610",
        "exchange": "SHFE",
        "direction": "LONG",
        "type": "LIMIT",
        "volume": volume,
        "price": 3100,
        "offset": "OPEN",
    }


def _context(
    request: dict[str, Any],
    *,
    intent_id: str,
    leader_epoch: int = 1,
    fencing_token: int = 1,
    action: str = "send",
) -> dict[str, Any]:
    context = {
        "account_scope": "account:windows",
        "environment": "simnow",
        "leader_epoch": leader_epoch,
        "fencing_token": fencing_token,
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


def _install_fence(
    server: FakeServer, *, leader_epoch: int = 1, fencing_token: int = 1
) -> None:
    server._functions["install_fence_v1"](
        {
            "account_scope": "account:windows",
            "environment": "simnow",
            "leader_epoch": leader_epoch,
            "fencing_token": fencing_token,
        }
    )


def _register(server: FakeServer, context: dict[str, Any]) -> None:
    server._functions["register_receipt_v1"](
        {"intent_id": context["intent_id"], "receipt": context}
    )


def _install_fake_vnpy(monkeypatch: pytest.MonkeyPatch) -> None:
    class Direction(Enum):
        LONG = "LONG"

    class Exchange(Enum):
        SHFE = "SHFE"

    class Offset(Enum):
        NONE = "NONE"
        OPEN = "OPEN"

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


def test_simnow_e2e_attach_has_exact_controlled_signature_and_negative_gates() -> None:
    assert (
        durable_module._ISSUE291_SIMNOW_ACCOUNT_SHA256
        == "9d8809bc4525db5796ac9ec140130371352b92041169e02a6da1e4c31d609559"
    )
    assert set(
        inspect.signature(durable_module.attach_windows_rpc_simnow_e2e_v1).parameters
    ) == {
        "rpc_engine",
        "event_engine",
        "main_engine",
        "explicit_e2e_authorized",
        "production_authorized",
        "live_trading_authorized",
        "countable_forward",
        "max_order_volume",
    }
    baseline = {
        "rpc_engine": None,
        "event_engine": None,
        "main_engine": None,
        "explicit_e2e_authorized": True,
        "production_authorized": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "max_order_volume": 1,
    }
    for field, value in (
        ("explicit_e2e_authorized", 1),
        ("production_authorized", 0),
        ("live_trading_authorized", 0),
        ("countable_forward", 0),
        ("max_order_volume", True),
        ("max_order_volume", 2),
    ):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="authorization"):
            durable_module.attach_windows_rpc_simnow_e2e_v1(
                **{**baseline, field: value}
            )


def test_simnow_e2e_front_allowlist_is_current_and_exact() -> None:
    assert dict(durable_module._ISSUE291_SIMNOW_FRONT_PAIRS) == {
        "182.254.243.31:30001": "182.254.243.31:30011",
        "182.254.243.31:30002": "182.254.243.31:30012",
        "182.254.243.31:30003": "182.254.243.31:30013",
        "182.254.243.31:40001": "182.254.243.31:40011",
    }


def test_simnow_e2e_attach_reads_only_the_actual_ctp_connect_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    engine = FactSource()
    actual_setting = _gateway_setting()
    monkeypatch.setattr(
        durable_module,
        "_ISSUE291_SIMNOW_ACCOUNT_SHA256",
        sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest(),
    )
    durable_module.connect_windows_rpc_simnow_e2e_v1(
        main_engine=engine, gateway_setting=actual_setting
    )
    binding = getattr(
        engine.gateway, durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE
    )
    assert binding is getattr(
        engine.gateway.td_api, durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE
    )
    assert binding is getattr(
        engine.gateway.md_api, durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE
    )
    assert engine.connect_calls == [(actual_setting, "CTP")]
    actual_setting["交易服务器"] = "tcp://180.168.146.187:10201"

    _attach(monkeypatch, tmp_path, server, main_engine=engine)

    assert "send_order_fenced_v1" in server._functions
    assert binding.broker_id == "9999"
    assert binding.environment == "实盘"
    assert binding.trade_front == "tcp://182.254.243.31:30001"


def test_simnow_e2e_attach_rejects_missing_actual_ctp_connect_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    monkeypatch.setattr(
        durable_module,
        "_simnow_e2e_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )

    with pytest.raises(WindowsRpcDurableFenceDenied, match="connect binding"):
        durable_module.attach_windows_rpc_simnow_e2e_v1(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=object(),
            main_engine=FactSource(),
            explicit_e2e_authorized=True,
            production_authorized=False,
            live_trading_authorized=False,
            countable_forward=False,
            max_order_volume=1,
        )

    assert not any(
        name in server._functions
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )


@pytest.mark.parametrize("api_name", ["td_api", "md_api"])
def test_simnow_e2e_connect_rejects_an_already_connected_gateway(
    api_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = FactSource()
    monkeypatch.setattr(
        durable_module,
        "_ISSUE291_SIMNOW_ACCOUNT_SHA256",
        sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest(),
    )
    getattr(engine.gateway, api_name).connect_status = True

    with pytest.raises(WindowsRpcDurableFenceDenied, match="fresh disconnected"):
        durable_module.connect_windows_rpc_simnow_e2e_v1(
            main_engine=engine, gateway_setting=_gateway_setting()
        )

    assert engine.connect_calls == []
    assert (
        getattr(
            engine.gateway,
            durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE,
            None,
        )
        is None
    )


@pytest.mark.parametrize(
    ("trade_front", "market_front"),
    [
        ("182.254.243.31:30001", "182.254.243.31:30011"),
        ("182.254.243.31:30002", "182.254.243.31:30012"),
        ("182.254.243.31:30003", "182.254.243.31:30013"),
        ("182.254.243.31:40001", "182.254.243.31:40011"),
    ],
)
def test_simnow_e2e_connect_accepts_only_current_exact_front_pairs(
    trade_front: str, market_front: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = FactSource()
    monkeypatch.setattr(
        durable_module,
        "_ISSUE291_SIMNOW_ACCOUNT_SHA256",
        sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest(),
    )
    setting = {
        **_gateway_setting(),
        "交易服务器": f"tcp://{trade_front}",
        "行情服务器": f"tcp://{market_front}",
    }

    durable_module.connect_windows_rpc_simnow_e2e_v1(
        main_engine=engine, gateway_setting=setting
    )

    binding = getattr(
        engine.gateway, durable_module._SIMNOW_E2E_CONNECT_BINDING_ATTRIBUTE
    )
    assert (binding.trade_front, binding.market_front) == (
        f"tcp://{trade_front}",
        f"tcp://{market_front}",
    )
    assert engine.connect_calls == [(setting, "CTP")]


def test_simnow_e2e_runbook_keeps_active_profile_and_m2_negative_gates() -> None:
    runbook = (
        Path(__file__).resolve().parents[3]
        / "docs/operations/windows-rpc-simnow-e2e-controlled-mutation-attach-v1.md"
    ).read_text(encoding="utf-8")

    for required in (
        "-PolicyStore ActiveStore",
        "-PolicyStore RSOP",
        "DefaultInboundAction -ne 'Block'",
        "DisabledInterfaceAliases",
        "182.254.243.31:30001",
        "182.254.243.31:30011",
        "182.254.243.31:30002",
        "182.254.243.31:30012",
        "182.254.243.31:30003",
        "182.254.243.31:30013",
        "182.254.243.31:40001",
        "182.254.243.31:40011",
        "## M2-only negative gate",
        "M2 non-member negative gate: PASS",
    ):
        assert required in runbook


@pytest.mark.parametrize(
    ("setting_update", "engine", "connect_rejected"),
    [
        ({"交易服务器": "tcp://180.168.146.187:10201"}, FactSource(), True),
        ({"行情服务器": "tcp://180.168.146.187:10211"}, FactSource(), True),
        ({"行情服务器": "tcp://182.254.243.31:30012"}, FactSource(), True),
        ({"经纪商代码": "0000"}, FactSource(), True),
        ({"柜台环境": "测试"}, FactSource(), True),
        ({}, FactSource(account_username="foreign-account"), False),
        ({}, FactSource(extra_account_username="second-account"), False),
        ({}, FactSource(td_login_status=False), False),
        ({}, FactSource(md_userid="foreign-account"), False),
    ],
)
def test_simnow_e2e_attach_rejects_front_account_or_login_mismatch_before_typed_rpc(
    setting_update: dict[str, Any],
    engine: FactSource,
    connect_rejected: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FakeServer()
    setting = {**_gateway_setting(), **setting_update}

    with pytest.raises(WindowsRpcDurableFenceDenied):
        _attach(
            monkeypatch,
            tmp_path,
            server,
            main_engine=engine,
            gateway_setting=setting,
        )

    assert not any(
        name in server._functions
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )
    assert server.send_calls == server.cancel_calls == 0
    if connect_rejected:
        assert engine.connect_calls == []
    else:
        for name in ("send_order", "cancel_order"):
            with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
                server._functions[name](object(), "CTP")


def test_simnow_e2e_attach_uses_only_module_pinned_account_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()

    with pytest.raises(WindowsRpcDurableFenceDenied, match="pinned Issue 291"):
        _attach(
            monkeypatch,
            tmp_path,
            server,
            pin_test_account_hash=False,
        )

    assert not any(
        name in server._functions
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )
    assert server.send_calls == server.cancel_calls == 0


def test_simnow_e2e_raw_id_hash_pin_accepts_only_synthetic_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        durable_module,
        "_ISSUE291_SIMNOW_ACCOUNT_SHA256",
        sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest(),
    )
    server = FakeServer()

    _attach(
        monkeypatch,
        tmp_path,
        server,
        pin_test_account_hash=False,
    )

    assert "send_order_fenced_v1" in server._functions
    assert server.send_calls == server.cancel_calls == 0


def test_simnow_e2e_sorted_account_key_list_json_hash_cannot_pass_raw_id_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_id_hash = sha256(SIM_ACCOUNT.encode("utf-8")).hexdigest()
    list_json_hash = sha256(
        durable_module.canonical_json_bytes(sorted([SIM_ACCOUNT]))
    ).hexdigest()
    assert list_json_hash != raw_id_hash
    monkeypatch.setattr(
        durable_module, "_ISSUE291_SIMNOW_ACCOUNT_SHA256", list_json_hash
    )
    server = FakeServer()

    with pytest.raises(WindowsRpcDurableFenceDenied, match="pinned Issue 291"):
        _attach(
            monkeypatch,
            tmp_path,
            server,
            pin_test_account_hash=False,
        )

    assert not any(
        name in server._functions
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS
    )
    assert server.send_calls == server.cancel_calls == 0


def test_simnow_e2e_attach_has_only_fixed_methods_and_frozen_legacy_denials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    _attach(monkeypatch, tmp_path, server)

    assert set(server._functions) == {
        "send_order",
        "cancel_order",
        "install_fence_v1",
        "register_receipt_v1",
        "send_order_fenced_v1",
        "cancel_order_fenced_v1",
        "query_intent_v1",
        "get_execution_snapshot_v1",
        "peek_current_facts_v1",
    }
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), "CTP")
    assert server.send_calls == server.cancel_calls == 0

    server._active = True
    with pytest.raises(WindowsRpcDurableFenceError, match="before rpc_engine.start"):
        _attach(monkeypatch, tmp_path, server)
    server._active = False
    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        _attach(monkeypatch, tmp_path, server)


def test_simnow_e2e_attach_requires_fence_and_receipt_before_one_lot_native_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_vnpy(monkeypatch)
    server = FakeServer()
    _attach(monkeypatch, tmp_path, server)
    request = _request()
    context = _context(request, intent_id="intent-send-0001")

    with pytest.raises(WindowsRpcDurableFenceDenied):
        server._functions["send_order_fenced_v1"](request, context)
    assert server.send_calls == 0

    _install_fence(server)
    with pytest.raises(
        WindowsRpcDurableFenceDenied, match="receipt was not registered"
    ):
        server._functions["send_order_fenced_v1"](request, context)
    assert server.send_calls == 0

    _register(server, context)
    sent = server._functions["send_order_fenced_v1"](request, context)
    assert sent["state"] == "SUBMITTED"
    assert sent["broker_order_id"] == "CTP.1"
    assert server.send_calls == 1


@pytest.mark.parametrize("volume", [2, 0, -1, True, 1.0, 0.5, "1", None])
def test_simnow_e2e_send_volume_is_fail_closed_before_native_handler(
    volume: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_vnpy(monkeypatch)
    server = FakeServer()
    _attach(monkeypatch, tmp_path, server)
    _install_fence(server)
    request = _request(volume)
    context = _context(
        request, intent_id=f"intent-volume-{str(volume).replace('-', 'n')}"
    )
    _register(server, context)

    with pytest.raises(WindowsRpcDurableFenceDenied):
        server._functions["send_order_fenced_v1"](request, context)
    assert server.send_calls == 0


def test_simnow_e2e_rejects_foreign_scope_receipt_and_fence_before_native_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_vnpy(monkeypatch)
    server = FakeServer()
    _attach(monkeypatch, tmp_path, server)
    request = _request()
    context = _context(request, intent_id="intent-scope-0001")

    with pytest.raises(WindowsRpcDurableFenceDenied, match="scope is foreign"):
        server._functions["install_fence_v1"](
            {
                "account_scope": "account:foreign",
                "environment": "simnow",
                "leader_epoch": 1,
                "fencing_token": 1,
            }
        )
    _install_fence(server)
    foreign_receipt = {**context, "environment": "paper"}
    foreign_receipt["receipt_hash"] = _receipt_digest(foreign_receipt)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="scope is foreign"):
        _register(server, foreign_receipt)
    _register(server, context)

    foreign_scope = {**context, "account_scope": "account:foreign"}
    with pytest.raises(WindowsRpcDurableFenceDenied, match="scope is foreign"):
        server._functions["send_order_fenced_v1"](request, foreign_scope)
    stale_fence = {**context, "fencing_token": 2}
    with pytest.raises(WindowsRpcDurableFenceDenied, match="stale"):
        server._functions["send_order_fenced_v1"](request, stale_fence)
    foreign_receipt_context = {**context, "receipt_id": "receipt-foreign-0001"}
    with pytest.raises(WindowsRpcDurableFenceDenied, match="receipt binding"):
        server._functions["send_order_fenced_v1"](request, foreign_receipt_context)
    assert server.send_calls == 0


def test_simnow_e2e_failure_cleans_typed_methods_and_preserves_frozen_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    monkeypatch.setattr(
        durable_module,
        "_simnow_e2e_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )

    def fail_after_registration(runtime: Any, *_args: Any, **_kwargs: Any) -> None:
        for name in durable_module._VALIDATION_TRANSIENT_RPC_METHODS:
            runtime.rpc_engine.server._functions[name] = lambda: None
        raise WindowsRpcDurableFenceError(
            "injected E2E attach failure", code="RPC_REGISTRY_UNAVAILABLE"
        )

    monkeypatch.setattr(
        durable_module, "_attach_fixed_typed_fenced_methods", fail_after_registration
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="injected E2E"):
        _attach(monkeypatch, tmp_path, server)

    assert set(server._functions) == {"send_order", "cancel_order"}
    for name in ("send_order", "cancel_order"):
        with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
            server._functions[name](object(), "CTP")


@pytest.mark.parametrize(
    "attach_name",
    [
        "attach_windows_rpc_validation_only_v1",
        "attach_windows_rpc_reconciliation_only_v1",
    ],
)
def test_simnow_e2e_attach_is_mutually_exclusive_with_existing_attaches(
    attach_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )
    getattr(durable_module, attach_name)(
        rpc_engine=SimpleNamespace(server=server),
        event_engine=object(),
        main_engine=FactSource(),
    )
    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        _attach(monkeypatch, tmp_path, server)


@pytest.mark.parametrize(
    "attach_name",
    [
        "attach_windows_rpc_validation_only_v1",
        "attach_windows_rpc_reconciliation_only_v1",
    ],
)
def test_existing_attaches_reject_a_simnow_e2e_runtime(
    attach_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer()
    _attach(monkeypatch, tmp_path, server)
    monkeypatch.setattr(
        durable_module,
        "_validation_durable_store_path_v1",
        lambda: tmp_path / "execution-final-admission-v1.json",
    )

    with pytest.raises(WindowsRpcDurableFenceError, match="already attached"):
        getattr(durable_module, attach_name)(
            rpc_engine=SimpleNamespace(server=server),
            event_engine=object(),
            main_engine=FactSource(),
        )


def test_simnow_e2e_restart_restores_high_water_and_receipt_query_then_cancels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_vnpy(monkeypatch)
    orders: list[dict[str, Any]] = []
    engine = FactSource(orders=orders)

    class StatefulServer(FakeServer):
        def __init__(self) -> None:
            super().__init__()
            self._functions["send_order"] = self.native_send
            self._functions["cancel_order"] = self.native_cancel

        def native_send(self, request: Any, gateway_name: str) -> str:
            self.send_calls += 1
            orderid = str(len(orders) + 1)
            vt_orderid = f"{gateway_name}.{orderid}"
            orders.append(
                {
                    "vt_orderid": vt_orderid,
                    "orderid": orderid,
                    "symbol": request.symbol,
                    "exchange": request.exchange.name,
                    "reference": request.reference,
                    "gateway_name": gateway_name,
                    "status": "not_traded",
                }
            )
            return vt_orderid

        def native_cancel(self, request: Any, gateway_name: str) -> None:
            self.cancel_calls += 1
            assert gateway_name == "CTP"
            for order in orders:
                if order["orderid"] == request.orderid:
                    order["status"] = "cancelled"
                    return
            raise AssertionError("cancel target missing")

    first_server = StatefulServer()
    _attach(monkeypatch, tmp_path, first_server, main_engine=engine)
    _install_fence(first_server)
    send_request = _request()
    send_context = _context(send_request, intent_id="intent-restart-send-0001")
    _register(first_server, send_context)
    sent = first_server._functions["send_order_fenced_v1"](send_request, send_context)
    assert sent["broker_order_id"] == "CTP.1"

    restarted_server = StatefulServer()
    _attach(monkeypatch, tmp_path, restarted_server, main_engine=engine)
    peek = restarted_server._functions["peek_current_facts_v1"](
        {"account_scope": "account:windows", "environment": "simnow"}
    )
    assert peek["admission"]["fence"] == {
        "active": False,
        "current_epoch": 0,
        "current_fencing_token": 0,
        "high_water_epoch": 1,
        "high_water_fencing_token": 1,
    }
    assert peek["admission"]["receipt_intents"] == [send_context["intent_id"]]

    with pytest.raises(WindowsRpcDurableFenceDenied, match="strictly newer"):
        _install_fence(restarted_server)
    with pytest.raises(WindowsRpcDurableFenceDenied):
        restarted_server._functions["send_order_fenced_v1"](send_request, send_context)
    with pytest.raises(WindowsRpcDurableFenceDenied):
        _register(restarted_server, send_context)
    assert restarted_server.send_calls == 0

    recovered = restarted_server._functions["query_intent_v1"](
        {
            "account_scope": "account:windows",
            "environment": "simnow",
            "intent_id": send_context["intent_id"],
            "broker_order_id": "CTP.1",
        }
    )
    assert recovered["state"] == "ACKNOWLEDGED"
    assert recovered["broker_order_id"] == "CTP.1"

    _install_fence(restarted_server, leader_epoch=2, fencing_token=2)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="stale"):
        _register(restarted_server, send_context)
    with pytest.raises(WindowsRpcDurableFenceDenied, match="stale"):
        restarted_server._functions["send_order_fenced_v1"](send_request, send_context)
    cancel_request = {
        "target_intent_id": send_context["intent_id"],
        "broker_order_id": "CTP.1",
    }
    cancel_context = _context(
        cancel_request,
        intent_id="intent-restart-cancel-001",
        leader_epoch=2,
        fencing_token=2,
        action="cancel",
    )
    _register(restarted_server, cancel_context)
    cancelled = restarted_server._functions["cancel_order_fenced_v1"](
        cancel_request, cancel_context
    )
    assert cancelled["state"] == "CANCELLED"
    assert restarted_server.cancel_calls == 1
    assert orders[0]["status"] == "cancelled"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows RpcServer")
def test_simnow_e2e_attach_preserves_native_windows_rpc_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vnpy.rpc import RpcServer

    native_calls: list[str] = []

    def send_order(*_args: Any, **_kwargs: Any) -> str:
        native_calls.append("send")
        return "CTP.1"

    def cancel_order(*_args: Any, **_kwargs: Any) -> None:
        native_calls.append("cancel")

    server = RpcServer()
    try:
        server.register(send_order)
        server.register(cancel_order)
        _attach(monkeypatch, tmp_path, server)
        assert not server.is_active()
        assert set(server._functions) == {
            "send_order",
            "cancel_order",
            "install_fence_v1",
            "register_receipt_v1",
            "send_order_fenced_v1",
            "cancel_order_fenced_v1",
            "query_intent_v1",
            "get_execution_snapshot_v1",
            "peek_current_facts_v1",
        }
        for name in ("send_order", "cancel_order"):
            with pytest.raises(WindowsRpcDurableFenceDenied, match="FROZEN"):
                server._functions[name](object(), "CTP")
        assert native_calls == []
    finally:
        server._socket_rep.close(linger=0)
        server._socket_pub.close(linger=0)
        server._context.destroy(linger=0)
