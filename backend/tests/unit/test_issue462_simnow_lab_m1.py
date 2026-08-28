from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from vnpy.event import Event
from vnpy.trader.constant import Direction, Exchange, OrderType, Product, Status
from vnpy.trader.event import EVENT_ACCOUNT, EVENT_ORDER, EVENT_POSITION, EVENT_TRADE
from vnpy.trader.object import (
    AccountData,
    ContractData,
    OrderData,
    PositionData,
    TickData,
    TradeData,
)

from scripts.windows_rpc_durable_fence_v1 import _SIMNOW_E2E_RPC_METHODS
from scripts.windows_simnow_lab import executor_v1
from scripts.windows_simnow_lab.executor_v1 import (
    RPC_APPLY,
    RPC_GET,
    SimNowLabError,
    SimNowLabExecutorV1,
    attach_windows_simnow_lab_v1,
)

PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")


def target(*, ag: int = 0, rb: int = 0) -> dict[str, Any]:
    rows = [
        {
            "product": product,
            "vt_symbol": f"{product}2610.{'INE' if product == 'sc' else 'SHFE'}",
            "quantity": ag if product == "ag" else rb if product == "rb" else 0,
        }
        for product in PRODUCTS
    ]
    payload = {
        "schema_version": "simnow_lab_target_v1",
        "strategy_id": "STATIC_CORE_EQUAL",
        "generated_at": "2026-08-27T01:02:03Z",
        "targets": rows,
    }
    payload["target_id"] = sha256(executor_v1._canonical(payload)).hexdigest()
    return payload


class FakeEventEngine:
    def __init__(self) -> None:
        self.handlers: dict[str, list[Any]] = {}

    def register(self, event_type: str, handler: Any) -> None:
        self.handlers.setdefault(event_type, []).append(handler)

    def emit(self, event_type: str, data: Any) -> None:
        for handler in list(self.handlers.get(event_type, [])):
            handler(Event(event_type, data))


class FakeTracker:
    def __init__(self) -> None:
        self.ready = False
        self.generation = 0

    def is_ready(self) -> bool:
        return self.ready


class FakeTdApi:
    def __init__(self, main: FakeMainEngine) -> None:
        self.main = main
        self.login_status = True
        self.brokerid = "9999"
        self.userid = "redacted"
        self.reqid = 0
        self.order_ref = 0
        self.order_query_failure = False
        self.order_query_fail_after: int | None = None
        self.order_query_count = 0
        self._vnpy_position_readiness_v1 = FakeTracker()
        self._vnpy_current_day_order_recovery_v1 = True

    def onRspQryOrder(self, _data: Any, _error: Any, _request_id: int, _last: bool) -> None:
        return None

    def reqQryOrder(self, _request: Any, request_id: int) -> int:
        self.order_query_count += 1
        if self.order_query_failure or (
            self.order_query_fail_after is not None
            and self.order_query_count >= self.order_query_fail_after
        ):
            return 1
        self.main.oms.orders = dict(self.main.broker_orders)
        self.main.oms.active_orders = {
            vt_orderid: order
            for vt_orderid, order in self.main.broker_orders.items()
            if order.status not in {Status.ALLTRADED, Status.CANCELLED, Status.REJECTED}
        }
        self.onRspQryOrder({}, {}, request_id, True)
        return 0


class FakeGateway:
    def __init__(self, main: FakeMainEngine) -> None:
        self.main = main
        self.td_api = FakeTdApi(main)
        self.md_api = SimpleNamespace(login_status=True)
        self.position_query_rejected = False
        self.position_event_delayed = False

    def query_position(self) -> None:
        tracker = self.td_api._vnpy_position_readiness_v1
        if self.position_query_rejected:
            return
        tracker.generation += 1
        tracker.ready = False
        positions = {row.vt_positionid: row for row in self.main.broker_positions}
        if self.position_event_delayed:
            tracker.ready = True

            def publish() -> None:
                self.main.oms.positions = positions
                for position in positions.values():
                    self.main.events.emit(EVENT_POSITION, position)

            threading.Timer(0.01, publish).start()
        else:
            self.main.oms.positions = positions
            for position in positions.values():
                self.main.events.emit(EVENT_POSITION, position)
            tracker.ready = True

    def query_account(self) -> None:
        account = AccountData(accountid="redacted", balance=1_000_000, frozen=0, gateway_name="CTP")
        account.available = 900_000
        self.main.oms.accounts = {account.vt_accountid: account}
        self.main.events.emit(EVENT_ACCOUNT, account)


class FakeMainEngine:
    def __init__(self, events: FakeEventEngine) -> None:
        self.events = events
        self.oms = SimpleNamespace(orders={}, active_orders={}, positions={}, accounts={})
        self.gateway = FakeGateway(self)
        self.broker_positions: list[PositionData] = []
        self.broker_orders: dict[str, OrderData] = {}
        self.contracts: dict[str, ContractData] = {}
        self.ticks: dict[str, TickData] = {}
        self.sent = 0
        self.synchronous_fill = False
        self.send_failure: Exception | None = None
        self.timeout_has_local_order = False
        self.db_path: Path | None = None
        self.saw_created_before_send = False
        for product in PRODUCTS:
            symbol = f"{product}2610"
            exchange = Exchange.INE if product == "sc" else Exchange.SHFE
            vt_symbol = f"{symbol}.{exchange.value}"
            self.contracts[vt_symbol] = ContractData(
                symbol=symbol,
                exchange=exchange,
                name=product,
                product=Product.FUTURES,
                size=10,
                pricetick=1,
                gateway_name="CTP",
            )
            self.ticks[vt_symbol] = TickData(
                symbol=symbol,
                exchange=exchange,
                datetime=datetime.now(timezone.utc),
                bid_price_1=99,
                ask_price_1=100,
                gateway_name="CTP",
            )

    def get_gateway(self, _name: str) -> FakeGateway:
        return self.gateway

    def get_engine(self, _name: str) -> Any:
        return self.oms

    def get_all_active_orders(self) -> list[Any]:
        return list(self.oms.active_orders.values())

    def get_all_orders(self) -> list[Any]:
        return list(self.oms.orders.values())

    def get_all_positions(self) -> list[Any]:
        return list(self.oms.positions.values())

    def get_all_accounts(self) -> list[Any]:
        return list(self.oms.accounts.values())

    def get_contract(self, vt_symbol: str) -> Any:
        return self.contracts.get(vt_symbol)

    def get_tick(self, vt_symbol: str) -> Any:
        return self.ticks.get(vt_symbol)

    def subscribe(self, _request: Any, _gateway_name: str) -> None:
        return None

    def send_order(self, request: Any, gateway_name: str) -> str:
        assert self.db_path is not None
        with sqlite3.connect(self.db_path) as db:
            self.saw_created_before_send = db.execute(
                "SELECT COUNT(*) FROM orders WHERE status='CREATED'"
            ).fetchone()[0] == 1
        self.sent += 1
        orderid = str(self.sent)
        vt_orderid = f"{gateway_name}.{orderid}"
        submitting = request.create_order_data(orderid, gateway_name)
        self.gateway.td_api.order_ref += 1
        if self.send_failure is not None:
            if self.timeout_has_local_order:
                self.oms.orders[vt_orderid] = submitting
                self.broker_orders[vt_orderid] = submitting
            raise self.send_failure
        self.oms.orders[vt_orderid] = submitting
        self.oms.active_orders[vt_orderid] = submitting
        self.broker_orders[vt_orderid] = submitting
        self.events.emit(EVENT_ORDER, submitting)

        def fill() -> None:
            net = sum(
                row.volume if row.direction == Direction.LONG else -row.volume
                for row in self.broker_positions
                if row.vt_symbol == f"{request.symbol}.{request.exchange.value}"
            )
            net += request.volume if request.direction == Direction.LONG else -request.volume
            self.broker_positions = (
                [
                    PositionData(
                        symbol=request.symbol,
                        exchange=request.exchange,
                        direction=Direction.LONG if net > 0 else Direction.SHORT,
                        volume=abs(net),
                        yd_volume=0,
                        gateway_name=gateway_name,
                    )
                ]
                if net
                else []
            )
            filled = OrderData(
                symbol=request.symbol,
                exchange=request.exchange,
                orderid=orderid,
                type=OrderType.LIMIT,
                direction=request.direction,
                offset=request.offset,
                price=request.price,
                volume=request.volume,
                traded=request.volume,
                status=Status.ALLTRADED,
                datetime=datetime.now(timezone.utc),
                reference=request.reference,
                gateway_name=gateway_name,
            )
            self.oms.orders[vt_orderid] = filled
            self.oms.active_orders.pop(vt_orderid, None)
            self.broker_orders[vt_orderid] = filled
            self.events.emit(EVENT_ORDER, filled)
            trade = TradeData(
                symbol=request.symbol,
                exchange=request.exchange,
                orderid=orderid,
                tradeid="T1",
                direction=request.direction,
                offset=request.offset,
                price=request.price,
                volume=request.volume,
                datetime=datetime.now(timezone.utc),
                gateway_name=gateway_name,
            )
            self.events.emit(EVENT_TRADE, trade)

        if self.synchronous_fill:
            fill()
        else:
            threading.Timer(0.02, fill).start()
        return vt_orderid


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[SimNowLabExecutorV1, FakeMainEngine, Path]:
    monkeypatch.setattr(executor_v1, "QUERY_INTERVAL_SECONDS", 0.0)
    events = FakeEventEngine()
    main = FakeMainEngine(events)
    db_path = tmp_path / "lab.sqlite3"
    subject = SimNowLabExecutorV1(
        main_engine=main,
        event_engine=events,
        gateway_name="CTP",
        db_path=db_path,
        wait_seconds=1,
    )
    main.db_path = db_path
    return subject, main, db_path


def test_target_requires_exact_ten_product_hash() -> None:
    value = target(rb=1)
    assert executor_v1.validate_target_v1(value)["target_id"] == value["target_id"]
    value["targets"].pop()
    with pytest.raises(SimNowLabError, match="TARGET_COUNT_INVALID"):
        executor_v1.validate_target_v1(value)


def test_target_locks_products_and_normalizes_exchange_first_symbol() -> None:
    value = target(rb=1)
    value["targets"][5]["vt_symbol"] = "SHFE.rb2610"
    normalized = {**value, "targets": [dict(row) for row in value["targets"]]}
    normalized["targets"][5]["vt_symbol"] = "rb2610.SHFE"
    value["target_id"] = sha256(
        executor_v1._canonical({key: item for key, item in normalized.items() if key != "target_id"})
    ).hexdigest()
    assert executor_v1.validate_target_v1(value)["targets"][5]["vt_symbol"] == "rb2610.SHFE"
    value = target(rb=1)
    value["targets"][6]["product"] = "sn"
    value["targets"][6]["vt_symbol"] = "sn2610.SHFE"
    value["target_id"] = sha256(executor_v1._canonical({key: item for key, item in value.items() if key != "target_id"})).hexdigest()
    with pytest.raises(SimNowLabError, match="TARGET_PRODUCTS_INVALID"):
        executor_v1.validate_target_v1(value)


def test_attach_requires_simnow_and_registers_only_lab_rpcs(tmp_path: Path) -> None:
    class Server:
        def __init__(self) -> None:
            self._functions: dict[str, Any] = {}

        def register(self, handler: Any) -> None:
            self._functions[handler.__name__] = handler

        def is_active(self) -> bool:
            return False

    events = FakeEventEngine()
    main = FakeMainEngine(events)
    server = Server()
    runtime = SimpleNamespace(
        rpc_engine=SimpleNamespace(server=server),
        main_engine=main,
        event_engine=events,
        config=SimpleNamespace(gateway_name="CTP", environment="simnow"),
    )

    attach_windows_simnow_lab_v1(runtime=runtime, db_path=tmp_path / "lab.sqlite3")

    assert set(server._functions) == {RPC_APPLY, RPC_GET}
    runtime.config.environment = "production"
    with pytest.raises(SimNowLabError, match="SIMNOW_LAB_ENVIRONMENT_INVALID"):
        attach_windows_simnow_lab_v1(runtime=runtime, db_path=tmp_path / "other.sqlite3")


def test_simnow_e2e_seal_keeps_both_lab_rpcs() -> None:
    assert {RPC_APPLY, RPC_GET}.issubset(_SIMNOW_E2E_RPC_METHODS)


def test_m1_single_product_real_callback_path_reaches_done_and_sqlite(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, db_path = lab
    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "DONE"
    assert len(result["orders"]) == 1
    assert result["orders"][0]["status"] == "FILLED"
    assert len(result["trades"]) == 1
    assert [row["phase"] for row in result["snapshots"]] == ["BEFORE", "AFTER"]
    assert main.saw_created_before_send is True
    with sqlite3.connect(db_path) as db:
        assert {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        } == {"runs", "orders", "trades", "snapshots"}


def test_same_target_is_true_noop(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    assert subject.simnow_lab_apply_target_v1(target(rb=1))["run"]["status"] == "DONE"
    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "NOOP"
    assert result["orders"] == []
    assert main.sent == 1


def test_quantity_change_then_restore_reuses_fresh_positions(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab

    first = subject.simnow_lab_apply_target_v1(target(rb=1))
    changed = subject.simnow_lab_apply_target_v1(target(rb=2))
    restored = subject.simnow_lab_apply_target_v1(target(rb=0))

    assert [result["run"]["status"] for result in (first, changed, restored)] == ["DONE", "DONE", "DONE"]
    assert [len(result["orders"]) for result in (first, changed, restored)] == [1, 1, 1]
    assert [result["orders"][0]["quantity"] for result in (first, changed, restored)] == [1, 1, 2]
    assert restored["orders"][0]["offset"] == "CLOSETODAY"
    assert main.broker_positions == []
    assert main.sent == 3


def test_current_is_fresh_redacted_and_zero_mutation(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, db_path = lab
    main.broker_positions = [
        PositionData(
            symbol="rb2610",
            exchange=Exchange.SHFE,
            direction=Direction.LONG,
            volume=3,
            yd_volume=1,
            gateway_name="CTP",
        )
    ]
    active = OrderData(
        symbol="rb2610",
        exchange=Exchange.SHFE,
        orderid="current-order",
        type=OrderType.LIMIT,
        direction=Direction.LONG,
        volume=1,
        status=Status.NOTTRADED,
        gateway_name="CTP",
    )
    main.broker_orders[active.vt_orderid] = active

    result = subject.simnow_lab_get_run_v1("CURRENT")

    assert result == {
        "status": "CURRENT",
        "positions": [{"vt_symbol": "rb2610.SHFE", "direction": "LONG", "volume": 3, "yd_volume": 1}],
        "active_order_count": 1,
    }
    assert main.sent == 0
    with sqlite3.connect(db_path) as db:
        assert all(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0 for table in ("runs", "orders", "trades", "snapshots"))


def test_position_query_reject_cannot_reuse_stale_ready_after_oms_clear(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    subject.wait_seconds = 0.01
    main.gateway.td_api._vnpy_position_readiness_v1.ready = True
    main.gateway.position_query_rejected = True

    with pytest.raises(SimNowLabError, match="CTP_POSITION_QUERY_TIMEOUT"):
        subject._query_positions()


def test_position_query_waits_for_oms_position_event_after_ctp_final(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    position = PositionData(
        symbol="rb2610", exchange=Exchange.SHFE, direction=Direction.LONG,
        volume=1, gateway_name="CTP",
    )
    main.broker_positions = [position]
    main.gateway.position_event_delayed = True

    assert subject._query_positions() == [position]


def test_sync_callback_keeps_terminal_order_and_trade(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    main.synchronous_fill = True
    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "DONE"
    assert [(row["status"], row["broker_order_id"]) for row in result["orders"]] == [("FILLED", "CTP.1")]
    assert len(result["trades"]) == 1


def test_oserror_binds_fresh_queried_order_before_marking_unknown(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    subject.wait_seconds = 0.01
    main.send_failure = OSError()
    main.timeout_has_local_order = True

    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "PARTIAL"
    assert [(row["status"], row["broker_order_id"]) for row in result["orders"]] == [("SUBMITTED", "CTP.1")]


def test_local_ctp_exception_is_rejected(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    main.send_failure = RuntimeError("ctp rejected")

    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "FAILED"
    assert result["run"]["error"] == "ORDERS_REJECTED"
    assert [row["status"] for row in result["orders"]] == ["REJECTED"]


def test_oserror_without_fresh_queried_order_is_unknown_and_fails(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    main.send_failure = OSError()

    result = subject.simnow_lab_apply_target_v1(target(ag=1, rb=1))

    assert result["run"]["status"] == "FAILED"
    assert result["run"]["error"] == "UNKNOWN_ORDER_PRESENT"
    assert [row["status"] for row in result["orders"]] == ["UNKNOWN"]
    assert main.sent == 1


def test_oserror_with_failed_fresh_query_is_unknown_and_fails(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    main.send_failure = OSError()
    main.gateway.td_api.order_query_fail_after = 2

    result = subject.simnow_lab_apply_target_v1(target(rb=1))

    assert result["run"]["status"] == "FAILED"
    assert result["run"]["error"] == "UNKNOWN_ORDER_PRESENT"
    assert [row["status"] for row in result["orders"]] == ["UNKNOWN"]


def test_fresh_order_ref_suffix_collision_is_not_a_match(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, main, _db_path = lab
    order = OrderData(
        symbol="rb2610",
        exchange=Exchange.SHFE,
        orderid="11",
        type=OrderType.LIMIT,
        direction=Direction.LONG,
        volume=1,
        status=Status.NOTTRADED,
        gateway_name="CTP",
    )
    main.broker_orders[order.vt_orderid] = order

    assert subject._resolve_uncertain_send("LAB-not-matched", "1") == "UNKNOWN"


def test_shfe_close_plan_splits_yesterday_and_today(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, _main, _db_path = lab
    position = PositionData(
        symbol="rb2610",
        exchange=Exchange.SHFE,
        direction=Direction.LONG,
        volume=5,
        yd_volume=2,
        gateway_name="CTP",
    )

    assert subject._plans({"rb2610.SHFE": 0}, [position]) == [
        {"vt_symbol": "rb2610.SHFE", "direction": "SHORT", "offset": "CLOSEYESTERDAY", "quantity": 2},
        {"vt_symbol": "rb2610.SHFE", "direction": "SHORT", "offset": "CLOSETODAY", "quantity": 3},
    ]


def test_shfe_position_rejects_yesterday_volume_above_total(lab: tuple[SimNowLabExecutorV1, FakeMainEngine, Path]) -> None:
    subject, _main, _db_path = lab
    position = PositionData(
        symbol="rb2610",
        exchange=Exchange.SHFE,
        direction=Direction.LONG,
        volume=1,
        yd_volume=2,
        gateway_name="CTP",
    )

    with pytest.raises(SimNowLabError, match="BROKER_FACT_INVALID"):
        subject._portfolio([position])
