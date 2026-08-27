"""Issue #462 in-process Windows SimNow executor.

The executor owns two private RPCs, one process lock, and one SQLite file.  It
uses only the CTP session already owned by the Windows RPC process.
"""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from types import MethodType
from typing import Any

TARGET_SCHEMA = "simnow_lab_target_v1"
STRATEGY_ID = "STATIC_CORE_EQUAL"
RPC_APPLY = "simnow_lab_apply_target_v1"
RPC_GET = "simnow_lab_get_run_v1"
TARGET_COUNT = 10
FROZEN_PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
TICK_CUSHION = 1
TICK_MAX_AGE_SECONDS = 10.0
QUERY_INTERVAL_SECONDS = 1.05
WAIT_SECONDS = 10.0

_VT_SYMBOL = re.compile(r"^(?P<symbol>[A-Za-z]+[0-9]+)\.(?P<exchange>SHFE|INE|DCE|CZCE|GFEX|CFFEX)$")
_EXCHANGE_FIRST_VT_SYMBOL = re.compile(r"^(?P<exchange>SHFE|INE|DCE|CZCE|GFEX|CFFEX)\.(?P<symbol>[A-Za-z]+[0-9]+)$")
_PRODUCT = re.compile(r"^[a-z]{1,8}$")
_ORDER_QUERY_MARKER = "_simnow_lab_order_query_v1"
_ATTACH_MARKER = "_simnow_lab_executor_v1"
_TERMINAL = frozenset({"FILLED", "CANCELLED", "REJECTED"})


class SimNowLabError(RuntimeError):
    """Stable local Lab rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SimNowLabError("TARGET_JSON_INVALID") from exc


def _field(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def _enum_text(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.name)
    return str(getattr(value, "name", value))


def _number(value: Any, *, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SimNowLabError("BROKER_FACT_INVALID")
    result = float(value)
    if not math.isfinite(result):
        raise SimNowLabError("BROKER_FACT_INVALID")
    return result


def _json_fact(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return value.isoformat()
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _json_fact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_fact(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        return {key: _json_fact(item) for key, item in vars(value).items() if not key.startswith("_")}
    except TypeError:
        return str(value)


def _canonical_vt_symbol(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = _VT_SYMBOL.fullmatch(value)
    if match is None:
        match = _EXCHANGE_FIRST_VT_SYMBOL.fullmatch(value)
    if match is None:
        return None
    return f"{match.group('symbol').lower()}.{match.group('exchange')}"


def validate_target_v1(value: Any) -> dict[str, Any]:
    """Validate the fixed ten-product target and its canonical SHA256."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "strategy_id",
        "generated_at",
        "target_id",
        "targets",
    }:
        raise SimNowLabError("TARGET_FIELDS_INVALID")
    if value["schema_version"] != TARGET_SCHEMA or value["strategy_id"] != STRATEGY_ID:
        raise SimNowLabError("TARGET_CONSTANT_INVALID")
    generated_at = value["generated_at"]
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise SimNowLabError("TARGET_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(generated_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SimNowLabError("TARGET_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SimNowLabError("TARGET_TIME_INVALID")
    rows = value["targets"]
    if not isinstance(rows, list) or len(rows) != TARGET_COUNT:
        raise SimNowLabError("TARGET_COUNT_INVALID")
    products: set[str] = set()
    symbols: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"product", "vt_symbol", "quantity"}:
            raise SimNowLabError("TARGET_ROW_INVALID")
        product = row["product"]
        vt_symbol = _canonical_vt_symbol(row["vt_symbol"])
        quantity = row["quantity"]
        match = _VT_SYMBOL.fullmatch(vt_symbol) if vt_symbol is not None else None
        if (
            not isinstance(product, str)
            or _PRODUCT.fullmatch(product) is None
            or match is None
            or not match.group("symbol").lower().startswith(product)
            or type(quantity) is not int
            or abs(quantity) > 1_000_000
            or product in products
            or vt_symbol in symbols
        ):
            raise SimNowLabError("TARGET_ROW_INVALID")
        products.add(product)
        symbols.add(vt_symbol)
        normalized.append({"product": product, "vt_symbol": vt_symbol, "quantity": quantity})
    payload = {
        "schema_version": TARGET_SCHEMA,
        "strategy_id": STRATEGY_ID,
        "generated_at": generated_at,
        "targets": normalized,
    }
    expected = sha256(_canonical(payload)).hexdigest()
    if value["target_id"] != expected:
        raise SimNowLabError("TARGET_ID_INVALID")
    if products != set(FROZEN_PRODUCTS):
        raise SimNowLabError("TARGET_PRODUCTS_INVALID")
    return {**payload, "target_id": expected}


class _ProcessLock:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def hold(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise SimNowLabError("LAB_ALREADY_RUNNING") from exc
        try:
            yield
        finally:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


class SimNowLabExecutorV1:
    def __init__(
        self,
        *,
        main_engine: Any,
        event_engine: Any,
        gateway_name: str,
        db_path: Path,
        wait_seconds: float = WAIT_SECONDS,
    ) -> None:
        self.main_engine = main_engine
        self.event_engine = event_engine
        self.gateway_name = gateway_name
        self.db_path = db_path
        self.wait_seconds = wait_seconds
        self._thread_lock = threading.Lock()
        self._process_lock = _ProcessLock(db_path.with_suffix(".lock"))
        self._condition = threading.Condition()
        self._last_query_at = 0.0
        self._order_query: dict[str, Any] = {}
        self._sending: dict[str, Any] | None = None
        self._account_generation = 0
        self._initialize_db()
        self._register_callbacks()
        self._install_order_query_callback()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, target_json TEXT NOT NULL,
                    started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL, error TEXT
                );
                CREATE TABLE IF NOT EXISTS orders (
                    client_order_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, symbol TEXT NOT NULL,
                    order_ref TEXT NOT NULL,
                    direction TEXT NOT NULL, offset TEXT NOT NULL, quantity INTEGER NOT NULL,
                    touch_price REAL NOT NULL, price_tick REAL NOT NULL, limit_price REAL NOT NULL,
                    broker_order_id TEXT, status TEXT NOT NULL, traded REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trades (
                    trade_key TEXT PRIMARY KEY, run_id TEXT NOT NULL, client_order_id TEXT,
                    broker_order_id TEXT NOT NULL, trade_id TEXT NOT NULL, symbol TEXT NOT NULL,
                    direction TEXT NOT NULL, offset TEXT NOT NULL, price REAL NOT NULL,
                    volume REAL NOT NULL, trade_time TEXT, slippage REAL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, phase TEXT NOT NULL,
                    observed_at TEXT NOT NULL, positions_json TEXT NOT NULL,
                    active_orders_json TEXT NOT NULL, account_json TEXT NOT NULL,
                    equity REAL, available REAL, margin REAL, unrealized_pnl REAL
                );
                """
            )

    def _register_callbacks(self) -> None:
        from vnpy.trader.event import (
            EVENT_ACCOUNT,
            EVENT_ORDER,
            EVENT_TICK,
            EVENT_TRADE,
        )

        self.event_engine.register(EVENT_ORDER, self._on_order)
        self.event_engine.register(EVENT_TRADE, self._on_trade)
        self.event_engine.register(EVENT_TICK, self._notify)
        self.event_engine.register(EVENT_ACCOUNT, self._on_account)

    def _gateway(self) -> Any:
        gateway = self.main_engine.get_gateway(self.gateway_name)
        if gateway is None or getattr(getattr(gateway, "td_api", None), "login_status", False) is not True:
            raise SimNowLabError("SIMNOW_CTP_NOT_CONNECTED")
        if getattr(getattr(gateway, "md_api", None), "login_status", False) is not True:
            raise SimNowLabError("SIMNOW_CTP_NOT_CONNECTED")
        return gateway

    def _oms(self) -> Any:
        oms = self.main_engine.get_engine("oms")
        if oms is None:
            raise SimNowLabError("OMS_UNAVAILABLE")
        return oms

    def _install_order_query_callback(self) -> None:
        td_api = getattr(self.main_engine.get_gateway(self.gateway_name), "td_api", None)
        if td_api is None:
            raise SimNowLabError("CTP_ORDER_QUERY_UNAVAILABLE")
        marker = getattr(td_api, _ORDER_QUERY_MARKER, None)
        if marker is not None:
            raise SimNowLabError("CTP_ORDER_QUERY_ALREADY_ATTACHED")
        original = getattr(td_api, "onRspQryOrder", None)
        if not callable(original):
            raise SimNowLabError("CTP_ORDER_QUERY_UNAVAILABLE")

        def wrapped(subject: Any, data: Any, error: Any, request_id: Any, last: Any) -> Any:
            result = original(data, error, request_id, last)
            with self._condition:
                if request_id == self._order_query.get("request_id"):
                    error_id = error.get("ErrorID", 0) if isinstance(error, Mapping) else None
                    if type(error_id) is not int or error_id != 0:
                        self._order_query["error"] = "CTP_ORDER_QUERY_REJECTED"
                    if last is True:
                        self._order_query["done"] = True
                    self._condition.notify_all()
            return result

        td_api.onRspQryOrder = MethodType(wrapped, td_api)
        setattr(td_api, _ORDER_QUERY_MARKER, self)

    def _pace_query(self) -> None:
        delay = QUERY_INTERVAL_SECONDS - (time.monotonic() - self._last_query_at)
        if delay > 0:
            time.sleep(delay)
        self._last_query_at = time.monotonic()

    def _query_orders(self) -> list[Any]:
        gateway = self._gateway()
        td_api = gateway.td_api
        oms = self._oms()
        oms.orders.clear()
        oms.active_orders.clear()
        self._pace_query()
        request_id = td_api.reqid + 1
        with self._condition:
            self._order_query = {"request_id": request_id, "done": False, "error": None}
        request = {"BrokerID": td_api.brokerid, "InvestorID": td_api.userid}
        td_api.reqid = request_id
        result = td_api.reqQryOrder(request, request_id)
        if result != 0:
            raise SimNowLabError("CTP_ORDER_QUERY_REJECTED")
        deadline = time.monotonic() + self.wait_seconds
        with self._condition:
            while not self._order_query["done"] and self._order_query["error"] is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SimNowLabError("CTP_ORDER_QUERY_TIMEOUT")
                self._condition.wait(remaining)
            if self._order_query["error"]:
                raise SimNowLabError(str(self._order_query["error"]))
        return list(self.main_engine.get_all_active_orders())

    def _query_positions(self) -> list[Any]:
        gateway = self._gateway()
        tracker = getattr(gateway.td_api, "_vnpy_position_readiness_v1", None)
        if tracker is None or not callable(getattr(tracker, "is_ready", None)):
            raise SimNowLabError("CTP_POSITION_QUERY_UNAVAILABLE")
        generation = getattr(tracker, "generation", None)
        if type(generation) is not int:
            raise SimNowLabError("CTP_POSITION_QUERY_UNAVAILABLE")
        self._oms().positions.clear()
        self._pace_query()
        gateway.query_position()
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            if tracker.generation > generation and tracker.is_ready() is True:
                return list(self.main_engine.get_all_positions())
            time.sleep(0.05)
        raise SimNowLabError("CTP_POSITION_QUERY_TIMEOUT")

    def _query_account(self) -> list[Any]:
        gateway = self._gateway()
        with self._condition:
            generation = self._account_generation
        self._pace_query()
        gateway.query_account()
        deadline = time.monotonic() + self.wait_seconds
        with self._condition:
            while self._account_generation == generation:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
        return list(self.main_engine.get_all_accounts())

    def _fresh_facts(self) -> dict[str, Any]:
        active_orders = self._query_orders()
        positions = self._query_positions()
        accounts = self._query_account()
        return {"positions": positions, "active_orders": active_orders, "accounts": accounts}

    @staticmethod
    def _portfolio(positions: Sequence[Any]) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {}
        for row in positions:
            symbol = _canonical_vt_symbol(_field(row, "vt_symbol"))
            if not symbol:
                raw_symbol = _field(row, "symbol")
                exchange = _enum_text(_field(row, "exchange"))
                symbol = _canonical_vt_symbol(f"{raw_symbol}.{exchange}")
            if not symbol:
                raise SimNowLabError("BROKER_FACT_INVALID")
            direction = _enum_text(_field(row, "direction")).upper()
            raw_volume = _number(_field(row, "volume"))
            raw_yd_volume = _number(_field(row, "yd_volume"))
            if (
                raw_volume < 0
                or raw_yd_volume < 0
                or not raw_volume.is_integer()
                or not raw_yd_volume.is_integer()
            ):
                raise SimNowLabError("BROKER_FACT_INVALID")
            volume = int(raw_volume)
            yd_volume = int(raw_yd_volume)
            if symbol.rsplit(".", 1)[1] in {"SHFE", "INE"} and yd_volume > volume:
                raise SimNowLabError("BROKER_FACT_INVALID")
            bucket = result.setdefault(symbol, {"long": 0, "long_yd": 0, "short": 0, "short_yd": 0})
            if direction == "LONG":
                bucket["long"] += volume
                bucket["long_yd"] += yd_volume
            elif direction == "SHORT":
                bucket["short"] += volume
                bucket["short_yd"] += yd_volume
        return result

    @staticmethod
    def _at_target(target: Mapping[str, int], positions: Sequence[Any]) -> bool:
        portfolio = SimNowLabExecutorV1._portfolio(positions)
        return all(portfolio.get(symbol, {}).get("long", 0) - portfolio.get(symbol, {}).get("short", 0) == quantity for symbol, quantity in target.items())

    def _plans(self, target: Mapping[str, int], positions: Sequence[Any]) -> list[dict[str, Any]]:
        portfolio = self._portfolio(positions)
        plans: list[dict[str, Any]] = []
        for vt_symbol, desired in target.items():
            current = portfolio.get(vt_symbol, {"long": 0, "long_yd": 0, "short": 0, "short_yd": 0})
            delta = desired - (current["long"] - current["short"])
            exchange = vt_symbol.rsplit(".", 1)[1]
            split_close = exchange in {"SHFE", "INE"}
            if delta > 0:
                closing = min(delta, current["short"])
                yd = min(closing, current["short_yd"]) if split_close else closing
                today = closing - yd
                if yd:
                    plans.append({"vt_symbol": vt_symbol, "direction": "LONG", "offset": "CLOSEYESTERDAY" if split_close else "CLOSE", "quantity": yd})
                if today:
                    plans.append({"vt_symbol": vt_symbol, "direction": "LONG", "offset": "CLOSETODAY" if split_close else "CLOSE", "quantity": today})
                if delta > closing:
                    plans.append({"vt_symbol": vt_symbol, "direction": "LONG", "offset": "OPEN", "quantity": delta - closing})
            elif delta < 0:
                required = -delta
                closing = min(required, current["long"])
                yd = min(closing, current["long_yd"]) if split_close else closing
                today = closing - yd
                if yd:
                    plans.append({"vt_symbol": vt_symbol, "direction": "SHORT", "offset": "CLOSEYESTERDAY" if split_close else "CLOSE", "quantity": yd})
                if today:
                    plans.append({"vt_symbol": vt_symbol, "direction": "SHORT", "offset": "CLOSETODAY" if split_close else "CLOSE", "quantity": today})
                if required > closing:
                    plans.append({"vt_symbol": vt_symbol, "direction": "SHORT", "offset": "OPEN", "quantity": required - closing})
        return plans

    def _tick(self, vt_symbol: str) -> tuple[Any, float, float]:
        from vnpy.trader.object import SubscribeRequest

        contract = self.main_engine.get_contract(vt_symbol)
        if contract is None or _number(_field(contract, "pricetick")) <= 0:
            raise SimNowLabError("CONTRACT_UNAVAILABLE")
        deadline = time.monotonic() + self.wait_seconds
        tick = self.main_engine.get_tick(vt_symbol)
        if tick is None:
            self.main_engine.subscribe(
                SubscribeRequest(symbol=contract.symbol, exchange=contract.exchange),
                self.gateway_name,
            )
        while time.monotonic() < deadline:
            tick = self.main_engine.get_tick(vt_symbol)
            observed = _field(tick, "datetime") if tick is not None else None
            if isinstance(observed, datetime) and observed.tzinfo is not None:
                age = (datetime.now(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds()
                if -1 <= age <= TICK_MAX_AGE_SECONDS:
                    bid = _number(_field(tick, "bid_price_1"))
                    ask = _number(_field(tick, "ask_price_1"))
                    if bid > 0 and ask > 0:
                        return tick, bid, ask
            with self._condition:
                self._condition.wait(min(0.25, max(0.0, deadline - time.monotonic())))
        raise SimNowLabError("FRESH_TICK_UNAVAILABLE")

    def _insert_run(self, run_id: str, target: Mapping[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO runs(run_id,target_id,target_json,started_at,status) VALUES(?,?,?,?,?)",
                (run_id, target["target_id"], _canonical(target).decode("ascii"), _utc_now(), "RUNNING"),
            )

    def _finish_run(self, run_id: str, status: str, error: str | None = None) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE runs SET ended_at=?,status=?,error=? WHERE run_id=?",
                (_utc_now(), status, error, run_id),
            )

    def _snapshot(self, run_id: str, phase: str, facts: Mapping[str, Any]) -> None:
        accounts = list(facts["accounts"])
        account = accounts[0] if accounts else None
        positions = list(facts["positions"])
        equity = _number(_field(account, "balance"), default=0.0) if account else None
        available = _number(_field(account, "available"), default=0.0) if account else None
        margin = _field(account, "margin") if account else None
        unrealized = sum(_number(_field(row, "pnl"), default=0.0) for row in positions)
        with self._connect() as db:
            db.execute(
                "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uuid.uuid4().hex,
                    run_id,
                    phase,
                    _utc_now(),
                    json.dumps(_json_fact(positions), ensure_ascii=True, sort_keys=True),
                    json.dumps(_json_fact(facts["active_orders"]), ensure_ascii=True, sort_keys=True),
                    json.dumps(_json_fact(accounts), ensure_ascii=True, sort_keys=True),
                    equity,
                    available,
                    margin,
                    unrealized,
                ),
            )

    def _send(self, run_id: str, plan: Mapping[str, Any]) -> str:
        from vnpy.trader.constant import Direction, Offset, OrderType
        from vnpy.trader.object import OrderRequest

        vt_symbol = str(plan["vt_symbol"])
        contract = self.main_engine.get_contract(vt_symbol)
        if contract is None:
            raise SimNowLabError("CONTRACT_UNAVAILABLE")
        _tick_value, bid, ask = self._tick(vt_symbol)
        price_tick = _number(contract.pricetick)
        direction = str(plan["direction"])
        touch = ask if direction == "LONG" else bid
        limit_price = touch + price_tick * TICK_CUSHION if direction == "LONG" else touch - price_tick * TICK_CUSHION
        client_order_id = f"LAB-{uuid.uuid4().hex}"
        td_api = self._gateway().td_api
        current_order_ref = _field(td_api, "order_ref")
        if type(current_order_ref) is not int or current_order_ref < 0:
            raise SimNowLabError("CTP_ORDER_REF_UNAVAILABLE")
        order_ref = str(current_order_ref + 1)
        now = _utc_now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO orders(client_order_id,run_id,symbol,order_ref,direction,offset,quantity,touch_price,price_tick,limit_price,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (client_order_id, run_id, vt_symbol, order_ref, direction, plan["offset"], plan["quantity"], touch, price_tick, limit_price, "CREATED", now, now),
            )
        request = OrderRequest(
            symbol=contract.symbol,
            exchange=contract.exchange,
            direction=Direction[direction],
            type=OrderType.LIMIT,
            volume=int(plan["quantity"]),
            price=limit_price,
            offset=Offset[str(plan["offset"])],
            reference=client_order_id,
        )
        self._sending = {
            "client_order_id": client_order_id,
            "symbol": vt_symbol,
            "direction": direction,
            "offset": str(plan["offset"]),
            "quantity": int(plan["quantity"]),
            "order_ref": order_ref,
        }
        try:
            broker_order_id = self.main_engine.send_order(request, self.gateway_name)
        except (TimeoutError, ConnectionError, OSError):
            return self._resolve_uncertain_send(client_order_id, order_ref)
        except Exception:  # noqa: BLE001 - a local CTP error is an explicit rejection.
            self._update_order(client_order_id, status="REJECTED")
            return "REJECTED"
        finally:
            self._sending = None
        if not isinstance(broker_order_id, str) or not broker_order_id:
            self._update_order(client_order_id, status="REJECTED")
            return "REJECTED"
        self._mark_submitted(client_order_id, broker_order_id)
        return "SUBMITTED"

    def _resolve_uncertain_send(self, client_order_id: str, order_ref: str) -> str:
        try:
            self._query_orders()
        except SimNowLabError:
            self._update_order(client_order_id, status="UNKNOWN")
            return "UNKNOWN"
        orders = getattr(self.main_engine, "get_all_orders", None)
        if callable(orders):
            try:
                current_orders = list(orders())
            except Exception:  # noqa: BLE001 - a disconnected OMS cannot resolve timeout.
                current_orders = []
            for order in current_orders:
                broker_order_id = str(_field(order, "vt_orderid", ""))
                explicit_order_ref = _field(order, "order_ref")
                order_id = str(_field(order, "orderid", ""))
                broker_order_ref = order_id.rsplit("_", 1)[-1]
                if (
                    _field(order, "reference") != client_order_id
                    and str(explicit_order_ref) != order_ref
                    and broker_order_ref != order_ref
                ):
                    continue
                status = self._order_status(order)
                self._update_order(
                    client_order_id,
                    status=status,
                    broker_order_id=broker_order_id or None,
                    traded=_number(_field(order, "traded")),
                )
                return status
        self._update_order(client_order_id, status="UNKNOWN")
        return "UNKNOWN"

    def _update_order(
        self,
        client_order_id: str,
        *,
        status: str,
        broker_order_id: str | None = None,
        traded: float | None = None,
    ) -> None:
        fields = ["status=?", "updated_at=?"]
        values: list[Any] = [status, _utc_now()]
        if broker_order_id is not None:
            fields.append("broker_order_id=?")
            values.append(broker_order_id)
        if traded is not None:
            fields.append("traded=?")
            values.append(traded)
        values.append(client_order_id)
        with self._connect() as db:
            db.execute(f"UPDATE orders SET {','.join(fields)} WHERE client_order_id=?", values)

    def _mark_submitted(self, client_order_id: str, broker_order_id: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE orders SET broker_order_id=?,status=CASE WHEN status IN ('FILLED','CANCELLED','REJECTED') THEN status ELSE 'SUBMITTED' END,updated_at=? WHERE client_order_id=?",
                (broker_order_id, _utc_now(), client_order_id),
            )

    @staticmethod
    def _order_status(order: Any) -> str:
        status_name = _enum_text(_field(order, "status")).upper().replace("_", "")
        return {
            "ALLTRADED": "FILLED",
            "CANCELLED": "CANCELLED",
            "REJECTED": "REJECTED",
        }.get(status_name, "SUBMITTED")

    def _sending_order(self, value: Any) -> str | None:
        if not isinstance(self._sending, Mapping):
            return None
        if _canonical_vt_symbol(_field(value, "vt_symbol")) != self._sending["symbol"]:
            return None
        if _enum_text(_field(value, "direction")).upper() != self._sending["direction"]:
            return None
        if _enum_text(_field(value, "offset")).upper() != self._sending["offset"]:
            return None
        if _number(_field(value, "volume")) > self._sending["quantity"]:
            return None
        return str(self._sending["client_order_id"])

    def _on_order(self, event: Any) -> None:
        order = event.data
        if _field(order, "gateway_name") != self.gateway_name:
            return
        broker_order_id = str(_field(order, "vt_orderid", ""))
        reference = str(_field(order, "reference", ""))
        status = self._order_status(order)
        client_order_id = self._sending_order(order)
        with self._connect() as db:
            row = db.execute(
                "SELECT client_order_id FROM orders WHERE broker_order_id=? OR client_order_id=? ORDER BY created_at DESC LIMIT 1",
                (broker_order_id, reference),
            ).fetchone()
        if row or client_order_id:
            self._update_order(
                row["client_order_id"] if row else client_order_id,
                status=status,
                broker_order_id=broker_order_id or None,
                traded=_number(_field(order, "traded")),
            )
        self._notify(event)

    def _on_trade(self, event: Any) -> None:
        trade = event.data
        if _field(trade, "gateway_name") != self.gateway_name:
            return
        broker_order_id = str(_field(trade, "vt_orderid", ""))
        if not broker_order_id:
            orderid = str(_field(trade, "orderid", ""))
            broker_order_id = f"{self.gateway_name}.{orderid}" if orderid else ""
        trade_id = str(_field(trade, "tradeid", ""))
        volume = _number(_field(trade, "volume"))
        if not broker_order_id or not trade_id or volume <= 0:
            return
        pending_client_order_id = self._sending_order(trade)
        with self._connect() as db:
            order = db.execute(
                "SELECT * FROM orders WHERE broker_order_id=? ORDER BY created_at DESC LIMIT 1",
                (broker_order_id,),
            ).fetchone()
            if order is None and pending_client_order_id:
                order = db.execute(
                    "SELECT * FROM orders WHERE client_order_id=?",
                    (pending_client_order_id,),
                ).fetchone()
            if order:
                price = _number(_field(trade, "price"))
                slippage = price - order["touch_price"] if order["direction"] == "LONG" else order["touch_price"] - price
                trade_key = str(_field(trade, "vt_tradeid", "")) or f"{broker_order_id}.{trade_id}"
                db.execute(
                    "INSERT OR IGNORE INTO trades VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        trade_key,
                        order["run_id"],
                        order["client_order_id"],
                        broker_order_id,
                        trade_id,
                        str(_field(trade, "vt_symbol", order["symbol"])),
                        _enum_text(_field(trade, "direction")),
                        _enum_text(_field(trade, "offset")),
                        price,
                        volume,
                        str(_field(trade, "datetime", "")),
                        slippage,
                        _utc_now(),
                    ),
                )
        self._notify(event)

    def _on_account(self, event: Any) -> None:
        if _field(event.data, "gateway_name") == self.gateway_name:
            with self._condition:
                self._account_generation += 1
                self._condition.notify_all()

    def _notify(self, _event: Any) -> None:
        with self._condition:
            self._condition.notify_all()

    def _wait_orders(self, run_id: str) -> None:
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            with self._connect() as db:
                statuses = [row[0] for row in db.execute("SELECT status FROM orders WHERE run_id=?", (run_id,))]
            if statuses and all(status in _TERMINAL for status in statuses):
                return
            with self._condition:
                self._condition.wait(min(0.25, max(0.0, deadline - time.monotonic())))

    def simnow_lab_apply_target_v1(self, value: Any) -> dict[str, Any]:
        target = validate_target_v1(value)
        if not self._thread_lock.acquire(blocking=False):
            raise SimNowLabError("LAB_ALREADY_RUNNING")
        try:
            with self._process_lock.hold():
                run_id = uuid.uuid4().hex
                self._insert_run(run_id, target)
                try:
                    facts = self._fresh_facts()
                    self._snapshot(run_id, "BEFORE", facts)
                    target_map = {row["vt_symbol"]: row["quantity"] for row in target["targets"]}
                    if facts["active_orders"]:
                        self._finish_run(run_id, "PARTIAL", "ACTIVE_ORDERS_PRESENT")
                        return self.simnow_lab_get_run_v1(run_id)
                    if self._at_target(target_map, facts["positions"]):
                        self._finish_run(run_id, "NOOP")
                        return self.simnow_lab_get_run_v1(run_id)
                    results = []
                    for plan in self._plans(target_map, facts["positions"]):
                        result = self._send(run_id, plan)
                        results.append(result)
                        if result == "UNKNOWN":
                            self._finish_run(run_id, "FAILED", "UNKNOWN_ORDER_PRESENT")
                            return self.simnow_lab_get_run_v1(run_id)
                    self._wait_orders(run_id)
                    final_facts = self._fresh_facts()
                    self._snapshot(run_id, "AFTER", final_facts)
                    if self._at_target(target_map, final_facts["positions"]):
                        self._finish_run(run_id, "DONE")
                    elif results and all(result == "REJECTED" for result in results):
                        self._finish_run(run_id, "FAILED", "ORDERS_REJECTED")
                    else:
                        self._finish_run(run_id, "PARTIAL")
                    return self.simnow_lab_get_run_v1(run_id)
                except SimNowLabError as exc:
                    self._finish_run(run_id, "FAILED", exc.code)
                    return self.simnow_lab_get_run_v1(run_id)
        finally:
            self._thread_lock.release()

    def simnow_lab_get_run_v1(self, run_id: Any) -> dict[str, Any]:
        if run_id == "CURRENT":
            return self._current()
        if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
            raise SimNowLabError("RUN_ID_INVALID")
        with self._connect() as db:
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise SimNowLabError("RUN_NOT_FOUND")
            orders = [dict(row) for row in db.execute("SELECT * FROM orders WHERE run_id=? ORDER BY created_at", (run_id,))]
            trades = [dict(row) for row in db.execute("SELECT * FROM trades WHERE run_id=? ORDER BY created_at", (run_id,))]
            snapshots = [dict(row) for row in db.execute("SELECT * FROM snapshots WHERE run_id=? ORDER BY observed_at", (run_id,))]
        return {"run": dict(run), "orders": orders, "trades": trades, "snapshots": snapshots}

    def _current(self) -> dict[str, Any]:
        if not self._thread_lock.acquire(blocking=False):
            raise SimNowLabError("LAB_ALREADY_RUNNING")
        try:
            active_orders, positions = self._query_orders(), self._query_positions()
            result: list[dict[str, Any]] = []
            for row in positions:
                vt_symbol = _canonical_vt_symbol(_field(row, "vt_symbol"))
                if vt_symbol is None:
                    vt_symbol = _canonical_vt_symbol(
                        f"{_field(row, 'symbol')}.{_enum_text(_field(row, 'exchange'))}"
                    )
                direction = _enum_text(_field(row, "direction")).upper()
                volume = _number(_field(row, "volume"))
                yd_volume = _number(_field(row, "yd_volume"))
                if (
                    vt_symbol is None
                    or direction not in {"LONG", "SHORT"}
                    or volume < 0
                    or yd_volume < 0
                    or not volume.is_integer()
                    or not yd_volume.is_integer()
                ):
                    raise SimNowLabError("BROKER_FACT_INVALID")
                result.append(
                    {
                        "vt_symbol": vt_symbol,
                        "direction": direction,
                        "volume": int(volume),
                        "yd_volume": int(yd_volume),
                    }
                )
            return {
                "status": "CURRENT",
                "positions": sorted(result, key=lambda item: (item["vt_symbol"], item["direction"])),
                "active_order_count": len(active_orders),
            }
        finally:
            self._thread_lock.release()


def attach_windows_simnow_lab_v1(*, runtime: Any, db_path: str | Path) -> SimNowLabExecutorV1:
    """Attach the two Lab RPCs before the existing server registry is sealed."""

    if getattr(getattr(runtime, "config", None), "environment", "simnow") != "simnow":
        raise SimNowLabError("SIMNOW_LAB_ENVIRONMENT_INVALID")
    server = runtime.rpc_engine.server
    functions = getattr(server, "_functions", None)
    if not isinstance(functions, dict) or not callable(getattr(server, "register", None)):
        raise SimNowLabError("RPC_REGISTRY_UNAVAILABLE")
    active = getattr(server, "is_active", None)
    if callable(active) and active():
        raise SimNowLabError("RPC_LISTENER_STARTED_EARLY")
    if getattr(server, _ATTACH_MARKER, None) is not None:
        raise SimNowLabError("LAB_ALREADY_ATTACHED")
    executor = SimNowLabExecutorV1(
        main_engine=runtime.main_engine,
        event_engine=runtime.event_engine,
        gateway_name=runtime.config.gateway_name,
        db_path=Path(db_path),
    )
    server.register(executor.simnow_lab_apply_target_v1)
    server.register(executor.simnow_lab_get_run_v1)
    if not callable(functions.get(RPC_APPLY)) or not callable(functions.get(RPC_GET)):
        raise SimNowLabError("RPC_REGISTRATION_INCOMPLETE")
    setattr(server, _ATTACH_MARKER, executor)
    return executor


__all__ = [
    "SimNowLabError",
    "SimNowLabExecutorV1",
    "attach_windows_simnow_lab_v1",
    "validate_target_v1",
]
