from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.core.config import Settings, get_settings
from app.core.errors import RpcCallError, RpcTimeoutError, RpcUnavailableError
from app.schemas.common import to_plain_dict, to_plain_list
from app.stores.memory_store import memory_store
from app.ws.events import ws_message
from app.ws.manager import ws_manager

try:
    from vnpy.rpc import RpcClient
    from vnpy.trader.constant import Exchange
    from vnpy.trader.event import EVENT_ORDER, EVENT_TICK, EVENT_TRADE
    from vnpy.trader.object import CancelRequest, OrderRequest, SubscribeRequest
except ImportError:  # pragma: no cover - covered in deployments with vn.py installed
    RpcClient = object  # type: ignore[assignment,misc]
    Exchange = None  # type: ignore[assignment]
    EVENT_ORDER = "eOrder"
    EVENT_TICK = "eTick"
    EVENT_TRADE = "eTrade"
    CancelRequest = None  # type: ignore[assignment]
    OrderRequest = None  # type: ignore[assignment]
    SubscribeRequest = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class BridgeRpcClient(RpcClient):  # type: ignore[misc,valid-type]
    def __init__(self, service: "VnpyRpcService") -> None:
        super().__init__()
        self.service = service

    def callback(self, topic: str, data: Any) -> None:
        self.service.handle_event(topic, data)


class VnpyRpcService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.client: BridgeRpcClient | None = None
        self.started = False
        self.last_connected_at: datetime | None = None
        self.last_error: str | None = None
        self.loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def start(self) -> None:
        if self.started:
            return
        if RpcClient is object:
            self.last_error = "vn.py 未安装"
            raise RpcUnavailableError(self.last_error)

        self.client = BridgeRpcClient(self)
        try:
            self.client.subscribe_topic("")
            self.client.start(
                self.settings.vnpy_rpc_req_address,
                self.settings.vnpy_rpc_pub_address,
            )
            self.started = True
            self.last_connected_at = datetime.now(ZoneInfo("Asia/Shanghai"))
            self.last_error = None
            logger.info("vn.py RPC started")
        except Exception as exc:
            self.last_error = str(exc)
            self.started = False
            logger.exception("vn.py RPC start failed")
            raise RpcUnavailableError("RPC 启动失败", detail={"error": str(exc)}) from exc

    def stop(self) -> None:
        if self.client and self.started:
            self.client.stop()
            self.client.join()
        self.started = False
        self.client = None

    def status(self, *, probe: bool = False) -> dict[str, Any]:
        if probe and self.started and self.client:
            try:
                self.call("get_all_contracts", timeout=1_000)
            except Exception as exc:
                self.started = False
                self.last_error = str(exc)

        return {
            "connected": self.started,
            "req_address": self.settings.vnpy_rpc_req_address,
            "pub_address": self.settings.vnpy_rpc_pub_address,
            "gateway_name": self.settings.vnpy_gateway_name,
            "last_connected_at": self.last_connected_at.isoformat() if self.last_connected_at else None,
            "last_error": self.last_error,
        }

    def call(self, name: str, *args: Any, timeout: int | None = None, **kwargs: Any) -> Any:
        if not self.started or not self.client:
            raise RpcUnavailableError()

        call_timeout = timeout or self.settings.vnpy_rpc_timeout_ms
        try:
            method = getattr(self.client, name)
            return method(*args, timeout=call_timeout, **kwargs)
        except TimeoutError as exc:
            self.last_error = str(exc)
            raise RpcTimeoutError(detail={"method": name, "timeout_ms": call_timeout}) from exc
        except Exception as exc:
            self.last_error = str(exc)
            message = str(exc)
            if "timeout" in message.lower():
                raise RpcTimeoutError(detail={"method": name, "timeout_ms": call_timeout}) from exc
            raise RpcCallError(detail={"method": name, "error": message}) from exc

    def call_first(self, names: list[str]) -> Any:
        errors: list[str] = []
        for name in names:
            try:
                return self.call(name)
            except RpcCallError as exc:
                errors.append(f"{name}: {exc.detail.get('error')}")
        raise RpcCallError(detail={"methods": names, "errors": errors})

    def get_contracts(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call("get_all_contracts"))

    def get_accounts(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call("get_all_accounts"))

    def get_positions(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call("get_all_positions"))

    def get_orders(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call_first(["get_all_orders", "get_all_active_orders"]))

    def get_trades(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call_first(["get_all_trades"]))

    def get_order_raw(self, vt_orderid: str) -> Any:
        return self.call("get_order", vt_orderid)

    def get_active_orders_raw(self) -> list[Any]:
        orders = self.call_first(["get_all_active_orders", "get_all_orders"])
        return list(orders or [])

    def send_order(self, order_request: "OrderRequest", gateway_name: str) -> Any:
        return self.call("send_order", order_request, gateway_name)

    def cancel_order(self, cancel_request: "CancelRequest", gateway_name: str) -> Any:
        return self.call("cancel_order", cancel_request, gateway_name)

    def subscribe_market(self, symbol: str, exchange: str) -> dict[str, Any]:
        if SubscribeRequest is None or Exchange is None:
            raise RpcUnavailableError("vn.py 未安装")

        try:
            exchange_value = Exchange(exchange)
        except ValueError:
            try:
                exchange_value = Exchange[exchange]
            except KeyError as exc:
                raise RpcCallError("交易所代码无效", detail={"exchange": exchange}) from exc

        req = SubscribeRequest(symbol=symbol, exchange=exchange_value)
        self.call("subscribe", req, self.settings.vnpy_gateway_name)
        return {"symbol": symbol, "exchange": exchange_value.value, "vt_symbol": f"{symbol}.{exchange_value.value}"}

    def handle_event(self, topic: str, event: Any) -> None:
        event_type = getattr(event, "type", topic)
        data = getattr(event, "data", event)
        payload = to_plain_dict(data)

        ws_type: str | None = None
        if event_type.startswith(EVENT_TICK):
            ws_type = "tick"
            vt_symbol = payload.get("vt_symbol")
            if vt_symbol:
                memory_store.save_tick(str(vt_symbol), payload)
        elif event_type.startswith(EVENT_ORDER):
            ws_type = "order"
            memory_store.save_order(payload)
        elif event_type.startswith(EVENT_TRADE):
            ws_type = "trade"
            memory_store.save_trade(payload)

        if ws_type and self.loop:
            message = ws_message(ws_type, payload)
            self.loop.call_soon_threadsafe(asyncio.create_task, ws_manager.broadcast(message))


rpc_service = VnpyRpcService()
