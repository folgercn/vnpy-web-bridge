from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from threading import RLock
from time import monotonic
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo

from app.core.config import Settings, get_settings
from app.core.errors import (
    DeploymentDrainActiveError,
    RpcCallError,
    RpcTimeoutError,
    RpcUnavailableError,
)
from app.schemas.common import to_plain_dict, to_plain_list
from app.services.market_data_service import market_data_service
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
    deployment_drain_for,
)
from app.services.tick_persistence import tick_persistence_service
from app.stores.memory_store import memory_store
from app.ws.events import ws_message
from app.ws.manager import ws_manager

try:
    from vnpy.rpc import RpcClient
    from vnpy.trader.constant import Exchange, Interval
    from vnpy.trader.event import EVENT_ORDER, EVENT_TICK, EVENT_TRADE
    from vnpy.trader.object import CancelRequest, HistoryRequest, OrderRequest, SubscribeRequest
except ImportError:  # pragma: no cover - covered in deployments with vn.py installed
    RpcClient = object  # type: ignore[assignment,misc]
    Exchange = Interval = None  # type: ignore[assignment]
    EVENT_ORDER = "eOrder"
    EVENT_TICK = "eTick"
    EVENT_TRADE = "eTrade"
    CancelRequest = HistoryRequest = None  # type: ignore[assignment]
    OrderRequest = None  # type: ignore[assignment]
    SubscribeRequest = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

RETRYABLE_RPC_METHODS = {
    "get_all_accounts",
    "get_all_contracts",
    "get_all_positions",
    "get_all_orders",
    "get_all_active_orders",
    "get_all_trades",
    "get_all_strategy_status",
    "get_strategy_status",
    "get_all_strategies",
    "get_strategy_parameters",
    "get_strategy_setting",
    "get_strategy_config",
    "get_strategy_variables",
    "get_strategy_variable",
    "get_gateway_status",
    "get_order",
    "get_bars",
    "query_history",
}


class _CFastTerminalPublicationCapability:
    __slots__ = ("service", "owner")

    def __init__(self, service: "VnpyRpcService", owner: object) -> None:
        self.service = service
        self.owner = owner

    def __reduce__(self) -> object:
        raise TypeError("C_FAST terminal publication capability is process-local")


class _CFastTerminalPublicationTicket:
    __slots__ = ("capability", "event_generation", "session_id", "used")

    def __init__(
        self,
        capability: _CFastTerminalPublicationCapability,
        session_id: str,
        event_generation: int,
    ) -> None:
        self.capability = capability
        self.session_id = session_id
        self.event_generation = event_generation
        self.used = False

    def __reduce__(self) -> object:
        raise TypeError("C_FAST terminal publication ticket is process-local")


class BridgeRpcClient(RpcClient):  # type: ignore[misc,valid-type]
    def __init__(self, service: "VnpyRpcService") -> None:
        super().__init__()
        self.service = service

    def callback(self, topic: str, data: Any) -> None:
        self.service.handle_event(topic, data)


class VnpyRpcService:
    def __init__(
        self,
        settings: Settings | None = None,
        deployment_drain: DeploymentDrainService | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.deployment_drain = deployment_drain or deployment_drain_for(
            self.settings.deployment_drain_state_root,
            allow_initial_bootstrap=(
                self.settings.deployment_drain_initial_bootstrap_allowed
                or self.settings.app_env.lower() == "test"
            ),
        )
        self.client: BridgeRpcClient | None = None
        self.started = False
        self.last_connected_at: datetime | None = None
        self.last_error: str | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self._call_lock = RLock()
        self._subscription_lock = RLock()
        self._order_trade_event_lock = RLock()
        self._order_trade_event_generation = 0
        self._c_fast_terminal_publication_capability: (
            _CFastTerminalPublicationCapability | None
        ) = None
        self._c_fast_terminal_publication_active = False
        self._c_fast_terminal_publication_committing = False
        self._market_subscriptions: set[str] = set()
        self._readonly_tick_listeners: list[Callable[[Mapping[str, Any]], object]] = []
        self._last_probe_at = 0.0
        self._last_probe_connected: bool | None = None
        self._probe_ttl_seconds = 5.0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def bind_readonly_tick_listener(
        self,
        listener: Callable[[Mapping[str, Any]], object],
    ) -> None:
        """Bind a local publish-only Tick copy listener before RPC startup.

        The listener receives no service/client handle and this method never
        performs an upstream market subscription.
        """

        if not callable(listener):
            raise ValueError("readonly Tick listener must be callable")
        with self._subscription_lock:
            if self.started:
                raise ValueError("readonly Tick listeners must bind before start")
            if listener not in self._readonly_tick_listeners:
                self._readonly_tick_listeners.append(listener)

    def bind_c_fast_terminal_publication_owner(
        self,
        owner: object,
    ) -> object:
        """Bind one process-local owner to the narrow terminal publisher."""

        if owner is None:
            raise ValueError("C_FAST terminal publication owner is required")
        with self._order_trade_event_lock:
            existing = self._c_fast_terminal_publication_capability
            if existing is not None:
                if existing.owner is not owner:
                    raise ValueError(
                        "C_FAST terminal publication owner is already bound"
                    )
                return existing
            capability = _CFastTerminalPublicationCapability(self, owner)
            self._c_fast_terminal_publication_capability = capability
            return capability

    def prepare_c_fast_terminal_publication(
        self,
        capability: object,
        *,
        session_id: str,
    ) -> object:
        """Pin callback generation for one named terminal session."""

        with self._order_trade_event_lock:
            trusted = self._require_c_fast_terminal_capability(capability)
            if (
                not session_id.startswith("cfast-shakedown-")
                or len(session_id) != len("cfast-shakedown-") + 32
            ):
                raise ValueError("C_FAST terminal publication session is invalid")
            return _CFastTerminalPublicationTicket(
                trusted,
                session_id,
                self._order_trade_event_generation,
            )

    def publish_c_fast_terminal_archive(
        self,
        capability: object,
        ticket: object,
        *,
        session_id: str,
        publisher: Callable[[int], Any],
        committer: Callable[[Any], Any] | None = None,
    ) -> Any:
        """Replay outside locks, then generation-check and commit under lock.

        This capability is deliberately limited to the single bound C_FAST
        owner and a one-shot session ticket.  It does not expose the lock or
        authorize any RPC/trading operation.
        """

        with self._order_trade_event_lock:
            trusted = self._require_c_fast_terminal_capability(capability)
            if (
                not isinstance(ticket, _CFastTerminalPublicationTicket)
                or ticket.capability is not trusted
                or ticket.session_id != session_id
                or ticket.used
            ):
                raise ValueError("C_FAST terminal publication ticket is invalid")
            ticket.used = True
            if ticket.event_generation != self._order_trade_event_generation:
                raise RpcCallError(
                    "C_FAST callback generation drifted before publication",
                    detail={
                        "expected_event_generation": ticket.event_generation,
                        "observed_event_generation": (
                            self._order_trade_event_generation
                        ),
                    },
                )
            if self._c_fast_terminal_publication_active:
                raise RpcCallError("C_FAST terminal publication is already active")
            if not callable(publisher):
                raise ValueError("C_FAST terminal publisher is required")
            if committer is not None and not callable(committer):
                raise ValueError("C_FAST terminal committer is invalid")
            self._c_fast_terminal_publication_active = True
            generation = self._order_trade_event_generation
        try:
            # Blocking RPC snapshots cannot run under the callback lock:
            # reconnect owns _call_lock while joining callback threads.
            result = publisher(generation)
            with self._order_trade_event_lock:
                if self._order_trade_event_generation != generation:
                    raise RpcCallError(
                        "C_FAST callback generation changed before commit"
                    )
                if committer is None:
                    return result
                self._c_fast_terminal_publication_committing = True
                try:
                    committed = committer(result)
                    if self._order_trade_event_generation != generation:
                        raise RpcCallError(
                            "C_FAST callback generation changed inside commit"
                        )
                    return committed
                finally:
                    self._c_fast_terminal_publication_committing = False
        finally:
            with self._order_trade_event_lock:
                self._c_fast_terminal_publication_active = False

    def _require_c_fast_terminal_capability(
        self,
        capability: object,
    ) -> _CFastTerminalPublicationCapability:
        trusted = self._c_fast_terminal_publication_capability
        if (
            trusted is None
            or capability is not trusted
            or trusted.service is not self
        ):
            raise ValueError("C_FAST terminal publication capability is invalid")
        return trusted

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
            self._record_connected_generation(
                datetime.now(ZoneInfo("Asia/Shanghai"))
            )
            self.last_error = None
            logger.info("vn.py RPC started")
        except Exception as exc:
            self.last_error = str(exc)
            self.started = False
            logger.exception("vn.py RPC start failed")
            raise RpcUnavailableError("RPC 启动失败", detail={"error": str(exc)}) from exc

    def _record_connected_generation(self, connected_at: datetime) -> None:
        with self._order_trade_event_lock:
            self.last_connected_at = connected_at
            self._order_trade_event_generation += 1

    def stop(self) -> None:
        if self.client and self.started:
            self.client.stop()
            self.client.join()
        self.started = False
        self.client = None
        self._last_probe_at = 0.0
        self._last_probe_connected = None

    def status(self, *, probe: bool = False) -> dict[str, Any]:
        connected = self.started
        if probe and self.started and self.client:
            now = monotonic()
            if now - self._last_probe_at >= self._probe_ttl_seconds:
                self._last_probe_at = now
                try:
                    self.call("get_all_accounts", timeout=1_000)
                    self._last_probe_connected = True
                    self.last_error = None
                except Exception as exc:
                    self._last_probe_connected = False
                    self.last_error = str(exc)
            if self._last_probe_connected is False:
                connected = False

        return {
            "connected": connected,
            "req_address": self.settings.vnpy_rpc_req_address,
            "pub_address": self.settings.vnpy_rpc_pub_address,
            "gateway_name": self.settings.vnpy_gateway_name,
            "last_connected_at": self.last_connected_at.isoformat() if self.last_connected_at else None,
            "last_error": self.last_error,
        }

    def call(self, name: str, *args: Any, timeout: int | None = None, **kwargs: Any) -> Any:
        if name == "send_order":
            try:
                with self.deployment_drain.mutation_guard():
                    return self._call_under_deployment_gate(
                        name, *args, timeout=timeout, **kwargs
                    )
            except DeploymentDrainError as exc:
                raise DeploymentDrainActiveError(
                    detail={"gate_code": exc.code}
                ) from exc
        return self._call_under_deployment_gate(
            name, *args, timeout=timeout, **kwargs
        )

    def _call_under_deployment_gate(
        self,
        name: str,
        *args: Any,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> Any:
        if not self.started or not self.client:
            raise RpcUnavailableError()

        call_timeout = timeout or self.settings.vnpy_rpc_timeout_ms
        try:
            with self._call_lock:
                return self._call_client(name, *args, timeout=call_timeout, **kwargs)
        except TimeoutError as exc:
            self.last_error = str(exc)
            self._rebuild_client_after_failure(name, str(exc))
            raise RpcTimeoutError(detail={"method": name, "timeout_ms": call_timeout}) from exc
        except Exception as exc:
            self.last_error = str(exc)
            message = str(exc)
            if "timeout" in message.lower():
                self._rebuild_client_after_failure(name, message)
                raise RpcTimeoutError(detail={"method": name, "timeout_ms": call_timeout}) from exc
            if self._is_recoverable_client_state_error(message):
                return self._reconnect_and_maybe_retry(name, *args, timeout=call_timeout, original_error=message, **kwargs)
            raise RpcCallError(detail={"method": name, "error": message}) from exc

    def _call_client(self, name: str, *args: Any, timeout: int, **kwargs: Any) -> Any:
        if not self.client:
            raise RpcUnavailableError()
        method = getattr(self.client, name)
        return method(*args, timeout=timeout, **kwargs)

    def _reconnect_and_maybe_retry(self, name: str, *args: Any, timeout: int, original_error: str, **kwargs: Any) -> Any:
        logger.warning("vn.py RPC client state error, reconnecting before handling %s: %s", name, original_error)
        try:
            with self._call_lock:
                self._restart_client()
                if name not in RETRYABLE_RPC_METHODS:
                    raise RpcCallError(
                        detail={
                            "method": name,
                            "error": original_error,
                            "client_rebuilt": True,
                            "retry_suppressed": "non_idempotent_method",
                        }
                    )
                result = self._call_client(name, *args, timeout=timeout, **kwargs)
                self.last_error = None
                return result
        except TimeoutError as exc:
            self.last_error = str(exc)
            raise RpcTimeoutError(detail={"method": name, "timeout_ms": timeout, "retried_after_reconnect": True}) from exc
        except RpcUnavailableError:
            raise
        except RpcCallError:
            raise
        except Exception as exc:
            self.last_error = str(exc)
            message = str(exc)
            if "timeout" in message.lower():
                raise RpcTimeoutError(detail={"method": name, "timeout_ms": timeout, "retried_after_reconnect": True}) from exc
            raise RpcCallError(
                detail={
                    "method": name,
                    "error": message,
                    "original_error": original_error,
                    "client_rebuilt": True,
                    "retried_after_reconnect": True,
                }
            ) from exc

    def _rebuild_client_after_failure(self, name: str, error: str) -> None:
        logger.warning("vn.py RPC call failed, rebuilding client before next request %s: %s", name, error)
        try:
            with self._call_lock:
                self._restart_client()
        except Exception:
            logger.warning("vn.py RPC client rebuild failed after %s error", name, exc_info=True)

    def _restart_client(self) -> None:
        old_client = self.client
        if old_client:
            try:
                old_client.stop()
            except Exception:
                logger.warning("vn.py RPC client stop failed during reconnect", exc_info=True)
            try:
                old_client.join()
            except Exception:
                logger.warning("vn.py RPC client join failed during reconnect", exc_info=True)

        self.started = False
        self.client = None
        self._last_probe_at = 0.0
        self._last_probe_connected = None
        self.start()

    def _is_recoverable_client_state_error(self, message: str) -> bool:
        return "operation cannot be accomplished in current state" in message.lower()

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

    def get_all_orders(self) -> list[dict[str, Any]]:
        """Return complete order history without active-only fallback."""
        return to_plain_list(self.call("get_all_orders"))

    def get_trades(self) -> list[dict[str, Any]]:
        return to_plain_list(self.call_first(["get_all_trades"]))

    def get_bars(self, symbol: str, exchange: str, interval: str = "1m", limit: int = 300) -> list[dict[str, Any]]:
        local_bars = market_data_service.get_bars(symbol, exchange, interval, limit)
        if local_bars:
            return local_bars

        if HistoryRequest is not None and Exchange is not None and Interval is not None:
            try:
                exchange_value = self._parse_exchange(exchange)
                interval_value = self._parse_interval(interval)
                end = datetime.now(ZoneInfo("Asia/Shanghai"))
                start = end - timedelta(minutes=max(limit, 1) * _interval_minutes(interval))
                request = HistoryRequest(symbol=symbol, exchange=exchange_value, interval=interval_value, start=start, end=end)
                return to_plain_list(self.call("query_history", request, self.settings.vnpy_gateway_name))
            except RpcCallError:
                pass

        return to_plain_list(self.call("get_bars", symbol, exchange, interval, limit))

    def get_order_raw(self, vt_orderid: str) -> Any:
        return self.call("get_order", vt_orderid)

    def get_active_orders_raw(self) -> list[Any]:
        orders = self.call_first(["get_all_active_orders", "get_all_orders"])
        return list(orders or [])

    def send_order(self, order_request: "OrderRequest", gateway_name: str) -> Any:
        return self.call("send_order", order_request, gateway_name)

    def send_order_guarded(
        self,
        order_request: "OrderRequest",
        gateway_name: str,
        guard: Callable[[], Any],
        *,
        linearization_lock: Any | None = None,
    ) -> Any:
        """Linearize the final guard and non-idempotent send with abort."""
        try:
            with self.deployment_drain.mutation_guard(), self._call_lock:
                if linearization_lock is None:
                    guard()
                    return self._call_under_deployment_gate(
                        "send_order", order_request, gateway_name
                    )
                with linearization_lock:
                    guard()
                    return self._call_under_deployment_gate(
                        "send_order", order_request, gateway_name
                    )
        except DeploymentDrainError as exc:
            raise DeploymentDrainActiveError(
                detail={"gate_code": exc.code}
            ) from exc

    def cancel_order(self, cancel_request: "CancelRequest", gateway_name: str) -> Any:
        return self.call("cancel_order", cancel_request, gateway_name)

    def subscribe_market(self, symbol: str, exchange: str) -> dict[str, Any]:
        if SubscribeRequest is None or Exchange is None:
            raise RpcUnavailableError("vn.py 未安装")

        exchange_value = self._parse_exchange(exchange)

        req = SubscribeRequest(symbol=symbol, exchange=exchange_value)
        self.call("subscribe", req, self.settings.vnpy_gateway_name)
        vt_symbol = f"{symbol}.{exchange_value.value}"
        with self._subscription_lock:
            self._market_subscriptions.add(vt_symbol)
        return {"symbol": symbol, "exchange": exchange_value.value, "vt_symbol": vt_symbol, "subscribed": True}

    def unsubscribe_market(self, symbol: str, exchange: str) -> dict[str, Any]:
        exchange_value = self._parse_exchange(exchange)
        vt_symbol = f"{symbol}.{exchange_value.value}"
        with self._subscription_lock:
            self._market_subscriptions.discard(vt_symbol)
        memory_store.delete_tick(vt_symbol)
        return {
            "symbol": symbol,
            "exchange": exchange_value.value,
            "vt_symbol": vt_symbol,
            "subscribed": False,
            "rpc_unsubscribe_supported": False,
        }

    def market_subscriptions(self) -> list[str]:
        with self._subscription_lock:
            return sorted(self._market_subscriptions)

    def _parse_exchange(self, exchange: str) -> Any:
        if Exchange is None:
            raise RpcUnavailableError("vn.py 未安装")
        try:
            return Exchange(exchange)
        except ValueError:
            try:
                return Exchange[exchange]
            except KeyError as exc:
                raise RpcCallError("交易所代码无效", detail={"exchange": exchange}) from exc

    def _parse_interval(self, interval: str) -> Any:
        if Interval is None:
            raise RpcUnavailableError("vn.py 未安装")
        value_map = {"1m": "MINUTE", "1h": "HOUR", "1d": "DAILY", "1w": "WEEKLY"}
        name = value_map.get(interval, interval).upper()
        try:
            return Interval(interval)
        except ValueError:
            try:
                return Interval[name]
            except KeyError as exc:
                raise RpcCallError("K线周期无效", detail={"interval": interval}) from exc

    def handle_event(self, topic: str, event: Any) -> None:
        event_type = getattr(event, "type", topic)
        data = getattr(event, "data", event)
        payload = to_plain_dict(data)
        self._merge_computed_fields(payload, data, ("vt_symbol", "vt_orderid", "vt_tradeid"))

        ws_type: str | None = None
        if event_type.startswith(EVENT_TICK):
            ws_type = "tick"
            vt_symbol = payload.get("vt_symbol")
            if vt_symbol:
                tick_persistence_service.enqueue_tick(payload)
            self._publish_readonly_tick(payload)
            if not vt_symbol or not self._is_market_subscribed(str(vt_symbol)):
                return
            memory_store.save_tick(str(vt_symbol), payload)
        elif event_type.startswith(EVENT_ORDER):
            ws_type = "order"
            with self._order_trade_event_lock:
                if self._c_fast_terminal_publication_committing:
                    raise RpcCallError(
                        "order callback attempted reentrant terminal mutation"
                    )
                memory_store.save_order(payload)
                self._order_trade_event_generation += 1
        elif event_type.startswith(EVENT_TRADE):
            ws_type = "trade"
            with self._order_trade_event_lock:
                if self._c_fast_terminal_publication_committing:
                    raise RpcCallError(
                        "trade callback attempted reentrant terminal mutation"
                    )
                memory_store.save_trade(payload)
                self._order_trade_event_generation += 1

        if ws_type and self.loop:
            message = ws_message(ws_type, payload)
            self.loop.call_soon_threadsafe(asyncio.create_task, ws_manager.broadcast(message))

    def _merge_computed_fields(self, payload: dict[str, Any], data: Any, fields: tuple[str, ...]) -> None:
        for field in fields:
            if payload.get(field):
                continue
            value = getattr(data, field, None)
            if value:
                payload[field] = to_plain_dict({"value": value})["value"]

    def _is_market_subscribed(self, vt_symbol: str) -> bool:
        with self._subscription_lock:
            return vt_symbol in self._market_subscriptions

    def _publish_readonly_tick(self, payload: Mapping[str, Any]) -> None:
        with self._subscription_lock:
            listeners = tuple(self._readonly_tick_listeners)
        for listener in listeners:
            try:
                listener(dict(payload))
            except Exception:
                logger.exception("readonly Tick listener failed in isolation")


rpc_service = VnpyRpcService()


def _interval_minutes(interval: str) -> int:
    return {"1m": 1, "1h": 60, "1d": 1440, "1w": 10080}.get(interval, 1)
