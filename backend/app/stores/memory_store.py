from __future__ import annotations

from collections import OrderedDict, deque
from threading import Lock
from typing import Any


class MemoryStore:
    def __init__(self, max_events: int = 500) -> None:
        self._lock = Lock()
        self._max_events = max_events
        self._ticks: dict[str, dict[str, Any]] = {}
        self._orders: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._trades: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._strategy_logs: deque[dict[str, Any]] = deque(maxlen=max_events)

    def save_tick(self, vt_symbol: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._ticks[vt_symbol] = data

    def get_tick(self, vt_symbol: str) -> dict[str, Any] | None:
        with self._lock:
            return self._ticks.get(vt_symbol)

    def delete_tick(self, vt_symbol: str) -> None:
        with self._lock:
            self._ticks.pop(vt_symbol, None)

    def save_order(self, data: dict[str, Any]) -> None:
        with self._lock:
            key = str(data.get("vt_orderid") or data.get("orderid") or "")
            if not key:
                return
            self._orders[key] = data
            self._orders.move_to_end(key, last=False)
            self._trim(self._orders)

    def save_trade(self, data: dict[str, Any]) -> None:
        with self._lock:
            key = str(data.get("vt_tradeid") or data.get("tradeid") or "")
            if not key:
                return
            self._trades[key] = data
            self._trades.move_to_end(key, last=False)
            self._trim(self._trades)

    def orders(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._orders.values())

    def trades(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._trades.values())

    def _trim(self, rows: OrderedDict[str, dict[str, Any]]) -> None:
        while len(rows) > self._max_events:
            rows.popitem(last=True)

    def save_strategy_log(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._strategy_logs.append(data)

    def strategy_logs(self, strategy_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            logs = list(self._strategy_logs)
        if strategy_name:
            return [log for log in logs if log.get("strategy_name") == strategy_name]
        return logs


memory_store = MemoryStore()
