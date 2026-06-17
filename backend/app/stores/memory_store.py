from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Any


class MemoryStore:
    def __init__(self, max_events: int = 500) -> None:
        self._lock = Lock()
        self._ticks: dict[str, dict[str, Any]] = {}
        self._orders: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._trades: deque[dict[str, Any]] = deque(maxlen=max_events)

    def save_tick(self, vt_symbol: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._ticks[vt_symbol] = data

    def get_tick(self, vt_symbol: str) -> dict[str, Any] | None:
        with self._lock:
            return self._ticks.get(vt_symbol)

    def save_order(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._orders.append(data)

    def save_trade(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._trades.append(data)

    def orders(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._orders)

    def trades(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._trades)


memory_store = MemoryStore()
