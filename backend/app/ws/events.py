from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo


EVENT_TYPES = {
    "tick",
    "order",
    "trade",
    "account",
    "position",
    "log",
    "gateway_status",
    "pong",
}


def ws_message(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": event_type,
        "ts": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="milliseconds"),
        "data": data,
    }
