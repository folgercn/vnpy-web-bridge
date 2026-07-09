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
    "risk_alert",
    "strategy_status",
    "strategy_log",
    "strategy_variable",
    "mak_v2_signal",
    "mak_v2_order_intent",
    "mak_v2_order_ack",
    "mak_v2_order_status",
    "mak_v2_fill",
    "mak_v2_exit",
    "mak_v2_position_reconcile",
    "mak_v2_guardrail",
    "mak_v2_daily_summary",
}


def ws_message(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": event_type,
        "ts": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="milliseconds"),
        "data": data,
    }
