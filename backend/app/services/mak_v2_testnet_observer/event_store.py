from __future__ import annotations

from collections import deque
from datetime import date
from threading import Lock
from typing import Any


class MakV2ObserverEventStore:
    def __init__(self, max_rows: int = 5_000) -> None:
        self.max_rows = max_rows
        self._lock = Lock()
        self.signals: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.decisions: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.order_intents: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.order_acks: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.status_events: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.fills: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.position_reconciliations: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.horizon_exits: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.pnl_comparisons: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.guardrails: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.safety_audits: deque[dict[str, Any]] = deque(maxlen=max_rows)
        self.daily_summaries: dict[str, dict[str, Any]] = {}

    def append_signal(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.signals.appendleft(row)

    def append_decision(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.decisions.appendleft(row)

    def append_order_intent(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.order_intents.appendleft(row)

    def append_guardrail(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.guardrails.appendleft(row)

    def append_safety_audit(self, row: dict[str, Any]) -> None:
        with self._lock:
            self.safety_audits.appendleft(row)

    def list_rows(self, name: str, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(getattr(self, name))
        return rows[:limit]

    def latest_safety_audit(self) -> dict[str, Any] | None:
        with self._lock:
            return self.safety_audits[0] if self.safety_audits else None

    def update_daily_summary(self, trading_day: date | str) -> dict[str, Any]:
        day = trading_day.isoformat() if isinstance(trading_day, date) else str(trading_day)
        with self._lock:
            signals = [row for row in self.signals if str(row.get("local_date")) == day]
            intents = [row for row in self.order_intents if str(row.get("local_date")) == day]
            blocked = [row for row in self.decisions if str(row.get("local_date")) == day and row.get("decision") == "blocked"]
            guardrails = [row for row in self.guardrails if str(row.get("local_date")) == day]
            summary = {
                "date": day,
                "signals_total": len(signals),
                "eligible_signals": sum(1 for row in signals if row.get("eligible_for_testnet")),
                "orders_submitted": 0,
                "orders_filled": 0,
                "orders_rejected": 0,
                "orders_canceled": 0,
                "partial_fills": 0,
                "fill_rate": 0.0,
                "reject_rate": 0.0,
                "avg_ack_latency_ms": None,
                "avg_fill_latency_ms": None,
                "avg_slippage_ticks": None,
                "testnet_net_pnl": 0.0,
                "hypothetical_net_pnl": None,
                "pnl_divergence": None,
                "max_intraday_drawdown": None,
                "lc_signal_count": sum(1 for row in signals if row.get("instrument") == "lc"),
                "ps_signal_count": sum(1 for row in signals if row.get("instrument") == "ps"),
                "lc_testnet_pnl": 0.0,
                "ps_testnet_pnl": 0.0,
                "cluster_max_overlap": max((int(row.get("active_overlap_900s") or 0) for row in signals), default=0),
                "missing_quote_rate": sum(1 for row in blocked if row.get("decision_reason") == "L1 missing") / len(signals) if signals else 0.0,
                "guardrail_triggers": len(guardrails),
                "dry_run_intents": len(intents),
                "daily_decision": "DRY_RUN_ONLY",
            }
            self.daily_summaries[day] = summary
            return dict(summary)

    def latest_daily_summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(sorted(self.daily_summaries.values(), key=lambda row: str(row["date"]), reverse=True))
