from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, time, timedelta, timezone
import logging
from threading import Lock
from typing import Any, Callable

from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.services.alert_service import AlertService, alert_service
from app.services.market_data_service import QuestDbMarketDataService, market_data_service
from app.services.risk_service import RiskService, risk_service
from app.services.strategy_service import StrategyService, strategy_service
from app.services.tick_persistence import TickPersistenceService, tick_persistence_service
from app.services.vnpy_rpc_service import VnpyRpcService, rpc_service
from app.services.watchlist_service import WatchlistService, watchlist_service
from app.stores.memory_store import MemoryStore, memory_store

logger = logging.getLogger(__name__)

WindowEvent = tuple[datetime, str]


class MonitoringService:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        alerts: AlertService | None = None,
        rpc: VnpyRpcService | None = None,
        market_store: QuestDbMarketDataService | None = None,
        tick_persistence: TickPersistenceService | None = None,
        postgres: WatchlistService | None = None,
        strategies: StrategyService | None = None,
        risk: RiskService | None = None,
        store: MemoryStore | None = None,
        now_func: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.alerts = alerts or alert_service
        self.rpc = rpc or rpc_service
        self.market_store = market_store or market_data_service
        self.tick_persistence = tick_persistence or tick_persistence_service
        self.postgres = postgres or watchlist_service
        self.strategies = strategies or strategy_service
        self.risk = risk or risk_service
        self.store = store or memory_store
        self.now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._lock = Lock()
        self._last_snapshot: dict[str, Any] = {"checks": [], "checked_at": None}
        self._http_5xx: deque[WindowEvent] = deque()
        self._trade_failures: deque[WindowEvent] = deque()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task or not self.settings.monitor_enabled:
            return
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        if not self._task:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._last_snapshot)

    def run_checks(self, *, probe_rpc: bool = True) -> dict[str, Any]:
        now = self.now_func()
        checks: list[dict[str, Any]] = []
        suppressed: list[dict[str, Any]] = []
        rpc_connected = self._check_rpc(checks, now, probe=probe_rpc)
        if rpc_connected:
            self._check_gateway(checks, now)
            self._check_strategies(checks, now)
            self._check_daily_loss(checks, now)
            self._check_tick_freshness(checks, suppressed, now)
        else:
            suppressed.extend(
                [
                    {"rule_id": "gateway_disconnected", "scope_id": self.settings.vnpy_gateway_name, "suppressed_by": "rpc_unavailable"},
                    {"rule_id": "tick_stale", "scope_id": "market_ticks", "suppressed_by": "rpc_unavailable"},
                    {"rule_id": "strategy_unexpected_stop", "scope_id": "*", "suppressed_by": "rpc_unavailable"},
                ]
            )

        self._check_questdb(checks, now)
        self._check_postgres(checks, now)
        self._check_risk(checks, now)
        self._check_http_5xx(checks, now)
        self._check_trade_failures(checks, now)

        snapshot = {
            "checked_at": iso(now),
            "checks": checks,
            "suppressed": suppressed,
            "incidents": self.alerts.list_incidents(include_resolved=False),
            "summary": self.alerts.summary(),
        }
        with self._lock:
            self._last_snapshot = snapshot
        return snapshot

    def record_http_response(self, status_code: int, path: str) -> None:
        if status_code < 500:
            return
        now = self.now_func()
        with self._lock:
            self._http_5xx.append((now, path))
            self._trim_window(self._http_5xx, now, self.settings.monitor_http_5xx_window_seconds)

    def record_trade_failure(self, kind: str, error_code: str) -> None:
        now = self.now_func()
        with self._lock:
            self._trade_failures.append((now, f"{kind}:{error_code}"))
            self._trim_window(self._trade_failures, now, self.settings.monitor_trade_failure_window_seconds)

    async def _run_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.run_checks)
            except Exception:
                logger.exception("monitoring check cycle failed")
            await asyncio.sleep(self.settings.monitor_interval_seconds)

    def _check_rpc(self, checks: list[dict[str, Any]], now: datetime, *, probe: bool) -> bool:
        try:
            status = self.rpc.status(probe=probe)
            connected = bool(status.get("connected"))
            severity = "critical" if self._production_context_active(now) else "warning"
            summary = "RPC connected" if connected else str(status.get("last_error") or "RPC unavailable")
            incident = self.alerts.record_check(
                rule_id="rpc_unavailable",
                scope_id=self.settings.vnpy_gateway_name,
                healthy=connected,
                severity=severity,
                summary=summary,
                details=_safe_details(status, deny_keys={"req_address", "pub_address"}),
                now=now,
            )
            checks.append(_check("rpc", connected, summary, incident))
            return connected
        except Exception as exc:
            incident = self.alerts.record_check(
                rule_id="rpc_unavailable",
                scope_id=self.settings.vnpy_gateway_name,
                healthy=False,
                severity="critical" if self._production_context_active(now) else "warning",
                summary=f"RPC probe failed: {exc.__class__.__name__}",
                details={"type": exc.__class__.__name__},
                now=now,
            )
            checks.append(_check("rpc", False, str(exc), incident))
            return False

    def _check_gateway(self, checks: list[dict[str, Any]], now: datetime) -> None:
        status = self._gateway_status()
        connected = status["connected"]
        incident = self.alerts.record_check(
            rule_id="gateway_disconnected",
            scope_id=self.settings.vnpy_gateway_name,
            healthy=connected,
            severity="critical",
            summary=status["summary"],
            details=status.get("details", {}),
            now=now,
        )
        checks.append(_check("gateway", connected, status["summary"], incident))

    def _check_questdb(self, checks: list[dict[str, Any]], now: datetime) -> None:
        try:
            status = self.market_store.health_check()
            healthy = not status.get("configured") or bool(status.get("connected"))
            severity = "warning"
            summary = "QuestDB disabled" if not status.get("configured") else "QuestDB connected"
        except Exception as exc:
            healthy = False
            severity = "warning"
            summary = f"QuestDB unavailable: {exc.__class__.__name__}"
            status = {"type": exc.__class__.__name__}
        incident = self.alerts.record_check(
            rule_id="questdb_unavailable",
            scope_id="market_ticks",
            healthy=healthy,
            severity=severity,
            summary=summary,
            details=status,
            now=now,
        )
        checks.append(_check("questdb", healthy, summary, incident))

        tick_status = self.tick_persistence.snapshot()
        lag = tick_status.get("persistence_lag_seconds")
        worker_alive = bool(tick_status.get("worker_alive", tick_status.get("running")))
        has_corruption = bool(tick_status.get("corrupt_total") or tick_status.get("quarantined_rows"))
        tick_healthy = not tick_status.get("enabled") or (worker_alive and not tick_status.get("last_error") and not has_corruption)
        if isinstance(lag, (int, float)) and lag >= 300:
            tick_healthy = False
        if not worker_alive and tick_status.get("enabled"):
            summary = "tick persistence writer stopped"
        elif has_corruption:
            summary = str(tick_status.get("last_error") or "tick spool corruption detected")
        elif tick_status.get("last_error"):
            summary = str(tick_status.get("last_error"))
        else:
            summary = f"lag {lag}s"
        tick_incident = self.alerts.record_check(
            rule_id="questdb_tick_persistence_lag",
            scope_id="market_ticks",
            healthy=tick_healthy,
            severity="critical" if isinstance(lag, (int, float)) and lag >= 300 else "warning",
            summary="Tick persistence healthy" if tick_healthy else summary,
            details={
                key: tick_status.get(key)
                for key in (
                    "enabled",
                    "running",
                    "worker_alive",
                    "queue_depth",
                    "spool_rows",
                    "spool_bytes",
                    "corrupt_total",
                    "quarantined_rows",
                    "quarantined_bytes",
                    "oldest_pending_received_at",
                    "persistence_lag_seconds",
                    "consecutive_failures",
                    "last_error",
                )
            },
            now=now,
        )
        checks.append(_check("tick_persistence", tick_healthy, str(tick_incident.get("summary")), tick_incident))

    def _check_postgres(self, checks: list[dict[str, Any]], now: datetime) -> None:
        try:
            status = self.postgres.health_check()
            healthy = not status.get("configured") or bool(status.get("connected"))
            summary = "PostgreSQL disabled" if not status.get("configured") else "PostgreSQL connected"
        except Exception as exc:
            healthy = False
            summary = f"PostgreSQL unavailable: {exc.__class__.__name__}"
            status = {"type": exc.__class__.__name__}
        incident = self.alerts.record_check(
            rule_id="postgres_unavailable",
            scope_id="watchlist",
            healthy=healthy,
            severity="warning",
            summary=summary,
            details=status,
            now=now,
        )
        checks.append(_check("postgres", healthy, summary, incident))

    def _check_tick_freshness(self, checks: list[dict[str, Any]], suppressed: list[dict[str, Any]], now: datetime) -> None:
        subscriptions = self.rpc.market_subscriptions()
        if not subscriptions or not self._trading_session_active(now):
            checks.append({"name": "tick_freshness", "healthy": True, "status": "quiet", "summary": "No active tick freshness requirement"})
            return
        ticks = self.store.ticks()
        stale: list[str] = []
        missing: list[str] = []
        for vt_symbol in subscriptions:
            tick = ticks.get(vt_symbol)
            if not tick:
                missing.append(vt_symbol)
                continue
            tick_at = _parse_tick_time(tick)
            if tick_at is None or (now - tick_at).total_seconds() > self.settings.monitor_tick_stale_seconds:
                stale.append(vt_symbol)
        unhealthy = bool(stale or missing)
        summary = "Ticks fresh" if not unhealthy else f"stale={len(stale)} missing={len(missing)}"
        incident = self.alerts.record_check(
            rule_id="tick_stale",
            scope_id="market_ticks",
            healthy=not unhealthy,
            severity="critical" if self._expected_strategies() else "warning",
            summary=summary,
            details={"stale": stale[:20], "missing": missing[:20], "subscription_count": len(subscriptions)},
            now=now,
        )
        checks.append(_check("tick_freshness", not unhealthy, summary, incident))

    def _check_strategies(self, checks: list[dict[str, Any]], now: datetime) -> None:
        expected = set(self._expected_strategies())
        if not expected:
            checks.append({"name": "strategies", "healthy": True, "status": "quiet", "summary": "No expected strategies configured"})
            return
        try:
            rows = self.strategies.list_strategies()
        except Exception as exc:
            incident = self.alerts.record_check(
                rule_id="strategy_rpc_error",
                scope_id="expected_strategies",
                healthy=False,
                severity="warning",
                summary=f"Strategy status query failed: {exc.__class__.__name__}",
                details={"type": exc.__class__.__name__},
                now=now,
            )
            checks.append(_check("strategies", False, str(incident.get("summary")), incident))
            return
        by_name = {str(item.get("strategy_name")): item for item in rows if item.get("strategy_name")}
        unhealthy = False
        for name in expected:
            item = by_name.get(name)
            running = bool(item and item.get("status") == "running")
            unhealthy = unhealthy or not running
            self.alerts.record_check(
                rule_id="strategy_unexpected_stop",
                scope_id=name,
                healthy=running,
                severity="critical" if self.risk.status().get("web_trade_enabled") else "warning",
                summary="strategy running" if running else "strategy stopped or missing",
                details={"strategy": item or {}, "expected": True},
                now=now,
            )
        checks.append({"name": "strategies", "healthy": not unhealthy, "status": "ok" if not unhealthy else "failed", "summary": f"expected={len(expected)}"})

    def _check_risk(self, checks: list[dict[str, Any]], now: datetime) -> None:
        status = self.risk.status()
        emergency = bool(status.get("emergency_stopped"))
        incident = self.alerts.record_check(
            rule_id="emergency_stop",
            scope_id="global",
            healthy=not emergency,
            severity="critical",
            summary="Emergency stop active" if emergency else "Emergency stop clear",
            details=status,
            now=now,
        )
        checks.append(_check("emergency_stop", not emergency, str(incident.get("summary")), incident))

    def _check_daily_loss(self, checks: list[dict[str, Any]], now: datetime) -> None:
        max_loss = float(self.risk.get_rules().get("max_daily_loss") or 0)
        if max_loss <= 0:
            checks.append({"name": "daily_loss", "healthy": True, "status": "quiet", "summary": "Daily loss limit disabled"})
            return
        try:
            total_pnl = sum(float(position.get("pnl") or 0) for position in self.rpc.get_positions())
        except Exception as exc:
            checks.append({"name": "daily_loss", "healthy": True, "status": "unknown", "summary": f"Daily loss skipped: {exc.__class__.__name__}"})
            return
        breached = total_pnl < 0 and abs(total_pnl) > max_loss
        incident = self.alerts.record_check(
            rule_id="daily_loss_limit",
            scope_id="global",
            healthy=not breached,
            severity="critical",
            summary="Daily loss limit breached" if breached else "Daily loss within limit",
            details={"daily_pnl": total_pnl, "max_daily_loss": max_loss},
            now=now,
        )
        checks.append(_check("daily_loss", not breached, str(incident.get("summary")), incident))

    def _check_http_5xx(self, checks: list[dict[str, Any]], now: datetime) -> None:
        with self._lock:
            self._trim_window(self._http_5xx, now, self.settings.monitor_http_5xx_window_seconds)
            count = len(self._http_5xx)
            paths = [path for _, path in self._http_5xx]
        unhealthy = count >= self.settings.monitor_http_5xx_threshold
        incident = self.alerts.record_check(
            rule_id="http_5xx_rate",
            scope_id="api",
            healthy=not unhealthy,
            severity="warning",
            summary="HTTP 5xx within threshold" if not unhealthy else f"{count} HTTP 5xx responses in window",
            details={"count": count, "sample_paths": paths[-10:]},
            now=now,
        )
        checks.append(_check("http_5xx", not unhealthy, str(incident.get("summary")), incident))

    def _check_trade_failures(self, checks: list[dict[str, Any]], now: datetime) -> None:
        with self._lock:
            self._trim_window(self._trade_failures, now, self.settings.monitor_trade_failure_window_seconds)
            count = len(self._trade_failures)
            kinds = [kind for _, kind in self._trade_failures]
        unhealthy = count >= self.settings.monitor_trade_failure_threshold
        incident = self.alerts.record_check(
            rule_id="trade_route_failures",
            scope_id="orders",
            healthy=not unhealthy,
            severity="critical" if self.risk.status().get("web_trade_enabled") else "warning",
            summary="Trade route failures within threshold" if not unhealthy else f"{count} trade route failures in window",
            details={"count": count, "sample": kinds[-10:]},
            now=now,
        )
        checks.append(_check("trade_failures", not unhealthy, str(incident.get("summary")), incident))

    def _gateway_status(self) -> dict[str, Any]:
        try:
            data = self.rpc.call("get_gateway_status", self.settings.vnpy_gateway_name)
        except AppError:
            return {"connected": True, "summary": "Gateway status method unavailable", "details": {"status": "unknown"}}
        except Exception as exc:
            return {"connected": False, "summary": f"Gateway status query failed: {exc.__class__.__name__}", "details": {"type": exc.__class__.__name__}}
        if isinstance(data, dict):
            raw = str(data.get("status") or data.get("state") or "").lower()
            connected = bool(data.get("connected")) or raw in {"connected", "login", "logged_in", "ok", "active"}
            return {"connected": connected, "summary": "Gateway connected" if connected else "Gateway disconnected", "details": _safe_details(data)}
        connected = bool(data)
        return {"connected": connected, "summary": "Gateway connected" if connected else "Gateway disconnected", "details": {"raw": str(data)}}

    def _production_context_active(self, now: datetime) -> bool:
        if self.risk.status().get("web_trade_enabled"):
            return True
        if self._expected_strategies():
            return True
        return self._trading_session_active(now)

    def _trading_session_active(self, now: datetime) -> bool:
        local = now.astimezone(timezone(timedelta(hours=8)))
        if local.weekday() >= 5:
            return False
        current = local.time()
        return (
            time(9, 0) <= current <= time(11, 30)
            or time(13, 30) <= current <= time(15, 15)
            or time(21, 0) <= current <= time(23, 59)
        )

    def _expected_strategies(self) -> list[str]:
        return [item.strip() for item in self.settings.monitor_expected_strategies.split(",") if item.strip()]

    def _trim_window(self, events: deque[WindowEvent], now: datetime, seconds: int) -> None:
        cutoff = now - timedelta(seconds=seconds)
        while events and events[0][0] < cutoff:
            events.popleft()


def _check(name: str, healthy: bool, summary: str, incident: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "healthy": healthy,
        "status": "ok" if healthy else "failed",
        "summary": summary,
        "incident_id": incident.get("incident_id"),
        "incident_status": incident.get("status"),
        "severity": incident.get("severity"),
    }


def _safe_details(data: dict[str, Any], deny_keys: set[str] | None = None) -> dict[str, Any]:
    deny = {"token", "secret", "password", "dsn", "address", *(deny_keys or set())}
    safe = {}
    for key, value in data.items():
        normalized = key.lower()
        if any(part in normalized for part in deny):
            continue
        safe[key] = value
    return safe


def _parse_tick_time(tick: dict[str, Any]) -> datetime | None:
    value = tick.get("received_at") or tick.get("datetime") or tick.get("ts")
    if isinstance(value, datetime):
        parsed = value
    elif value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


monitoring_service = MonitoringService()
