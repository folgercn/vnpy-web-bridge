from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.services.alert_service import AlertService
from app.services.monitoring_service import MonitoringService
from app.stores.alert_state_store import AlertStateStore
from app.stores.memory_store import MemoryStore


class FakeTelegram:
    def config_status(self) -> dict:
        return {"enabled": False, "configured": False, "send_levels": []}

    def send_incident(self, incident: dict, *, event: str) -> dict:
        return {"sent": False, "skipped": "disabled"}


class FakeRpc:
    def __init__(self, *, connected: bool = True, gateway_connected: bool = True) -> None:
        self.connected = connected
        self.gateway_connected = gateway_connected
        self.subscriptions: list[str] = []
        self.positions: list[dict] = []

    def status(self, *, probe: bool = False) -> dict:
        return {"connected": self.connected, "gateway_name": "CTP", "last_error": None if self.connected else "offline"}

    def call(self, name: str, *args):
        if name == "get_gateway_status":
            return {"connected": self.gateway_connected}
        raise RuntimeError(name)

    def market_subscriptions(self) -> list[str]:
        return self.subscriptions

    def get_positions(self) -> list[dict]:
        return self.positions


class HealthyMarketStore:
    def health_check(self) -> dict:
        return {"configured": True, "connected": True, "status": "ok"}


class HealthyPostgres:
    def health_check(self) -> dict:
        return {"configured": True, "connected": True, "status": "ok"}


class HealthyTickPersistence:
    def snapshot(self) -> dict:
        return {"enabled": True, "running": True, "worker_alive": True, "last_error": None, "queue_depth": 0, "spool_rows": 0, "persistence_lag_seconds": 0}


class StoppedTickPersistence:
    def snapshot(self) -> dict:
        return {"enabled": True, "running": False, "worker_alive": False, "last_error": None, "queue_depth": 0, "spool_rows": 0, "persistence_lag_seconds": 0}


class FakeStrategies:
    def __init__(self, rows: list[dict] | None = None) -> None:
        self.rows = rows or []

    def list_strategies(self) -> list[dict]:
        return self.rows


class FakeRisk:
    def __init__(self, *, web_trade_enabled: bool = False, emergency_stopped: bool = False, max_daily_loss: float = 1000) -> None:
        self.web_trade_enabled = web_trade_enabled
        self.emergency_stopped = emergency_stopped
        self.max_daily_loss = max_daily_loss

    def status(self) -> dict:
        return {"web_trade_enabled": self.web_trade_enabled, "emergency_stopped": self.emergency_stopped}

    def get_rules(self) -> dict:
        return {"max_daily_loss": self.max_daily_loss}


def build_service(tmp_path, *, now: datetime, settings: Settings | None = None, **overrides) -> MonitoringService:
    settings = settings or Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_flap_send_grace_seconds=0,
        monitor_flap_recovery_grace_seconds=0,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        monitor_http_5xx_threshold=2,
        monitor_trade_failure_threshold=2,
        monitor_expected_strategies="",
    )
    alerts = AlertService(
        settings=settings,
        store=AlertStateStore(settings.monitor_state_path, settings.monitor_events_path),
        telegram=FakeTelegram(),
    )
    defaults = {
        "alerts": alerts,
        "rpc": FakeRpc(),
        "market_store": HealthyMarketStore(),
        "tick_persistence": HealthyTickPersistence(),
        "postgres": HealthyPostgres(),
        "strategies": FakeStrategies(),
        "risk": FakeRisk(),
        "store": MemoryStore(),
        "now_func": lambda: now,
    }
    defaults.update(overrides)
    return MonitoringService(settings=settings, **defaults)


def test_rpc_failure_suppresses_derived_checks(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now, rpc=FakeRpc(connected=False))

    snapshot = service.run_checks()

    names = {item["name"] for item in snapshot["checks"]}
    assert "rpc" in names
    assert "gateway" not in names
    assert any(item["suppressed_by"] == "rpc_unavailable" for item in snapshot["suppressed"])
    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "rpc_unavailable:CTP")
    assert incident["status"] == "firing"


def test_tick_freshness_records_stale_subscription(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 30, tzinfo=timezone.utc)  # 10:30 Asia/Shanghai
    rpc = FakeRpc()
    rpc.subscriptions = ["rb2610.SHFE"]
    store = MemoryStore()
    store.save_tick("rb2610.SHFE", {"vt_symbol": "rb2610.SHFE", "datetime": (now - timedelta(seconds=300)).isoformat()})
    service = build_service(tmp_path, now=now, rpc=rpc, store=store)

    snapshot = service.run_checks()

    tick_check = next(item for item in snapshot["checks"] if item["name"] == "tick_freshness")
    assert tick_check["healthy"] is False
    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "tick_stale:market_ticks")
    assert incident["details"]["stale"] == ["rb2610.SHFE"]


def test_expected_strategy_stop_records_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    settings = Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_flap_send_grace_seconds=0,
        monitor_flap_recovery_grace_seconds=0,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        monitor_expected_strategies="demo_strategy",
    )
    service = build_service(
        tmp_path,
        now=now,
        settings=settings,
        strategies=FakeStrategies([{"strategy_name": "demo_strategy", "status": "stopped"}]),
        risk=FakeRisk(web_trade_enabled=True),
    )

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "strategy_unexpected_stop:demo_strategy")
    assert incident["severity"] == "critical"
    assert incident["status"] == "firing"


def test_http_5xx_window_records_aggregate_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now)

    service.record_http_response(500, "/api/orders")
    service.record_http_response(502, "/api/rpc/probe")
    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "http_5xx_rate:api")
    assert incident["status"] == "firing"
    assert incident["details"]["count"] == 2


def test_trade_failure_window_records_aggregate_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now, risk=FakeRisk(web_trade_enabled=True))

    service.record_trade_failure("order", "RPC_TIMEOUT")
    service.record_trade_failure("cancel", "RPC_TIMEOUT")
    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "trade_route_failures:orders")
    assert incident["severity"] == "critical"
    assert incident["details"]["count"] == 2


def test_dependency_health_error_records_incident(tmp_path) -> None:
    class BrokenPostgres:
        def health_check(self) -> dict:
            raise RuntimeError("postgres down")

    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now, postgres=BrokenPostgres())

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "postgres_unavailable:watchlist")
    assert incident["status"] == "firing"
    assert incident["details"]["type"] == "RuntimeError"


def test_tick_persistence_worker_stop_records_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now, tick_persistence=StoppedTickPersistence())

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "questdb_tick_persistence_lag:market_ticks")
    assert incident["status"] == "firing"
    assert incident["summary"] == "tick persistence writer stopped"
    assert incident["details"]["worker_alive"] is False
