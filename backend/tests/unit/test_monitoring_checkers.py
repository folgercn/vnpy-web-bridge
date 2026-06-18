from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from threading import Lock
import time

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


class SelectiveTelegram:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    def config_status(self) -> dict:
        return {"enabled": True, "configured": True, "send_levels": ["critical", "warning"]}

    def send_incident(self, incident: dict, *, event: str) -> dict:
        severity = str(incident.get("severity") or "info").lower()
        if severity not in {"critical", "warning"}:
            return {"sent": False, "skipped": "level_disabled"}
        self.sent.append((incident["incident_id"], event, severity))
        return {"sent": True, "message_id": len(self.sent)}


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


class SlowRpc(FakeRpc):
    def __init__(self) -> None:
        super().__init__(connected=True)
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self._lock = Lock()

    def status(self, *, probe: bool = False) -> dict:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(0.05)
        with self._lock:
            self.active -= 1
        return super().status(probe=probe)


class HealthyMarketStore:
    def health_check(self) -> dict:
        return {"configured": True, "connected": True, "status": "ok"}


class HealthyPostgres:
    def health_check(self) -> dict:
        return {"configured": True, "connected": True, "status": "ok"}


class BrokenPostgres:
    def health_check(self) -> dict:
        raise RuntimeError("postgres down")


class HealthyTickPersistence:
    def snapshot(self) -> dict:
        return {"enabled": True, "running": True, "worker_alive": True, "last_error": None, "queue_depth": 0, "spool_rows": 0, "persistence_lag_seconds": 0}


class StoppedTickPersistence:
    def snapshot(self) -> dict:
        return {"enabled": True, "running": False, "worker_alive": False, "last_error": None, "queue_depth": 0, "spool_rows": 0, "persistence_lag_seconds": 0}


class CorruptTickPersistence:
    def snapshot(self) -> dict:
        return {
            "enabled": True,
            "running": True,
            "worker_alive": True,
            "last_error": "quarantined corrupt tick spool segment",
            "queue_depth": 0,
            "spool_rows": 1,
            "spool_bytes": 128,
            "corrupt_total": 1,
            "quarantined_rows": 1,
            "quarantined_bytes": 128,
            "persistence_lag_seconds": 0,
        }


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
        monitor_startup_grace_seconds=0,
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
    assert incident["severity"] == "info"


def test_monitoring_run_checks_is_single_flight(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    rpc = SlowRpc()
    service = build_service(tmp_path, now=now, rpc=rpc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        snapshots = list(pool.map(lambda _: service.run_checks(), range(2)))

    assert len(snapshots) == 2
    assert rpc.calls == 2
    assert rpc.max_active == 1


def test_non_production_rpc_warning_does_not_send_telegram_by_default(tmp_path) -> None:
    now = datetime(2026, 6, 18, 8, 0, tzinfo=timezone.utc)  # 16:00 Asia/Shanghai, no expected strategy and web trade disabled.
    settings = Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_startup_grace_seconds=0,
        monitor_flap_send_grace_seconds=0,
        monitor_flap_recovery_grace_seconds=0,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        telegram_enabled=True,
        telegram_bot_token="token",
        telegram_chat_id="chat",
        telegram_send_levels="critical,warning",
    )
    telegram = SelectiveTelegram()
    alerts = AlertService(
        settings=settings,
        store=AlertStateStore(settings.monitor_state_path, settings.monitor_events_path),
        telegram=telegram,
    )
    service = build_service(tmp_path, now=now, settings=settings, alerts=alerts, rpc=FakeRpc(connected=False))

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "rpc_unavailable:CTP")
    assert incident["severity"] == "info"
    assert incident["delivery"]["firing"]["result"]["skipped"] == "level_disabled"
    assert telegram.sent == []


def test_startup_grace_suppresses_runtime_dependency_checks(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    settings = Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_startup_grace_seconds=120,
        monitor_flap_send_grace_seconds=0,
        monitor_flap_recovery_grace_seconds=0,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        monitor_expected_strategies="demo_strategy",
    )
    service = build_service(tmp_path, now=now, settings=settings, rpc=FakeRpc(connected=False), postgres=BrokenPostgres())

    snapshot = service.run_checks()

    names = {item["name"] for item in snapshot["checks"]}
    assert "startup_grace" in names
    assert "rpc" not in names
    assert "postgres" not in names
    assert any(item["suppressed_by"] == "startup_grace" for item in snapshot["suppressed"])
    assert not any(item["incident_id"] == "rpc_unavailable:CTP" for item in snapshot["incidents"])


def test_deployment_maintenance_suppresses_runtime_dependency_checks(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    maintenance_path = tmp_path / "maintenance.json"
    maintenance_path.write_text(
        json.dumps(
            {
                "status": "running",
                "reason": "deploy in progress",
                "expires_at": (now + timedelta(minutes=5)).isoformat(timespec="seconds"),
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_startup_grace_seconds=0,
        monitor_flap_send_grace_seconds=0,
        monitor_flap_recovery_grace_seconds=0,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        monitor_maintenance_path=str(maintenance_path),
        monitor_expected_strategies="demo_strategy",
    )
    service = build_service(tmp_path, now=now, settings=settings, rpc=FakeRpc(connected=False), postgres=BrokenPostgres())

    snapshot = service.run_checks()

    names = {item["name"] for item in snapshot["checks"]}
    assert "deployment_maintenance" in names
    assert "rpc" not in names
    assert "postgres" not in names
    assert any(item["suppressed_by"] == "deployment_maintenance" for item in snapshot["suppressed"])
    assert not any(item["incident_id"] == "rpc_unavailable:CTP" for item in snapshot["incidents"])


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


def test_tick_freshness_quiet_after_product_night_session(tmp_path) -> None:
    now = datetime(2026, 6, 18, 15, 30, tzinfo=timezone.utc)  # 23:30 Asia/Shanghai
    rpc = FakeRpc()
    rpc.subscriptions = ["rb2610.SHFE"]
    service = build_service(tmp_path, now=now, rpc=rpc)

    snapshot = service.run_checks()

    tick_check = next(item for item in snapshot["checks"] if item["name"] == "tick_freshness")
    assert tick_check["healthy"] is True
    assert tick_check["status"] == "quiet"
    assert not any(item["incident_id"] == "tick_stale:market_ticks" for item in snapshot["incidents"])


def test_tick_freshness_checks_only_active_subscriptions(tmp_path) -> None:
    now = datetime(2026, 6, 16, 15, 30, tzinfo=timezone.utc)  # 23:30 Asia/Shanghai
    rpc = FakeRpc()
    rpc.subscriptions = ["au2612.SHFE", "rb2610.SHFE"]
    service = build_service(tmp_path, now=now, rpc=rpc)

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "tick_stale:market_ticks")
    assert incident["details"]["missing"] == ["au2612.SHFE"]
    assert "rb2610.SHFE" not in incident["details"]["missing"]
    assert incident["details"]["active_subscription_count"] == 1
    assert incident["details"]["quiet_subscription_count"] == 1


def test_expected_strategy_stop_records_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    settings = Settings(
        monitor_failure_threshold=1,
        monitor_recovery_threshold=1,
        monitor_startup_grace_seconds=0,
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


def test_tick_persistence_corruption_records_incident(tmp_path) -> None:
    now = datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    service = build_service(tmp_path, now=now, tick_persistence=CorruptTickPersistence())

    snapshot = service.run_checks()

    incident = next(item for item in snapshot["incidents"] if item["incident_id"] == "questdb_tick_persistence_lag:market_ticks")
    assert incident["status"] == "firing"
    assert incident["summary"] == "quarantined corrupt tick spool segment"
    assert incident["details"]["corrupt_total"] == 1
    assert incident["details"]["quarantined_rows"] == 1
