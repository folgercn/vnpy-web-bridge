from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import Settings
from app.services.alert_service import AlertService
from app.services.telegram_service import TelegramDeliveryError, TelegramService
from app.stores.alert_state_store import AlertStateStore


class FakeTelegram:
    def __init__(self, *, fail: bool = False, fail_events: list[str] | None = None) -> None:
        self.fail = fail
        self.fail_events = fail_events or []
        self.sent: list[tuple[str, str]] = []

    def config_status(self) -> dict:
        return {"enabled": True, "configured": True, "send_levels": ["warning", "critical"]}

    def send_incident(self, incident: dict, *, event: str) -> dict:
        if self.fail:
            raise TelegramDeliveryError("offline")
        if event in self.fail_events:
            self.fail_events.remove(event)
            raise TelegramDeliveryError("offline")
        self.sent.append((incident["incident_id"], event))
        return {"sent": True, "message_id": len(self.sent)}


def build_service(tmp_path, *, fail_telegram: bool = False, fail_events: list[str] | None = None) -> tuple[AlertService, FakeTelegram]:
    settings = Settings(
        monitor_failure_threshold=3,
        monitor_recovery_threshold=2,
        monitor_flap_send_grace_seconds=45,
        monitor_flap_recovery_grace_seconds=60,
        monitor_state_path=str(tmp_path / "state.json"),
        monitor_events_path=str(tmp_path / "events.jsonl"),
        telegram_enabled=True,
        telegram_bot_token="token",
        telegram_chat_id="chat",
    )
    telegram = FakeTelegram(fail=fail_telegram, fail_events=fail_events)
    store = AlertStateStore(settings.monitor_state_path, settings.monitor_events_path)
    return AlertService(settings=settings, store=store, telegram=telegram), telegram


def test_alert_state_store_update_keeps_concurrent_mutations(tmp_path) -> None:
    store = AlertStateStore(tmp_path / "state.json", tmp_path / "events.jsonl")

    def add_incident(index: int) -> None:
        def mutate(state: dict) -> None:
            state["incidents"][f"test_rule:{index}"] = {
                "incident_id": f"test_rule:{index}",
                "rule_id": "test_rule",
                "scope_id": str(index),
                "status": "healthy",
            }

        store.update(mutate)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add_incident, range(50)))

    state = store.load()
    assert len(state["incidents"]) == 50


def test_incident_sends_once_after_threshold_and_grace(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    service.record_check(rule_id="rpc_unavailable", scope_id="CTP", healthy=False, severity="critical", summary="RPC offline", now=start)
    service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline",
        now=start + timedelta(seconds=20),
    )
    incident = service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC timeout text changed",
        now=start + timedelta(seconds=46),
    )

    assert incident["status"] == "firing"
    assert incident["incident_id"] == "rpc_unavailable:CTP"
    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]

    for seconds in (60, 75, 90):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary=f"changed {seconds}",
            now=start + timedelta(seconds=seconds),
        )

    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]


def test_critical_reminder_respects_configured_interval(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    service.settings.monitor_critical_reminder_minutes = 1
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    for seconds in (0, 20, 46):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline",
        now=start + timedelta(seconds=105),
    )
    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]

    service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline",
        now=start + timedelta(seconds=107),
    )
    service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline",
        now=start + timedelta(seconds=168),
    )

    assert telegram.sent == [
        ("rpc_unavailable:CTP", "firing"),
        ("rpc_unavailable:CTP", "reminder_1"),
        ("rpc_unavailable:CTP", "reminder_2"),
    ]


def test_failed_critical_reminder_retries_same_event(tmp_path) -> None:
    service, telegram = build_service(tmp_path, fail_events=["reminder_1"])
    service.settings.monitor_critical_reminder_minutes = 1
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    for seconds in (0, 20, 46, 107):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    incident = service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline",
        now=start + timedelta(seconds=168),
    )

    assert telegram.sent == [
        ("rpc_unavailable:CTP", "firing"),
        ("rpc_unavailable:CTP", "reminder_1"),
    ]
    assert incident["pending_reminder_event"] is None
    assert "rpc_unavailable:CTP:1:reminder_1" in service.store.load()["deliveries"]


def test_recovery_sends_once_after_success_threshold_and_grace(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    for seconds in (0, 20, 46):
        service.record_check(
            rule_id="questdb_unavailable",
            scope_id="market_ticks",
            healthy=False,
            severity="warning",
            summary="QuestDB offline",
            now=start + timedelta(seconds=seconds),
        )

    service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="QuestDB ok",
        now=start + timedelta(seconds=70),
    )
    incident = service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="QuestDB stable",
        now=start + timedelta(seconds=131),
    )

    assert incident["status"] == "resolved"
    assert telegram.sent == [
        ("questdb_unavailable:market_ticks", "firing"),
        ("questdb_unavailable:market_ticks", "resolved"),
    ]

    service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="still ok",
        now=start + timedelta(seconds=150),
    )
    assert len(telegram.sent) == 2


def test_recovery_delivery_failure_retries_until_sent(tmp_path) -> None:
    service, telegram = build_service(tmp_path, fail_events=["resolved"])
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    for seconds in (0, 20, 46):
        service.record_check(
            rule_id="questdb_unavailable",
            scope_id="market_ticks",
            healthy=False,
            severity="warning",
            summary="QuestDB offline",
            now=start + timedelta(seconds=seconds),
        )
    service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="QuestDB ok",
        now=start + timedelta(seconds=70),
    )
    incident = service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="QuestDB stable",
        now=start + timedelta(seconds=131),
    )

    assert incident["status"] == "resolved"
    assert incident["delivery"]["resolved"]["sent"] is False
    assert telegram.sent == [("questdb_unavailable:market_ticks", "firing")]

    incident = service.record_check(
        rule_id="questdb_unavailable",
        scope_id="market_ticks",
        healthy=True,
        severity="warning",
        summary="QuestDB still stable",
        now=start + timedelta(seconds=192),
    )

    assert incident["status"] == "healthy"
    assert telegram.sent == [
        ("questdb_unavailable:market_ticks", "firing"),
        ("questdb_unavailable:market_ticks", "resolved"),
    ]


def test_delivery_state_survives_service_restart(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    for seconds in (0, 20, 46):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    restarted = AlertService(settings=service.settings, store=service.store, telegram=telegram)
    restarted.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC offline after restart",
        now=start + timedelta(seconds=90),
    )

    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]


def test_new_episode_sends_after_previous_resolution(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    for offset in (0, 20, 46):
        service.record_check(rule_id="rpc_unavailable", scope_id="CTP", healthy=False, severity="critical", summary="RPC offline", now=start + timedelta(seconds=offset))
    for offset in (70, 131):
        service.record_check(rule_id="rpc_unavailable", scope_id="CTP", healthy=True, severity="critical", summary="RPC connected", now=start + timedelta(seconds=offset))
    for offset in (200, 220, 246):
        service.record_check(rule_id="rpc_unavailable", scope_id="CTP", healthy=False, severity="critical", summary="RPC offline again", now=start + timedelta(seconds=offset))
    for offset in (270, 331):
        service.record_check(rule_id="rpc_unavailable", scope_id="CTP", healthy=True, severity="critical", summary="RPC connected again", now=start + timedelta(seconds=offset))

    assert telegram.sent == [
        ("rpc_unavailable:CTP", "firing"),
        ("rpc_unavailable:CTP", "resolved"),
        ("rpc_unavailable:CTP", "firing"),
        ("rpc_unavailable:CTP", "resolved"),
    ]


def test_silence_updates_incident_without_sending(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    service.create_silence(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        reason="maintenance",
        operator="admin",
        expires_at=start + timedelta(hours=1),
        now=start,
    )

    for seconds in (0, 20, 46):
        incident = service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    assert incident["status"] == "firing"
    assert incident["delivery"]["firing"]["skipped"] == "silenced"
    assert telegram.sent == []


def test_active_incident_sends_after_silence_expires(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    service.create_silence(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        reason="maintenance",
        operator="admin",
        expires_at=start + timedelta(seconds=90),
        now=start,
    )

    for seconds in (0, 20, 46):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )
    incident = service.record_check(
        rule_id="rpc_unavailable",
        scope_id="CTP",
        healthy=False,
        severity="critical",
        summary="RPC still offline after maintenance",
        now=start + timedelta(seconds=100),
    )

    assert incident["status"] == "firing"
    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]


def test_non_silenceable_rule_is_rejected(tmp_path) -> None:
    service, _ = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError):
        service.create_silence(
            rule_id="emergency_stop",
            scope_id="global",
            reason="ignore",
            operator="admin",
            expires_at=start + timedelta(minutes=30),
            now=start,
        )


def test_emergency_stop_ignores_global_silence_and_sends_immediately(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    service.create_silence(
        reason="maintenance",
        operator="admin",
        expires_at=start + timedelta(hours=1),
        now=start,
    )

    incident = service.record_check(
        rule_id="emergency_stop",
        scope_id="global",
        healthy=False,
        severity="critical",
        summary="Emergency stop active",
        now=start,
    )

    assert incident["status"] == "firing"
    assert incident["failure_count"] == 1
    assert incident["delivery"]["firing"]["sent"] is True
    assert telegram.sent == [("emergency_stop:global", "firing")]


def test_daily_loss_limit_ignores_scope_silence_and_sends_immediately(tmp_path) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)
    service.create_silence(
        scope_id="global",
        reason="maintenance",
        operator="admin",
        expires_at=start + timedelta(hours=1),
        now=start,
    )

    incident = service.record_check(
        rule_id="daily_loss_limit",
        scope_id="global",
        healthy=False,
        severity="critical",
        summary="Daily loss limit breached",
        now=start,
    )

    assert incident["status"] == "firing"
    assert incident["failure_count"] == 1
    assert incident["delivery"]["firing"]["sent"] is True
    assert telegram.sent == [("daily_loss_limit:global", "firing")]


def test_telegram_failure_records_retry_without_raising(tmp_path) -> None:
    service, _ = build_service(tmp_path, fail_telegram=True)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    incident = None
    for seconds in (0, 20, 46):
        incident = service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    assert incident is not None
    assert incident["status"] == "firing"
    assert incident["delivery"]["firing"]["sent"] is False
    assert incident["delivery"]["next_retry_at"]


def test_event_log_failure_does_not_duplicate_delivery(tmp_path, monkeypatch) -> None:
    service, telegram = build_service(tmp_path)
    start = datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)

    def fail_append(_event: dict) -> None:
        raise OSError("events read-only")

    monkeypatch.setattr(service.store, "append_event", fail_append)
    for seconds in (0, 20, 46, 60):
        service.record_check(
            rule_id="rpc_unavailable",
            scope_id="CTP",
            healthy=False,
            severity="critical",
            summary="RPC offline",
            now=start + timedelta(seconds=seconds),
        )

    state = service.store.load()
    assert telegram.sent == [("rpc_unavailable:CTP", "firing")]
    assert "rpc_unavailable:CTP:1:firing" in state["deliveries"]


def test_telegram_unexpected_transport_error_is_wrapped(monkeypatch) -> None:
    settings = Settings(
        telegram_enabled=True,
        telegram_bot_token="token",
        telegram_chat_id="chat",
    )
    service = TelegramService(settings)

    def fail_open(*_args, **_kwargs):
        raise RuntimeError("transport failure")

    monkeypatch.setattr("app.services.telegram_service.urllib.request.urlopen", fail_open)

    with pytest.raises(TelegramDeliveryError, match="RuntimeError"):
        service.send_message("test")
