from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings, get_settings


class TelegramDeliveryError(Exception):
    pass


class TelegramService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def config_status(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.telegram_enabled,
            "configured": self.configured,
            "send_levels": self.send_levels,
            "trade_events_enabled": self.settings.telegram_trade_events_enabled,
            "timeout_seconds": self.settings.telegram_http_timeout_seconds,
        }

    @property
    def configured(self) -> bool:
        return bool(self.settings.telegram_bot_token and self.settings.telegram_chat_id)

    @property
    def send_levels(self) -> list[str]:
        return [item.strip().lower() for item in self.settings.telegram_send_levels.split(",") if item.strip()]

    def should_send(self, severity: str) -> bool:
        return self.settings.telegram_enabled and severity.lower() in set(self.send_levels)

    def send_incident(self, incident: dict[str, Any], *, event: str) -> dict[str, Any]:
        if not self.should_send(str(incident.get("severity", "info"))):
            return {"sent": False, "skipped": "level_disabled"}
        return self.send_message(self._format_incident_message(incident, event=event))

    def send_test(self, *, operator: str = "anonymous") -> dict[str, Any]:
        return self.send_message(f"[VnPy Web Bridge] Telegram test message from {operator}")

    def send_message(self, text: str) -> dict[str, Any]:
        if not self.settings.telegram_enabled:
            return {"sent": False, "skipped": "disabled"}
        if not self.configured:
            raise TelegramDeliveryError("Telegram is enabled but not configured")

        token = self.settings.telegram_bot_token
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps(
            {
                "chat_id": self.settings.telegram_chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.settings.telegram_http_timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise TelegramDeliveryError(str(exc.reason)) from exc
        except TimeoutError as exc:
            raise TelegramDeliveryError("Telegram request timed out") from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {"ok": False, "description": "invalid response"}
        if not data.get("ok"):
            raise TelegramDeliveryError(str(data.get("description") or "Telegram API returned error"))
        return {"sent": True, "telegram_message_id": data.get("result", {}).get("message_id")}

    def _format_incident_message(self, incident: dict[str, Any], *, event: str) -> str:
        event_label = "RECOVERED" if event == "resolved" else "ALERT"
        severity = str(incident.get("severity", "warning")).upper()
        first_seen = str(incident.get("first_seen") or "-")
        duration = _duration_text(first_seen, str(incident.get("resolved_at") or incident.get("last_seen") or ""))
        return "\n".join(
            [
                f"[{event_label}] {self.settings.app_env} {severity}",
                f"incident: {incident.get('incident_id')}",
                f"scope: {incident.get('rule_id')} / {incident.get('scope_id')}",
                f"first_seen: {first_seen}",
                f"duration: {duration}",
                f"summary: {incident.get('summary') or '-'}",
            ]
        )


def _duration_text(start: str, end: str) -> str:
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end) if end else datetime.now(timezone.utc)
    except ValueError:
        return "-"
    seconds = max(0, int((end_dt - start_dt).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes}m"


telegram_service = TelegramService()
