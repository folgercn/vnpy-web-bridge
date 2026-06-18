from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from app.core.config import Settings, get_settings
from app.services.telegram_service import TelegramDeliveryError, TelegramService, telegram_service
from app.stores.alert_state_store import AlertStateStore

ACTIVE_STATUSES = {"pending", "firing", "acknowledged", "recovering"}
NON_SILENCEABLE_RULES = {"emergency_stop", "daily_loss_limit"}
RETRY_SECONDS = [60, 300, 900]


class AlertService:
    def __init__(
        self,
        settings: Settings | None = None,
        store: AlertStateStore | None = None,
        telegram: TelegramService | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.store = store or AlertStateStore(self.settings.monitor_state_path, self.settings.monitor_events_path)
        self.telegram = telegram or telegram_service

    def record_check(
        self,
        *,
        rule_id: str,
        scope_id: str,
        healthy: bool,
        severity: str = "warning",
        summary: str = "",
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        state = self.store.load()
        self._expire_silences(state, now)
        incident_id = fingerprint(rule_id, scope_id)
        incident = state["incidents"].get(incident_id)
        if incident is None:
            incident = self._new_incident(rule_id, scope_id, severity, summary, details, now)
            state["incidents"][incident_id] = incident

        incident.update(
            {
                "severity": severity,
                "summary": summary,
                "details": details or {},
                "last_seen": iso(now),
            }
        )

        if healthy:
            self._apply_success(state, incident, now)
        else:
            self._apply_failure(state, incident, now)

        self.store.save(state)
        return incident

    def list_incidents(self, *, include_resolved: bool = True) -> list[dict[str, Any]]:
        state = self.store.load()
        incidents = list(state["incidents"].values())
        if not include_resolved:
            incidents = [item for item in incidents if item.get("status") in ACTIVE_STATUSES]
        return sorted(incidents, key=lambda item: str(item.get("last_seen") or ""), reverse=True)

    def summary(self) -> dict[str, Any]:
        state = self.store.load()
        incidents = list(state["incidents"].values())
        active = [item for item in incidents if item.get("status") in ACTIVE_STATUSES]
        severity_rank = {"info": 0, "warning": 1, "critical": 2}
        highest = max((str(item.get("severity", "info")) for item in active), key=lambda value: severity_rank.get(value, 0), default="info")
        return {
            "enabled": self.settings.monitor_enabled,
            "active_count": len(active),
            "highest_severity": highest,
            "last_updated_at": state.get("updated_at"),
            "silence_count": len(state["silences"]),
            "telegram": self.telegram.config_status(),
        }

    def ack(self, incident_id: str, *, operator: str, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        state = self.store.load()
        incident = self._require_incident(state, incident_id)
        if incident.get("status") in {"firing", "recovering"}:
            incident["status"] = "acknowledged"
        incident["acknowledged_by"] = operator
        incident["acknowledged_at"] = iso(now)
        self.store.append_event({"type": "ack", "incident_id": incident_id, "operator": operator})
        self.store.save(state)
        return incident

    def create_silence(
        self,
        *,
        reason: str,
        operator: str,
        expires_at: datetime,
        rule_id: str | None = None,
        scope_id: str | None = None,
        incident_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        if not reason.strip():
            raise ValueError("reason is required")
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        max_expires_at = now + timedelta(seconds=self.settings.monitor_max_silence_seconds)
        if expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if expires_at > max_expires_at:
            raise ValueError("silence TTL exceeds maximum")
        if rule_id in NON_SILENCEABLE_RULES:
            raise ValueError(f"{rule_id} cannot be silenced")

        state = self.store.load()
        if incident_id:
            incident = self._require_incident(state, incident_id)
            rule_id = str(incident["rule_id"])
            scope_id = str(incident["scope_id"])
            if rule_id in NON_SILENCEABLE_RULES:
                raise ValueError(f"{rule_id} cannot be silenced")
        silence_id = f"sil_{uuid4().hex[:12]}"
        silence = {
            "silence_id": silence_id,
            "rule_id": rule_id,
            "scope_id": scope_id,
            "incident_id": incident_id,
            "reason": reason.strip(),
            "created_by": operator,
            "created_at": iso(now),
            "expires_at": iso(expires_at),
        }
        state["silences"][silence_id] = silence
        self.store.append_event({"type": "silence_created", "silence_id": silence_id, "operator": operator})
        self.store.save(state)
        return silence

    def delete_silence(self, silence_id: str, *, operator: str) -> dict[str, Any]:
        state = self.store.load()
        silence = state["silences"].pop(silence_id, None)
        if silence is None:
            raise KeyError(silence_id)
        self.store.append_event({"type": "silence_deleted", "silence_id": silence_id, "operator": operator})
        self.store.save(state)
        return silence

    def _apply_failure(self, state: dict[str, Any], incident: dict[str, Any], now: datetime) -> None:
        if incident.get("status") in {"healthy", "resolved"}:
            self._start_episode(incident, now)
            incident["status"] = "pending"
            incident["fired_at"] = None
            incident["resolved_at"] = None
            incident["delivery"] = {}
        if incident.get("status") == "recovering":
            incident["status"] = "firing" if incident.get("fired_at") else "pending"
        incident["failure_count"] = int(incident.get("failure_count") or 0) + 1
        incident["success_count"] = 0

        failure_started_at = parse_time(str(incident.get("failure_started_at") or incident.get("first_seen")), now)
        failure_age = (now - failure_started_at).total_seconds()
        send_now = incident["rule_id"] in NON_SILENCEABLE_RULES
        if (
            (
                send_now
                or (
                    incident["failure_count"] >= self.settings.monitor_failure_threshold
                    and failure_age >= self.settings.monitor_flap_send_grace_seconds
                )
            )
            and incident.get("status") == "pending"
        ):
            incident["status"] = "firing"
            incident["fired_at"] = iso(now)
            self._deliver(state, incident, event="firing", now=now)
        elif incident.get("status") in {"firing", "acknowledged"} and self._should_attempt_delivery(state, incident, "firing", now):
            self._deliver(state, incident, event="firing", now=now)

    def _apply_success(self, state: dict[str, Any], incident: dict[str, Any], now: datetime) -> None:
        incident["success_count"] = int(incident.get("success_count") or 0) + 1
        incident["failure_count"] = 0
        if incident.get("status") == "pending":
            incident["status"] = "healthy"
            incident["failure_started_at"] = None
            return
        if incident.get("status") in {"firing", "acknowledged"}:
            incident["status"] = "recovering"
            incident["recovery_started_at"] = iso(now)
        if incident.get("status") == "recovering":
            recovery_started_at = parse_time(str(incident.get("recovery_started_at") or incident.get("last_seen")), now)
            recovery_age = (now - recovery_started_at).total_seconds()
            if (
                incident["success_count"] >= self.settings.monitor_recovery_threshold
                and recovery_age >= self.settings.monitor_flap_recovery_grace_seconds
            ):
                incident["status"] = "resolved"
                incident["resolved_at"] = iso(now)
                self._deliver(state, incident, event="resolved", now=now)
        elif incident.get("status") in {"healthy", "resolved"}:
            incident["status"] = "healthy"

    def _deliver(self, state: dict[str, Any], incident: dict[str, Any], *, event: str, now: datetime) -> None:
        delivery_key = self._delivery_key(incident, event)
        if delivery_key in state["deliveries"]:
            return
        if self._matching_silence(state, incident, now):
            incident.setdefault("delivery", {})[event] = {"sent": False, "skipped": "silenced", "at": iso(now)}
            return
        try:
            result = self.telegram.send_incident(incident, event=event)
        except TelegramDeliveryError as exc:
            attempts = int(incident.setdefault("delivery", {}).get("attempts", 0)) + 1
            retry_after = RETRY_SECONDS[min(attempts - 1, len(RETRY_SECONDS) - 1)]
            incident["delivery"].update(
                {
                    event: {"sent": False, "error": str(exc), "at": iso(now)},
                    "attempts": attempts,
                    "next_retry_at": iso(now + timedelta(seconds=retry_after)),
                }
            )
            return
        if result.get("sent"):
            state["deliveries"][delivery_key] = {"sent_at": iso(now), "result": result}
        incident.setdefault("delivery", {})[event] = {"sent": bool(result.get("sent")), "result": result, "at": iso(now)}
        self.store.append_event({"type": f"incident_{event}", "incident_id": incident["incident_id"], "delivery": result})

    def _should_attempt_delivery(self, state: dict[str, Any], incident: dict[str, Any], event: str, now: datetime) -> bool:
        if self._delivery_key(incident, event) in state["deliveries"]:
            return False
        event_delivery = incident.get("delivery", {}).get(event)
        if not event_delivery:
            return True
        if event_delivery.get("skipped") == "silenced":
            return self._matching_silence(state, incident, now) is None
        next_retry_at = incident.get("delivery", {}).get("next_retry_at")
        if next_retry_at:
            return parse_time(str(next_retry_at), now) <= now
        return False

    def _start_episode(self, incident: dict[str, Any], now: datetime) -> None:
        episode_seq = int(incident.get("episode_seq") or 0) + 1
        incident["episode_seq"] = episode_seq
        incident["episode_id"] = f"{incident['incident_id']}:{episode_seq}"
        incident["first_seen"] = iso(now)
        incident["failure_started_at"] = iso(now)
        incident["recovery_started_at"] = None

    def _delivery_key(self, incident: dict[str, Any], event: str) -> str:
        episode_id = incident.get("episode_id") or f"{incident['incident_id']}:{int(incident.get('episode_seq') or 0)}"
        return f"{episode_id}:{event}"

    def _matching_silence(self, state: dict[str, Any], incident: dict[str, Any], now: datetime) -> dict[str, Any] | None:
        if incident.get("rule_id") in NON_SILENCEABLE_RULES:
            return None
        for silence in state["silences"].values():
            expires_at = parse_time(str(silence.get("expires_at")), now)
            if expires_at <= now:
                continue
            if silence.get("incident_id") and silence["incident_id"] != incident["incident_id"]:
                continue
            if silence.get("rule_id") and silence["rule_id"] != incident["rule_id"]:
                continue
            if silence.get("scope_id") and silence["scope_id"] != incident["scope_id"]:
                continue
            return silence
        return None

    def _expire_silences(self, state: dict[str, Any], now: datetime) -> None:
        expired = [
            silence_id
            for silence_id, silence in state["silences"].items()
            if parse_time(str(silence.get("expires_at")), now) <= now
        ]
        for silence_id in expired:
            state["silences"].pop(silence_id, None)

    def _new_incident(
        self,
        rule_id: str,
        scope_id: str,
        severity: str,
        summary: str,
        details: dict[str, Any] | None,
        now: datetime,
    ) -> dict[str, Any]:
        incident_id = fingerprint(rule_id, scope_id)
        return {
            "incident_id": incident_id,
            "rule_id": rule_id,
            "scope_id": scope_id,
            "status": "healthy",
            "severity": severity,
            "summary": summary,
            "details": details or {},
            "first_seen": iso(now),
            "last_seen": iso(now),
            "failure_started_at": None,
            "recovery_started_at": None,
            "fired_at": None,
            "resolved_at": None,
            "failure_count": 0,
            "success_count": 0,
            "episode_seq": 0,
            "episode_id": None,
            "delivery": {},
        }

    def _require_incident(self, state: dict[str, Any], incident_id: str) -> dict[str, Any]:
        incident = state["incidents"].get(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        return incident


def fingerprint(rule_id: str, scope_id: str) -> str:
    raw = f"{rule_id}:{scope_id}"
    if all(char.isalnum() or char in "._:-" for char in raw):
        return raw
    suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{rule_id}:{suffix}"


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_time(value: str, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


alert_service = AlertService()
