#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.request

RETRY_SECONDS = [60, 300, 900]
ACTIVE_STATUSES = {"pending", "firing"}


@dataclass
class CheckResult:
    rule_id: str
    scope_id: str
    healthy: bool
    severity: str
    summary: str
    details: dict[str, Any]


class WatchdogConfig:
    def __init__(self) -> None:
        self.enabled = env_bool("WATCHDOG_ENABLED", True)
        self.interval_seconds = env_int("WATCHDOG_INTERVAL_SECONDS", 15)
        self.failure_threshold = env_int("WATCHDOG_FAILURE_THRESHOLD", 3)
        self.recovery_threshold = env_int("WATCHDOG_RECOVERY_THRESHOLD", 2)
        self.container_name = os.getenv("WATCHDOG_CONTAINER_NAME", "vnpy-web-bridge")
        self.liveness_url = os.getenv("WATCHDOG_LIVENESS_URL", "http://127.0.0.1:8080/api/health/live")
        self.log_dir = Path(os.getenv("WATCHDOG_LOG_DIR", "/Users/fujun/services/vnpy-web-bridge/logs"))
        self.state_path = Path(os.getenv("WATCHDOG_STATE_PATH", str(self.log_dir / "watchdog/state.json")))
        self.events_path = Path(os.getenv("WATCHDOG_EVENTS_PATH", str(self.log_dir / "watchdog/events.jsonl")))
        self.maintenance_file = Path(os.getenv("WATCHDOG_MAINTENANCE_FILE", str(self.log_dir / "watchdog/maintenance.json")))
        self.disk_warning_percent = env_float("WATCHDOG_DISK_WARNING_PERCENT", 85)
        self.disk_critical_percent = env_float("WATCHDOG_DISK_CRITICAL_PERCENT", 95)
        self.http_timeout_seconds = env_float("WATCHDOG_HTTP_TIMEOUT_SECONDS", 3)
        self.telegram_enabled = env_bool("TELEGRAM_ENABLED", False)
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.app_env = os.getenv("APP_ENV", "production")


class Watchdog:
    def __init__(
        self,
        config: WatchdogConfig,
        *,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        self.config = config
        self.runner = runner
        self.opener = opener
        self._fallback_state: dict[str, Any] | None = None
        self._pending_events: list[dict[str, Any]] = []

    def run_forever(self) -> None:
        while True:
            try:
                self.run_once()
            except Exception as exc:
                print(f"watchdog cycle failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            time.sleep(self.config.interval_seconds)

    def run_once(self) -> dict[str, Any]:
        now = utc_now()
        state = self._load_state()
        maintenance = self._maintenance(now)
        checks = self.collect_checks(maintenance=maintenance)
        for check in checks:
            self._apply_check(state, check, now, maintenance=maintenance)
        self._resolve_suppressed_incidents(state, checks, now)
        self._save_state(state)
        return {"checked_at": now.isoformat(timespec="seconds"), "checks": [check.__dict__ for check in checks], "maintenance": maintenance}

    def collect_checks(self, *, maintenance: dict[str, Any] | None = None) -> list[CheckResult]:
        if maintenance and maintenance.get("status") == "failed":
            return [
                CheckResult(
                    "deployment_smoke_failed",
                    "web-bridge",
                    False,
                    "critical",
                    str(maintenance.get("reason") or "deployment smoke failed"),
                    safe_details(maintenance),
                )
            ]
        if maintenance and maintenance.get("active"):
            return [
                CheckResult(
                    "deployment_window",
                    "web-bridge",
                    True,
                    "info",
                    "deployment maintenance window active",
                    safe_details(maintenance),
                )
            ]
        checks = [self._safe_check("watchdog_checker_failed", "docker", self._docker_daemon_check)]
        if checks[0].healthy:
            container = self._safe_check("watchdog_checker_failed", self.config.container_name, self._container_check)
            checks.append(container)
            if container.healthy:
                checks.append(self._safe_check("watchdog_checker_failed", "web-bridge", self._liveness_check))
        checks.extend(
            [
                self._safe_check("watchdog_checker_failed", "logs", self._log_dir_check),
                self._safe_check("watchdog_checker_failed", "logs", self._disk_check),
            ]
        )
        return checks

    def _safe_check(self, rule_id: str, scope_id: str, checker: Callable[[], CheckResult]) -> CheckResult:
        try:
            return checker()
        except Exception as exc:
            return CheckResult(
                rule_id,
                scope_id,
                False,
                "critical",
                f"{checker.__name__} failed: {exc.__class__.__name__}",
                {"type": exc.__class__.__name__, "error": str(exc)},
            )

    def _docker_daemon_check(self) -> CheckResult:
        result = self._run_docker_command(["docker", "info"], timeout=5)
        if isinstance(result, CheckResult):
            return result
        healthy = result.returncode == 0
        return CheckResult(
            "docker_daemon_unavailable",
            "docker",
            healthy,
            "critical",
            "Docker daemon reachable" if healthy else "Docker daemon unavailable",
            {"returncode": result.returncode, "stderr": (result.stderr or "")[-500:]},
        )

    def _container_check(self) -> CheckResult:
        result = self._run_docker_command(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.config.container_name],
            timeout=5,
            failure_rule_id="container_not_running",
            failure_scope_id=self.config.container_name,
            failure_summary="container status query failed",
        )
        if isinstance(result, CheckResult):
            return result
        running = result.returncode == 0 and result.stdout.strip().lower() == "true"
        return CheckResult(
            "container_not_running",
            self.config.container_name,
            running,
            "critical",
            "container running" if running else "container missing or stopped",
            {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": (result.stderr or "")[-500:]},
        )

    def _run_docker_command(
        self,
        cmd: list[str],
        *,
        timeout: float,
        failure_rule_id: str = "docker_daemon_unavailable",
        failure_scope_id: str = "docker",
        failure_summary: str = "Docker command failed",
    ) -> subprocess.CompletedProcess | CheckResult:
        try:
            return self.runner(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            return CheckResult(
                failure_rule_id,
                failure_scope_id,
                False,
                "critical",
                f"{failure_summary}: TimeoutExpired",
                {"type": "TimeoutExpired", "timeout": exc.timeout, "cmd": cmd[:2]},
            )
        except FileNotFoundError as exc:
            return CheckResult(
                failure_rule_id,
                failure_scope_id,
                False,
                "critical",
                f"{failure_summary}: FileNotFoundError",
                {"type": "FileNotFoundError", "error": str(exc), "cmd": cmd[:2]},
            )
        except Exception as exc:
            return CheckResult(
                failure_rule_id,
                failure_scope_id,
                False,
                "critical",
                f"{failure_summary}: {exc.__class__.__name__}",
                {"type": exc.__class__.__name__, "error": str(exc), "cmd": cmd[:2]},
            )

    def _liveness_check(self) -> CheckResult:
        try:
            with self.opener(self.config.liveness_url, timeout=self.config.http_timeout_seconds) as response:
                status = getattr(response, "status", 200)
                body = response.read(300).decode("utf-8", errors="replace")
            healthy = 200 <= int(status) < 300
            details = {"status": status, "body": body}
        except Exception as exc:
            healthy = False
            details = {"type": exc.__class__.__name__}
        return CheckResult(
            "app_liveness_failed",
            "web-bridge",
            healthy,
            "critical",
            "liveness ok" if healthy else "liveness failed",
            details,
        )

    def _log_dir_check(self) -> CheckResult:
        try:
            self.config.log_dir.mkdir(parents=True, exist_ok=True)
            probe = self.config.log_dir / ".watchdog-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            healthy = True
            details: dict[str, Any] = {"path": str(self.config.log_dir)}
        except Exception as exc:
            healthy = False
            details = {"path": str(self.config.log_dir), "type": exc.__class__.__name__}
        return CheckResult(
            "log_dir_not_writable",
            "logs",
            healthy,
            "critical",
            "log directory writable" if healthy else "log directory not writable",
            details,
        )

    def _disk_check(self) -> CheckResult:
        try:
            self.config.log_dir.mkdir(parents=True, exist_ok=True)
            disk = shutil.disk_usage(self.config.log_dir)
        except Exception as exc:
            return CheckResult(
                "disk_space_high",
                "logs",
                False,
                "critical",
                f"disk check failed: {exc.__class__.__name__}",
                {"path": str(self.config.log_dir), "type": exc.__class__.__name__, "error": str(exc)},
            )
        used_percent = round((disk.used / disk.total) * 100, 2) if disk.total else 0
        severity = "critical" if used_percent >= self.config.disk_critical_percent else "warning"
        healthy = used_percent < self.config.disk_warning_percent
        return CheckResult(
            "disk_space_high",
            "logs",
            healthy,
            severity,
            "disk usage ok" if healthy else f"disk usage {used_percent}%",
            {"used_percent": used_percent, "total": disk.total, "used": disk.used, "free": disk.free},
        )

    def _maintenance(self, now: datetime) -> dict[str, Any] | None:
        data = load_json(self.config.maintenance_file, default=None)
        if not data:
            return None
        expires_at = parse_time(str(data.get("expires_at") or ""), fallback=now)
        data["active"] = data.get("status") == "running" and expires_at > now
        data["expired"] = expires_at <= now
        return data

    def _apply_check(self, state: dict[str, Any], check: CheckResult, now: datetime, *, maintenance: dict[str, Any] | None) -> None:
        incident_id = f"{check.rule_id}:{check.scope_id}"
        incident = state.setdefault("incidents", {}).setdefault(
            incident_id,
            {
                "incident_id": incident_id,
                "rule_id": check.rule_id,
                "scope_id": check.scope_id,
                "status": "healthy",
                "failure_count": 0,
                "success_count": 0,
                "first_seen": now.isoformat(timespec="seconds"),
            },
        )
        incident.update({"severity": check.severity, "summary": check.summary, "details": check.details, "last_seen": now.isoformat(timespec="seconds")})
        if check.healthy:
            incident["success_count"] = int(incident.get("success_count") or 0) + 1
            incident["failure_count"] = 0
            if incident.get("status") == "firing" and incident["success_count"] >= self.config.recovery_threshold:
                incident["status"] = "resolved"
                incident["resolved_at"] = now.isoformat(timespec="seconds")
                self._notify_once(state, incident, "resolved", now)
            elif incident.get("status") == "resolved":
                if self._should_attempt_delivery(incident, "resolved", now):
                    self._notify_once(state, incident, "resolved", now)
                if self._delivery_complete(state, incident, "resolved"):
                    incident["status"] = "healthy"
            elif incident.get("status") in {"healthy", "pending"}:
                incident["status"] = "healthy"
            return

        incident["failure_count"] = int(incident.get("failure_count") or 0) + 1
        incident["success_count"] = 0
        if incident.get("status") in {"healthy", "resolved"}:
            self._start_episode(incident, now)
            incident["status"] = "pending"
            incident["fired_at"] = None
            incident["resolved_at"] = None
            incident["delivery"] = {}
        if incident["failure_count"] >= self.config.failure_threshold:
            incident["status"] = "firing"
            incident.setdefault("fired_at", now.isoformat(timespec="seconds"))
            self._notify_once(state, incident, "firing", now)

    def _notify_once(self, state: dict[str, Any], incident: dict[str, Any], event: str, now: datetime) -> None:
        key = self._delivery_key(incident, event)
        if key in state.setdefault("deliveries", {}):
            return
        if not self._should_attempt_delivery(incident, event, now):
            return
        result = self._send_telegram(incident, event=event)
        incident.setdefault("delivery", {})[event] = {"sent": bool(result.get("sent")), "result": result, "at": now.isoformat(timespec="seconds")}
        if result.get("sent"):
            state["deliveries"][key] = {"sent_at": now.isoformat(timespec="seconds"), "result": result}
        else:
            attempts = int(incident.setdefault("delivery", {}).get("attempts", 0)) + 1
            retry_after = RETRY_SECONDS[min(attempts - 1, len(RETRY_SECONDS) - 1)]
            incident["delivery"].update({"attempts": attempts, "next_retry_at": (now + timedelta(seconds=retry_after)).isoformat(timespec="seconds")})
        self._append_event({"timestamp": now.isoformat(timespec="seconds"), "type": event, "incident_id": incident["incident_id"], "delivery": result})

    def _load_state(self) -> dict[str, Any]:
        if self._fallback_state is not None:
            return deepcopy(self._fallback_state)
        return load_json(self.config.state_path, default={"incidents": {}, "deliveries": {}})

    def _save_state(self, state: dict[str, Any]) -> None:
        try:
            save_json(self.config.state_path, state)
        except Exception as exc:
            self._fallback_state = deepcopy(state)
            print(f"watchdog state write failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            return
        self._fallback_state = None

    def _append_event(self, event: dict[str, Any]) -> None:
        events = [*self._pending_events, event]
        self._pending_events = []
        for item in events:
            try:
                append_jsonl(self.config.events_path, item)
            except Exception as exc:
                self._pending_events.append(item)
                print(f"watchdog event write failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
                return

    def _resolve_suppressed_incidents(self, state: dict[str, Any], checks: list[CheckResult], now: datetime) -> None:
        by_rule = {check.rule_id: check for check in checks}
        docker = by_rule.get("docker_daemon_unavailable")
        if docker and not docker.healthy:
            self._resolve_suppressed_incident(state, "container_not_running", self.config.container_name, "docker_daemon_unavailable", now)
            self._resolve_suppressed_incident(state, "app_liveness_failed", "web-bridge", "docker_daemon_unavailable", now)
            return

        container = by_rule.get("container_not_running")
        if container and not container.healthy:
            self._resolve_suppressed_incident(state, "app_liveness_failed", "web-bridge", "container_not_running", now)

    def _resolve_suppressed_incident(
        self,
        state: dict[str, Any],
        rule_id: str,
        scope_id: str,
        suppressed_by: str,
        now: datetime,
    ) -> None:
        incident_id = f"{rule_id}:{scope_id}"
        incident = state.setdefault("incidents", {}).get(incident_id)
        if not incident or incident.get("status") not in ACTIVE_STATUSES:
            return
        previous_summary = incident.get("summary")
        incident.update(
            {
                "status": "resolved",
                "resolved_at": now.isoformat(timespec="seconds"),
                "last_seen": now.isoformat(timespec="seconds"),
                "summary": f"suppressed by {suppressed_by}",
                "details": {"suppressed_by": suppressed_by, "previous_summary": previous_summary},
                "failure_count": 0,
                "success_count": max(int(incident.get("success_count") or 0), self.config.recovery_threshold),
            }
        )
        incident.setdefault("delivery", {})["resolved"] = {
            "sent": False,
            "result": {"sent": False, "skipped": "suppressed"},
            "suppressed_by": suppressed_by,
            "at": now.isoformat(timespec="seconds"),
        }
        self._append_event(
            {
                "timestamp": now.isoformat(timespec="seconds"),
                "type": "suppressed",
                "incident_id": incident_id,
                "suppressed_by": suppressed_by,
            }
        )

    def _should_attempt_delivery(self, incident: dict[str, Any], event: str, now: datetime) -> bool:
        event_delivery = incident.get("delivery", {}).get(event)
        if not event_delivery:
            return True
        next_retry_at = incident.get("delivery", {}).get("next_retry_at")
        if next_retry_at:
            return parse_time(str(next_retry_at), fallback=now) <= now
        return False

    def _delivery_complete(self, state: dict[str, Any], incident: dict[str, Any], event: str) -> bool:
        if self._delivery_key(incident, event) in state.get("deliveries", {}):
            return True
        event_delivery = incident.get("delivery", {}).get(event)
        if not event_delivery:
            return False
        if event_delivery.get("sent"):
            return True
        if incident.get("delivery", {}).get("next_retry_at"):
            return False
        result = event_delivery.get("result") or {}
        return result.get("skipped") in {"disabled", "suppressed"}

    def _start_episode(self, incident: dict[str, Any], now: datetime) -> None:
        episode_seq = int(incident.get("episode_seq") or 0) + 1
        incident["episode_seq"] = episode_seq
        incident["episode_id"] = f"{incident['incident_id']}:{episode_seq}"
        incident["first_seen"] = now.isoformat(timespec="seconds")

    def _delivery_key(self, incident: dict[str, Any], event: str) -> str:
        episode_id = incident.get("episode_id") or f"{incident['incident_id']}:{int(incident.get('episode_seq') or 0)}"
        return f"{episode_id}:{event}"

    def _send_telegram(self, incident: dict[str, Any], *, event: str) -> dict[str, Any]:
        if not self.config.telegram_enabled:
            return {"sent": False, "skipped": "disabled"}
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return {"sent": False, "error": "telegram_not_configured"}
        label = "RECOVERED" if event == "resolved" else "WATCHDOG"
        text = "\n".join(
            [
                f"[{label}] {self.config.app_env} {str(incident.get('severity')).upper()}",
                f"incident: {incident.get('incident_id')}",
                f"summary: {incident.get('summary')}",
                f"first_seen: {incident.get('first_seen')}",
            ]
        )
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        payload = json.dumps({"chat_id": self.config.telegram_chat_id, "text": text}).encode("utf-8")
        request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener(request, timeout=self.config.http_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return {"sent": False, "error": exc.__class__.__name__}
        return {"sent": bool(data.get("ok")), "message_id": data.get("result", {}).get("message_id")}


def load_env_file(path: str) -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


def safe_details(data: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in data.items():
        normalized = key.lower()
        if any(part in normalized for part in ("token", "secret", "password", "dsn")):
            continue
        result[key] = value
    return result


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str, *, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def env_bool(key: str, default: bool) -> bool:
    return os.getenv(key, str(default)).lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


def main() -> int:
    parser = argparse.ArgumentParser(description="vnpy-web-bridge host watchdog")
    parser.add_argument("--env-file", default="/Users/fujun/services/vnpy-web-bridge/.env")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    load_env_file(args.env_file)
    config = WatchdogConfig()
    if not config.enabled:
        print("watchdog disabled")
        return 0
    watchdog = Watchdog(config)
    if args.once:
        print(json.dumps(watchdog.run_once(), ensure_ascii=False, indent=2, default=str))
        return 0
    watchdog.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
