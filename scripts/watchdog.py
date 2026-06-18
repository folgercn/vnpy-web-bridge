#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

    def run_forever(self) -> None:
        while True:
            self.run_once()
            time.sleep(self.config.interval_seconds)

    def run_once(self) -> dict[str, Any]:
        now = utc_now()
        state = load_json(self.config.state_path, default={"incidents": {}, "deliveries": {}})
        maintenance = self._maintenance(now)
        checks = self.collect_checks(maintenance=maintenance)
        for check in checks:
            self._apply_check(state, check, now, maintenance=maintenance)
        save_json(self.config.state_path, state)
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
        return [
            self._docker_daemon_check(),
            self._container_check(),
            self._liveness_check(),
            self._log_dir_check(),
            self._disk_check(),
        ]

    def _docker_daemon_check(self) -> CheckResult:
        result = self.runner(["docker", "info"], capture_output=True, text=True, timeout=5)
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
        result = self.runner(["docker", "inspect", "-f", "{{.State.Running}}", self.config.container_name], capture_output=True, text=True, timeout=5)
        running = result.returncode == 0 and result.stdout.strip().lower() == "true"
        return CheckResult(
            "container_not_running",
            self.config.container_name,
            running,
            "critical",
            "container running" if running else "container missing or stopped",
            {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": (result.stderr or "")[-500:]},
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
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        disk = shutil.disk_usage(self.config.log_dir)
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
            elif incident.get("status") in {"healthy", "resolved"}:
                incident["status"] = "healthy"
            return

        incident["failure_count"] = int(incident.get("failure_count") or 0) + 1
        incident["success_count"] = 0
        if incident.get("status") in {"healthy", "resolved"}:
            incident["status"] = "pending"
            incident["first_seen"] = now.isoformat(timespec="seconds")
        if incident["failure_count"] >= self.config.failure_threshold:
            incident["status"] = "firing"
            incident.setdefault("fired_at", now.isoformat(timespec="seconds"))
            self._notify_once(state, incident, "firing", now)

    def _notify_once(self, state: dict[str, Any], incident: dict[str, Any], event: str, now: datetime) -> None:
        key = f"{incident['incident_id']}:{event}"
        if key in state.setdefault("deliveries", {}):
            return
        result = self._send_telegram(incident, event=event)
        state["deliveries"][key] = {"sent_at": now.isoformat(timespec="seconds"), "result": result}
        append_jsonl(self.config.events_path, {"timestamp": now.isoformat(timespec="seconds"), "type": event, "incident_id": incident["incident_id"], "delivery": result})

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
