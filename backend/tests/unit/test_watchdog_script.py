from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
WATCHDOG_PATH = ROOT / "scripts" / "watchdog.py"
spec = importlib.util.spec_from_file_location("watchdog_script", WATCHDOG_PATH)
watchdog_script = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules["watchdog_script"] = watchdog_script
spec.loader.exec_module(watchdog_script)


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, *_args):
        return b'{"ok": true}'


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def build_config(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHDOG_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("WATCHDOG_STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setenv("WATCHDOG_EVENTS_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("WATCHDOG_MAINTENANCE_FILE", str(tmp_path / "maintenance.json"))
    monkeypatch.setenv("WATCHDOG_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("WATCHDOG_RECOVERY_THRESHOLD", "1")
    monkeypatch.setenv("TELEGRAM_ENABLED", "false")
    return watchdog_script.WatchdogConfig()


def healthy_runner(cmd, **_kwargs):
    if cmd[:2] == ["docker", "inspect"]:
        return completed(0, "true\n")
    return completed(0, "ok\n")


def test_watchdog_records_single_firing_delivery(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)

    def bad_runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, "false\n")
        return completed(0, "ok\n")

    watchdog = watchdog_script.Watchdog(config, runner=bad_runner, opener=lambda *args, **kwargs: FakeResponse())

    watchdog.run_once()
    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["container_not_running:vnpy-web-bridge"]
    assert incident["status"] == "firing"
    assert list(key for key in state["deliveries"] if key.startswith("container_not_running:")) == [
        "container_not_running:vnpy-web-bridge:firing"
    ]


def test_watchdog_sends_recovery_once(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            calls["count"] += 1
            return completed(0, "false\n" if calls["count"] == 1 else "true\n")
        return completed(0, "ok\n")

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=lambda *args, **kwargs: FakeResponse())

    watchdog.run_once()
    watchdog.run_once()
    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    assert state["incidents"]["container_not_running:vnpy-web-bridge"]["status"] == "healthy"
    assert "container_not_running:vnpy-web-bridge:resolved" in state["deliveries"]


def test_active_maintenance_suppresses_runtime_checks(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    config.maintenance_file.write_text(
        '{"status":"running","expires_at":"%s","reason":"deploy"}'
        % (now + timedelta(minutes=5)).isoformat(timespec="seconds"),
        encoding="utf-8",
    )
    calls = {"docker": 0}

    def runner(cmd, **_kwargs):
        calls["docker"] += 1
        return completed(1, "", "should not run")

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=lambda *args, **kwargs: FakeResponse())
    snapshot = watchdog.run_once()

    assert calls["docker"] == 0
    assert snapshot["checks"][0]["rule_id"] == "deployment_window"
    assert snapshot["checks"][0]["healthy"] is True


def test_failed_maintenance_emits_deployment_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    config.maintenance_file.write_text(
        '{"status":"failed","expires_at":"%s","reason":"smoke failed"}'
        % (now + timedelta(minutes=5)).isoformat(timespec="seconds"),
        encoding="utf-8",
    )
    watchdog = watchdog_script.Watchdog(config, runner=healthy_runner, opener=lambda *args, **kwargs: FakeResponse())

    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    assert state["incidents"]["deployment_smoke_failed:web-bridge"]["status"] == "firing"
