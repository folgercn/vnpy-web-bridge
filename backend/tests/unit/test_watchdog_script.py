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
    monkeypatch.setenv("TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat")
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
        "container_not_running:vnpy-web-bridge:1:firing"
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
    assert "container_not_running:vnpy-web-bridge:1:resolved" in state["deliveries"]


def test_watchdog_retries_failed_recovery_delivery(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    current = {"now": datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)}
    runner_calls = {"count": 0}
    telegram_calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            runner_calls["count"] += 1
            return completed(0, "false\n" if runner_calls["count"] == 1 else "true\n")
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        if hasattr(args[0], "full_url"):
            telegram_calls["count"] += 1
            if telegram_calls["count"] == 2:
                raise TimeoutError("telegram timeout")
        return FakeResponse()

    monkeypatch.setattr(watchdog_script, "utc_now", lambda: current["now"])
    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)

    watchdog.run_once()
    current["now"] = current["now"] + timedelta(seconds=1)
    watchdog.run_once()
    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["container_not_running:vnpy-web-bridge"]
    assert incident["status"] == "resolved"
    assert incident["delivery"]["resolved"]["sent"] is False
    assert "container_not_running:vnpy-web-bridge:1:resolved" not in state["deliveries"]

    current["now"] = current["now"] + timedelta(seconds=61)
    watchdog.run_once()
    state = watchdog_script.load_json(config.state_path, default={})
    assert state["incidents"]["container_not_running:vnpy-web-bridge"]["status"] == "healthy"
    assert "container_not_running:vnpy-web-bridge:1:resolved" in state["deliveries"]


def test_watchdog_new_episode_sends_after_resolution(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    values = iter(["false\n", "true\n", "false\n", "true\n"])

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, next(values))
        return completed(0, "ok\n")

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=lambda *args, **kwargs: FakeResponse())

    for _ in range(4):
        watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    assert "container_not_running:vnpy-web-bridge:1:firing" in state["deliveries"]
    assert "container_not_running:vnpy-web-bridge:1:resolved" in state["deliveries"]
    assert "container_not_running:vnpy-web-bridge:2:firing" in state["deliveries"]
    assert "container_not_running:vnpy-web-bridge:2:resolved" in state["deliveries"]


def test_watchdog_pending_returns_healthy_before_threshold(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    config.failure_threshold = 2
    values = iter(["false\n", "true\n"])

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, next(values))
        return completed(0, "ok\n")

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=lambda *args, **kwargs: FakeResponse())

    watchdog.run_once()
    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["container_not_running:vnpy-web-bridge"]
    assert incident["status"] == "healthy"
    assert incident["failure_count"] == 0
    assert state["deliveries"] == {}


def test_watchdog_container_failure_suppresses_liveness_check(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    opener_calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, "false\n")
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        opener_calls["count"] += 1
        return FakeResponse()

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)
    snapshot = watchdog.run_once()

    rule_ids = [check["rule_id"] for check in snapshot["checks"]]
    assert "container_not_running" in rule_ids
    assert "app_liveness_failed" not in rule_ids
    assert opener_calls["count"] == 1


def test_watchdog_docker_info_timeout_records_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    calls = {"inspect": 0, "opener": 0}

    def runner(cmd, **kwargs):
        if cmd[:2] == ["docker", "info"]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))
        if cmd[:2] == ["docker", "inspect"]:
            calls["inspect"] += 1
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        calls["opener"] += 1
        return FakeResponse()

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)
    snapshot = watchdog.run_once()

    docker_check = next(item for item in snapshot["checks"] if item["rule_id"] == "docker_daemon_unavailable")
    assert docker_check["healthy"] is False
    assert docker_check["details"]["type"] == "TimeoutExpired"
    assert calls == {"inspect": 0, "opener": 1}

    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["docker_daemon_unavailable:docker"]
    assert incident["status"] == "firing"
    assert incident["summary"] == "Docker command failed: TimeoutExpired"


def test_watchdog_docker_binary_missing_records_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "info"]:
            raise FileNotFoundError("docker")
        return completed(0, "ok\n")

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=lambda *args, **kwargs: FakeResponse())

    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["docker_daemon_unavailable:docker"]
    assert incident["status"] == "firing"
    assert incident["details"]["type"] == "FileNotFoundError"


def test_watchdog_inspect_timeout_records_container_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    opener_calls = {"count": 0}

    def runner(cmd, **kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        opener_calls["count"] += 1
        return FakeResponse()

    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)
    snapshot = watchdog.run_once()

    rule_ids = [check["rule_id"] for check in snapshot["checks"]]
    assert "container_not_running" in rule_ids
    assert "app_liveness_failed" not in rule_ids
    assert opener_calls["count"] == 1

    state = watchdog_script.load_json(config.state_path, default={})
    incident = state["incidents"]["container_not_running:vnpy-web-bridge"]
    assert incident["status"] == "firing"
    assert incident["summary"] == "container status query failed: TimeoutExpired"
    assert incident["details"]["type"] == "TimeoutExpired"


def test_watchdog_telegram_failure_retries_current_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    current = {"now": datetime(2026, 6, 18, 9, 0, tzinfo=timezone.utc)}
    calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, "false\n")
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise TimeoutError("telegram timeout")
        return FakeResponse()

    monkeypatch.setattr(watchdog_script, "utc_now", lambda: current["now"])
    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)

    watchdog.run_once()
    state = watchdog_script.load_json(config.state_path, default={})
    assert state["deliveries"] == {}
    assert state["incidents"]["container_not_running:vnpy-web-bridge"]["delivery"]["firing"]["sent"] is False

    current["now"] = current["now"] + timedelta(seconds=61)
    watchdog.run_once()
    state = watchdog_script.load_json(config.state_path, default={})
    assert "container_not_running:vnpy-web-bridge:1:firing" in state["deliveries"]


def test_watchdog_log_dir_failure_does_not_abort_disk_check(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    config.log_dir.write_text("not a directory", encoding="utf-8")

    watchdog = watchdog_script.Watchdog(config, runner=healthy_runner, opener=lambda *args, **kwargs: FakeResponse())
    snapshot = watchdog.run_once()

    checks = {item["rule_id"]: item for item in snapshot["checks"]}
    assert checks["log_dir_not_writable"]["healthy"] is False
    assert checks["disk_space_high"]["healthy"] is False
    assert checks["disk_space_high"]["summary"] == "disk check failed: FileExistsError"

    state = watchdog_script.load_json(config.state_path, default={})
    assert state["incidents"]["log_dir_not_writable:logs"]["status"] == "firing"
    assert state["incidents"]["disk_space_high:logs"]["status"] == "firing"


def test_watchdog_checker_exception_becomes_incident(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    watchdog = watchdog_script.Watchdog(config, runner=healthy_runner, opener=lambda *args, **kwargs: FakeResponse())

    def broken_liveness():
        raise RuntimeError("boom")

    monkeypatch.setattr(watchdog, "_liveness_check", broken_liveness)
    snapshot = watchdog.run_once()

    incident = watchdog_script.load_json(config.state_path, default={})["incidents"]["watchdog_checker_failed:web-bridge"]
    assert incident["status"] == "firing"
    assert incident["details"]["type"] == "RuntimeError"
    assert any(item["rule_id"] == "watchdog_checker_failed" for item in snapshot["checks"])


def test_watchdog_state_write_failure_uses_in_memory_fallback(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    telegram_calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, "false\n")
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        telegram_calls["count"] += 1
        return FakeResponse()

    def fail_save(*_args, **_kwargs):
        raise OSError("state disk read-only")

    monkeypatch.setattr(watchdog_script, "save_json", fail_save)
    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)

    watchdog.run_once()
    watchdog.run_once()

    assert telegram_calls["count"] == 1
    assert not config.state_path.exists()
    assert watchdog._fallback_state is not None
    assert "container_not_running:vnpy-web-bridge:1:firing" in watchdog._fallback_state["deliveries"]


def test_watchdog_event_write_failure_does_not_duplicate_delivery(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    telegram_calls = {"count": 0}

    def runner(cmd, **_kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return completed(0, "false\n")
        return completed(0, "ok\n")

    def opener(*args, **kwargs):
        telegram_calls["count"] += 1
        return FakeResponse()

    def fail_append(*_args, **_kwargs):
        raise OSError("events disk read-only")

    monkeypatch.setattr(watchdog_script, "append_jsonl", fail_append)
    watchdog = watchdog_script.Watchdog(config, runner=runner, opener=opener)

    watchdog.run_once()
    watchdog.run_once()

    state = watchdog_script.load_json(config.state_path, default={})
    assert telegram_calls["count"] == 1
    assert "container_not_running:vnpy-web-bridge:1:firing" in state["deliveries"]
    assert len(watchdog._pending_events) == 1


def test_watchdog_run_forever_continues_after_cycle_exception(tmp_path, monkeypatch) -> None:
    config = build_config(tmp_path, monkeypatch)
    watchdog = watchdog_script.Watchdog(config, runner=healthy_runner, opener=lambda *args, **kwargs: FakeResponse())
    calls = {"run": 0, "sleep": 0}

    def run_once():
        calls["run"] += 1
        if calls["run"] == 1:
            raise RuntimeError("cycle failed")
        raise KeyboardInterrupt()

    def sleep(_seconds):
        calls["sleep"] += 1

    monkeypatch.setattr(watchdog, "run_once", run_once)
    monkeypatch.setattr(watchdog_script.time, "sleep", sleep)

    try:
        watchdog.run_forever()
    except KeyboardInterrupt:
        pass

    assert calls == {"run": 2, "sleep": 1}


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
