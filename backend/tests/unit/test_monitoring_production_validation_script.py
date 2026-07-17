from __future__ import annotations

from datetime import datetime
import importlib.util
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = ROOT / "scripts/monitoring_production_validation.py"
spec = importlib.util.spec_from_file_location("monitoring_production_validation", SCRIPT_PATH)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules["monitoring_production_validation"] = module
spec.loader.exec_module(module)


def validation(tmp_path: Path):
    deploy = tmp_path / "Users/fujun/services/vnpy-web-bridge"
    deploy.mkdir(parents=True)
    return module.MonitoringProductionValidation(
        deploy_path=deploy,
        output_path=tmp_path / "artifacts/result.json",
        markdown_path=tmp_path / "artifacts/result.md",
    )


def prepare_preflight(subject) -> None:
    subject.compose_file.parent.mkdir(parents=True)
    subject.compose_file.write_text("services: {}\n", encoding="utf-8")
    subject.watchdog_script.parent.mkdir(parents=True)
    subject.watchdog_script.write_text("", encoding="utf-8")
    subject.env_file.write_text(
        "APP_ENV=production\n"
        "MONITOR_ENABLED=true\n"
        "TELEGRAM_ENABLED=true\n"
        "TELEGRAM_BOT_TOKEN=test-token\n"
        "TELEGRAM_CHAT_ID=test-chat\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-07-17T15:29:00+08:00", False),
        ("2026-07-17T15:30:00+08:00", True),
        ("2026-07-17T19:30:00+08:00", True),
        ("2026-07-17T19:31:00+08:00", False),
        ("2026-07-18T03:59:00+08:00", False),
        ("2026-07-18T04:00:00+08:00", True),
    ],
)
def test_safe_drill_window(value: str, expected: bool) -> None:
    assert module.is_safe_drill_window(datetime.fromisoformat(value)) is expected


def test_wrong_confirmation_writes_failure_without_mutating(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: pytest.fail("preflight should not run"))
    monkeypatch.setattr(subject, "_recover_production", lambda: pytest.fail("recovery should not mutate"))

    with pytest.raises(module.ValidationError, match="ISSUE45_PRODUCTION"):
        subject.run(mode="full", confirmation="wrong")

    assert subject.report["status"] == "failed"
    assert subject.report["recovery"]["skipped"] is True
    assert subject.output_path.exists()
    assert subject.markdown_path.exists()


def test_testing_stage_requires_distinct_confirmation(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: pytest.fail("preflight should not run"))

    with pytest.raises(module.ValidationError, match="ISSUE45_TESTING"):
        subject.run(mode="full", confirmation=module.CONFIRMATION, environment_stage="testing")

    assert subject.report["recovery"]["skipped"] is True


def test_preflight_mode_never_runs_fault_scenarios_or_recovery(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: None)
    monkeypatch.setattr(subject, "_run_scenario", lambda *args: pytest.fail("fault scenario should not run"))
    monkeypatch.setattr(subject, "_recover_production", lambda: pytest.fail("recovery should not mutate"))

    result = subject.run(mode="preflight", confirmation="")

    assert result["status"] == "passed"
    assert result["recovery"]["skipped"] is True


def test_testing_stage_selects_explicit_gate_overrides(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    preflight: dict = {}
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: preflight.update(kwargs))
    monkeypatch.setattr(subject, "_run_scenario", lambda *args: None)
    monkeypatch.setattr(subject, "_recover_production", lambda: {"ok": True, "actions": []})

    result = subject.run(mode="full", confirmation=module.TESTING_CONFIRMATION, environment_stage="testing")

    assert result["status"] == "passed"
    assert result["environment_stage"] == "testing"
    assert preflight == {"require_safe_window": False, "allow_active_orders": True}


def test_testing_preflight_allows_active_orders(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    prepare_preflight(subject)
    monkeypatch.setattr(subject, "_container_health", lambda: {"web": "healthy"})
    monkeypatch.setattr(subject, "_active_incident_ids", lambda: [])
    monkeypatch.setattr(subject, "_rpc_exposure", lambda: {"positions": 1, "nonzero_positions": 0, "active_orders": 1})

    subject._preflight(require_safe_window=False, allow_active_orders=True)

    assert subject.report["preflight"]["active_orders_allowed"] is True
    assert subject.report["preflight"]["rpc"]["active_orders"] == 1


def test_production_preflight_blocks_active_orders(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    prepare_preflight(subject)
    monkeypatch.setattr(subject, "_container_health", lambda: {"web": "healthy"})
    monkeypatch.setattr(subject, "_active_incident_ids", lambda: [])
    monkeypatch.setattr(subject, "_rpc_exposure", lambda: {"positions": 1, "nonzero_positions": 0, "active_orders": 1})

    with pytest.raises(module.ValidationError, match="production exposure"):
        subject._preflight(require_safe_window=False, allow_active_orders=False)


def test_testing_preflight_still_blocks_nonzero_positions(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    prepare_preflight(subject)
    monkeypatch.setattr(subject, "_container_health", lambda: {"web": "healthy"})
    monkeypatch.setattr(subject, "_active_incident_ids", lambda: [])
    monkeypatch.setattr(subject, "_rpc_exposure", lambda: {"positions": 1, "nonzero_positions": 1, "active_orders": 0})

    with pytest.raises(module.ValidationError, match="production exposure"):
        subject._preflight(require_safe_window=False, allow_active_orders=True)


def test_rpc_exposure_starts_isolated_rpc_client(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(args, **kwargs):
        calls.append(args)
        return module.CommandResult(stdout='{"positions": 1, "nonzero_positions": 0, "active_orders": 1}\n')

    subject = module.MonitoringProductionValidation(
        deploy_path=tmp_path / "Users/fujun/services/vnpy-web-bridge",
        output_path=tmp_path / "result.json",
        markdown_path=tmp_path / "result.md",
        runner=runner,
    )

    result = subject._rpc_exposure()

    probe = calls[0][-1]
    assert probe.index("rpc_service.start()") < probe.index("rpc_service.get_positions()")
    assert result == {"positions": 1, "nonzero_positions": 0, "active_orders": 1}


def test_full_mode_recovers_and_persists_failure_evidence(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: None)
    monkeypatch.setattr(subject, "_maintenance_restart", lambda: (_ for _ in ()).throw(module.ValidationError("boom")))
    monkeypatch.setattr(subject, "_failure_diagnostics", lambda phase: {"phase": phase})
    monkeypatch.setattr(subject, "_recover_production", lambda: {"ok": True, "actions": [{"action": "restore", "ok": True}]})

    with pytest.raises(module.ValidationError, match="boom"):
        subject.run(mode="full", confirmation=module.CONFIRMATION)

    assert subject.report["status"] == "failed"
    assert subject.report["scenarios"][0]["name"] == "maintenance_restart"
    assert subject.report["scenarios"][0]["status"] == "failed"
    assert subject.report["diagnostics"] == [{"phase": "scenario_failure"}]
    assert subject.report["recovery"]["ok"] is True
    assert "boom" in subject.markdown_path.read_text(encoding="utf-8")


def test_failure_diagnostics_capture_sanitized_container_state_and_error_logs(tmp_path: Path, monkeypatch) -> None:
    state = {
        "Status": "running",
        "Running": True,
        "Restarting": False,
        "ExitCode": 0,
        "OOMKilled": False,
        "Error": "",
        "Health": {
            "Status": "unhealthy",
            "FailingStreak": 3,
            "Log": [{"ExitCode": 1, "Output": "RPC tcp://10.0.0.8:2014 failed token=abc"}],
        },
    }

    def runner(args, **kwargs):
        if args[1] == "inspect":
            return module.CommandResult(stdout=module.json.dumps(state))
        if args[1] == "logs":
            return module.CommandResult(
                stderr=(
                    "INFO routine request account_id=visible-if-context-leaks\n"
                    "ERROR RPC tcp://10.0.0.8:2014 failed password=hunter2 symbol=rb2510 account_id=123\n"
                    "Traceback: boom\n"
                )
            )
        raise AssertionError(args)

    subject = module.MonitoringProductionValidation(
        deploy_path=tmp_path / "Users/fujun/services/vnpy-web-bridge",
        output_path=tmp_path / "result.json",
        markdown_path=tmp_path / "result.md",
        runner=runner,
    )
    monkeypatch.setattr(subject, "_liveness_diagnostic", lambda: {"status": "unreachable"})

    result = subject._failure_diagnostics("scenario_failure")
    serialized = module.json.dumps(result)

    assert result["containers"]["vnpy-web-bridge"]["health"]["status"] == "unhealthy"
    assert result["containers"]["vnpy-web-bridge"]["health"]["failing_streak"] == 3
    assert result["web_bridge_log_tail"]
    assert "10.0.0.8" not in serialized
    assert "hunter2" not in serialized
    assert "abc" not in serialized
    assert "visible-if-context-leaks" not in serialized
    assert "rb2510" not in serialized
    assert "123" not in serialized


def test_diagnostic_collection_failure_never_masks_validation_error(tmp_path: Path, monkeypatch) -> None:
    subject = validation(tmp_path)
    monkeypatch.setattr(subject, "_preflight", lambda **kwargs: None)
    monkeypatch.setattr(subject, "_maintenance_restart", lambda: (_ for _ in ()).throw(module.ValidationError("primary")))
    monkeypatch.setattr(subject, "_failure_diagnostics", lambda phase: (_ for _ in ()).throw(RuntimeError("diagnostic")))
    monkeypatch.setattr(subject, "_recover_production", lambda: {"ok": True, "actions": []})

    with pytest.raises(module.ValidationError, match="primary"):
        subject.run(mode="full", confirmation=module.CONFIRMATION)

    assert subject.report["error"]["message"] == "primary"
    assert subject.report["diagnostics"][0]["collection_error"]["message"] == "diagnostic"


def test_clear_maintenance_preserves_foreign_file(tmp_path: Path) -> None:
    subject = validation(tmp_path)
    subject.maintenance_file.parent.mkdir(parents=True)
    subject.maintenance_file.write_text('{"status":"running","source":"deploy"}', encoding="utf-8")

    subject._clear_maintenance()

    assert subject.maintenance_file.exists()


def test_delivery_helpers_support_backend_and_watchdog_shapes() -> None:
    backend = {"delivery": {"firing": {"sent": True, "result": {"telegram_message_id": 12}}}}
    watchdog = {"delivery": {"resolved": {"sent": True, "result": {"message_id": 13}}}}

    assert module.delivery_sent(backend, "firing") is True
    assert module.delivery_message_id(backend, "firing") == 12
    assert module.delivery_message_id(watchdog, "resolved") == 13
    assert module.delivery_outcome(backend, "firing") == "sent"
    assert module.delivery_outcome({"delivery": {"firing": {"result": {"skipped": "level_disabled"}}}}, "firing") == "skipped:level_disabled"


def test_sanitize_text_removes_transport_secrets_and_addresses() -> None:
    value = (
        "https://api.telegram.org/bot123:secret/sendMessage tcp://10.0.0.1:2014 "
        "postgresql://u:p@db/vnpy password=hunter2 token=abc client=192.168.1.5 "
        "account_id=123 symbol=rb2510 order_id=456 tradeid=789"
    )

    sanitized = module.sanitize_text(value)

    assert "secret" not in sanitized
    assert "10.0.0.1" not in sanitized
    assert "u:p" not in sanitized
    assert "hunter2" not in sanitized
    assert "abc" not in sanitized
    assert "192.168.1.5" not in sanitized
    assert "rb2510" not in sanitized
    assert "123" not in sanitized
    assert "456" not in sanitized
    assert "789" not in sanitized
