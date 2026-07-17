from __future__ import annotations

from pathlib import Path
import runpy
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "tick_production_validation.py"
MODULE = runpy.run_path(str(SCRIPT), run_name="tick_production_validation")


def test_command_result_preserves_nonzero_exit_code() -> None:
    host = MODULE["DockerHost"](web_container="unused", questdb_container="unused")
    result = host.run([sys.executable, "-c", "raise SystemExit(7)"], check=False)
    assert result.returncode == 7


def test_restore_production_web_clears_interrupted_issue45_override(tmp_path: Path) -> None:
    compose = tmp_path / "deployments/docker-compose.prod.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services: {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text("APP_ENV=production\n", encoding="utf-8")
    watchdog = tmp_path / "logs/watchdog"
    watchdog.mkdir(parents=True)
    override = watchdog / "issue45-rpc-override.yml"
    override.write_text("services: {}\n", encoding="utf-8")
    maintenance = watchdog / "maintenance.json"
    maintenance.write_text('{"source":"issue45-production-validation"}', encoding="utf-8")

    host = MODULE["DockerHost"](
        web_container="web",
        questdb_container="questdb",
        deploy_path=tmp_path,
    )
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(args: list[str], **kwargs: object):
        calls.append((args, kwargs))
        if args[:3] == ["docker", "image", "ls"]:
            return MODULE["CommandResult"]("vnpy-web-bridge:sha-abc123\n", "", 0)
        return MODULE["CommandResult"]("", "", 0)

    host.run = fake_run
    host.restore_production_web()

    assert not override.exists()
    assert not maintenance.exists()
    compose_args, compose_kwargs = calls[-1]
    assert compose_args[-4:] == ["-d", "--no-deps", "--force-recreate", "web-bridge"]
    assert compose_kwargs["env"] == {"IMAGE_REPO": "vnpy-web-bridge", "IMAGE_TAG": "sha-abc123"}


def test_select_complete_trading_day_requires_night_and_day() -> None:
    selected = MODULE["select_complete_trading_day"](
        [
            {"trading_day": "20260717", "rows": 100, "start": "2026-07-17T01:00:00", "end": "2026-07-17T07:00:00"},
            {"trading_day": "20260716", "rows": 200, "start": "2026-07-15T13:00:00", "end": "2026-07-16T07:00:00"},
        ]
    )
    assert selected["trading_day"] == "20260716"


def test_select_complete_trading_day_fails_without_full_session() -> None:
    with pytest.raises(MODULE["ValidationError"]):
        MODULE["select_complete_trading_day"](
            [{"trading_day": "20260717", "rows": 100, "start": "2026-07-17T01:00:00", "end": "2026-07-17T07:00:00"}]
        )


def test_render_markdown_is_sanitized_summary() -> None:
    result = {
        "started_at": "start",
        "finished_at": "finish",
        "historical_day": {
            "trading_day": "20260716",
            "rows": 200,
            "symbols": 3,
            "exchange_count": 2,
            "start": "night",
            "end": "day",
            "peak_tps": 20,
            "average_active_tps": 10,
        },
        "checks": [{"name": "final_no_drops", "ok": True, "secret": "must-not-render"}],
        "faults": [{"name": "questdb_outage", "started_at": "now"}],
    }
    markdown = MODULE["render_markdown"](result)
    assert "final_no_drops" in markdown
    assert "questdb_outage" in markdown
    assert "must-not-render" not in markdown


def test_incident_and_spool_final_checks_cover_real_payload_fields() -> None:
    assert MODULE["is_active_incident"]({"status": "firing"})
    assert MODULE["is_active_incident"]({"state": "recovering"})
    assert not MODULE["is_active_incident"]({"status": "resolved"})
    assert MODULE["is_spool_clean"](
        {"spool_rows": 0},
        {"active_bytes": 0, "bad_files": 0, "replay_files": 0},
    )
    assert not MODULE["is_spool_clean"](
        {"spool_rows": 0},
        {"active_bytes": 0, "bad_files": 0, "replay_files": 1},
    )


def test_sanitize_evidence_removes_secrets_and_internal_addresses() -> None:
    sanitized = MODULE["sanitize_evidence"](
        {
            "last_error": "connect http://questdb:9000/write at 198.18.0.146",
            "questdb_pg_dsn": "postgresql://user:pass@questdb:8812/qdb",
            "telegram_chat_id": "123456",
        }
    )
    rendered = str(sanitized)
    assert "198.18.0.146" not in rendered
    assert "questdb:9000" not in rendered
    assert "user:pass" not in rendered
    assert "123456" not in rendered


def test_summarize_resource_peaks() -> None:
    peaks = MODULE["summarize_resource_peaks"](
        [
            {"questdb_data_kb": 100, "containers": [{"Name": "web", "CPUPerc": "1.5%", "MemUsage": "10MiB / 1GiB"}]},
            {"questdb_data_kb": None, "containers": [{"Name": "web", "CPUPerc": "2.0%", "MemUsage": "11MiB / 1GiB"}]},
            {"questdb_data_kb": 140, "containers": [{"Name": "web", "CPUPerc": "3.0%", "MemUsage": "12MiB / 1GiB"}]},
        ]
    )
    assert peaks["containers"]["web"] == {"cpu_percent": 3.0, "memory_bytes": 12 * 1024**2}
    assert peaks["questdb_data_growth_kb"] == 40
