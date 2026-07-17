#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.request
from zoneinfo import ZoneInfo


CONFIRMATION = "ISSUE45_PRODUCTION"
TESTING_CONFIRMATION = "ISSUE45_TESTING"
ACTIVE_STATUSES = {"pending", "firing", "acknowledged", "recovering"}
SHANGHAI = ZoneInfo("Asia/Shanghai")
DIAGNOSTIC_LOG_PATTERN = re.compile(
    r"traceback|error|exception|failed|warning|critical|startup|uvicorn|rpc|health|address already in use|bind",
    re.IGNORECASE,
)


class ValidationError(RuntimeError):
    pass


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    def __call__(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 60,
        check: bool = True,
    ) -> CommandResult:
        result = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            message = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise ValidationError(f"command failed: {args[0]}: {sanitize_text(message)[:500]}")
        return CommandResult(stdout=result.stdout, stderr=result.stderr)


class MonitoringProductionValidation:
    def __init__(
        self,
        *,
        deploy_path: Path,
        output_path: Path,
        markdown_path: Path,
        runner: Callable[..., CommandResult] | None = None,
        now: Callable[[], datetime] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.deploy_path = deploy_path.resolve()
        self.output_path = output_path
        self.markdown_path = markdown_path
        self.runner = runner or CommandRunner()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sleeper = sleeper or time.sleep
        self.compose_file = self.deploy_path / "deployments/docker-compose.prod.yml"
        self.env_file = self.deploy_path / ".env"
        self.monitor_state = self.deploy_path / "logs/monitor/state.json"
        self.watchdog_state = self.deploy_path / "logs/watchdog/state.json"
        self.maintenance_file = self.deploy_path / "logs/watchdog/maintenance.json"
        self.watchdog_script = self.deploy_path / "scripts/watchdog.py"
        self.rpc_override = self.deploy_path / "logs/watchdog/issue45-rpc-override.yml"
        self.manual_watchdog_maintenance = self.deploy_path / "logs/watchdog/issue45-manual-maintenance.json"
        self.mutation_started = False
        self.rpc_override_active = False
        self.web_bridge_image = ""
        self.environment_stage = "production"
        self.allow_active_orders = False
        self.report: dict[str, Any] = {
            "issue": 45,
            "started_at": self._iso_now(),
            "status": "running",
            "preflight": {},
            "scenarios": [],
            "diagnostics": [],
            "recovery": {},
        }

    def run(self, *, mode: str, confirmation: str, environment_stage: str = "production") -> dict[str, Any]:
        failure: BaseException | None = None
        try:
            self.environment_stage = environment_stage
            self.allow_active_orders = environment_stage == "testing"
            self.report["environment_stage"] = environment_stage
            self._require_confirmation(mode, confirmation, environment_stage)
            self._preflight(
                require_safe_window=mode == "full" and environment_stage == "production",
                allow_active_orders=self.allow_active_orders,
            )
            if mode == "full":
                self.mutation_started = True
                self._run_scenario("maintenance_restart", self._maintenance_restart)
                self._run_scenario("watchdog_telegram_retry", self._watchdog_telegram_retry)
                self._run_scenario("questdb_root_suppression", self._questdb_root_suppression)
                self._run_scenario("postgres_outage", self._postgres_outage)
                self._run_scenario("rpc_root_suppression", self._rpc_root_suppression)
                self._run_scenario("final_health", self._final_health)
            self.report["status"] = "passed"
        except BaseException as exc:
            failure = exc
            self.report["status"] = "failed"
            self.report["error"] = {"type": exc.__class__.__name__, "message": sanitize_text(str(exc))[:500]}
            if self.mutation_started:
                self.report["diagnostics"].append(self._safe_failure_diagnostics("scenario_failure"))
        finally:
            self.report["recovery"] = self._recover_production() if self.mutation_started else {"ok": True, "skipped": True, "actions": []}
            if not self.report["recovery"].get("ok"):
                self.report["status"] = "failed"
                self.report.setdefault("error", {"type": "RecoveryError", "message": "production recovery was incomplete"})
                self.report["diagnostics"].append(self._safe_failure_diagnostics("post_recovery"))
            self.report["finished_at"] = self._iso_now()
            self._write_evidence()
        if failure:
            raise failure
        return self.report

    def _require_confirmation(self, mode: str, confirmation: str, environment_stage: str) -> None:
        if environment_stage not in {"production", "testing"}:
            raise ValidationError("environment stage must be production or testing")
        expected = TESTING_CONFIRMATION if environment_stage == "testing" else CONFIRMATION
        if mode == "full" and confirmation != expected:
            raise ValidationError(f"full {environment_stage} mode requires --confirm {expected}")

    def _preflight(self, *, require_safe_window: bool, allow_active_orders: bool) -> None:
        if self.deploy_path == Path("/") or len(self.deploy_path.parts) < 4:
            raise ValidationError("unsafe deployment path")
        for path in (self.deploy_path, self.compose_file, self.env_file, self.watchdog_script):
            if not path.exists():
                raise ValidationError(f"required path is missing: {path}")
        local_now = self.now().astimezone(SHANGHAI)
        if require_safe_window and not is_safe_drill_window(local_now):
            raise ValidationError("production fault drills are allowed only during the configured non-trading window")

        env = load_env(self.env_file)
        if env.get("APP_ENV", "").lower() != "production":
            raise ValidationError("APP_ENV must be production")
        if not env_bool(env.get("MONITOR_ENABLED"), False):
            raise ValidationError("MONITOR_ENABLED must be true")
        if not env_bool(env.get("TELEGRAM_ENABLED"), False):
            raise ValidationError("TELEGRAM_ENABLED must be true")
        if not env.get("TELEGRAM_BOT_TOKEN") or not env.get("TELEGRAM_CHAT_ID"):
            raise ValidationError("Telegram credentials are not configured")

        containers = self._container_health()
        unhealthy = [name for name, status in containers.items() if status not in {"healthy", "running"}]
        if unhealthy:
            raise ValidationError(f"containers are not healthy: {', '.join(unhealthy)}")
        self.web_bridge_image = self._container_image("vnpy-web-bridge")
        if self.maintenance_file.exists():
            raise ValidationError("an existing deployment maintenance file must be cleared before validation")
        active = self._active_incident_ids()
        if active:
            raise ValidationError(f"active incidents must be cleared first: {', '.join(active)}")
        exposure = self._rpc_exposure()
        if exposure["nonzero_positions"] or (exposure["active_orders"] and not allow_active_orders):
            raise ValidationError("production exposure is active; refusing fault drills")

        self.report["preflight"] = {
            "checked_at": local_now.isoformat(timespec="seconds"),
            "safe_window": is_safe_drill_window(local_now),
            "containers": containers,
            "active_incident_count": 0,
            "rpc": exposure,
            "active_orders_allowed": allow_active_orders,
            "compose_image_pinned": True,
            "monitor_enabled": True,
            "telegram_enabled": True,
        }

    def _run_scenario(self, name: str, callback: Callable[[], dict[str, Any]]) -> None:
        item: dict[str, Any] = {"name": name, "started_at": self._iso_now(), "status": "running"}
        self.report["scenarios"].append(item)
        try:
            item["evidence"] = callback()
            item["status"] = "passed"
        except BaseException as exc:
            item["status"] = "failed"
            item["error"] = {"type": exc.__class__.__name__, "message": sanitize_text(str(exc))[:500]}
            raise
        finally:
            item["finished_at"] = self._iso_now()

    def _maintenance_restart(self) -> dict[str, Any]:
        tracked = [
            "container_not_running:vnpy-web-bridge",
            "app_liveness_failed:web-bridge",
            "deployment_smoke_failed:web-bridge",
        ]
        before = {incident_id: self._episode(self.watchdog_state, incident_id) for incident_id in tracked}
        self._write_maintenance("Issue #45 maintenance-window restart", ttl_seconds=300)
        self._docker("restart", "vnpy-web-bridge", timeout=90)
        self._wait_liveness(timeout=180)
        self._clear_maintenance()
        self._run_watchdog()
        after = {incident_id: self._episode(self.watchdog_state, incident_id) for incident_id in tracked}
        if after != before:
            raise ValidationError("maintenance restart created a watchdog incident episode")
        return {"tracked_incidents": tracked, "new_episode_count": 0, "liveness": "ok"}

    def _watchdog_telegram_retry(self) -> dict[str, Any]:
        incident_id = "container_not_running:vnpy-web-bridge"
        before = self._episode(self.watchdog_state, incident_id)
        self._write_maintenance("Issue #45 watchdog delivery drill", ttl_seconds=300)
        self._docker("stop", "vnpy-web-bridge", timeout=90)
        manual_env = dict(os.environ)
        for key in load_env(self.env_file):
            manual_env.pop(key, None)
        manual_env["WATCHDOG_MAINTENANCE_FILE"] = str(self.manual_watchdog_maintenance)
        invalid_env = dict(manual_env)
        invalid_env["TELEGRAM_BOT_TOKEN"] = "issue45-invalid-token"
        for _ in range(self._watchdog_threshold("WATCHDOG_FAILURE_THRESHOLD", 3)):
            self._run_watchdog(env=invalid_env)
        failed = self._wait_incident(
            self.watchdog_state,
            incident_id,
            statuses={"firing"},
            episode_gt=before,
            timeout=30,
        )
        if bool((failed.get("delivery") or {}).get("firing", {}).get("sent")):
            raise ValidationError("invalid Telegram token unexpectedly delivered")
        retry_at = parse_time(str((failed.get("delivery") or {}).get("next_retry_at") or ""))
        delay = max(0.0, (retry_at - self.now()).total_seconds()) + 2
        self.sleeper(delay)
        self._run_watchdog(env=manual_env)
        delivered = self._wait_incident(
            self.watchdog_state,
            incident_id,
            statuses={"firing"},
            episode_gt=before,
            delivery_event="firing",
            timeout=30,
        )
        self._docker("start", "vnpy-web-bridge", timeout=90)
        self._wait_liveness(timeout=180)
        for _ in range(self._watchdog_threshold("WATCHDOG_RECOVERY_THRESHOLD", 2) + 1):
            self._run_watchdog(env=manual_env)
        recovered = self._wait_incident(
            self.watchdog_state,
            incident_id,
            statuses={"resolved", "healthy"},
            episode_gt=before,
            delivery_event="resolved",
            timeout=30,
        )
        self._clear_maintenance()
        return {
            "incident_id": incident_id,
            "episode": int(delivered.get("episode_seq") or 0),
            "failed_attempt_recorded": True,
            "firing_message_id": delivery_message_id(delivered, "firing"),
            "resolved_message_id": delivery_message_id(recovered, "resolved"),
        }

    def _questdb_root_suppression(self) -> dict[str, Any]:
        root_id = "questdb_unavailable:market_ticks"
        derived_id = "questdb_tick_persistence_lag:market_ticks"
        before = self._episode(self.monitor_state, root_id)
        self._docker("stop", "vnpy-web-bridge-questdb", timeout=90)
        firing = self._wait_incident(
            self.monitor_state,
            root_id,
            statuses={"firing", "acknowledged"},
            episode_gt=before,
            delivery_event="firing",
            timeout=240,
        )
        derived = self._incident(self.monitor_state, derived_id)
        if derived and derived.get("status") in ACTIVE_STATUSES:
            raise ValidationError("QuestDB root cause did not suppress tick persistence incident")
        self._docker("start", "vnpy-web-bridge-questdb", timeout=90)
        self._wait_container("vnpy-web-bridge-questdb", timeout=180)
        recovered = self._wait_incident(
            self.monitor_state,
            root_id,
            statuses={"resolved", "healthy"},
            episode_gt=before,
            delivery_event="resolved",
            timeout=180,
        )
        return {
            "incident_id": root_id,
            "episode": int(firing.get("episode_seq") or 0),
            "derived_incident_active": False,
            "firing_message_id": delivery_message_id(firing, "firing"),
            "resolved_message_id": delivery_message_id(recovered, "resolved"),
        }

    def _postgres_outage(self) -> dict[str, Any]:
        incident_id = "postgres_unavailable:watchlist"
        before = self._episode(self.monitor_state, incident_id)
        self._docker("stop", "vnpy-web-bridge-postgres", timeout=90)
        firing = self._wait_incident(
            self.monitor_state,
            incident_id,
            statuses={"firing", "acknowledged"},
            episode_gt=before,
            delivery_event="firing",
            timeout=240,
        )
        self._docker("start", "vnpy-web-bridge-postgres", timeout=90)
        self._wait_container("vnpy-web-bridge-postgres", timeout=180)
        recovered = self._wait_incident(
            self.monitor_state,
            incident_id,
            statuses={"resolved", "healthy"},
            episode_gt=before,
            delivery_event="resolved",
            timeout=180,
        )
        return {
            "incident_id": incident_id,
            "episode": int(firing.get("episode_seq") or 0),
            "firing_message_id": delivery_message_id(firing, "firing"),
            "resolved_message_id": delivery_message_id(recovered, "resolved"),
        }

    def _rpc_root_suppression(self) -> dict[str, Any]:
        root_id = "rpc_unavailable:CTP"
        derived_ids = [
            "gateway_disconnected:CTP",
            "tick_stale:market_ticks",
            "strategy_rpc_error:expected_strategies",
        ]
        before = self._episode(self.monitor_state, root_id)
        self.rpc_override.parent.mkdir(parents=True, exist_ok=True)
        self.rpc_override.write_text(
            "services:\n"
            "  web-bridge:\n"
            "    environment:\n"
            "      VNPY_RPC_REQ_ADDRESS: tcp://127.0.0.1:1\n"
            "      VNPY_RPC_PUB_ADDRESS: tcp://127.0.0.1:2\n",
            encoding="utf-8",
        )
        self.rpc_override_active = True
        self._write_maintenance("Issue #45 RPC root-cause drill", ttl_seconds=300)
        self._compose_with_override("up", "-d", "--no-deps", "--force-recreate", "web-bridge", timeout=180)
        self._wait_liveness(timeout=180)
        self._clear_maintenance()
        firing = self._wait_incident(
            self.monitor_state,
            root_id,
            statuses={"firing", "acknowledged"},
            episode_gt=before,
            timeout=360,
        )
        active_derived = [
            incident_id
            for incident_id in derived_ids
            if (self._incident(self.monitor_state, incident_id) or {}).get("status") in ACTIVE_STATUSES
        ]
        if active_derived:
            raise ValidationError(f"RPC root cause left derived incidents active: {', '.join(active_derived)}")

        self._write_maintenance("Issue #45 RPC recovery", ttl_seconds=300)
        self._compose("up", "-d", "--no-deps", "--force-recreate", "web-bridge", timeout=180)
        self.rpc_override.unlink(missing_ok=True)
        self.rpc_override_active = False
        self._wait_liveness(timeout=180)
        self._clear_maintenance()
        recovered = self._wait_incident(
            self.monitor_state,
            root_id,
            statuses={"resolved", "healthy"},
            episode_gt=before,
            timeout=360,
        )
        exposure = self._rpc_exposure()
        if exposure["nonzero_positions"] or (exposure["active_orders"] and not self.allow_active_orders):
            raise ValidationError("RPC recovered with active exposure")
        return {
            "incident_id": root_id,
            "episode": int(firing.get("episode_seq") or 0),
            "active_derived_incidents": [],
            "firing_message_id": delivery_message_id(firing, "firing"),
            "resolved_message_id": delivery_message_id(recovered, "resolved"),
            "firing_delivery": delivery_outcome(firing, "firing"),
            "resolved_delivery": delivery_outcome(recovered, "resolved"),
            "rpc": exposure,
        }

    def _final_health(self) -> dict[str, Any]:
        containers = self._container_health()
        unhealthy = [name for name, status in containers.items() if status not in {"healthy", "running"}]
        if unhealthy:
            raise ValidationError(f"final container health failed: {', '.join(unhealthy)}")
        self._wait_liveness(timeout=180)
        self._wait_for(lambda: not self._active_incident_ids(), timeout=360, description="all incidents to resolve")
        exposure = self._rpc_exposure()
        if exposure["nonzero_positions"] or (exposure["active_orders"] and not self.allow_active_orders):
            raise ValidationError("final RPC exposure is active")
        return {
            "containers": containers,
            "liveness": "ok",
            "active_incident_count": 0,
            "rpc": exposure,
        }

    def _recover_production(self) -> dict[str, Any]:
        actions: list[dict[str, Any]] = []
        try:
            self._write_maintenance("Issue #45 automatic recovery", ttl_seconds=600)
            actions.append({"action": "start_recovery_maintenance", "ok": True})
        except Exception as exc:
            actions.append({"action": "start_recovery_maintenance", "ok": False, "error": exc.__class__.__name__})
        for container in ("vnpy-web-bridge-questdb", "vnpy-web-bridge-postgres"):
            try:
                self._docker("start", container, timeout=90, check=False)
                actions.append({"action": f"start:{container}", "ok": True})
            except Exception as exc:
                actions.append({"action": f"start:{container}", "ok": False, "error": exc.__class__.__name__})
        try:
            if self.rpc_override_active or self.rpc_override.exists():
                self._compose("up", "-d", "--no-deps", "--force-recreate", "web-bridge", timeout=180)
                self.rpc_override_active = False
            else:
                self._docker("start", "vnpy-web-bridge", timeout=90, check=False)
            actions.append({"action": "restore:web-bridge", "ok": True})
        except Exception as exc:
            actions.append({"action": "restore:web-bridge", "ok": False, "error": exc.__class__.__name__})
        try:
            self.rpc_override.unlink(missing_ok=True)
            actions.append({"action": "remove_rpc_override", "ok": True})
        except Exception as exc:
            actions.append({"action": "remove_rpc_override", "ok": False, "error": exc.__class__.__name__})
        try:
            self._wait_container("vnpy-web-bridge-questdb", timeout=180)
            self._wait_container("vnpy-web-bridge-postgres", timeout=180)
            self._wait_liveness(timeout=180)
            actions.append({"action": "verify_containers_and_liveness", "ok": True})
        except Exception as exc:
            actions.append({"action": "verify_containers_and_liveness", "ok": False, "error": exc.__class__.__name__})
        try:
            self._clear_maintenance()
            actions.append({"action": "clear_recovery_maintenance", "ok": True})
        except Exception as exc:
            actions.append({"action": "clear_recovery_maintenance", "ok": False, "error": exc.__class__.__name__})
        try:
            self._wait_for(lambda: not self._active_incident_ids(), timeout=360, description="recovery incidents to resolve")
            actions.append({"action": "verify_no_active_incidents", "ok": True})
        except Exception as exc:
            actions.append({"action": "verify_no_active_incidents", "ok": False, "error": exc.__class__.__name__})
        return {"actions": actions, "ok": all(item["ok"] for item in actions)}

    def _safe_failure_diagnostics(self, phase: str) -> dict[str, Any]:
        try:
            return self._failure_diagnostics(phase)
        except BaseException as exc:
            return {
                "phase": phase,
                "collected_at": self._iso_now(),
                "collection_error": {
                    "type": exc.__class__.__name__,
                    "message": sanitize_text(str(exc))[:500],
                },
            }

    def _failure_diagnostics(self, phase: str) -> dict[str, Any]:
        containers = {
            name: self._container_diagnostic(name)
            for name in ("vnpy-web-bridge", "vnpy-web-bridge-questdb", "vnpy-web-bridge-postgres")
        }
        return {
            "phase": phase,
            "collected_at": self._iso_now(),
            "liveness": self._liveness_diagnostic(),
            "containers": containers,
            "web_bridge_log_tail": self._web_bridge_diagnostic_logs(),
        }

    def _container_diagnostic(self, name: str) -> dict[str, Any]:
        result = self._docker("inspect", "--format", "{{json .State}}", name, timeout=15, check=False)
        try:
            state = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return {
                "status": "missing",
                "error": sanitize_text(result.stderr.strip() or result.stdout.strip() or "inspect returned no state")[:500],
            }

        health = state.get("Health") or {}
        health_logs = []
        for item in (health.get("Log") or [])[-3:]:
            health_logs.append(
                {
                    "exit_code": int(item.get("ExitCode") or 0),
                    "output": sanitize_text(str(item.get("Output") or ""))[:1000],
                }
            )
        return {
            "status": str(state.get("Status") or "unknown"),
            "running": bool(state.get("Running")),
            "restarting": bool(state.get("Restarting")),
            "exit_code": int(state.get("ExitCode") or 0),
            "oom_killed": bool(state.get("OOMKilled")),
            "error": sanitize_text(str(state.get("Error") or ""))[:500],
            "health": {
                "status": str(health.get("Status") or "not_configured"),
                "failing_streak": int(health.get("FailingStreak") or 0),
                "checks": health_logs,
            },
        }

    def _liveness_diagnostic(self) -> dict[str, Any]:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/api/health/live", timeout=3) as response:
                payload = response.read(2000).decode("utf-8", errors="replace")
            return {"status": int(response.status), "body": sanitize_text(payload)[:2000]}
        except Exception as exc:
            return {"status": "unreachable", "error": sanitize_text(f"{exc.__class__.__name__}: {exc}")[:500]}

    def _web_bridge_diagnostic_logs(self) -> list[str]:
        result = self._docker(
            "logs",
            "--since",
            "15m",
            "--tail",
            "300",
            "vnpy-web-bridge",
            timeout=30,
            check=False,
        )
        lines = (result.stdout + "\n" + result.stderr).splitlines()
        selected = [line for line in lines if DIAGNOSTIC_LOG_PATTERN.search(line)]
        return [sanitize_text(line)[:1000] for line in selected[-120:]]

    def _rpc_exposure(self) -> dict[str, int]:
        code = (
            "import json; "
            "from app.services.vnpy_rpc_service import rpc_service; "
            "rpc_service.start(); "
            "positions=rpc_service.get_positions(); "
            "orders=list(rpc_service.call('get_all_active_orders') or []); "
            "nonzero=sum(1 for p in positions if abs(float(p.get('volume') or 0)) > 0); "
            "print(json.dumps({'positions':len(positions),'nonzero_positions':nonzero,'active_orders':len(orders)})); "
            "rpc_service.stop()"
        )
        result = self._docker("exec", "vnpy-web-bridge", "python", "-c", code, timeout=45)
        try:
            payload = json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise ValidationError("unable to read sanitized RPC exposure") from exc
        return {key: int(payload[key]) for key in ("positions", "nonzero_positions", "active_orders")}

    def _active_incident_ids(self) -> list[str]:
        result: list[str] = []
        for path in (self.monitor_state, self.watchdog_state):
            state = load_json(path, default={})
            for incident_id, incident in (state.get("incidents") or {}).items():
                if incident.get("status") in ACTIVE_STATUSES:
                    result.append(str(incident_id))
        return sorted(set(result))

    def _wait_incident(
        self,
        path: Path,
        incident_id: str,
        *,
        statuses: set[str],
        episode_gt: int,
        timeout: int,
        delivery_event: str | None = None,
    ) -> dict[str, Any]:
        found: dict[str, Any] = {}

        def ready() -> bool:
            nonlocal found
            found = self._incident(path, incident_id) or {}
            if int(found.get("episode_seq") or 0) <= episode_gt or found.get("status") not in statuses:
                return False
            if delivery_event:
                return delivery_sent(found, delivery_event)
            return True

        self._wait_for(ready, timeout=timeout, description=f"{incident_id} in {sorted(statuses)}")
        return found

    def _incident(self, path: Path, incident_id: str) -> dict[str, Any] | None:
        state = load_json(path, default={})
        incident = (state.get("incidents") or {}).get(incident_id)
        return dict(incident) if isinstance(incident, dict) else None

    def _episode(self, path: Path, incident_id: str) -> int:
        return int((self._incident(path, incident_id) or {}).get("episode_seq") or 0)

    def _wait_for(self, callback: Callable[[], bool], *, timeout: int, description: str) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if callback():
                return
            self.sleeper(5)
        raise ValidationError(f"timed out waiting for {description}")

    def _wait_liveness(self, *, timeout: int) -> None:
        def healthy() -> bool:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8080/api/health/live", timeout=3) as response:
                    payload = json.load(response)
                data = payload.get("data") or {}
                return response.status == 200 and data.get("status") == "live" and data.get("env") == "production"
            except Exception:
                return False

        self._wait_for(healthy, timeout=timeout, description="production liveness")

    def _wait_container(self, name: str, *, timeout: int) -> None:
        self._wait_for(
            lambda: self._container_status(name) in {"healthy", "running"},
            timeout=timeout,
            description=f"{name} health",
        )

    def _container_health(self) -> dict[str, str]:
        return {
            name: self._container_status(name)
            for name in ("vnpy-web-bridge", "vnpy-web-bridge-questdb", "vnpy-web-bridge-postgres")
        }

    def _container_status(self, name: str) -> str:
        result = self._docker(
            "inspect",
            "--format",
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
            name,
            timeout=15,
            check=False,
        )
        return result.stdout.strip() or "missing"

    def _container_image(self, name: str) -> str:
        result = self._docker("inspect", "--format", "{{.Config.Image}}", name, timeout=15)
        image = result.stdout.strip()
        if not image:
            raise ValidationError(f"container image reference is missing: {name}")
        return image

    def _watchdog_threshold(self, key: str, default: int) -> int:
        return max(1, int(load_env(self.env_file).get(key, str(default))))

    def _run_watchdog(self, *, env: dict[str, str] | None = None) -> None:
        self.runner(
            ["python3", str(self.watchdog_script), "--env-file", str(self.env_file), "--once"],
            cwd=self.deploy_path,
            env=env,
            timeout=30,
            check=True,
        )

    def _write_maintenance(self, reason: str, *, ttl_seconds: int) -> None:
        now = self.now()
        payload = {
            "status": "running",
            "reason": reason,
            "started_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds"),
            "source": "issue45-production-validation",
        }
        self.maintenance_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.maintenance_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.maintenance_file)

    def _clear_maintenance(self) -> None:
        payload = load_json(self.maintenance_file, default={})
        if payload.get("source") == "issue45-production-validation":
            self.maintenance_file.unlink(missing_ok=True)

    def _compose(self, *args: str, timeout: int, check: bool = True) -> CommandResult:
        return self.runner(
            ["docker", "compose", "--env-file", str(self.env_file), "-f", str(self.compose_file), *args],
            cwd=self.deploy_path,
            env=self._compose_environment(),
            timeout=timeout,
            check=check,
        )

    def _compose_with_override(self, *args: str, timeout: int, check: bool = True) -> CommandResult:
        return self.runner(
            [
                "docker",
                "compose",
                "--env-file",
                str(self.env_file),
                "-f",
                str(self.compose_file),
                "-f",
                str(self.rpc_override),
                *args,
            ],
            cwd=self.deploy_path,
            env=self._compose_environment(),
            timeout=timeout,
            check=check,
        )

    def _compose_environment(self) -> dict[str, str]:
        repository, tag = split_image_reference(self.web_bridge_image)
        environment = dict(os.environ)
        environment["IMAGE_REPO"] = repository
        environment["IMAGE_TAG"] = tag
        return environment

    def _docker(self, *args: str, timeout: int, check: bool = True) -> CommandResult:
        return self.runner(["docker", *args], cwd=self.deploy_path, timeout=timeout, check=check)

    def _write_evidence(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.markdown_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(self.report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        lines = [
            "# Issue #45 production monitoring validation",
            "",
            f"- Status: **{self.report.get('status')}**",
            f"- Started: `{self.report.get('started_at')}`",
            f"- Finished: `{self.report.get('finished_at')}`",
            f"- Recovery complete: `{bool((self.report.get('recovery') or {}).get('ok'))}`",
            "",
            "## Scenarios",
            "",
            "| Scenario | Status |",
            "|---|---|",
        ]
        lines.extend(f"| `{item['name']}` | {item['status']} |" for item in self.report.get("scenarios", []))
        if self.report.get("error"):
            lines.extend(["", "## Error", "", f"`{self.report['error']['type']}: {self.report['error']['message']}`"])
        if self.report.get("diagnostics"):
            lines.extend(["", "## Failure diagnostics", ""])
            for item in self.report["diagnostics"]:
                container_states = ", ".join(
                    f"{name}={details.get('status', 'unknown')}"
                    for name, details in (item.get("containers") or {}).items()
                )
                lines.append(
                    f"- `{item.get('phase')}`: liveness=`{(item.get('liveness') or {}).get('status', 'unknown')}`; "
                    f"containers: {container_states or 'unavailable'}; filtered log lines: "
                    f"`{len(item.get('web_bridge_log_tail') or [])}`"
                )
        self.markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _iso_now(self) -> str:
        return self.now().astimezone(timezone.utc).isoformat(timespec="seconds")


def is_safe_drill_window(value: datetime) -> bool:
    local = value.astimezone(SHANGHAI)
    minute = local.hour * 60 + local.minute
    if local.weekday() < 5:
        return 15 * 60 + 30 <= minute <= 19 * 60 + 30
    return 4 * 60 <= minute <= 19 * 60 + 30


def split_image_reference(value: str) -> tuple[str, str]:
    image = value.strip()
    if not image or "@" in image:
        raise ValidationError("current Web Bridge image must use a tagged reference")
    separator = image.rfind(":")
    if separator > image.rfind("/"):
        repository, tag = image[:separator], image[separator + 1 :]
    else:
        repository, tag = image, "latest"
    if not repository or not tag:
        raise ValidationError("current Web Bridge image reference is invalid")
    return repository, tag


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def env_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def delivery_sent(incident: dict[str, Any], event: str) -> bool:
    delivery = (incident.get("delivery") or {}).get(event) or {}
    if delivery.get("sent"):
        return True
    result = delivery.get("result") or {}
    return bool(result.get("sent"))


def delivery_message_id(incident: dict[str, Any], event: str) -> int | None:
    delivery = (incident.get("delivery") or {}).get(event) or {}
    result = delivery.get("result") or {}
    value = result.get("telegram_message_id") or result.get("message_id")
    return int(value) if isinstance(value, (int, str)) and str(value).isdigit() else None


def delivery_outcome(incident: dict[str, Any], event: str) -> str:
    delivery = (incident.get("delivery") or {}).get(event) or {}
    if delivery.get("sent"):
        return "sent"
    result = delivery.get("result") or {}
    skipped = delivery.get("skipped") or result.get("skipped")
    if skipped:
        return f"skipped:{skipped}"
    if delivery.get("error") or result.get("error"):
        return "failed"
    return "not_recorded"


def sanitize_text(value: str) -> str:
    result = re.sub(r"https://api\.telegram\.org/bot[^/\s]+", "https://api.telegram.org/bot[redacted]", value)
    result = re.sub(r"\b(?:tcp|ipc)://[^\s,;]+", "[rpc-address-redacted]", result)
    result = re.sub(r"\b(?:postgresql|postgres)://[^\s]+", "[dsn-redacted]", result)
    result = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key|chat[_-]?id)\s*[:=]\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=[redacted]",
        result,
    )
    result = re.sub(
        r"(?i)(\b(?:account(?:id|_id)?|symbol|vt_symbol|order(?:id|_id)|trade(?:id|_id))\s*[:=]\s*)[^\s,;]+",
        lambda match: f"{match.group(1)}[redacted]",
        result,
    )
    result = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", "[ip-redacted]", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue #45 production monitoring validation")
    parser.add_argument("--mode", choices=("preflight", "full"), default="preflight")
    parser.add_argument("--environment-stage", choices=("production", "testing"), default="production")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--deploy-path", default="/Users/fujun/services/vnpy-web-bridge")
    parser.add_argument("--output", default="artifacts/issue-45-production-validation.json")
    parser.add_argument("--markdown-output", default="artifacts/issue-45-production-validation.md")
    args = parser.parse_args()
    validation = MonitoringProductionValidation(
        deploy_path=Path(args.deploy_path),
        output_path=Path(args.output),
        markdown_path=Path(args.markdown_output),
    )
    try:
        validation.run(mode=args.mode, confirmation=args.confirm, environment_stage=args.environment_stage)
    except BaseException as exc:
        print(f"validation failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "passed", "output": args.output, "markdown": args.markdown_output}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
