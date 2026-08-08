"""Standalone monitor consuming typed health/readiness/metrics projections."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import stat
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from . import CONTRACT_VERSION
    from .contracts import (
        HealthSnapshot,
        IncidentEvent,
        ReadinessSnapshot,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        project_dependency,
    )
    from .durable import AppendOnlyIncidentLog, AtomicCheckpoint
    from .projections import (
        REQUIRED_PROJECTION_SERVICES,
        ProjectionError,
        validate_projection,
    )
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from phase_b_workers import CONTRACT_VERSION
    from phase_b_workers.contracts import (
        HealthSnapshot,
        IncidentEvent,
        ReadinessSnapshot,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        project_dependency,
    )
    from phase_b_workers.durable import AppendOnlyIncidentLog, AtomicCheckpoint
    from phase_b_workers.projections import (
        REQUIRED_PROJECTION_SERVICES,
        ProjectionError,
        validate_projection,
    )


class ProjectionSource(Protocol):
    def read(self) -> Iterable[Mapping[str, object]]: ...


class AlertNotifier(Protocol):
    def send(self, incident: IncidentEvent) -> bool: ...


class DirectoryProjectionSource:
    def __init__(self, directory: str | Path | None, *, max_age_seconds: float = 60.0) -> None:
        self.directory = Path(directory) if directory else None
        self.max_age_seconds = max_age_seconds

    def _paths(self) -> dict[str, Path]:
        if self.directory is None:
            return {}
        return {
            service: self.directory / service / f"{service}.json"
            for service in REQUIRED_PROJECTION_SERVICES
        }

    def read(self) -> Iterable[Mapping[str, object]]:
        if self.directory is None:
            return []
        try:
            info = self.directory.lstat()
        except OSError:
            return []
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return []
        values: list[Mapping[str, object]] = []
        for service, path in sorted(self._paths().items()):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, Mapping):
                    raise ProjectionError("PROJECTION_SCHEMA_INVALID")
                values.append(validate_projection(value, expected_service_id=service, max_age_seconds=self.max_age_seconds))
            except (OSError, json.JSONDecodeError, ProjectionError, ValueError) as exc:
                values.append({"service_id": service, "status": "unhealthy", "ready": False, "error_code": type(exc).__name__})
        return values

    def readiness(self) -> tuple[bool, str]:
        if self.directory is None or not self.directory.exists():
            return False, "projection_dir_missing"
        if self.directory.is_symlink() or not self.directory.is_dir():
            return False, "projection_dir_invalid"
        for service, path in self._paths().items():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, Mapping):
                    return False, f"projection_invalid:{service}"
                validate_projection(value, expected_service_id=service, max_age_seconds=self.max_age_seconds)
            except (OSError, json.JSONDecodeError, ProjectionError, ValueError):
                return False, f"projection_invalid:{service}"
        return True, ""


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, *, timeout_seconds: float = 5.0) -> None:
        self.token = str(token)
        self.chat_id = str(chat_id)
        self.timeout_seconds = timeout_seconds

    def send(self, incident: IncidentEvent) -> bool:
        if not self.token or not self.chat_id:
            return False
        payload = urlencode({"chat_id": self.chat_id, "text": f"[{incident.severity}] {incident.service_id}: {incident.summary}"}).encode()
        request = Request(f"https://api.telegram.org/bot{self.token}/sendMessage", data=payload, method="POST")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return 200 <= int(response.status) < 300
        except Exception:  # noqa: BLE001
            return False


class NullNotifier:
    def __init__(self, *, reason: str = "disabled") -> None:
        self.reason = reason

    def send(self, incident: IncidentEvent) -> bool:
        del incident
        return False

    def status(self) -> dict[str, object]:
        return {"status": "disabled", "reason": self.reason}


class SqliteIncidentOutbox:
    """Transactional local adapter matching the monitor Postgres contract."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS incidents (incident_id TEXT PRIMARY KEY, episode_key TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, created_at_utc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS delivery_outbox (delivery_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, lease_generation TEXT, delivered_at_utc TEXT);
                CREATE TABLE IF NOT EXISTS worker_fence (singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation TEXT NOT NULL, epoch INTEGER NOT NULL);
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def activate_generation(self, generation: str) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT generation,epoch FROM worker_fence WHERE singleton=1").fetchone()
            if row is None:
                epoch = 1
                db.execute("INSERT INTO worker_fence VALUES (1,?,?)", (generation, epoch))
            elif str(row[0]) == str(generation):
                epoch = int(row[1])
            else:
                epoch = int(row[1]) + 1
                db.execute("UPDATE worker_fence SET generation=?,epoch=? WHERE singleton=1", (generation, epoch))
            return epoch

    def record(self, incident: IncidentEvent) -> bool:
        payload = json.dumps(incident.as_dict(), sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            inserted = db.execute("INSERT OR IGNORE INTO incidents VALUES (?,?,?,?,?)", (incident.incident_id, incident.episode_key, incident.event_hash, payload, isoformat())).rowcount == 1
            if inserted:
                db.execute("INSERT INTO delivery_outbox (incident_id,payload_json) VALUES (?,?)", (incident.incident_id, payload))
            return inserted

    def pending(self, *, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as db:
            rows = db.execute("SELECT delivery_id,incident_id,payload_json,attempts FROM delivery_outbox WHERE state='pending' ORDER BY delivery_id LIMIT ?", (max(1, int(limit)),)).fetchall()
        return [{"delivery_id": row[0], "incident_id": row[1], "payload": json.loads(row[2]), "attempts": row[3]} for row in rows]

    def mark_delivered(self, delivery_id: int, *, generation: str, epoch: int) -> bool:
        with self._connect() as db:
            return db.execute("UPDATE delivery_outbox SET state='delivered',lease_generation=?,delivered_at_utc=? WHERE delivery_id=? AND state='pending' AND EXISTS (SELECT 1 FROM worker_fence WHERE singleton=1 AND generation=? AND epoch=?)", (generation, isoformat(), int(delivery_id), generation, int(epoch))).rowcount == 1


def read_secret_file(path: str) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError("secret must be a regular file")
        value = os.read(descriptor, 8193)
        if len(value) > 8192:
            raise RuntimeError("secret file is too large")
    finally:
        os.close(descriptor)
    return value.decode().strip()


def configured_worker_secret() -> str:
    runtime = os.getenv("APP_ENV", "development").lower().strip()
    path = os.getenv("PHASE_B_WORKER_SHARED_SECRET_FILE", "").strip()
    raw = os.getenv("PHASE_B_WORKER_SHARED_SECRET", "").strip()
    if path:
        return read_secret_file(path)
    if raw and runtime not in {"test", "testing", "development", "local"}:
        raise RuntimeError("raw worker shared secret is forbidden outside local/test")
    return raw


@dataclass(frozen=True)
class MonitorConfig:
    state_dir: Path
    projection_dir: Path | None
    runtime_mode: str = "disabled"
    source_revision: str = "unknown"
    generation: str = "generation-1"
    telegram_enabled: bool = False
    telegram_egress_permitted: bool = False

    @classmethod
    def from_environment(cls, state_dir: str | Path | None = None) -> MonitorConfig:
        root = Path(state_dir or os.getenv("PHASE_B_MONITOR_STATE_DIR", "/var/lib/phase-b/monitor"))
        enabled = os.getenv("PHASE_B_TELEGRAM_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        egress_permitted = os.getenv("PHASE_B_TELEGRAM_EGRESS_PERMITTED", "false").strip().lower() in {"1", "true", "yes", "on"}
        projection_value = os.getenv("PHASE_B_PROJECTION_DIR", "").strip()
        projection = Path(projection_value) if projection_value else None
        return cls(root, projection, os.getenv("PHASE_B_RUNTIME_MODE", "disabled"), os.getenv("SOURCE_REVISION", "unknown"), os.getenv("PHASE_B_MONITOR_GENERATION", "generation-1"), enabled, egress_permitted)


class MonitorStateRepository(Protocol):
    def read(self) -> dict[str, object]: ...
    def write(self, value: Mapping[str, object]) -> None: ...


class JsonMonitorStateRepository:
    def __init__(self, path: str | Path) -> None:
        self.checkpoint = AtomicCheckpoint(path, default={"episodes": {}, "delivery_pending": {}})
    def read(self) -> dict[str, object]: return self.checkpoint.read()
    def write(self, value: Mapping[str, object]) -> None: self.checkpoint.write(value)


class MonitorWorker:
    service_id = "monitor-worker"

    def __init__(self, config: MonitorConfig | str | Path, *, generation: str | None = None, source: ProjectionSource | None = None, notifier: AlertNotifier | None = None, state: MonitorStateRepository | None = None, identity: WorkerIdentity | None = None) -> None:
        if not isinstance(config, MonitorConfig):
            root = Path(config)
            config = MonitorConfig(root, root / "projections", generation=generation or "generation-1")
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True)
        info = config.state_dir.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("monitor state directory is not a real directory")
        os.chmod(config.state_dir, 0o700)
        self.identity = identity or WorkerIdentity.from_environment(self.service_id, runtime_mode=config.runtime_mode)
        self.source = source or DirectoryProjectionSource(config.projection_dir)
        token, chat = os.getenv("PHASE_B_TELEGRAM_TOKEN", ""), os.getenv("PHASE_B_TELEGRAM_CHAT_ID", "")
        self.notifier = notifier or (
            TelegramNotifier(token, chat)
            if config.telegram_enabled and config.telegram_egress_permitted and token and chat
            else NullNotifier(reason="network_disabled_or_not_configured")
        )
        self.state = state or JsonMonitorStateRepository(config.state_dir / "monitor_state.json")
        self.incidents = AppendOnlyIncidentLog(config.state_dir / "incidents.jsonl")
        self.repository = SqliteIncidentOutbox(config.state_dir / "monitor.sqlite3")
        self.generation, self.fence_epoch = config.generation, 0
        self.metrics = WorkerMetrics(self.service_id, isoformat(), worker_generation=config.generation)
        self._last_error: str | None = None
        self._state_recovered = False
        self._lock = threading.RLock()

    def recover(self) -> None:
        self._state_recovered = False
        try:
            self.fence_epoch = self.repository.activate_generation(self.generation)
            self.repository.pending(limit=1)
            self.state.read()
        except Exception as exc:
            self._last_error = type(exc).__name__
            raise
        else:
            self._state_recovered = True
            self._last_error = None

    def _deliver_outbox(self) -> None:
        if not self.fence_epoch:
            self.recover()
        if isinstance(self.notifier, NullNotifier):
            if self.repository.pending(limit=1):
                self.metrics.increment("alerts_disabled")
            return
        for item in self.repository.pending():
            raw = item.get("payload")
            if not isinstance(raw, Mapping):
                continue
            try:
                incident = IncidentEvent(
                    incident_id=str(raw["incident_id"]),
                    episode_key=str(raw["episode_key"]),
                    service_id=str(raw["service_id"]),
                    severity=str(raw["severity"]),
                    state=str(raw["state"]),
                    summary=str(raw["summary"]),
                    occurred_at_utc=str(raw["occurred_at_utc"]),
                    source_revision=str(raw.get("source_revision") or "unknown"),
                    details=raw.get("details") if isinstance(raw.get("details"), Mapping) else {},
                    event_hash=str(raw.get("event_hash") or ""),
                )
                delivered = bool(self.notifier.send(incident))
            except Exception as exc:  # noqa: BLE001
                self._last_error = type(exc).__name__
                continue
            if delivered and self.repository.mark_delivered(int(item["delivery_id"]), generation=self.generation, epoch=self.fence_epoch):
                self.metrics.increment("alerts_delivered")

    def observe(self, service_id: str, projection: Mapping[str, object]) -> IncidentEvent | None:
        if not self.fence_epoch:
            self.recover()
        safe = project_dependency(projection)
        status = str(safe.get("status") or "unknown").lower()
        if status in {"ok", "live", "ready", "healthy", "nominal"} and safe.get("ready") is not False:
            return None
        incident = IncidentEvent.create(service_id=str(service_id), episode_key=f"{service_id}:unavailable", severity="critical" if status in {"failed", "unavailable", "unhealthy"} else "warning", state="open", summary=f"typed projection reports {status}", source_revision=self.identity.source_revision, details={"projection": safe})
        self.metrics.increment("incidents_created" if self.repository.record(incident) else "incidents_deduplicated")
        self.metrics.queue_depth = len(self.repository.pending())
        return incident

    def run_once(self) -> dict[str, object]:
        with self._lock:
            if not self.fence_epoch:
                self.recover()
            projections = list(self.source.read())
            transitions: list[dict[str, object]] = []
            durable = self.state.read()
            episodes = durable.get("episodes") if isinstance(durable.get("episodes"), dict) else {}
            for projection in projections:
                safe = project_dependency(projection)
                service = str(safe.get("service_id") or "unknown-service")
                status = str(safe.get("status") or "unknown").lower()
                healthy = status in {"healthy", "ready", "ok", "nominal"} and safe.get("ready", True) is not False
                key = f"worker:{service}:readiness"
                prior = episodes.get(key) if isinstance(episodes, dict) else None
                state = "resolved" if healthy else "open"
                if not isinstance(prior, Mapping) or prior.get("state") != state:
                    incident = IncidentEvent.create(service_id=service, episode_key=key, severity="critical" if not healthy and safe.get("ready") is False else "warning", state=state, summary="worker healthy" if healthy else f"worker unhealthy ({status})", source_revision=self.config.source_revision, details=safe)
                    inserted = self.repository.record(incident)
                    if inserted:
                        self.incidents.append(incident)
                        transitions.append(incident.as_dict())
                        self.metrics.increment("incidents_created")
                    else:
                        self.metrics.increment("incidents_deduplicated")
                    if isinstance(episodes, dict):
                        episodes[key] = {"state": state, "incident_id": incident.incident_id, "updated_at_utc": incident.occurred_at_utc}
            durable["episodes"] = episodes
            self.state.write(durable)
            self._deliver_outbox()
            self.metrics.increment("check_cycles_total")
            self._last_error = None
            return {"checked_at_utc": isoformat(), "projections": len(projections), "transitions": transitions}

    def run(self, *, stop_event: threading.Event | None = None, interval_seconds: float = 5.0) -> None:
        stop_event = stop_event or threading.Event()
        while not stop_event.is_set():
            try: self.run_once()
            except Exception as exc:  # noqa: BLE001
                self._last_error = type(exc).__name__
            stop_event.wait(max(0.05, float(interval_seconds)))

    def health(self) -> HealthSnapshot:
        projection = DirectoryProjectionSource(self.config.projection_dir).readiness()
        notifier = self.notifier.status() if hasattr(self.notifier, "status") else {"status": "configured"}
        status = "healthy" if not self._last_error else "degraded"
        return HealthSnapshot(self.service_id, status, isoformat(), self.metrics.started_at_utc, {"projection_source": {"status": "healthy" if projection[0] else "unavailable", "reason": projection[1]}, "notifier": notifier, "incident_state": {"status": "healthy"}}, self._last_error)

    def readiness(self) -> ReadinessSnapshot:
        blockers: list[str] = []
        if not self._state_recovered or self._last_error:
            blockers.append("state_recovery_required")
        source_ready, reason = DirectoryProjectionSource(self.config.projection_dir).readiness()
        if not source_ready:
            blockers.append(reason)
        return ReadinessSnapshot(self.service_id, not blockers, isoformat(), CONTRACT_VERSION in self.identity.contract_versions, True, not bool(blockers), self._state_recovered and not bool(self._last_error), tuple(blockers))

    def metrics_snapshot(self) -> dict[str, object]: return self.metrics.as_dict()
    def version(self) -> dict[str, object]: return self.identity.as_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase B monitor worker")
    parser.add_argument("--state-dir")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", action="store_true")
    group.add_argument("--health", action="store_true")
    group.add_argument("--ready", action="store_true")
    group.add_argument("--metrics", action="store_true")
    group.add_argument("--check", action="store_true")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    worker = MonitorWorker(MonitorConfig.from_environment(args.state_dir))
    if args.version: value = worker.version()
    elif args.ready:
        try:
            worker.recover()
        except Exception as exc:  # noqa: BLE001 - readiness reports a fail-closed snapshot
            worker._last_error = type(exc).__name__
        value = worker.readiness().as_dict()
    elif args.metrics: value = worker.metrics_snapshot()
    elif args.check: value = {"snapshot": worker.run_once(), "metrics": worker.metrics_snapshot()}
    elif args.run:
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT): signal.signal(signum, lambda *_: stop.set())
        worker.run(stop_event=stop, interval_seconds=float(os.getenv("PHASE_B_MONITOR_INTERVAL_SECONDS", "5")))
        return 0
    else: value = worker.health().as_dict()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0 if not args.ready or bool(value.get("ready")) else 1


if __name__ == "__main__": raise SystemExit(main())
