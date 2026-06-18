from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from queue import Empty, Full, Queue
import shutil
from threading import Event, Lock, Thread
import time
from typing import Any, Iterable
from uuid import uuid4

from app.core.config import Settings, get_settings
from app.services.market_data_service import QuestDbMarketDataService, market_data_service

logger = logging.getLogger(__name__)


class SpoolFullError(RuntimeError):
    pass


@dataclass
class TickPersistenceStats:
    received_total: int = 0
    valid_total: int = 0
    invalid_total: int = 0
    persisted_total: int = 0
    retry_total: int = 0
    failed_total: int = 0
    dropped_total: int = 0
    corrupt_total: int = 0
    quarantined_rows: int = 0
    quarantined_bytes: int = 0
    spooled_total: int = 0
    last_received_at: datetime | None = None
    last_persisted_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_success_at: datetime | None = None
    oldest_pending_received_at: datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None


@dataclass
class ReplaySegment:
    path: Path
    rows: list[dict[str, Any]]
    row_count: int
    corrupt_rows: int = 0
    quarantined_rows: int = 0
    quarantined_bytes: int = 0
    error: str | None = None


@dataclass
class SpoolCorruptionReport:
    path: Path
    corrupt_rows: int
    quarantined_rows: int
    quarantined_bytes: int
    error: str


class JsonlTickSpool:
    def __init__(
        self,
        directory: str | Path,
        max_bytes: int,
        segment_bytes: int,
        market_store: QuestDbMarketDataService,
        *,
        fsync: bool = False,
    ) -> None:
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.segment_bytes = segment_bytes
        self.market_store = market_store
        self.fsync = fsync
        self.path = self.directory / "ticks.active.jsonl"
        self.meta_path = self.directory / "ticks.active.meta.json"
        self._lock = Lock()

    def append_rows(self, rows: Iterable[dict[str, Any]]) -> int:
        serialized = [json.dumps(self.market_store.serialize_tick_row(row), ensure_ascii=False, default=str) for row in rows]
        if not serialized:
            return 0

        payload = "\n".join(serialized) + "\n"
        payload_bytes = len(payload.encode("utf-8"))
        with self._lock:
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if self.size_bytes_locked() + payload_bytes > self.max_bytes:
                raise SpoolFullError(f"tick spool exceeds max bytes: {self.size_bytes_locked() + payload_bytes} > {self.max_bytes}")
            self.directory.mkdir(parents=True, exist_ok=True)
            if current_size and current_size + payload_bytes > self.segment_bytes:
                self._rotate_active_locked()
            with self.path.open("a", encoding="utf-8") as file:
                file.write(payload)
                file.flush()
                if self.fsync:
                    os.fsync(file.fileno())
            self._update_active_meta_locked(len(serialized), serialized)
        return len(serialized)

    def claim_replay_segment(self) -> ReplaySegment | SpoolCorruptionReport | None:
        with self._lock:
            self._rotate_active_locked()
            segment_path = self._oldest_replay_file_locked()
            if segment_path is None:
                return None
            rows: list[dict[str, Any]] = []
            row_count = 0
            with segment_path.open("r", encoding="utf-8") as file:
                lines = list(file)
            for index, line in enumerate(lines):
                text = line.strip()
                if not text:
                    continue
                try:
                    rows.append(self.market_store.deserialize_tick_row(json.loads(text)))
                    row_count += 1
                except (json.JSONDecodeError, ValueError) as exc:
                    if index == len(lines) - 1:
                        message = f"truncated tick spool record in {segment_path}: {exc}"
                        logger.warning("ignored %s", message)
                        return ReplaySegment(segment_path, rows, row_count, corrupt_rows=1, error=message)
                        continue
                    bad_path = segment_path.with_suffix(segment_path.suffix + ".bad")
                    segment_path.rename(bad_path)
                    if self.fsync:
                        self._fsync_directory_locked()
                    quarantined_rows = max(self._row_count_from_replay_path(bad_path), 1)
                    quarantined_bytes = bad_path.stat().st_size if bad_path.exists() else 0
                    message = f"quarantined corrupt tick spool segment {bad_path}: {exc}"
                    logger.error(message)
                    return SpoolCorruptionReport(
                        path=bad_path,
                        corrupt_rows=1,
                        quarantined_rows=quarantined_rows,
                        quarantined_bytes=quarantined_bytes,
                        error=message,
                    )
            return ReplaySegment(segment_path, rows, row_count)

    def ack_replay_segment(self, segment: ReplaySegment) -> None:
        with self._lock:
            if segment.path.exists():
                segment.path.unlink()
                if self.fsync:
                    self._fsync_directory_locked()

    def size_bytes(self) -> int:
        with self._lock:
            return self.size_bytes_locked()

    def size_bytes_locked(self) -> int:
        total = self.path.stat().st_size if self.path.exists() else 0
        total += sum(path.stat().st_size for path in self._replay_files_locked())
        total += sum(path.stat().st_size for path in self._bad_files_locked())
        return total

    def row_count(self) -> int:
        with self._lock:
            rows = self._read_active_meta_locked().get("rows", 0)
            rows += sum(self._row_count_from_replay_path(path) for path in self._replay_files_locked())
            rows += self.quarantined_rows_locked()
            return rows

    def quarantined_rows(self) -> int:
        with self._lock:
            return self.quarantined_rows_locked()

    def quarantined_rows_locked(self) -> int:
        return sum(self._row_count_from_replay_path(path) for path in self._bad_files_locked())

    def quarantined_bytes(self) -> int:
        with self._lock:
            return sum(path.stat().st_size for path in self._bad_files_locked())

    def oldest_received_at(self) -> datetime | None:
        with self._lock:
            candidates: list[datetime] = []
            active_oldest = self._read_active_meta_locked().get("oldest_received_at")
            if active_oldest:
                candidates.append(_parse_datetime(active_oldest))
            return min(candidates) if candidates else None

    def disk_usage(self) -> Any:
        self.directory.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(self.directory)

    def _rotate_active_locked(self) -> Path | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        meta = self._read_active_meta_locked()
        rows = int(meta.get("rows") or 0)
        replay_path = self.directory / f"ticks.replaying.{time.time_ns()}.{rows}.jsonl"
        self.path.rename(replay_path)
        if self.meta_path.exists():
            self.meta_path.unlink()
        if self.fsync:
            self._fsync_directory_locked()
        return replay_path

    def _oldest_replay_file_locked(self) -> Path | None:
        files = self._replay_files_locked()
        return files[0] if files else None

    def _replay_files_locked(self) -> list[Path]:
        return sorted(self.directory.glob("ticks.replaying.*.jsonl"))

    def _bad_files_locked(self) -> list[Path]:
        return sorted(self.directory.glob("ticks.replaying.*.jsonl.bad"))

    def _row_count_from_replay_path(self, path: Path) -> int:
        parts = path.name.split(".")
        try:
            return int(parts[3])
        except (IndexError, ValueError):
            return 0

    def _update_active_meta_locked(self, row_count: int, serialized_rows: list[str]) -> None:
        meta = self._read_active_meta_locked()
        meta["rows"] = int(meta.get("rows") or 0) + row_count
        if not meta.get("oldest_received_at"):
            for item in serialized_rows:
                try:
                    value = json.loads(item).get("received_at")
                except json.JSONDecodeError:
                    value = None
                if value:
                    meta["oldest_received_at"] = value
                    break
        tmp_path = self.meta_path.with_suffix(self.meta_path.suffix + f".{time.time_ns()}.tmp")
        with tmp_path.open("w", encoding="utf-8") as file:
            file.write(json.dumps(meta, ensure_ascii=False, sort_keys=True))
            file.flush()
            if self.fsync:
                os.fsync(file.fileno())
        tmp_path.replace(self.meta_path)
        if self.fsync:
            self._fsync_directory_locked()

    def _read_active_meta_locked(self) -> dict[str, Any]:
        if not self.meta_path.exists():
            return {"rows": 0, "oldest_received_at": None}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"rows": 0, "oldest_received_at": None}

    def _fsync_directory_locked(self) -> None:
        try:
            fd = os.open(self.directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def load_rows(self) -> list[dict[str, Any]]:
        segment = self.claim_replay_segment()
        return segment.rows if isinstance(segment, ReplaySegment) else []

    def clear(self) -> None:
        segment = self.claim_replay_segment()
        if isinstance(segment, ReplaySegment):
            self.ack_replay_segment(segment)

    def iter_active_rows_for_test(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []
            rows: list[dict[str, Any]] = []
            with self.path.open("r", encoding="utf-8") as file:
                for line in file:
                    text = line.strip()
                    if not text:
                        continue
                    rows.append(self.market_store.deserialize_tick_row(json.loads(text)))
            return rows


class TickPersistenceService:
    def __init__(
        self,
        settings: Settings | None = None,
        market_store: QuestDbMarketDataService | None = None,
        *,
        sleep_func: Any = time.sleep,
    ) -> None:
        self.settings = settings or get_settings()
        self.market_store = market_store or market_data_service
        self.sleep_func = sleep_func
        self.queue: Queue[dict[str, Any]] = Queue(maxsize=self.settings.questdb_tick_queue_size)
        self.spool = JsonlTickSpool(
            self.settings.questdb_tick_spool_dir,
            self.settings.questdb_tick_spool_max_bytes,
            self.settings.questdb_tick_spool_segment_bytes,
            self.market_store,
            fsync=self.settings.questdb_tick_spool_fsync,
        )
        self.stats = TickPersistenceStats()
        self._stats_lock = Lock()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._running = False
        self._ingest_seq = 0
        self._ingest_seq_lock = Lock()
        self._inflight_lock = Lock()
        self._inflight_batch: list[dict[str, Any]] = []
        self._inflight_spooled = False
        self._backoff_seconds = 1.0
        self._last_error_log_at = float("-inf")

    @property
    def enabled(self) -> bool:
        return bool(self.settings.questdb_tick_persist_enabled and self.market_store.enabled)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if not self.enabled or self.running:
            return
        self._stop_event.clear()
        self._running = True
        self._thread = Thread(target=self._run, name="tick-persistence-writer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float | None = None) -> bool:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout or max(5.0, self.settings.questdb_tick_retry_max_seconds + 1.0))
            if self._thread.is_alive():
                spooled_inflight = self._spool_inflight_once()
                if self.queue.qsize():
                    self._spool_or_drop(self._drain_queue_nowait())
                message = "tick persistence writer did not stop before timeout"
                if spooled_inflight:
                    message += f"; spooled {spooled_inflight} inflight rows for recovery"
                self._set_error(message)
                logger.warning(message)
                return False
        if self.queue.qsize():
            self._spool_or_drop(self._drain_queue_nowait())
        self._running = False
        self._thread = None
        self._clear_inflight_batch()
        return True

    def enqueue_tick(self, tick: dict[str, Any]) -> bool:
        self._inc("received_total")
        self._set_last_received()
        if not self.enabled:
            return False

        received_at = datetime.now(timezone.utc)
        tick_payload = dict(tick)
        tick_payload["received_at"] = received_at.isoformat()
        tick_payload["ingest_id"] = tick_payload.get("ingest_id") or f"{received_at.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid4().hex}"
        tick_payload["ingest_seq"] = tick_payload.get("ingest_seq") or self._next_ingest_seq()
        row = self.market_store.normalize_tick(tick_payload)
        if row is None:
            self._inc("invalid_total")
            return False
        self._inc("valid_total")
        self._set_oldest_pending(row.get("received_at"))

        try:
            self.queue.put_nowait(row)
            return True
        except Full:
            return self._spool_or_drop([row])

    def drain_once(self) -> None:
        self._flush_spool()
        batch = self._collect_batch(block=False)
        if batch:
            self._flush_batch(batch)

    def snapshot(self) -> dict[str, Any]:
        with self._stats_lock:
            data = self.stats.__dict__.copy()
        last_received_at = data.pop("last_received_at")
        last_persisted_at = data.pop("last_persisted_at")
        last_failure_at = data.pop("last_failure_at")
        last_success_at = data.pop("last_success_at")
        oldest_pending_received_at = data.pop("oldest_pending_received_at")
        queue_depth = self.queue.qsize()
        inflight_batch_size = self._inflight_size()
        spool_rows = self.spool.row_count()
        spool_bytes = self.spool.size_bytes()
        quarantined_rows = self.spool.quarantined_rows()
        quarantined_bytes = self.spool.quarantined_bytes()
        disk = self.spool.disk_usage()
        oldest_pending_received_at = oldest_pending_received_at or self.spool.oldest_received_at()
        data["quarantined_rows"] = max(int(data.get("quarantined_rows") or 0), quarantined_rows)
        data["quarantined_bytes"] = max(int(data.get("quarantined_bytes") or 0), quarantined_bytes)
        data.update(
            {
                "enabled": self.enabled,
                "running": self.running,
                "worker_alive": self.running,
                "connected": bool(getattr(self.market_store, "connected", False)),
                "queue_depth": queue_depth,
                "queue_capacity": self.queue.maxsize,
                "inflight_batch_size": inflight_batch_size,
                "spool_rows": spool_rows,
                "spool_bytes": spool_bytes,
                "spool_max_bytes": self.settings.questdb_tick_spool_max_bytes,
                "spool_disk_total_bytes": disk.total,
                "spool_disk_used_bytes": disk.used,
                "spool_disk_free_bytes": disk.free,
                "spool_disk_used_percent": round((disk.used / disk.total) * 100, 2) if disk.total else None,
                "last_received_at": _format_datetime(last_received_at),
                "last_persisted_at": _format_datetime(last_persisted_at),
                "last_failure_at": _format_datetime(last_failure_at),
                "last_success_at": _format_datetime(last_success_at),
                "oldest_pending_received_at": _format_datetime(oldest_pending_received_at),
                "persistence_lag_seconds": _persistence_lag_seconds(
                    oldest_pending_received_at,
                ),
            }
        )
        return data

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set() or not self.queue.empty():
                self._flush_spool()
                batch = self._collect_batch(block=not self._stop_event.is_set())
                if batch:
                    self._flush_batch(batch)
            self._flush_spool()
        except Exception as exc:
            self._set_error(str(exc))
            logger.exception("tick persistence writer exited unexpectedly")
        finally:
            self._running = False

    def _collect_batch(self, *, block: bool) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        timeout = self.settings.questdb_tick_flush_interval_ms / 1000
        try:
            first = self.queue.get(timeout=timeout if block else 0)
            batch.append(first)
        except Empty:
            return batch

        while len(batch) < self.settings.questdb_tick_batch_size:
            try:
                batch.append(self.queue.get_nowait())
            except Empty:
                break
        return batch

    def _drain_queue_nowait(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        while True:
            try:
                rows.append(self.queue.get_nowait())
            except Empty:
                return rows

    def _flush_batch(self, rows: list[dict[str, Any]]) -> None:
        self._set_inflight_batch(rows)
        try:
            self.market_store.save_tick_rows_or_raise(rows)
            self._inc("persisted_total", len(rows))
            self._record_success()
            self._backoff_seconds = 1.0
        except Exception as exc:
            self._record_error(exc, row_count=len(rows))
            self._spool_or_drop(rows)
            self._sleep_backoff()
        finally:
            self._clear_inflight_batch()

    def _flush_spool(self) -> None:
        segment = self.spool.claim_replay_segment()
        if not segment:
            return
        if isinstance(segment, SpoolCorruptionReport):
            self._record_spool_corruption(
                segment.error,
                corrupt_rows=segment.corrupt_rows,
                dropped_rows=segment.quarantined_rows,
                quarantined_rows=segment.quarantined_rows,
                quarantined_bytes=segment.quarantined_bytes,
            )
            return
        try:
            self.market_store.save_tick_rows_or_raise(segment.rows)
            self.spool.ack_replay_segment(segment)
            self._inc("persisted_total", segment.row_count)
            self._record_success()
            if segment.corrupt_rows:
                self._record_spool_corruption(
                    segment.error or f"ignored {segment.corrupt_rows} corrupt tick spool rows",
                    corrupt_rows=segment.corrupt_rows,
                    dropped_rows=segment.corrupt_rows,
                )
            self._backoff_seconds = 1.0
        except Exception as exc:
            self._record_error(exc, row_count=segment.row_count)
            self._sleep_backoff()

    def _spool_or_drop(self, rows: list[dict[str, Any]]) -> bool:
        try:
            count = self.spool.append_rows(rows)
            self._inc("spooled_total", count)
            return True
        except Exception as exc:
            self._inc("dropped_total", len(rows))
            self._set_error(str(exc))
            logger.error("tick persistence dropped %s rows: %s", len(rows), exc)
            return False

    def _record_error(self, exc: Exception, *, row_count: int) -> None:
        self._inc("retry_total")
        self._inc("failed_total", row_count)
        self._set_error(str(exc))
        with self._stats_lock:
            self.stats.last_failure_at = datetime.now(timezone.utc)
            self.stats.consecutive_failures += 1
        now = time.monotonic()
        if now - self._last_error_log_at >= self.settings.questdb_tick_error_log_interval_seconds:
            self._last_error_log_at = now
            logger.warning("tick persistence write failed for %s rows: %s", row_count, exc)

    def _record_spool_corruption(
        self,
        message: str,
        *,
        corrupt_rows: int,
        dropped_rows: int = 0,
        quarantined_rows: int = 0,
        quarantined_bytes: int = 0,
    ) -> None:
        with self._stats_lock:
            self.stats.corrupt_total += corrupt_rows
            self.stats.dropped_total += dropped_rows
            self.stats.invalid_total += corrupt_rows
            self.stats.quarantined_rows += quarantined_rows
            self.stats.quarantined_bytes += quarantined_bytes
            self.stats.last_failure_at = datetime.now(timezone.utc)
            self.stats.last_error = message
        logger.error("tick spool corruption recorded: %s", message)

    def _set_inflight_batch(self, rows: list[dict[str, Any]]) -> None:
        with self._inflight_lock:
            self._inflight_batch = list(rows)
            self._inflight_spooled = False

    def _next_ingest_seq(self) -> int:
        with self._ingest_seq_lock:
            self._ingest_seq += 1
            return self._ingest_seq

    def _clear_inflight_batch(self) -> None:
        with self._inflight_lock:
            self._inflight_batch = []
            self._inflight_spooled = False

    def _inflight_size(self) -> int:
        with self._inflight_lock:
            return len(self._inflight_batch)

    def _spool_inflight_once(self) -> int:
        with self._inflight_lock:
            if self._inflight_spooled or not self._inflight_batch:
                return 0
            rows = list(self._inflight_batch)
            self._inflight_spooled = True
        return len(rows) if self._spool_or_drop(rows) else 0

    def _sleep_backoff(self) -> None:
        delay = min(self._backoff_seconds, float(self.settings.questdb_tick_retry_max_seconds))
        self.sleep_func(delay)
        self._backoff_seconds = min(delay * 2, float(self.settings.questdb_tick_retry_max_seconds))

    def _inc(self, field: str, amount: int = 1) -> None:
        with self._stats_lock:
            setattr(self.stats, field, getattr(self.stats, field) + amount)

    def _set_error(self, message: str | None) -> None:
        with self._stats_lock:
            self.stats.last_error = message

    def _set_last_received(self) -> None:
        with self._stats_lock:
            self.stats.last_received_at = datetime.now(timezone.utc)

    def _set_last_persisted(self) -> None:
        with self._stats_lock:
            self.stats.last_persisted_at = datetime.now(timezone.utc)

    def _set_oldest_pending(self, value: Any) -> None:
        timestamp = value if isinstance(value, datetime) else datetime.now(timezone.utc)
        with self._stats_lock:
            if self.stats.oldest_pending_received_at is None:
                self.stats.oldest_pending_received_at = timestamp

    def _record_success(self) -> None:
        now = datetime.now(timezone.utc)
        with self._stats_lock:
            self.stats.last_persisted_at = now
            self.stats.last_success_at = now
            self.stats.last_error = None
            self.stats.consecutive_failures = 0
            if self.queue.empty() and self.spool.row_count() == 0:
                self.stats.oldest_pending_received_at = None


tick_persistence_service = TickPersistenceService()


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _persistence_lag_seconds(oldest_pending_received_at: datetime | None) -> float:
    if not oldest_pending_received_at:
        return 0.0
    return max(0.0, (datetime.now(timezone.utc) - oldest_pending_received_at).total_seconds())
