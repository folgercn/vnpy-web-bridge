from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
import time
from typing import Any, Iterable

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
    spooled_total: int = 0
    last_error: str | None = None


class JsonlTickSpool:
    def __init__(self, directory: str | Path, max_bytes: int, market_store: QuestDbMarketDataService) -> None:
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.market_store = market_store
        self.path = self.directory / "ticks.jsonl"
        self._lock = Lock()

    def append_rows(self, rows: Iterable[dict[str, Any]]) -> int:
        serialized = [json.dumps(self.market_store.serialize_tick_row(row), ensure_ascii=False, default=str) for row in rows]
        if not serialized:
            return 0

        payload = "\n".join(serialized) + "\n"
        payload_bytes = len(payload.encode("utf-8"))
        with self._lock:
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + payload_bytes > self.max_bytes:
                raise SpoolFullError(f"tick spool exceeds max bytes: {current_size + payload_bytes} > {self.max_bytes}")
            self.directory.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(payload)
        return len(serialized)

    def load_rows(self) -> list[dict[str, Any]]:
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

    def clear(self) -> None:
        with self._lock:
            if self.path.exists():
                self.path.unlink()

    def size_bytes(self) -> int:
        with self._lock:
            return self.path.stat().st_size if self.path.exists() else 0

    def row_count(self) -> int:
        with self._lock:
            if not self.path.exists():
                return 0
            with self.path.open("r", encoding="utf-8") as file:
                return sum(1 for line in file if line.strip())


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
        self.spool = JsonlTickSpool(self.settings.questdb_tick_spool_dir, self.settings.questdb_tick_spool_max_bytes, self.market_store)
        self.stats = TickPersistenceStats()
        self._stats_lock = Lock()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._running = False
        self._backoff_seconds = 1.0

    @property
    def enabled(self) -> bool:
        return bool(self.settings.questdb_tick_persist_enabled and self.market_store.enabled)

    def start(self) -> None:
        if not self.enabled or self._running:
            return
        self._stop_event.clear()
        self._running = True
        self._thread = Thread(target=self._run, name="tick-persistence-writer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout or max(5.0, self.settings.questdb_tick_retry_max_seconds + 1.0))
        self._running = False
        self._thread = None

    def enqueue_tick(self, tick: dict[str, Any]) -> bool:
        self._inc("received_total")
        if not self.enabled:
            return False

        row = self.market_store.normalize_tick(tick)
        if row is None:
            self._inc("invalid_total")
            return False
        self._inc("valid_total")

        try:
            self.queue.put_nowait(row)
            return True
        except Full:
            overflow_rows = self._drain_queue_nowait()
            overflow_rows.append(row)
            return self._spool_or_drop(overflow_rows)

    def drain_once(self) -> None:
        self._flush_spool()
        batch = self._collect_batch(block=False)
        if batch:
            self._flush_batch(batch)

    def snapshot(self) -> dict[str, Any]:
        with self._stats_lock:
            data = self.stats.__dict__.copy()
        data.update(
            {
                "enabled": self.enabled,
                "running": self._running,
                "queue_depth": self.queue.qsize(),
                "queue_capacity": self.queue.maxsize,
                "spool_rows": self.spool.row_count(),
                "spool_bytes": self.spool.size_bytes(),
            }
        )
        return data

    def _run(self) -> None:
        while not self._stop_event.is_set() or not self.queue.empty():
            self._flush_spool()
            batch = self._collect_batch(block=not self._stop_event.is_set())
            if batch:
                self._flush_batch(batch)

        self._flush_spool()

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
        try:
            self.market_store.save_tick_rows_or_raise(rows)
            self._inc("persisted_total", len(rows))
            self._backoff_seconds = 1.0
        except Exception as exc:
            self._record_error(exc, row_count=len(rows))
            self._spool_or_drop(rows)
            self._sleep_backoff()

    def _flush_spool(self) -> None:
        rows = self.spool.load_rows()
        if not rows:
            return
        try:
            self.market_store.save_tick_rows_or_raise(rows)
            self.spool.clear()
            self._inc("persisted_total", len(rows))
            self._backoff_seconds = 1.0
        except Exception as exc:
            self._record_error(exc, row_count=len(rows))
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
        logger.warning("tick persistence write failed for %s rows: %s", row_count, exc)

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


tick_persistence_service = TickPersistenceService()
