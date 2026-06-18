from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

from app.core.config import Settings
from app.services.tick_persistence import TickPersistenceService


class FakeMarketStore:
    enabled = True
    connected = True

    def __init__(self) -> None:
        self.saved: list[dict[str, Any]] = []
        self.fail = False

    def normalize_tick(self, tick: dict[str, Any]) -> dict[str, Any] | None:
        if tick.get("invalid"):
            return None
        return {
            "ts": datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc),
            "received_at": datetime(2026, 6, 18, 2, 0, 1, tzinfo=timezone.utc),
            "ingest_id": tick.get("ingest_id", "row-1"),
            "schema_version": 2,
            "vt_symbol": tick.get("vt_symbol", "rb2610.SHFE"),
            "raw_json": "{}",
        }

    def save_tick_rows_or_raise(self, rows) -> None:
        if self.fail:
            raise RuntimeError("questdb down")
        self.saved.extend(rows)

    def serialize_tick_row(self, row: dict[str, Any]) -> dict[str, Any]:
        serialized = dict(row)
        serialized["ts"] = serialized["ts"].isoformat()
        serialized["received_at"] = serialized["received_at"].isoformat()
        return serialized

    def deserialize_tick_row(self, row: dict[str, Any]) -> dict[str, Any]:
        restored = dict(row)
        restored["ts"] = datetime.fromisoformat(restored["ts"])
        restored["received_at"] = datetime.fromisoformat(restored["received_at"])
        return restored


def make_service(tmp_path, *, queue_size: int = 10, batch_size: int = 10) -> tuple[TickPersistenceService, FakeMarketStore]:
    store = FakeMarketStore()
    settings = Settings(
        questdb_pg_dsn="postgresql://admin:quest@127.0.0.1:8812/qdb",
        questdb_tick_queue_size=queue_size,
        questdb_tick_batch_size=batch_size,
        questdb_tick_flush_interval_ms=10,
        questdb_tick_retry_max_seconds=1,
        questdb_tick_spool_dir=str(tmp_path),
        questdb_tick_spool_max_bytes=1024 * 1024,
    )
    service = TickPersistenceService(settings, store, sleep_func=lambda _: None)  # type: ignore[arg-type]
    return service, store


def test_enqueue_tick_only_queues_without_db_write(tmp_path) -> None:
    service, store = make_service(tmp_path)

    assert service.enqueue_tick({"vt_symbol": "rb2610.SHFE"}) is True

    assert store.saved == []
    assert service.queue.qsize() == 1
    assert service.snapshot()["valid_total"] == 1


def test_invalid_tick_is_counted_without_queueing(tmp_path) -> None:
    service, store = make_service(tmp_path)

    assert service.enqueue_tick({"invalid": True}) is False

    assert store.saved == []
    assert service.queue.qsize() == 0
    assert service.snapshot()["invalid_total"] == 1


def test_drain_once_flushes_batch(tmp_path) -> None:
    service, store = make_service(tmp_path, batch_size=2)
    service.enqueue_tick({"ingest_id": "row-1"})
    service.enqueue_tick({"ingest_id": "row-2"})

    service.drain_once()

    assert [row["ingest_id"] for row in store.saved] == ["row-1", "row-2"]
    assert service.snapshot()["persisted_total"] == 2


def test_queue_full_spools_without_silent_drop(tmp_path) -> None:
    service, store = make_service(tmp_path, queue_size=1)

    assert service.enqueue_tick({"ingest_id": "queued"}) is True
    assert service.enqueue_tick({"ingest_id": "spooled"}) is True

    assert store.saved == []
    assert service.queue.qsize() == 0
    assert service.snapshot()["spooled_total"] == 2
    assert service.snapshot()["dropped_total"] == 0
    assert service.spool.row_count() == 2
    assert [row["ingest_id"] for row in service.spool.load_rows()] == ["queued", "spooled"]


def test_failed_flush_spools_and_replays_later(tmp_path) -> None:
    service, store = make_service(tmp_path)
    store.fail = True
    service.enqueue_tick({"ingest_id": "row-1"})

    service.drain_once()

    assert store.saved == []
    assert service.spool.row_count() == 1
    assert service.snapshot()["failed_total"] == 1
    assert service.snapshot()["retry_total"] == 1

    store.fail = False
    service.drain_once()

    assert [row["ingest_id"] for row in store.saved] == ["row-1"]
    assert service.spool.row_count() == 0
    assert service.snapshot()["persisted_total"] == 1


def test_stop_drains_queued_ticks(tmp_path) -> None:
    service, store = make_service(tmp_path)
    service.start()
    service.enqueue_tick({"ingest_id": "row-1"})

    service.stop(timeout=2)

    assert [row["ingest_id"] for row in store.saved] == ["row-1"]


def test_snapshot_exposes_required_observability_fields(tmp_path) -> None:
    service, store = make_service(tmp_path)
    service.enqueue_tick({"ingest_id": "row-1"})
    before_drain = service.snapshot()

    assert before_drain["enabled"] is True
    assert before_drain["connected"] is True
    assert before_drain["received_total"] == 1
    assert before_drain["valid_total"] == 1
    assert before_drain["invalid_total"] == 0
    assert before_drain["queue_depth"] == 1
    assert before_drain["queue_capacity"] == 10
    assert before_drain["spool_rows"] == 0
    assert before_drain["spool_bytes"] == 0
    assert before_drain["last_received_at"]
    assert before_drain["persistence_lag_seconds"] is not None
    assert before_drain["spool_disk_free_bytes"] > 0

    service.drain_once()
    after_drain = service.snapshot()

    assert len(store.saved) == 1
    assert after_drain["persisted_total"] == 1
    assert after_drain["last_persisted_at"]
    assert after_drain["persistence_lag_seconds"] == 0.0


def test_write_error_logs_are_rate_limited(tmp_path, caplog) -> None:
    service, store = make_service(tmp_path)
    store.fail = True
    service.enqueue_tick({"ingest_id": "row-1"})
    service.enqueue_tick({"ingest_id": "row-2"})

    with caplog.at_level(logging.WARNING):
        service.drain_once()
        service.drain_once()

    messages = [record.message for record in caplog.records if "tick persistence write failed" in record.message]
    assert len(messages) == 1
