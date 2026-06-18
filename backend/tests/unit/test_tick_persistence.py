from __future__ import annotations

from datetime import datetime, timezone
import logging
from threading import Event
from typing import Any

from app.core.config import Settings
from app.services.tick_persistence import SpoolCorruptionReport, TickPersistenceService


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
            "received_at": datetime.fromisoformat(tick["received_at"]) if tick.get("received_at") else datetime(2026, 6, 18, 2, 0, 1, tzinfo=timezone.utc),
            "ingest_id": tick.get("ingest_id", "row-1"),
            "ingest_seq": tick.get("ingest_seq", 0),
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


class BlockingMarketStore(FakeMarketStore):
    def __init__(self) -> None:
        super().__init__()
        self.started = Event()
        self.release = Event()

    def save_tick_rows_or_raise(self, rows) -> None:
        self.started.set()
        self.release.wait(timeout=5)
        super().save_tick_rows_or_raise(rows)


def make_service(tmp_path, *, queue_size: int = 10, batch_size: int = 10, spool_fsync: bool = False) -> tuple[TickPersistenceService, FakeMarketStore]:
    store = FakeMarketStore()
    settings = Settings(
        questdb_pg_dsn="postgresql://admin:quest@127.0.0.1:8812/qdb",
        questdb_tick_queue_size=queue_size,
        questdb_tick_batch_size=batch_size,
        questdb_tick_flush_interval_ms=10,
        questdb_tick_retry_max_seconds=1,
        questdb_tick_spool_dir=str(tmp_path),
        questdb_tick_spool_max_bytes=1024 * 1024,
        questdb_tick_spool_fsync=spool_fsync,
    )
    service = TickPersistenceService(settings, store, sleep_func=lambda _: None)  # type: ignore[arg-type]
    return service, store


def make_service_with_store(tmp_path, store: FakeMarketStore, *, queue_size: int = 10, batch_size: int = 10) -> TickPersistenceService:
    settings = Settings(
        questdb_pg_dsn="postgresql://admin:quest@127.0.0.1:8812/qdb",
        questdb_tick_queue_size=queue_size,
        questdb_tick_batch_size=batch_size,
        questdb_tick_flush_interval_ms=10,
        questdb_tick_retry_max_seconds=1,
        questdb_tick_spool_dir=str(tmp_path),
        questdb_tick_spool_max_bytes=1024 * 1024,
    )
    return TickPersistenceService(settings, store, sleep_func=lambda _: None)  # type: ignore[arg-type]


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


def test_enqueue_tick_assigns_monotonic_ingest_seq(tmp_path) -> None:
    service, store = make_service(tmp_path, batch_size=2)
    service.enqueue_tick({"ingest_id": "row-1"})
    service.enqueue_tick({"ingest_id": "row-2"})

    service.drain_once()

    assert [(row["ingest_id"], row["ingest_seq"]) for row in store.saved] == [("row-1", 1), ("row-2", 2)]


def test_queue_full_spools_without_silent_drop(tmp_path) -> None:
    service, store = make_service(tmp_path, queue_size=1)

    assert service.enqueue_tick({"ingest_id": "queued"}) is True
    assert service.enqueue_tick({"ingest_id": "spooled"}) is True

    assert store.saved == []
    assert service.queue.qsize() == 1
    assert service.snapshot()["spooled_total"] == 1
    assert service.snapshot()["dropped_total"] == 0
    assert service.spool.row_count() == 1
    assert [row["ingest_id"] for row in service.spool.load_rows()] == ["spooled"]


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


def test_stop_timeout_spools_inflight_batch_once(tmp_path) -> None:
    store = BlockingMarketStore()
    service = make_service_with_store(tmp_path, store)
    service.start()
    service.enqueue_tick({"ingest_id": "inflight"})
    assert store.started.wait(timeout=2)

    stopped = service.stop(timeout=0.05)
    second_stopped = service.stop(timeout=0.05)
    snapshot = service.snapshot()

    assert stopped is False
    assert second_stopped is False
    assert snapshot["running"] is True
    assert snapshot["inflight_batch_size"] == 1
    assert snapshot["spool_rows"] == 1
    assert snapshot["spooled_total"] == 1
    assert "did not stop before timeout" in snapshot["last_error"]

    store.release.set()
    assert service.stop(timeout=2) is True


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
    assert after_drain["last_error"] is None
    assert after_drain["consecutive_failures"] == 0


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


def test_spool_replay_ack_does_not_delete_new_active_rows(tmp_path) -> None:
    service, _ = make_service(tmp_path)
    first = service.market_store.normalize_tick({"ingest_id": "old", "received_at": "2026-06-18T02:00:01+00:00"})
    second = service.market_store.normalize_tick({"ingest_id": "new", "received_at": "2026-06-18T02:00:02+00:00"})
    assert first and second

    service.spool.append_rows([first])
    segment = service.spool.claim_replay_segment()
    assert segment
    assert [row["ingest_id"] for row in segment.rows] == ["old"]

    service.spool.append_rows([second])
    service.spool.ack_replay_segment(segment)

    assert service.spool.row_count() == 1
    assert [row["ingest_id"] for row in service.spool.iter_active_rows_for_test()] == ["new"]


def test_replay_segment_preserves_oldest_received_at_after_restart(tmp_path) -> None:
    service, _ = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "old", "received_at": "2026-06-18T01:00:00+00:00"})
    assert row
    service.spool.append_rows([row])
    segment = service.spool.claim_replay_segment()
    assert segment
    replay_meta_path = service.spool._replay_meta_path(segment.path)
    assert replay_meta_path.exists()

    restarted, _ = make_service(tmp_path)
    snapshot = restarted.snapshot()

    assert snapshot["spool_rows"] == 1
    assert snapshot["oldest_pending_received_at"] == "2026-06-18T01:00:00+00:00"
    assert snapshot["persistence_lag_seconds"] > 0


def test_replay_ack_removes_sidecar_meta(tmp_path) -> None:
    service, _ = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "old", "received_at": "2026-06-18T01:00:00+00:00"})
    assert row
    service.spool.append_rows([row])
    segment = service.spool.claim_replay_segment()
    assert segment
    replay_meta_path = service.spool._replay_meta_path(segment.path)
    assert replay_meta_path.exists()

    service.spool.ack_replay_segment(segment)

    assert not segment.path.exists()
    assert not replay_meta_path.exists()


def test_spool_fsync_policy_is_configurable(tmp_path, monkeypatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr("app.services.tick_persistence.os.fsync", lambda fd: calls.append(fd))
    service, _ = make_service(tmp_path, spool_fsync=True)
    row = service.market_store.normalize_tick({"ingest_id": "durable", "received_at": "2026-06-18T02:00:01+00:00"})
    assert row

    service.spool.append_rows([row])
    segment = service.spool.claim_replay_segment()
    assert segment
    service.spool.ack_replay_segment(segment)

    assert service.spool.fsync is True
    assert calls
    assert not list(tmp_path.glob("*.tmp"))


def test_worker_starts_without_opening_database(tmp_path) -> None:
    service, store = make_service(tmp_path)
    store.fail = True

    service.start()
    try:
        assert service.running is True
    finally:
        service.stop(timeout=2)


def test_spool_ignores_truncated_last_record(tmp_path) -> None:
    service, _ = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "ok", "received_at": "2026-06-18T02:00:01+00:00"})
    assert row
    service.spool.append_rows([row])
    with service.spool.path.open("a", encoding="utf-8") as file:
        file.write('{"partial":')

    segment = service.spool.claim_replay_segment()

    assert segment
    assert [item["ingest_id"] for item in segment.rows] == ["ok"]
    assert segment.corrupt_rows == 1
    assert segment.error


def test_truncated_spool_record_is_counted_as_dropped(tmp_path) -> None:
    service, store = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "ok", "received_at": "2026-06-18T02:00:01+00:00"})
    assert row
    service.spool.append_rows([row])
    with service.spool.path.open("a", encoding="utf-8") as file:
        file.write('{"partial":')

    service.drain_once()
    snapshot = service.snapshot()

    assert [item["ingest_id"] for item in store.saved] == ["ok"]
    assert snapshot["persisted_total"] == 1
    assert snapshot["corrupt_total"] == 1
    assert snapshot["invalid_total"] == 1
    assert snapshot["dropped_total"] == 1
    assert snapshot["last_error"]


def test_spool_quarantines_corrupt_middle_record(tmp_path) -> None:
    service, _ = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "ok", "received_at": "2026-06-18T02:00:01+00:00"})
    assert row
    service.spool.append_rows([row])
    with service.spool.path.open("a", encoding="utf-8") as file:
        file.write('{"broken":\n')
        file.write('{"valid": true}\n')

    segment = service.spool.claim_replay_segment()

    assert isinstance(segment, SpoolCorruptionReport)
    assert segment.corrupt_rows == 1
    assert segment.quarantined_rows == 1
    assert segment.quarantined_bytes > 0
    assert list(tmp_path.glob("*.bad"))


def test_corrupt_middle_record_is_quarantined_and_reported(tmp_path) -> None:
    service, store = make_service(tmp_path)
    row = service.market_store.normalize_tick({"ingest_id": "ok", "received_at": "2026-06-18T02:00:01+00:00"})
    assert row
    service.spool.append_rows([row])
    with service.spool.path.open("a", encoding="utf-8") as file:
        file.write('{"broken":\n')
        file.write('{"valid": true}\n')

    service.drain_once()
    snapshot = service.snapshot()

    assert store.saved == []
    assert list(tmp_path.glob("*.bad"))
    assert snapshot["corrupt_total"] == 1
    assert snapshot["invalid_total"] == 1
    assert snapshot["dropped_total"] == 1
    assert snapshot["quarantined_rows"] == 1
    assert snapshot["quarantined_bytes"] > 0
    assert snapshot["spool_rows"] == 1
    assert snapshot["spool_bytes"] >= snapshot["quarantined_bytes"]
    assert "quarantined corrupt tick spool segment" in snapshot["last_error"]
