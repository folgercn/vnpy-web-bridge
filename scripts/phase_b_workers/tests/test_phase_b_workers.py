from __future__ import annotations

import ast
import json
import os
import pickle
import subprocess
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

from phase_b_artifact_custody import _publish_projection as publish_custody_projection

import phase_b_workers.durable as durable_module
import phase_b_workers.market_data_worker as market_data_module
from phase_b_workers.contracts import GatewayTickEnvelope, VerifiedTick
from phase_b_workers.durable import (
    AppendOnlyJsonl,
    BackpressureError,
    BoundedIngressQueue,
    DuplicateRecordError,
    DurableCorruptionError,
    DurableStateError,
    DurableVerifiedTickStream,
    GenerationMismatch,
)
from phase_b_workers.execution_quality_worker import (
    ExecutionQualityConfig,
    ExecutionQualityWorker,
)
from phase_b_workers.execution_quality_worker import (
    main as execution_quality_main,
)
from phase_b_workers.market_data_worker import (
    MARKET_TICK_COLUMNS,
    MARKET_TICK_SCHEMA_TYPES,
    MarketDataConfig,
    MarketDataWorker,
    QuestDbTickWriter,
    ZmqPublishTickSource,
    ZmqTickWireSourceV1,
    restricted_tick_wire_loads,
    verified_tick_to_market_tick_v3,
)
from phase_b_workers.market_data_worker import main as market_data_main
from phase_b_workers.monitor_worker import MonitorConfig, MonitorWorker, NullNotifier


def envelope(event_id="tick-1", seq=1, **payload):
    return GatewayTickEnvelope.create(
        event_id=event_id,
        source_service="gateway-market-reader",
        source_generation="source-g1",
        source_seq=seq,
        observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        payload={
            "vt_symbol": "rb2610.SHFE",
            "bid_price": 100,
            "ask_price": 102,
            **payload,
        },
    )


class Writer:
    def __init__(self, fail=False):
        self.fail, self.events = fail, []

    def write_verified_tick(self, tick):
        if self.fail:
            raise OSError("writer unavailable")
        self.events.append(tick)


class UnhealthyWriter(Writer):
    def health(self):
        return {"status": "degraded", "configured": True}


class CommitThenAckWriter(Writer):
    def __init__(self):
        super().__init__()
        self.persisted = {}

    def write_verified_tick(self, tick):
        self.events.append(tick)
        self.persisted[tick.ingest_id] = verified_tick_to_market_tick_v3(tick)

    def readback(self, tick):
        return self.persisted.get(tick.ingest_id)


class FakeCursor:
    def __init__(self, rows=(), fail_execute=False, readbacks=()):
        self.rows = list(rows)
        self.readbacks = list(readbacks)
        self.calls = []
        self.fail_execute = fail_execute
        self.last_sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        self.last_sql = sql
        if self.fail_execute:
            raise OSError("poisoned pgwire connection")

    def executemany(self, sql, params_seq):
        for params in params_seq:
            self.execute(sql, params)

    def fetchone(self):
        if "WHERE ts = %s AND ingest_id = %s" in self.last_sql:
            return self.readbacks.pop(0) if self.readbacks else None
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        if "FROM table_columns" in self.last_sql:
            return [
                (name, data_type, name in {"ts", "ingest_id"}, name == "ts")
                for name, data_type in MARKET_TICK_SCHEMA_TYPES.items()
            ]
        return []


class FakeConnection:
    def __init__(self, rows=(), fail_execute=False, fail_commit=False, readbacks=()):
        self.cursor_value = FakeCursor(rows, fail_execute, readbacks)
        self.closed = False
        self.commits = self.rollbacks = 0
        self.fail_commit = fail_commit

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.commits += 1
        if self.fail_commit:
            raise OSError("commit failed")

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class FakeZmqError(Exception):
    pass


class FakeSocket:
    def __init__(self, values=()):
        self.values = list(values)
        self.options = []
        self.endpoint = None
        self.closed = False

    def setsockopt(self, option, value):
        self.options.append((option, value))

    def connect(self, endpoint):
        self.endpoint = endpoint

    def poll(self, _timeout):
        return bool(self.values)

    def recv(self):
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, bytes) else pickle.dumps(value)

    def close(self, linger=0):
        assert linger == 0
        self.closed = True


class FakeContext:
    def __init__(self, sockets):
        self.sockets = list(sockets)
        self.kinds = []

    def socket(self, kind):
        self.kinds.append(kind)
        return self.sockets.pop(0)


class FakeZmq:
    SUB = 1
    SUBSCRIBE = 2
    ZMQError = FakeZmqError

    class Context:
        @staticmethod
        def instance():
            raise AssertionError("test supplies a fake context")


class MaliciousPickle:
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return os.system, (f"touch {self.marker}",)


def rpc_tick(**kwargs):
    from vnpy.trader.constant import Exchange
    from vnpy.trader.object import TickData

    return TickData(
        symbol=kwargs.pop("symbol", "rb2610"),
        exchange=kwargs.pop("exchange", Exchange.SHFE),
        datetime=kwargs.pop("datetime", datetime(2026, 8, 8, tzinfo=timezone.utc)),
        gateway_name=kwargs.pop("gateway_name", "rpc"),
        **kwargs,
    )


class Notifier:
    def __init__(self, delivered=False):
        self.delivered, self.events = delivered, []

    def send(self, incident):
        self.events.append(incident)
        return self.delivered


class Projection:
    def __init__(self, *values):
        self.values = values

    def read(self):
        return list(self.values)


def test_gateway_contract_rejects_privileged_or_legacy_source():
    value = envelope().as_dict()
    value["capability"] = "order.send"
    with pytest.raises(ValueError):
        GatewayTickEnvelope.from_dict(value)
    value = envelope().as_dict()
    value["source_service"] = "vnpy-rpc-service"
    with pytest.raises(ValueError):
        GatewayTickEnvelope.from_dict(value)


def test_market_sequence_fence_dedup_and_replay(tmp_path):
    writer = Writer()
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    worker.accept(envelope())
    first = worker.process_one()
    assert first.ingest_seq == 1 and worker.stream.is_acknowledged(first)
    worker.accept(envelope())
    assert (
        worker.process_one().event_hash == first.event_hash and len(writer.events) == 1
    )
    worker.accept(envelope("tick-2", 1, last_price=101))
    with pytest.raises(DurableStateError):
        worker.process_one()


def test_market_writer_failure_is_replayed(tmp_path):
    writer = Writer(True)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    worker.accept(envelope())
    with pytest.raises(OSError):
        worker.process_one()
    assert len(worker.stream.pending_for_tick_writer()) == 1
    writer.fail = False
    assert worker.replay_pending_writes() == 1
    assert not worker.stream.pending_for_tick_writer()


def test_commit_before_ack_replays_via_readback_without_second_insert(
    tmp_path, monkeypatch
):
    writer = CommitThenAckWriter()
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    worker.accept(envelope())
    original_ack = worker.stream.acknowledge_tick_write
    failed = False

    def fail_after_commit(tick):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("acknowledgement crash after committed insert")
        return original_ack(tick)

    monkeypatch.setattr(worker.stream, "acknowledge_tick_write", fail_after_commit)
    with pytest.raises(OSError, match="acknowledgement crash"):
        worker.process_one()
    assert len(writer.events) == 1 and writer.readback(writer.events[0])
    assert worker.replay_pending_writes() == 1
    assert len(writer.events) == 1
    assert not worker.stream.pending_for_tick_writer()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("ts", "2026-08-09T00:00:00Z"), ("last_price", 999.0)],
)
def test_readback_never_acknowledges_same_ingest_id_with_different_row(
    tmp_path, field, replacement
):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "same-id", "vt_symbol": "rb2610.SHFE", "last_price": 1},
        stream_generation="g1",
        ingest_seq=worker.stream.next_sequence(),
        source="gateway-publish-proxy",
    )
    worker.stream.append(tick)
    row = verified_tick_to_market_tick_v3(tick)
    row[field] = replacement

    class WrongRowWriter:
        def readback(self, candidate):
            assert candidate.ingest_id == tick.ingest_id
            return row

        def write_verified_tick(self, _candidate):
            pytest.fail("wrong readback must never be overwritten")

    worker.writer = WrongRowWriter()
    with pytest.raises(DurableStateError, match="readback does not match"):
        worker.replay_pending_writes()
    assert not worker.stream.is_acknowledged(tick)


def test_verified_tick_raw_hash_excludes_transport_identity_but_not_content():
    first = VerifiedTick.from_raw(
        {"source_event_id": "one", "vt_symbol": "rb2610.SHFE", "last_price": 1},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-publish-proxy",
    )
    replay = VerifiedTick.from_raw(
        {"source_event_id": "two", "vt_symbol": "rb2610.SHFE", "last_price": 1},
        stream_generation="g1",
        ingest_seq=2,
        source="gateway-publish-proxy",
    )
    changed = VerifiedTick.from_raw(
        {"source_event_id": "one", "vt_symbol": "rb2610.SHFE", "last_price": 2},
        stream_generation="g1",
        ingest_seq=3,
        source="gateway-publish-proxy",
    )
    assert first.raw_hash == replay.raw_hash
    assert first.raw_hash != changed.raw_hash


def test_verified_tick_maps_only_exact_v3_fields_and_nulls_the_rest(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(
        envelope(
            event_time_utc="2026-08-08T01:02:03+00:00",
            last_price=101.5,
            last_volume=7,
            bid_price=100.5,
            ask_price=102.5,
            bid_volume=3,
            ask_volume=4,
        )
    )
    row = verified_tick_to_market_tick_v3(worker.process_one())
    assert tuple(row) == MARKET_TICK_COLUMNS
    assert row["symbol"] == "rb2610" and row["exchange"] == "SHFE"
    assert row["last_price"] == 101.5 and row["last_volume"] == 7.0
    assert row["bid_price_1"] == 100.5 and row["ask_volume_1"] == 4.0
    for field in (
        "gateway_name",
        "name",
        "trading_day",
        "action_day",
        "volume",
        "turnover",
        "open_interest",
        "open_price",
        "high_price",
        "low_price",
        "pre_close",
        "limit_up",
        "limit_down",
        "bid_price_2",
        "ask_volume_5",
    ):
        assert row[field] is None


def test_questdb_writer_is_insert_health_readback_only_and_recovers_connection(
    tmp_path,
):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(envelope())
    tick = worker.process_one()
    first = FakeConnection(
        rows=[(1,)],
        readbacks=[
            tuple(
                verified_tick_to_market_tick_v3(tick)[column]
                for column in MARKET_TICK_COLUMNS
            )
        ],
    )
    connections = [first]
    writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connections.pop(0)
    )
    writer.write_verified_tick(tick)
    assert first.commits == 1
    insert_sql, params = next(
        call
        for call in first.cursor_value.calls
        if call[0].startswith("INSERT INTO market_ticks")
    )
    assert insert_sql.startswith("INSERT INTO market_ticks")
    assert len(params) == len(MARKET_TICK_COLUMNS)
    assert all(
        word not in insert_sql.upper()
        for word in ("CREATE", "ALTER", "DROP", "DELETE", "UPDATE")
    )
    assert writer.health()["status"] == "healthy"
    assert writer.readback(tick) == verified_tick_to_market_tick_v3(tick)
    assert all(
        "postgresql://not-logged" not in sql for sql, _ in first.cursor_value.calls
    )
    metadata = next(
        sql for sql, _ in first.cursor_value.calls if "FROM table_columns" in sql
    )
    assert metadata == (
        'SELECT "column", type, upsertKey, designated '
        "FROM table_columns('market_ticks')"
    )
    readback_sql, readback_params = next(
        call
        for call in first.cursor_value.calls
        if "WHERE ts = %s AND ingest_id = %s" in call[0]
    )
    assert readback_sql.startswith("SELECT ts, received_at, ingest_id")
    assert readback_params == (tick.event_time_utc, tick.ingest_id)
    assert all(
        not any(word in sql.upper() for word in ("CREATE", "ALTER", "DROP"))
        for sql, _ in first.cursor_value.calls
    )


def test_questdb_writer_rejects_missing_prebuilt_schema_before_ready(tmp_path):
    bad = FakeConnection()
    bad.cursor_value.fetchall = lambda: [("ts", "TIMESTAMP")]
    writer = QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: bad)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    with pytest.raises(OSError, match="writer is unavailable"):
        worker.recover()
    assert not worker.readiness().ready


def test_questdb_writer_duplicate_insert_requires_verified_dedup_contract(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(envelope())
    tick = worker.process_one()
    connection = FakeConnection()
    writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connection
    )
    writer.write_verified_tick(tick)
    writer.write_verified_tick(tick)
    inserts = [
        sql for sql, _ in connection.cursor_value.calls if sql.startswith("INSERT INTO")
    ]
    assert len(inserts) == 2
    assert writer._schema_verified


def test_questdb_writer_drops_poisoned_connection_and_reconnects_for_replay(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(envelope())
    tick = worker.process_one()
    poisoned = FakeConnection(fail_execute=True)
    recovered = FakeConnection()
    connections = [poisoned, recovered]
    writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connections.pop(0)
    )
    with pytest.raises(OSError, match="poisoned"):
        writer.write_verified_tick(tick)
    assert poisoned.closed and poisoned.rollbacks == 1
    writer.write_verified_tick(tick)
    assert recovered.commits == 1


def test_market_questdb_batches_commit_before_ack_and_replays_failure(tmp_path):
    first = FakeConnection()
    writer = QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: first)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    for sequence in range(1, 4):
        worker.accept(envelope(f"batch-{sequence}", sequence, last_price=sequence))
    assert worker.process_queue() == 3
    inserts = [
        params
        for sql, params in first.cursor_value.calls
        if sql.startswith("INSERT INTO market_ticks")
    ]
    assert len(inserts) == 3 and first.commits == 1
    assert not worker.stream.pending_for_tick_writer()
    batch = worker.metrics_snapshot()["questdb_batch"]
    assert batch["size_samples"] == [3]
    assert batch["commit_latency_ms"]["p99"] is not None

    failed = FakeConnection(fail_commit=True)
    recovered = FakeConnection()
    connections = [failed, recovered]
    retry_writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connections.pop(0)
    )
    retry = MarketDataWorker(tmp_path / "retry", generation="g1", writer=retry_writer)
    retry.recover()
    retry.accept(envelope("retry", 1))
    with pytest.raises(OSError, match="commit failed"):
        retry.process_queue()
    assert failed.rollbacks == 1
    assert len(retry.stream.pending_for_tick_writer()) == 1
    assert retry.replay_pending() == 1
    assert recovered.commits == 1
    assert not retry.stream.pending_for_tick_writer()


def test_market_questdb_partial_ack_retry_never_reinserts_committed_batch(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(market_data_module.monotonic_time, "monotonic", lambda: 0.0)
    connection = FakeConnection()
    writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connection
    )
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    for sequence in range(1, 3):
        worker.accept(
            envelope(f"partial-{sequence}", sequence, last_price=sequence)
        )

    acknowledge = worker.stream.acknowledge_tick_writes
    failed = False

    def fail_after_first_durable_ack(ticks):
        nonlocal failed
        if not failed:
            failed = True
            acknowledge(tuple(ticks)[:1])
            raise OSError("ack failed after commit")
        return acknowledge(ticks)

    monkeypatch.setattr(
        worker.stream, "acknowledge_tick_writes", fail_after_first_durable_ack
    )
    with pytest.raises(OSError, match="ack failed after commit"):
        worker.process_queue()
    assert connection.commits == 1
    assert len(worker._questdb_pending) == 2

    monkeypatch.setattr(worker.stream, "acknowledge_tick_writes", acknowledge)
    worker.accept(envelope("partial-3", 3, last_price=3))
    assert worker.process_queue() == 1
    assert connection.commits == 2
    assert not worker.stream.pending_for_tick_writer()


def test_market_questdb_failure_keeps_batch_bounded_and_shutdown_fails(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(market_data_module.monotonic_time, "monotonic", lambda: 0.0)
    connections = []

    def connect(_dsn):
        connection = FakeConnection(fail_commit=True)
        connections.append(connection)
        return connection

    writer = QuestDbTickWriter("postgresql://not-logged", connect=connect)

    class BurstSource:
        def __init__(self):
            self.callback = None
            self.polls = 0

        def subscribe(self, callback):
            self.callback = callback

        def poll(self, _timeout_ms=0, *, limit=256):
            self.polls += 1
            if self.polls == 1:
                for sequence in range(1, 101):
                    self.callback(
                        envelope(
                            f"bounded-{sequence}", sequence, last_price=sequence
                        )
                    )
                return min(100, limit)
            return 0

        def has_backlog(self):
            return False

        def close(self):
            return None

    class BoundedStop:
        def __init__(self):
            self.waits = 0

        def is_set(self):
            return self.waits >= 3

        def wait(self, _seconds):
            self.waits += 1
            return self.is_set()

    source = BurstSource()
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", writer=writer, source=source
    )
    with pytest.raises(OSError, match="commit failed"):
        worker.run(stop_event=BoundedStop())
    assert source.polls == 1
    assert 0 < len(worker._questdb_pending) <= worker.QUESTDB_BATCH_MAX_SIZE
    assert len(worker._questdb_pending) + worker.ingress.qsize() == 100
    assert connections and all(connection.rollbacks == 1 for connection in connections)


def test_questdb_predrain_keeps_poison_and_tail_after_durable_prefix(tmp_path):
    connection = FakeConnection()
    worker = MarketDataWorker(
        tmp_path / "market",
        generation="g1",
        writer=QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: connection),
    )
    worker.recover()
    worker.accept(envelope("valid", 1, last_price=1))
    worker.accept(
        GatewayTickEnvelope.create(
            event_id="poison",
            source_service="gateway-market-reader",
            source_generation="source-g1",
            source_seq=2,
            observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            payload={"bid_price": 100, "ask_price": 102},
        )
    )
    worker.accept(envelope("tail", 3, last_price=3))
    with pytest.raises(ValueError, match="vt_symbol is required"):
        worker.process_queue()
    assert worker.stream.stats()["events"] == 1
    assert [worker.ingress.get().event_id, worker.ingress.get().event_id] == [
        "poison",
        "tail",
    ]
    assert connection.commits == 1


def test_questdb_pending_capacity_splits_63_plus_64_without_loss(tmp_path):
    connection = FakeConnection()
    writer = QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: connection)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    old = [
        VerifiedTick.from_raw(
            {"source_event_id": f"old-{sequence}", "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1",
            ingest_seq=sequence,
            source="gateway-market-reader",
        )
        for sequence in range(1, 64)
    ]
    assert all(worker.stream.append_many(old))
    worker._questdb_pending = {tick.ingest_id: tick for tick in old}
    batch_sizes = []
    original_write = writer.write_verified_ticks

    def record_batch(ticks):
        batch_sizes.append(len(ticks))
        original_write(ticks)

    writer.write_verified_ticks = record_batch  # type: ignore[method-assign]
    for sequence in range(1, 65):
        worker.accept(envelope(f"new-{sequence}", sequence, last_price=sequence))
    assert worker.process_queue() == 64
    assert batch_sizes == [64, 63]
    assert max(batch_sizes) == worker.QUESTDB_BATCH_MAX_SIZE
    assert not worker.stream.pending_for_tick_writer()


def test_finalize_failure_preserves_prepared_state_until_next_ingress_recovery(
    tmp_path, monkeypatch
):
    connection = FakeConnection()
    writer = QuestDbTickWriter(
        "postgresql://not-logged", connect=lambda _dsn: connection
    )
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    original_write = worker.source_fence.write
    failed = False

    def fail_final(value):
        nonlocal failed
        if "prepared_batch" not in value and not failed:
            failed = True
            raise OSError("source fence final write failed")
        original_write(value)

    monkeypatch.setattr(worker.source_fence, "write", fail_final)
    worker.accept(envelope("first", 1, last_price=1))
    worker.accept(envelope("second", 2, last_price=2))
    with pytest.raises(OSError, match="source fence final write failed"):
        worker.process_queue()
    assert worker._source_fence_state is not None
    assert "prepared_batch" not in worker._source_fence_state
    assert not worker.ingress.qsize()
    assert len(worker._questdb_pending) == 2
    assert len(worker.stream.pending_for_tick_writer()) == 2

    assert worker.process_queue() == 0
    assert connection.commits == 1
    assert [record["ingest_seq"] for record in worker.stream.acknowledgements.journal.read_all()] == [1, 2]
    assert not worker.stream.pending_for_tick_writer()


def test_group_commit_apis_reject_65_without_consuming_or_writing(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    consumed = 0

    def records():
        nonlocal consumed
        for sequence in range(100):
            consumed += 1
            yield {"sequence": sequence}

    with pytest.raises(BackpressureError, match="group capacity exhausted"):
        journal.append_many(records())
    assert consumed == 65
    assert not journal.path.exists()

    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    ticks = [
        VerifiedTick.from_raw(
            {"source_event_id": f"tick-{sequence}", "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1",
            ingest_seq=sequence,
            source="gateway-market-reader",
        )
        for sequence in range(1, 66)
    ]
    with pytest.raises(BackpressureError, match="tick group capacity exhausted"):
        stream.append_many(iter(ticks))
    assert stream.stats()["events"] == 0

    assert all(stream.append_many(ticks[:64]))
    with pytest.raises(BackpressureError, match="acknowledgement group capacity exhausted"):
        stream.acknowledge_tick_writes(iter([*ticks[:64], ticks[0]]))
    assert not stream.acknowledgements.journal.read_all()


def test_append_only_jsonl_zero_write_poison_stops_same_instance(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    original_write = durable_module.os.write
    calls = 0

    def zero_once(descriptor, value):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 0
        return original_write(descriptor, value)

    monkeypatch.setattr(durable_module.os, "write", zero_once)
    with pytest.raises(DurableCorruptionError, match="journal write failed"):
        journal.append_many(({"first": 1},))
    size = journal.path.stat().st_size
    with pytest.raises(DurableStateError, match="writer is poisoned"):
        journal.append_many(({"second": 2},))
    assert journal.path.stat().st_size == size


def test_append_only_jsonl_short_write_poison_requires_strict_restart_recovery(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    original_write = durable_module.os.write
    calls = 0

    def short_then_fail(descriptor, value):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(descriptor, value[:5])
        raise OSError("short write interrupted")

    monkeypatch.setattr(durable_module.os, "write", short_then_fail)
    with pytest.raises(DurableCorruptionError, match="journal write failed"):
        journal.append_many(({"first": 1},))
    size = journal.path.stat().st_size
    with pytest.raises(DurableStateError, match="writer is poisoned"):
        journal.append_many(({"second": 2},))
    assert journal.path.stat().st_size == size
    with pytest.raises(DurableCorruptionError, match="noncanonical JSONL"):
        AppendOnlyJsonl(journal.path).read_all()


def test_stream_ack_and_watermark_write_failures_poison_same_instance(tmp_path, monkeypatch):
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    first = VerifiedTick.from_raw(
        {"source_event_id": "first", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    monkeypatch.setattr(
        stream.watermark,
        "write",
        lambda _value: (_ for _ in ()).throw(OSError("watermark interrupted")),
    )
    with pytest.raises(OSError, match="watermark interrupted"):
        stream.append_many((first,))
    with pytest.raises(DurableStateError, match="writer is poisoned"):
        stream.append_many((first,))
    # A fresh stream repairs the watermark from the complete journal prefix.
    repaired = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    assert repaired.stats()["events"] == 1

    second = VerifiedTick.from_raw(
        {"source_event_id": "second", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=2,
        source="gateway-market-reader",
    )
    assert repaired.append(second)
    monkeypatch.setattr(
        repaired.acknowledgements.journal,
        "append_many",
        lambda _values: (_ for _ in ()).throw(OSError("ack interrupted")),
    )
    with pytest.raises(OSError, match="ack interrupted"):
        repaired.acknowledge_tick_writes((first, second))
    assert repaired._ack_frontier == 0
    with pytest.raises(DurableStateError, match="writer is poisoned"):
        repaired.acknowledge_tick_writes((first,))


@pytest.mark.parametrize(("count", "expected_batch"), [(3, 3), (64, 64)])
def test_questdb_run_groups_raw_ingress_by_timer_or_size(
    tmp_path, monkeypatch, count, expected_batch
):
    clock = [0.0]
    monkeypatch.setattr(
        market_data_module.monotonic_time, "monotonic", lambda: clock[0]
    )
    connection = FakeConnection()

    class Source:
        def __init__(self):
            self.callback = None
            self.remaining = list(range(1, count + 1))

        def subscribe(self, callback):
            self.callback = callback

        def poll(self, _timeout_ms=0, *, limit=256):
            for _ in range(min(limit, len(self.remaining))):
                sequence = self.remaining.pop(0)
                self.callback(envelope(f"run-{sequence}", sequence, last_price=sequence))
            return 0

        def has_backlog(self):
            return bool(self.remaining)

        def close(self):
            return None

    class ClockStop:
        def __init__(self):
            self.waits = 0

        def is_set(self):
            return self.waits >= 7

        def wait(self, seconds):
            self.waits += 1
            clock[0] += max(float(seconds), 0.01)
            return self.is_set()

    writer = QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: connection)
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", writer=writer, source=Source()
    )
    worker.run(stop_event=ClockStop(), idle_seconds=0.01)
    assert worker.metrics_snapshot()["questdb_batch"]["size_samples"] == [expected_batch]
    assert not worker.stream.pending_for_tick_writer()


def test_questdb_run_shutdown_flushes_partial_raw_ingress(tmp_path, monkeypatch):
    connection = FakeConnection()
    stop = threading.Event()

    class Source:
        def subscribe(self, callback):
            self.callback = callback

        def poll(self, _timeout_ms=0, *, limit=256):
            for sequence in range(1, 4):
                self.callback(envelope(f"shutdown-{sequence}", sequence, last_price=sequence))
            stop.set()
            return 3

        def has_backlog(self):
            return False

        def close(self):
            return None

    monkeypatch.setattr(
        market_data_module.monotonic_time, "monotonic", lambda: 0.0
    )
    writer = QuestDbTickWriter("postgresql://not-logged", connect=lambda _dsn: connection)
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", writer=writer, source=Source()
    )
    worker.run(stop_event=stop)
    assert worker.metrics_snapshot()["questdb_batch"]["size_samples"] == [3]
    assert not worker.stream.pending_for_tick_writer()


def test_zmq_publish_source_is_sub_only_and_recovers_after_poisoned_socket(tmp_path):
    first = FakeSocket([FakeZmqError("reset")])
    tick_data = rpc_tick(
        datetime=datetime(2026, 8, 8, tzinfo=timezone.utc),
        last_price=101.0,
        last_volume=2,
        bid_price_1=100.0,
        ask_price_1=102.0,
        bid_volume_1=3,
        ask_volume_1=4,
    )
    # This exact list is what RpcServer.send_pyobj() publishes.
    second = FakeSocket([[b"eTick.rb2610.SHFE", tick_data]])
    context = FakeContext([first, second])
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=context,
        zmq_module=FakeZmq,
    )
    received = []
    source.subscribe(received.append)
    assert context.kinds == [FakeZmq.SUB]
    assert first.options == [(FakeZmq.SUBSCRIBE, b"")]
    with pytest.raises(OSError, match="disconnected"):
        source.poll()
    assert first.closed
    assert source.poll() == 1
    received_envelope = GatewayTickEnvelope.from_dict(received[0])
    assert received_envelope.capability == "market_data.read"
    assert received_envelope.payload == {
        "vt_symbol": "rb2610.SHFE",
        "symbol": "rb2610",
        "exchange": "SHFE",
        "datetime": datetime(2026, 8, 8, tzinfo=timezone.utc),
        "last_price": 101.0,
        "last_volume": 2,
        "bid_price": 100.0,
        "ask_price": 102.0,
        "bid_volume": 3,
        "ask_volume": 4,
    }
    source.close()
    assert second.closed


def test_zmq_source_drains_bounded_burst_without_reordering_or_loss(tmp_path):
    socket = FakeSocket(
        [
            ["eTick.rb2610.SHFE", rpc_tick(last_price=float(index))]
            for index in range(1, 6)
        ]
    )
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([socket]),
        zmq_module=FakeZmq,
    )
    received = []
    source.subscribe(received.append)
    assert source.poll(limit=3) == 3
    assert source.has_backlog()
    assert source.poll(limit=3) == 2
    assert not source.has_backlog()
    envelopes = [GatewayTickEnvelope.from_dict(value) for value in received]
    assert [event.source_seq for event in envelopes] == [1, 2, 3, 4, 5]
    assert [event.payload["last_price"] for event in envelopes] == [1, 2, 3, 4, 5]
    source.close()


def test_tick_wire_source_keeps_durable_cursor_but_reads_it_once_per_owner(
    tmp_path, monkeypatch
):
    state_dir = tmp_path / "tick-wire"
    source = ZmqTickWireSourceV1(
        "tcp://tick-wire-proxy:4103",
        state_dir=state_dir,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    source.subscribe(lambda _value: None)
    original_read = source._cursor.read
    read_count = 0

    def count_read():
        nonlocal read_count
        read_count += 1
        return original_read()

    monkeypatch.setattr(source._cursor, "read", count_read)
    assert source._next_source_seq() == 1
    assert source._next_source_seq() == 2
    assert read_count == 1
    assert source._cursor.read()["last_source_seq"] == 64
    source.close()

    restarted = ZmqTickWireSourceV1(
        "tcp://tick-wire-proxy:4103",
        state_dir=state_dir,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    restarted.subscribe(lambda _value: None)
    assert restarted._next_source_seq() == 65
    restarted.close()


def test_tick_wire_source_reserves_one_durable_cursor_per_bounded_sequence_group(
    tmp_path, monkeypatch
):
    source = ZmqTickWireSourceV1(
        "tcp://tick-wire-proxy:4103",
        state_dir=tmp_path / "tick-wire",
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    source.subscribe(lambda _value: None)
    original_write = source._cursor.write
    write_count = 0

    def count_write(value):
        nonlocal write_count
        write_count += 1
        original_write(value)

    monkeypatch.setattr(source._cursor, "write", count_write)
    assert [source._next_source_seq() for _ in range(64)] == list(range(1, 65))
    assert write_count == 1
    assert source._next_source_seq() == 65
    assert write_count == 2
    source.close()


def test_tick_wire_source_does_not_expose_sequence_when_reservation_write_fails(
    tmp_path, monkeypatch
):
    source = ZmqTickWireSourceV1(
        "tcp://tick-wire-proxy:4103",
        state_dir=tmp_path / "tick-wire",
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    source.subscribe(lambda _value: None)
    original_write = source._cursor.write
    monkeypatch.setattr(
        source._cursor,
        "write",
        lambda _value: (_ for _ in ()).throw(OSError("cursor unavailable")),
    )
    with pytest.raises(OSError, match="cursor unavailable"):
        source._next_source_seq()
    monkeypatch.setattr(source._cursor, "write", original_write)
    assert source._next_source_seq() == 1
    source.close()


def test_market_source_fence_allows_restart_reservation_gap(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(envelope("before-crash", 1))
    worker.process_one()
    worker.accept(envelope("after-crash", 65, last_price=101))
    worker.process_one()
    assert [tick.ingest_seq for tick in worker.writer.events] == [1, 2]


def test_tick_wire_source_reservation_still_rejects_generation_change(tmp_path):
    source = ZmqTickWireSourceV1(
        "tcp://tick-wire-proxy:4103",
        state_dir=tmp_path / "tick-wire",
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    source._cursor.write({"source_generation": "gateway-g2", "last_source_seq": 64})
    source.subscribe(lambda _value: None)
    with pytest.raises(GenerationMismatch):
        source._next_source_seq()
    source.close()


def test_market_run_drains_backlog_without_idle_wait(tmp_path, monkeypatch):
    socket = FakeSocket(
        [
            ["eTick.rb2610.SHFE", rpc_tick(last_price=1.0)],
            ["eTick.rb2610.SHFE", rpc_tick(last_price=2.0)],
        ]
    )
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path / "market",
        source_generation="gateway-g1",
        context=FakeContext([socket]),
        zmq_module=FakeZmq,
    )

    class StopAfterTwoWriter(Writer):
        def write_verified_tick(self, tick):
            super().write_verified_tick(tick)
            if len(self.events) == 2:
                stop.set()

    stop = threading.Event()
    monkeypatch.setattr(MarketDataWorker, "SOURCE_DRAIN_LIMIT", 1)
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", source=source, writer=StopAfterTwoWriter()
    )
    worker.run(stop_event=stop, idle_seconds=60)
    assert [event.ingest_seq for event in worker.writer.events] == [1, 2]


def test_market_run_processes_existing_ingress_before_receiving_more(tmp_path):
    class Source:
        def subscribe(self, _callback):
            pass

        def poll(self, *_args, **_kwargs):
            pytest.fail("source must not receive while ingress is nonempty")

        def has_backlog(self):
            return False

        def close(self):
            pass

    stop = threading.Event()

    class StopAfterOneWriter(Writer):
        def write_verified_tick(self, tick):
            super().write_verified_tick(tick)
            stop.set()

    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", source=Source(), writer=StopAfterOneWriter()
    )
    worker.accept(envelope())
    worker.run(stop_event=stop)
    assert [event.ingest_seq for event in worker.writer.events] == [1]


def test_market_worker_binds_typed_pub_source_through_envelope_validation(tmp_path):
    tick_data = rpc_tick()
    socket = FakeSocket(
        [["eTick.rb2610.SHFE", tick_data], ["eTick.rb2610.SHFE", tick_data]]
    )
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path / "market",
        source_generation="gateway-g1",
        context=FakeContext([socket]),
        zmq_module=FakeZmq,
    )
    writer = Writer()
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", source=source, writer=writer
    )
    worker.recover()
    worker.bind_source()
    assert source.poll(limit=1) == 1
    worker.process_one()
    assert source.poll(limit=1) == 1
    worker.process_one()
    assert len(writer.events) == 1
    assert worker.metrics.counters["ticks_deduplicated"] == 1


def test_zmq_source_rejects_non_tick_topic_even_if_data_has_tick_like_fields(tmp_path):
    socket = FakeSocket([["eOrder", rpc_tick()]])
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([socket]),
        zmq_module=FakeZmq,
    )
    source.subscribe(lambda _value: pytest.fail("order topic reached tick ingress"))
    with pytest.raises(TypeError, match="not a tick topic"):
        source.poll()


def test_zmq_source_tick_suffix_must_match_exact_vt_symbol(tmp_path):
    tick = rpc_tick()
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket([["eTick.rb2610.SHFE", tick]])]),
        zmq_module=FakeZmq,
    )
    received = []
    source.subscribe(received.append)
    assert source.poll() == 1
    source.close()
    assert (
        GatewayTickEnvelope.from_dict(received[0]).payload["vt_symbol"] == "rb2610.SHFE"
    )

    symbol_only = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket([["eTick.rb2610", tick]])]),
        zmq_module=FakeZmq,
    )
    symbol_only.subscribe(
        lambda _value: pytest.fail("symbol-only topic reached ingress")
    )
    with pytest.raises(TypeError, match="does not match"):
        symbol_only.poll()
    symbol_only.close()

    empty = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket([["eTick", tick]])]),
        zmq_module=FakeZmq,
    )
    empty.subscribe(lambda _value: pytest.fail("empty tick topic reached ingress"))
    with pytest.raises(TypeError, match="not a tick topic"):
        empty.poll()
    empty.close()

    mismatch = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket([["eTick.au2401.SHFE", tick]])]),
        zmq_module=FakeZmq,
    )
    mismatch.subscribe(lambda _value: pytest.fail("mismatched topic reached ingress"))
    with pytest.raises(TypeError, match="does not match"):
        mismatch.poll()
    mismatch.close()


def test_zmq_source_single_process_lock_rejects_second_owner_then_releases(tmp_path):
    first = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    second = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    first.subscribe(lambda _value: None)
    with pytest.raises(DurableStateError, match="already owned"):
        second.subscribe(lambda _value: None)
    first.close()
    second.subscribe(lambda _value: None)
    second.close()


def test_zmq_source_lock_is_enforced_across_processes_and_recovers_after_release(
    tmp_path,
):
    lock_path = tmp_path / "publish_proxy_source.lock"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl, os, sys; "
                "fd=os.open(sys.argv[1], os.O_CREAT|os.O_RDWR, 0o600); "
                "fcntl.flock(fd, fcntl.LOCK_EX); "
                "print('locked', flush=True); sys.stdin.read()"
            ),
            str(lock_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout and holder.stdout.readline().strip() == "locked"
    source = ZmqPublishTickSource(
        "tcp://publish-proxy:4102",
        state_dir=tmp_path,
        source_generation="gateway-g1",
        context=FakeContext([FakeSocket()]),
        zmq_module=FakeZmq,
    )
    with pytest.raises(DurableStateError, match="already owned"):
        source.subscribe(lambda _value: None)
    assert holder.stdin
    holder.stdin.close()
    assert holder.wait(timeout=5) == 0
    source.subscribe(lambda _value: None)
    source.close()


def test_zmq_source_lock_fails_closed_for_symlink_wide_mode_and_replacement(
    tmp_path, monkeypatch
):
    lock_path = tmp_path / "publish_proxy_source.lock"
    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    target.chmod(0o600)
    lock_path.symlink_to(target)
    with pytest.raises(DurableStateError, match="lock"):
        market_data_module._SingleProcessFileLock(lock_path).acquire()
    lock_path.unlink()
    lock_path.write_text("wide", encoding="utf-8")
    lock_path.chmod(0o644)
    with pytest.raises(DurableStateError, match="unsafe"):
        market_data_module._SingleProcessFileLock(lock_path).acquire()
    lock_path.unlink()

    original_flock = market_data_module.fcntl.flock
    replaced = False

    def replace_after_lock(fd, operation):
        nonlocal replaced
        original_flock(fd, operation)
        if not replaced and operation & market_data_module.fcntl.LOCK_EX:
            replaced = True
            lock_path.unlink()
            lock_path.write_text("replacement", encoding="utf-8")
            lock_path.chmod(0o600)

    monkeypatch.setattr(market_data_module.fcntl, "flock", replace_after_lock)
    with pytest.raises(DurableStateError, match="unsafe"):
        market_data_module._SingleProcessFileLock(lock_path).acquire()


def test_market_source_has_only_sub_receive_and_no_order_capabilities():
    source = (Path(__file__).resolve().parents[1] / "market_data_worker.py").read_text(
        encoding="utf-8"
    )
    assert "restricted_tick_wire_loads(self._socket.recv())" in source
    assert "recv_pyobj" not in source and "recv_json" not in source
    assert ".socket(self._zmq.SUB)" in source
    assert all(
        token not in source
        for token in ("send_order", "cancel_order", "get_account", "get_position")
    )


def test_restricted_unpickler_accepts_real_rpc_list_wire_and_blocks_reduce(tmp_path):
    original = rpc_tick(last_price=123.5)
    wire = pickle.dumps(
        ["eTick.rb2610.SHFE", original], protocol=pickle.HIGHEST_PROTOCOL
    )
    decoded = restricted_tick_wire_loads(wire)
    assert isinstance(decoded, list) and decoded[0] == "eTick.rb2610.SHFE"
    assert decoded[1].vt_symbol == "rb2610.SHFE"
    assert decoded[1].last_price == 123.5

    marker = tmp_path / "unpickle-rce-marker"
    malicious = pickle.dumps(
        ["eTick.rb2610.SHFE", MaliciousPickle(marker)], protocol=pickle.HIGHEST_PROTOCOL
    )
    with pytest.raises(pickle.UnpicklingError, match="forbidden pickle global"):
        restricted_tick_wire_loads(malicious)
    assert not marker.exists()


def test_market_config_uses_private_dsn_file_and_does_not_connect_without_endpoints(
    tmp_path, monkeypatch
):
    dsn_file = tmp_path / "questdb.dsn"
    dsn_file.write_text(
        "postgresql://secret-user:secret@questdb/qdb\n", encoding="utf-8"
    )
    dsn_file.chmod(0o600)
    monkeypatch.setenv("PHASE_B_QUESTDB_PG_DSN_FILE", str(dsn_file))
    config = MarketDataConfig.from_environment(tmp_path / "market")
    assert config.questdb_pg_dsn and "secret" in config.questdb_pg_dsn
    assert config.publish_endpoint is None
    worker = MarketDataWorker(config)
    assert worker.source is None
    dsn_file.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        MarketDataConfig.from_environment(tmp_path / "other")


def test_market_ready_fails_closed_when_configured_tick_writer_is_unhealthy(tmp_path):
    worker = MarketDataWorker(
        tmp_path / "market", generation="g1", writer=UnhealthyWriter()
    )
    with pytest.raises(OSError, match="writer is unavailable"):
        worker.recover()
    assert not worker.readiness().ready


def test_durable_state_rejects_symlink_noncanonical_and_unsafe_journals(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    journal.append({"record_type": "ok"})
    journal.path.unlink()
    target = tmp_path / "elsewhere.jsonl"
    target.write_text('{"record_type":"bad"}\n', encoding="utf-8")
    journal.path.symlink_to(target)
    with pytest.raises(DurableCorruptionError):
        journal.read_all()
    journal.path.unlink()
    journal.path.write_text('{"record_type": "not-canonical"}\n', encoding="utf-8")
    journal.path.chmod(0o600)
    with pytest.raises(DurableCorruptionError):
        journal.read_all()


def test_append_only_jsonl_streams_large_multibyte_and_chunked_lines(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    large = "x" * (1024 * 1024 + 17)
    expected = [{"payload": large}, {"text": "多字节 UTF-8"}]
    for record in expected:
        journal.append(record)
    original_read = os.read

    def tiny_reads(descriptor, size):
        return original_read(descriptor, min(size, 3))

    monkeypatch.setattr(os, "read", tiny_reads)
    assert journal.read_all() == expected


def test_append_only_jsonl_group_commit_fsyncs_existing_file_once(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    journal.ensure_exists()
    calls = []
    original_fsync = durable_module.os.fsync

    def count_fsync(descriptor):
        calls.append(descriptor)
        return original_fsync(descriptor)

    monkeypatch.setattr(durable_module.os, "fsync", count_fsync)
    journal.append_many(({"record_type": "one"}, {"record_type": "two"}))
    assert journal.read_all() == [{"record_type": "one"}, {"record_type": "two"}]
    assert len(calls) == 1


def test_verified_stream_group_append_and_ack_use_one_journal_write_each(tmp_path, monkeypatch):
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    ticks = [
        VerifiedTick.from_raw(
            {"source_event_id": f"group-{seq}", "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1",
            ingest_seq=seq,
            source="gateway-market-reader",
        )
        for seq in range(1, 4)
    ]
    append_calls = []
    original_append_many = stream.journal.append_many

    def count_tick_append(records):
        values = tuple(records)
        append_calls.append(values)
        return original_append_many(values)

    monkeypatch.setattr(stream.journal, "append_many", count_tick_append)
    assert stream.append_many(ticks) == (True, True, True)
    assert len(append_calls) == 1 and len(append_calls[0]) == 3

    ack_calls = []
    original_ack_append_many = stream.acknowledgements.journal.append_many

    def count_ack_append(records):
        values = tuple(records)
        ack_calls.append(values)
        return original_ack_append_many(values)

    monkeypatch.setattr(
        stream.acknowledgements.journal, "append_many", count_ack_append
    )
    assert stream.acknowledge_tick_writes(ticks) == (True, True, True)
    assert len(ack_calls) == 1 and len(ack_calls[0]) == 3


def test_market_prepared_source_fence_recovers_complete_or_rejects_partial_batch(tmp_path):
    worker = MarketDataWorker(tmp_path / "complete", generation="g1", writer=Writer())
    worker.recover()
    events = [envelope(f"prepared-{seq}", seq, last_price=seq) for seq in (1, 2)]
    ticks = [
        VerifiedTick.from_raw(
            {**dict(event.payload), "source_event_id": event.event_id},
            stream_generation="g1",
            ingest_seq=seq,
            source=event.source_service,
        )
        for seq, event in enumerate(events, start=1)
    ]
    prepare, _ = worker._prepare_source_fence_batch(list(zip(events, ticks)))
    prepare()
    worker.stream.append_many(ticks)
    restarted = MarketDataWorker(tmp_path / "complete", generation="g1", writer=Writer())
    restarted.recover()
    assert restarted._source_fence_state is not None
    assert "prepared_batch" not in restarted._source_fence_state
    assert restarted._source_fence_state["sources"]["gateway-market-reader"]["seq"] == 2

    partial = MarketDataWorker(tmp_path / "partial", generation="g1", writer=Writer())
    partial.recover()
    prepare, _ = partial._prepare_source_fence_batch(list(zip(events, ticks)))
    prepare()
    partial.stream.append(ticks[0])
    with pytest.raises(DurableCorruptionError, match="batch is partial"):
        MarketDataWorker(tmp_path / "partial", generation="g1", writer=Writer()).recover()

    absent = MarketDataWorker(tmp_path / "absent", generation="g1", writer=Writer())
    absent.recover()
    prepare, _ = absent._prepare_source_fence_batch(list(zip(events, ticks)))
    prepare()
    restarted_absent = MarketDataWorker(
        tmp_path / "absent", generation="g1", writer=Writer()
    )
    restarted_absent.recover()
    assert restarted_absent._source_fence_state is not None
    assert restarted_absent._source_fence_state["sources"] == {}


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"value":1}', "noncanonical JSONL"),
        (b'{"value":"' + bytes([255]) + b'"}\n', "invalid UTF-8 journal"),
    ],
)
def test_append_only_jsonl_streaming_rejects_unterminated_and_invalid_utf8(
    tmp_path, raw, message
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = state / "journal.jsonl"
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(DurableCorruptionError, match=message):
        AppendOnlyJsonl(path).read_all()


def test_verified_stream_rejects_gap_and_forged_ack_before_polluting_journal(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    market.recover()
    market.accept(envelope())
    first = market.process_one()
    forged = VerifiedTick.from_raw(
        {"source_event_id": first.source_event_id, "vt_symbol": first.vt_symbol},
        stream_generation="g1",
        ingest_seq=2,
        source=first.source,
    )
    with pytest.raises(DurableCorruptionError):
        market.stream.acknowledge_tick_write(forged)
    assert len(market.stream.acknowledgements.values()) == 1
    gap = VerifiedTick.from_raw(
        {"source_event_id": "gap", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=3,
        source="gateway-market-reader",
    )
    market.stream.journal.append(
        {"record_type": "verified_tick", "tick": gap.as_dict()}
    )
    restarted = DurableVerifiedTickStream(
        tmp_path / "market" / "stream", generation="g1"
    )
    with pytest.raises(DurableCorruptionError, match="gap/duplicate"):
        restarted.stats()


def test_verified_stream_serializes_competing_producers_without_duplicate_sequence(
    tmp_path,
):
    stream_dir = tmp_path / "stream"
    first = DurableVerifiedTickStream(stream_dir, generation="g1")
    second = DurableVerifiedTickStream(stream_dir, generation="g1")
    candidates = [
        VerifiedTick.from_raw(
            {"source_event_id": event_id, "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1",
            ingest_seq=1,
            source="gateway-market-reader",
        )
        for event_id in ("first", "second")
    ]
    barrier = threading.Barrier(2)
    outcomes = []

    def append(stream, tick):
        barrier.wait()
        try:
            outcomes.append(stream.append(tick))
        except DurableStateError:
            outcomes.append(False)

    threads = [
        threading.Thread(target=append, args=(first, candidates[0])),
        threading.Thread(target=append, args=(second, candidates[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count(True) == 1
    assert DurableVerifiedTickStream(stream_dir, generation="g1").stats()["events"] == 1


def test_verified_stream_append_and_contiguous_ack_frontiers_are_incremental(
    tmp_path, monkeypatch
):
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    calls = 0
    original_records = AppendOnlyJsonl.records

    def count_records(journal):
        nonlocal calls
        calls += 1
        yield from original_records(journal)

    monkeypatch.setattr(AppendOnlyJsonl, "records", count_records)
    ticks = [
        VerifiedTick.from_raw(
            {
                "source_event_id": f"event-{seq}",
                "vt_symbol": "rb2610.SHFE",
                "last_price": seq,
            },
            stream_generation="g1",
            ingest_seq=seq,
            source="gateway-market-reader",
        )
        for seq in range(1, 5)
    ]
    for tick in ticks:
        assert stream.append(tick)
    # Initial recovery reads tick and acknowledgement JSONL once each.  Later
    # append/ack operations must advance their in-memory frontiers directly.
    assert calls == 2

    assert stream.acknowledge_tick_write(ticks[2])
    assert stream._ack_frontier == 0
    assert stream._ack_sparse == {3}
    assert stream.acknowledge_tick_write(ticks[0])
    assert stream._ack_frontier == 1
    assert stream.acknowledge_tick_write(ticks[1])
    assert stream._ack_frontier == 3
    assert stream._ack_sparse == set()
    assert stream.acknowledge_tick_write(ticks[3])
    assert stream._ack_frontier == 4
    assert calls == 2


def test_verified_stream_ack_reloads_after_competing_producer_advances_frontier(
    tmp_path,
):
    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    writer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    first = VerifiedTick.from_raw(
        {"source_event_id": "first", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    second = VerifiedTick.from_raw(
        {"source_event_id": "second", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=2,
        source="gateway-market-reader",
    )
    assert producer.append(first)
    assert writer.stats()["events"] == 1
    assert producer.append(second)
    assert writer.acknowledge_tick_write(second)
    assert writer._indexed_watermark_seq == 2
    assert writer.is_acknowledged(second)


def test_verified_stream_ack_refreshes_cross_process_ack_only_drift(tmp_path):
    stream_dir = tmp_path / "stream"
    first = DurableVerifiedTickStream(stream_dir, generation="g1")
    second = DurableVerifiedTickStream(stream_dir, generation="g1")
    first.initialize()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "same", "vt_symbol": "rb2610.SHFE", "last_price": 1},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    assert first.append(tick)
    # Both instances capture the same watermark and initial empty ack journal.
    assert first.stats()["events"] == second.stats()["events"] == 1
    assert first.acknowledge_tick_write(tick)
    assert not second.acknowledge_tick_write(tick)
    assert len(second.acknowledgements.journal.read_all()) == 1

    altered = VerifiedTick.from_raw(
        {"source_event_id": "same", "vt_symbol": "rb2610.SHFE", "last_price": 2},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    with pytest.raises(DurableCorruptionError, match="does not bind to persisted tick"):
        second.acknowledge_tick_write(altered)


def test_verified_stream_sparse_ack_capacity_fails_before_durable_write(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(DurableVerifiedTickStream, "_ACK_SPARSE_LIMIT", 1)
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    ticks = [
        VerifiedTick.from_raw(
            {
                "source_event_id": f"event-{seq}",
                "vt_symbol": "rb2610.SHFE",
                "last_price": seq,
            },
            stream_generation="g1",
            ingest_seq=seq,
            source="gateway-market-reader",
        )
        for seq in range(1, 5)
    ]
    for tick in ticks:
        assert stream.append(tick)
    assert stream.acknowledge_tick_write(ticks[2])
    with pytest.raises(BackpressureError, match="sparse frontier exhausted"):
        stream.acknowledge_tick_write(ticks[3])
    assert not stream.is_acknowledged(ticks[3])


def test_verified_stream_uses_bounded_hot_cache_and_exact_durable_fallback(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(DurableVerifiedTickStream, "_TICK_CACHE_LIMIT", 2)
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    ticks = [
        VerifiedTick.from_raw(
            {"source_event_id": f"event-{seq}", "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1",
            ingest_seq=seq,
            source="gateway-market-reader",
        )
        for seq in range(1, 5)
    ]
    for tick in ticks:
        assert stream.append(tick)
    assert len(stream._index or {}) == 2
    assert stream.get(ticks[0].ingest_id) == ticks[0]
    assert stream.find_by_source_event_id("event-1") == ticks[0]
    assert stream.find_by_raw_hash(ticks[0].raw_hash) == ticks[0]
    assert not stream.append(ticks[0])

    altered = VerifiedTick.from_raw(
        {"source_event_id": "event-1", "vt_symbol": "rb2610.SHFE", "last_price": 2},
        stream_generation="g1",
        ingest_seq=5,
        source="gateway-market-reader",
    )
    with pytest.raises(DuplicateRecordError, match="ingest_id reused"):
        stream.append(altered)


def test_verified_stream_membership_capacity_fails_closed_before_append(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "phase_b_workers.durable._BoundedMembershipFilter._CAPACITY", 2
    )
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    for seq in (1, 2):
        assert stream.append(
            VerifiedTick.from_raw(
                {"source_event_id": f"event-{seq}", "vt_symbol": "rb2610.SHFE"},
                stream_generation="g1",
                ingest_seq=seq,
                source="gateway-market-reader",
            )
        )
    third = VerifiedTick.from_raw(
        {"source_event_id": "event-3", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=3,
        source="gateway-market-reader",
    )
    with pytest.raises(BackpressureError, match="membership filter capacity"):
        stream.append(third)
    assert stream.stats()["events"] == 2


def test_verified_stream_recovery_rejects_ack_binding_tampering(tmp_path):
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "one", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    assert stream.append(tick)
    assert stream.acknowledge_tick_write(tick)
    stream.acknowledgements.journal.path.write_text(
        json.dumps(
            {
                "ingest_id": tick.ingest_id,
                "stream_generation": "g1",
                "ingest_seq": 1,
                "event_hash": "0" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    stream.acknowledgements.journal.path.chmod(0o600)
    with pytest.raises(DurableCorruptionError, match="does not bind to tick"):
        DurableVerifiedTickStream(tmp_path / "stream", generation="g1").stats()


def test_verified_stream_recovery_rejects_exact_duplicate_ack_record(tmp_path):
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation="g1")
    stream.initialize()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "one", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    assert stream.append(tick)
    assert stream.acknowledge_tick_write(tick)
    original = stream.acknowledgements.journal.path.read_text(encoding="utf-8")
    stream.acknowledgements.journal.path.write_text(original + original, encoding="utf-8")
    stream.acknowledgements.journal.path.chmod(0o600)
    with pytest.raises(DurableCorruptionError, match="identity duplicated"):
        DurableVerifiedTickStream(tmp_path / "stream", generation="g1").stats()


def test_market_revalidates_constructed_envelopes_and_persists_event_fence_before_sink(
    tmp_path,
):
    writer = Writer(True)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    valid = envelope("same-id", 1)
    with pytest.raises(ValueError):
        worker.accept(replace(valid, capability="order.send"))
    worker.accept(valid)
    with pytest.raises(OSError):
        worker.process_one()
    restarted = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    restarted.recover()
    restarted.accept(envelope("same-id", 2))
    with pytest.raises(DurableStateError, match="reused with different content"):
        restarted.process_one()


def test_market_source_fence_hotpath_uses_recovered_state_and_fails_closed_at_capacity(
    tmp_path, monkeypatch
):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    monkeypatch.setattr(
        worker.source_fence,
        "read",
        lambda: pytest.fail("source fence checkpoint must not be reread per event"),
    )
    worker.accept(envelope("one", 1))
    worker.process_one()
    worker.accept(envelope("two", 2))
    worker.process_one()

    monkeypatch.setattr(MarketDataWorker, "_SOURCE_FENCE_EVENT_LIMIT", 2)
    worker.accept(envelope("three", 3))
    with pytest.raises(BackpressureError, match="identity capacity exhausted"):
        worker.process_one()
    assert worker._source_fence_state is not None
    assert set(worker._source_fence_state["events"]) == {"one", "two"}


def test_market_source_fence_rejects_generation_sequence_and_identity_regressions(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    worker.accept(envelope("one", 1))
    worker.process_one()
    worker.accept(envelope("two", 2, last_price=102))
    worker.process_one()
    worker.accept(envelope("old", 1))
    with pytest.raises(DurableStateError, match="stale source sequence"):
        worker.process_one()
    worker.accept(
        GatewayTickEnvelope.create(
            event_id="new-generation",
            source_service="gateway-market-reader",
            source_generation="source-g2",
            source_seq=3,
            observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            payload={"vt_symbol": "rb2610.SHFE", "bid_price": 100, "ask_price": 102},
        )
    )
    with pytest.raises(GenerationMismatch):
        worker.process_one()


def test_market_deterministic_source_fence_keeps_event_state_compact(tmp_path):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    worker.recover()
    checkpoint_sizes = []
    for seq in range(1, 5):
        payload = {
            "vt_symbol": "rb2610.SHFE",
            "bid_price": 100,
            "ask_price": 102,
            "last_price": seq,
        }
        event_id = market_data_module.sha256_hex(
            {
                "source_generation": "source-g1",
                "source_seq": seq,
                "topic": "eTick.rb2610.SHFE",
                "payload": payload,
            }
        )[:32]
        worker.accept(
            GatewayTickEnvelope.create(
                event_id=event_id,
                source_service="gateway-publish-proxy",
                source_generation="source-g1",
                source_seq=seq,
                observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
                payload=payload,
            )
        )
        worker.process_one()
        checkpoint_sizes.append(worker.source_fence.path.stat().st_size)
    assert worker._source_fence_state is not None
    assert worker._source_fence_state["events"] == {}
    assert checkpoint_sizes == [checkpoint_sizes[0]] * 4

    worker.accept(
        GatewayTickEnvelope.create(
            event_id="forged",
            source_service="gateway-publish-proxy",
            source_generation="source-g1",
            source_seq=5,
            observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            payload={"vt_symbol": "rb2610.SHFE", "bid_price": 100, "ask_price": 102},
        )
    )
    with pytest.raises(DurableStateError, match="deterministic source event identity"):
        worker.process_one()

    # A replay with the old deterministic identity but modified payload also
    # fails before stream/sink processing; no historical event map is needed.
    original_event_id = market_data_module.sha256_hex(
        {
            "source_generation": "source-g1",
            "source_seq": 1,
            "topic": "eTick.rb2610.SHFE",
            "payload": {
                "vt_symbol": "rb2610.SHFE",
                "bid_price": 100,
                "ask_price": 102,
                "last_price": 1,
            },
        }
    )[:32]
    worker.accept(
        GatewayTickEnvelope.create(
            # Same historical ID with a different payload/envelope hash.
            event_id=original_event_id,
            source_service="gateway-publish-proxy",
            source_generation="source-g1",
            source_seq=1,
            observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
            payload={"vt_symbol": "rb2610.SHFE", "bid_price": 999, "ask_price": 102},
        )
    )
    with pytest.raises(DurableStateError, match="deterministic source event identity"):
        worker.process_one()


def test_market_projection_heartbeats_at_most_once_per_second(tmp_path, monkeypatch):
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    published = []
    monkeypatch.setattr(worker, "publish_projection", lambda: published.append(True))
    clock = [100.0]
    monkeypatch.setattr(market_data_module.monotonic_time, "monotonic", lambda: clock[0])
    assert worker._publish_projection_if_due(force=True)
    assert not worker._publish_projection_if_due()
    clock[0] += 0.99
    assert not worker._publish_projection_if_due()
    clock[0] += 0.01
    assert worker._publish_projection_if_due()
    assert len(published) == 2


def test_market_long_queue_and_replay_keep_projection_heartbeat(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(market_data_module.monotonic_time, "monotonic", lambda: clock[0])

    class SlowWriter(Writer):
        def write_verified_tick(self, tick):
            super().write_verified_tick(tick)
            clock[0] += 1.1

    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=SlowWriter())
    worker.recover()
    published = []
    monkeypatch.setattr(worker, "publish_projection", lambda: published.append(clock[0]))
    for sequence in range(1, 4):
        worker.accept(envelope(f"queue-{sequence}", sequence, last_price=sequence))
    assert worker.process_queue() == 3
    assert [tick.ingest_seq for tick in worker.writer.events] == [1, 2, 3]
    assert len(published) == 3

    failed = MarketDataWorker(tmp_path / "replay", generation="g1", writer=Writer(True))
    failed.recover()
    for sequence in range(1, 4):
        failed.accept(envelope(f"replay-{sequence}", sequence, last_price=sequence))
        with pytest.raises(OSError):
            failed.process_one()
    replayed = MarketDataWorker(
        tmp_path / "replay", generation="g1", writer=SlowWriter()
    )
    replayed.recover()
    replay_published = []
    monkeypatch.setattr(
        replayed, "publish_projection", lambda: replay_published.append(clock[0])
    )
    assert replayed.replay_pending() == 3
    assert [tick.ingest_seq for tick in replayed.writer.events] == [1, 2, 3]
    assert len(replay_published) == 3


def test_market_run_recovers_and_replays_before_readiness(tmp_path):
    failed = Writer(True)
    first = MarketDataWorker(tmp_path / "market", generation="g1", writer=failed)
    first.recover()
    first.accept(envelope())
    with pytest.raises(OSError):
        first.process_one()
    recovered_writer = Writer()
    restarted = MarketDataWorker(
        tmp_path / "market", generation="g1", writer=recovered_writer
    )
    stop = threading.Event()
    stop.set()
    restarted.run(stop_event=stop)
    assert [tick.ingest_seq for tick in recovered_writer.events] == [1]
    assert restarted.readiness().ready


def test_market_and_execution_quality_are_not_ready_before_recovery(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    assert not market.readiness().ready
    for snapshot in (
        market.health().as_dict(),
        market.readiness().as_dict(),
        market.version(),
    ):
        assert all(
            snapshot[name] is False
            for name in (
                "private_key_access",
                "trade_rpc_access",
                "account_access",
                "order_access",
            )
        )
    market.recover()
    quality = ExecutionQualityWorker(
        tmp_path / "quality",
        generation="g1",
        tick_stream_dir=tmp_path / "market" / "stream",
    )
    assert not quality.readiness().ready
    for snapshot in (
        quality.health().as_dict(),
        quality.readiness().as_dict(),
        quality.version(),
    ):
        assert all(
            snapshot[name] is False
            for name in (
                "private_key_access",
                "trade_rpc_access",
                "account_access",
                "order_access",
            )
        )


def test_ready_cli_performs_bounded_recovery_and_reports_access_boundaries(
    tmp_path, monkeypatch, capsys
):
    market_dir = tmp_path / "market"
    monkeypatch.setenv("PHASE_B_EQ_STATE_DIR", str(tmp_path / "quality"))
    monkeypatch.setenv("PHASE_B_VERIFIED_STREAM_DIR", str(market_dir / "stream"))
    assert execution_quality_main(["--ready"]) == 1
    unavailable = json.loads(capsys.readouterr().out)
    assert not unavailable["ready"] and unavailable["blockers"] == [
        "consumer_recovery_required"
    ]

    monkeypatch.setenv("PHASE_B_MARKET_DATA_STATE_DIR", str(market_dir))
    assert market_data_main(["--ready"]) == 0
    market_ready = json.loads(capsys.readouterr().out)
    assert market_ready["ready"] and market_ready["state_recovered"]
    assert all(
        not market_ready[name]
        for name in (
            "private_key_access",
            "trade_rpc_access",
            "account_access",
            "order_access",
        )
    )

    assert execution_quality_main(["--ready"]) == 0
    quality_ready = json.loads(capsys.readouterr().out)
    assert quality_ready["ready"] and quality_ready["state_recovered"]
    assert all(
        not quality_ready[name]
        for name in (
            "private_key_access",
            "trade_rpc_access",
            "account_access",
            "order_access",
        )
    )


def test_read_only_tick_stream_never_mutates_producer_artifacts(tmp_path):
    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    before = {
        path.name: (path.stat().st_mtime_ns, path.stat().st_mode)
        for path in stream_dir.iterdir()
        if path.name != ".stream.lock"
    }
    consumer = DurableVerifiedTickStream(stream_dir, generation="g1", read_only=True)
    assert consumer.stats()["events"] == 0
    after = {
        path.name: (path.stat().st_mtime_ns, path.stat().st_mode)
        for path in stream_dir.iterdir()
        if path.name != ".stream.lock"
    }
    assert after == before


def test_default_tick_stream_scans_one_locked_producer_frontier(tmp_path, monkeypatch):
    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    first = VerifiedTick.from_raw(
        {"source_event_id": "first", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    second = VerifiedTick.from_raw(
        {"source_event_id": "second", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=2,
        source="gateway-market-reader",
    )
    assert producer.append(first)

    scan_started = threading.Event()
    release_scan = threading.Event()
    append_started = threading.Event()
    append_finished = threading.Event()
    original_records = AppendOnlyJsonl.records

    def pause_stream_scan(journal):
        if (
            journal.path == producer.journal.path
            and threading.current_thread().name == "stream-loader"
        ):
            scan_started.set()
            assert release_scan.wait(timeout=5)
        yield from original_records(journal)

    monkeypatch.setattr(AppendOnlyJsonl, "records", pause_stream_scan)
    snapshots = []
    failures = []

    def load_stream():
        try:
            consumer = DurableVerifiedTickStream(stream_dir, generation="g1")
            snapshots.append([tick.ingest_seq for tick in consumer.iter_from()])
        except (AssertionError, DurableStateError, OSError) as exc:
            failures.append(exc)

    def append_while_scanning():
        try:
            append_started.set()
            assert producer.append(second)
        except (AssertionError, DurableStateError, OSError) as exc:
            failures.append(exc)
        finally:
            append_finished.set()

    reader = threading.Thread(target=load_stream, name="stream-loader")
    reader.start()
    assert scan_started.wait(timeout=5)
    writer = threading.Thread(target=append_while_scanning)
    writer.start()
    assert append_started.wait(timeout=5)
    assert not append_finished.wait(timeout=0.2)
    release_scan.set()
    reader.join(timeout=5)
    writer.join(timeout=5)

    assert not reader.is_alive() and not writer.is_alive()
    assert not failures
    assert snapshots == [[1]]
    assert [tick.ingest_seq for tick in producer.iter_from()] == [1, 2]


def test_read_only_tick_stream_does_not_cache_ahead_watermark_failure(tmp_path):
    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "tick", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    assert producer.append(tick)
    consumer = DurableVerifiedTickStream(stream_dir, generation="g1", read_only=True)
    producer.watermark.write(
        {
            "stream_generation": "g1",
            "last_ingest_seq": 2,
            "last_event_hash": tick.event_hash,
        }
    )
    consumer._index = None

    for _ in range(2):
        with pytest.raises(DurableCorruptionError, match="ahead of journal"):
            consumer._load_index()
        assert consumer._index is None


def test_tick_stream_preserves_producer_repair_and_read_only_behind_semantics(tmp_path):
    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    tick = VerifiedTick.from_raw(
        {"source_event_id": "tick", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1",
        ingest_seq=1,
        source="gateway-market-reader",
    )
    assert producer.append(tick)
    producer.watermark.write(
        {"stream_generation": "g1", "last_ingest_seq": 0, "last_event_hash": ""}
    )

    with pytest.raises(DurableCorruptionError, match="watermark is behind"):
        DurableVerifiedTickStream(stream_dir, generation="g1", read_only=True)

    restarted = DurableVerifiedTickStream(stream_dir, generation="g1")
    assert restarted.stats()["last_ingest_seq"] == 1
    assert producer.watermark.read()["last_ingest_seq"] == 1


def test_read_only_tick_stream_rejects_missing_or_corrupt_producer_state(tmp_path):
    missing = tmp_path / "missing"
    missing.mkdir(mode=0o700)
    with pytest.raises(DurableCorruptionError, match="producer-initialized"):
        DurableVerifiedTickStream(missing, generation="g1", read_only=True)

    stream_dir = tmp_path / "stream"
    producer = DurableVerifiedTickStream(stream_dir, generation="g1")
    producer.initialize()
    (stream_dir / "verified_ticks.jsonl").write_text(
        '{"record_type": "bad"}\n', encoding="utf-8"
    )
    (stream_dir / "verified_ticks.jsonl").chmod(0o600)
    with pytest.raises(DurableCorruptionError, match="noncanonical JSONL"):
        DurableVerifiedTickStream(stream_dir, generation="g1", read_only=True)


def test_execution_checkpoint_follows_evidence(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    market.recover()
    market.accept(envelope())
    tick = market.process_one()
    eq = ExecutionQualityWorker(
        tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"
    )
    eq.recover()
    prior = eq._make_evidence(tick)
    eq.evidence.append(prior)
    assert eq.process_one() is not None and eq.last_ingest_seq == 1


def test_execution_recovery_binds_checkpoint_event_evidence_generation_and_algorithm(
    tmp_path,
):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    market.recover()
    market.accept(envelope())
    market.process_one()
    eq = ExecutionQualityWorker(
        tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"
    )
    eq.recover()
    assert eq.process_one() is not None
    checkpoint = eq.checkpoint.read()
    eq.checkpoint.write({**checkpoint, "last_evidence_hash": "0" * 64})
    restarted = ExecutionQualityWorker(
        tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"
    )
    with pytest.raises(
        DurableCorruptionError, match="checkpoint evidence hash mismatch"
    ):
        restarted.recover()


def test_monitor_outbox_fences_delivery(tmp_path):
    worker = MonitorWorker(tmp_path / "monitor", generation="old")
    worker.recover()
    incident = worker.observe(
        "execution-orchestrator", {"status": "unavailable", "token": "secret"}
    )
    assert incident is not None and len(worker.repository.pending()) == 1
    delivery = int(worker.repository.pending()[0]["delivery_id"])
    new = MonitorWorker(tmp_path / "monitor", generation="new")
    new.recover()
    assert not worker.repository.mark_delivered(
        delivery, generation="old", epoch=worker.fence_epoch
    )
    assert new.repository.mark_delivered(
        delivery, generation="new", epoch=new.fence_epoch
    )


def test_monitor_run_once_durably_records_incident_and_outbox_then_replays(tmp_path):
    config = MonitorConfig(tmp_path / "monitor", None, generation="g1")
    projection = {
        "service_id": "market-data-worker",
        "status": "unhealthy",
        "ready": False,
    }
    first_notifier = Notifier(False)
    worker = MonitorWorker(
        config, source=Projection(projection), notifier=first_notifier
    )
    result = worker.run_once()
    assert len(result["transitions"]) == 1
    assert len(worker.incidents.records()) == 1
    assert len(worker.repository.pending()) == 1
    second_notifier = Notifier(True)
    restarted = MonitorWorker(
        config, source=Projection(projection), notifier=second_notifier
    )
    restarted.run_once()
    assert len(second_notifier.events) == 1
    assert not restarted.repository.pending()


def test_monitor_projection_absence_blocks_readiness_and_network_notifier_is_disabled(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PHASE_B_TELEGRAM_TOKEN", "not-a-real-token")
    monkeypatch.setenv("PHASE_B_TELEGRAM_CHAT_ID", "not-a-real-chat")
    config = MonitorConfig(
        tmp_path / "monitor", None, generation="g1", telegram_enabled=False
    )
    worker = MonitorWorker(config)
    worker.recover()
    assert isinstance(worker.notifier, NullNotifier)
    assert worker.notifier.status()["status"] == "disabled"
    readiness = worker.readiness()
    assert not readiness.ready and "projection_dir_missing" in readiness.blockers


def test_typed_producer_projections_make_monitor_ready_and_fail_closed_when_tampered(
    tmp_path,
):
    projections = tmp_path / "projections"
    market_projection = projections / "market-data-worker"
    quality_projection = projections / "execution-quality-worker"
    custody_projection = projections / "artifact-custody"
    market = MarketDataWorker(
        MarketDataConfig(tmp_path / "market", "g1", projection_dir=market_projection),
        writer=Writer(),
    )
    market.recover()
    market.publish_projection()
    quality = ExecutionQualityWorker(
        ExecutionQualityConfig(
            tmp_path / "quality",
            tmp_path / "market" / "stream",
            "g1",
            projection_dir=quality_projection,
        )
    )
    quality.recover()
    quality.publish_projection()
    publish_custody_projection(
        str(custody_projection),
        audit={
            "version": 0,
            "artifact_count": 0,
            "receipt_count": 0,
            "previous_record_sha256": None,
            "production": False,
            "live": False,
            "countable_forward": False,
        },
    )
    monitor = MonitorWorker(
        MonitorConfig(tmp_path / "monitor", projections, generation="g1")
    )
    monitor.recover()
    assert monitor.readiness().ready
    assert monitor.run_once()["projections"] == 3

    path = market_projection / "market-data-worker.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["payload"]["health"]["status"] = "unhealthy"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not monitor.readiness().ready


def test_market_projection_health_exposes_running_queue_and_counter_metrics(tmp_path):
    projection_dir = tmp_path / "projections" / "market-data-worker"
    worker = MarketDataWorker(
        MarketDataConfig(tmp_path / "market", "g1", projection_dir=projection_dir),
        writer=Writer(),
    )
    worker.recover()
    worker.accept(envelope("one", 1))
    worker.accept(envelope("two", 2, last_price=102))
    worker.process_one()
    worker.publish_projection()

    projection = json.loads(
        (projection_dir / "market-data-worker.json").read_text(encoding="utf-8")
    )
    metrics = projection["payload"]["health"]["dependencies"]["worker_metrics"]
    assert metrics["queue_depth"] == 1
    assert metrics["counters"]["ingress_accepted"] == 2
    assert metrics["counters"]["processed_total"] == 1
    assert metrics["checkpoint_or_watermark"] == 1


def test_queue_overflow_is_visible():
    queue = BoundedIngressQueue[int](1)
    queue.put(1)
    with pytest.raises(BackpressureError):
        queue.put(2)


def test_sources_have_no_application_imports():
    package = Path(__file__).resolve().parents[1]
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("app", "backend", "vnpy"))
            if isinstance(node, ast.Import):
                assert all(
                    not alias.name.startswith(("app", "backend", "vnpy"))
                    for alias in node.names
                )


def test_worker_containerfiles_are_scripts_only():
    root = Path(__file__).resolve().parents[3]
    for name in (
        "Containerfile.market-data-worker",
        "Containerfile.execution-quality-worker",
        "Containerfile.monitor-worker",
    ):
        text = (root / "deployments" / "phase-b" / name).read_text(encoding="utf-8")
        assert (
            "COPY backend" not in text
            and "uvicorn" not in text
            and "EXPOSE" not in text
        )
