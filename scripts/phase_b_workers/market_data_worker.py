"""Standalone market-data worker with a durable verified-tick handoff."""

from __future__ import annotations

import argparse
import fcntl
import io
import json
import os
import pickle
import signal
import stat
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, Self

try:  # Installed only in the market-data worker image.
    import zmq
except ImportError:  # pragma: no cover - dependency absence is a deployment error
    zmq = None  # type: ignore[assignment]

try:  # Installed only in the market-data worker image.
    import psycopg
except ImportError:  # pragma: no cover - dependency absence is a deployment error
    psycopg = None  # type: ignore[assignment]

try:
    from . import CONTRACT_VERSION
    from .contracts import (
        GatewayTickEnvelope,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        sha256_hex,
    )
    from .durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableStateError,
        DurableVerifiedTickStream,
        GenerationMismatch,
        _open_parent,
    )
    from .projections import build_projection, publish_projection
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from phase_b_workers import CONTRACT_VERSION
    from phase_b_workers.contracts import (
        GatewayTickEnvelope,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        sha256_hex,
    )
    from phase_b_workers.durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableStateError,
        DurableVerifiedTickStream,
        GenerationMismatch,
        _open_parent,
    )
    from phase_b_workers.projections import build_projection, publish_projection


class ReadonlyTickSource(Protocol):
    def subscribe(self, callback: Callable[[Mapping[str, object]], None]) -> None: ...

    def close(self) -> None: ...


class TickWriter(Protocol):
    def write_tick(self, tick: Mapping[str, object]) -> None: ...


MARKET_TICK_COLUMNS = (
    "ts",
    "received_at",
    "ingest_id",
    "ingest_seq",
    "schema_version",
    "vt_symbol",
    "symbol",
    "exchange",
    "gateway_name",
    "name",
    "trading_day",
    "action_day",
    "last_price",
    "last_volume",
    "volume",
    "turnover",
    "open_interest",
    "open_price",
    "high_price",
    "low_price",
    "pre_close",
    "limit_up",
    "limit_down",
    "bid_price_1",
    "bid_price_2",
    "bid_price_3",
    "bid_price_4",
    "bid_price_5",
    "ask_price_1",
    "ask_price_2",
    "ask_price_3",
    "ask_price_4",
    "ask_price_5",
    "bid_volume_1",
    "bid_volume_2",
    "bid_volume_3",
    "bid_volume_4",
    "bid_volume_5",
    "ask_volume_1",
    "ask_volume_2",
    "ask_volume_3",
    "ask_volume_4",
    "ask_volume_5",
)
_MARKET_TICK_INSERT = (
    f"INSERT INTO market_ticks ({', '.join(MARKET_TICK_COLUMNS)}) "
    f"VALUES ({', '.join(['%s'] * len(MARKET_TICK_COLUMNS))})"
)
MARKET_TICK_SCHEMA_TYPES = {
    "ts": "TIMESTAMP",
    "received_at": "TIMESTAMP",
    "ingest_id": "STRING",
    "ingest_seq": "LONG",
    "schema_version": "INT",
    "vt_symbol": "SYMBOL",
    "symbol": "SYMBOL",
    "exchange": "SYMBOL",
    "gateway_name": "SYMBOL",
    "name": "STRING",
    "trading_day": "STRING",
    "action_day": "STRING",
    **{
        column: "DOUBLE"
        for column in MARKET_TICK_COLUMNS
        if column
        not in {
            "ts",
            "received_at",
            "ingest_id",
            "ingest_seq",
            "schema_version",
            "vt_symbol",
            "symbol",
            "exchange",
            "gateway_name",
            "name",
            "trading_day",
            "action_day",
        }
    },
}
_MARKET_TICKS_TABLE_SCHEMA_SQL = (
    "SELECT designatedTimestamp, dedup, dedupKeyColumns "
    "FROM tables() WHERE tableName = 'market_ticks'"
)
_MARKET_TICKS_COLUMN_SCHEMA_SQL = (
    "SELECT column, type FROM table_columns('market_ticks')"
)


def _dedup_key_columns(value: object) -> tuple[str, ...]:
    return tuple(
        part.strip().strip("\"'")
        for part in str(value or "").strip("[]() ").split(",")
        if part.strip()
    )


def verify_market_ticks_schema(connection: Any) -> None:
    """Fail closed unless the externally bootstrapped v3 table is exact enough.

    These are fixed metadata SELECTs.  The worker intentionally never creates,
    alters, or repairs the table.
    """

    with connection.cursor() as cursor:
        cursor.execute(_MARKET_TICKS_TABLE_SCHEMA_SQL)
        table = cursor.fetchone()
        if not isinstance(table, tuple) or len(table) != 3:
            raise DurableStateError("market_ticks table metadata is unavailable")
        timestamp, dedup, keys = table
        cursor.execute(_MARKET_TICKS_COLUMN_SCHEMA_SQL)
        columns = cursor.fetchall()
    normalized = {
        str(name): str(data_type).upper().split("(", 1)[0].strip()
        for name, data_type in columns
    }
    missing = {
        name: expected
        for name, expected in MARKET_TICK_SCHEMA_TYPES.items()
        if normalized.get(name) != expected
    }
    if (
        str(timestamp) != "ts"
        or str(dedup).lower() not in {"true", "1"}
        or _dedup_key_columns(keys) != ("ts", "ingest_id")
        or missing
    ):
        raise DurableStateError("market_ticks prebuilt schema contract is invalid")


class _SafeTickData:
    """State-only target for a trusted vn.py ``TickData`` pickle global."""


class _SafeExchange(str):
    """A value-only replacement for vn.py's ``Exchange`` enum."""

    def __new__(cls, value: str) -> Self:
        return super().__new__(cls, str(value))


_PICKLE_GLOBALS: dict[tuple[str, str], object] = {
    ("vnpy.trader.object", "TickData"): _SafeTickData,
    ("vnpy.trader.constant", "Exchange"): _SafeExchange,
    ("datetime", "datetime"): datetime,
    ("datetime", "date"): date,
    ("datetime", "time"): time,
    ("datetime", "timedelta"): timedelta,
    ("datetime", "timezone"): timezone,
    ("builtins", "str"): str,
    ("builtins", "bytes"): bytes,
    ("builtins", "int"): int,
    ("builtins", "float"): float,
    ("builtins", "bool"): bool,
    ("builtins", "tuple"): tuple,
    ("builtins", "list"): list,
    ("builtins", "dict"): dict,
    ("builtins", "set"): set,
    ("builtins", "frozenset"): frozenset,
}


class _RestrictedTickUnpickler(pickle.Unpickler):
    """Reject arbitrary pickle globals before they can execute code."""

    def find_class(self, module: str, name: str) -> object:
        allowed = _PICKLE_GLOBALS.get((module, name))
        if allowed is None:
            raise pickle.UnpicklingError(f"forbidden pickle global: {module}.{name}")
        return allowed


def restricted_tick_wire_loads(raw: bytes) -> object:
    return _RestrictedTickUnpickler(io.BytesIO(raw)).load()


class _SingleProcessFileLock:
    """Non-blocking process lease for one publish cursor/state directory."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        self._name = self.path.name
        self._fd: int | None = None

    @staticmethod
    def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
        return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)

    def _validate(
        self, descriptor: int, parent_fd: int, expected_parent: os.stat_result
    ) -> None:
        info = os.fstat(descriptor)
        named = os.stat(self._name, dir_fd=parent_fd, follow_symlinks=False)
        current_parent = os.fstat(parent_fd)
        if (
            not self._same_inode(current_parent, expected_parent)
            or stat.S_ISLNK(named.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or named.st_uid != os.geteuid()
            or named.st_mode & 0o077
            or named.st_nlink != 1
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or not self._same_inode(named, info)
        ):
            raise DurableStateError("market-data publish source lock is unsafe")

    def acquire(self) -> None:
        if self._fd is not None:
            return
        parent_fd, parent_info = _open_parent(self.path)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if not getattr(os, "O_NOFOLLOW", 0):
            os.close(parent_fd)
            raise DurableStateError(
                "market-data publish source lock requires O_NOFOLLOW"
            )
        flags |= os.O_NOFOLLOW
        fd = -1
        try:
            fd = os.open(self._name, flags, 0o600, dir_fd=parent_fd)
            self._validate(fd, parent_fd, parent_info)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._validate(fd, parent_fd, parent_info)
            self._fd = fd
            fd = -1
        except BlockingIOError as exc:
            raise DurableStateError(
                "market-data publish source is already owned"
            ) from exc
        except OSError as exc:
            raise DurableStateError(
                "market-data publish source lock is unavailable"
            ) from exc
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def verified_tick_to_market_tick_v3(tick: VerifiedTick) -> dict[str, object]:
    """Map only the verified-tick contract to the pre-created v3 schema.

    ``VerifiedTick`` deliberately carries L1 prices/volumes only.  Every v3
    field with no exact contract counterpart stays ``None``: the worker must
    never manufacture L2-L5, turnover, trading-day, or gateway metadata.
    """

    symbol, separator, exchange = tick.vt_symbol.rpartition(".")
    if not separator:
        symbol, exchange = tick.vt_symbol, None
    row = {column: None for column in MARKET_TICK_COLUMNS}
    row.update(
        {
            "ts": tick.event_time_utc,
            "received_at": tick.received_at_utc,
            "ingest_id": tick.ingest_id,
            "ingest_seq": tick.ingest_seq,
            "schema_version": 3,
            "vt_symbol": tick.vt_symbol,
            "symbol": symbol,
            "exchange": exchange,
            "last_price": tick.last_price,
            "last_volume": tick.last_volume,
            "bid_price_1": tick.bid_price,
            "ask_price_1": tick.ask_price,
            "bid_volume_1": tick.bid_volume,
            "ask_volume_1": tick.ask_volume,
        }
    )
    return row


class ZmqPublishTickSource:
    """A SUB-only adapter for the trusted RpcClient PUB ``(topic, TickData)`` wire."""

    def __init__(
        self,
        endpoint: str,
        *,
        state_dir: Path,
        source_generation: str,
        source_service: str = "gateway-publish-proxy",
        context: Any | None = None,
        zmq_module: Any | None = None,
    ) -> None:
        self.endpoint = str(endpoint).strip()
        if not self.endpoint:
            raise ValueError("market-data publish endpoint is required")
        self._zmq = zmq_module or zmq
        if self._zmq is None:
            raise RuntimeError("pyzmq is required for market-data ingress")
        self._context = context or self._zmq.Context.instance()
        self.source_generation = str(source_generation).strip()
        self.source_service = str(source_service).strip()
        if not self.source_generation or not self.source_service:
            raise ValueError("market-data source identity is required")
        self._cursor = AtomicCheckpoint(
            Path(state_dir) / "publish_proxy_cursor.json",
            default={
                "source_generation": self.source_generation,
                "last_source_seq": 0,
            },
        )
        self._process_lock = _SingleProcessFileLock(
            Path(state_dir) / "publish_proxy_source.lock"
        )
        self._sequence_lock = threading.RLock()
        self._socket: Any | None = None
        self._callback: Callable[[Mapping[str, object]], None] | None = None

    def subscribe(self, callback: Callable[[Mapping[str, object]], None]) -> None:
        self._process_lock.acquire()
        try:
            self._callback = callback
            self._connect()
        except Exception:
            self._callback = None
            self._process_lock.release()
            raise

    def _connect(self) -> None:
        if self._socket is not None:
            return
        socket = self._context.socket(self._zmq.SUB)
        socket.setsockopt(self._zmq.SUBSCRIBE, b"")
        socket.connect(self.endpoint)
        self._socket = socket

    def _reset(self) -> None:
        socket, self._socket = self._socket, None
        if socket is not None:
            socket.close(linger=0)

    def _next_source_seq(self) -> int:
        with self._sequence_lock:
            prior = self._cursor.read()
            if (
                str(prior.get("source_generation") or self.source_generation)
                != self.source_generation
            ):
                raise GenerationMismatch("publish source generation changed")
            sequence = int(prior.get("last_source_seq") or 0) + 1
            self._cursor.write(
                {
                    "source_generation": self.source_generation,
                    "last_source_seq": sequence,
                }
            )
            return sequence

    @staticmethod
    def _tick_payload(value: object) -> dict[str, object]:
        """Select only tick fields from a decoded vn.py object.

        The adapter deliberately does not pass through ``__dict__``.  This
        means a future/order/account object decoded from the same private PUB
        channel cannot acquire ingress authority through incidental fields.
        """

        def field(name: str) -> object | None:
            return (
                value.get(name)
                if isinstance(value, Mapping)
                else getattr(value, name, None)
            )

        payload = {
            "vt_symbol": field("vt_symbol"),
            "symbol": field("symbol"),
            "exchange": field("exchange"),
            "datetime": field("datetime"),
            "last_price": field("last_price"),
            "last_volume": field("last_volume"),
            "bid_price": field("bid_price_1"),
            "ask_price": field("ask_price_1"),
            "bid_volume": field("bid_volume_1"),
            "ask_volume": field("ask_volume_1"),
        }
        if not str(payload["vt_symbol"] or "").strip():
            symbol = str(payload["symbol"] or "").strip()
            exchange = str(payload["exchange"] or "").strip()
            payload["vt_symbol"] = (
                f"{symbol}.{exchange}" if symbol and exchange else symbol
            )
        if not str(payload["vt_symbol"] or "").strip():
            raise TypeError("market-data publish message is not a TickData payload")
        return {key: item for key, item in payload.items() if item is not None}

    def _decode_wire(self, wire: object) -> GatewayTickEnvelope:
        if not isinstance(wire, (list, tuple)) or len(wire) != 2:
            raise TypeError("market-data publish wire must be (topic, TickData)")
        topic, data = wire
        if not isinstance(topic, (str, bytes)):
            raise TypeError("market-data publish topic is invalid")
        topic_text = (
            topic.decode("utf-8", "replace") if isinstance(topic, bytes) else topic
        )
        if topic_text != "eTick" and not topic_text.startswith("eTick."):
            raise TypeError("market-data publish topic is not a tick topic")
        payload = self._tick_payload(data)
        if topic_text.startswith("eTick."):
            suffix = topic_text.removeprefix("eTick.")
            allowed_topics = {
                str(payload["vt_symbol"]),
                str(payload.get("symbol") or ""),
            }
            if suffix not in allowed_topics:
                raise TypeError("market-data publish topic does not match tick symbol")
        source_seq = self._next_source_seq()
        event_id = sha256_hex(
            {
                "source_generation": self.source_generation,
                "source_seq": source_seq,
                "topic": topic_text,
                "payload": payload,
            }
        )[:32]
        return GatewayTickEnvelope.create(
            event_id=event_id,
            source_service=self.source_service,
            source_generation=self.source_generation,
            source_seq=source_seq,
            payload=payload,
        )

    def poll(self, timeout_ms: int = 0) -> int:
        if self._callback is None:
            raise RuntimeError("market-data source has not been bound")
        self._connect()
        try:
            if not self._socket.poll(max(0, int(timeout_ms))):
                return 0
            value = restricted_tick_wire_loads(self._socket.recv())
        except self._zmq.ZMQError as exc:
            self._reset()
            raise OSError("market-data publish ingress disconnected") from exc
        self._callback(self._decode_wire(value).as_dict())
        return 1

    def close(self) -> None:
        try:
            self._reset()
        finally:
            self._process_lock.release()


class QuestDbTickWriter:
    """Narrow PGWire writer for a schema that is owned/pre-created elsewhere.

    This adapter intentionally has no schema-management API.  Its only SQL is
    INSERT, the small health SELECT, and an explicit test/readback SELECT.
    """

    def __init__(
        self,
        dsn: str,
        *,
        connect: Callable[..., Any] | None = None,
    ) -> None:
        self._dsn = str(dsn).strip()
        if not self._dsn:
            raise ValueError("QuestDB PGWire DSN is required")
        self._connect = connect or self._default_connect
        self._connection: Any | None = None
        self._schema_verified = False
        self._lock = threading.RLock()

    @staticmethod
    def _default_connect(dsn: str) -> Any:
        if psycopg is None:
            raise RuntimeError("psycopg is required for QuestDB tick writes")
        return psycopg.connect(dsn, connect_timeout=5)

    def _open(self) -> Any:
        if self._connection is None or bool(getattr(self._connection, "closed", False)):
            self._connection = self._connect(self._dsn)
            self._schema_verified = False
        return self._connection

    def _ensure_schema(self, connection: Any) -> None:
        if not self._schema_verified:
            verify_market_ticks_schema(connection)
            self._schema_verified = True

    def _drop_connection(self) -> None:
        connection, self._connection = self._connection, None
        self._schema_verified = False
        if connection is not None:
            try:
                connection.close()
            except Exception as close_error:  # noqa: BLE001
                # Closing a poisoned connection is best-effort and credentials
                # or driver details must never be emitted from this worker.
                _ = close_error

    def write_verified_tick(self, tick: VerifiedTick) -> None:
        row = verified_tick_to_market_tick_v3(tick)
        try:
            with self._lock:
                connection = self._open()
                self._ensure_schema(connection)
                with connection.cursor() as cursor:
                    cursor.execute(
                        _MARKET_TICK_INSERT,
                        tuple(row[column] for column in MARKET_TICK_COLUMNS),
                    )
                connection.commit()
        except Exception:
            with self._lock:
                if self._connection is not None:
                    try:
                        self._connection.rollback()
                    except Exception as rollback_error:  # noqa: BLE001
                        _ = rollback_error
                self._drop_connection()
            raise

    def write_tick(self, tick: Mapping[str, object]) -> None:
        self.write_verified_tick(VerifiedTick.from_dict(tick))

    def readback(self, ingest_id: str) -> Mapping[str, object] | None:
        """Read one row for a contract test or post-write verification."""

        with self._lock:
            connection = self._open()
            self._ensure_schema(connection)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT ingest_id, ingest_seq, vt_symbol, ts, received_at "
                    "FROM market_ticks WHERE ingest_id = %s",
                    (str(ingest_id),),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        keys = ("ingest_id", "ingest_seq", "vt_symbol", "ts", "received_at")
        return dict(zip(keys, row, strict=True))

    def health(self) -> Mapping[str, object]:
        try:
            with self._lock:
                connection = self._open()
                self._ensure_schema(connection)
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            return {"status": "healthy", "configured": True}
        except Exception as exc:  # noqa: BLE001 - driver exceptions are opaque
            with self._lock:
                self._drop_connection()
            return {
                "status": "degraded",
                "configured": True,
                "error": type(exc).__name__,
            }

    def close(self) -> None:
        with self._lock:
            self._drop_connection()


class JsonlTickWriter:
    """Small idempotent adapter standing in for the QuestDB tick sink."""

    def __init__(self, path: str | Path) -> None:
        self.log = AppendOnlyJsonl(path)
        self._ids: set[str] | None = None
        self._lock = threading.RLock()

    def _load(self) -> set[str]:
        if self._ids is None:
            self._ids = {
                str(row["ingest_id"])
                for row in self.log.records()
                if row.get("ingest_id")
            }
        return self._ids

    def write_tick(self, tick: Mapping[str, object]) -> None:
        ingest_id = str(tick.get("ingest_id") or "")
        if not ingest_id:
            raise ValueError("ingest_id is required")
        with self._lock:
            if ingest_id in self._load():
                return
            self.log.append({"record_type": "questdb_tick", **dict(tick)})
            self._ids.add(ingest_id)

    def write_verified_tick(self, tick: VerifiedTick) -> None:
        self.write_tick(tick.as_dict())

    def health(self) -> Mapping[str, object]:
        return {"status": "healthy", "written_ticks": len(self._load())}


@dataclass(frozen=True)
class MarketDataConfig:
    state_dir: Path
    stream_generation: str = "generation-1"
    queue_maxsize: int = 2048
    source_name: str = "readonly_market_source"
    runtime_mode: str = "disabled"
    projection_dir: Path | None = None
    publish_endpoint: str | None = None
    questdb_pg_dsn: str | None = None

    @classmethod
    def from_environment(cls, state_dir: str | Path | None = None) -> MarketDataConfig:
        projection = os.getenv("PHASE_B_MARKET_PROJECTION_DIR", "").strip()
        dsn = os.getenv("PHASE_B_QUESTDB_PG_DSN", "").strip()
        dsn_file = os.getenv("PHASE_B_QUESTDB_PG_DSN_FILE", "").strip()
        if dsn_file:
            if dsn:
                raise ValueError("set only one QuestDB DSN source")
            dsn = _read_secret_file(Path(dsn_file))
        return cls(
            state_dir=Path(
                state_dir
                or os.getenv(
                    "PHASE_B_MARKET_DATA_STATE_DIR", "/var/lib/phase-b/market-data"
                )
            ),
            stream_generation=os.getenv("PHASE_B_STREAM_GENERATION", "generation-1"),
            queue_maxsize=max(
                1, int(os.getenv("PHASE_B_MARKET_QUEUE_MAXSIZE", "2048"))
            ),
            source_name=os.getenv("PHASE_B_MARKET_SOURCE", "readonly_market_source"),
            runtime_mode=os.getenv("PHASE_B_RUNTIME_MODE", "disabled"),
            projection_dir=Path(projection) if projection else None,
            publish_endpoint=(
                os.getenv("PHASE_B_MARKET_PUBLISH_ENDPOINT", "").strip() or None
            ),
            questdb_pg_dsn=dsn or None,
        )


def _read_secret_file(path: Path) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("QuestDB DSN file is not a regular file")
    if info.st_mode & 0o077:
        raise ValueError("QuestDB DSN file permissions are too broad")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("QuestDB DSN file is empty")
    return value


class MarketDataWorker:
    service_id = "market-data-worker"

    def __init__(
        self,
        config: MarketDataConfig | str | Path,
        *,
        generation: str | None = None,
        source: ReadonlyTickSource | None = None,
        writer: TickWriter | None = None,
        queue_size: int | None = None,
        identity: WorkerIdentity | None = None,
    ) -> None:
        if not isinstance(config, MarketDataConfig):
            config = MarketDataConfig(
                Path(config), generation or "generation-1", queue_size or 2048
            )
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True)
        info = config.state_dir.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise DurableStateError(
                "market-data state directory is not a real directory"
            )
        os.chmod(config.state_dir, 0o700)
        self.identity = identity or WorkerIdentity.from_environment(
            self.service_id, runtime_mode=config.runtime_mode
        )
        self.stream = DurableVerifiedTickStream(
            config.state_dir / "stream", generation=config.stream_generation
        )
        self.source_fence = AtomicCheckpoint(
            config.state_dir / "source_fence.json",
            default={"worker_generation": config.stream_generation, "sources": {}},
        )
        self.writer = writer or (
            QuestDbTickWriter(config.questdb_pg_dsn)
            if config.questdb_pg_dsn
            else JsonlTickWriter(config.state_dir / "persisted_ticks.jsonl")
        )
        self.ingress: BoundedIngressQueue[
            Mapping[str, object] | GatewayTickEnvelope
        ] = BoundedIngressQueue(config.queue_maxsize)
        self.source = source or (
            ZmqPublishTickSource(
                config.publish_endpoint,
                state_dir=config.state_dir,
                source_generation=config.stream_generation,
            )
            if config.publish_endpoint
            else None
        )
        self._source_bound = False
        self._last_error: str | None = None
        self._state_recovered = False
        self.metrics = WorkerMetrics(
            self.service_id, isoformat(), worker_generation=config.stream_generation
        )

    def recover(self) -> None:
        self._state_recovered = False
        try:
            # The producer owns stream initialization.  Consumers only start
            # after this durable layout has been exposed by a ready producer.
            self.stream.initialize()
            self.stream.stats()
            state = self.source_fence.read()
            if (
                str(state.get("worker_generation") or self.config.stream_generation)
                != self.config.stream_generation
            ):
                raise GenerationMismatch(
                    "market-data generation changed without a new state directory"
                )
            writer_health = getattr(self.writer, "health", None)
            if callable(writer_health):
                status = str(dict(writer_health()).get("status") or "")
                if status not in {"healthy", "disabled"}:
                    raise OSError("market-data tick writer is unavailable")
        except Exception as exc:
            self._last_error = type(exc).__name__
            raise
        else:
            self._state_recovered = True
            self._last_error = None

    def bind_source(self) -> None:
        if self.source is not None and not self._source_bound:
            self.source.subscribe(self.accept)
            self._source_bound = True

    def enqueue(self, raw: Mapping[str, object]) -> None:
        try:
            self.ingress.put(dict(raw))
        except BackpressureError:
            self.metrics.increment("backpressure_total")
            raise
        self.metrics.increment("received_total")
        self.metrics.queue_depth = self.ingress.qsize()

    def accept(self, value: GatewayTickEnvelope | Mapping[str, object]) -> None:
        # Re-run the full ingress validator even for an already constructed
        # envelope; callers must not be able to bypass capability/hash/order
        # field checks by handing us a forged dataclass instance.
        envelope = GatewayTickEnvelope.from_dict(
            value.as_dict() if isinstance(value, GatewayTickEnvelope) else value
        )
        try:
            self.ingress.put(envelope)
        except BackpressureError:
            self.metrics.increment("backpressure_total")
            raise
        self.metrics.increment("ingress_accepted")
        self.metrics.queue_depth = self.ingress.qsize()

    def _assert_source_fence(self, event: GatewayTickEnvelope) -> None:
        state = self.source_fence.read()
        sources = dict(state.get("sources") or {})
        events = dict(state.get("events") or {})
        prior_event = events.get(event.event_id)
        if isinstance(prior_event, Mapping) and (
            prior_event.get("generation") != event.source_generation
            or int(prior_event.get("seq") or 0) != event.source_seq
            or prior_event.get("event_hash") != event.envelope_hash
        ):
            raise DurableStateError("source_event_id was reused with different content")
        prior = dict(sources.get(event.source_service) or {})
        old_generation = str(prior.get("generation") or event.source_generation)
        old_seq = int(prior.get("seq") or 0)
        if old_generation != event.source_generation:
            raise GenerationMismatch(
                "source generation changed; rotate the stream explicitly"
            )
        if event.source_seq < old_seq:
            raise DurableStateError("stale source sequence")
        if (
            event.source_seq == old_seq
            and old_seq
            and prior.get("event_hash") != event.envelope_hash
        ):
            raise DurableStateError("source sequence was reused with different content")

    def _record_source_fence(self, event: GatewayTickEnvelope) -> None:
        """Durably bind ingress identity before any fallible sink write.

        A crash after the verified stream append must not permit the same
        source event id to be replayed with altered envelope metadata.
        """

        state = self.source_fence.read()
        sources = dict(state.get("sources") or {})
        events = dict(state.get("events") or {})
        sources[event.source_service] = {
            "generation": event.source_generation,
            "seq": event.source_seq,
            "event_hash": event.envelope_hash,
        }
        events[event.event_id] = {
            "generation": event.source_generation,
            "seq": event.source_seq,
            "event_hash": event.envelope_hash,
        }
        self.source_fence.write(
            {
                "worker_generation": self.config.stream_generation,
                "sources": sources,
                "events": events,
            }
        )

    def _write(self, tick: VerifiedTick) -> None:
        if self.stream.is_acknowledged(tick):
            return
        readback = getattr(self.writer, "readback", None)
        persisted = readback(tick.ingest_id) if callable(readback) else None
        if persisted is not None:
            if (
                str(persisted.get("ingest_id") or "") != tick.ingest_id
                or int(persisted.get("ingest_seq") or 0) != tick.ingest_seq
                or str(persisted.get("vt_symbol") or "") != tick.vt_symbol
            ):
                raise DurableStateError("QuestDB readback does not match verified tick")
            self.stream.acknowledge_tick_write(tick)
            self.metrics.increment("ticks_persisted")
            self.metrics.last_success_at_utc = isoformat()
            return
        fn = getattr(self.writer, "write_verified_tick", None)
        if callable(fn):
            fn(tick)
        else:
            self.writer.write_tick(tick.as_dict())
        self.stream.acknowledge_tick_write(tick)
        self.metrics.increment("ticks_persisted")
        self.metrics.last_success_at_utc = isoformat()

    def ingest(self, raw: Mapping[str, object]) -> VerifiedTick:
        event_id = str(
            raw.get("source_event_id") or raw.get("event_id") or raw.get("id") or ""
        ).strip()
        candidate = VerifiedTick.from_raw(
            raw,
            stream_generation=self.config.stream_generation,
            ingest_seq=self.stream.next_sequence(),
            source=self.config.source_name,
        )
        existing = self.stream.find_by_source_event_id(event_id) if event_id else None
        if existing is None:
            existing = self.stream.find_by_raw_hash(candidate.raw_hash)
        if existing is not None:
            self.metrics.increment("ticks_deduplicated")
            replay = VerifiedTick.from_raw(
                raw,
                stream_generation=self.config.stream_generation,
                ingest_seq=existing.ingest_seq,
                source=self.config.source_name,
            )
            if replay.raw_hash != existing.raw_hash:
                raise DurableStateError(
                    "source_event_id was reused with different tick content"
                )
            try:
                self._write(existing)
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise
            self.metrics.checkpoint_or_watermark = existing.ingest_seq
            return existing
        tick = candidate
        self.stream.append(tick)
        self.metrics.increment("ticks_durable")
        try:
            self._write(tick)
        except Exception as exc:
            self._last_error = type(exc).__name__
            raise
        self.metrics.checkpoint_or_watermark = tick.ingest_seq
        self._last_error = None
        return tick

    def _process_envelope(self, event: GatewayTickEnvelope) -> VerifiedTick:
        self._assert_source_fence(event)
        raw = {**dict(event.payload), "source_event_id": event.event_id}
        candidate = VerifiedTick.from_raw(
            raw,
            stream_generation=self.config.stream_generation,
            ingest_seq=self.stream.next_sequence(),
            source=event.source_service,
        )
        tick = self.stream.find_by_source_event_id(event.event_id)
        if tick is None:
            tick = self.stream.find_by_raw_hash(candidate.raw_hash)
        if tick is None:
            tick = candidate
            self.stream.append(tick)
            self.metrics.increment("ticks_durable")
        else:
            self.metrics.increment("ticks_deduplicated")
            candidate = VerifiedTick.from_raw(
                raw,
                stream_generation=self.config.stream_generation,
                ingest_seq=tick.ingest_seq,
                source=event.source_service,
            )
            if candidate.raw_hash != tick.raw_hash:
                raise DurableStateError(
                    "source_event_id was reused with different tick content"
                )
        self._record_source_fence(event)
        self._write(tick)
        self.metrics.checkpoint_or_watermark = tick.ingest_seq
        self._last_error = None
        return tick

    def process_one(self) -> VerifiedTick:
        value = self.ingress.get()
        self.metrics.queue_depth = self.ingress.qsize()
        return (
            self._process_envelope(value)
            if isinstance(value, GatewayTickEnvelope)
            else self.ingest(value)
        )

    def process_queue(self, *, limit: int | None = None) -> int:
        processed = 0
        while limit is None or processed < limit:
            try:
                self.process_one()
            except Exception as exc:
                if type(exc).__name__ == "Empty":
                    break
                raise
            processed += 1
        return processed

    def replay_pending(self) -> int:
        recovered = 0
        for tick in self.stream.pending_for_tick_writer():
            self._write(tick)
            recovered += 1
        if recovered:
            self._last_error = None
        return recovered

    replay_pending_writes = replay_pending

    def run(
        self, *, stop_event: threading.Event | None = None, idle_seconds: float = 0.1
    ) -> None:
        self.recover()
        stop_event = stop_event or threading.Event()
        try:
            self.replay_pending()
            self.bind_source()
            self.publish_projection()
            while not stop_event.is_set():
                try:
                    poll = getattr(self.source, "poll", None)
                    if callable(poll):
                        poll(max(0, int(float(idle_seconds) * 1000)))
                    self.process_queue()
                except Exception as exc:  # noqa: BLE001
                    self._last_error = type(exc).__name__
                self.publish_projection()
                stop_event.wait(max(0.01, float(idle_seconds)))
        finally:
            close_source = getattr(self.source, "close", None)
            if callable(close_source):
                close_source()
            close_writer = getattr(self.writer, "close", None)
            if callable(close_writer):
                close_writer()

    def health(self) -> HealthSnapshot:
        writer_health = getattr(self.writer, "health", None)
        return HealthSnapshot(
            self.service_id,
            "healthy" if not self._last_error else "degraded",
            isoformat(),
            self.metrics.started_at_utc,
            {
                "verified_stream": self.stream.stats(),
                "tick_writer": writer_health()
                if callable(writer_health)
                else {"status": "configured"},
            },
            self._last_error,
        )

    def readiness(self) -> ReadinessSnapshot:
        blockers: list[str] = []
        if not self._state_recovered or self._last_error:
            blockers.append("writer_recovery_required")
        return ReadinessSnapshot(
            self.service_id,
            not blockers,
            isoformat(),
            CONTRACT_VERSION in self.identity.contract_versions,
            True,
            not bool(blockers),
            self._state_recovered and not bool(self._last_error),
            tuple(blockers),
        )

    def metrics_snapshot(self) -> dict[str, object]:
        self.metrics.queue_depth = self.ingress.qsize()
        self.metrics.checkpoint_or_watermark = self.stream.stats().get(
            "last_ingest_seq", 0
        )
        return self.metrics.as_dict()

    def version(self) -> dict[str, object]:
        return self.identity.as_dict()

    def publish_projection(self) -> None:
        publish_projection(
            self.config.projection_dir,
            build_projection(
                service_id=self.service_id,
                generation=self.identity.source_revision
                + ":"
                + self.config.stream_generation,
                health=self.health(),
                readiness=self.readiness(),
                version=self.identity,
            ),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase B market-data worker")
    parser.add_argument("--state-dir")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", action="store_true")
    group.add_argument("--health", action="store_true")
    group.add_argument("--ready", action="store_true")
    group.add_argument("--metrics", action="store_true")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    worker = MarketDataWorker(MarketDataConfig.from_environment(args.state_dir))
    if args.version:
        value = worker.version()
    elif args.ready:
        try:
            worker.recover()
        except Exception as exc:  # noqa: BLE001 - readiness reports a fail-closed snapshot
            worker._last_error = type(exc).__name__
        value = worker.readiness().as_dict()
    elif args.metrics:
        value = worker.metrics_snapshot()
    elif args.run:
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: stop.set())
        worker.run(
            stop_event=stop,
            idle_seconds=float(os.getenv("PHASE_B_MARKET_IDLE_SECONDS", "0.1")),
        )
        return 0
    else:
        value = worker.health().as_dict()
    worker.publish_projection()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0 if not args.ready or bool(value.get("ready")) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
