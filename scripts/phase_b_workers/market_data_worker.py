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
import time as monotonic_time
from collections import deque
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
        parse_time,
        sha256_hex,
    )
    from .durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableCorruptionError,
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
        parse_time,
        sha256_hex,
    )
    from phase_b_workers.durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableCorruptionError,
        DurableStateError,
        DurableVerifiedTickStream,
        GenerationMismatch,
        _open_parent,
    )
    from phase_b_workers.projections import build_projection, publish_projection


class ReadonlyTickSource(Protocol):
    def subscribe(self, callback: Callable[[Mapping[str, object]], None]) -> None: ...

    def poll(self, timeout_ms: int = 0, *, limit: int = 256) -> int: ...

    def has_backlog(self) -> bool: ...

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
_MARKET_TICK_READBACK = (
    f"SELECT {', '.join(MARKET_TICK_COLUMNS)} FROM market_ticks "
    "WHERE ts = %s AND ingest_id = %s"
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
_MARKET_TICKS_COLUMN_SCHEMA_SQL = (
    "SELECT \"column\", type, upsertKey, designated FROM table_columns('market_ticks')"
)


def verify_market_ticks_schema(connection: Any) -> None:
    """Fail closed unless the externally bootstrapped v3 table is exact enough.

    These are fixed metadata SELECTs.  The worker intentionally never creates,
    alters, or repairs the table.
    """

    with connection.cursor() as cursor:
        cursor.execute(_MARKET_TICKS_COLUMN_SCHEMA_SQL)
        columns = cursor.fetchall()
    normalized: dict[str, str] = {}
    upsert_keys: list[str] = []
    designated: list[str] = []
    for row in columns:
        if not isinstance(row, tuple) or len(row) != 4:
            raise DurableStateError("market_ticks column metadata is invalid")
        name, data_type, upsert_key, timestamp = row
        column = str(name)
        normalized[column] = str(data_type).upper().split("(", 1)[0].strip()
        if bool(upsert_key):
            upsert_keys.append(column)
        if bool(timestamp):
            designated.append(column)
    missing = {
        name: expected
        for name, expected in MARKET_TICK_SCHEMA_TYPES.items()
        if normalized.get(name) != expected
    }
    if (
        tuple(designated) != ("ts",)
        or tuple(upsert_keys) != ("ts", "ingest_id")
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


def _market_tick_row_matches(tick: VerifiedTick, actual: Mapping[str, object]) -> bool:
    expected = verified_tick_to_market_tick_v3(tick)
    # v3 has no separate source_event_id column.  The only source-event
    # binding it can prove is the contract invariant ingest_id == source id.
    if tick.source_event_id and tick.ingest_id != tick.source_event_id:
        return False
    for column, value in expected.items():
        observed = actual.get(column)
        if value is None:
            if observed is not None:
                return False
        elif column in {"ts", "received_at"}:
            try:
                if isoformat(parse_time(observed)) != isoformat(parse_time(value)):
                    return False
            except (TypeError, ValueError):
                return False
        elif isinstance(value, float):
            try:
                if float(observed) != value:
                    return False
            except (TypeError, ValueError):
                return False
        elif observed != value:
            return False
    return True


class ZmqPublishTickSource:
    """A SUB-only adapter for the trusted RpcClient PUB ``(topic, TickData)`` wire."""

    # Keep one receive pass below the normal ingress capacity.  The run loop
    # drains/processes this bounded slice before receiving again, so a socket
    # burst cannot silently consume beyond durable ingress backpressure.
    DEFAULT_DRAIN_LIMIT = 256

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
        if not topic_text.startswith("eTick."):
            raise TypeError("market-data publish topic is not a tick topic")
        payload = self._tick_payload(data)
        suffix = topic_text.removeprefix("eTick.")
        if suffix != str(payload["vt_symbol"]):
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

    def has_backlog(self) -> bool:
        """Return whether the subscribed socket already has another message."""

        self._connect()
        try:
            return bool(self._socket.poll(0))
        except self._zmq.ZMQError as exc:
            self._reset()
            raise OSError("market-data publish ingress disconnected") from exc

    def poll(self, timeout_ms: int = 0, *, limit: int = DEFAULT_DRAIN_LIMIT) -> int:
        if self._callback is None:
            raise RuntimeError("market-data source has not been bound")
        if int(limit) < 1:
            raise ValueError("market-data publish drain limit must be positive")
        self._connect()
        received = 0
        try:
            if not self._socket.poll(max(0, int(timeout_ms))):
                return 0
            while received < int(limit):
                value = restricted_tick_wire_loads(self._socket.recv())
                self._callback(self._decode_wire(value).as_dict())
                received += 1
                if received >= int(limit) or not self._socket.poll(0):
                    break
        except self._zmq.ZMQError as exc:
            self._reset()
            raise OSError("market-data publish ingress disconnected") from exc
        return received

    def close(self) -> None:
        try:
            self._reset()
        finally:
            self._process_lock.release()


class ZmqTickWireSourceV1:
    """SUB-only reader for the fixed tick-only ``eTick.v1`` JSON wire.

    Unlike :class:`ZmqPublishTickSource`, this reader never receives the
    legacy RPC 4102 object stream and has no pickle decoder in its path.
    """

    DEFAULT_DRAIN_LIMIT = 256

    def __init__(
        self,
        endpoint: str,
        *,
        state_dir: Path,
        source_generation: str,
        source_service: str = "windows-tick-wire-v1",
        context: Any | None = None,
        zmq_module: Any | None = None,
    ) -> None:
        from scripts.windows_tick_wire_v1 import TICK_WIRE_PREFIX

        self.endpoint = str(endpoint).strip()
        if not self.endpoint:
            raise ValueError("market-data tick wire endpoint is required")
        self._zmq = zmq_module or zmq
        if self._zmq is None:
            raise RuntimeError("pyzmq is required for market-data ingress")
        self._context = context or self._zmq.Context.instance()
        self.source_generation = str(source_generation).strip()
        self.source_service = str(source_service).strip()
        if not self.source_generation or not self.source_service:
            raise ValueError("market-data source identity is required")
        self._topic_prefix = TICK_WIRE_PREFIX.encode("ascii")
        self._cursor = AtomicCheckpoint(
            Path(state_dir) / "tick_wire_v1_cursor.json",
            default={"source_generation": self.source_generation, "last_source_seq": 0},
        )
        self._process_lock = _SingleProcessFileLock(Path(state_dir) / "tick_wire_v1_source.lock")
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
        if self._socket is None:
            socket = self._context.socket(self._zmq.SUB)
            socket.setsockopt(self._zmq.SUBSCRIBE, self._topic_prefix)
            socket.connect(self.endpoint)
            self._socket = socket

    def _reset(self) -> None:
        socket, self._socket = self._socket, None
        if socket is not None:
            socket.close(linger=0)

    def _next_source_seq(self) -> int:
        with self._sequence_lock:
            prior = self._cursor.read()
            if str(prior.get("source_generation") or self.source_generation) != self.source_generation:
                raise GenerationMismatch("tick wire source generation changed")
            sequence = int(prior.get("last_source_seq") or 0) + 1
            self._cursor.write({"source_generation": self.source_generation, "last_source_seq": sequence})
            return sequence

    def _decode_frames(self, frames: Any) -> GatewayTickEnvelope:
        from scripts.windows_tick_wire_v1 import TickWireError, decode_tick_wire_v1

        if not isinstance(frames, (list, tuple)) or len(frames) != 2:
            raise TypeError("tick wire must contain exactly two frames")
        topic, raw = frames
        try:
            payload = decode_tick_wire_v1(topic, raw)
        except TickWireError as exc:
            raise TypeError(f"tick wire rejected: {exc}") from exc
        sequence = self._next_source_seq()
        event_id = sha256_hex(
            {"source_generation": self.source_generation, "source_seq": sequence, "topic": topic.decode("ascii"), "payload": payload}
        )[:32]
        return GatewayTickEnvelope.create(
            event_id=event_id,
            source_service=self.source_service,
            source_generation=self.source_generation,
            source_seq=sequence,
            payload=payload,
        )

    def has_backlog(self) -> bool:
        self._connect()
        try:
            return bool(self._socket.poll(0))
        except self._zmq.ZMQError as exc:
            self._reset()
            raise OSError("market-data tick wire disconnected") from exc

    def poll(self, timeout_ms: int = 0, *, limit: int = DEFAULT_DRAIN_LIMIT) -> int:
        if self._callback is None:
            raise RuntimeError("market-data source has not been bound")
        if int(limit) < 1:
            raise ValueError("market-data tick wire drain limit must be positive")
        self._connect()
        received = 0
        try:
            if not self._socket.poll(max(0, int(timeout_ms))):
                return 0
            while received < int(limit):
                self._callback(self._decode_frames(self._socket.recv_multipart()).as_dict())
                received += 1
                if received >= int(limit) or not self._socket.poll(0):
                    break
        except self._zmq.ZMQError as exc:
            self._reset()
            raise OSError("market-data tick wire disconnected") from exc
        return received

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
        self.write_verified_ticks((tick,))

    def write_verified_ticks(self, ticks: tuple[VerifiedTick, ...] | list[VerifiedTick]) -> None:
        """Commit a bounded, already-durable tick batch as one transaction."""

        values = tuple(ticks)
        if not values:
            return
        try:
            with self._lock:
                connection = self._open()
                self._ensure_schema(connection)
                with connection.cursor() as cursor:
                    cursor.executemany(
                        _MARKET_TICK_INSERT,
                        [
                            tuple(
                                verified_tick_to_market_tick_v3(tick)[column]
                                for column in MARKET_TICK_COLUMNS
                            )
                            for tick in values
                        ],
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

    def readback(self, tick: VerifiedTick) -> Mapping[str, object] | None:
        """Read one row for a contract test or post-write verification."""

        with self._lock:
            connection = self._open()
            self._ensure_schema(connection)
            with connection.cursor() as cursor:
                cursor.execute(
                    _MARKET_TICK_READBACK,
                    (verified_tick_to_market_tick_v3(tick)["ts"], tick.ingest_id),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        return dict(zip(MARKET_TICK_COLUMNS, row, strict=True))

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
    SOURCE_DRAIN_LIMIT = ZmqPublishTickSource.DEFAULT_DRAIN_LIMIT
    _SOURCE_FENCE_EVENT_LIMIT = 4096
    _DETERMINISTIC_SOURCE_SERVICES = frozenset(
        {"gateway-publish-proxy", "windows-tick-wire-v1"}
    )
    _PROJECTION_INTERVAL_SECONDS = 1.0
    QUESTDB_BATCH_MAX_SIZE = 64
    QUESTDB_BATCH_MAX_WAIT_SECONDS = 0.05
    _BATCH_SAMPLE_LIMIT = 256

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
        self._source_fence_state: dict[str, object] | None = None
        self.writer = writer or (
            QuestDbTickWriter(config.questdb_pg_dsn)
            if config.questdb_pg_dsn
            else JsonlTickWriter(config.state_dir / "persisted_ticks.jsonl")
        )
        self.ingress: BoundedIngressQueue[
            Mapping[str, object] | GatewayTickEnvelope
        ] = BoundedIngressQueue(config.queue_maxsize)
        self.source = source or (
            ZmqTickWireSourceV1(
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
        self._next_projection_monotonic = 0.0
        self._questdb_batch_sizes: deque[int] = deque(maxlen=self._BATCH_SAMPLE_LIMIT)
        self._questdb_commit_latencies_ms: deque[float] = deque(
            maxlen=self._BATCH_SAMPLE_LIMIT
        )
        self._questdb_pending: dict[str, VerifiedTick] = {}
        self._questdb_batch_started_monotonic: float | None = None
        self._questdb_pending_committed = False
        self._durable_ingress_started_monotonic: float | None = None
        self._finalize_recovered_ticks: tuple[VerifiedTick, ...] = ()
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
            if not isinstance(state.get("sources") or {}, Mapping) or not isinstance(
                state.get("events") or {}, Mapping
            ):
                raise DurableStateError("market-data source fence state is invalid")
            if len(dict(state.get("events") or {})) > self._SOURCE_FENCE_EVENT_LIMIT:
                raise BackpressureError("source fence identity capacity exhausted")
            self._source_fence_state = dict(state)
            self._recover_prepared_source_fence()
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

    def _assert_source_fence(
        self,
        event: GatewayTickEnvelope,
        *,
        state: Mapping[str, object] | None = None,
    ) -> None:
        state = state if state is not None else self._source_fence_state
        if state is None:
            raise DurableStateError("market-data source fence recovery is required")
        sources = dict(state.get("sources") or {})
        events = dict(state.get("events") or {})
        deterministic = event.source_service in self._DETERMINISTIC_SOURCE_SERVICES
        if deterministic:
            expected_event_id = sha256_hex(
                {
                    "source_generation": event.source_generation,
                    "source_seq": event.source_seq,
                    "topic": (
                        f"eTick.v1.{event.payload.get('vt_symbol')}"
                        if event.source_service == "windows-tick-wire-v1"
                        else f"eTick.{event.payload.get('vt_symbol')}"
                    ),
                    "payload": dict(event.payload),
                }
            )[:32]
            if event.event_id != expected_event_id:
                raise DurableStateError("deterministic source event identity mismatch")
        prior_event = events.get(event.event_id)
        if isinstance(prior_event, Mapping) and (
            prior_event.get("generation") != event.source_generation
            or int(prior_event.get("seq") or 0) != event.source_seq
            or prior_event.get("event_hash") != event.envelope_hash
        ):
            raise DurableStateError("source_event_id was reused with different content")
        if not deterministic and prior_event is None and len(events) >= self._SOURCE_FENCE_EVENT_LIMIT:
            raise BackpressureError("source fence identity capacity exhausted")
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

    def _next_source_fence_state(
        self, state: Mapping[str, object], event: GatewayTickEnvelope
    ) -> dict[str, object]:
        """Return the compact source frontier after one validated envelope."""

        sources = dict(state.get("sources") or {})
        events = dict(state.get("events") or {})
        deterministic = event.source_service in self._DETERMINISTIC_SOURCE_SERVICES
        if (
            not deterministic
            and event.event_id not in events
            and len(events) >= self._SOURCE_FENCE_EVENT_LIMIT
        ):
            raise BackpressureError("source fence identity capacity exhausted")
        sources[event.source_service] = {
            "generation": event.source_generation,
            "seq": event.source_seq,
            "event_hash": event.envelope_hash,
        }
        if not deterministic:
            events[event.event_id] = {
                "generation": event.source_generation,
                "seq": event.source_seq,
                "event_hash": event.envelope_hash,
            }
        return {
            "worker_generation": self.config.stream_generation,
            "sources": sources,
            "events": events,
        }

    def _record_source_fence(self, event: GatewayTickEnvelope) -> None:
        """Durably bind ingress identity before any fallible sink write.

        A crash after the verified stream append must not permit the same
        source event id to be replayed with altered envelope metadata.
        """

        state = self._source_fence_state
        if state is None:
            raise DurableStateError("market-data source fence recovery is required")
        next_state = self._next_source_fence_state(state, event)
        self.source_fence.write(next_state)
        self._source_fence_state = next_state

    def _recover_prepared_source_fence(self) -> None:
        """Resolve a source-fence intent left around a journal group commit."""

        state = self._source_fence_state
        if state is None:
            raise DurableStateError("market-data source fence recovery is required")
        prepared = state.get("prepared_batch")
        if prepared is None:
            return
        if not isinstance(prepared, Mapping):
            raise DurableCorruptionError("market-data source fence batch is invalid")
        entries = prepared.get("entries")
        final_sources = prepared.get("final_sources")
        final_events = prepared.get("final_events")
        if (
            not isinstance(entries, list)
            or not entries
            or len(entries) > self.QUESTDB_BATCH_MAX_SIZE
            or not isinstance(final_sources, Mapping)
            or not isinstance(final_events, Mapping)
        ):
            raise DurableCorruptionError("market-data source fence batch is invalid")
        present = 0
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise DurableCorruptionError("market-data source fence batch is invalid")
            event_id = str(entry.get("event_id") or "")
            tick_event_id = str(entry.get("tick_event_id") or "")
            raw_hash = str(entry.get("raw_hash") or "")
            if not event_id or not tick_event_id or not raw_hash:
                raise DurableCorruptionError("market-data source fence batch is invalid")
            tick = self.stream.find_by_source_event_id(tick_event_id)
            if tick is None:
                continue
            if tick.raw_hash != raw_hash:
                raise DurableCorruptionError("prepared source fence tick mismatch")
            present += 1
        if present not in {0, len(entries)}:
            raise DurableCorruptionError("prepared source fence batch is partial")
        resolved = {
            "worker_generation": self.config.stream_generation,
            "sources": dict(final_sources if present else state.get("sources") or {}),
            "events": dict(final_events if present else state.get("events") or {}),
        }
        self.source_fence.write(resolved)
        self._source_fence_state = resolved

    def _prepare_source_fence_batch(
        self,
        pairs: list[tuple[GatewayTickEnvelope, VerifiedTick]],
    ) -> tuple[Callable[[], None], Callable[[], None]]:
        """Build a bounded prepare/finalize pair for a durable tick group."""

        state = self._source_fence_state
        if state is None:
            raise DurableStateError("market-data source fence recovery is required")
        if not pairs or len(pairs) > self.QUESTDB_BATCH_MAX_SIZE:
            raise BackpressureError("source fence batch capacity exhausted")
        final_state: Mapping[str, object] = state
        entries: list[dict[str, object]] = []
        for event, tick in pairs:
            self._assert_source_fence(event, state=final_state)
            final_state = self._next_source_fence_state(final_state, event)
            entries.append(
                {
                    "event_id": event.event_id,
                    "tick_event_id": tick.source_event_id,
                    "raw_hash": tick.raw_hash,
                }
            )
        prepared_state = {
            "worker_generation": self.config.stream_generation,
            "sources": dict(state.get("sources") or {}),
            "events": dict(state.get("events") or {}),
            "prepared_batch": {
                "entries": entries,
                "final_sources": dict(final_state.get("sources") or {}),
                "final_events": dict(final_state.get("events") or {}),
            },
        }
        committed_state = dict(final_state)

        def prepare() -> None:
            self.source_fence.write(prepared_state)
            self._source_fence_state = prepared_state

        def finalize() -> None:
            self.source_fence.write(committed_state)
            self._source_fence_state = committed_state

        return prepare, finalize

    def _write(self, tick: VerifiedTick) -> None:
        if self.stream.is_acknowledged(tick):
            return
        readback = getattr(self.writer, "readback", None)
        persisted = readback(tick) if callable(readback) else None
        if persisted is not None:
            if not _market_tick_row_matches(tick, persisted):
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

    def _durably_ingest_batch(
        self, values: list[Mapping[str, object] | GatewayTickEnvelope]
    ) -> list[VerifiedTick]:
        """Stage a bounded ingress group before one verified-journal flush."""

        if not values or len(values) > self.QUESTDB_BATCH_MAX_SIZE:
            raise BackpressureError("market-data durable batch capacity exhausted")
        if (
            self._source_fence_state is not None
            and self._source_fence_state.get("prepared_batch") is not None
        ):
            # A finalize failure after journal durability must be resolved
            # before another source identity can be admitted.
            self._recover_prepared_source_fence()
        next_sequence = self.stream.next_sequence()
        ticks: list[VerifiedTick] = []
        new: list[VerifiedTick] = []
        source_pairs: list[tuple[GatewayTickEnvelope, VerifiedTick]] = []
        staged_by_event_id: dict[str, VerifiedTick] = {}
        staged_by_raw_hash: dict[str, VerifiedTick] = {}
        source_state: Mapping[str, object] | None = self._source_fence_state
        for value in values:
            event = value if isinstance(value, GatewayTickEnvelope) else None
            if event is not None:
                # Validate every source identity before stream content dedupe:
                # altered deterministic replays must fail at the identity
                # fence, and legacy capacity must reject the whole group.
                if source_state is None:
                    raise DurableStateError(
                        "market-data source fence recovery is required"
                    )
                self._assert_source_fence(event, state=source_state)
                source_state = self._next_source_fence_state(source_state, event)
            raw = (
                {**dict(event.payload), "source_event_id": event.event_id}
                if event is not None
                else dict(value)
            )
            source = event.source_service if event is not None else self.config.source_name
            event_id = str(
                raw.get("source_event_id") or raw.get("event_id") or raw.get("id") or ""
            ).strip()
            candidate = VerifiedTick.from_raw(
                raw,
                stream_generation=self.config.stream_generation,
                ingest_seq=next_sequence,
                source=source,
            )
            existing = staged_by_event_id.get(event_id) if event_id else None
            if existing is None:
                existing = staged_by_raw_hash.get(candidate.raw_hash)
            if existing is None:
                existing = self.stream.find_by_source_event_id(event_id) if event_id else None
            if existing is None:
                existing = self.stream.find_by_raw_hash(candidate.raw_hash)
            if existing is not None:
                replay = VerifiedTick.from_raw(
                    raw,
                    stream_generation=self.config.stream_generation,
                    ingest_seq=existing.ingest_seq,
                    source=source,
                )
                if replay.raw_hash != existing.raw_hash:
                    raise DurableStateError(
                        "source_event_id was reused with different tick content"
                    )
                tick = existing
                self.metrics.increment("ticks_deduplicated")
            else:
                tick = candidate
                new.append(tick)
                if event_id:
                    staged_by_event_id[event_id] = tick
                staged_by_raw_hash[candidate.raw_hash] = tick
                next_sequence += 1
            ticks.append(tick)
            if event is not None:
                source_pairs.append((event, tick))
        before_journal = after_journal = None
        if source_pairs and not new:
            # Content-deduplicated ticks do not need a journal intent, but
            # their source frontier still must advance exactly once.
            if source_state is None:  # pragma: no cover - checked above
                raise DurableStateError("market-data source fence recovery is required")
            finalized_state = dict(source_state)
            self.source_fence.write(finalized_state)
            self._source_fence_state = finalized_state
        elif source_pairs:
            before_journal, after_journal = self._prepare_source_fence_batch(source_pairs)
        try:
            appended = self.stream.append_many(
                new,
                before_journal=before_journal,
                after_journal=after_journal,
            )
        except Exception:
            if (
                self._source_fence_state is not None
                and self._source_fence_state.get("prepared_batch") is not None
            ):
                self._recover_prepared_source_fence()
                # The journal/watermark group is durable and its source fence
                # is now finalized.  Do not retry its raw envelopes: hand the
                # exact durable group to the QuestDB pending path instead.
                self._finalize_recovered_ticks = tuple(ticks)
            raise
        self.metrics.increment("ticks_durable", sum(appended))
        self.metrics.checkpoint_or_watermark = ticks[-1].ingest_seq
        self._last_error = None
        return ticks

    def ingest(self, raw: Mapping[str, object], *, persist: bool = True) -> VerifiedTick:
        tick = self._durably_ingest_batch([raw])[0]
        if persist:
            try:
                self._write(tick)
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise
        return tick

    def _process_envelope(
        self, event: GatewayTickEnvelope, *, persist: bool = True
    ) -> VerifiedTick:
        tick = self._durably_ingest_batch([event])[0]
        if persist:
            self._write(tick)
        return tick

    def process_one(self) -> VerifiedTick:
        value = self.ingress.get()
        self.metrics.queue_depth = self.ingress.qsize()
        tick = (
            self._process_envelope(value)
            if isinstance(value, GatewayTickEnvelope)
            else self.ingest(value)
        )
        self.metrics.increment("processed_total")
        return tick

    @staticmethod
    def _percentile(values: tuple[float, ...], percentile: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * percentile))]

    def _record_questdb_batch(
        self, rows: int, *, reason: str, commit_latency_ms: float
    ) -> None:
        self._questdb_batch_sizes.append(rows)
        self._questdb_commit_latencies_ms.append(commit_latency_ms)
        self.metrics.increment("questdb_batches_total")
        self.metrics.increment("questdb_batch_rows_total", rows)
        self.metrics.increment(f"questdb_flush_{reason}_total")

    def _write_questdb_batch(
        self,
        ticks: list[VerifiedTick],
        *,
        reason: str,
        replay: bool = False,
        track_pending_commit: bool = False,
    ) -> None:
        if not ticks:
            return
        writer = self.writer
        if not isinstance(writer, QuestDbTickWriter):  # pragma: no cover - caller guard
            raise TypeError("QuestDB batch requires QuestDbTickWriter")
        pending = [tick for tick in ticks if not self.stream.is_acknowledged(tick)]
        if replay:
            to_write: list[VerifiedTick] = []
            for tick in pending:
                persisted = writer.readback(tick)
                if persisted is None:
                    to_write.append(tick)
                elif not _market_tick_row_matches(tick, persisted):
                    raise DurableStateError("QuestDB readback does not match verified tick")
                else:
                    self.stream.acknowledge_tick_write(tick)
                    self.metrics.increment("ticks_persisted")
            pending = to_write
        if not pending:
            return
        started = monotonic_time.monotonic()
        # A failed execute/executemany/commit raises from the writer after its
        # rollback/drop path.  Nothing below runs, so durable ticks stay pending.
        writer.write_verified_ticks(pending)
        if track_pending_commit:
            # The transaction is known committed.  Keep this fence until
            # every durable ack succeeds so retries never re-run the INSERTs.
            self._questdb_pending_committed = True
        latency_ms = (monotonic_time.monotonic() - started) * 1000
        self._record_questdb_batch(len(pending), reason=reason, commit_latency_ms=latency_ms)
        acknowledgements = self.stream.acknowledge_tick_writes(pending)
        for acknowledged in acknowledgements:
            if acknowledged:
                self.metrics.increment("ticks_persisted")
        self.metrics.last_success_at_utc = isoformat()

    def process_queue(self, *, limit: int | None = None, flush: bool = True) -> int:
        if isinstance(self.writer, QuestDbTickWriter):
            return self._process_questdb_queue(limit=limit, flush=flush)
        processed = 0
        while limit is None or processed < limit:
            try:
                self.process_one()
            except Exception as exc:
                if type(exc).__name__ == "Empty":
                    break
                raise
            processed += 1
            # A durable writer can be slower than the projection heartbeat.
            # Keep publishing through the existing <=1Hz monotonic gate while
            # a long queue drains, without changing sink commit semantics.
            self._publish_projection_if_due()
        return processed

    def _flush_questdb_pending(self, *, reason: str) -> None:
        if not self._questdb_pending:
            return
        pending = list(self._questdb_pending.values())
        if self._questdb_pending_committed:
            acknowledgements = self.stream.acknowledge_tick_writes(pending)
            for acknowledged in acknowledgements:
                if acknowledged:
                    self.metrics.increment("ticks_persisted")
            self.metrics.last_success_at_utc = isoformat()
        else:
            self._write_questdb_batch(
                pending,
                reason=reason,
                track_pending_commit=True,
            )
        self._questdb_pending.clear()
        self._questdb_batch_started_monotonic = None
        self._questdb_pending_committed = False

    def _questdb_batch_due(self) -> bool:
        return bool(self._questdb_pending) and (
            len(self._questdb_pending) >= self.QUESTDB_BATCH_MAX_SIZE
            or (
                self._questdb_batch_started_monotonic is not None
                and monotonic_time.monotonic() - self._questdb_batch_started_monotonic
                >= self.QUESTDB_BATCH_MAX_WAIT_SECONDS
            )
        )

    def _questdb_ingress_due(self) -> bool:
        """Start/observe the bounded raw ingress group used only by run()."""

        depth = self.ingress.qsize()
        if not depth:
            self._durable_ingress_started_monotonic = None
            return False
        now = monotonic_time.monotonic()
        if self._durable_ingress_started_monotonic is None:
            self._durable_ingress_started_monotonic = now
        return depth >= self.QUESTDB_BATCH_MAX_SIZE or (
            now - self._durable_ingress_started_monotonic
            >= self.QUESTDB_BATCH_MAX_WAIT_SECONDS
        )

    def _questdb_ingress_wait_seconds(self) -> float:
        if self._durable_ingress_started_monotonic is None:
            return self.QUESTDB_BATCH_MAX_WAIT_SECONDS
        return max(
            0.0,
            self.QUESTDB_BATCH_MAX_WAIT_SECONDS
            - (monotonic_time.monotonic() - self._durable_ingress_started_monotonic),
        )

    def _process_questdb_queue(self, *, limit: int | None, flush: bool) -> int:
        if self._questdb_pending_committed:
            # Never merge a fresh durable tick into a transaction that has
            # already committed but is still finishing its acknowledgements.
            self._flush_questdb_pending(reason="ack_retry")
        processed = 0
        while limit is None or processed < limit:
            remaining_pending = self.QUESTDB_BATCH_MAX_SIZE - len(
                self._questdb_pending
            )
            if remaining_pending <= 0:
                self._flush_questdb_pending(reason="max_size")
                remaining_pending = self.QUESTDB_BATCH_MAX_SIZE
            values: list[Mapping[str, object] | GatewayTickEnvelope] = []
            batch_limit = min(
                remaining_pending,
                (limit - processed) if limit is not None else self.QUESTDB_BATCH_MAX_SIZE,
            )
            while len(values) < batch_limit:
                try:
                    values.append(self.ingress.get())
                except Exception as exc:
                    if type(exc).__name__ == "Empty":
                        break
                    raise
            if not values:
                break
            self.metrics.queue_depth = self.ingress.qsize()
            try:
                ticks = self._durably_ingest_batch(values)
            except Exception:
                finalized_ticks = self._finalize_recovered_ticks
                self._finalize_recovered_ticks = ()
                if finalized_ticks:
                    for tick in finalized_ticks:
                        if not self._questdb_pending:
                            self._questdb_batch_started_monotonic = (
                                monotonic_time.monotonic()
                            )
                        self._questdb_pending.setdefault(tick.ingest_id, tick)
                        processed += 1
                        self.metrics.increment("processed_total")
                    # Preserve the finalize error for the caller, but the raw
                    # group was consumed exactly once and is retryable via the
                    # normal pending flush on the next worker turn.
                    raise
                # The queue was predrained for group commit.  Commit the
                # valid prefix one by one on this error path, then put the
                # rejected record and untouched tail back in their original
                # order so neither source identity is silently lost.
                prefix: list[VerifiedTick] = []
                failed_at = 0
                for failed_at, value in enumerate(values):
                    try:
                        prefix.extend(self._durably_ingest_batch([value]))
                    except Exception:  # noqa: BLE001 - retain rejected suffix
                        self.ingress.put_front_many(values[failed_at:])
                        break
                else:  # pragma: no cover - batch failure must reproduce
                    raise
                for tick in prefix:
                    if not self._questdb_pending:
                        self._questdb_batch_started_monotonic = monotonic_time.monotonic()
                    self._questdb_pending.setdefault(tick.ingest_id, tick)
                    processed += 1
                    self.metrics.increment("processed_total")
                if self._questdb_pending:
                    self._flush_questdb_pending(reason="processing_error")
                raise
            for tick in ticks:
                if not self._questdb_pending:
                    self._questdb_batch_started_monotonic = monotonic_time.monotonic()
                # Replayed identical market content may resolve to the same
                # durable tick before it has been acknowledged.  Preserve every
                # source-fence transition but write/ack that ingest id once.
                self._questdb_pending.setdefault(tick.ingest_id, tick)
                processed += 1
                self.metrics.increment("processed_total")
            if len(self._questdb_pending) >= self.QUESTDB_BATCH_MAX_SIZE:
                self._flush_questdb_pending(reason="max_size")
            elif self._questdb_batch_due():
                self._flush_questdb_pending(reason="max_wait")
            self._publish_projection_if_due()
        if flush:
            self._flush_questdb_pending(reason="queue_drained")
        return processed

    def replay_pending(self) -> int:
        if isinstance(self.writer, QuestDbTickWriter):
            pending = self.stream.pending_for_tick_writer()
            for offset in range(0, len(pending), self.QUESTDB_BATCH_MAX_SIZE):
                self._write_questdb_batch(
                    pending[offset : offset + self.QUESTDB_BATCH_MAX_SIZE],
                    reason="replay",
                    replay=True,
                )
                self._publish_projection_if_due()
            if pending:
                self._last_error = None
            return len(pending)
        recovered = 0
        for tick in self.stream.pending_for_tick_writer():
            self._write(tick)
            recovered += 1
            # Recovery may replay a large slow-writer backlog before the run
            # loop regains control; retain the same bounded heartbeat here.
            self._publish_projection_if_due()
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
            self._publish_projection_if_due(force=True)
            while not stop_event.is_set():
                if isinstance(self.writer, QuestDbTickWriter):
                    # First drain a known DB batch.  A failed flush is an
                    # explicit degraded/backpressure state: do not poll or
                    # consume another raw ingress item until it succeeds.
                    if self._questdb_batch_due():
                        try:
                            self._flush_questdb_pending(reason="max_wait")
                        except Exception as exc:  # noqa: BLE001
                            self._last_error = type(exc).__name__
                            self.metrics.increment("backpressure_total")
                            self._publish_projection_if_due()
                            stop_event.wait(self.QUESTDB_BATCH_MAX_WAIT_SECONDS)
                            continue

                    # A raw ingress group is journaled only when full or when
                    # its bounded 50ms window expires.  This is intentionally
                    # separate from the already-durable QuestDB pending group.
                    if self._questdb_ingress_due():
                        try:
                            self.process_queue(
                                limit=self.QUESTDB_BATCH_MAX_SIZE, flush=True
                            )
                            self._durable_ingress_started_monotonic = (
                                monotonic_time.monotonic()
                                if self.ingress.qsize()
                                else None
                            )
                        except Exception as exc:  # noqa: BLE001
                            self._last_error = type(exc).__name__
                            self.metrics.increment("backpressure_total")
                            self._publish_projection_if_due()
                            stop_event.wait(self.QUESTDB_BATCH_MAX_WAIT_SECONDS)
                        continue

                    poll = getattr(self.source, "poll", None)
                    if callable(poll) and not stop_event.is_set():
                        depth = self.ingress.qsize()
                        capacity = max(0, self.config.queue_maxsize - depth)
                        group_capacity = max(
                            0, self.QUESTDB_BATCH_MAX_SIZE - min(depth, self.QUESTDB_BATCH_MAX_SIZE)
                        )
                        if capacity and group_capacity:
                            timeout = 0
                            if depth:
                                remaining = self._questdb_ingress_wait_seconds()
                                timeout = max(1, int(remaining * 1000 + 0.999))
                            try:
                                poll(
                                    timeout,
                                    limit=min(
                                        self.SOURCE_DRAIN_LIMIT,
                                        capacity,
                                        group_capacity,
                                    ),
                                )
                            except Exception as exc:  # noqa: BLE001
                                self._last_error = type(exc).__name__
                    if self.ingress.qsize() and self._durable_ingress_started_monotonic is None:
                        self._durable_ingress_started_monotonic = monotonic_time.monotonic()
                    self._publish_projection_if_due()
                    if self.ingress.qsize():
                        # Poll implementations may return early without data;
                        # wait only to the group deadline, then journal it.
                        stop_event.wait(
                            min(0.01, self._questdb_ingress_wait_seconds())
                        )
                    else:
                        stop_event.wait(min(1.0, max(0.01, float(idle_seconds))))
                    continue

                # A due/failed QuestDB batch blocks further socket draining.
                # Retry the same bounded durable batch until it commits; this
                # keeps both the DB batch and already-polled ingress bounded.
                if (
                    isinstance(self.writer, QuestDbTickWriter)
                    and self._questdb_batch_due()
                ):
                    try:
                        self._flush_questdb_pending(reason="max_wait")
                    except Exception as exc:  # noqa: BLE001
                        self._last_error = type(exc).__name__
                        self._publish_projection_if_due()
                        stop_event.wait(self.QUESTDB_BATCH_MAX_WAIT_SECONDS)
                        continue
                # Process durable ingress before receiving anything new.  A
                # full bounded queue must be visible as backpressure, never a
                # dropped socket message after an over-eager receive burst.
                if self.ingress.qsize():
                    try:
                        self.process_queue(flush=False)
                    except Exception as exc:  # noqa: BLE001
                        self._last_error = type(exc).__name__
                        if isinstance(self.writer, QuestDbTickWriter):
                            self._publish_projection_if_due()
                            stop_event.wait(self.QUESTDB_BATCH_MAX_WAIT_SECONDS)
                            continue
                try:
                    poll = getattr(self.source, "poll", None)
                    if (
                        not stop_event.is_set()
                        and callable(poll)
                        and self.ingress.qsize() == 0
                    ):
                        poll(
                            0,
                            limit=min(
                                self.SOURCE_DRAIN_LIMIT,
                                self.config.queue_maxsize,
                            ),
                        )
                except Exception as exc:  # noqa: BLE001
                    self._last_error = type(exc).__name__
                try:
                    self.process_queue(flush=False)
                except Exception as exc:  # noqa: BLE001
                    self._last_error = type(exc).__name__
                    if isinstance(self.writer, QuestDbTickWriter):
                        self._publish_projection_if_due()
                        stop_event.wait(self.QUESTDB_BATCH_MAX_WAIT_SECONDS)
                        continue
                self._publish_projection_if_due()
                try:
                    has_backlog = getattr(self.source, "has_backlog", None)
                    source_backlog = (
                        bool(has_backlog()) if callable(has_backlog) else False
                    )
                except Exception as exc:  # noqa: BLE001
                    source_backlog = False
                    self._last_error = type(exc).__name__
                if (
                    not stop_event.is_set()
                    and not source_backlog
                    and self.ingress.qsize() == 0
                ):
                    # No active work: wait, but cap it at the projection
                    # heartbeat interval so <=1Hz projection freshness holds.
                    remaining = self.QUESTDB_BATCH_MAX_WAIT_SECONDS
                    if self._questdb_batch_started_monotonic is not None:
                        remaining = max(
                            0.0,
                            self.QUESTDB_BATCH_MAX_WAIT_SECONDS
                            - (
                                monotonic_time.monotonic()
                                - self._questdb_batch_started_monotonic
                            ),
                        )
                    stop_event.wait(
                        min(1.0, max(0.01, min(float(idle_seconds), remaining)))
                    )
        finally:
            shutdown_error: Exception | None = None
            if isinstance(self.writer, QuestDbTickWriter):
                try:
                    # Stop polling first, then make every already accepted raw
                    # ingress item durable before the final DB flush.
                    while self.ingress.qsize():
                        self.process_queue(
                            limit=self.QUESTDB_BATCH_MAX_SIZE, flush=True
                        )
                    self._durable_ingress_started_monotonic = None
                    self._flush_questdb_pending(reason="shutdown")
                except Exception as exc:  # noqa: BLE001
                    self._last_error = type(exc).__name__
                    shutdown_error = exc
            close_source = getattr(self.source, "close", None)
            if callable(close_source):
                close_source()
            close_writer = getattr(self.writer, "close", None)
            if callable(close_writer):
                close_writer()
            if shutdown_error is not None:
                raise shutdown_error

    def health(self) -> HealthSnapshot:
        writer_health = getattr(self.writer, "health", None)
        metrics = self.metrics_snapshot()
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
                # Use this running worker's in-memory counters.  A separate
                # CLI process has a fresh metrics object and must not be used
                # as an operational substitute for this projection.
                "worker_metrics": metrics,
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
        snapshot = self.metrics.as_dict()
        latencies = tuple(self._questdb_commit_latencies_ms)
        snapshot["questdb_batch"] = {
            "max_size": self.QUESTDB_BATCH_MAX_SIZE,
            "max_wait_ms": self.QUESTDB_BATCH_MAX_WAIT_SECONDS * 1000,
            "size_samples": list(self._questdb_batch_sizes),
            "commit_latency_ms": {
                "samples": list(latencies),
                "p50": self._percentile(latencies, 0.50),
                "p95": self._percentile(latencies, 0.95),
                "p99": self._percentile(latencies, 0.99),
            },
        }
        return snapshot

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

    def _publish_projection_if_due(self, *, force: bool = False) -> bool:
        now = monotonic_time.monotonic()
        if not force and now < self._next_projection_monotonic:
            return False
        self.publish_projection()
        self._next_projection_monotonic = now + self._PROJECTION_INTERVAL_SECONDS
        return True


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
