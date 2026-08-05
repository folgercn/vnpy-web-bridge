"""Crash-safe append-only primitives used by Phase B workers.

The primitives deliberately use local files rather than an implicit in-process
queue.  A deployment can mount these files on durable storage or replace the
small protocols with a queue adapter while keeping the wire contracts intact.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

from .contracts import (
    ExecutionQualityEvidence,
    IncidentEvent,
    VerifiedTick,
    canonical_json,
)


class DurableStateError(RuntimeError):
    """Base error for malformed or conflicting durable state."""


class DurableCorruptionError(DurableStateError):
    """Raised when an append-only record cannot be decoded or verified."""


class DuplicateRecordError(DurableStateError):
    """Raised when an identity is reused with different content."""


class GenerationMismatch(DurableStateError):
    """Raised when a consumer or producer uses a stale stream generation."""


class BackpressureError(DurableStateError):
    """Raised instead of silently dropping an item when a queue is full."""


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}"
    )
    payload = (canonical_json(dict(value)) + "\n").encode("utf-8")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


class AtomicCheckpoint:
    """One JSON document replaced atomically after a successful side effect."""

    def __init__(
        self, path: str | Path, *, default: Mapping[str, object] | None = None
    ) -> None:
        self.path = Path(path)
        self.default = dict(default or {})
        self._lock = threading.RLock()

    def read(self) -> dict[str, object]:
        with self._lock:
            if not self.path.exists():
                return dict(self.default)
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise DurableCorruptionError(f"invalid checkpoint {self.path}") from exc
            if not isinstance(value, dict):
                raise DurableCorruptionError(
                    f"checkpoint is not an object: {self.path}"
                )
            return dict(value)

    def write(self, value: Mapping[str, object]) -> None:
        with self._lock:
            atomic_write_json(self.path, value)

    def update(self, **changes: object) -> dict[str, object]:
        with self._lock:
            value = self.read()
            value.update(changes)
            self.write(value)
            return value


class AppendOnlyJsonl:
    """Fsync-on-append JSONL journal with strict replay semantics."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def append(self, value: Mapping[str, object]) -> None:
        line = (canonical_json(dict(value)) + "\n").encode("utf-8")
        with self._lock, self.path.open("ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def records(self) -> Iterator[dict[str, object]]:
        if not self.path.exists():
            return
        try:
            handle = self.path.open("r", encoding="utf-8")
        except OSError as exc:
            raise DurableCorruptionError(f"cannot read journal {self.path}") from exc
        with handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DurableCorruptionError(
                        f"invalid JSONL at {self.path}:{line_number}"
                    ) from exc
                if not isinstance(value, dict):
                    raise DurableCorruptionError(
                        f"non-object JSONL at {self.path}:{line_number}"
                    )
                yield value

    def read_all(self) -> list[dict[str, object]]:
        return list(self.records())


class AppendOnlySet:
    """Durable id set for write acknowledgements and delivery dedupe."""

    def __init__(self, path: str | Path, *, identity_key: str = "id") -> None:
        self.journal = AppendOnlyJsonl(path)
        self.identity_key = identity_key
        self._lock = threading.RLock()
        self._values: set[str] | None = None

    def _load(self) -> set[str]:
        if self._values is None:
            values: set[str] = set()
            for record in self.journal.records():
                value = record.get(self.identity_key)
                if value is not None:
                    values.add(str(value))
            self._values = values
        return self._values

    def contains(self, value: str) -> bool:
        with self._lock:
            return str(value) in self._load()

    def add(self, value: str, **metadata: object) -> bool:
        text = str(value)
        with self._lock:
            values = self._load()
            if text in values:
                return False
            self.journal.append({self.identity_key: text, **metadata})
            values.add(text)
            return True

    def values(self) -> set[str]:
        with self._lock:
            return set(self._load())


class DurableVerifiedTickStream:
    """Producer-owned verified stream plus explicit writer acknowledgements."""

    def __init__(self, directory: str | Path, *, generation: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.generation = str(generation)
        self.journal = AppendOnlyJsonl(self.directory / "verified_ticks.jsonl")
        self.watermark = AtomicCheckpoint(
            self.directory / "producer_watermark.json",
            default={"stream_generation": self.generation, "last_ingest_seq": 0},
        )
        self.acknowledgements = AppendOnlySet(
            self.directory / "tick_writer_acks.jsonl", identity_key="ingest_id"
        )
        self._lock = threading.RLock()
        self._index: dict[str, VerifiedTick] | None = None

    def _load_index(self) -> dict[str, VerifiedTick]:
        if self._index is None:
            index: dict[str, VerifiedTick] = {}
            for record in self.journal.records():
                if record.get("record_type") != "verified_tick":
                    raise DurableCorruptionError(
                        "unexpected record type in verified tick stream"
                    )
                try:
                    tick = VerifiedTick.from_dict(record["tick"])  # type: ignore[arg-type]
                except (KeyError, TypeError, ValueError) as exc:
                    raise DurableCorruptionError(
                        "invalid verified tick record"
                    ) from exc
                if tick.stream_generation != self.generation:
                    raise GenerationMismatch(
                        f"stream generation {tick.stream_generation!r} != {self.generation!r}"
                    )
                prior = index.get(tick.ingest_id)
                if prior and prior.event_hash != tick.event_hash:
                    raise DuplicateRecordError(f"ingest_id reused: {tick.ingest_id}")
                index[tick.ingest_id] = tick
            self._index = index
            state = self.watermark.read()
            state_generation = str(state.get("stream_generation") or self.generation)
            if state_generation != self.generation:
                raise GenerationMismatch(
                    f"watermark generation {state_generation!r} != {self.generation!r}"
                )
            max_seq = max((item.ingest_seq for item in index.values()), default=0)
            if int(state.get("last_ingest_seq") or 0) < max_seq:
                # A crash between the append and the checkpoint cannot cause
                # sequence reuse; recover the watermark from the durable log.
                self.watermark.write(
                    {
                        "stream_generation": self.generation,
                        "last_ingest_seq": max_seq,
                        "last_event_hash": max(
                            index.values(), key=lambda item: item.ingest_seq
                        ).event_hash
                        if index
                        else "",
                    }
                )
        return self._index

    def next_sequence(self) -> int:
        with self._lock:
            index = self._load_index()
            state = self.watermark.read()
            return (
                max(
                    int(state.get("last_ingest_seq") or 0),
                    max((item.ingest_seq for item in index.values()), default=0),
                )
                + 1
            )

    def append(self, tick: VerifiedTick) -> bool:
        if tick.stream_generation != self.generation:
            raise GenerationMismatch(
                f"tick generation {tick.stream_generation!r} != {self.generation!r}"
            )
        if tick.event_hash != tick.compute_event_hash():
            raise DurableCorruptionError(f"event hash mismatch for {tick.ingest_id}")
        with self._lock:
            index = self._load_index()
            prior = index.get(tick.ingest_id)
            if prior:
                if prior.event_hash != tick.event_hash:
                    raise DuplicateRecordError(f"ingest_id reused: {tick.ingest_id}")
                return False
            expected = self.next_sequence()
            if tick.ingest_seq != expected:
                raise DurableStateError(
                    f"expected ingest_seq {expected}, got {tick.ingest_seq}"
                )
            self.journal.append(
                {"record_type": "verified_tick", "tick": tick.as_dict()}
            )
            index[tick.ingest_id] = tick
            self.watermark.write(
                {
                    "stream_generation": self.generation,
                    "last_ingest_seq": tick.ingest_seq,
                    "last_event_hash": tick.event_hash,
                }
            )
            return True

    def iter_from(
        self, after_seq: int = 0, *, limit: int | None = None
    ) -> Iterator[VerifiedTick]:
        with self._lock:
            values = sorted(
                self._load_index().values(), key=lambda item: item.ingest_seq
            )
            selected = [item for item in values if item.ingest_seq > int(after_seq)]
        if limit is not None:
            selected = selected[: max(0, int(limit))]
        yield from selected

    def pending_for_tick_writer(self) -> list[VerifiedTick]:
        return [
            tick
            for tick in self.iter_from()
            if not self.acknowledgements.contains(tick.ingest_id)
        ]

    def get(self, ingest_id: str) -> VerifiedTick | None:
        with self._lock:
            return self._load_index().get(str(ingest_id))

    def find_by_source_event_id(self, source_event_id: str) -> VerifiedTick | None:
        identity = str(source_event_id or "")
        if not identity:
            return None
        with self._lock:
            for tick in self._load_index().values():
                if tick.source_event_id == identity:
                    return tick
        return None

    def find_by_raw_hash(self, raw_hash: str) -> VerifiedTick | None:
        digest = str(raw_hash or "")
        if not digest:
            return None
        with self._lock:
            for tick in self._load_index().values():
                if tick.raw_hash == digest:
                    return tick
        return None

    def is_acknowledged(self, tick: VerifiedTick) -> bool:
        return self.acknowledgements.contains(tick.ingest_id)

    def acknowledge_tick_write(self, tick: VerifiedTick) -> bool:
        return self.acknowledgements.add(
            tick.ingest_id,
            stream_generation=tick.stream_generation,
            ingest_seq=tick.ingest_seq,
            event_hash=tick.event_hash,
        )

    def stats(self) -> dict[str, object]:
        values = list(self.iter_from())
        state = self.watermark.read()
        return {
            "stream_generation": self.generation,
            "events": len(values),
            "last_ingest_seq": int(state.get("last_ingest_seq") or 0),
            "pending_writer_acks": sum(
                not self.acknowledgements.contains(item.ingest_id) for item in values
            ),
        }


class AppendOnlyEvidenceLog:
    """Append-only evidence sink with identity/hash conflict detection."""

    def __init__(self, path: str | Path) -> None:
        self.journal = AppendOnlyJsonl(path)
        self._lock = threading.RLock()
        self._index: dict[str, str] | None = None

    def _load_index(self) -> dict[str, str]:
        if self._index is None:
            index: dict[str, str] = {}
            for record in self.journal.records():
                identity = str(record.get("evidence_id") or "")
                digest = str(record.get("evidence_hash") or "")
                if not identity or not digest:
                    raise DurableCorruptionError("evidence identity/hash missing")
                if identity in index and index[identity] != digest:
                    raise DuplicateRecordError(f"evidence identity reused: {identity}")
                index[identity] = digest
            self._index = index
        return self._index

    def append(self, evidence: ExecutionQualityEvidence | Mapping[str, object]) -> bool:
        value = (
            evidence.as_dict()
            if isinstance(evidence, ExecutionQualityEvidence)
            else dict(evidence)
        )
        identity = str(value.get("evidence_id") or "")
        digest = str(value.get("evidence_hash") or "")
        if not identity or not digest:
            raise ValueError("evidence_id and evidence_hash are required")
        with self._lock:
            index = self._load_index()
            prior = index.get(identity)
            if prior:
                if prior != digest:
                    raise DuplicateRecordError(f"evidence identity reused: {identity}")
                return False
            self.journal.append(value)
            index[identity] = digest
            return True

    def records(self) -> list[dict[str, object]]:
        return self.journal.read_all()


class AppendOnlyIncidentLog:
    def __init__(self, path: str | Path) -> None:
        self.journal = AppendOnlyJsonl(path)
        self._lock = threading.RLock()

    def append(self, incident: IncidentEvent | Mapping[str, object]) -> bool:
        value = (
            incident.as_dict()
            if isinstance(incident, IncidentEvent)
            else dict(incident)
        )
        identity = str(value.get("incident_id") or "")
        if not identity:
            raise ValueError("incident_id is required")
        with self._lock:
            if any(
                str(item.get("incident_id")) == identity
                for item in self.journal.records()
            ):
                return False
            self.journal.append(value)
            return True

    def records(self) -> list[dict[str, object]]:
        return self.journal.read_all()


T = TypeVar("T")


@dataclass
class QueueStats:
    enqueued: int = 0
    dequeued: int = 0
    rejected: int = 0


class BoundedIngressQueue(Generic[T]):
    """A strict bounded queue: overflow is visible and never silently dropped."""

    def __init__(self, maxsize: int = 1024) -> None:
        from queue import Queue

        self._queue: Queue[T] = Queue(maxsize=max(1, int(maxsize)))
        self.stats = QueueStats()

    def put(self, value: T) -> None:
        try:
            self._queue.put_nowait(value)
        except Exception as exc:
            self.stats.rejected += 1
            raise BackpressureError("bounded ingress queue is full") from exc
        self.stats.enqueued += 1

    def get(self) -> T:
        value = self._queue.get_nowait()
        self.stats.dequeued += 1
        return value

    def qsize(self) -> int:
        return self._queue.qsize()
