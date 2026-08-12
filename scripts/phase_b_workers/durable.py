"""Crash-safe append-only primitives used by Phase B workers.

The primitives deliberately use local files rather than an implicit in-process
queue.  A deployment can mount these files on durable storage or replace the
small protocols with a queue adapter while keeping the wire contracts intact.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
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
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(directory), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_parent(path: Path) -> tuple[Path, os.stat_result]:
    """Pin one existing, private parent directory before file operations."""

    parent = Path(path).parent
    try:
        info = parent.lstat()
    except OSError as exc:
        raise DurableCorruptionError(
            f"durable parent is unavailable: {parent}"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise DurableCorruptionError(f"durable parent is not a directory: {parent}")
    if info.st_mode & 0o077:
        raise DurableCorruptionError(f"durable parent permissions are unsafe: {parent}")
    return parent, info


def _open_parent(path: Path) -> tuple[int, os.stat_result]:
    """Open every parent component without following a symlink.

    The returned descriptor, rather than the string path, is used for every
    child operation.  This prevents an ancestor replacement from redirecting a
    later journal/checkpoint write.
    """

    parent, expected = _ensure_parent(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if (
        os.open not in os.supports_dir_fd
        or not getattr(os, "O_DIRECTORY", 0)
        or not getattr(os, "O_NOFOLLOW", 0)
    ):
        raise DurableCorruptionError("durable dirfd O_NOFOLLOW support is required")
    flags |= os.O_NOFOLLOW
    # macOS exposes /var through the system-owned /private/var link.  Resolve
    # the supplied path once, then pin the concrete directory component by
    # component; all subsequent I/O remains relative to that held dirfd.
    absolute_parent = Path(os.path.realpath(parent))
    descriptor = -1
    try:
        descriptor = os.open(absolute_parent.anchor, flags)
        for component in absolute_parent.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        current = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DurableCorruptionError(f"cannot pin durable parent: {parent}") from exc
    if (current.st_dev, current.st_ino, current.st_mode) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
    ):
        os.close(descriptor)
        raise DurableCorruptionError(f"durable parent changed: {parent}")
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_mode & 0o077
    ):
        os.close(descriptor)
        raise DurableCorruptionError(f"durable parent permissions are unsafe: {parent}")
    return descriptor, current


def _strict_json_line(
    raw: str, path: Path, line_number: int | None = None
) -> dict[str, object]:
    suffix = f":{line_number}" if line_number is not None else ""
    if not raw.endswith("\n"):
        raise DurableCorruptionError(f"noncanonical JSONL at {path}{suffix}")
    text = raw[:-1]
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise DurableCorruptionError(f"invalid JSONL at {path}{suffix}") from exc
    if not isinstance(value, dict) or canonical_json(value) + "\n" != raw:
        raise DurableCorruptionError(f"noncanonical JSONL at {path}{suffix}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant is forbidden: {value}")


def atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    path = Path(os.path.abspath(path))
    _ensure_parent(path)
    parent_fd, _ = _open_parent(path)
    temporary_name = f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}"
    payload = (canonical_json(dict(value)) + "\n").encode("utf-8")
    fd = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise DurableCorruptionError(f"checkpoint write failed: {path}")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        destination = path.name
        try:
            existing = os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
        ):
            raise DurableCorruptionError(
                f"checkpoint destination is not a regular file: {path}"
            )
        os.replace(
            temporary_name, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
        )
        os.fsync(parent_fd)
    except OSError as exc:
        raise DurableCorruptionError(f"checkpoint write failed: {path}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


class AtomicCheckpoint:
    """One JSON document replaced atomically after a successful side effect."""

    def __init__(
        self,
        path: str | Path,
        *,
        default: Mapping[str, object] | None = None,
        read_only: bool = False,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self.default = dict(default or {})
        self.read_only = bool(read_only)
        self._lock = threading.RLock()
        if not self.read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.path.parent, 0o700)
        _ensure_parent(self.path)

    def read(self) -> dict[str, object]:
        with self._lock:
            parent_fd, _ = _open_parent(self.path)
            fd = -1
            try:
                try:
                    destination = os.stat(
                        self.path.name, dir_fd=parent_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    return dict(self.default)
                if stat.S_ISLNK(destination.st_mode):
                    raise DurableCorruptionError(f"invalid checkpoint {self.path}")
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.path.name, flags, dir_fd=parent_fd)
                info = os.fstat(fd)
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise DurableCorruptionError(f"invalid checkpoint {self.path}")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks).decode("utf-8")
                value = _strict_json_line(raw, self.path)
            except (OSError, UnicodeDecodeError, DurableCorruptionError) as exc:
                raise DurableCorruptionError(f"invalid checkpoint {self.path}") from exc
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)
            if not isinstance(value, dict):
                raise DurableCorruptionError(
                    f"checkpoint is not an object: {self.path}"
                )
            return dict(value)

    def write(self, value: Mapping[str, object]) -> None:
        if self.read_only:
            raise DurableStateError(f"checkpoint is read-only: {self.path}")
        with self._lock:
            atomic_write_json(self.path, value)

    def ensure_exists(self) -> None:
        """Create the default checkpoint only for its owning producer."""

        if self.read_only:
            raise DurableStateError(f"checkpoint is read-only: {self.path}")
        with self._lock:
            parent_fd, _ = _open_parent(self.path)
            try:
                try:
                    os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)
                    return
                except FileNotFoundError:
                    pass
            finally:
                os.close(parent_fd)
            self.write(self.default)

    def update(self, **changes: object) -> dict[str, object]:
        with self._lock:
            value = self.read()
            value.update(changes)
            self.write(value)
            return value


class AppendOnlyJsonl:
    """Fsync-on-append JSONL journal with strict replay semantics."""

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(os.path.abspath(path))
        self.read_only = bool(read_only)
        if not self.read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.path.parent, 0o700)
        _ensure_parent(self.path)
        self._lock = threading.RLock()

    def append(self, value: Mapping[str, object]) -> None:
        if self.read_only:
            raise DurableStateError(f"journal is read-only: {self.path}")
        line = (canonical_json(dict(value)) + "\n").encode("utf-8")
        with self._lock:
            parent_fd, _ = _open_parent(self.path)
            fd = -1
            try:
                flags = (
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
                )
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.path.name, flags, 0o600, dir_fd=parent_fd)
                info = os.fstat(fd)
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise DurableCorruptionError(
                        f"journal is not a regular file: {self.path}"
                    )
                view = memoryview(line)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise DurableCorruptionError(
                            f"journal write failed: {self.path}"
                        )
                    view = view[written:]
                os.fsync(fd)
                os.fsync(parent_fd)
            except OSError as exc:
                raise DurableCorruptionError(
                    f"journal write failed: {self.path}"
                ) from exc
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)

    def ensure_exists(self) -> None:
        """Create an empty journal only for its owning producer."""

        if self.read_only:
            raise DurableStateError(f"journal is read-only: {self.path}")
        with self._lock:
            parent_fd, _ = _open_parent(self.path)
            fd = -1
            try:
                flags = (
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
                )
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.path.name, flags, 0o600, dir_fd=parent_fd)
                info = os.fstat(fd)
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise DurableCorruptionError(
                        f"journal is not a regular file: {self.path}"
                    )
                os.fsync(fd)
                os.fsync(parent_fd)
            except OSError as exc:
                raise DurableCorruptionError(
                    f"journal initialization failed: {self.path}"
                ) from exc
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)

    def records(self) -> Iterator[dict[str, object]]:
        try:
            parent_fd, _ = _open_parent(self.path)
        except DurableCorruptionError:
            if not self.path.exists():
                return
            raise
        fd = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self.path.name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                return
            info = os.fstat(fd)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise DurableCorruptionError(
                    f"journal is not a regular file: {self.path}"
                )
            raw = bytearray()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                raw.extend(chunk)
        except OSError as exc:
            raise DurableCorruptionError(f"cannot read journal {self.path}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DurableCorruptionError(f"invalid UTF-8 journal {self.path}") from exc
        if not text:
            return
        lines = text.splitlines(keepends=True)
        for line_number, line in enumerate(lines, 1):
            yield _strict_json_line(line, self.path, line_number)

    def read_all(self) -> list[dict[str, object]]:
        return list(self.records())


class AppendOnlySet:
    """Durable id set for write acknowledgements and delivery dedupe."""

    def __init__(
        self, path: str | Path, *, identity_key: str = "id", read_only: bool = False
    ) -> None:
        self.journal = AppendOnlyJsonl(path, read_only=read_only)
        self.identity_key = identity_key
        self._lock = threading.RLock()
        self._values: set[str] | None = None
        self._records: dict[str, dict[str, object]] | None = None

    def _load(self) -> set[str]:
        if self._values is None:
            values: set[str] = set()
            records: dict[str, dict[str, object]] = {}
            for record in self.journal.records():
                value = record.get(self.identity_key)
                if value is None:
                    raise DurableCorruptionError("append-only set identity missing")
                identity = str(value)
                prior = records.get(identity)
                if prior is not None:
                    if prior != record:
                        raise DuplicateRecordError(
                            f"append-only set identity reused: {identity}"
                        )
                    raise DurableCorruptionError(
                        f"append-only set identity duplicated: {identity}"
                    )
                values.add(identity)
                records[identity] = dict(record)
            self._values = values
            self._records = records
        return self._values

    def contains(self, value: str) -> bool:
        with self._lock:
            return str(value) in self._load()

    def add(self, value: str, **metadata: object) -> bool:
        text = str(value)
        with self._lock:
            values = self._load()
            if text in values:
                expected = {self.identity_key: text, **metadata}
                if self._records is None or self._records[text] != expected:
                    raise DuplicateRecordError(
                        f"append-only set identity conflict: {text}"
                    )
                return False
            record = {self.identity_key: text, **metadata}
            self.journal.append(record)
            values.add(text)
            if self._records is None:
                self._records = {}
            self._records[text] = record
            return True

    def values(self) -> set[str]:
        with self._lock:
            return set(self._load())


class DurableVerifiedTickStream:
    """Producer-owned verified stream plus explicit writer acknowledgements."""

    def __init__(
        self, directory: str | Path, *, generation: str, read_only: bool = False
    ) -> None:
        self.directory = Path(directory)
        self.read_only = bool(read_only)
        if not self.read_only:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.directory, 0o700)
        self._validate_directory()
        self.generation = str(generation)
        self.journal = AppendOnlyJsonl(
            self.directory / "verified_ticks.jsonl", read_only=self.read_only
        )
        self.watermark = AtomicCheckpoint(
            self.directory / "producer_watermark.json",
            default={"stream_generation": self.generation, "last_ingest_seq": 0},
            read_only=self.read_only,
        )
        self.acknowledgements = AppendOnlySet(
            self.directory / "tick_writer_acks.jsonl",
            identity_key="ingest_id",
            read_only=self.read_only,
        )
        self._lock_path = self.directory / ".stream.lock"
        self._lock = threading.RLock()
        self._index: dict[str, VerifiedTick] | None = None
        if self.read_only:
            self._validate_read_only_layout()
            # Strict consumers validate the complete producer state at open
            # time.  Unlike producer recovery this path never repairs a
            # stale watermark or creates any stream artifact.
            self._load_index()

    def _validate_directory(self) -> None:
        """Verify a consumer mount without changing it."""

        try:
            info = self.directory.lstat()
        except OSError as exc:
            raise DurableCorruptionError(
                f"verified tick stream directory is unavailable: {self.directory}"
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise DurableCorruptionError(
                f"verified tick stream directory is unsafe: {self.directory}"
            )

    def _validate_read_only_layout(self) -> None:
        """Require producer-initialized artifacts before a consumer starts.

        A read-only consumer must never create or repair producer state.  A
        missing artifact therefore means the producer has not completed its
        initialization, rather than an empty stream that can be trusted.
        """

        for path in (
            self.journal.path,
            self.watermark.path,
            self.acknowledgements.journal.path,
            self._lock_path,
        ):
            try:
                info = path.lstat()
            except OSError as exc:
                raise DurableCorruptionError(
                    f"producer-initialized stream artifact is missing: {path}"
                ) from exc
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise DurableCorruptionError(f"stream artifact is unsafe: {path}")

    def initialize(self) -> None:
        """Initialize an empty producer stream before exposing it to readers."""

        if self.read_only:
            raise DurableStateError("read-only consumer cannot initialize a stream")
        with self._lock, self._process_lock():
            self.journal.ensure_exists()
            self.acknowledgements.journal.ensure_exists()
            self.watermark.ensure_exists()

    @contextmanager
    def _process_lock(self) -> Iterator[None]:
        """Hold one producer/consumer snapshot lock across worker processes."""

        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - Phase B is Unix-only
            raise DurableCorruptionError(
                "durable process locking is unavailable"
            ) from exc
        parent_fd, _ = _open_parent(self._lock_path)
        descriptor = -1
        try:
            flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            if self.read_only:
                # A consumer mount may be read-only.  It can take a shared
                # flock on the producer-created lock without creating or
                # opening the file for write access.
                flags |= os.O_RDONLY
            else:
                flags |= os.O_RDWR | os.O_CREAT
            descriptor = os.open(self._lock_path.name, flags, 0o600, dir_fd=parent_fd)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise DurableCorruptionError("durable stream lock is invalid")
            fcntl.flock(descriptor, fcntl.LOCK_SH if self.read_only else fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise DurableCorruptionError("cannot lock durable stream") from exc
        finally:
            if descriptor >= 0:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
            os.close(parent_fd)

    def _load_index(self) -> dict[str, VerifiedTick]:
        if self._index is None:
            # Recovery readers, including the default health worker, scan the
            # journal, watermark, and acknowledgement frontier as one
            # snapshot.  Producers hold the exclusive side of this same flock
            # for append and acknowledgement transitions, so a scan cannot
            # combine an old journal tail with a newer checkpoint.
            with self._process_lock():
                return self._load_index_unlocked()
        return self._index

    def _load_index_unlocked(self) -> dict[str, VerifiedTick]:
        """Validate and cache the stream while its caller owns any needed lock."""

        if self._index is None:
            index: dict[str, VerifiedTick] = {}
            expected_seq = 1
            source_events: dict[str, str] = {}
            for record in self.journal.records():
                if (
                    set(record) != {"record_type", "tick"}
                    or record.get("record_type") != "verified_tick"
                ):
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
                if tick.ingest_seq != expected_seq or tick.ingest_seq < 1:
                    raise DurableCorruptionError(
                        f"verified tick ingest sequence gap/duplicate: expected {expected_seq}, got {tick.ingest_seq}"
                    )
                if tick.ingest_id in index:
                    raise DuplicateRecordError(f"ingest_id reused: {tick.ingest_id}")
                if tick.source_event_id:
                    prior_hash = source_events.get(tick.source_event_id)
                    if prior_hash is not None:
                        raise DuplicateRecordError(
                            f"source_event_id reused: {tick.source_event_id}"
                        )
                    source_events[tick.source_event_id] = tick.event_hash
                index[tick.ingest_id] = tick
                expected_seq += 1
            state = self.watermark.read()
            state_generation = str(state.get("stream_generation") or self.generation)
            if state_generation != self.generation:
                raise GenerationMismatch(
                    f"watermark generation {state_generation!r} != {self.generation!r}"
                )
            max_seq = expected_seq - 1
            watermark_seq = int(state.get("last_ingest_seq") or 0)
            watermark_hash = str(state.get("last_event_hash") or "")
            expected_hash = (
                max(index.values(), key=lambda item: item.ingest_seq).event_hash
                if index
                else ""
            )
            if watermark_seq > max_seq:
                raise DurableCorruptionError(
                    "verified tick watermark is ahead of journal"
                )
            if watermark_seq < max_seq:
                # A crash after the journal fsync and before the checkpoint
                # fsync is recoverable from the strictly ordered journal.
                if self.read_only:
                    raise DurableCorruptionError(
                        "read-only verified tick stream watermark is behind journal"
                    )
                self.watermark.write(
                    {
                        "stream_generation": self.generation,
                        "last_ingest_seq": max_seq,
                        "last_event_hash": expected_hash,
                    }
                )
            elif watermark_hash != expected_hash:
                raise DurableCorruptionError("verified tick watermark hash mismatch")
            self._validate_acknowledgements(index)
            # Do not retain a partial journal if checkpoint or acknowledgement
            # validation fails.  A later access must fail closed again.
            self._index = index
        return self._index

    def _validate_acknowledgements(self, index: Mapping[str, VerifiedTick]) -> None:
        self.acknowledgements._load()  # type: ignore[attr-defined]
        records = self.acknowledgements._records or {}  # type: ignore[attr-defined]
        for ingest_id, record in records.items():
            tick = index.get(ingest_id)
            if tick is None:
                raise DurableCorruptionError("acknowledgement references unknown tick")
            if set(record) != {
                "ingest_id",
                "stream_generation",
                "ingest_seq",
                "event_hash",
            }:
                raise DurableCorruptionError("acknowledgement fields are invalid")
            if (
                record.get("stream_generation") != tick.stream_generation
                or int(record.get("ingest_seq") or 0) != tick.ingest_seq
                or record.get("event_hash") != tick.event_hash
            ):
                raise DurableCorruptionError("acknowledgement does not bind to tick")

    def next_sequence(self) -> int:
        with self._lock, self._process_lock():
            index = self._load_index_unlocked()
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
        with self._lock, self._process_lock():
            # Another producer can have appended while this object was idle.
            self._index = None
            index = self._load_index_unlocked()
            prior = index.get(tick.ingest_id)
            if prior:
                if prior.event_hash != tick.event_hash:
                    raise DuplicateRecordError(f"ingest_id reused: {tick.ingest_id}")
                return False
            state = self.watermark.read()
            expected = (
                max(
                    int(state.get("last_ingest_seq") or 0),
                    max((item.ingest_seq for item in index.values()), default=0),
                )
                + 1
            )
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
        self._validate_acknowledgements(self._load_index())
        return [
            tick
            for tick in self.iter_from()
            if not self.acknowledgements.contains(tick.ingest_id)
        ]

    def get(self, ingest_id: str) -> VerifiedTick | None:
        with self._lock:
            return self._load_index().get(str(ingest_id))

    def get_by_sequence(self, ingest_seq: int) -> VerifiedTick | None:
        sequence = int(ingest_seq)
        with self._lock:
            return next(
                (
                    tick
                    for tick in self._load_index().values()
                    if tick.ingest_seq == sequence
                ),
                None,
            )

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
        self._validate_acknowledgements(self._load_index())
        return self.acknowledgements.contains(tick.ingest_id)

    def acknowledge_tick_write(self, tick: VerifiedTick) -> bool:
        if tick.stream_generation != self.generation:
            raise GenerationMismatch("acknowledgement generation mismatch")
        if tick.event_hash != tick.compute_event_hash():
            raise DurableCorruptionError("acknowledgement source hash mismatch")
        with self._lock, self._process_lock():
            self._index = None
            self.acknowledgements._values = None  # type: ignore[attr-defined]
            self.acknowledgements._records = None  # type: ignore[attr-defined]
            persisted = self._load_index_unlocked().get(tick.ingest_id)
            if persisted is None:
                raise DurableCorruptionError("acknowledgement references unknown tick")
            if (
                persisted.stream_generation != tick.stream_generation
                or persisted.ingest_seq != tick.ingest_seq
                or persisted.event_hash != tick.event_hash
            ):
                raise DurableCorruptionError(
                    "acknowledgement does not bind to persisted tick"
                )
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
                try:
                    evidence = ExecutionQualityEvidence.from_dict(record)
                except (TypeError, ValueError) as exc:
                    raise DurableCorruptionError(
                        "invalid execution-quality evidence"
                    ) from exc
                identity = evidence.evidence_id
                digest = evidence.evidence_hash
                if identity in index and index[identity] != digest:
                    raise DuplicateRecordError(f"evidence identity reused: {identity}")
                if identity in index:
                    raise DurableCorruptionError(
                        f"evidence identity duplicated: {identity}"
                    )
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
        with self._lock:
            # Force semantic validation before exposing any records to a
            # recovering consumer.  A syntactically valid but tampered record
            # must never be treated as replayable evidence.
            self._load_index()
            return self.journal.read_all()

    def get_by_identity(self, evidence_id: str) -> ExecutionQualityEvidence | None:
        identity = str(evidence_id)
        with self._lock:
            self._load_index()
            for record in self.journal.records():
                if str(record.get("evidence_id") or "") == identity:
                    try:
                        return ExecutionQualityEvidence.from_dict(record)
                    except (TypeError, ValueError) as exc:
                        raise DurableCorruptionError(
                            "invalid execution-quality evidence"
                        ) from exc
        return None


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
