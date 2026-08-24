"""Crash-safe append-only primitives used by Phase B workers.

The primitives deliberately use local files rather than an implicit in-process
queue.  A deployment can mount these files on durable storage or replace the
small protocols with a queue adapter while keeping the wire contracts intact.
"""

from __future__ import annotations

import codecs
import json
import os
import stat
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import blake2b
from itertools import islice, pairwise
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


class _BoundedMembershipFilter:
    """Fixed-memory, no-false-negative membership hint for one JSONL stream.

    A positive is never treated as proof: callers must scan the durable JSONL
    for the exact record.  This gives a fixed resident footprint while a
    filter collision can only cost extra I/O, never admit an altered replay.
    """

    # Bloom sizing for 2,000,000 identities at <= 1e-9 false positives:
    # m = -n ln(p) / ln(2)^2 = 86,253,012 bits, k ~= 30.  The 10.3 MiB
    # resident filter makes a full journal fallback extraordinarily rare;
    # crossing capacity fails closed rather than saturating into O(N) scans.
    _CAPACITY = 2_000_000
    _BITS = 86_253_016
    _HASHES = 30

    def __init__(self) -> None:
        self._bits = bytearray(self._BITS // 8)
        self.count = 0

    def _positions(self, value: str) -> Iterator[int]:
        digest = blake2b(str(value).encode("utf-8"), digest_size=16).digest()
        first = int.from_bytes(digest[:8], "big")
        step = int.from_bytes(digest[8:], "big") | 1
        for offset in range(self._HASHES):
            yield (first + offset * step) % self._BITS

    def add(self, value: str) -> None:
        for position in self._positions(value):
            self._bits[position >> 3] |= 1 << (position & 7)

    def note_identity(self) -> None:
        if self.count >= self._CAPACITY:
            raise BackpressureError("durable membership filter capacity exhausted")
        self.count += 1

    def require_capacity(self) -> None:
        if self.count >= self._CAPACITY:
            raise BackpressureError("durable membership filter capacity exhausted")

    def may_contain(self, value: str) -> bool:
        return all(
            self._bits[position >> 3] & (1 << (position & 7))
            for position in self._positions(value)
        )


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
        self._write_poisoned = False

    def append(self, value: Mapping[str, object]) -> None:
        """Append one record with the historical fsync-on-append contract."""

        self.append_many((value,))

    def append_many(self, values: Iterable[Mapping[str, object]]) -> None:
        """Append a bounded record group with one durable file flush.

        The parent directory is stable for ordinary appends to an existing
        journal.  Its fsync is therefore required only when this call creates
        the directory entry; initialization deliberately performs that work
        before the journal becomes visible to consumers.
        """

        if self.read_only:
            raise DurableStateError(f"journal is read-only: {self.path}")
        if self._write_poisoned:
            raise DurableStateError(f"journal writer is poisoned: {self.path}")
        lines = tuple(
            (canonical_json(dict(value)) + "\n").encode("utf-8")
            for value in islice(values, DurableVerifiedTickStream._GROUP_COMMIT_LIMIT + 1)
        )
        if len(lines) > DurableVerifiedTickStream._GROUP_COMMIT_LIMIT:
            raise BackpressureError("append-only journal group capacity exhausted")
        if not lines:
            return
        with self._lock:
            parent_fd, _ = _open_parent(self.path)
            fd = -1
            try:
                try:
                    os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)
                    created = False
                except FileNotFoundError:
                    created = True
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
                for line in lines:
                    view = memoryview(line)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            self._write_poisoned = True
                            raise DurableCorruptionError(
                                f"journal write failed: {self.path}"
                            )
                        view = view[written:]
                os.fsync(fd)
                if created:
                    os.fsync(parent_fd)
            except OSError as exc:
                self._write_poisoned = True
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
        if self._write_poisoned:
            raise DurableStateError(f"journal writer is poisoned: {self.path}")
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
                self._write_poisoned = True
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
        except OSError as exc:
            raise DurableCorruptionError(f"cannot read journal {self.path}") from exc
        try:
            decoder = codecs.getincrementaldecoder("utf-8")("strict")
            buffered = ""
            line_number = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    try:
                        buffered += decoder.decode(b"", final=True)
                    except UnicodeDecodeError as exc:
                        raise DurableCorruptionError(
                            f"invalid UTF-8 journal {self.path}"
                        ) from exc
                    if buffered:
                        line_number += 1
                        yield _strict_json_line(buffered, self.path, line_number)
                    return
                try:
                    buffered += decoder.decode(chunk, final=False)
                except UnicodeDecodeError as exc:
                    raise DurableCorruptionError(
                        f"invalid UTF-8 journal {self.path}"
                    ) from exc
                while True:
                    newline = buffered.find("\n")
                    if newline < 0:
                        break
                    line_number += 1
                    line = buffered[: newline + 1]
                    buffered = buffered[newline + 1 :]
                    yield _strict_json_line(line, self.path, line_number)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    def read_all(self) -> list[dict[str, object]]:
        return list(self.records())

    def fingerprint(self) -> tuple[int, int, int, int] | None:
        """Return an O(1), dirfd-validated snapshot for external append drift."""

        parent_fd, _ = _open_parent(self.path)
        try:
            try:
                info = os.stat(
                    self.path.name, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                return None
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise DurableCorruptionError(f"journal is not a regular file: {self.path}")
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        except OSError as exc:
            raise DurableCorruptionError(f"cannot stat journal {self.path}") from exc
        finally:
            os.close(parent_fd)


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

    # These are deliberately bounded in-memory acceleration structures.  The
    # JSONL files remain the authority: a filter hit is always confirmed from
    # the durable journal after recovery or when it falls outside this window.
    # Keeping the live sparse window bounded prevents an adversarial out of
    # order writer from turning acknowledgement bookkeeping into an unbounded
    # second index.
    _ACK_SPARSE_LIMIT = 4096
    _TICK_CACHE_LIMIT = 4096
    _GROUP_COMMIT_LIMIT = 64

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
        self._indexed_watermark_seq = -1
        self._ack_frontier = 0
        self._ack_sparse: set[int] = set()
        self._ack_fingerprint: tuple[int, int, int, int] | None = None
        self._write_poisoned = False
        self._event_count = 0
        self._ack_count = 0
        self._cursor_cache: dict[
            tuple[int, int], tuple[VerifiedTick, int]
        ] = {}
        self._ingest_membership = _BoundedMembershipFilter()
        self._source_event_membership = _BoundedMembershipFilter()
        self._raw_membership = _BoundedMembershipFilter()
        self._ack_membership = _BoundedMembershipFilter()
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
            try:
                flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                if self.read_only:
                    # A consumer mount may be read-only.  It can take a shared
                    # flock on the producer-created lock without creating or
                    # opening the file for write access.
                    flags |= os.O_RDONLY
                else:
                    flags |= os.O_RDWR | os.O_CREAT
                descriptor = os.open(
                    self._lock_path.name, flags, 0o600, dir_fd=parent_fd
                )
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise DurableCorruptionError("durable stream lock is invalid")
                fcntl.flock(
                    descriptor, fcntl.LOCK_SH if self.read_only else fcntl.LOCK_EX
                )
            except OSError as exc:
                raise DurableCorruptionError("cannot lock durable stream") from exc
            yield
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
            cache: dict[str, VerifiedTick] = {}
            self._ingest_membership = _BoundedMembershipFilter()
            self._source_event_membership = _BoundedMembershipFilter()
            self._raw_membership = _BoundedMembershipFilter()
            self._ack_membership = _BoundedMembershipFilter()
            expected_seq = 1
            # Recovery-only fixed-width binding table.  It validates every
            # acknowledgement against the exact persisted identity, sequence,
            # and event hash without retaining unbounded Python objects; it is
            # discarded before the worker accepts new ingress.
            recovery_bindings = bytearray()
            last_tick: VerifiedTick | None = None
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
                if self._ingest_membership.may_contain(tick.ingest_id):
                    prior = self._exact_tick_unlocked(
                        lambda item, identity=tick.ingest_id: item.ingest_id == identity,
                        before_sequence=tick.ingest_seq,
                    )
                    if prior is not None:
                        raise DuplicateRecordError(f"ingest_id reused: {tick.ingest_id}")
                if tick.source_event_id:
                    if self._source_event_membership.may_contain(tick.source_event_id):
                        prior = self._exact_tick_unlocked(
                            lambda item, identity=tick.source_event_id: item.source_event_id
                            == identity,
                            before_sequence=tick.ingest_seq,
                        )
                    else:
                        prior = None
                    if prior is not None:
                        raise DuplicateRecordError(
                            f"source_event_id reused: {tick.source_event_id}"
                        )
                self._ingest_membership.note_identity()
                self._ingest_membership.add(tick.ingest_id)
                if tick.source_event_id:
                    self._source_event_membership.note_identity()
                    self._source_event_membership.add(tick.source_event_id)
                if tick.raw_hash:
                    self._raw_membership.note_identity()
                    self._raw_membership.add(tick.raw_hash)
                recovery_bindings.extend(self._ack_binding(tick))
                cache[tick.ingest_id] = tick
                while len(cache) > self._TICK_CACHE_LIMIT:
                    cache.pop(next(iter(cache)))
                last_tick = tick
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
            expected_hash = last_tick.event_hash if last_tick is not None else ""
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
            self._rebuild_ack_frontier_unlocked(recovery_bindings)
            self._ack_fingerprint = self.acknowledgements.journal.fingerprint()
            # Do not retain a partial journal if checkpoint or acknowledgement
            # validation fails.  A later access must fail closed again.
            # Keep a bounded hot cache only.  Positive membership checks fall
            # back to the authoritative JSONL for older identities.
            self._index = cache
            self._indexed_watermark_seq = max_seq
            self._event_count = max_seq
        return self._index

    @staticmethod
    def _ack_binding(tick: VerifiedTick) -> bytes:
        return blake2b(
            canonical_json(
                {
                    "ingest_id": tick.ingest_id,
                    "ingest_seq": tick.ingest_seq,
                    "event_hash": tick.event_hash,
                    "stream_generation": tick.stream_generation,
                }
            ).encode("utf-8"),
            digest_size=32,
        ).digest()

    def _rebuild_ack_frontier_unlocked(self, bindings: bytes) -> None:
        """Rebuild the compact acknowledgement frontier from durable JSONL.

        This is recovery-only.  In the steady state ``acknowledge_tick_write``
        advances the frontier incrementally.  A checkpoint is an optimisation,
        never correctness authority: a crash after the acknowledgement fsync
        and before the checkpoint is reconstructed here from the journal.
        """

        frontier = 0
        sparse: set[int] = set()
        ack_count = 0
        seen = _BoundedMembershipFilter()
        self._ack_membership = _BoundedMembershipFilter()
        for record in self.acknowledgements.journal.records():
            if set(record) != {"ingest_id", "stream_generation", "ingest_seq", "event_hash"}:
                raise DurableCorruptionError("acknowledgement fields are invalid")
            identity = str(record.get("ingest_id") or "")
            sequence = int(record.get("ingest_seq") or 0)
            if not identity or sequence < 1 or record.get("stream_generation") != self.generation:
                raise DurableCorruptionError("acknowledgement does not bind to tick")
            start = (sequence - 1) * 32
            expected = bindings[start : start + 32]
            actual = blake2b(
                canonical_json(
                    {
                        "ingest_id": identity,
                        "ingest_seq": sequence,
                        "event_hash": record.get("event_hash"),
                        "stream_generation": record.get("stream_generation"),
                    }
                ).encode("utf-8"),
                digest_size=32,
            ).digest()
            if len(expected) != 32 or actual != expected:
                raise DurableCorruptionError("acknowledgement does not bind to tick")
            if seen.may_contain(identity) and self._exact_acknowledgement_by_id_unlocked(identity) != record:
                raise DurableCorruptionError("acknowledgement identity duplicated")
            seen.note_identity()
            seen.add(identity)
            self._ack_membership.note_identity()
            self._ack_membership.add(identity)
            ack_count += 1
            if sequence == frontier + 1:
                frontier += 1
                while frontier + 1 in sparse:
                    sparse.remove(frontier + 1)
                    frontier += 1
            elif sequence > frontier:
                if len(sparse) >= self._ACK_SPARSE_LIMIT:
                    raise BackpressureError("durable acknowledgement sparse frontier exhausted")
                sparse.add(sequence)
        self._ack_frontier = frontier
        self._ack_sparse = sparse
        self._ack_count = ack_count

    def _ack_bindings_unlocked(self) -> bytes:
        """Stream exact tick bindings only when another process changed acks."""

        bindings = bytearray()
        expected_sequence = 1
        for record in self.journal.records():
            if set(record) != {"record_type", "tick"} or record.get("record_type") != "verified_tick":
                raise DurableCorruptionError("unexpected record type in verified tick stream")
            try:
                tick = VerifiedTick.from_dict(record["tick"])  # type: ignore[arg-type]
            except (KeyError, TypeError, ValueError) as exc:
                raise DurableCorruptionError("invalid verified tick record") from exc
            if tick.stream_generation != self.generation or tick.ingest_seq != expected_sequence:
                raise DurableCorruptionError("verified tick stream changed during acknowledgement refresh")
            bindings.extend(self._ack_binding(tick))
            expected_sequence += 1
        if expected_sequence - 1 != self._indexed_watermark_seq:
            raise DurableCorruptionError("verified tick stream changed during acknowledgement refresh")
        return bytes(bindings)

    def _refresh_ack_frontier_if_changed_unlocked(self) -> None:
        fingerprint = self.acknowledgements.journal.fingerprint()
        if self._ack_fingerprint == fingerprint:
            return
        self._rebuild_ack_frontier_unlocked(self._ack_bindings_unlocked())
        self._ack_fingerprint = fingerprint

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

    def _exact_tick_unlocked(
        self,
        predicate: object,
        *,
        before_sequence: int | None = None,
        unique: bool = True,
    ) -> VerifiedTick | None:
        """Resolve a filter hit from durable state while the stream is locked."""

        matches = predicate
        if not callable(matches):  # pragma: no cover - internal invariant
            raise TypeError("tick predicate is invalid")
        found: VerifiedTick | None = None
        for record in self.journal.records():
            if set(record) != {"record_type", "tick"} or record.get("record_type") != "verified_tick":
                raise DurableCorruptionError("unexpected record type in verified tick stream")
            try:
                tick = VerifiedTick.from_dict(record["tick"])  # type: ignore[arg-type]
            except (KeyError, TypeError, ValueError) as exc:
                raise DurableCorruptionError("invalid verified tick record") from exc
            if tick.stream_generation != self.generation:
                raise GenerationMismatch("verified tick generation mismatch")
            if (before_sequence is None or tick.ingest_seq < before_sequence) and matches(tick):
                if found is not None and unique:
                    raise DuplicateRecordError("verified tick identity reused")
                if found is None:
                    found = tick
        return found

    def _cache_tick(self, tick: VerifiedTick) -> None:
        index = self._index
        if index is None:  # pragma: no cover - callers load first
            return
        index.pop(tick.ingest_id, None)
        index[tick.ingest_id] = tick
        while len(index) > self._TICK_CACHE_LIMIT:
            index.pop(next(iter(index)))

    def _exact_acknowledgement_unlocked(
        self, tick: VerifiedTick
    ) -> dict[str, object] | None:
        return self._exact_acknowledgement_by_id_unlocked(tick.ingest_id)

    def _exact_acknowledgement_by_id_unlocked(
        self, ingest_id: str
    ) -> dict[str, object] | None:
        found: dict[str, object] | None = None
        for record in self.acknowledgements.journal.records():
            if str(record.get("ingest_id") or "") != str(ingest_id):
                continue
            if found is not None:
                raise DurableCorruptionError("acknowledgement identity duplicated")
            found = record
        return found

    def next_sequence(self) -> int:
        with self._lock:
            # Recovery already validated the producer snapshot under this
            # flock.  Do not hold it while a consumer seeks an old immutable
            # prefix: an append-only writer must not wait behind that scan.
            with self._process_lock():
                self._load_index_unlocked()
            state = self.watermark.read()
            return int(state.get("last_ingest_seq") or 0) + 1

    def append(self, tick: VerifiedTick) -> bool:
        return self.append_many((tick,))[0]

    def append_many(
        self,
        ticks: Iterable[VerifiedTick],
        *,
        before_journal: Callable[[], None] | None = None,
        after_journal: Callable[[], None] | None = None,
    ) -> tuple[bool, ...]:
        """Durably append one bounded, contiguous tick group.

        A single verified-journal fsync establishes the complete group before
        the watermark advances to its tail.  Callers must pre-stage any
        companion checkpoint intent (such as the market source fence) before
        invoking this method.
        """

        values = tuple(islice(ticks, self._GROUP_COMMIT_LIMIT + 1))
        if self._write_poisoned:
            raise DurableStateError("verified tick stream writer is poisoned")
        if len(values) > self._GROUP_COMMIT_LIMIT:
            raise BackpressureError("durable tick group capacity exhausted")
        if not values:
            return ()
        for tick in values:
            if tick.stream_generation != self.generation:
                raise GenerationMismatch(
                    f"tick generation {tick.stream_generation!r} != {self.generation!r}"
                )
            if tick.event_hash != tick.compute_event_hash():
                raise DurableCorruptionError(
                    f"event hash mismatch for {tick.ingest_id}"
                )
        with self._lock, self._process_lock():
            state = self.watermark.read()
            # Preserve #327's competing-producer semantics without a steady
            # state replay: only a watermark change made by another stream
            # object invalidates our compact in-process frontier.
            if self._indexed_watermark_seq != int(state.get("last_ingest_seq") or 0):
                self._index = None
            index = self._load_index_unlocked()
            # Loading can repair a producer watermark left behind by a crash
            # after the journal fsync, so use the post-recovery frontier.
            expected = int(self.watermark.read().get("last_ingest_seq") or 0) + 1
            new: list[VerifiedTick] = []
            results: list[bool] = []
            staged: dict[str, VerifiedTick] = {}
            for tick in values:
                prior = staged.get(tick.ingest_id) or index.get(tick.ingest_id)
                if prior is None and self._ingest_membership.may_contain(
                    tick.ingest_id
                ):
                    prior = self._exact_tick_unlocked(
                        lambda item, identity=tick.ingest_id: item.ingest_id == identity
                    )
                if prior is not None:
                    if prior.event_hash != tick.event_hash:
                        raise DuplicateRecordError(
                            f"ingest_id reused: {tick.ingest_id}"
                        )
                    results.append(False)
                    continue
                if tick.ingest_seq != expected:
                    raise DurableStateError(
                        f"expected ingest_seq {expected}, got {tick.ingest_seq}"
                    )
                staged[tick.ingest_id] = tick
                new.append(tick)
                results.append(True)
                expected += 1
            for membership, identities in (
                (self._ingest_membership, {tick.ingest_id for tick in new}),
                (
                    self._source_event_membership,
                    {tick.source_event_id for tick in new if tick.source_event_id},
                ),
                (self._raw_membership, {tick.raw_hash for tick in new if tick.raw_hash}),
            ):
                if membership.count + len(identities) > membership._CAPACITY:
                    raise BackpressureError("durable membership filter capacity exhausted")
            if not new:
                if before_journal is not None:
                    before_journal()
                if after_journal is not None:
                    after_journal()
                return tuple(results)
            if before_journal is not None:
                before_journal()
            try:
                self.journal.append_many(
                    {"record_type": "verified_tick", "tick": tick.as_dict()}
                    for tick in new
                )
            except Exception:
                self._write_poisoned = True
                raise
            for tick in new:
                self._cache_tick(tick)
                self._ingest_membership.note_identity()
                self._ingest_membership.add(tick.ingest_id)
                if tick.source_event_id:
                    self._source_event_membership.note_identity()
                    self._source_event_membership.add(tick.source_event_id)
                if tick.raw_hash:
                    self._raw_membership.note_identity()
                    self._raw_membership.add(tick.raw_hash)
            tail = new[-1]
            try:
                self.watermark.write(
                    {
                        "stream_generation": self.generation,
                        "last_ingest_seq": tail.ingest_seq,
                        "last_event_hash": tail.event_hash,
                    }
                )
            except Exception:
                self._write_poisoned = True
                raise
            self._indexed_watermark_seq = tail.ingest_seq
            self._event_count += len(new)
            if after_journal is not None:
                after_journal()
            return tuple(results)

    def iter_from(
        self, after_seq: int = 0, *, limit: int | None = None
    ) -> Iterator[VerifiedTick]:
        remaining = None if limit is None else max(0, int(limit))
        with self._lock, self._process_lock():
            self._load_index_unlocked()
            for record in self.journal.records():
                if set(record) != {"record_type", "tick"} or record.get("record_type") != "verified_tick":
                    raise DurableCorruptionError("unexpected record type in verified tick stream")
                try:
                    tick = VerifiedTick.from_dict(record["tick"])  # type: ignore[arg-type]
                except (KeyError, TypeError, ValueError) as exc:
                    raise DurableCorruptionError("invalid verified tick record") from exc
                if tick.ingest_seq <= int(after_seq):
                    continue
                if remaining is not None and remaining <= 0:
                    break
                yield tick
                if remaining is not None:
                    remaining -= 1

    def next_after(
        self, after_seq: int = 0, *, offset: int | None = None
    ) -> tuple[VerifiedTick | None, int]:
        """Return one next tick without retaining the shared snapshot lock.

        A long-running read-only consumer must not keep ``iter_from`` open:
        that generator deliberately owns the shared process lock while it
        yields.  Re-opening ``iter_from(..., limit=1)`` for every record is
        safe but rescans the whole journal each time.  This cursor is only an
        in-memory byte offset; recovery still validates the full durable
        stream and a restart re-seeks from its durable checkpoint.
        """

        sequence = int(after_seq)
        if sequence < 0:
            raise DurableCorruptionError("verified tick sequence is negative")
        if offset is not None:
            cached = self._cursor_cache.pop((sequence, int(offset)), None)
            if cached is not None:
                return cached
        with self._lock, self._process_lock():
            self._load_index_unlocked()
            parent_fd, _ = _open_parent(self.journal.path)
            descriptor = -1
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.journal.path.name, flags, dir_fd=parent_fd)
                info = os.fstat(descriptor)
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or info.st_mode & 0o077
                ):
                    raise DurableCorruptionError(
                        f"journal is not a regular file: {self.journal.path}"
                    )
                position = 0 if offset is None else int(offset)
                if position < 0 or position > info.st_size:
                    raise DurableCorruptionError("verified tick cursor is outside journal")
                os.lseek(descriptor, position, os.SEEK_SET)
                buffered = b""
                expected_sequence = sequence + 1
                def read_tick() -> VerifiedTick | None:
                    nonlocal buffered, position
                    newline = buffered.find(b"\n")
                    while newline < 0:
                        # The cursor returns one record.  Keep the read
                        # bounded to avoid turning a long recovery into a
                        # repeated megabyte read per evidence record.
                        chunk = os.read(descriptor, 4096)
                        if not chunk:
                            if not buffered:
                                return None
                            # An unlocked producer may be between partial
                            # writes at the live tail.  Leave that record for
                            # the next short read instead of accepting it.
                            return None
                        buffered += chunk
                        newline = buffered.find(b"\n")
                    line = buffered[: newline + 1]
                    buffered = buffered[newline + 1 :]
                    position += len(line)
                    try:
                        raw = _strict_json_line(line.decode("utf-8"), self.journal.path, 0)
                    except UnicodeDecodeError as exc:
                        raise DurableCorruptionError(f"invalid UTF-8 journal {self.journal.path}") from exc
                    if set(raw) != {"record_type", "tick"} or raw.get("record_type") != "verified_tick":
                        raise DurableCorruptionError("unexpected record type in verified tick stream")
                    try:
                        return VerifiedTick.from_dict(raw["tick"])  # type: ignore[arg-type]
                    except (KeyError, TypeError, ValueError) as exc:
                        raise DurableCorruptionError("invalid verified tick record") from exc

                while True:
                    tick = read_tick()
                    if tick is None:
                        return None, position
                    if tick.ingest_seq <= sequence:
                        if offset is not None:
                            raise DurableCorruptionError(
                                "verified tick cursor is behind checkpoint"
                            )
                        continue
                    if tick.ingest_seq != expected_sequence:
                        raise DurableCorruptionError(
                            "verified tick cursor sequence is not contiguous"
                        )
                    prefetched = [(tick, position)]
                    while len(prefetched) < 64:
                        following = read_tick()
                        if following is None:
                            break
                        if following.ingest_seq != prefetched[-1][0].ingest_seq + 1:
                            raise DurableCorruptionError(
                                "verified tick cursor sequence is not contiguous"
                            )
                        prefetched.append((following, position))
                    for previous, current in pairwise(prefetched):
                        self._cursor_cache[(previous[0].ingest_seq, previous[1])] = current
                    return prefetched[0]
            except OSError as exc:
                raise DurableCorruptionError(
                    f"cannot read journal {self.journal.path}"
                ) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent_fd)

    def pending_for_tick_writer(self) -> list[VerifiedTick]:
        # Do not call the public ``is_acknowledged`` from ``iter_from``: that
        # generator deliberately holds the process snapshot lock while it
        # yields, and taking a second flock descriptor can deadlock on macOS.
        with self._lock, self._process_lock():
            self._load_index_unlocked()
            self._refresh_ack_frontier_if_changed_unlocked()
            pending: list[VerifiedTick] = []
            for record in self.journal.records():
                if set(record) != {"record_type", "tick"} or record.get("record_type") != "verified_tick":
                    raise DurableCorruptionError("unexpected record type in verified tick stream")
                try:
                    tick = VerifiedTick.from_dict(record["tick"])  # type: ignore[arg-type]
                except (KeyError, TypeError, ValueError) as exc:
                    raise DurableCorruptionError("invalid verified tick record") from exc
                if not self._is_acknowledged_unlocked(tick):
                    pending.append(tick)
            return pending

    def get(self, ingest_id: str) -> VerifiedTick | None:
        with self._lock:
            identity = str(ingest_id)
            cached = self._load_index().get(identity)
            if cached is not None or not self._ingest_membership.may_contain(identity):
                return cached
            with self._process_lock():
                return self._exact_tick_unlocked(lambda item: item.ingest_id == identity)

    def get_by_sequence(self, ingest_seq: int) -> VerifiedTick | None:
        sequence = int(ingest_seq)
        with self._lock:
            cached = next(
                (tick for tick in self._load_index().values() if tick.ingest_seq == sequence),
                None,
            )
            if cached is not None:
                return cached
            if sequence < 1 or sequence > self._indexed_watermark_seq:
                return None
            with self._process_lock():
                return self._exact_tick_unlocked(lambda item: item.ingest_seq == sequence)

    def find_by_source_event_id(self, source_event_id: str) -> VerifiedTick | None:
        identity = str(source_event_id or "")
        if not identity:
            return None
        with self._lock:
            for tick in self._load_index().values():
                if tick.source_event_id == identity:
                    return tick
            if not self._source_event_membership.may_contain(identity):
                return None
            with self._process_lock():
                return self._exact_tick_unlocked(
                    lambda item: item.source_event_id == identity
                )

    def find_by_raw_hash(self, raw_hash: str) -> VerifiedTick | None:
        digest = str(raw_hash or "")
        if not digest:
            return None
        with self._lock:
            self._load_index()
            if not self._raw_membership.may_contain(digest):
                return None
            with self._process_lock():
                return self._exact_tick_unlocked(
                    lambda item: item.raw_hash == digest, unique=False
                )

    def is_acknowledged(self, tick: VerifiedTick) -> bool:
        with self._lock, self._process_lock():
            self._load_index_unlocked()
            self._refresh_ack_frontier_if_changed_unlocked()
            return self._is_acknowledged_unlocked(tick)

    def _is_acknowledged_unlocked(self, tick: VerifiedTick) -> bool:
        if tick.ingest_seq <= self._ack_frontier:
            return True
        if tick.ingest_seq in self._ack_sparse:
            return True
        # A negative from the compact state is not used as durable proof:
        # check the append-only journal before saying the item is pending.
        # This covers a process crash between acknowledgement fsync and a
        # later checkpoint/state update without any false negative.
        if not self._ack_membership.may_contain(tick.ingest_id):
            return False
        record = self._exact_acknowledgement_unlocked(tick)
        if record is None:
            return False
        return (
            record.get("stream_generation") == tick.stream_generation
            and int(record.get("ingest_seq") or 0) == tick.ingest_seq
            and record.get("event_hash") == tick.event_hash
        )

    def acknowledge_tick_write(self, tick: VerifiedTick) -> bool:
        return self.acknowledge_tick_writes((tick,))[0]

    def acknowledge_tick_writes(
        self, ticks: Iterable[VerifiedTick]
    ) -> tuple[bool, ...]:
        """Record a bounded committed writer group with one acknowledgement fsync."""

        values = tuple(islice(ticks, self._GROUP_COMMIT_LIMIT + 1))
        if self._write_poisoned:
            raise DurableStateError("verified tick stream writer is poisoned")
        if len(values) > self._GROUP_COMMIT_LIMIT:
            raise BackpressureError("durable acknowledgement group capacity exhausted")
        if not values:
            return ()
        for tick in values:
            if tick.stream_generation != self.generation:
                raise GenerationMismatch("acknowledgement generation mismatch")
            if tick.event_hash != tick.compute_event_hash():
                raise DurableCorruptionError("acknowledgement source hash mismatch")
        with self._lock, self._process_lock():
            state = self.watermark.read()
            if self._indexed_watermark_seq != int(state.get("last_ingest_seq") or 0):
                # Another producer may have advanced the stream while this
                # writer object was idle.  Revalidate its complete durable
                # frontier before binding an acknowledgement to any tick.
                self._index = None
                self.acknowledgements._values = None  # type: ignore[attr-defined]
                self.acknowledgements._records = None  # type: ignore[attr-defined]
            index = self._load_index_unlocked()
            self._refresh_ack_frontier_if_changed_unlocked()
            results: list[bool] = []
            pending: list[tuple[VerifiedTick, dict[str, object]]] = []
            staged: dict[str, dict[str, object]] = {}
            for tick in values:
                persisted = index.get(tick.ingest_id)
                if persisted is None and self._ingest_membership.may_contain(
                    tick.ingest_id
                ):
                    persisted = self._exact_tick_unlocked(
                        lambda item, identity=tick.ingest_id: item.ingest_id == identity
                    )
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
                expected = {
                    "ingest_id": tick.ingest_id,
                    "stream_generation": tick.stream_generation,
                    "ingest_seq": tick.ingest_seq,
                    "event_hash": tick.event_hash,
                }
                prior = staged.get(tick.ingest_id)
                if prior is None and self._ack_membership.may_contain(tick.ingest_id):
                    prior = self._exact_acknowledgement_unlocked(tick)
                if prior is not None:
                    if prior != expected:
                        raise DuplicateRecordError(
                            f"append-only set identity conflict: {tick.ingest_id}"
                        )
                    results.append(False)
                    continue
                if tick.ingest_seq <= self._ack_frontier:
                    results.append(False)
                    continue
                staged[tick.ingest_id] = expected
                pending.append((tick, expected))
                results.append(True)
            if self._ack_membership.count + len(pending) > self._ack_membership._CAPACITY:
                raise BackpressureError("durable membership filter capacity exhausted")
            frontier = self._ack_frontier
            sparse = set(self._ack_sparse)
            for tick, _ in sorted(pending, key=lambda item: item[0].ingest_seq):
                if tick.ingest_seq == frontier + 1:
                    frontier += 1
                    while frontier + 1 in sparse:
                        sparse.remove(frontier + 1)
                        frontier += 1
                elif tick.ingest_seq > frontier and tick.ingest_seq not in sparse:
                    if len(sparse) >= self._ACK_SPARSE_LIMIT:
                        raise BackpressureError(
                            "durable acknowledgement sparse frontier exhausted"
                        )
                    sparse.add(tick.ingest_seq)
            try:
                self.acknowledgements.journal.append_many(
                    expected
                    for _, expected in sorted(
                        pending, key=lambda item: item[0].ingest_seq
                    )
                )
            except Exception:
                self._write_poisoned = True
                raise
            self._ack_fingerprint = self.acknowledgements.journal.fingerprint()
            for tick, _ in pending:
                self._ack_membership.note_identity()
                self._ack_membership.add(tick.ingest_id)
            self._ack_count += len(pending)
            self._ack_frontier = frontier
            self._ack_sparse = sparse
            return tuple(results)

    def stats(self) -> dict[str, object]:
        with self._lock:
            self._load_index()
            return {
                "stream_generation": self.generation,
                "events": self._event_count,
                "last_ingest_seq": self._indexed_watermark_seq,
                "pending_writer_acks": self._event_count - self._ack_count,
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

    def put_front_many(self, values: Iterable[T]) -> None:
        """Return a predrained failure suffix without reordering or loss."""

        items = tuple(values)
        if not items:
            return
        queue = self._queue
        with queue.mutex:
            if queue.maxsize > 0 and queue._qsize() + len(items) > queue.maxsize:
                raise BackpressureError("bounded ingress queue is full")
            for value in reversed(items):
                queue.queue.appendleft(value)
            queue.unfinished_tasks += len(items)
            queue.not_empty.notify_all()

    def qsize(self) -> int:
        return self._queue.qsize()
