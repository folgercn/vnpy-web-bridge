"""Read authenticated formal CTP ticks from the durable market-data projection.

This module is deliberately a local, read-only verifier.  It has no gateway,
RPC, database, subscriber, or network dependency and never creates or repairs
durable state.  A caller names one exact contract and price side; the returned
binding is anchored to the canonical verified-tick journal, writer
acknowledgement, producer watermark, source fence, and healthy projection.
"""

from __future__ import annotations

import os
import re
import stat
import time
import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

FORMAL_TICK_SOURCE = "windows-tick-wire-v1"
_PHASE_B_CONTRACT_VERSION = "phase_b_worker_contract_v1"
_PROJECTION_SCHEMA_VERSION = "phase-b-worker-projection-v1"
FORMAL_TICK_TAIL_BYTES = 512 * 1024
FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS = 1.0
FORMAL_TICK_SNAPSHOT_RETRY_SECONDS = 0.05
FORMAL_TICK_MAX_AGE_SECONDS = 2.0
FORMAL_TICK_FUTURE_SKEW_SECONDS = 2.0
_FORMAL_CHECKPOINT_MAX_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PRICE_SIDES = frozenset({"last", "bid", "ask"})

PriceSide = Literal["last", "bid", "ask"]
LegacyTickBinding = tuple[str, str, int, str, str, float]


class DurableStateError(RuntimeError):
    """Read-only durable state cannot be authenticated."""


class DurableCorruptionError(DurableStateError):
    """A read-only durable artifact is malformed or unsafe."""


class _SourceUnavailableError(DurableStateError):
    """A required read-only source or mount is temporarily unavailable."""


class ProjectionError(ValueError):
    """The market-data projection fails its strict read contract."""


class FormalTickReadError(ValueError):
    """Stable error contract for a later Runtime admission mapping."""

    code = "FORMAL_TICK_READ_FAILED"
    retryable = False


class FormalTickSourceUnavailable(FormalTickReadError):
    code = "SOURCE_UNAVAILABLE"
    retryable = True


class FormalTickEvidenceInvalid(FormalTickReadError):
    code = "EVIDENCE_INVALID"
    retryable = False


class RetryableFormalTickTail(DurableCorruptionError):
    """The bounded tail ended while a writer was appending its final record."""


@dataclass(frozen=True, slots=True)
class FormalTickRequest:
    """Strict input contract for one exact formal quote observation."""

    vt_symbol: str
    price_side: PriceSide
    price_tick: float

    def __post_init__(self) -> None:
        _require_vt_symbol(self.vt_symbol)
        _require_price_side(self.price_side)
        _require_positive_finite(self.price_tick, label="formal CTP price tick")


@dataclass(frozen=True, slots=True)
class FormalTickBinding:
    """One exact-contract quote bound to authenticated durable journal state."""

    source: str
    vt_symbol: str
    price_side: PriceSide
    price_tick: float
    stream_generation: str
    ingest_id: str
    ingest_seq: int
    event_hash: str
    received_at_utc: str
    reference_price: float

    def __post_init__(self) -> None:
        if self.source != FORMAL_TICK_SOURCE:
            raise ValueError("formal CTP tick source is invalid")
        _require_vt_symbol(self.vt_symbol)
        _require_price_side(self.price_side)
        tick = _require_positive_finite(self.price_tick, label="formal CTP price tick")
        price = _require_positive_finite(
            self.reference_price, label="formal CTP tick reference price"
        )
        if (
            not isinstance(self.stream_generation, str)
            or not self.stream_generation
            or not isinstance(self.ingest_id, str)
            or not self.ingest_id
        ):
            raise ValueError("formal CTP tick identity is invalid")
        if (
            isinstance(self.ingest_seq, bool)
            or not isinstance(self.ingest_seq, int)
            or self.ingest_seq < 1
        ):
            raise ValueError("formal CTP tick sequence is invalid")
        if not isinstance(self.event_hash, str) or not _SHA256_RE.fullmatch(
            self.event_hash
        ):
            raise ValueError("formal CTP tick event hash is invalid")
        _parse_explicit_utc(self.received_at_utc, label="formal CTP tick")
        try:
            quotient = Decimal(str(price)) / Decimal(str(tick))
        except (InvalidOperation, ZeroDivisionError) as exc:
            raise ValueError("formal CTP tick is not aligned to price tick") from exc
        if quotient != quotient.to_integral_value():
            raise ValueError("formal CTP tick is not aligned to price tick")

    def as_legacy_tuple(self) -> LegacyTickBinding:
        return (
            self.stream_generation,
            self.ingest_id,
            self.ingest_seq,
            self.event_hash,
            self.received_at_utc,
            self.reference_price,
        )

    def as_dict(self) -> dict[str, object]:
        """Return the exact TargetPlan-v3 formal quote binding payload."""

        return {
            "source": self.source,
            "vt_symbol": self.vt_symbol,
            "price_side": self.price_side,
            "stream_generation": self.stream_generation,
            "ingest_id": self.ingest_id,
            "ingest_seq": self.ingest_seq,
            "event_hash": self.event_hash,
            "received_at_utc": self.received_at_utc,
            "reference_price": self.reference_price,
            "price_tick": self.price_tick,
        }


@dataclass(frozen=True, slots=True)
class _ObservedFormalTick:
    source: str
    vt_symbol: str
    price_side: PriceSide
    stream_generation: str
    ingest_id: str
    ingest_seq: int
    event_hash: str
    received_at_utc: str
    reference_price: float

    def as_legacy_tuple(self) -> LegacyTickBinding:
        return (
            self.stream_generation,
            self.ingest_id,
            self.ingest_seq,
            self.event_hash,
            self.received_at_utc,
            self.reference_price,
        )


def _require_vt_symbol(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("formal CTP tick contract is invalid")
    return value


def _require_price_side(value: object) -> PriceSide:
    if value not in _PRICE_SIDES:
        raise ValueError("formal CTP tick reference price is invalid")
    return value  # type: ignore[return-value]


def _require_positive_finite(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} is invalid")
    normalized = float(value)
    if not 0 < normalized < float("inf"):
        raise ValueError(f"{label} is invalid")
    return normalized


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _parse_json_time(value: object) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _isoformat(value: object) -> str:
    return _parse_json_time(value).isoformat().replace("+00:00", "Z")


def _number(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        normalized = float(value)
    except (TypeError, ValueError):
        return None
    return normalized if math.isfinite(normalized) else None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON constant is forbidden: {value}")


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
    if not isinstance(value, dict) or _canonical_json(value) + "\n" != raw:
        raise DurableCorruptionError(f"noncanonical JSONL at {path}{suffix}")
    return value


def _ensure_parent(path: Path) -> tuple[Path, os.stat_result]:
    parent = Path(path).parent
    try:
        info = parent.lstat()
    except OSError as exc:
        raise _SourceUnavailableError(
            f"durable parent is unavailable: {parent}"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
    ):
        raise DurableCorruptionError(f"durable parent is not a directory: {parent}")
    if info.st_mode & 0o077:
        raise DurableCorruptionError(f"durable parent permissions are unsafe: {parent}")
    return parent, info


def _open_parent(path: Path) -> tuple[int, os.stat_result]:
    """Pin every concrete parent component without following symlinks."""

    parent, expected = _ensure_parent(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if (
        os.open not in os.supports_dir_fd
        or not getattr(os, "O_DIRECTORY", 0)
        or not getattr(os, "O_NOFOLLOW", 0)
    ):
        raise DurableCorruptionError("durable dirfd O_NOFOLLOW support is required")
    flags |= os.O_NOFOLLOW
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
        or current.st_gid != os.getegid()
        or current.st_mode & 0o077
    ):
        os.close(descriptor)
        raise DurableCorruptionError(f"durable parent permissions are unsafe: {parent}")
    return descriptor, current


def _read_checkpoint(path: Path) -> dict[str, object]:
    """Read one canonical checkpoint without exposing any writer operation."""

    path = Path(os.path.abspath(path))
    parent_fd, _ = _open_parent(path)
    descriptor = -1
    try:
        destination = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(destination.st_mode):
            raise DurableCorruptionError(f"invalid checkpoint {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if (
            not _safe_bounded_tail_info(info)
            or (info.st_dev, info.st_ino) != (destination.st_dev, destination.st_ino)
            or info.st_size < 1
            or info.st_size > _FORMAL_CHECKPOINT_MAX_BYTES
        ):
            raise DurableCorruptionError(f"invalid checkpoint {path}")
        raw = _read_exact_checkpoint(descriptor, size=info.st_size)
        for _ in range(2):
            after = os.fstat(descriptor)
            named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_checkpoint_file(info, after) or not _same_checkpoint_file(
                info, named_after
            ):
                raise DurableCorruptionError(f"invalid checkpoint {path}")
            if _read_exact_checkpoint(descriptor, size=info.st_size) != raw:
                raise DurableCorruptionError(f"invalid checkpoint {path}")
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_checkpoint_file(info, after) or not _same_checkpoint_file(
            info, named_after
        ):
            raise DurableCorruptionError(f"invalid checkpoint {path}")
        raw = raw.decode("utf-8")
        return _strict_json_line(raw, path)
    except (FileNotFoundError, PermissionError) as exc:
        raise _SourceUnavailableError(f"checkpoint is unavailable: {path}") from exc
    except (OSError, UnicodeDecodeError, DurableCorruptionError) as exc:
        raise DurableCorruptionError(f"invalid checkpoint {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _read_exact_checkpoint(descriptor: int, *, size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < size:
        chunk = os.read(descriptor, size - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) != size:
        raise DurableCorruptionError("checkpoint changed during bounded read")
    return bytes(raw)


def _same_checkpoint_file(initial: os.stat_result, current: os.stat_result) -> bool:
    return (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        current.st_size,
    ) == (
        initial.st_dev,
        initial.st_ino,
        initial.st_mode,
        initial.st_uid,
        initial.st_gid,
        initial.st_nlink,
        initial.st_size,
    ) and _safe_bounded_tail_info(current)


def _parse_explicit_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} timestamp must be explicit UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} timestamp is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} timestamp must be explicit UTC")
    return parsed


def _safe_bounded_tail_info(info: os.stat_result) -> bool:
    return (
        not stat.S_ISLNK(info.st_mode)
        and stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and info.st_nlink == 1
        and not info.st_mode & 0o077
    )


def _same_bounded_tail_file(initial: os.stat_result, current: os.stat_result) -> bool:
    return (
        (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_uid,
            current.st_gid,
            current.st_nlink,
        )
        == (
            initial.st_dev,
            initial.st_ino,
            initial.st_mode,
            initial.st_uid,
            initial.st_gid,
            initial.st_nlink,
        )
        and current.st_size >= initial.st_size
        and _safe_bounded_tail_info(current)
    )


@dataclass(frozen=True, slots=True)
class _VerifiedTick:
    stream_generation: str
    ingest_id: str
    ingest_seq: int
    event_time_utc: str
    vt_symbol: str
    source: str
    source_event_id: str
    received_at_utc: str
    bid_price: float | None = None
    ask_price: float | None = None
    last_price: float | None = None
    bid_volume: float | None = None
    ask_volume: float | None = None
    last_volume: float | None = None
    raw_hash: str = ""
    event_hash: str = ""

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> _VerifiedTick:
        expected = {"contract_version", *cls.__dataclass_fields__}
        if (
            set(value) != expected
            or value.get("contract_version") != _PHASE_B_CONTRACT_VERSION
        ):
            raise ValueError("verified tick contract mismatch")
        sequence = value["ingest_seq"]
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise TypeError("verified tick ingest sequence is invalid")
        tick = cls(
            stream_generation=str(value["stream_generation"]),
            ingest_id=str(value["ingest_id"]),
            ingest_seq=sequence,
            event_time_utc=_isoformat(value["event_time_utc"]),
            vt_symbol=str(value["vt_symbol"]),
            source=str(value.get("source") or "readonly_market_source"),
            source_event_id=str(value.get("source_event_id") or ""),
            received_at_utc=_isoformat(
                value.get("received_at_utc") or value["event_time_utc"]
            ),
            bid_price=_number(value.get("bid_price")),
            ask_price=_number(value.get("ask_price")),
            last_price=_number(value.get("last_price")),
            bid_volume=_number(value.get("bid_volume")),
            ask_volume=_number(value.get("ask_volume")),
            last_volume=_number(value.get("last_volume")),
            raw_hash=str(value.get("raw_hash") or ""),
            event_hash=str(value["event_hash"]),
        )
        if (
            not tick.stream_generation
            or not tick.ingest_id
            or tick.ingest_seq < 1
            or not tick.vt_symbol
            or not tick.source
            or not _SHA256_RE.fullmatch(tick.raw_hash)
            or not _SHA256_RE.fullmatch(tick.event_hash)
            or tick.event_hash != tick.compute_event_hash()
        ):
            raise ValueError("verified tick identity/hash is invalid")
        return tick

    def body(self) -> dict[str, object]:
        return {
            "contract_version": _PHASE_B_CONTRACT_VERSION,
            "stream_generation": self.stream_generation,
            "ingest_id": self.ingest_id,
            "ingest_seq": self.ingest_seq,
            "event_time_utc": self.event_time_utc,
            "vt_symbol": self.vt_symbol,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "received_at_utc": self.received_at_utc,
            "bid_price": self.bid_price,
            "ask_price": self.ask_price,
            "last_price": self.last_price,
            "bid_volume": self.bid_volume,
            "ask_volume": self.ask_volume,
            "last_volume": self.last_volume,
            "raw_hash": self.raw_hash,
        }

    def compute_event_hash(self) -> str:
        return _sha256_json(self.body())


def _read_bounded_range(descriptor: int, *, offset: int, length: int) -> bytes:
    os.lseek(descriptor, offset, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < length:
        chunk = os.read(descriptor, length - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) != length:
        raise DurableCorruptionError("verified tick journal shrank during tail read")
    return bytes(raw)


def _bounded_jsonl_tail(
    path: Path,
    *,
    tail_bytes: int = FORMAL_TICK_TAIL_BYTES,
    read_range: Callable[..., bytes] = _read_bounded_range,
) -> list[dict[str, object]]:
    """Read a stable, bounded JSONL tail while allowing concurrent appends."""

    parent_fd, _ = _open_parent(path)
    descriptor = -1
    raw = b""
    offset = 0
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        destination = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _safe_bounded_tail_info(destination):
            raise DurableCorruptionError("verified tick journal is unsafe")
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if not _safe_bounded_tail_info(info) or (info.st_dev, info.st_ino) != (
            destination.st_dev,
            destination.st_ino,
        ):
            raise DurableCorruptionError("verified tick journal is unsafe")
        offset = max(0, info.st_size - tail_bytes)
        length = info.st_size - offset
        raw = read_range(descriptor, offset=offset, length=length)
        for _ in range(2):
            descriptor_info = os.fstat(descriptor)
            named_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_bounded_tail_file(
                info, descriptor_info
            ) or not _same_bounded_tail_file(info, named_info):
                raise DurableCorruptionError(
                    "verified tick journal changed during tail read"
                )
            if read_range(descriptor, offset=offset, length=length) != raw:
                raise DurableCorruptionError(
                    "verified tick journal changed during tail read"
                )
        descriptor_info = os.fstat(descriptor)
        named_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_bounded_tail_file(
            info, descriptor_info
        ) or not _same_bounded_tail_file(info, named_info):
            raise DurableCorruptionError(
                "verified tick journal changed during tail read"
            )
    except (FileNotFoundError, PermissionError) as exc:
        raise _SourceUnavailableError("verified tick journal is unavailable") from exc
    except OSError as exc:
        raise DurableCorruptionError("cannot read verified tick journal tail") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
    if not raw:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DurableCorruptionError(
            "invalid UTF-8 verified tick journal tail"
        ) from exc
    lines = text.splitlines(keepends=True)
    if offset:
        if not lines or not lines[0].endswith("\n"):
            raise DurableCorruptionError("verified tick tail has no complete record")
        lines = lines[1:]
    if lines and not lines[-1].endswith("\n"):
        raise RetryableFormalTickTail("verified tick tail has a partial record")
    return [_strict_json_line(line, path) for line in lines]


def _bounded_verified_tick_tail(
    path: Path,
    *,
    tail_reader: Callable[[Path], list[dict[str, object]]] = _bounded_jsonl_tail,
) -> list[_VerifiedTick]:
    ticks: list[_VerifiedTick] = []
    for record in tail_reader(path):
        if (
            set(record) != {"record_type", "tick"}
            or record.get("record_type") != "verified_tick"
        ):
            raise DurableCorruptionError("verified tick tail record is invalid")
        try:
            ticks += [_VerifiedTick.from_dict(record["tick"])]  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise DurableCorruptionError(
                "verified tick tail contract is invalid"
            ) from exc
    return ticks


def _validate_projection(
    value: Mapping[str, object], *, expected_service_id: str
) -> dict[str, object]:
    if (
        set(value)
        != {
            "schema_version",
            "service_id",
            "generation",
            "projected_at_utc",
            "payload",
            "payload_sha256",
            "production",
            "live",
            "countable_forward",
        }
        or value.get("schema_version") != _PROJECTION_SCHEMA_VERSION
    ):
        raise ProjectionError("PROJECTION_SCHEMA_INVALID")
    if value.get("service_id") != expected_service_id:
        raise ProjectionError("PROJECTION_SERVICE_ID_MISMATCH")
    generation = value.get("generation")
    if not isinstance(generation, str) or not generation:
        raise ProjectionError("PROJECTION_GENERATION_INVALID")
    if any(
        value.get(flag) is not False
        for flag in ("production", "live", "countable_forward")
    ):
        raise ProjectionError("PROJECTION_AUTHORITY_INVALID")
    payload = value.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != {
        "health",
        "readiness",
        "version",
    }:
        raise ProjectionError("PROJECTION_PAYLOAD_INVALID")
    payload_hash = value.get("payload_sha256")
    if (
        not isinstance(payload_hash, str)
        or not _SHA256_RE.fullmatch(payload_hash)
        or payload_hash != _sha256_json(payload)
    ):
        raise ProjectionError("PROJECTION_HASH_MISMATCH")
    for key in ("health", "readiness", "version"):
        nested = payload[key]
        if (
            not isinstance(nested, Mapping)
            or nested.get("service_id") != expected_service_id
        ):
            raise ProjectionError("PROJECTION_SERVICE_ID_MISMATCH")
    version = payload["version"]
    contract_versions = version.get("contract_versions")
    if (
        not isinstance(contract_versions, list)
        or _PHASE_B_CONTRACT_VERSION not in contract_versions
    ):
        raise ProjectionError("PROJECTION_VERSION_INVALID")
    observed = _parse_json_time(value.get("projected_at_utc"))
    age = (datetime.now(timezone.utc) - observed).total_seconds()
    if age < -5.0 or age > 60.0:
        raise ProjectionError("PROJECTION_STALE")
    return dict(value)


def _formal_market_checkpoint(
    *, state_dir: Path, projection_dir: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    projection = _read_checkpoint(projection_dir / "market-data-worker.json")
    projection = _validate_projection(
        projection, expected_service_id="market-data-worker"
    )
    payload = projection["payload"]
    health = payload.get("health") if isinstance(payload, Mapping) else None
    readiness = payload.get("readiness") if isinstance(payload, Mapping) else None
    dependencies = health.get("dependencies") if isinstance(health, Mapping) else None
    stream = (
        dependencies.get("verified_stream")
        if isinstance(dependencies, Mapping)
        else None
    )
    if (
        not isinstance(health, Mapping)
        or health.get("status") != "healthy"
        or not isinstance(readiness, Mapping)
        or readiness.get("ready") is not True
        or not isinstance(stream, Mapping)
        or set(stream)
        != {
            "stream_generation",
            "events",
            "last_ingest_seq",
            "pending_writer_acks",
        }
        or not isinstance(stream.get("stream_generation"), str)
        or not stream["stream_generation"]
        or isinstance(stream.get("last_ingest_seq"), bool)
        or not isinstance(stream.get("last_ingest_seq"), int)
        or stream["last_ingest_seq"] < 1
        or isinstance(stream.get("events"), bool)
        or not isinstance(stream.get("events"), int)
        or stream["events"] != stream["last_ingest_seq"]
        or stream.get("pending_writer_acks") != 0
    ):
        raise ValueError("formal CTP market projection is not ready")
    watermark = _read_checkpoint(state_dir / "stream" / "producer_watermark.json")
    generation = watermark.get("stream_generation")
    if (
        not isinstance(generation, str)
        or not generation
        or isinstance(watermark.get("last_ingest_seq"), bool)
        or not isinstance(watermark.get("last_ingest_seq"), int)
        or watermark["last_ingest_seq"] < 1
        or not isinstance(watermark.get("last_event_hash"), str)
        or not _SHA256_RE.fullmatch(watermark["last_event_hash"])
        or stream["stream_generation"] != generation
        or stream["last_ingest_seq"] > watermark["last_ingest_seq"]
    ):
        raise ValueError("formal CTP watermark/projection is invalid")
    fence = _read_checkpoint(state_dir / "source_fence.json")
    sources = fence.get("sources") if isinstance(fence, Mapping) else None
    source = sources.get(FORMAL_TICK_SOURCE) if isinstance(sources, Mapping) else None
    if (
        not isinstance(source, Mapping)
        or fence.get("worker_generation") != generation
        or not isinstance(source.get("generation"), str)
        or not source["generation"]
        or isinstance(source.get("seq"), bool)
        or not isinstance(source.get("seq"), int)
        or source["seq"] < 1
        or not isinstance(source.get("event_hash"), str)
        or not _SHA256_RE.fullmatch(source["event_hash"])
    ):
        raise ValueError("formal CTP source fence is invalid")
    return projection, watermark, fence


def _wait_for_formal_snapshot(
    deadline: float, *, retry_seconds: float = FORMAL_TICK_SNAPSHOT_RETRY_SECONDS
) -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    time.sleep(min(retry_seconds, remaining))
    return True


def _checkpoint_progressed(
    before_watermark: Mapping[str, Any],
    before_fence: Mapping[str, Any],
    after_watermark: Mapping[str, Any],
    after_fence: Mapping[str, Any],
) -> bool:
    """Permit append-only progress, but never a changed or regressed anchor."""

    generation = before_watermark["stream_generation"]
    if after_watermark["stream_generation"] != generation:
        return False
    before_sequence = before_watermark["last_ingest_seq"]
    after_sequence = after_watermark["last_ingest_seq"]
    if after_sequence < before_sequence:
        return False
    if (
        after_sequence == before_sequence
        and after_watermark["last_event_hash"] != before_watermark["last_event_hash"]
    ):
        return False
    before_source = before_fence["sources"][FORMAL_TICK_SOURCE]
    after_source = after_fence["sources"][FORMAL_TICK_SOURCE]
    if after_source["generation"] != before_source["generation"]:
        return False
    before_fence_sequence = before_source["seq"]
    after_fence_sequence = after_source["seq"]
    return not (
        after_fence_sequence < before_fence_sequence
        or (
            after_fence_sequence == before_fence_sequence
            and after_source["event_hash"] != before_source["event_hash"]
        )
    )


def _read_observed_formal_ticks(
    *,
    state_dir: Path,
    projection_dir: Path,
    clock: Callable[[], datetime],
    requests: tuple[tuple[str, PriceSide], ...],
    max_age_seconds: float = FORMAL_TICK_MAX_AGE_SECONDS,
    future_skew_seconds: float = FORMAL_TICK_FUTURE_SKEW_SECONDS,
    snapshot_max_wait_seconds: float = FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS,
    checkpoint_reader: Callable[
        [], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ]
    | None = None,
    verified_tail_reader: Callable[[Path], list[_VerifiedTick]] | None = None,
    jsonl_tail_reader: Callable[[Path], list[dict[str, object]]] | None = None,
    snapshot_waiter: Callable[[float], bool] | None = None,
    checkpoint_progress: Callable[
        [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
        bool,
    ] = _checkpoint_progressed,
    strict_snapshot: bool = False,
) -> tuple[_ObservedFormalTick, ...]:
    """Authenticate an exact contract set inside one stable checkpoint window."""

    if not requests:
        raise FormalTickEvidenceInvalid("formal CTP tick request set is invalid")
    normalized_requests = tuple(
        (_require_vt_symbol(symbol), _require_price_side(side))
        for symbol, side in requests
    )
    state_dir = Path(state_dir)
    projection_dir = Path(projection_dir)
    checkpoint_reader = checkpoint_reader or (
        lambda: _formal_market_checkpoint(
            state_dir=state_dir, projection_dir=projection_dir
        )
    )
    verified_tail_reader = verified_tail_reader or _bounded_verified_tick_tail
    jsonl_tail_reader = jsonl_tail_reader or _bounded_jsonl_tail
    snapshot_waiter = snapshot_waiter or _wait_for_formal_snapshot

    try:
        selected_ticks: tuple[_VerifiedTick, ...] = ()
        deadline = time.monotonic() + snapshot_max_wait_seconds
        while True:
            try:
                before_projection, before_watermark, before_fence = checkpoint_reader()
            except ValueError as exc:
                if str(exc) != "formal CTP watermark/projection is invalid":
                    raise
                if not snapshot_waiter(deadline):
                    raise
                continue
            generation = before_watermark["stream_generation"]
            frontier = before_watermark["last_ingest_seq"]
            try:
                tail_ticks = verified_tail_reader(
                    state_dir / "stream" / "verified_ticks.jsonl"
                )
                acknowledgements = jsonl_tail_reader(
                    state_dir / "stream" / "tick_writer_acks.jsonl"
                )
            except RetryableFormalTickTail as exc:
                if not snapshot_waiter(deadline):
                    raise _SourceUnavailableError(
                        "formal CTP journal append did not stabilize"
                    ) from exc
                continue
            frontier_tick = next(
                (
                    item
                    for item in reversed(tail_ticks)
                    if item.stream_generation == generation
                    and item.ingest_seq == frontier
                    and item.event_hash == before_watermark["last_event_hash"]
                ),
                None,
            )
            if frontier_tick is None:
                raise ValueError("formal CTP verified journal tail is invalid")
            selected: list[_VerifiedTick] = []
            for symbol, _side in normalized_requests:
                tick = next(
                    (
                        item
                        for item in reversed(tail_ticks)
                        if item.source == FORMAL_TICK_SOURCE
                        and item.vt_symbol == symbol
                        and item.stream_generation == generation
                        and item.ingest_seq <= frontier
                    ),
                    None,
                )
                if tick is None:
                    raise ValueError("formal CTP tick is unavailable")
                selected += [tick]
            selected_ticks = tuple(selected)
            expected_sequence: int | None = None
            for record in acknowledgements:
                if (
                    set(record)
                    != {"ingest_id", "stream_generation", "ingest_seq", "event_hash"}
                    or record.get("stream_generation") != generation
                    or isinstance(record.get("ingest_seq"), bool)
                    or not isinstance(record.get("ingest_seq"), int)
                    or record["ingest_seq"] < 1
                    or not isinstance(record.get("ingest_id"), str)
                    or not record["ingest_id"]
                    or not isinstance(record.get("event_hash"), str)
                    or not _SHA256_RE.fullmatch(record["event_hash"])
                ):
                    raise ValueError("formal CTP acknowledgement tail is invalid")
                if record["ingest_seq"] > frontier:
                    continue
                if expected_sequence is None:
                    expected_sequence = record["ingest_seq"]
                if record["ingest_seq"] != expected_sequence:
                    raise ValueError(
                        "formal CTP acknowledgement tail is not contiguous"
                    )
                expected_sequence += 1
            required_acknowledgements = (
                {
                    "ingest_id": frontier_tick.ingest_id,
                    "stream_generation": generation,
                    "ingest_seq": frontier,
                    "event_hash": frontier_tick.event_hash,
                },
                *(
                    {
                        "ingest_id": tick.ingest_id,
                        "stream_generation": generation,
                        "ingest_seq": tick.ingest_seq,
                        "event_hash": tick.event_hash,
                    }
                    for tick in selected_ticks
                ),
            )
            if not acknowledgements or any(
                required not in acknowledgements
                for required in required_acknowledgements
            ):
                raise ValueError("formal CTP acknowledgement tail is invalid")
            try:
                after_projection, after_watermark, after_fence = checkpoint_reader()
            except ValueError as exc:
                if str(exc) != "formal CTP watermark/projection is invalid":
                    raise
                if not snapshot_waiter(deadline):
                    raise
                continue
            snapshot_stable = (
                before_projection == after_projection
                and before_watermark == after_watermark
                and before_fence == after_fence
            )
            if strict_snapshot and snapshot_stable:
                break
            if not strict_snapshot and checkpoint_progress(
                before_watermark, before_fence, after_watermark, after_fence
            ):
                break
            raise ValueError("formal CTP durable tick state changed during validation")
    except FormalTickReadError:
        raise
    except _SourceUnavailableError as exc:
        raise FormalTickSourceUnavailable(
            "formal CTP durable tick source is unavailable"
        ) from exc
    except (OSError, ProjectionError, TypeError, ValueError, DurableStateError) as exc:
        raise FormalTickEvidenceInvalid(
            "formal CTP durable tick state is invalid"
        ) from exc

    now = clock()
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise FormalTickEvidenceInvalid("tick clock must be explicit UTC")
    observed: list[_ObservedFormalTick] = []
    for tick, (symbol, side) in zip(selected_ticks, normalized_requests, strict=True):
        if tick.source != FORMAL_TICK_SOURCE:
            raise FormalTickEvidenceInvalid("formal CTP tick source is invalid")
        if tick.vt_symbol != symbol:
            raise FormalTickEvidenceInvalid("formal CTP tick contract is invalid")
        received_at = _parse_explicit_utc(tick.received_at_utc, label="formal CTP tick")
        age = (now - received_at).total_seconds()
        if age < -future_skew_seconds or age > max_age_seconds:
            raise FormalTickEvidenceInvalid(
                "formal CTP tick is stale or from the future"
            )
        try:
            price = _require_positive_finite(
                getattr(tick, f"{side}_price"),
                label="formal CTP tick reference price",
            )
        except ValueError as exc:
            raise FormalTickEvidenceInvalid(str(exc)) from exc
        observed += [
            _ObservedFormalTick(
                source=tick.source,
                vt_symbol=tick.vt_symbol,
                price_side=side,
                stream_generation=tick.stream_generation,
                ingest_id=tick.ingest_id,
                ingest_seq=tick.ingest_seq,
                event_hash=tick.event_hash,
                received_at_utc=tick.received_at_utc,
                reference_price=price,
            )
        ]
    return tuple(observed)


def _read_observed_formal_tick(
    *,
    state_dir: Path,
    projection_dir: Path,
    clock: Callable[[], datetime],
    vt_symbol: str,
    price_side: PriceSide,
    max_age_seconds: float = FORMAL_TICK_MAX_AGE_SECONDS,
    future_skew_seconds: float = FORMAL_TICK_FUTURE_SKEW_SECONDS,
    snapshot_max_wait_seconds: float = FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS,
    checkpoint_reader: Callable[
        [], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ]
    | None = None,
    verified_tail_reader: Callable[[Path], list[_VerifiedTick]] | None = None,
    jsonl_tail_reader: Callable[[Path], list[dict[str, object]]] | None = None,
    snapshot_waiter: Callable[[float], bool] | None = None,
    checkpoint_progress: Callable[
        [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
        bool,
    ] = _checkpoint_progressed,
) -> _ObservedFormalTick:
    """Legacy single-binding facade over the stable set reader."""

    return _read_observed_formal_ticks(
        state_dir=state_dir,
        projection_dir=projection_dir,
        clock=clock,
        requests=((vt_symbol, price_side),),
        max_age_seconds=max_age_seconds,
        future_skew_seconds=future_skew_seconds,
        snapshot_max_wait_seconds=snapshot_max_wait_seconds,
        checkpoint_reader=checkpoint_reader,
        verified_tail_reader=verified_tail_reader,
        jsonl_tail_reader=jsonl_tail_reader,
        snapshot_waiter=snapshot_waiter,
        checkpoint_progress=checkpoint_progress,
        strict_snapshot=False,
    )[0]


def read_formal_tick_binding(
    request: FormalTickRequest,
    *,
    state_dir: Path = Path("/run/market-data"),
    projection_dir: Path = Path("/run/market-projection"),
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> FormalTickBinding:
    """Return one verified, fresh, price-tick-aligned exact-contract binding."""

    return read_formal_tick_bindings(
        (request,),
        state_dir=state_dir,
        projection_dir=projection_dir,
        clock=clock,
    )[0]


def read_formal_tick_bindings(
    requests: tuple[FormalTickRequest, ...],
    *,
    state_dir: Path = Path("/run/market-data"),
    projection_dir: Path = Path("/run/market-projection"),
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> tuple[FormalTickBinding, ...]:
    """Read exactly the requested contract set, preserving caller order."""

    if (
        not isinstance(requests, tuple)
        or not requests
        or any(not isinstance(item, FormalTickRequest) for item in requests)
    ):
        raise TypeError("formal CTP tick request set is invalid")
    symbols = tuple(item.vt_symbol for item in requests)
    if len(set(symbols)) != len(symbols):
        raise ValueError("formal CTP tick request set has duplicate contracts")
    observed = _read_observed_formal_ticks(
        state_dir=state_dir,
        projection_dir=projection_dir,
        clock=clock,
        requests=tuple((item.vt_symbol, item.price_side) for item in requests),
        strict_snapshot=True,
    )
    try:
        return tuple(
            FormalTickBinding(
                source=item.source,
                vt_symbol=item.vt_symbol,
                price_side=item.price_side,
                price_tick=request.price_tick,
                stream_generation=item.stream_generation,
                ingest_id=item.ingest_id,
                ingest_seq=item.ingest_seq,
                event_hash=item.event_hash,
                received_at_utc=item.received_at_utc,
                reference_price=item.reference_price,
            )
            for request, item in zip(requests, observed, strict=True)
        )
    except ValueError as exc:
        raise FormalTickEvidenceInvalid(str(exc)) from exc


def require_tick_fresh(
    binding: LegacyTickBinding,
    *,
    clock: Callable[[], datetime],
    max_age_seconds: float = FORMAL_TICK_MAX_AGE_SECONDS,
    future_skew_seconds: float = FORMAL_TICK_FUTURE_SKEW_SECONDS,
) -> None:
    now = clock()
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValueError("tick clock must be explicit UTC")
    received_at = _parse_explicit_utc(binding[4], label="formal CTP tick")
    age = (now - received_at).total_seconds()
    if age < -future_skew_seconds or age > max_age_seconds:
        raise ValueError("formal CTP tick is stale or from the future")


def require_current_tick_binding(
    expected: LegacyTickBinding, observed: LegacyTickBinding
) -> None:
    if observed[0] != expected[0] or observed[2] < expected[2]:
        raise ValueError("formal CTP tick generation or sequence regressed")
    if observed[2] == expected[2] and observed != expected:
        raise ValueError("formal CTP tick changed before pilot mutation")
