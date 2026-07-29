from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionQualityCollectionPolicyV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
    CFastVirtualIntentPlanDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
    CFastExecutionQualityScoreDTO,
    CFastL1L5BookSnapshotDTO,
)
from app.services.commodity_c_fast_execution_quality_scorer import (
    CFastExecutionQualityScorerError,
    reload_and_verify_execution_quality_score,
    score_execution_quality,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


MAX_JOURNAL_RECORD_BYTES = 16 * 1024 * 1024
_RECORD_NAME = re.compile(r"^([0-9]{20})-([0-9a-f]{64})\.json$")
_RESERVATION_NAME = re.compile(r"^([0-9]{20})\.reservation$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HORIZONS = (250, 1_000, 5_000, 30_000, 60_000)
_GENESIS_HASH = "0" * 64
_LOCK_NAME = ".journal.lock"
_FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


class CFastExecutionQualitySidecarError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class JournalRecord:
    sequence: int
    operation_id: str
    previous_record_hash: str
    record_hash: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class SidecarState:
    records: tuple[JournalRecord, ...]
    intents: Mapping[str, JournalRecord]
    anchors: Mapping[str, JournalRecord]
    snapshots: tuple[JournalRecord, ...]
    evidence: Mapping[tuple[str, str], JournalRecord]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _utc_text(value: datetime) -> str:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise CFastExecutionQualitySidecarError("UTC_TIMESTAMP_REQUIRED")
    return value.isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CFastExecutionQualitySidecarError("UTC_TIMESTAMP_REQUIRED")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CFastExecutionQualitySidecarError(
            "UTC_TIMESTAMP_REQUIRED"
        ) from exc
    _utc_text(parsed)
    return parsed


def _record_hash(core: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(core)).hexdigest()


def _operation_id(kind: str, identity: str) -> str:
    return f"{kind}:{identity}"


class CreateOnlyExecutionQualityJournal:
    """Create-only, fsynced research journal with an in-process root pin."""

    def __init__(self, root: Path) -> None:
        expanded = root.expanduser()
        try:
            if (
                not expanded.is_absolute()
                or expanded.resolve(strict=True) != expanded
            ):
                raise ValueError
            metadata = expanded.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_ROOT_INVALID"
            ) from exc
        self.root = expanded
        self._root_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        )
        lock_fd = self._open_lock()
        try:
            self._lock_identity = self._file_identity(
                os.fstat(lock_fd),
                require_empty=True,
            )
        finally:
            os.close(lock_fd)

    def recover(self) -> tuple[JournalRecord, ...]:
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            self._assert_lock(lock_fd)
            records = self._recover_locked()
            self._assert_lock(lock_fd)
            return records
        finally:
            os.close(lock_fd)

    def _recover_locked(self) -> tuple[JournalRecord, ...]:
        root_fd = self._open_root()
        try:
            reservation_names: dict[int, str] = {}
            record_names: dict[int, list[str]] = {}
            for name in os.listdir(root_fd):
                if name == _LOCK_NAME:
                    continue
                reservation_match = _RESERVATION_NAME.fullmatch(name)
                if reservation_match is not None:
                    sequence = int(reservation_match.group(1))
                    reservation_names[sequence] = name
                    continue
                record_match = _RECORD_NAME.fullmatch(name)
                if record_match is not None:
                    sequence = int(record_match.group(1))
                    record_names.setdefault(sequence, []).append(name)
                    continue
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_SEQUENCE_INVALID"
                )
            sequences = set(reservation_names) | set(record_names)
            if sequences:
                expected_sequences = set(range(1, max(sequences) + 1))
                if sequences != expected_sequences:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_SEQUENCE_INVALID"
                    )
            for sequence in sorted(sequences):
                if sequence not in reservation_names:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RESERVATION_MISSING"
                    )
                if sequence not in record_names:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_INCOMPLETE_RESERVATION"
                    )
                if len(record_names[sequence]) != 1:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_SEQUENCE_INVALID"
                    )

            records: list[JournalRecord] = []
            previous = _GENESIS_HASH
            for expected_sequence in sorted(sequences):
                reservation_raw = self._read_record(
                    root_fd,
                    reservation_names[expected_sequence],
                )
                try:
                    reservation = json.loads(reservation_raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RESERVATION_JSON_INVALID"
                    ) from exc
                if not isinstance(reservation, dict):
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RESERVATION_INVALID"
                    )
                reservation_core = {
                    key: value
                    for key, value in reservation.items()
                    if key != "reservation_hash"
                }
                expected_reservation_hash = _record_hash(reservation_core)
                if (
                    reservation_raw != _canonical_json(reservation) + b"\n"
                    or set(reservation)
                    != {
                        "schema_version",
                        "sequence",
                        "operation_id",
                        "previous_record_hash",
                        "record_hash",
                        "record_filename",
                        "record_bytes_sha256",
                        "reservation_hash",
                    }
                    or reservation.get("schema_version")
                    != (
                        "commodity_c_fast_execution_quality_journal_reservation_v1"
                    )
                    or type(reservation.get("sequence")) is not int
                    or reservation["sequence"] != expected_sequence
                    or not isinstance(reservation.get("operation_id"), str)
                    or reservation.get("previous_record_hash") != previous
                    or _SHA256.fullmatch(str(reservation.get("record_hash")))
                    is None
                    or _SHA256.fullmatch(
                        str(reservation.get("record_bytes_sha256"))
                    )
                    is None
                    or reservation.get("record_filename")
                    != record_names[expected_sequence][0]
                    or not hmac.compare_digest(
                        str(reservation.get("reservation_hash")),
                        expected_reservation_hash,
                    )
                ):
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RESERVATION_INVALID"
                    )

                name = record_names[expected_sequence][0]
                match = _RECORD_NAME.fullmatch(name)
                if match is None:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_SEQUENCE_INVALID"
                    )
                raw = self._read_record(root_fd, name)
                try:
                    payload = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RECORD_JSON_INVALID"
                    ) from exc
                if (
                    not isinstance(payload, dict)
                    or raw != _canonical_json(payload) + b"\n"
                    or set(payload)
                    != {
                        "schema_version",
                        "sequence",
                        "operation_id",
                        "previous_record_hash",
                        "payload",
                        "record_hash",
                    }
                    or payload.get("schema_version")
                    != "commodity_c_fast_execution_quality_journal_record_v1"
                    or type(payload.get("sequence")) is not int
                    or payload["sequence"] != expected_sequence
                    or not isinstance(payload.get("operation_id"), str)
                    or not isinstance(payload.get("payload"), dict)
                    or payload.get("previous_record_hash") != previous
                    or payload.get("operation_id")
                    != reservation.get("operation_id")
                ):
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RECORD_SCHEMA_INVALID"
                    )
                core = {
                    key: value
                    for key, value in payload.items()
                    if key != "record_hash"
                }
                expected_hash = _record_hash(core)
                if (
                    match.group(2) != expected_hash
                    or reservation.get("record_hash") != expected_hash
                    or reservation.get("record_bytes_sha256")
                    != hashlib.sha256(raw).hexdigest()
                    or not hmac.compare_digest(
                        str(payload.get("record_hash")),
                        expected_hash,
                    )
                ):
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RECORD_HASH_MISMATCH"
                    )
                records.append(
                    JournalRecord(
                        sequence=expected_sequence,
                        operation_id=payload["operation_id"],
                        previous_record_hash=previous,
                        record_hash=expected_hash,
                        payload=payload["payload"],
                    )
                )
                previous = expected_hash
            self._assert_root(root_fd)
            return tuple(records)
        finally:
            os.close(root_fd)

    def append(
        self,
        *,
        operation_id: str,
        payload: Mapping[str, Any],
        pre_append_validate: (
            Callable[[tuple[JournalRecord, ...]], None] | None
        ) = None,
    ) -> JournalRecord:
        if (
            not operation_id
            or len(operation_id) > 320
            or not isinstance(payload, Mapping)
        ):
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_OPERATION_INVALID"
            )
        normalized = json.loads(_canonical_json(dict(payload)))
        lock_fd = self._open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._assert_lock(lock_fd)
            records = self._recover_locked()
            self._assert_lock(lock_fd)
            for record in records:
                if record.operation_id != operation_id:
                    continue
                if record.payload != normalized:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_OPERATION_REPLAY_CONFLICT"
                    )
                return record
            if pre_append_validate is not None:
                pre_append_validate(records)
            previous = records[-1].record_hash if records else _GENESIS_HASH
            sequence = len(records) + 1
            core = {
                "schema_version": (
                    "commodity_c_fast_execution_quality_journal_record_v1"
                ),
                "sequence": sequence,
                "operation_id": operation_id,
                "previous_record_hash": previous,
                "payload": normalized,
            }
            digest = _record_hash(core)
            envelope = {**core, "record_hash": digest}
            raw = _canonical_json(envelope) + b"\n"
            if len(raw) > MAX_JOURNAL_RECORD_BYTES:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_RECORD_SIZE_INVALID"
                )
            filename = f"{sequence:020d}-{digest}.json"
            reservation_core = {
                "schema_version": (
                    "commodity_c_fast_execution_quality_journal_reservation_v1"
                ),
                "sequence": sequence,
                "operation_id": operation_id,
                "previous_record_hash": previous,
                "record_hash": digest,
                "record_filename": filename,
                "record_bytes_sha256": hashlib.sha256(raw).hexdigest(),
            }
            reservation = {
                **reservation_core,
                "reservation_hash": _record_hash(reservation_core),
            }
            reservation_raw = _canonical_json(reservation) + b"\n"
            self._assert_lock(lock_fd)
            self._create_reservation(
                f"{sequence:020d}.reservation",
                reservation_raw,
            )
            self._assert_lock(lock_fd)
            self._create_record(filename, raw)
            self._assert_lock(lock_fd)
            return JournalRecord(
                sequence=sequence,
                operation_id=operation_id,
                previous_record_hash=previous,
                record_hash=digest,
                payload=normalized,
            )
        finally:
            os.close(lock_fd)

    def _create_reservation(self, filename: str, raw: bytes) -> None:
        self._create_journal_file(
            filename,
            raw,
            collision_code="JOURNAL_SEQUENCE_COLLISION",
            write_failure_code="JOURNAL_RESERVATION_WRITE_FAILED",
        )

    def _create_record(self, filename: str, raw: bytes) -> None:
        self._create_journal_file(
            filename,
            raw,
            collision_code="JOURNAL_SEQUENCE_COLLISION",
            write_failure_code="JOURNAL_CREATE_ONLY_WRITE_FAILED",
        )

    def _create_journal_file(
        self,
        filename: str,
        raw: bytes,
        *,
        collision_code: str,
        write_failure_code: str,
    ) -> None:
        root_fd = self._open_root()
        file_fd: int | None = None
        try:
            file_fd = os.open(
                filename,
                (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC
                ),
                0o600,
                dir_fd=root_fd,
            )
            os.fchmod(file_fd, 0o600)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(file_fd, remaining)
                if written <= 0:
                    raise OSError("short journal write")
                remaining = remaining[written:]
            os.fsync(file_fd)
            metadata = os.fstat(file_fd)
            if metadata.st_size != len(raw):
                raise OSError("journal record size mismatch")
            os.close(file_fd)
            file_fd = None
            os.fsync(root_fd)
            self._assert_root(root_fd)
        except FileExistsError as exc:
            raise CFastExecutionQualitySidecarError(collision_code) from exc
        except CFastExecutionQualitySidecarError:
            raise
        except OSError as exc:
            raise CFastExecutionQualitySidecarError(
                write_failure_code
            ) from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(root_fd)

    def _open_root(self) -> int:
        root_fd: int | None = None
        try:
            root_fd = os.open(
                self.root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            self._assert_root(root_fd)
            return root_fd
        except CFastExecutionQualitySidecarError:
            if root_fd is not None:
                os.close(root_fd)
            raise
        except OSError as exc:
            if root_fd is not None:
                os.close(root_fd)
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_ROOT_INVALID"
            ) from exc

    def _assert_root(self, root_fd: int) -> None:
        metadata = os.fstat(root_fd)
        fd_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
        )
        try:
            current = self.root.lstat()
        except OSError as exc:
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_ROOT_CHANGED"
            ) from exc
        path_identity = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
        )
        if (
            fd_identity != self._root_identity
            or path_identity != self._root_identity
            or not stat.S_ISDIR(metadata.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
        ):
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_ROOT_CHANGED"
            )

    def _open_lock(self) -> int:
        root_fd = self._open_root()
        lock_fd: int | None = None
        try:
            lock_fd = os.open(
                _LOCK_NAME,
                os.O_RDWR
                | os.O_CREAT
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
            identity = self._file_identity(
                os.fstat(lock_fd),
                require_empty=True,
            )
            expected = getattr(self, "_lock_identity", identity)
            if identity != expected:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_LOCK_CHANGED"
                )
            path_identity = self._file_identity(
                os.stat(
                    _LOCK_NAME,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                ),
                require_empty=True,
            )
            if path_identity != identity:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_LOCK_CHANGED"
                )
            return lock_fd
        except CFastExecutionQualitySidecarError:
            if lock_fd is not None:
                os.close(lock_fd)
            raise
        except (OSError, ValueError) as exc:
            if lock_fd is not None:
                os.close(lock_fd)
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_LOCK_INVALID"
            ) from exc
        finally:
            os.close(root_fd)

    def _assert_lock(self, lock_fd: int) -> None:
        try:
            identity = self._file_identity(
                os.fstat(lock_fd),
                require_empty=True,
            )
        except (CFastExecutionQualitySidecarError, OSError) as exc:
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_LOCK_CHANGED"
            ) from exc
        if identity != self._lock_identity:
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_LOCK_CHANGED"
            )
        root_fd = self._open_root()
        try:
            path_identity = self._file_identity(
                os.stat(
                    _LOCK_NAME,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                ),
                require_empty=True,
            )
            if path_identity != identity:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_LOCK_CHANGED"
                )
        finally:
            os.close(root_fd)

    @staticmethod
    def _file_identity(
        metadata: os.stat_result,
        *,
        require_empty: bool,
    ) -> tuple[int, ...]:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or (require_empty and metadata.st_size != 0)
        ):
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_LOCK_INVALID"
            )
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_nlink,
        )

    def _read_record(self, root_fd: int, name: str) -> bytes:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                before = os.fstat(file_fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or before.st_size <= 0
                    or before.st_size > MAX_JOURNAL_RECORD_BYTES
                ):
                    raise ValueError
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(file_fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(file_fd)
                path_after = os.stat(
                    name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                if (
                    identity
                    != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                    or identity
                    != (
                        path_after.st_dev,
                        path_after.st_ino,
                        path_after.st_size,
                        path_after.st_mtime_ns,
                        path_after.st_ctime_ns,
                    )
                    or len(raw) != before.st_size
                ):
                    raise ValueError
                return raw
            finally:
                os.close(file_fd)
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualitySidecarError(
                "JOURNAL_RECORD_BYTES_INVALID"
            ) from exc


class OfflineExecutionQualitySidecar:
    """Explicitly invoked durable scorer infrastructure in the Research Plane."""

    def __init__(
        self,
        journal: CreateOnlyExecutionQualityJournal,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.journal = journal
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.recover()

    def register_preverified_intent(
        self,
        *,
        preverified_plan: CFastVirtualIntentPlanDTO,
        intent_id: str,
        source_snapshot_receipt_sha256: str,
        score_policy: CFastExecutionQualityCollectionPolicyV2DTO,
        score_policy_hash: str,
        contract_spec: CFastExecutionQualityContractSpecDTO,
    ) -> datetime:
        if _SHA256.fullmatch(source_snapshot_receipt_sha256) is None:
            raise CFastExecutionQualitySidecarError(
                "SOURCE_SNAPSHOT_RECEIPT_INVALID"
            )
        intent = next(
            (
                row
                for row in preverified_plan.intents
                if row.intent_id == intent_id
            ),
            None,
        )
        if intent is None:
            raise CFastExecutionQualitySidecarError(
                "INTENT_NOT_IN_ACCEPTED_PLAN"
            )
        if (
            preverified_plan.snapshot_hash
            != source_snapshot_receipt_sha256
            or preverified_plan.policy_hash != intent.policy_hash
            or score_policy_hash
            != sha256_json(score_policy.model_dump(mode="json"))
            or score_policy.foundation_policy_hash != intent.policy_hash
            or contract_spec.exact_contract != intent.exact_contract
        ):
            raise CFastExecutionQualitySidecarError(
                "INTENT_SOURCE_BINDING_INVALID"
            )
        provisional_anchor = self.clock()
        _utc_text(provisional_anchor)
        score_execution_quality(
            intent=intent,
            durably_created_at_utc=provisional_anchor,
            policy=score_policy,
            policy_hash=score_policy_hash,
            contract_spec=contract_spec,
            snapshots=(),
        )
        payload = {
            "record_type": "PREVERIFIED_VIRTUAL_INTENT_INPUT",
            "preverified_plan_hash": preverified_plan.plan_hash,
            "source_snapshot_receipt_sha256": (
                source_snapshot_receipt_sha256
            ),
            "intent": intent.model_dump(mode="json"),
            "score_policy": score_policy.model_dump(mode="json"),
            "score_policy_hash": score_policy_hash,
            "contract_spec": contract_spec.model_dump(mode="json"),
            "source_validation_scope": (
                "CALLER_REVALIDATION_REQUIRED_SIGNED_SNAPSHOT_PLAN_AND_POLICY"
            ),
            **_FALSE_AUTHORITY,
        }
        self.journal.append(
            operation_id=_operation_id("intent", intent_id),
            payload=payload,
            pre_append_validate=self._semantic_append_validator(
                _operation_id("intent", intent_id),
                payload,
            ),
        )
        state = self.recover()
        existing = state.anchors.get(intent_id)
        if existing is not None:
            return _parse_utc(existing.payload["durably_created_at_utc"])
        anchor = self.clock()
        anchor_payload = {
            "record_type": "DURABLE_INTENT_ANCHOR",
            "intent_id": intent_id,
            "durably_created_at_utc": _utc_text(anchor),
            "anchor_basis": (
                "AFTER_PREVERIFIED_INTENT_INPUT_FILE_AND_DIRECTORY_FSYNC"
            ),
            **_FALSE_AUTHORITY,
        }
        self.journal.append(
            operation_id=_operation_id("anchor", intent_id),
            payload=anchor_payload,
            pre_append_validate=self._semantic_append_validator(
                _operation_id("anchor", intent_id),
                anchor_payload,
            ),
        )
        self.recover()
        return anchor

    def append_preverified_snapshot(
        self,
        snapshot: CFastL1L5BookSnapshotDTO,
    ) -> JournalRecord:
        snapshot = CFastL1L5BookSnapshotDTO.model_validate(
            snapshot.model_dump(mode="json")
        )
        state = self.recover()
        for record in state.snapshots:
            current = CFastL1L5BookSnapshotDTO.model_validate(
                record.payload["snapshot"]
            )
            same_ingest = current.ingest_id == snapshot.ingest_id
            same_event = (
                current.exact_contract == snapshot.exact_contract
                and current.exchange_timestamp == snapshot.exchange_timestamp
                and current.ingest_seq == snapshot.ingest_seq
            )
            if not same_ingest and not same_event:
                continue
            if current.book_snapshot_hash != snapshot.book_snapshot_hash:
                raise CFastExecutionQualitySidecarError(
                    "SNAPSHOT_IDENTITY_REUSE_CONFLICT"
                )
            return record
        contract_rows = [
            CFastL1L5BookSnapshotDTO.model_validate(row.payload["snapshot"])
            for row in state.snapshots
            if row.payload["snapshot"]["exact_contract"]
            == snapshot.exact_contract
        ]
        if (
            contract_rows
            and snapshot.received_at_utc < contract_rows[-1].received_at_utc
        ):
            raise CFastExecutionQualitySidecarError(
                "SNAPSHOT_RECEIVED_TIME_REGRESSION"
            )
        event_key = sha256_json(
            {
                "schema_version": (
                "commodity_c_fast_execution_quality_event_key_v1"
                ),
                "exact_contract": snapshot.exact_contract,
                "exchange_timestamp": _utc_text(
                    snapshot.exchange_timestamp
                ),
                "ingest_seq": snapshot.ingest_seq,
            }
        )
        payload = {
            "record_type": "PREVERIFIED_L1_L5_SNAPSHOT_INPUT",
            "ingest_id": snapshot.ingest_id,
            "event_key_sha256": event_key,
            "content_fingerprint_sha256": snapshot.book_snapshot_hash,
            "snapshot": snapshot.model_dump(mode="json"),
            **_FALSE_AUTHORITY,
        }
        record = self.journal.append(
            operation_id=_operation_id(
                "snapshot",
                snapshot.book_snapshot_hash,
            ),
            payload=payload,
            pre_append_validate=self._semantic_append_validator(
                _operation_id(
                    "snapshot",
                    snapshot.book_snapshot_hash,
                ),
                payload,
            ),
        )
        self.recover()
        return record

    def seal_ready_evidence(
        self,
        intent_id: str,
    ) -> tuple[JournalRecord, ...]:
        created: list[JournalRecord] = []
        while True:
            state = self.recover()
            intent_record = state.intents.get(intent_id)
            anchor_record = state.anchors.get(intent_id)
            if intent_record is None or anchor_record is None:
                raise CFastExecutionQualitySidecarError(
                    "INTENT_NOT_DURABLY_REGISTERED"
                )
            intent, policy, policy_hash, contract_spec = self._intent_inputs(
                intent_record
            )
            anchor = _parse_utc(
                anchor_record.payload["durably_created_at_utc"]
            )
            matching = [
                row
                for row in state.snapshots
                if row.payload["snapshot"]["exact_contract"]
                == intent.exact_contract
            ]
            if not matching:
                return tuple(created)
            watermark_record = matching[-1]
            watermark = CFastL1L5BookSnapshotDTO.model_validate(
                watermark_record.payload["snapshot"]
            )
            ready: tuple[str, int] | None = None
            for target_key, horizon_ms in (
                ("decision", 0),
                *((str(value), value) for value in _HORIZONS),
            ):
                if (intent_id, target_key) in state.evidence:
                    continue
                window_end = anchor + timedelta(
                    milliseconds=(
                        horizon_ms
                        + policy.tick_selection.horizon_max_lateness_ms
                    )
                )
                if target_key == "decision":
                    window_end = anchor + timedelta(
                        milliseconds=(
                            policy.tick_selection.decision_max_lateness_ms
                        )
                    )
                if watermark.received_at_utc > window_end:
                    ready = (target_key, horizon_ms)
                    break
            if ready is None:
                return tuple(created)
            target_key, horizon_ms = ready
            window_end = anchor + timedelta(
                milliseconds=(
                    (
                        policy.tick_selection.decision_max_lateness_ms
                        if target_key == "decision"
                        else horizon_ms
                        + policy.tick_selection.horizon_max_lateness_ms
                    )
                )
            )
            input_records = [
                row
                for row in matching
                if anchor
                <= CFastL1L5BookSnapshotDTO.model_validate(
                    row.payload["snapshot"]
                ).received_at_utc
                <= window_end
            ]
            snapshots = tuple(
                CFastL1L5BookSnapshotDTO.model_validate(
                    row.payload["snapshot"]
                )
                for row in input_records
            )
            score = score_execution_quality(
                intent=intent,
                durably_created_at_utc=anchor,
                policy=policy,
                policy_hash=policy_hash,
                contract_spec=contract_spec,
                snapshots=snapshots,
            )
            completion_state = self._completion_state(
                score,
                target_key=target_key,
                horizon_ms=horizon_ms,
            )
            payload = {
                "record_type": "SEALED_SCORE_EVIDENCE",
                "intent_id": intent_id,
                "target_key": target_key,
                "horizon_ms": horizon_ms,
                "completion_state": completion_state,
                "window_end_utc": _utc_text(window_end),
                "watermark_snapshot_record_hash": (
                    watermark_record.record_hash
                ),
                "input_snapshot_record_hashes": [
                    row.record_hash for row in input_records
                ],
                "score": score.model_dump(mode="json"),
                "evidence_state": (
                    "CREATE_ONLY_FSYNCED_RESEARCH_EVIDENCE_AUTHORITY_ABSENT"
                ),
                **_FALSE_AUTHORITY,
            }
            created.append(
                self.journal.append(
                    operation_id=_operation_id(
                        "evidence",
                        f"{intent_id}:{target_key}",
                    ),
                    payload=payload,
                    pre_append_validate=self._semantic_append_validator(
                        _operation_id(
                            "evidence",
                            f"{intent_id}:{target_key}",
                        ),
                        payload,
                    ),
                )
            )

    def status(self, intent_id: str) -> dict[str, Any]:
        state = self.recover()
        if intent_id not in state.intents:
            raise CFastExecutionQualitySidecarError("INTENT_NOT_FOUND")
        anchor_record = state.anchors.get(intent_id)
        completion: dict[str, str] = {}
        for key in ("decision", *(str(value) for value in _HORIZONS)):
            record = state.evidence.get((intent_id, key))
            completion[key] = (
                record.payload["completion_state"]
                if record is not None
                else "PENDING_NOT_SEALED"
            )
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_sidecar_status_v1"
            ),
            "sidecar_state": (
                "OFFLINE_DURABLE_RESEARCH_INFRASTRUCTURE_NOT_ACTIVATED"
            ),
            "intent_id": intent_id,
            "durably_created_at_utc": (
                anchor_record.payload["durably_created_at_utc"]
                if anchor_record is not None
                else None
            ),
            "completion": completion,
            "journal_record_count": len(state.records),
            "snapshot_record_count": len(state.snapshots),
            "evidence_record_count": sum(
                1 for key in state.evidence if key[0] == intent_id
            ),
            **_FALSE_AUTHORITY,
        }

    def recover(self) -> SidecarState:
        return self._state_from_records(self.journal.recover())

    def _semantic_append_validator(
        self,
        operation_id: str,
        payload: Mapping[str, Any],
    ) -> Callable[[tuple[JournalRecord, ...]], None]:
        normalized = json.loads(_canonical_json(dict(payload)))

        def validate(records: tuple[JournalRecord, ...]) -> None:
            previous = (
                records[-1].record_hash if records else _GENESIS_HASH
            )
            proposed = JournalRecord(
                sequence=len(records) + 1,
                operation_id=operation_id,
                previous_record_hash=previous,
                record_hash="f" * 64,
                payload=normalized,
            )
            self._state_from_records((*records, proposed))

        return validate

    def _state_from_records(
        self,
        records: tuple[JournalRecord, ...],
    ) -> SidecarState:
        intents: dict[str, JournalRecord] = {}
        anchors: dict[str, JournalRecord] = {}
        snapshots: list[JournalRecord] = []
        evidence: dict[tuple[str, str], JournalRecord] = {}
        operations: set[str] = set()
        last_received: dict[str, datetime] = {}
        ingest_ids: dict[str, str] = {}
        event_keys: dict[str, str] = {}
        snapshot_records_by_hash: dict[str, JournalRecord] = {}

        for record in records:
            if record.operation_id in operations:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_OPERATION_DUPLICATE"
                )
            operations.add(record.operation_id)
            self._require_false_authority(record.payload)
            record_type = record.payload.get("record_type")
            try:
                if record_type == "PREVERIFIED_VIRTUAL_INTENT_INPUT":
                    intent = CFastVirtualIntentDTO.model_validate(
                        record.payload["intent"]
                    )
                    policy = (
                        CFastExecutionQualityCollectionPolicyV2DTO.model_validate(
                            record.payload["score_policy"]
                        )
                    )
                    spec = CFastExecutionQualityContractSpecDTO.model_validate(
                        record.payload["contract_spec"]
                    )
                    if (
                        intent.intent_id in intents
                        or record.operation_id
                        != _operation_id("intent", intent.intent_id)
                        or _SHA256.fullmatch(
                            str(record.payload.get("preverified_plan_hash"))
                        )
                        is None
                        or record.payload.get("source_snapshot_receipt_sha256")
                        != intent.snapshot_hash
                        or record.payload.get("source_validation_scope")
                        != (
                            "CALLER_REVALIDATION_REQUIRED_SIGNED_SNAPSHOT_"
                            "PLAN_AND_POLICY"
                        )
                        or record.payload.get("score_policy_hash")
                        != sha256_json(policy.model_dump(mode="json"))
                        or policy.foundation_policy_hash != intent.policy_hash
                        or spec.exact_contract != intent.exact_contract
                    ):
                        raise CFastExecutionQualitySidecarError(
                            "INTENT_RECORD_INVALID"
                        )
                    intents[intent.intent_id] = record
                elif record_type == "DURABLE_INTENT_ANCHOR":
                    intent_id = record.payload.get("intent_id")
                    if (
                        not isinstance(intent_id, str)
                        or intent_id not in intents
                        or intent_id in anchors
                        or record.operation_id
                        != _operation_id("anchor", intent_id)
                        or record.payload.get("anchor_basis")
                        != (
                            "AFTER_PREVERIFIED_INTENT_INPUT_FILE_AND_"
                            "DIRECTORY_FSYNC"
                        )
                    ):
                        raise CFastExecutionQualitySidecarError(
                            "INTENT_ANCHOR_INVALID"
                        )
                    _parse_utc(record.payload.get("durably_created_at_utc"))
                    anchors[intent_id] = record
                elif record_type == "PREVERIFIED_L1_L5_SNAPSHOT_INPUT":
                    snapshot = CFastL1L5BookSnapshotDTO.model_validate(
                        record.payload["snapshot"]
                    )
                    event_key = sha256_json(
                        {
                            "schema_version": (
                                "commodity_c_fast_execution_quality_event_key_v1"
                            ),
                            "exact_contract": snapshot.exact_contract,
                            "exchange_timestamp": _utc_text(
                                snapshot.exchange_timestamp
                            ),
                            "ingest_seq": snapshot.ingest_seq,
                        }
                    )
                    if (
                        record.operation_id
                        != _operation_id(
                            "snapshot",
                            snapshot.book_snapshot_hash,
                        )
                        or record.payload.get("ingest_id")
                        != snapshot.ingest_id
                        or record.payload.get("event_key_sha256") != event_key
                        or record.payload.get("content_fingerprint_sha256")
                        != snapshot.book_snapshot_hash
                    ):
                        raise CFastExecutionQualitySidecarError(
                            "SNAPSHOT_RECORD_INVALID"
                        )
                    for identity, registry in (
                        (snapshot.ingest_id, ingest_ids),
                        (event_key, event_keys),
                    ):
                        prior = registry.get(identity)
                        if (
                            prior is not None
                            and prior != snapshot.book_snapshot_hash
                        ):
                            raise CFastExecutionQualitySidecarError(
                                "SNAPSHOT_IDENTITY_REUSE_CONFLICT"
                            )
                        registry[identity] = snapshot.book_snapshot_hash
                    prior_received = last_received.get(
                        snapshot.exact_contract
                    )
                    if (
                        prior_received is not None
                        and snapshot.received_at_utc < prior_received
                    ):
                        raise CFastExecutionQualitySidecarError(
                            "SNAPSHOT_RECEIVED_TIME_REGRESSION"
                        )
                    last_received[snapshot.exact_contract] = (
                        snapshot.received_at_utc
                    )
                    snapshots.append(record)
                    snapshot_records_by_hash[record.record_hash] = record
                elif record_type == "SEALED_SCORE_EVIDENCE":
                    self._recover_evidence(
                        record,
                        intents=intents,
                        anchors=anchors,
                        snapshot_records=tuple(snapshots),
                        snapshot_records_by_hash=snapshot_records_by_hash,
                        evidence=evidence,
                    )
                else:
                    raise CFastExecutionQualitySidecarError(
                        "JOURNAL_RECORD_TYPE_INVALID"
                    )
            except (KeyError, TypeError, ValidationError) as exc:
                raise CFastExecutionQualitySidecarError(
                    "JOURNAL_PAYLOAD_INVALID"
                ) from exc
        return SidecarState(
            records=records,
            intents=intents,
            anchors=anchors,
            snapshots=tuple(snapshots),
            evidence=evidence,
        )

    def _recover_evidence(
        self,
        record: JournalRecord,
        *,
        intents: Mapping[str, JournalRecord],
        anchors: Mapping[str, JournalRecord],
        snapshot_records: Sequence[JournalRecord],
        snapshot_records_by_hash: Mapping[str, JournalRecord],
        evidence: dict[tuple[str, str], JournalRecord],
    ) -> None:
        intent_id = record.payload.get("intent_id")
        target_key = record.payload.get("target_key")
        horizon_ms = record.payload.get("horizon_ms")
        if (
            not isinstance(intent_id, str)
            or intent_id not in intents
            or intent_id not in anchors
            or target_key
            not in {"decision", *(str(value) for value in _HORIZONS)}
            or type(horizon_ms) is not int
            or horizon_ms
            != (0 if target_key == "decision" else int(target_key))
            or (intent_id, target_key) in evidence
            or record.operation_id
            != _operation_id(
                "evidence",
                f"{intent_id}:{target_key}",
            )
        ):
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_IDENTITY_INVALID"
            )
        intent, policy, policy_hash, spec = self._intent_inputs(
            intents[intent_id]
        )
        anchor = _parse_utc(
            anchors[intent_id].payload["durably_created_at_utc"]
        )
        expected_end = anchor + timedelta(
            milliseconds=(
                policy.tick_selection.decision_max_lateness_ms
                if target_key == "decision"
                else horizon_ms
                + policy.tick_selection.horizon_max_lateness_ms
            )
        )
        if _parse_utc(record.payload.get("window_end_utc")) != expected_end:
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_WINDOW_INVALID"
            )
        watermark_hash = record.payload.get(
            "watermark_snapshot_record_hash"
        )
        watermark_record = snapshot_records_by_hash.get(str(watermark_hash))
        if watermark_record is None:
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_WATERMARK_INVALID"
            )
        watermark = CFastL1L5BookSnapshotDTO.model_validate(
            watermark_record.payload["snapshot"]
        )
        if (
            watermark.exact_contract != intent.exact_contract
            or watermark.received_at_utc <= expected_end
        ):
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_WATERMARK_INVALID"
            )
        expected_inputs = [
            row
            for row in snapshot_records
            if row.sequence <= watermark_record.sequence
            and row.payload["snapshot"]["exact_contract"]
            == intent.exact_contract
            and anchor
            <= CFastL1L5BookSnapshotDTO.model_validate(
                row.payload["snapshot"]
            ).received_at_utc
            <= expected_end
        ]
        supplied_hashes = record.payload.get(
            "input_snapshot_record_hashes"
        )
        if supplied_hashes != [row.record_hash for row in expected_inputs]:
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_INPUT_SET_INVALID"
            )
        snapshots = tuple(
            CFastL1L5BookSnapshotDTO.model_validate(row.payload["snapshot"])
            for row in expected_inputs
        )
        try:
            score = reload_and_verify_execution_quality_score(
                record.payload["score"],
                intent=intent,
                durably_created_at_utc=anchor,
                policy=policy,
                policy_hash=policy_hash,
                contract_spec=spec,
                snapshots=snapshots,
            )
        except (CFastExecutionQualityScorerError, ValidationError) as exc:
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_DERIVATION_INVALID"
            ) from exc
        if record.payload.get("evidence_state") != (
            "CREATE_ONLY_FSYNCED_RESEARCH_EVIDENCE_AUTHORITY_ABSENT"
        ):
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_STATE_INVALID"
            )
        if record.payload.get("completion_state") != self._completion_state(
            score,
            target_key=target_key,
            horizon_ms=horizon_ms,
        ):
            raise CFastExecutionQualitySidecarError(
                "SCORE_EVIDENCE_COMPLETION_INVALID"
            )
        evidence[(intent_id, target_key)] = record

    @staticmethod
    def _intent_inputs(
        record: JournalRecord,
    ) -> tuple[
        CFastVirtualIntentDTO,
        CFastExecutionQualityCollectionPolicyV2DTO,
        str,
        CFastExecutionQualityContractSpecDTO,
    ]:
        return (
            CFastVirtualIntentDTO.model_validate(record.payload["intent"]),
            CFastExecutionQualityCollectionPolicyV2DTO.model_validate(
                record.payload["score_policy"]
            ),
            record.payload["score_policy_hash"],
            CFastExecutionQualityContractSpecDTO.model_validate(
                record.payload["contract_spec"]
            ),
        )

    @staticmethod
    def _completion_state(
        score: CFastExecutionQualityScoreDTO,
        *,
        target_key: str,
        horizon_ms: int,
    ) -> str:
        if target_key == "decision":
            return (
                "SEALED_SELECTED_EVIDENCE"
                if score.decision_tick is not None
                else "SEALED_MISSING_NOT_IMPUTED"
            )
        horizon = next(
            row for row in score.horizons if row.horizon_ms == horizon_ms
        )
        return (
            "SEALED_SELECTED_EVIDENCE"
            if horizon.selected_tick is not None
            else "SEALED_MISSING_NOT_IMPUTED"
        )

    @staticmethod
    def _require_false_authority(payload: Mapping[str, Any]) -> None:
        if any(
            payload.get(key) is not value
            for key, value in _FALSE_AUTHORITY.items()
        ):
            raise CFastExecutionQualitySidecarError(
                "SIDECAR_AUTHORITY_BOUNDARY_INVALID"
            )
