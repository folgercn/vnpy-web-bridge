from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_quality_evidence_export import (
    CFastExecutionQualityEvidenceExportDTO,
    CFastExecutionQualityEvidenceProjectionDTO,
    CFastExecutionQualityIntentProjectionDTO,
    CFastExecutionQualityTargetProjectionDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityScoreDTO,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    OfflineExecutionQualitySidecar,
    SidecarState,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_EXPORT_FILES = 10_000
_LOCK_NAME = ".export.lock"
_EXPORT_NAME = re.compile(
    r"^cfast-execution-quality-evidence-export-v1-"
    r"([0-9a-f]{64})-([0-9a-f]{64})\.json$"
)
_TEMP_NAME = re.compile(
    r"^\.((?:cfast-execution-quality-evidence-export-v1-)"
    r"[0-9a-f]{64}-[0-9a-f]{64}\.json)\.tmp-([0-9a-f]{32})$"
)
_TARGETS = (
    ("decision", 0),
    ("250", 250),
    ("1000", 1_000),
    ("5000", 5_000),
    ("30000", 30_000),
    ("60000", 60_000),
)
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


class CFastExecutionQualityEvidenceExportError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_evidence_export_json_line(payload: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_CANONICAL_JSON_FAILED"
        ) from exc


def build_execution_quality_evidence_export(
    source: OfflineExecutionQualitySidecar,
) -> CFastExecutionQualityEvidenceExportDTO:
    """Build one fresh, non-M2 projection from the local durable journal."""

    if type(source) is not OfflineExecutionQualitySidecar:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_SOURCE_TYPE_INVALID"
        )
    try:
        state = source.recover()
        return _build_from_state(source, state)
    except CFastExecutionQualityEvidenceExportError:
        raise
    except Exception as exc:
        raise CFastExecutionQualityEvidenceExportError(
            f"EVIDENCE_EXPORT_SOURCE_REPLAY_FAILED:{getattr(exc, 'code', type(exc).__name__)}"
        ) from exc


def execution_quality_evidence_export_json_bytes(
    source: OfflineExecutionQualitySidecar,
) -> bytes:
    exported = build_execution_quality_evidence_export(source)
    raw = canonical_evidence_export_json_line(exported.model_dump(mode="json"))
    if len(raw) > MAX_EXPORT_BYTES:
        raise CFastExecutionQualityEvidenceExportError("EVIDENCE_EXPORT_RESOURCE_LIMIT")
    return raw


def reload_and_verify_execution_quality_evidence_export(
    payload_or_raw: Mapping[str, Any] | bytes,
    *,
    source: OfflineExecutionQualitySidecar,
) -> CFastExecutionQualityEvidenceExportDTO:
    """Revalidate canonical bytes and compare them with a fresh source replay."""

    if type(source) is not OfflineExecutionQualitySidecar:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_SOURCE_TYPE_INVALID"
        )
    if isinstance(payload_or_raw, bytes):
        if not 0 < len(payload_or_raw) <= MAX_EXPORT_BYTES:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_RESOURCE_LIMIT"
            )
        try:
            payload = json.loads(payload_or_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_JSON_INVALID"
            ) from exc
        if not isinstance(payload, dict):
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_JSON_INVALID"
            )
        if canonical_evidence_export_json_line(payload) != payload_or_raw:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_NOT_CANONICAL"
            )
    elif isinstance(payload_or_raw, Mapping):
        payload = dict(payload_or_raw)
        if len(canonical_evidence_export_json_line(payload)) > MAX_EXPORT_BYTES:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_RESOURCE_LIMIT"
            )
    else:
        raise CFastExecutionQualityEvidenceExportError("EVIDENCE_EXPORT_INPUT_INVALID")
    try:
        reloaded = CFastExecutionQualityEvidenceExportDTO.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_DTO_INVALID"
        ) from exc
    try:
        state = source.recover_at_tip(
            record_count=reloaded.source_journal_record_count,
            tip_record_hash=reloaded.source_journal_tip_record_hash,
        )
        expected = _build_from_state(source, state)
    except Exception as exc:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_FRESH_SOURCE_MISMATCH"
        ) from exc
    if reloaded != expected:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_FRESH_SOURCE_MISMATCH"
        )
    return reloaded


class CreateOnlyExecutionQualityEvidenceExportStore:
    """Publish verified projections into a separate create-only custody root."""

    def __init__(self, root: Path) -> None:
        expanded = root.expanduser()
        try:
            metadata = expanded.lstat()
            if (
                not expanded.is_absolute()
                or expanded.resolve(strict=True) != expanded
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_INVALID"
            ) from exc
        self.root = expanded
        self._root_identity = _directory_identity(metadata)
        root_fd = self._open_root()
        lock_fd: int | None = None
        try:
            lock_fd = self._open_or_create_lock(root_fd)
            try:
                try:
                    self._lock_identity = _lock_identity(os.fstat(lock_fd))
                except (OSError, ValueError) as exc:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_LOCK_INVALID"
                    ) from exc
                self._assert_lock(root_fd, lock_fd)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except OSError as exc:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_LOCK_ACQUIRE_FAILED"
                    ) from exc
                self._assert_lock(root_fd, lock_fd)
                self._assert_root(root_fd)
                self._recover_temporary_artifacts(root_fd)
                self._validate_artifacts(root_fd)
                self._assert_lock(root_fd, lock_fd)
                self._assert_root(root_fd)
                try:
                    os.fsync(root_fd)
                except OSError as exc:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_ROOT_FSYNC_FAILED"
                    ) from exc
            finally:
                os.close(lock_fd)
                lock_fd = None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)

    def publish(
        self,
        source: OfflineExecutionQualitySidecar,
    ) -> dict[str, object]:
        self._require_separate_source_root(source)
        exported = build_execution_quality_evidence_export(source)
        raw = canonical_evidence_export_json_line(exported.model_dump(mode="json"))
        if len(raw) > MAX_EXPORT_BYTES:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_RESOURCE_LIMIT"
            )
        generation_digest = exported.generation_basis_sha256
        filename = (
            "cfast-execution-quality-evidence-export-v1-"
            f"{generation_digest}-{exported.source_journal_tip_record_hash}.json"
        )
        root_fd = self._open_root()
        lock_fd: int | None = None
        try:
            lock_fd = self._open_or_create_lock(root_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError as exc:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_LOCK_ACQUIRE_FAILED"
                ) from exc
            self._assert_lock(root_fd, lock_fd)
            self._assert_root(root_fd)
            self._validate_artifacts(root_fd)
            existing = self._read_optional(root_fd, filename)
            if existing is None:
                if self._artifact_count(root_fd) >= MAX_EXPORT_FILES:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_FILE_LIMIT"
                    )
                artifact_state = self._write_create_only(
                    root_fd,
                    filename,
                    raw,
                )
            elif existing == raw:
                artifact_state = "ALREADY_PRESENT"
            else:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_CONFLICT"
                )
            self._assert_lock(root_fd, lock_fd)
            self._assert_root(root_fd)
            self._validate_artifacts(root_fd)
            if self._read_required(root_fd, filename) != raw:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_CHANGED"
                )
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_evidence_export_publish_v1"
            ),
            "artifact_state": artifact_state,
            "artifact_filename": filename,
            "generation_id": exported.generation_id,
            "source_journal_tip_record_hash": (exported.source_journal_tip_record_hash),
            "export_sha256": exported.export_sha256,
            "m2_acceptance_state": (
                "NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW"
            ),
            "runtime_active": False,
            "execution_quality_implemented": False,
            "real_execution_window_verified": False,
            "zero_order_t2_evidence_accepted": False,
            "orders_sent": 0,
            "positions_modified": 0,
            **_FALSE_AUTHORITY,
        }

    def load(
        self,
        filename: str,
        *,
        source: OfflineExecutionQualitySidecar,
    ) -> CFastExecutionQualityEvidenceExportDTO:
        if _EXPORT_NAME.fullmatch(filename) is None:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_FILENAME_INVALID"
            )
        self._require_separate_source_root(source)
        root_fd = self._open_root()
        lock_fd: int | None = None
        try:
            lock_fd = self._open_or_create_lock(root_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_SH)
            except OSError as exc:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_LOCK_ACQUIRE_FAILED"
                ) from exc
            self._assert_lock(root_fd, lock_fd)
            self._assert_root(root_fd)
            self._validate_artifacts(root_fd)
            raw = self._read_required(root_fd, filename)
            self._assert_lock(root_fd, lock_fd)
            self._assert_root(root_fd)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(root_fd)
        return reload_and_verify_execution_quality_evidence_export(
            raw,
            source=source,
        )

    def _require_separate_source_root(
        self,
        source: OfflineExecutionQualitySidecar,
    ) -> None:
        if type(source) is not OfflineExecutionQualitySidecar:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_SOURCE_TYPE_INVALID"
            )
        source_root = source.journal.root
        if (
            source_root == self.root
            or source_root in self.root.parents
            or self.root in source_root.parents
        ):
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_SOURCE_ROOT_OVERLAP"
            )

    def _open_root(self) -> int:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self.root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            self._assert_root(descriptor)
            return descriptor
        except CFastExecutionQualityEvidenceExportError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except (OSError, ValueError) as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_OPEN_FAILED"
            ) from exc

    def _assert_root(self, descriptor: int) -> None:
        try:
            descriptor_identity = _directory_identity(os.fstat(descriptor))
            path_identity = _directory_identity(self.root.lstat())
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_CHANGED"
            ) from exc
        if (
            descriptor_identity != self._root_identity
            or path_identity != self._root_identity
        ):
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_CHANGED"
            )

    def _open_or_create_lock(self, root_fd: int) -> int:
        try:
            descriptor = os.open(
                _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
            return descriptor
        except OSError as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_LOCK_OPEN_FAILED"
            ) from exc

    def _assert_lock(self, root_fd: int, lock_fd: int) -> None:
        try:
            descriptor_identity = _lock_identity(os.fstat(lock_fd))
            path_identity = _lock_identity(
                os.stat(_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
            )
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_LOCK_CHANGED"
            ) from exc
        if (
            descriptor_identity != self._lock_identity
            or path_identity != self._lock_identity
        ):
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_LOCK_CHANGED"
            )

    def _validate_artifacts(self, root_fd: int) -> None:
        try:
            names = os.listdir(root_fd)
        except OSError as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_LIST_FAILED"
            ) from exc
        if sum(name != _LOCK_NAME for name in names) > MAX_EXPORT_FILES:
            raise CFastExecutionQualityEvidenceExportError("EVIDENCE_EXPORT_FILE_LIMIT")
        for name in names:
            if name == _LOCK_NAME:
                continue
            if _EXPORT_NAME.fullmatch(name) is None:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_UNKNOWN_ARTIFACT"
                )
            try:
                metadata = os.stat(
                    name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_INVALID"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= MAX_EXPORT_BYTES
            ):
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_INVALID"
                )

    @staticmethod
    def _artifact_count(root_fd: int) -> int:
        try:
            return sum(name != _LOCK_NAME for name in os.listdir(root_fd))
        except OSError as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_LIST_FAILED"
            ) from exc

    def _recover_temporary_artifacts(self, root_fd: int) -> None:
        """Remove only structurally valid remnants of interrupted publishes."""

        try:
            names = os.listdir(root_fd)
        except OSError as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ROOT_LIST_FAILED"
            ) from exc
        if sum(name != _LOCK_NAME for name in names) > MAX_EXPORT_FILES + 1:
            raise CFastExecutionQualityEvidenceExportError("EVIDENCE_EXPORT_FILE_LIMIT")
        changed = False
        for name in names:
            match = _TEMP_NAME.fullmatch(name)
            if match is None:
                continue
            final_name = match.group(1)
            try:
                temporary = os.stat(
                    name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                _validate_temporary_file(temporary)
                try:
                    final = os.stat(
                        final_name,
                        dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    final = None
                if final is None:
                    if temporary.st_nlink != 1:
                        raise ValueError("unpaired temporary hard link")
                else:
                    _validate_published_file(final)
                    same_file = (
                        temporary.st_dev == final.st_dev
                        and temporary.st_ino == final.st_ino
                    )
                    if same_file:
                        if temporary.st_nlink != 2 or final.st_nlink != 2:
                            raise ValueError("published hard link count invalid")
                    elif temporary.st_nlink != 1 or final.st_nlink != 1:
                        raise ValueError("temporary hard link conflict")
                os.unlink(name, dir_fd=root_fd)
                changed = True
            except (OSError, ValueError) as exc:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_TEMP_RECOVERY_FAILED"
                ) from exc
        if changed:
            try:
                os.fsync(root_fd)
            except OSError as exc:
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ROOT_FSYNC_FAILED"
                ) from exc

    def _read_optional(self, root_fd: int, filename: str) -> bytes | None:
        try:
            return self._read_required(root_fd, filename)
        except FileNotFoundError:
            return None

    @staticmethod
    def _read_required(root_fd: int, filename: str) -> bytes:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_EXPORT_BYTES
            ):
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_INVALID"
                )
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_ARTIFACT_INVALID"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            path_after = os.stat(
                filename,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            identity = _regular_file_identity(before)
            if (
                identity != _regular_file_identity(after)
                or identity != _regular_file_identity(path_after)
                or len(raw) != before.st_size
            ):
                raise CFastExecutionQualityEvidenceExportError(
                    "EVIDENCE_EXPORT_ARTIFACT_CHANGED"
                )
            return raw
        except FileNotFoundError:
            raise
        except CFastExecutionQualityEvidenceExportError:
            raise
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_ARTIFACT_READ_FAILED"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _write_create_only(
        root_fd: int,
        filename: str,
        raw: bytes,
    ) -> str:
        temporary_name = f".{filename}.tmp-{secrets.token_hex(16)}"
        descriptor: int | None = None
        temporary_created = False
        try:
            descriptor = os.open(
                temporary_name,
                (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC),
                0o600,
                dir_fd=root_fd,
            )
            temporary_created = True
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short export write")
                remaining = remaining[written:]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_size != len(raw) or metadata.st_nlink != 1:
                raise OSError("export size mismatch")
            os.close(descriptor)
            descriptor = None
            path_metadata = os.stat(
                temporary_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            _validate_temporary_file(path_metadata)
            if (
                path_metadata.st_dev != metadata.st_dev
                or path_metadata.st_ino != metadata.st_ino
                or path_metadata.st_size != metadata.st_size
            ):
                raise OSError("temporary export changed")
            try:
                os.link(
                    temporary_name,
                    filename,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = CreateOnlyExecutionQualityEvidenceExportStore._read_required(
                    root_fd,
                    filename,
                )
                if existing != raw:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_ARTIFACT_CONFLICT"
                    )
                return "ALREADY_PRESENT"
            os.fsync(root_fd)
            return "CREATED"
        except CFastExecutionQualityEvidenceExportError:
            raise
        except OSError as exc:
            raise CFastExecutionQualityEvidenceExportError(
                "EVIDENCE_EXPORT_CREATE_ONLY_WRITE_FAILED"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_created:
                try:
                    os.unlink(temporary_name, dir_fd=root_fd)
                    os.fsync(root_fd)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise CFastExecutionQualityEvidenceExportError(
                        "EVIDENCE_EXPORT_TEMP_CLEANUP_FAILED"
                    ) from exc


def _build_from_state(
    source: OfflineExecutionQualitySidecar,
    state: SidecarState,
) -> CFastExecutionQualityEvidenceExportDTO:
    if not state.intents or set(state.intents) != set(state.anchors):
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_DURABLE_PLAN_INCOMPLETE"
        )
    plan_hashes = {
        str(record.payload["preverified_plan_hash"])
        for record in state.intents.values()
    }
    if len(plan_hashes) != 1:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_GENERATION_PLAN_SET_INVALID"
        )
    plan_hash = next(iter(plan_hashes))
    plan_records = [
        record
        for record in state.intents.values()
        if record.payload["preverified_plan_hash"] == plan_hash
    ]
    expected_sets = {
        tuple(record.payload["expected_plan_intent_ids"]) for record in plan_records
    }
    if len(expected_sets) != 1:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_EXPECTED_INTENT_SET_INVALID"
        )
    expected_intent_ids = next(iter(expected_sets))
    if set(expected_intent_ids) != set(state.intents):
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_DURABLE_PLAN_INCOMPLETE"
        )
    ordered_intent_records = tuple(
        state.intents[intent_id] for intent_id in expected_intent_ids
    )
    source_receipts = {
        str(record.payload["source_snapshot_receipt_sha256"])
        for record in ordered_intent_records
    }
    if len(source_receipts) != 1:
        raise CFastExecutionQualityEvidenceExportError(
            "EVIDENCE_EXPORT_SOURCE_RECEIPT_SET_INVALID"
        )
    source_receipt = next(iter(source_receipts))
    exact_contracts = tuple(
        sorted(
            {
                str(record.payload["intent"]["exact_contract"])
                for record in ordered_intent_records
            }
        )
    )
    root_path_sha256, root_identity_sha256 = source.journal.custody_hashes()

    evidence_rows: list[CFastExecutionQualityEvidenceProjectionDTO] = []
    intent_rows: list[CFastExecutionQualityIntentProjectionDTO] = []
    pending_target_count = 0
    for intent_record in ordered_intent_records:
        intent_id = str(intent_record.payload["intent"]["intent_id"])
        anchor_record = state.anchors[intent_id]
        targets: list[CFastExecutionQualityTargetProjectionDTO] = []
        for target_key, horizon_ms in _TARGETS:
            evidence_record = state.evidence.get((intent_id, target_key))
            if evidence_record is None:
                pending_target_count += 1
                targets.append(
                    CFastExecutionQualityTargetProjectionDTO(
                        target_key=target_key,
                        horizon_ms=horizon_ms,
                        completion_state="PENDING_NOT_SEALED",
                    )
                )
                continue
            score = CFastExecutionQualityScoreDTO.model_validate(
                evidence_record.payload["score"]
            )
            evidence = CFastExecutionQualityEvidenceProjectionDTO(
                schema_version=(
                    "commodity_c_fast_execution_quality_evidence_projection_v1"
                ),
                evidence_record_sequence=evidence_record.sequence,
                evidence_record_hash=evidence_record.record_hash,
                intent_id=intent_id,
                target_key=target_key,
                horizon_ms=horizon_ms,
                completion_state=evidence_record.payload["completion_state"],
                window_end_utc=evidence_record.payload["window_end_utc"],
                watermark_snapshot_record_hash=evidence_record.payload[
                    "watermark_snapshot_record_hash"
                ],
                input_snapshot_record_hashes=tuple(
                    evidence_record.payload["input_snapshot_record_hashes"]
                ),
                score=score,
                evidence_state=evidence_record.payload["evidence_state"],
                **_FALSE_AUTHORITY,
            )
            evidence_rows.append(evidence)
            targets.append(
                CFastExecutionQualityTargetProjectionDTO(
                    target_key=target_key,
                    horizon_ms=horizon_ms,
                    completion_state=evidence.completion_state,
                    evidence_record_sequence=evidence.evidence_record_sequence,
                    evidence_record_hash=evidence.evidence_record_hash,
                    score_hash=evidence.score.score_hash,
                )
            )
        intent_rows.append(
            CFastExecutionQualityIntentProjectionDTO(
                schema_version=(
                    "commodity_c_fast_execution_quality_intent_projection_v1"
                ),
                preverified_plan_hash=plan_hash,
                source_snapshot_receipt_sha256=source_receipt,
                intent_record_sequence=intent_record.sequence,
                intent_record_hash=intent_record.record_hash,
                anchor_record_sequence=anchor_record.sequence,
                anchor_record_hash=anchor_record.record_hash,
                durably_created_at_utc=anchor_record.payload["durably_created_at_utc"],
                intent=intent_record.payload["intent"],
                score_policy_hash=intent_record.payload["score_policy_hash"],
                contract_spec_hash=intent_record.payload["contract_spec"][
                    "contract_spec_hash"
                ],
                targets=tuple(targets),
            )
        )
    intent_tuple = tuple(intent_rows)
    evidence_tuple = tuple(evidence_rows)
    generation_core = {
        "schema_version": ("commodity_c_fast_execution_quality_generation_basis_v1"),
        "source_journal_root_path_sha256": root_path_sha256,
        "source_journal_root_identity_sha256": root_identity_sha256,
        "preverified_plan_hash": plan_hash,
        "source_snapshot_receipt_sha256": source_receipt,
        "exact_contracts": list(exact_contracts),
        "intent_record_hashes": [row.intent_record_hash for row in intent_tuple],
        "anchor_record_hashes": [row.anchor_record_hash for row in intent_tuple],
    }
    generation_hash = sha256_json(generation_core)
    core = {
        "schema_version": ("commodity_c_fast_execution_quality_evidence_export_v1"),
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "generation_id": f"cfast-eq-generation-v1-{generation_hash}",
        "generation_basis_sha256": generation_hash,
        "preverified_plan_hash": plan_hash,
        "source_snapshot_receipt_sha256": source_receipt,
        "source_journal_root_path_sha256": root_path_sha256,
        "source_journal_root_identity_sha256": root_identity_sha256,
        "source_journal_record_count": len(state.records),
        "source_journal_tip_record_hash": state.records[-1].record_hash,
        "ordered_journal_record_hashes_sha256": sha256_json(
            [record.record_hash for record in state.records]
        ),
        "exact_contracts": list(exact_contracts),
        "intent_count": len(intent_tuple),
        "snapshot_record_count": len(state.snapshots),
        "evidence_record_count": len(evidence_tuple),
        "pending_target_count": pending_target_count,
        "intents": [row.model_dump(mode="json") for row in intent_tuple],
        "evidence": [row.model_dump(mode="json") for row in evidence_tuple],
        "journal_window_state": (
            "PENDING_TARGETS_PRESENT_LOCAL_JOURNAL_ONLY"
            if pending_target_count
            else "ALL_TARGETS_SEALED_LOCAL_JOURNAL_ONLY"
        ),
        "source_verification_scope": (
            "FRESH_REPLAY_OF_PINNED_LOCAL_CREATE_ONLY_JOURNAL_AT_EXPORT"
        ),
        "self_contained_replay_state": (
            "NOT_SELF_CONTAINED_REQUIRES_PINNED_SOURCE_JOURNAL"
        ),
        "external_custody_anchor_state": ("NOT_PROVIDED_CODE_ONLY_LOCAL_JOURNAL"),
        "signed_runtime_revalidation_binding_state": (
            "NOT_INCLUDED_REQUIRES_RUNTIME_ADAPTER"
        ),
        "real_tick_source_attestation_state": (
            "NOT_INCLUDED_LOCAL_JOURNAL_CANNOT_PROVE_SOURCE"
        ),
        "m2_acceptance_state": ("NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW"),
        "artifact_write_semantics": "CREATE_ONLY_0600_FSYNC_NO_OVERWRITE",
        "execution_quality_implemented": False,
        "runtime_active": False,
        "real_execution_window_verified": False,
        "zero_order_t2_evidence_accepted": False,
        "countable_forward": False,
        "orders_sent": 0,
        "positions_modified": 0,
        **_FALSE_AUTHORITY,
    }
    return CFastExecutionQualityEvidenceExportDTO.model_validate(
        {**core, "export_sha256": sha256_json(core)}
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("directory identity invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _lock_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise ValueError("lock identity invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )


def _regular_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("regular file identity invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_temporary_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink not in {1, 2}
        or not 0 <= metadata.st_size <= MAX_EXPORT_BYTES
    ):
        raise ValueError("temporary export identity invalid")


def _validate_published_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink not in {1, 2}
        or not 0 < metadata.st_size <= MAX_EXPORT_BYTES
    ):
        raise ValueError("published export identity invalid")
