"""Fd-pinned, read-only custody inventory for Issue #267 C2.

This module deliberately does not capture RPC facts, bind a Commodity owner, or
publish reconciliation evidence.  It provides the filesystem trust primitive
that those later steps must execute while holding the same deployment flock.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from threading import get_ident
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError

from app.schemas.deployment_drain import (
    DeploymentCustodyFileEntryDTO,
    DeploymentEpochAnchorV2DTO,
    DeploymentLegacyMigrationSourceArchiveDTO,
    DeploymentReconciliationCustodyInventoryDTO,
    LegacyMigrationSourceStateV1DTO,
    LegacyMigrationSourceStateV2DTO,
    SafeRestartConsumeCommitMarkerDTO,
    SafeRestartOnlineRecheckDTO,
)
from app.services.deployment_restart_reconciliation import (
    DeploymentRestartReconciliationError,
    _require_exact_state_v3,
    verify_planned_restart_input_bundle,
)
from app.services.deployment_state_commitment import (
    DeploymentStateCommitmentError,
    parse_exact_state_commitment,
)


class DeploymentReconciliationCustodyError(RuntimeError):
    """A live custody snapshot cannot be proved safe or self-consistent."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


_LOCK_NAME = ".deployment-drain.lock"
_STATE_NAME = "state.json"
_ANCHOR_NAME = "epoch-anchor.json"
_INPUT_DIRECTORIES = (
    "receipts",
    "consumes",
    "checkpoints",
    "rechecks",
    "state-commitments",
    "migration-sources",
)
_RESERVED_OUTPUT_DIRECTORIES = (
    "reconciliation-intents",
    "reconciliation-blobs",
    "reconciliation-heads",
)
_RESERVED_OUTPUT_DIRECTORY_SET = frozenset(_RESERVED_OUTPUT_DIRECTORIES)
_OUTPUT_BASENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,249}\.json$")
_ROOT_ENTRIES = frozenset(
    (_LOCK_NAME, _STATE_NAME, _ANCHOR_NAME)
    + _INPUT_DIRECTORIES
    + _RESERVED_OUTPUT_DIRECTORIES
)
_SHA = r"(?!0{64})[0-9a-f]{64}"
_BASENAME_PATTERNS: dict[str, tuple[str, re.Pattern[str]]] = {
    "receipts": (
        "RECEIPT",
        re.compile(rf"^safe-restart-{_SHA}\.json$"),
    ),
    "checkpoints": (
        "CHECKPOINT",
        re.compile(rf"^checkpoint-{_SHA}\.json$"),
    ),
    "rechecks": (
        "RECHECK",
        re.compile(rf"^safe-restart-{_SHA}\.online-recheck\.json$"),
    ),
    "state-commitments": (
        "STATE_COMMITMENT",
        re.compile(r"^[0-9]{20}\.json$"),
    ),
}
_CONSUME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "CONSUME_INTENT",
        re.compile(rf"^safe-restart-{_SHA}\.consume-intent\.json$"),
    ),
    (
        "CONSUME_MARKER",
        re.compile(rf"^safe-restart-{_SHA}\.consume-marker\.json$"),
    ),
)
_MIGRATION_SOURCE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^source-state-{_SHA}\.json$"),
    re.compile(rf"^source-epoch-anchor-{_SHA}\.json$"),
    re.compile(rf"^archive-{_SHA}\.json$"),
)
_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_BASELINE_EMPTY_FIELDS = {
    "active_request_id",
    "active_request_sha256",
    "active_receipt_id",
    "active_receipt_raw_sha256",
    "consumed_at",
    "consume_id",
    "consumed_receipt_id",
    "consume_intent_raw_sha256",
    "consume_marker_raw_sha256",
    "consume_state_projection_sha256",
    "consumed_online_recheck_id",
    "consumed_online_recheck_raw_sha256",
    "preconsume_state_commitment_raw_sha256",
    "active_online_recheck_id",
    "active_online_recheck_raw_sha256",
    "active_recheck_checkpoint_raw_sha256",
    "online_rechecked_at",
    "last_invalidated_online_recheck_id",
    "last_invalidated_receipt_id",
    "expires_at",
}


@dataclass(frozen=True)
class DeploymentCustodyRawFile:
    """Exact bytes and immutable observation metadata for one input file."""

    entry: DeploymentCustodyFileEntryDTO
    raw: bytes


@dataclass(frozen=True)
class DeploymentReconciliationCustodySnapshot:
    """Validated inventory DTO plus exact bytes indexed by relative path."""

    inventory: DeploymentReconciliationCustodyInventoryDTO
    files: Mapping[str, DeploymentCustodyRawFile]

    def raw_for(self, relative_path: str) -> bytes:
        try:
            return self.files[relative_path].raw
        except KeyError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ENTRY_NOT_FOUND",
                f"custody entry is absent: {relative_path}",
            ) from exc


@dataclass(frozen=True)
class DeploymentReconciliationStoredArtifact:
    """One canonical, create-only C2 output observed by secure readback."""

    relative_path: str
    raw_sha256: str
    raw: bytes


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_JSON_INVALID", "custody JSON is not strict"
        ) from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(_canonical_bytes(value))


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_exact_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_JSON_INVALID", f"{label} is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_JSON_INVALID", f"{label} must be a JSON object"
        )
    if raw != _canonical_bytes(value) + b"\n":
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_JSON_NONCANONICAL", f"{label} bytes are not canonical"
        )
    return value


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in _STAT_FIELDS)


def _bounded_directory_names(
    directory_fd: int,
    *,
    max_entries: int,
    label: str,
) -> tuple[str, ...]:
    """Enumerate at most the trusted bound before allocating a sortable list."""

    names: list[str] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if len(names) >= max_entries:
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_ENTRY_LIMIT_EXCEEDED",
                        f"custody directory exceeds the entry limit: {label}",
                    )
                names.append(entry.name)
    except OSError as exc:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_DIRECTORY_LIST_FAILED",
            f"custody directory cannot be enumerated: {label}",
        ) from exc
    return tuple(sorted(names))


def _identity_matches_fd(path_info: os.stat_result, fd_info: os.stat_result) -> bool:
    return (
        not stat.S_ISLNK(path_info.st_mode)
        and path_info.st_dev == fd_info.st_dev
        and path_info.st_ino == fd_info.st_ino
    )


class DeploymentReconciliationCustodyRepository:
    """Read actual deployment custody through pinned directory descriptors."""

    def __init__(
        self,
        root: Path | str,
        *,
        expected_uid: int | None = None,
        max_entries: int = 10_000,
        max_file_bytes: int = 16 * 1024 * 1024,
        max_total_bytes: int = 128 * 1024 * 1024,
    ) -> None:
        root_path = Path(root).expanduser()
        if (
            not root_path.is_absolute()
            or Path(os.path.normpath(root_path)) != root_path
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_PATH_INVALID",
                "custody root must be absolute and lexically normalized",
            )
        for name, value in (
            ("max_entries", max_entries),
            ("max_file_bytes", max_file_bytes),
            ("max_total_bytes", max_total_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.root = root_path
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid
        if type(self.expected_uid) is not int or self.expected_uid < 0:
            raise ValueError("expected_uid must be a non-negative integer")
        self.max_entries = max_entries
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self._session_capability = object()

    def snapshot(
        self, *, captured_at: datetime | None = None
    ) -> DeploymentReconciliationCustodySnapshot:
        """Acquire the deployment flock and return one validated live snapshot."""

        with self.locked() as session:
            return session.snapshot(captured_at=captured_at)

    @contextmanager
    def locked(self) -> Iterator[DeploymentReconciliationCustodySession]:
        """Hold the deployment flock and pinned root for a future C2 transaction."""

        root_fd = self._open_root()
        lock_fd: int | None = None
        try:
            root_info = os.fstat(root_fd)
            self._validate_directory(root_info, "custody root")
            self._assert_root_path(root_fd, root_info)
            lock_fd = self._open_regular_at(root_fd, _LOCK_NAME, "deployment lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            lock_info = os.fstat(lock_fd)
            lock_path_info = os.stat(_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
            if not _identity_matches_fd(lock_path_info, lock_info):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_LOCK_REPLACED",
                    "deployment lock path changed during acquisition",
                )
            self._assert_root_path(root_fd, root_info)
            session = DeploymentReconciliationCustodySession(
                repository=self,
                root_fd=root_fd,
                lock_fd=lock_fd,
                root_info=root_info,
                lock_info=lock_info,
                capability=self._session_capability,
            )
            session._activate()
            try:
                yield session
            finally:
                session._deactivate()
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(root_fd)

    def _open_root(self) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC
        for required in ("O_DIRECTORY", "O_NOFOLLOW"):
            value = getattr(os, required, None)
            if value is None:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_PLATFORM_UNSUPPORTED",
                    f"secure custody requires {required}",
                )
            flags |= value
        current_fd: int | None = None
        try:
            current_fd = os.open("/", flags)
            for component in self.root.parts[1:]:
                _validate_basename(component)
                next_fd = os.open(component, flags, dir_fd=current_fd)
                path_info = os.stat(
                    component,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
                next_info = os.fstat(next_fd)
                if not _identity_matches_fd(path_info, next_info):
                    os.close(next_fd)
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_ROOT_REPLACED",
                        "custody root component changed during anchored traversal",
                    )
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except DeploymentReconciliationCustodyError:
            if current_fd is not None:
                os.close(current_fd)
            raise
        except OSError as exc:
            if current_fd is not None:
                os.close(current_fd)
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_OPEN_FAILED",
                "custody root cannot be opened by symlink-free anchored traversal",
            ) from exc

    def _assert_root_path(self, root_fd: int, expected: os.stat_result) -> None:
        current_fd = os.fstat(root_fd)
        try:
            path_fd = self._open_root()
        except DeploymentReconciliationCustodyError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_REPLACED", "custody root path became unavailable"
            ) from exc
        try:
            current_path = os.fstat(path_fd)
        finally:
            os.close(path_fd)
        if not _same_stat(current_fd, expected) or not _identity_matches_fd(
            current_path, expected
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_REPLACED", "custody root identity changed"
            )

    def _validate_directory(self, info: os.stat_result, label: str) -> None:
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.expected_uid
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_DIRECTORY_INSECURE", f"{label} is not owner-only"
            )

    def _open_regular_at(self, parent_fd: int, name: str, label: str) -> int:
        _validate_basename(name)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_FILE_OPEN_FAILED", f"{label} cannot be securely opened"
            ) from exc
        try:
            self._validate_regular(os.fstat(fd), label)
            return fd
        except Exception:
            os.close(fd)
            raise

    def _validate_regular(self, info: os.stat_result, label: str) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.expected_uid
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_FILE_INSECURE",
                f"{label} is not an owner-only single-link file",
            )


class DeploymentReconciliationCustodySession:
    """One flock-held view of a pinned custody root."""

    def __init__(
        self,
        *,
        repository: DeploymentReconciliationCustodyRepository,
        root_fd: int,
        lock_fd: int,
        root_info: os.stat_result,
        lock_info: os.stat_result,
        capability: object,
    ) -> None:
        if capability is not repository._session_capability:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_SESSION_UNTRUSTED",
                "custody sessions must be created by their repository",
            )
        self.repository = repository
        self.root_fd = root_fd
        self.lock_fd = lock_fd
        self.root_info = root_info
        self.lock_info = lock_info
        self._active = False
        self._owner_thread_id: int | None = None

    def _activate(self) -> None:
        if self._active:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_SESSION_STATE_INVALID", "custody session is already active"
            )
        self._owner_thread_id = get_ident()
        self._active = True

    def _deactivate(self) -> None:
        self._active = False
        self._owner_thread_id = None

    def assert_live(self) -> None:
        """Prove this call still runs in the thread holding the pinned flock."""

        if not self._active:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_SESSION_CLOSED", "custody session is no longer active"
            )
        if self._owner_thread_id != get_ident():
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_SESSION_THREAD_MISMATCH",
                "custody session cannot cross thread ownership",
            )
        self._assert_session_identity()

    def write_intent(
        self, basename: str, payload: Mapping[str, Any]
    ) -> DeploymentReconciliationStoredArtifact:
        return self._write_output("reconciliation-intents", basename, payload)

    def write_blob(
        self, basename: str, payload: Mapping[str, Any]
    ) -> DeploymentReconciliationStoredArtifact:
        return self._write_output("reconciliation-blobs", basename, payload)

    def write_head(
        self, basename: str, payload: Mapping[str, Any]
    ) -> DeploymentReconciliationStoredArtifact:
        return self._write_output("reconciliation-heads", basename, payload)

    def read_intent(self, basename: str) -> DeploymentReconciliationStoredArtifact:
        return self._read_output("reconciliation-intents", basename)

    def read_blob(self, basename: str) -> DeploymentReconciliationStoredArtifact:
        return self._read_output("reconciliation-blobs", basename)

    def read_head(self, basename: str) -> DeploymentReconciliationStoredArtifact:
        return self._read_output("reconciliation-heads", basename)

    def _write_output(
        self,
        directory_name: str,
        basename: str,
        payload: Mapping[str, Any],
    ) -> DeploymentReconciliationStoredArtifact:
        self.assert_live()
        self._validate_output_location(directory_name, basename)
        if not isinstance(payload, Mapping):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_JSON_INVALID",
                "custody output must be one JSON object",
            )
        raw = _canonical_bytes(dict(payload)) + b"\n"
        _parse_exact_object(raw, f"{directory_name}/{basename}")
        if len(raw) > self.repository.max_file_bytes:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_SIZE_INVALID", "custody output exceeds the file limit"
            )

        directory_fd = self._open_output_directory(directory_name, create=True)
        try:
            existing = self._stat_output(directory_fd, basename)
            if existing is not None:
                return self._reuse_output(
                    directory_fd, directory_name, basename, raw
                )
            temporary = f".{basename}.{uuid.uuid4().hex}.tmp"
            temp_fd: int | None = None
            temp_info: os.stat_result | None = None
            publish_collision = False
            try:
                temp_fd = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                os.fchmod(temp_fd, 0o600)
                temp_info = os.fstat(temp_fd)
                self.repository._validate_regular(
                    temp_info, f"temporary custody output {temporary}"
                )
                self._write_all(temp_fd, raw)
                self._fsync(temp_fd, "custody output file")
                os.close(temp_fd)
                temp_fd = None
                try:
                    os.link(
                        temporary,
                        basename,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    publish_collision = True
                self._fsync(directory_fd, "custody output directory")
            except OSError as exc:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_WRITE_FAILED",
                    f"custody output cannot be published: {directory_name}/{basename}",
                ) from exc
            finally:
                if temp_fd is not None:
                    os.close(temp_fd)
                if temp_info is not None:
                    self._unlink_temporary(directory_fd, temporary, temp_info)

            if publish_collision:
                return self._reuse_output(
                    directory_fd, directory_name, basename, raw
                )
            observed = self._read_output_raw(directory_fd, basename)
            if observed != raw:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_READBACK_MISMATCH",
                    f"custody output readback differs: {directory_name}/{basename}",
                )
            self.assert_live()
            return self._stored_artifact(directory_name, basename, observed)
        finally:
            os.close(directory_fd)

    def _read_output(
        self, directory_name: str, basename: str
    ) -> DeploymentReconciliationStoredArtifact:
        self.assert_live()
        self._validate_output_location(directory_name, basename)
        directory_fd = self._open_output_directory(directory_name, create=False)
        try:
            raw = self._read_output_raw(directory_fd, basename)
            self.assert_live()
            return self._stored_artifact(directory_name, basename, raw)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _validate_output_location(directory_name: str, basename: str) -> None:
        if directory_name not in _RESERVED_OUTPUT_DIRECTORY_SET:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_DIRECTORY_INVALID", "custody output role is invalid"
            )
        _validate_basename(basename)
        if (
            not _OUTPUT_BASENAME_RE.fullmatch(basename)
            or basename.startswith(".")
            or any(
                token in basename.lower()
                for token in (".tmp", ".bak", "backup", "~")
            )
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_NAME_INVALID", "custody output basename is invalid"
            )

    def _open_output_directory(self, name: str, *, create: bool) -> int:
        self.assert_live()
        created = False
        try:
            descriptor = self._open_directory_at(self.root_fd, name)
        except DeploymentReconciliationCustodyError as exc:
            if not create or exc.code != "CUSTODY_DIRECTORY_OPEN_FAILED":
                raise
            try:
                os.mkdir(name, 0o700, dir_fd=self.root_fd)
                created = True
            except FileExistsError:
                # A concurrent creator is not trusted as this session owns the flock.
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_DIRECTORY_RACE",
                    f"custody output directory appeared concurrently: {name}",
                ) from exc
            except OSError as mkdir_exc:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_DIRECTORY_CREATE_FAILED",
                    f"custody output directory cannot be created: {name}",
                ) from mkdir_exc
            descriptor = self._open_directory_at(self.root_fd, name)

        try:
            if created:
                os.fchmod(descriptor, 0o700)
                self._fsync(descriptor, "custody output directory")
                self._fsync(self.root_fd, "custody root directory")
                refreshed = os.fstat(self.root_fd)
                if (
                    refreshed.st_dev != self.root_info.st_dev
                    or refreshed.st_ino != self.root_info.st_ino
                ):
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_ROOT_REPLACED", "custody root changed during mkdir"
                    )
                self.repository._validate_directory(refreshed, "custody root")
                self.root_info = refreshed
                self.repository._assert_root_path(self.root_fd, refreshed)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _stat_output(directory_fd: int, basename: str) -> os.stat_result | None:
        try:
            return os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_STAT_FAILED", "custody output cannot be inspected"
            ) from exc

    def _reuse_output(
        self,
        directory_fd: int,
        directory_name: str,
        basename: str,
        expected: bytes,
    ) -> DeploymentReconciliationStoredArtifact:
        observed = self._read_output_raw(directory_fd, basename)
        if observed != expected:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_COLLISION",
                f"custody output slot contains different bytes: {directory_name}/{basename}",
            )
        self._fsync(directory_fd, "custody output directory")
        self.assert_live()
        return self._stored_artifact(directory_name, basename, observed)

    def _read_output_raw(self, directory_fd: int, basename: str) -> bytes:
        fd = self.repository._open_regular_at(
            directory_fd, basename, f"custody output {basename}"
        )
        try:
            before = os.fstat(fd)
            path_before = os.stat(
                basename, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                not _identity_matches_fd(path_before, before)
                or before.st_size < 1
                or before.st_size > self.repository.max_file_bytes
            ):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_FILE_INVALID", "custody output is not securely bounded"
                )
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            path_after = os.stat(
                basename, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                len(raw) != before.st_size
                or not _same_stat(before, after)
                or not _same_stat(path_before, path_after)
                or not _identity_matches_fd(path_after, after)
            ):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_CHANGED_DURING_READ",
                    "custody output changed during secure readback",
                )
        finally:
            os.close(fd)
        _parse_exact_object(raw, basename)
        return raw

    @staticmethod
    def _stored_artifact(
        directory_name: str, basename: str, raw: bytes
    ) -> DeploymentReconciliationStoredArtifact:
        return DeploymentReconciliationStoredArtifact(
            relative_path=str(PurePosixPath(directory_name, basename)),
            raw_sha256=_sha256(raw),
            raw=raw,
        )

    @staticmethod
    def _write_all(fd: int, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            try:
                written = os.write(fd, raw[offset:])
            except OSError as exc:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_WRITE_FAILED", "custody output write failed"
                ) from exc
            if written <= 0:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_OUTPUT_WRITE_FAILED", "custody output write made no progress"
                )
            offset += written

    @staticmethod
    def _fsync(fd: int, label: str) -> None:
        try:
            os.fsync(fd)
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_FSYNC_FAILED", f"{label} fsync failed"
            ) from exc

    def _unlink_temporary(
        self, directory_fd: int, temporary: str, expected: os.stat_result
    ) -> None:
        try:
            current = os.stat(
                temporary, dir_fd=directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_TEMP_CLEANUP_FAILED",
                "custody output temporary cannot be inspected",
            ) from exc
        if not _identity_matches_fd(current, expected):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_TEMP_REPLACED",
                "custody output temporary was replaced",
            )
        try:
            os.unlink(temporary, dir_fd=directory_fd)
            self._fsync(directory_fd, "custody output directory")
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_OUTPUT_TEMP_CLEANUP_FAILED",
                "custody output temporary cannot be removed",
            ) from exc

    def snapshot(
        self, *, captured_at: datetime | None = None
    ) -> DeploymentReconciliationCustodySnapshot:
        observed_at = captured_at or datetime.now(timezone.utc)
        if (
            observed_at.tzinfo is None
            or observed_at.utcoffset() is None
            or observed_at.utcoffset().total_seconds() != 0
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_CAPTURE_TIME_INVALID", "custody capture time must be UTC"
            )
        self._assert_session_identity()
        directories = self._open_input_directories()
        try:
            directory_snapshot = self._snapshot_directory_identities(directories)
            raw_files = self._read_inventory(directories)
            self._assert_directories_unchanged(directories, directory_snapshot)
            self._assert_files_unchanged(raw_files, directories)
        finally:
            for descriptor in directories.values():
                os.close(descriptor)
        self._assert_session_identity()
        return self._build_snapshot(raw_files, observed_at)

    def _snapshot_directory_identities(
        self, directories: Mapping[str, int]
    ) -> tuple[tuple[str, ...], dict[str, tuple[os.stat_result, tuple[str, ...]]]]:
        try:
            root_names = _bounded_directory_names(
                self.root_fd,
                max_entries=len(_ROOT_ENTRIES),
                label="custody root",
            )
            snapshots: dict[str, tuple[os.stat_result, tuple[str, ...]]] = {}
            remaining = max(self.repository.max_entries - 2, 0)
            for name, descriptor in directories.items():
                info = os.fstat(descriptor)
                path_info = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
                if not _identity_matches_fd(path_info, info):
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_DIRECTORY_REPLACED",
                        f"custody directory path changed before scan: {name}",
                    )
                names = _bounded_directory_names(
                    descriptor,
                    max_entries=remaining,
                    label=name,
                )
                snapshots[name] = (info, names)
                remaining -= len(names)
            return root_names, snapshots
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_DIRECTORY_LIST_FAILED",
                "custody directory identity cannot be captured",
            ) from exc

    def _assert_directories_unchanged(
        self,
        directories: Mapping[str, int],
        expected: tuple[
            tuple[str, ...], dict[str, tuple[os.stat_result, tuple[str, ...]]]
        ],
    ) -> None:
        root_names, directory_snapshots = expected
        try:
            if (
                _bounded_directory_names(
                    self.root_fd,
                    max_entries=len(root_names),
                    label="custody root",
                )
                != root_names
            ):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_INVENTORY_CHANGED",
                    "custody root entries changed during the snapshot",
                )
            for name, descriptor in directories.items():
                before, before_names = directory_snapshots[name]
                after = os.fstat(descriptor)
                path_after = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
                after_names = _bounded_directory_names(
                    descriptor,
                    max_entries=len(before_names),
                    label=name,
                )
                if (
                    not _same_stat(before, after)
                    or not _identity_matches_fd(path_after, after)
                    or after_names != before_names
                ):
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_INVENTORY_CHANGED",
                        f"custody directory changed during snapshot: {name}",
                    )
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_INVENTORY_CHANGED",
                "custody directory became unavailable during snapshot",
            ) from exc

    def _assert_files_unchanged(
        self,
        files: Mapping[str, DeploymentCustodyRawFile],
        directories: Mapping[str, int],
    ) -> None:
        """Revalidate every observed inode after the complete inventory scan."""

        try:
            for relative_path, observed in files.items():
                parts = PurePosixPath(relative_path).parts
                if len(parts) == 1:
                    parent_fd = self.root_fd
                    name = parts[0]
                elif len(parts) == 2 and parts[0] in directories:
                    parent_fd = directories[parts[0]]
                    name = parts[1]
                else:  # DTO path validation should make this unreachable.
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_ENTRY_PATH_INVALID",
                        f"custody entry has no pinned parent: {relative_path}",
                    )
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                entry = observed.entry
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_dev != entry.device
                    or current.st_ino != entry.inode
                    or current.st_uid != entry.uid
                    or current.st_gid != entry.gid
                    or stat.S_IMODE(current.st_mode) != entry.mode
                    or current.st_nlink != entry.nlink
                    or current.st_size != entry.size
                    or current.st_mtime_ns != entry.mtime_ns
                    or current.st_ctime_ns != entry.ctime_ns
                ):
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_FILE_CHANGED_AFTER_READ",
                        f"custody file changed after read: {relative_path}",
                    )
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_FILE_CHANGED_AFTER_READ",
                "custody file became unavailable after read",
            ) from exc

    def _assert_session_identity(self) -> None:
        self.repository._assert_root_path(self.root_fd, self.root_info)
        if not _same_stat(os.fstat(self.lock_fd), self.lock_info):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LOCK_REPLACED", "deployment lock identity changed"
            )
        try:
            path_info = os.stat(_LOCK_NAME, dir_fd=self.root_fd, follow_symlinks=False)
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LOCK_REPLACED", "deployment lock path became unavailable"
            ) from exc
        if not _identity_matches_fd(path_info, self.lock_info):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LOCK_REPLACED", "deployment lock path changed"
            )

    def _open_input_directories(self) -> dict[str, int]:
        try:
            root_names = set(
                _bounded_directory_names(
                    self.root_fd,
                    max_entries=len(_ROOT_ENTRIES),
                    label="custody root",
                )
            )
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_LIST_FAILED", "custody root cannot be enumerated"
            ) from exc
        unknown = sorted(root_names - _ROOT_ENTRIES)
        missing = sorted(
            set((_LOCK_NAME, _STATE_NAME, _ANCHOR_NAME) + _INPUT_DIRECTORIES)
            - root_names
        )
        if unknown:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_INVENTORY_INVALID",
                f"custody root contains unknown entries: {unknown}",
            )
        if missing:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_ROOT_INVENTORY_INVALID",
                f"custody root is missing required entries: {missing}",
            )
        result: dict[str, int] = {}
        try:
            for name in _INPUT_DIRECTORIES:
                result[name] = self._open_directory_at(self.root_fd, name)
            for name in _RESERVED_OUTPUT_DIRECTORIES:
                if name in root_names:
                    output_fd = self._open_directory_at(self.root_fd, name)
                    os.close(output_fd)
            return result
        except Exception:
            for descriptor in result.values():
                os.close(descriptor)
            raise

    def _open_directory_at(self, parent_fd: int, name: str) -> int:
        _validate_basename(name)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_DIRECTORY_OPEN_FAILED",
                f"custody directory cannot be securely opened: {name}",
            ) from exc
        try:
            info = os.fstat(descriptor)
            self.repository._validate_directory(info, name)
            path_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not _identity_matches_fd(path_info, info):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_DIRECTORY_REPLACED",
                    f"custody directory path changed: {name}",
                )
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _read_inventory(
        self, directories: Mapping[str, int]
    ) -> dict[str, DeploymentCustodyRawFile]:
        files: dict[str, DeploymentCustodyRawFile] = {}
        total_bytes = 0
        remaining_entries = max(self.repository.max_entries - 2, 0)
        for name, role in ((_STATE_NAME, "STATE"), (_ANCHOR_NAME, "EPOCH_ANCHOR")):
            observed = self._read_file(self.root_fd, name, role, name)
            files[name] = observed
            total_bytes += len(observed.raw)
        for directory_name in _INPUT_DIRECTORIES:
            directory_fd = directories[directory_name]
            names = _bounded_directory_names(
                directory_fd,
                max_entries=remaining_entries,
                label=directory_name,
            )
            remaining_entries -= len(names)
            for name in names:
                role = _role_for(directory_name, name)
                relative = str(PurePosixPath(directory_name, name))
                observed = self._read_file(directory_fd, name, role, relative)
                files[relative] = observed
                total_bytes += len(observed.raw)
                if total_bytes > self.repository.max_total_bytes:
                    raise DeploymentReconciliationCustodyError(
                        "CUSTODY_TOTAL_SIZE_EXCEEDED",
                        "custody inventory exceeds the total size limit",
                    )
        return files

    def _read_file(
        self, parent_fd: int, name: str, role: str, relative_path: str
    ) -> DeploymentCustodyRawFile:
        fd = self.repository._open_regular_at(parent_fd, name, relative_path)
        try:
            before = os.fstat(fd)
            path_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not _identity_matches_fd(path_before, before):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_FILE_REPLACED",
                    f"custody file changed before read: {relative_path}",
                )
            if before.st_size < 1 or before.st_size > self.repository.max_file_bytes:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_FILE_SIZE_INVALID",
                    f"custody file size is outside limits: {relative_path}",
                )
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            path_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                len(raw) != before.st_size
                or not _same_stat(before, after)
                or not _same_stat(path_before, path_after)
                or not _identity_matches_fd(path_after, after)
            ):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_FILE_CHANGED_DURING_READ",
                    f"custody file changed during read: {relative_path}",
                )
        except OSError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_FILE_READ_FAILED",
                f"custody file cannot be read: {relative_path}",
            ) from exc
        finally:
            os.close(fd)
        _parse_exact_object(raw, relative_path)
        entry = _build_entry(role, relative_path, raw, before)
        return DeploymentCustodyRawFile(entry=entry, raw=raw)

    def _build_snapshot(
        self,
        files: dict[str, DeploymentCustodyRawFile],
        captured_at: datetime,
    ) -> DeploymentReconciliationCustodySnapshot:
        state_raw = files[_STATE_NAME].raw
        anchor_raw = files[_ANCHOR_NAME].raw
        state = _parse_exact_object(state_raw, _STATE_NAME)
        anchor_payload = _parse_exact_object(anchor_raw, _ANCHOR_NAME)
        try:
            anchor = DeploymentEpochAnchorV2DTO.model_validate(anchor_payload)
        except ValidationError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_EPOCH_ANCHOR_INVALID", "epoch anchor v2 is invalid"
            ) from exc

        commitment_paths = sorted(
            path
            for path, item in files.items()
            if item.entry.role == "STATE_COMMITMENT"
        )
        if len(commitment_paths) < 2:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_COMMITMENT_CHAIN_INCOMPLETE",
                "custody requires genesis and current runtime commitments",
            )
        commitments = []
        previous_raw_sha: str | None = None
        previous_created_at: datetime | None = None
        for generation, path in enumerate(commitment_paths, start=1):
            if path != f"state-commitments/{generation:020d}.json":
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_COMMITMENT_CHAIN_GAP",
                    "state commitment inventory is not contiguous",
                )
            raw = files[path].raw
            try:
                commitment = parse_exact_state_commitment(raw)
            except DeploymentStateCommitmentError as exc:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_COMMITMENT_INVALID",
                    f"state commitment is invalid: {path}",
                ) from exc
            try:
                strict_state = _require_exact_state_v3(commitment.state)
            except DeploymentRestartReconciliationError as exc:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_COMMITMENT_STATE_INVALID",
                    f"state commitment does not contain exact state v3: {path}",
                ) from exc
            if (
                commitment.state_generation != generation
                or commitment.previous_state_commitment_raw_sha256 != previous_raw_sha
                or commitment.state.get("updated_at")
                != commitment.created_at.isoformat()
                or strict_state != commitment.state
                or (
                    previous_created_at is not None
                    and commitment.created_at < previous_created_at
                )
            ):
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_COMMITMENT_CHAIN_INVALID",
                    "state commitment chain is not exact and monotonic",
                )
            commitments.append(commitment)
            previous_raw_sha = _sha256(raw)
            previous_created_at = commitment.created_at

        genesis = commitments[0]
        head = commitments[-1]
        head_raw_sha = _sha256(files[commitment_paths[-1]].raw)
        state_raw_sha = _sha256(state_raw)
        if (
            state.get("schema_version") != "web_bridge_deployment_drain_state_v3"
            or state.get("state") != "RESTARTED_FROZEN"
            or type(state.get("state_generation")) is not int
            or state["state_generation"] != len(commitments)
            or type(state.get("drain_epoch")) is not int
            or state["drain_epoch"] < 0
            or type(state.get("execution_epoch")) is not int
            or state["execution_epoch"] < 1
            or not isinstance(state.get("runtime_instance_id"), str)
            or head.state != state
            or head.state_raw_sha256 != state_raw_sha
            or anchor.state_generation != state["state_generation"]
            or anchor.state_commitment_raw_sha256 != head_raw_sha
            or anchor.drain_epoch != state["drain_epoch"]
            or anchor.execution_epoch != state["execution_epoch"]
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_CURRENT_HEAD_MISMATCH",
                "state, commitment head, and epoch anchor are inconsistent",
            )

        mode = _derive_mode(state, genesis.genesis_source)
        business_roles = {
            "RECEIPT",
            "CHECKPOINT",
            "RECHECK",
            "CONSUME_INTENT",
            "CONSUME_MARKER",
        }
        business_entries = [
            item for item in files.values() if item.entry.role in business_roles
        ]
        if (
            mode in {"INITIAL_BASELINE", "LEGACY_MIGRATION_BASELINE"}
            and business_entries
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_BASELINE_INVENTORY_NOT_EMPTY",
                "an unconsumed baseline cannot contain restart artifacts",
            )
        if mode == "INITIAL_BASELINE":
            _validate_initial_baseline_lineage(commitments)
        elif mode == "LEGACY_MIGRATION_BASELINE":
            archive = self._validate_legacy_archive(files, genesis)
            _validate_legacy_baseline_lineage(commitments, archive)
        elif mode == "PLANNED_RESTART":
            _validate_planned_restart_closure(
                state=state,
                files=files,
                commitments=commitments,
                commitment_paths=commitment_paths,
                anchor_raw=anchor_raw,
            )
        if mode != "LEGACY_MIGRATION_BASELINE" and any(
            item.entry.role == "LEGACY_SOURCE_ARCHIVE" for item in files.values()
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_MODE_AMBIGUOUS",
                "non-migration custody contains legacy source archive files",
            )

        entries = sorted(
            (item.entry for item in files.values()),
            key=lambda item: (item.relative_path, item.role),
        )
        entries_json = [entry.model_dump(mode="json") for entry in entries]
        inventory_digest = _canonical_sha256(entries_json)
        core: dict[str, Any] = {
            "schema_version": (
                "web_bridge_deployment_reconciliation_custody_inventory_v1"
            ),
            "purpose": "bind_actual_live_custody_for_owner_reconciliation",
            "mode": mode,
            "inventory_digest_sha256": inventory_digest,
            "custody_root_path_sha256": _sha256(
                str(self.repository.root).encode("utf-8")
            ),
            "custody_root_device": self.root_info.st_dev,
            "custody_root_inode": self.root_info.st_ino,
            "custody_root_uid": self.root_info.st_uid,
            "custody_root_gid": self.root_info.st_gid,
            "custody_root_mode": stat.S_IMODE(self.root_info.st_mode),
            "custody_root_nlink": self.root_info.st_nlink,
            "lock_file_device": self.lock_info.st_dev,
            "lock_file_inode": self.lock_info.st_ino,
            "lock_file_uid": self.lock_info.st_uid,
            "lock_file_gid": self.lock_info.st_gid,
            "lock_file_mode": stat.S_IMODE(self.lock_info.st_mode),
            "lock_file_nlink": self.lock_info.st_nlink,
            "genesis_commitment_raw_sha256": _sha256(files[commitment_paths[0]].raw),
            "genesis_commitment": genesis.model_dump(mode="json"),
            "state_commitment_raw_sha256s": [
                _sha256(files[path].raw) for path in commitment_paths
            ],
            "state_commitments": [
                commitment.model_dump(mode="json") for commitment in commitments
            ],
            "actual_state_raw_sha256": state_raw_sha,
            "actual_state": state,
            "actual_epoch_anchor_raw_sha256": _sha256(anchor_raw),
            "actual_epoch_anchor": anchor.model_dump(mode="json"),
            "actual_head_commitment_raw_sha256": head_raw_sha,
            "actual_head_commitment": head.model_dump(mode="json"),
            "actual_state_generation": state["state_generation"],
            "actual_drain_epoch": state["drain_epoch"],
            "actual_execution_epoch": state["execution_epoch"],
            "actual_runtime_instance_id": state["runtime_instance_id"],
            "entries": entries_json,
            "captured_at": captured_at,
            "fd_pinned_root_verified": True,
            "deployment_flock_held": True,
            "actual_live_custody_verified": True,
            "custody_inventory_verified": True,
            "external_high_water_verified": False,
            "target_runtime_verified": False,
            "reconciliation_completed": False,
            "windows_fence_released": False,
            "authority_restore_allowed": False,
            "consume_authorized": False,
            "reconciliation_authorized": False,
            "deployment_authorized": False,
            "automatic_deploy_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        }
        digest_core = {**core, "captured_at": captured_at.isoformat()}
        digest = _canonical_sha256(digest_core)
        try:
            inventory = DeploymentReconciliationCustodyInventoryDTO.model_validate(
                {
                    **core,
                    "inventory_id": (
                        f"deployment-reconciliation-custody-inventory-{digest}"
                    ),
                    "inventory_core_sha256": digest,
                }
            )
        except ValidationError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_INVENTORY_INVALID",
                "validated custody cannot form an inventory DTO",
            ) from exc
        return DeploymentReconciliationCustodySnapshot(
            inventory=inventory,
            files=MappingProxyType(dict(files)),
        )

    def _validate_legacy_archive(
        self, files: Mapping[str, DeploymentCustodyRawFile], genesis: Any
    ) -> DeploymentLegacyMigrationSourceArchiveDTO:
        migration_files = {
            path: item
            for path, item in files.items()
            if item.entry.role == "LEGACY_SOURCE_ARCHIVE"
        }
        archive_paths = [
            path
            for path in migration_files
            if PurePosixPath(path).name.startswith("archive-")
        ]
        if len(migration_files) != 3 or len(archive_paths) != 1:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_ARCHIVE_INCOMPLETE",
                "legacy mode requires exactly one sealed state/anchor archive",
            )
        archive_path = archive_paths[0]
        try:
            archive = DeploymentLegacyMigrationSourceArchiveDTO.model_validate_json(
                migration_files[archive_path].raw
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_ARCHIVE_INVALID",
                "legacy migration source archive is invalid",
            ) from exc
        if archive.archive_path != archive_path:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_ARCHIVE_PATH_MISMATCH",
                "legacy archive does not bind its actual relative path",
            )
        try:
            state_raw = migration_files[archive.source_state_path].raw
            anchor_raw = migration_files[archive.source_epoch_anchor_path].raw
        except KeyError as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_ARCHIVE_INCOMPLETE",
                "legacy archive source bytes are absent",
            ) from exc
        expected_state_raw = _canonical_bytes(archive.source_state) + b"\n"
        expected_anchor_raw = (
            _canonical_bytes(archive.source_epoch_anchor.model_dump(mode="json"))
            + b"\n"
        )
        expected_source = (
            "v1_migration"
            if archive.source_schema_version == "web_bridge_deployment_drain_state_v1"
            else "v2_migration"
        )
        if (
            state_raw != expected_state_raw
            or anchor_raw != expected_anchor_raw
            or _sha256(state_raw) != archive.source_state_raw_sha256
            or _sha256(anchor_raw) != archive.source_epoch_anchor_raw_sha256
            or genesis.genesis_source != expected_source
            or genesis.source_state_raw_sha256 != archive.source_state_raw_sha256
            or genesis.source_epoch_anchor_raw_sha256
            != archive.source_epoch_anchor_raw_sha256
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_ARCHIVE_BINDING_MISMATCH",
                "sealed legacy bytes do not bind the migration genesis",
            )
        return archive


def _validate_basename(name: str) -> None:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_BASENAME_INVALID", "custody entry basename is unsafe"
        )


def _role_for(directory_name: str, name: str) -> str:
    _validate_basename(name)
    if name.startswith(".") or any(
        token in name.lower() for token in (".tmp", ".bak", "backup", "~")
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_TEMPORARY_OR_BACKUP_FORBIDDEN",
            f"temporary or backup custody entry is forbidden: {directory_name}/{name}",
        )
    if directory_name == "consumes":
        for role, pattern in _CONSUME_PATTERNS:
            if pattern.fullmatch(name):
                return role
    elif directory_name == "migration-sources":
        if any(pattern.fullmatch(name) for pattern in _MIGRATION_SOURCE_PATTERNS):
            return "LEGACY_SOURCE_ARCHIVE"
    else:
        role_and_pattern = _BASENAME_PATTERNS.get(directory_name)
        if role_and_pattern is not None and role_and_pattern[1].fullmatch(name):
            return role_and_pattern[0]
    raise DeploymentReconciliationCustodyError(
        "CUSTODY_ENTRY_NAME_INVALID",
        f"custody entry name is not allowlisted: {directory_name}/{name}",
    )


def _build_entry(
    role: str, relative_path: str, raw: bytes, info: os.stat_result
) -> DeploymentCustodyFileEntryDTO:
    core: dict[str, Any] = {
        "schema_version": "web_bridge_deployment_custody_file_entry_v1",
        "role": role,
        "relative_path": relative_path,
        "raw_sha256": _sha256(raw),
        "size": info.st_size,
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }
    digest = _canonical_sha256(core)
    try:
        return DeploymentCustodyFileEntryDTO.model_validate(
            {
                **core,
                "entry_id": f"deployment-custody-file-entry-{digest}",
                "entry_core_sha256": digest,
            }
        )
    except ValidationError as exc:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_ENTRY_INVALID",
            f"custody entry metadata is invalid: {relative_path}",
        ) from exc


def _derive_mode(state: Mapping[str, Any], genesis_source: object) -> str:
    consumed = state.get("receipt_consumed") is True
    if consumed:
        return "PLANNED_RESTART"
    if genesis_source == "fresh_bootstrap":
        return "INITIAL_BASELINE"
    if genesis_source in {"v1_migration", "v2_migration"}:
        return "LEGACY_MIGRATION_BASELINE"
    raise DeploymentReconciliationCustodyError(
        "CUSTODY_MODE_AMBIGUOUS",
        "custody cannot be assigned to exactly one reconciliation mode",
    )


def _require_empty_fields(state: Mapping[str, Any], label: str) -> None:
    if any(state.get(field) is not None for field in _BASELINE_EMPTY_FIELDS):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_BASELINE_LINEAGE_INVALID",
            f"{label} contains restart or consumption pointers",
        )


def _validate_initial_baseline_lineage(commitments: list[Any]) -> None:
    if len(commitments) < 3:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_INITIAL_BASELINE_INCOMPLETE",
            "fresh bootstrap requires bootstrap activation and online takeover",
        )
    for commitment in commitments:
        state = commitment.state
        _require_empty_fields(state, "fresh bootstrap state")
        if (
            state["state"] != "RESTARTED_FROZEN"
            or state["drain_epoch"] != 0
            or state["receipt_consumed"] is not False
            or state["blockers"] != []
            or state["freeze_reason"] != "initial_bootstrap_requires_reconciliation"
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_INITIAL_BASELINE_INVALID",
                "fresh bootstrap lineage is not pristine and frozen",
            )
    genesis = commitments[0]
    if (
        genesis.genesis_source != "fresh_bootstrap"
        or genesis.source_state_raw_sha256 is not None
        or genesis.source_epoch_anchor_raw_sha256 is not None
        or genesis.state["execution_epoch"] != 0
        or genesis.state["runtime_instance_id"] != "bootstrap-frozen-runtime"
        or commitments[1].state["execution_epoch"] != 1
        or commitments[1].state["runtime_instance_id"] != "bootstrap-frozen-runtime"
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_INITIAL_BASELINE_GENESIS_INVALID",
            "fresh bootstrap genesis or activation is invalid",
        )
    previous = commitments[1].state
    for commitment in commitments[2:]:
        current = commitment.state
        if (
            current["execution_epoch"] != previous["execution_epoch"] + 1
            or current["runtime_instance_id"] == previous["runtime_instance_id"]
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_INITIAL_BASELINE_RUNTIME_INVALID",
                "fresh bootstrap runtime transitions are invalid",
            )
        previous = current
    if (
        commitments[-1].state["runtime_instance_id"] == "bootstrap-frozen-runtime"
        or commitments[-1].state["execution_epoch"] < 2
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_INITIAL_BASELINE_RUNTIME_INVALID",
            "fresh bootstrap has no current online runtime takeover",
        )


def _validate_legacy_baseline_lineage(
    commitments: list[Any], archive: DeploymentLegacyMigrationSourceArchiveDTO
) -> None:
    if len(commitments) < 2:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_LEGACY_BASELINE_INCOMPLETE",
            "legacy migration requires a runtime takeover",
        )
    source_model = (
        LegacyMigrationSourceStateV1DTO
        if archive.source_schema_version == "web_bridge_deployment_drain_state_v1"
        else LegacyMigrationSourceStateV2DTO
    )
    try:
        source = source_model.model_validate(archive.source_state)
    except ValidationError as exc:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_LEGACY_SOURCE_INVALID",
            "sealed legacy source is not a clean strict source state",
        ) from exc
    if source.model_dump(mode="json") != archive.source_state:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_LEGACY_SOURCE_INVALID",
            "sealed legacy source has a non-strict representation",
        )
    seen_runtimes = {source.runtime_instance_id}
    for generation, commitment in enumerate(commitments, start=1):
        state = commitment.state
        _require_empty_fields(state, "legacy migration state")
        if (
            state["state"] != "RESTARTED_FROZEN"
            or state["drain_epoch"] != source.drain_epoch
            or state["receipt_consumed"] is not False
            or state["blockers"]
            != ["legacy_state_migrated_to_v3_requires_reconciliation"]
            or state["freeze_reason"]
            != "legacy_state_migrated_to_v3_requires_reconciliation"
            or state["execution_epoch"] != source.execution_epoch + generation - 1
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_LEGACY_BASELINE_INVALID",
                "legacy migration lineage is not clean and frozen",
            )
        if generation > 1:
            if state["runtime_instance_id"] in seen_runtimes:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_LEGACY_RUNTIME_INVALID",
                    "legacy migration runtime identity was reused",
                )
            seen_runtimes.add(state["runtime_instance_id"])
    expected_genesis = source.model_dump(mode="json")
    if isinstance(source, LegacyMigrationSourceStateV1DTO):
        expected_genesis.update(
            active_online_recheck_id=None,
            active_online_recheck_raw_sha256=None,
            active_recheck_checkpoint_raw_sha256=None,
            online_rechecked_at=None,
            last_invalidated_online_recheck_id=None,
        )
    expected_genesis.update(
        schema_version="web_bridge_deployment_drain_state_v3",
        state_generation=1,
        previous_state_commitment_raw_sha256=None,
        consumed_receipt_id=None,
        consume_intent_raw_sha256=None,
        consume_marker_raw_sha256=None,
        consume_state_projection_sha256=None,
        consumed_online_recheck_id=None,
        consumed_online_recheck_raw_sha256=None,
        preconsume_state_commitment_raw_sha256=None,
        state="RESTARTED_FROZEN",
        blockers=["legacy_state_migrated_to_v3_requires_reconciliation"],
        expires_at=None,
        freeze_reason="legacy_state_migrated_to_v3_requires_reconciliation",
        updated_at=commitments[0].created_at.isoformat(),
    )
    if commitments[0].state != expected_genesis:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_LEGACY_GENESIS_INVALID",
            "migration genesis is not the exact archived source projection",
        )


def _validate_planned_restart_closure(
    *,
    state: Mapping[str, Any],
    files: Mapping[str, DeploymentCustodyRawFile],
    commitments: list[Any],
    commitment_paths: list[str],
    anchor_raw: bytes,
) -> None:
    required_pointer_fields = (
        "consumed_receipt_id",
        "consume_id",
        "consume_intent_raw_sha256",
        "consume_marker_raw_sha256",
        "consume_state_projection_sha256",
        "consumed_online_recheck_id",
        "consumed_online_recheck_raw_sha256",
        "preconsume_state_commitment_raw_sha256",
    )
    if (
        state.get("state") != "RESTARTED_FROZEN"
        or state.get("receipt_consumed") is not True
        or state.get("freeze_reason")
        != "process_restarted_consumed_receipt_requires_reconciliation"
        or state.get("blockers")
        != ["process_restarted_consumed_receipt_requires_reconciliation"]
        or any(not state.get(field) for field in required_pointer_fields)
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_PLANNED_RESTART_INCOMPLETE",
            "consumed restart lacks required pointers or artifacts",
        )

    business_roles = {
        "RECEIPT",
        "CHECKPOINT",
        "RECHECK",
        "CONSUME_INTENT",
        "CONSUME_MARKER",
    }
    observed_business_paths = {
        path for path, item in files.items() if item.entry.role in business_roles
    }
    intent_receipt_ids = {
        PurePosixPath(path).name.removesuffix(".consume-intent.json")
        for path, item in files.items()
        if item.entry.role == "CONSUME_INTENT"
    }
    marker_receipt_ids = {
        PurePosixPath(path).name.removesuffix(".consume-marker.json")
        for path, item in files.items()
        if item.entry.role == "CONSUME_MARKER"
    }
    current_receipt_id = state["consumed_receipt_id"]
    if (
        intent_receipt_ids != marker_receipt_ids
        or current_receipt_id not in marker_receipt_ids
    ):
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
            "planned restart WAL groups are partial or omit the current receipt",
        )

    commitment_raws = [files[path].raw for path in commitment_paths]
    expected_business_paths: set[str] = set()
    groups: list[tuple[Any, ...]] = []
    for receipt_id in sorted(marker_receipt_ids):
        receipt_path = f"receipts/{receipt_id}.json"
        recheck_path = f"rechecks/{receipt_id}.online-recheck.json"
        intent_path = f"consumes/{receipt_id}.consume-intent.json"
        marker_path = f"consumes/{receipt_id}.consume-marker.json"
        try:
            online_raw = files[recheck_path].raw
            marker_raw = files[marker_path].raw
            online = SafeRestartOnlineRecheckDTO.model_validate_json(online_raw)
            marker = SafeRestartConsumeCommitMarkerDTO.model_validate_json(marker_raw)
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
                "planned restart group is absent or invalid",
            ) from exc
        if (
            online_raw != _canonical_bytes(online.model_dump(mode="json")) + b"\n"
            or marker_raw != _canonical_bytes(marker.model_dump(mode="json")) + b"\n"
            or online.receipt_id != receipt_id
            or marker.receipt_id != receipt_id
        ):
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
                "planned restart group bytes or receipt slot are invalid",
            )
        original_checkpoint_path = (
            f"checkpoints/checkpoint-{online.original_checkpoint_raw_sha256}.json"
        )
        recheck_checkpoint_path = (
            f"checkpoints/checkpoint-{online.recheck_checkpoint_raw_sha256}.json"
        )
        expected_business_paths.update(
            {
                receipt_path,
                recheck_path,
                intent_path,
                marker_path,
                original_checkpoint_path,
                recheck_checkpoint_path,
            }
        )
        groups.append(
            (
                receipt_id,
                receipt_path,
                recheck_path,
                intent_path,
                marker_path,
                original_checkpoint_path,
                recheck_checkpoint_path,
                marker,
            )
        )

    if observed_business_paths != expected_business_paths:
        raise DeploymentReconciliationCustodyError(
            "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
            "planned restart contains missing, orphaned, or conflicting artifacts",
        )
    for (
        receipt_id,
        receipt_path,
        recheck_path,
        intent_path,
        marker_path,
        original_checkpoint_path,
        recheck_checkpoint_path,
        marker,
    ) in groups:
        matching_generations = [
            index
            for index, raw in enumerate(commitment_raws)
            if _sha256(raw) == marker.preconsume_state_commitment_raw_sha256
        ]
        if len(matching_generations) != 1:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
                "preconsume commitment is absent or ambiguous",
            )
        preconsume_index = matching_generations[0]
        if receipt_id == current_receipt_id:
            endpoint_index = len(commitments) - 1
            group_anchor_raw = anchor_raw
        else:
            endpoint_index = preconsume_index + 1
            for index in range(preconsume_index + 2, len(commitments)):
                historical_state = commitments[index].state
                if (
                    historical_state.get("state") != "RESTARTED_FROZEN"
                    or historical_state.get("receipt_consumed") is not True
                    or historical_state.get("consumed_receipt_id") != receipt_id
                ):
                    break
                endpoint_index = index
            if endpoint_index < preconsume_index + 2:
                raise DeploymentReconciliationCustodyError(
                    "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
                    "historical planned restart lacks a frozen runtime takeover",
                )
            endpoint = commitments[endpoint_index]
            endpoint_state = endpoint.state
            group_anchor_raw = (
                _canonical_bytes(
                    {
                        "schema_version": "web_bridge_deployment_drain_epoch_anchor_v2",
                        "state_generation": endpoint.state_generation,
                        "state_commitment_raw_sha256": _sha256(
                            commitment_raws[endpoint_index]
                        ),
                        "drain_epoch": endpoint_state["drain_epoch"],
                        "execution_epoch": endpoint_state["execution_epoch"],
                    }
                )
                + b"\n"
            )
        endpoint_state = commitments[endpoint_index].state
        try:
            verify_planned_restart_input_bundle(
                receipt_raw=files[receipt_path].raw,
                original_checkpoint_raw=files[original_checkpoint_path].raw,
                consumed_recheck_checkpoint_raw=files[recheck_checkpoint_path].raw,
                consume_intent_raw=files[intent_path].raw,
                consume_marker_raw=files[marker_path].raw,
                consumed_online_recheck_raw=files[recheck_path].raw,
                preconsume_state_commitment_raw=commitment_raws[preconsume_index],
                state_commitment_chain_raw=commitment_raws[
                    preconsume_index : endpoint_index + 1
                ],
                current_epoch_anchor_raw=group_anchor_raw,
                current_runtime_instance_id=endpoint_state["runtime_instance_id"],
                current_execution_epoch=endpoint_state["execution_epoch"],
            )
        except (KeyError, DeploymentRestartReconciliationError) as exc:
            raise DeploymentReconciliationCustodyError(
                "CUSTODY_PLANNED_RESTART_CLOSURE_INVALID",
                "planned restart exact artifact closure is invalid",
            ) from exc
