"""Create-only artifact custody with a durable receipt hash chain.

The custody root has one live writer. Artifacts, writer-epoch claims and receipt
records are immutable files published with link(2), after the temporary file is
fsync'd, followed by an fsync of the containing directory. All reads and writes
are relative to pinned directory descriptors and reject symlinks.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from shared.artifact_contracts.v1 import (
    build_receipt,
    validate_artifact_envelope,
    validate_receipt,
)
from shared.trust_contracts.v1 import (
    KEY_DOMAINS,
    ContractError,
    assert_non_authoritative,
    canonical_json_line,
    sha256_bytes,
)

CUSTODY_RECORD_SCHEMA_VERSION = "web-bridge-custody-record-v1"
_EPOCH_SCHEMA_VERSION = "web-bridge-custody-writer-epoch-v1"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_RECEIPT_NAME = re.compile(r"^(\d{20})-(receipt-[0-9a-f]{64})\.json$")
_EPOCH_NAME = re.compile(r"^(\d{20})-([A-Za-z0-9][A-Za-z0-9._:-]{0,191})\.json$")


class CustodyError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _State:
    version: int
    previous_receipt_sha256: str | None
    previous_record_sha256: str | None
    artifacts: Mapping[str, dict[str, Any]]
    receipts: tuple[dict[str, Any], ...]
    idempotency: Mapping[str, dict[str, Any]]
    lifecycle: Mapping[str, tuple[str, ...]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_id(value: str, code: str) -> str:
    if not isinstance(value, str) or _SAFE_NAME.fullmatch(value) is None:
        raise CustodyError(code)
    return value


class ArtifactCustody:
    """A context-managed, uniquely fenced custody writer.

    ``schema_registry`` is mandatory: each ``schema_ref`` is either a JSON
    Schema mapping or a validation callback. Unknown schemas fail closed.
    Every new process incarnation must claim an epoch greater than every epoch
    already recorded in this custody root.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        writer_id: str,
        writer_epoch: int,
        schema_registry: Mapping[str, Mapping[str, Any] | Callable[[Any], None]],
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        self.root = Path(root)
        self.writer_id = _safe_id(writer_id, "CUSTODY_WRITER_ID_INVALID")
        if (
            not isinstance(writer_epoch, int)
            or isinstance(writer_epoch, bool)
            or writer_epoch <= 0
        ):
            raise CustodyError("CUSTODY_WRITER_EPOCH_INVALID")
        if not schema_registry:
            raise CustodyError("CUSTODY_SCHEMA_REGISTRY_REQUIRED")
        self.writer_epoch = writer_epoch
        self.schema_registry = dict(schema_registry)
        self.clock = clock
        self._root_fd = -1
        self._lock_fd = -1
        self._dirs: dict[str, int] = {}
        self._open()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        for fd in self._dirs.values():
            os.close(fd)
        self._dirs.clear()
        if self._lock_fd >= 0:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = -1
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def _open(self) -> None:
        try:
            if not self.root.is_absolute() or self.root.resolve() != self.root:
                raise CustodyError("CUSTODY_ROOT_NOT_PINNED")
            self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            self._root_fd = os.open(self.root, flags)
            root_stat = os.fstat(self._root_fd)
            if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_mode & 0o022:
                raise CustodyError("CUSTODY_ROOT_PERMISSIONS_INVALID")
            lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                lock_flags |= os.O_NOFOLLOW
            self._lock_fd = os.open(
                ".writer.lock", lock_flags, 0o600, dir_fd=self._root_fd
            )
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CustodyError("CUSTODY_WRITER_ALREADY_ACTIVE") from exc
            for name in ("artifacts", "receipts", "epochs", ".tmp"):
                self._dirs[name] = self._open_child_dir(name)
            self._claim_epoch()
            self.audit()
        except Exception:
            self.close()
            raise

    def _open_child_dir(self, name: str) -> int:
        try:
            os.mkdir(name, 0o700, dir_fd=self._root_fd)
            os.fsync(self._root_fd)
        except FileExistsError:
            pass
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, dir_fd=self._root_fd)
        except OSError as exc:
            raise CustodyError("CUSTODY_DIRECTORY_INVALID") from exc
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            os.close(fd)
            raise CustodyError("CUSTODY_DIRECTORY_PERMISSIONS_INVALID")
        return fd

    def _claim_epoch(self) -> None:
        maximum = 0
        for name in os.listdir(self._dirs["epochs"]):
            match = _EPOCH_NAME.fullmatch(name)
            if match is None:
                raise CustodyError("CUSTODY_EPOCH_LEDGER_CORRUPT")
            payload, _ = self._read_json(self._dirs["epochs"], name)
            expected = {
                "schema_version": _EPOCH_SCHEMA_VERSION,
                "writer_id": match.group(2),
                "writer_epoch": int(match.group(1)),
                "production": False,
                "live": False,
                "countable_forward": False,
            }
            if payload != expected:
                raise CustodyError("CUSTODY_EPOCH_LEDGER_CORRUPT")
            maximum = max(maximum, expected["writer_epoch"])
        if self.writer_epoch <= maximum:
            raise CustodyError("CUSTODY_WRITER_EPOCH_STALE")
        claim = {
            "schema_version": _EPOCH_SCHEMA_VERSION,
            "writer_id": self.writer_id,
            "writer_epoch": self.writer_epoch,
            "production": False,
            "live": False,
            "countable_forward": False,
        }
        name = f"{self.writer_epoch:020d}-{self.writer_id}.json"
        self._publish_create_only("epochs", name, canonical_json_line(claim))

    def _read_bytes(
        self, directory_fd: int, name: str, *, limit: int = 20 * 1024 * 1024
    ) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size <= 0
                    or before.st_size > limit
                ):
                    raise CustodyError("CUSTODY_FILE_INVALID")
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        raise CustodyError("CUSTODY_FILE_TRUNCATED")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(fd)
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise CustodyError("CUSTODY_FILE_CHANGED_DURING_READ")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except CustodyError:
            raise
        except OSError as exc:
            raise CustodyError("CUSTODY_FILE_READ_FAILED") from exc

    def _read_json(self, directory_fd: int, name: str) -> tuple[dict[str, Any], bytes]:
        raw = self._read_bytes(directory_fd, name)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustodyError("CUSTODY_JSON_INVALID") from exc
        if not isinstance(value, dict) or canonical_json_line(value) != raw:
            raise CustodyError("CUSTODY_JSON_NOT_CANONICAL")
        return value, raw

    def _publish_create_only(self, directory: str, final_name: str, raw: bytes) -> None:
        target_fd = self._dirs[directory]
        temp_name = f"{self.writer_id}.{self.writer_epoch}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=self._dirs[".tmp"])
        try:
            view = memoryview(raw)
            while view:
                written = os.write(temp_fd, view)
                if written <= 0:
                    raise CustodyError("CUSTODY_WRITE_FAILED")
                view = view[written:]
            os.fsync(temp_fd)
            try:
                os.link(
                    temp_name,
                    final_name,
                    src_dir_fd=self._dirs[".tmp"],
                    dst_dir_fd=target_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise CustodyError("CUSTODY_CREATE_ONLY_CONFLICT") from exc
            os.fsync(target_fd)
        finally:
            os.close(temp_fd)
            try:
                os.unlink(temp_name, dir_fd=self._dirs[".tmp"])
                os.fsync(self._dirs[".tmp"])
            except FileNotFoundError:
                pass

    def _validate_schema(self, artifact: Mapping[str, Any]) -> None:
        schema_ref = artifact["schema_ref"]
        validator = self.schema_registry.get(schema_ref)
        if validator is None:
            raise CustodyError("CUSTODY_SCHEMA_UNKNOWN")
        try:
            if callable(validator):
                validator(artifact["payload"])
            else:
                from jsonschema import Draft202012Validator

                Draft202012Validator.check_schema(validator)
                Draft202012Validator(validator).validate(artifact["payload"])
        except CustodyError:
            raise
        except Exception as exc:
            raise CustodyError("CUSTODY_SCHEMA_VALIDATION_FAILED") from exc

    def _load_artifacts(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for name in os.listdir(self._dirs["artifacts"]):
            if not name.startswith("artifact-") or not name.endswith(".json"):
                raise CustodyError("CUSTODY_ARTIFACT_STORE_CORRUPT")
            payload, _ = self._read_json(self._dirs["artifacts"], name)
            try:
                artifact = validate_artifact_envelope(payload)
                assert_non_authoritative(artifact)
            except ContractError as exc:
                raise CustodyError("CUSTODY_ARTIFACT_INVALID") from exc
            if (
                name != f"{artifact['artifact_id']}.json"
                or artifact["trust_domain"] not in KEY_DOMAINS
            ):
                raise CustodyError("CUSTODY_ARTIFACT_INVALID")
            self._validate_schema(artifact)
            result[artifact["artifact_id"]] = artifact
        return result

    def _load_state(self) -> _State:
        artifacts = self._load_artifacts()
        receipt_names = sorted(os.listdir(self._dirs["receipts"]))
        receipts: list[dict[str, Any]] = []
        idempotency: dict[str, dict[str, Any]] = {}
        lifecycle: dict[str, list[str]] = {}
        previous_receipt_sha: str | None = None
        previous_record_sha: str | None = None
        previous_writer_epoch = 0
        for sequence, name in enumerate(receipt_names, start=1):
            match = _RECEIPT_NAME.fullmatch(name)
            if match is None or int(match.group(1)) != sequence:
                raise CustodyError("CUSTODY_RECEIPT_SEQUENCE_INVALID")
            record, raw = self._read_json(self._dirs["receipts"], name)
            if set(record) != {
                "schema_version",
                "sequence",
                "writer_id",
                "writer_epoch",
                "receipt",
                "receipt_sha256",
                "previous_record_sha256",
                "production",
                "live",
                "countable_forward",
            }:
                raise CustodyError("CUSTODY_RECORD_FIELDS_INVALID")
            if (
                record["schema_version"] != CUSTODY_RECORD_SCHEMA_VERSION
                or record["sequence"] != sequence
            ):
                raise CustodyError("CUSTODY_RECORD_INVALID")
            if (
                not isinstance(record["writer_epoch"], int)
                or record["writer_epoch"] <= 0
            ):
                raise CustodyError("CUSTODY_RECORD_EPOCH_INVALID")
            _safe_id(record["writer_id"], "CUSTODY_RECORD_WRITER_INVALID")
            if record["writer_epoch"] < previous_writer_epoch:
                raise CustodyError("CUSTODY_RECORD_EPOCH_ROLLBACK")
            epoch_claim = f"{record['writer_epoch']:020d}-{record['writer_id']}.json"
            if epoch_claim not in os.listdir(self._dirs["epochs"]):
                raise CustodyError("CUSTODY_RECORD_EPOCH_UNCLAIMED")
            if any(
                record.get(flag) is not False
                for flag in ("production", "live", "countable_forward")
            ):
                raise CustodyError("CUSTODY_RECORD_AUTHORITY_INVALID")
            try:
                receipt = validate_receipt(record["receipt"])
            except ContractError as exc:
                raise CustodyError("CUSTODY_RECEIPT_INVALID") from exc
            receipt_raw = canonical_json_line(receipt)
            if record["receipt_sha256"] != sha256_bytes(receipt_raw):
                raise CustodyError("CUSTODY_RECEIPT_HASH_MISMATCH")
            if record["previous_record_sha256"] != previous_record_sha:
                raise CustodyError("CUSTODY_RECORD_CHAIN_BROKEN")
            if receipt["previous_receipt_sha256"] != previous_receipt_sha:
                raise CustodyError("CUSTODY_RECEIPT_CHAIN_BROKEN")
            if (
                receipt["expected_version"] != sequence - 1
                or receipt["resulting_version"] != sequence
            ):
                raise CustodyError("CUSTODY_RECEIPT_VERSION_INVALID")
            if (
                receipt["fencing_token"]
                != f"{record['writer_id']}:{record['writer_epoch']}"
            ):
                raise CustodyError("CUSTODY_RECEIPT_FENCE_MISMATCH")
            if name != f"{sequence:020d}-{receipt['receipt_id']}.json":
                raise CustodyError("CUSTODY_RECEIPT_FILENAME_INVALID")
            artifact = artifacts.get(receipt["artifact_id"])
            if artifact is None or any(
                receipt[key] != artifact[artifact_key]
                for key, artifact_key in (
                    ("artifact_type", "artifact_type"),
                    ("trust_domain", "trust_domain"),
                    ("artifact_canonical_sha256", "canonical_sha256"),
                    ("artifact_raw_sha256", "raw_sha256"),
                    ("schema_ref", "schema_ref"),
                    ("predecessor_refs", "predecessor_refs"),
                    ("lineage", "lineage"),
                )
            ):
                raise CustodyError("CUSTODY_RECEIPT_ARTIFACT_MISMATCH")
            key = receipt["idempotency_key"]
            if key in idempotency:
                raise CustodyError("CUSTODY_IDEMPOTENCY_LEDGER_DUPLICATE")
            idempotency[key] = record
            history = lifecycle.setdefault(receipt["artifact_id"], [])
            receipt_type = receipt["receipt_type"]
            if (
                (receipt_type == "publish" and history)
                or (
                    receipt_type == "install"
                    and (not history or "install" in history or "revoke" in history)
                )
                or (
                    receipt_type == "consume"
                    and ("install" not in history or "revoke" in history)
                )
                or (receipt_type == "revoke" and (not history or "revoke" in history))
            ):
                raise CustodyError("CUSTODY_RECEIPT_TRANSITION_INVALID")
            history.append(receipt_type)
            receipts.append(record)
            previous_receipt_sha = record["receipt_sha256"]
            previous_record_sha = sha256_bytes(raw)
            previous_writer_epoch = record["writer_epoch"]
        return _State(
            version=len(receipts),
            previous_receipt_sha256=previous_receipt_sha,
            previous_record_sha256=previous_record_sha,
            artifacts=artifacts,
            receipts=tuple(receipts),
            idempotency=idempotency,
            lifecycle={key: tuple(value) for key, value in lifecycle.items()},
        )

    def audit(self) -> dict[str, Any]:
        state = self._load_state()
        return {
            "version": state.version,
            "artifact_count": len(state.artifacts),
            "receipt_count": len(state.receipts),
            "previous_record_sha256": state.previous_record_sha256,
            "production": False,
            "live": False,
            "countable_forward": False,
        }

    def _validate_lineage(self, artifact: Mapping[str, Any], state: _State) -> None:
        expected: set[str] = set()
        for predecessor in artifact["predecessor_refs"]:
            stored = state.artifacts.get(predecessor["artifact_id"])
            if (
                stored is None
                or stored["canonical_sha256"] != predecessor["canonical_sha256"]
            ):
                raise CustodyError("CUSTODY_PREDECESSOR_MISSING_OR_MISMATCHED")
            expected.add(stored["canonical_sha256"])
            expected.update(stored["lineage"])
        if set(artifact["lineage"]) != expected:
            raise CustodyError("CUSTODY_LINEAGE_MISMATCH")

    def _artifact_bytes(self, artifact: Mapping[str, Any]) -> bytes:
        return canonical_json_line(validate_artifact_envelope(artifact))

    def _store_artifact(self, artifact: Mapping[str, Any], state: _State) -> None:
        name = f"{artifact['artifact_id']}.json"
        raw = self._artifact_bytes(artifact)
        existing = state.artifacts.get(artifact["artifact_id"])
        if existing is not None:
            if canonical_json_line(existing) != raw:
                raise CustodyError("CUSTODY_ARTIFACT_COLLISION")
            return
        try:
            self._publish_create_only("artifacts", name, raw)
        except CustodyError as exc:
            if exc.code != "CUSTODY_CREATE_ONLY_CONFLICT":
                raise
            observed = self._read_bytes(self._dirs["artifacts"], name)
            if observed != raw:
                raise CustodyError("CUSTODY_ARTIFACT_COLLISION") from exc

    def _append(
        self,
        receipt_type: str,
        artifact: Mapping[str, Any],
        *,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        actor_id = _safe_id(actor_id, "CUSTODY_ACTOR_INVALID")
        idempotency_key = _safe_id(idempotency_key, "CUSTODY_IDEMPOTENCY_INVALID")
        correlation_id = _safe_id(correlation_id, "CUSTODY_CORRELATION_INVALID")
        state = self._load_state()
        replay = state.idempotency.get(idempotency_key)
        if replay is not None:
            old = replay["receipt"]
            if (
                old["receipt_type"] == receipt_type
                and old["artifact_id"] == artifact["artifact_id"]
                and old["actor_id"] == actor_id
                and old["correlation_id"] == correlation_id
            ):
                return dict(old)
            raise CustodyError("CUSTODY_IDEMPOTENCY_CONFLICT")
        history = state.lifecycle.get(artifact["artifact_id"], ())
        if receipt_type == "publish" and history:
            raise CustodyError("CUSTODY_ARTIFACT_ALREADY_PUBLISHED")
        if receipt_type == "install" and (
            not history or "install" in history or "revoke" in history
        ):
            raise CustodyError("CUSTODY_INSTALL_TRANSITION_INVALID")
        if receipt_type == "consume" and (
            "install" not in history or "revoke" in history
        ):
            raise CustodyError("CUSTODY_CONSUME_TRANSITION_INVALID")
        if receipt_type == "revoke" and (not history or "revoke" in history):
            raise CustodyError("CUSTODY_REVOKE_TRANSITION_INVALID")
        receipt = build_receipt(
            receipt_type=receipt_type,
            artifact=artifact,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=state.version,
            resulting_version=state.version + 1,
            previous_receipt_sha256=state.previous_receipt_sha256,
            created_at=self.clock(),
            fencing_token=f"{self.writer_id}:{self.writer_epoch}",
            status="revoked" if receipt_type == "revoke" else "accepted",
        )
        receipt_raw = canonical_json_line(receipt)
        record = {
            "schema_version": CUSTODY_RECORD_SCHEMA_VERSION,
            "sequence": state.version + 1,
            "writer_id": self.writer_id,
            "writer_epoch": self.writer_epoch,
            "receipt": receipt,
            "receipt_sha256": sha256_bytes(receipt_raw),
            "previous_record_sha256": state.previous_record_sha256,
            "production": False,
            "live": False,
            "countable_forward": False,
        }
        name = f"{state.version + 1:020d}-{receipt['receipt_id']}.json"
        self._publish_create_only("receipts", name, canonical_json_line(record))
        self._load_state()
        return receipt

    def publish(
        self,
        artifact: Mapping[str, Any],
        *,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        try:
            envelope = validate_artifact_envelope(artifact)
            assert_non_authoritative(envelope)
        except ContractError as exc:
            raise CustodyError("CUSTODY_ARTIFACT_INVALID") from exc
        if envelope["trust_domain"] not in KEY_DOMAINS:
            raise CustodyError("CUSTODY_TRUST_DOMAIN_INVALID")
        self._validate_schema(envelope)
        state = self._load_state()
        self._validate_lineage(envelope, state)
        replay = state.idempotency.get(idempotency_key)
        if replay is not None:
            old = replay["receipt"]
            if (
                old["receipt_type"] == "publish"
                and old["artifact_id"] == envelope["artifact_id"]
                and old["actor_id"] == actor_id
                and old["correlation_id"] == correlation_id
            ):
                return dict(old)
            raise CustodyError("CUSTODY_IDEMPOTENCY_CONFLICT")
        self._store_artifact(envelope, state)
        return self._append(
            "publish",
            envelope,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    def record(
        self,
        receipt_type: str,
        artifact_id: str,
        *,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        if receipt_type not in {"install", "consume", "revoke"}:
            raise CustodyError("CUSTODY_RECEIPT_TYPE_INVALID")
        state = self._load_state()
        artifact = state.artifacts.get(
            _safe_id(artifact_id, "CUSTODY_ARTIFACT_ID_INVALID")
        )
        if artifact is None:
            raise CustodyError("CUSTODY_ARTIFACT_NOT_FOUND")
        return self._append(
            receipt_type,
            artifact,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )
