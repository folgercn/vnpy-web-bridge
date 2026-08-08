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
    load_keyring,
    sha256_bytes,
    verify_signed_artifact,
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
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 192
        or _SAFE_NAME.fullmatch(value) is None
    ):
        raise CustodyError(code)
    return value


def _expected_version(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CustodyError("CUSTODY_EXPECTED_VERSION_INVALID")
    return value


def _request_fields(
    *, actor_id: str, idempotency_key: str, correlation_id: str, expected_version: int
) -> tuple[str, str, str, int]:
    return (
        _safe_id(actor_id, "CUSTODY_ACTOR_INVALID"),
        _safe_id(idempotency_key, "CUSTODY_IDEMPOTENCY_INVALID"),
        _safe_id(correlation_id, "CUSTODY_CORRELATION_INVALID"),
        _expected_version(expected_version),
    )


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class ArtifactCustody:
    """A context-managed, uniquely fenced custody writer.

    ``schema_registry`` is mandatory: each ``schema_ref`` is either a JSON
    Schema mapping or a validation callback. Unknown schemas fail closed.
    A writer epoch is an explicit fence.  A process may re-open an unchanged
    root with the *same* writer/epoch after a crash or container restart, but
    another writer and every lower epoch are rejected.  The exclusive lock
    makes that exception safe: two live processes can never share the fence.
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
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or stat.S_IMODE(root_stat.st_mode) != 0o700
            ):
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
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise CustodyError("CUSTODY_DIRECTORY_PERMISSIONS_INVALID")
        return fd

    def _claim_epoch(self) -> None:
        maximum = 0
        claims: dict[int, str] = {}
        for name in os.listdir(self._dirs["epochs"]):
            match = _EPOCH_NAME.fullmatch(name)
            if match is None:
                raise CustodyError("CUSTODY_EPOCH_LEDGER_CORRUPT")
            payload, _ = self._read_json(self._dirs["epochs"], name)
            if not isinstance(payload.get("writer_epoch"), int) or isinstance(
                payload["writer_epoch"], bool
            ):
                raise CustodyError("CUSTODY_EPOCH_LEDGER_CORRUPT")
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
            prior = claims.setdefault(expected["writer_epoch"], expected["writer_id"])
            if prior != expected["writer_id"]:
                raise CustodyError("CUSTODY_EPOCH_LEDGER_FORK")
            maximum = max(maximum, expected["writer_epoch"])
        prior_writer = claims.get(self.writer_epoch)
        if prior_writer is not None:
            if prior_writer != self.writer_id:
                raise CustodyError("CUSTODY_WRITER_EPOCH_FORK")
            if self.writer_epoch != maximum:
                raise CustodyError("CUSTODY_WRITER_EPOCH_STALE")
            # Same writer + same epoch is the only legal restart path.  It is
            # safe only while this process owns the root's single-writer lock.
            return
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
            before_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
                raise CustodyError("CUSTODY_FILE_INVALID")
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
                if _identity(before) != _identity(before_path) or _identity(
                    before
                ) != _identity(after):
                    raise CustodyError("CUSTODY_FILE_CHANGED_DURING_READ")
                result = b"".join(chunks)
            finally:
                os.close(fd)
            after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _identity(before_path) != _identity(after_path):
                raise CustodyError("CUSTODY_FILE_CHANGED_DURING_READ")
            return result
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

    def _load_state(self) -> _State:
        # A publish envelope is committed inside its receipt ledger record.
        # Keeping a second artifact file would reintroduce an unavoidable
        # crash window between two create-only files, leaving an orphan.
        if os.listdir(self._dirs["artifacts"]):
            raise CustodyError("CUSTODY_ARTIFACT_STORE_CORRUPT")
        artifacts: dict[str, dict[str, Any]] = {}
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
            try:
                assert_non_authoritative(record)
            except ContractError as exc:
                raise CustodyError("CUSTODY_RECORD_AUTHORITY_INVALID") from exc
            if set(record) != {
                "schema_version",
                "sequence",
                "writer_id",
                "writer_epoch",
                "artifact",
                "signed_artifact",
                "signed_artifact_sha256",
                "signed_artifact_keyring",
                "signed_artifact_keyring_raw_sha256",
                "signed_artifact_expected_domain",
                "signed_artifact_expected_key_purpose",
                "receipt",
                "receipt_sha256",
                "previous_record_sha256",
                "production",
                "live",
                "countable_forward",
            }:
                raise CustodyError("CUSTODY_RECORD_FIELDS_INVALID")
            if record["schema_version"] != CUSTODY_RECORD_SCHEMA_VERSION:
                raise CustodyError("CUSTODY_RECORD_INVALID")
            if (
                not isinstance(record["sequence"], int)
                or isinstance(record["sequence"], bool)
                or record["sequence"] != sequence
            ):
                raise CustodyError("CUSTODY_RECORD_INVALID")
            if (
                not isinstance(record["writer_epoch"], int)
                or isinstance(record["writer_epoch"], bool)
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
            inline = record["artifact"]
            signed = record["signed_artifact"]
            signed_sha = record["signed_artifact_sha256"]
            if receipt["receipt_type"] == "publish":
                try:
                    artifact = validate_artifact_envelope(inline)
                    assert_non_authoritative(artifact)
                except ContractError as exc:
                    raise CustodyError("CUSTODY_ARTIFACT_INVALID") from exc
                if (
                    artifact["trust_domain"] not in KEY_DOMAINS
                    or artifact["artifact_id"] in artifacts
                ):
                    raise CustodyError("CUSTODY_ARTIFACT_INVALID")
                self._validate_schema(artifact)
                if signed is not None:
                    if not isinstance(signed, dict):
                        raise CustodyError("CUSTODY_SIGNED_ARTIFACT_INVALID")
                    keyring = record["signed_artifact_keyring"]
                    keyring_pin = record["signed_artifact_keyring_raw_sha256"]
                    expected_domain = record["signed_artifact_expected_domain"]
                    expected_key_purpose = record[
                        "signed_artifact_expected_key_purpose"
                    ]
                    if (
                        not isinstance(keyring, dict)
                        or not isinstance(keyring_pin, str)
                        or not isinstance(expected_domain, str)
                        or not isinstance(expected_key_purpose, str)
                        or expected_domain not in KEY_DOMAINS
                        or not expected_key_purpose
                        or keyring_pin != sha256_bytes(canonical_json_line(keyring))
                    ):
                        raise CustodyError(
                            "CUSTODY_SIGNED_ARTIFACT_TRUST_SNAPSHOT_INVALID"
                        )
                    try:
                        verified = verify_signed_artifact(
                            signed,
                            keyring=keyring,
                            expected_domain=expected_domain,
                            expected_key_purpose=expected_key_purpose,
                        )
                    except ContractError as exc:
                        raise CustodyError(
                            f"CUSTODY_SIGNED_ARTIFACT_{exc.code}"
                        ) from exc
                    signed_artifact = signed.get("artifact")
                    if (
                        verified != signed
                        or signed_artifact != artifact
                        or signed_sha != sha256_bytes(canonical_json_line(signed))
                    ):
                        raise CustodyError("CUSTODY_SIGNED_ARTIFACT_MISMATCH")
                elif any(
                    record[key] is not None
                    for key in (
                        "signed_artifact_sha256",
                        "signed_artifact_keyring",
                        "signed_artifact_keyring_raw_sha256",
                        "signed_artifact_expected_domain",
                        "signed_artifact_expected_key_purpose",
                    )
                ):
                    raise CustodyError("CUSTODY_SIGNED_ARTIFACT_MISMATCH")
                artifacts[artifact["artifact_id"]] = artifact
            elif inline is not None or any(
                record[key] is not None
                for key in (
                    "signed_artifact",
                    "signed_artifact_sha256",
                    "signed_artifact_keyring",
                    "signed_artifact_keyring_raw_sha256",
                    "signed_artifact_expected_domain",
                    "signed_artifact_expected_key_purpose",
                )
            ):
                raise CustodyError("CUSTODY_RECORD_ARTIFACT_INVALID")
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

    @staticmethod
    def _replay(
        state: _State,
        *,
        receipt_type: str,
        artifact_id: str,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
        expected_version: int,
    ) -> dict[str, Any] | None:
        replay = state.idempotency.get(idempotency_key)
        if replay is None:
            return None
        old = replay["receipt"]
        if (
            old["receipt_type"] == receipt_type
            and old["artifact_id"] == artifact_id
            and old["actor_id"] == actor_id
            and old["correlation_id"] == correlation_id
            and old["expected_version"] == expected_version
        ):
            return dict(old)
        raise CustodyError("CUSTODY_IDEMPOTENCY_CONFLICT")

    @staticmethod
    def _validate_transition(
        state: _State, *, receipt_type: str, artifact_id: str
    ) -> None:
        history = state.lifecycle.get(artifact_id, ())
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

    @staticmethod
    def _check_expected(state: _State, expected_version: int) -> None:
        if state.version != expected_version:
            raise CustodyError("CUSTODY_EXPECTED_VERSION_MISMATCH")

    def _append(
        self,
        receipt_type: str,
        artifact: Mapping[str, Any],
        *,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
        expected_version: int,
        signed_artifact: Mapping[str, Any] | None = None,
        signed_artifact_keyring: Mapping[str, Any] | None = None,
        signed_artifact_keyring_raw_sha256: str | None = None,
        signed_artifact_expected_domain: str | None = None,
        signed_artifact_expected_key_purpose: str | None = None,
    ) -> dict[str, Any]:
        actor_id, idempotency_key, correlation_id, expected_version = _request_fields(
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        state = self._load_state()
        replay = self._replay(
            state,
            receipt_type=receipt_type,
            artifact_id=artifact["artifact_id"],
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        if replay is not None:
            return replay
        self._check_expected(state, expected_version)
        self._validate_transition(
            state, receipt_type=receipt_type, artifact_id=artifact["artifact_id"]
        )
        receipt = build_receipt(
            receipt_type=receipt_type,
            artifact=artifact,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
            resulting_version=expected_version + 1,
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
            "artifact": dict(artifact) if receipt_type == "publish" else None,
            "signed_artifact": dict(signed_artifact)
            if receipt_type == "publish" and signed_artifact is not None
            else None,
            "signed_artifact_sha256": (
                sha256_bytes(canonical_json_line(signed_artifact))
                if receipt_type == "publish" and signed_artifact is not None
                else None
            ),
            "signed_artifact_keyring": (
                dict(signed_artifact_keyring)
                if receipt_type == "publish" and signed_artifact_keyring is not None
                else None
            ),
            "signed_artifact_keyring_raw_sha256": (
                signed_artifact_keyring_raw_sha256
                if receipt_type == "publish" and signed_artifact_keyring is not None
                else None
            ),
            "signed_artifact_expected_domain": (
                signed_artifact_expected_domain
                if receipt_type == "publish" and signed_artifact_keyring is not None
                else None
            ),
            "signed_artifact_expected_key_purpose": (
                signed_artifact_expected_key_purpose
                if receipt_type == "publish" and signed_artifact_keyring is not None
                else None
            ),
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
        expected_version: int,
    ) -> dict[str, Any]:
        actor_id, idempotency_key, correlation_id, expected_version = _request_fields(
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        try:
            envelope = validate_artifact_envelope(artifact)
            assert_non_authoritative(envelope)
        except ContractError as exc:
            raise CustodyError("CUSTODY_ARTIFACT_INVALID") from exc
        if envelope["trust_domain"] not in KEY_DOMAINS:
            raise CustodyError("CUSTODY_TRUST_DOMAIN_INVALID")
        self._validate_schema(envelope)
        state = self._load_state()
        replay = self._replay(
            state,
            receipt_type="publish",
            artifact_id=envelope["artifact_id"],
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        if replay is not None:
            return replay
        self._check_expected(state, expected_version)
        self._validate_lineage(envelope, state)
        self._validate_transition(
            state, receipt_type="publish", artifact_id=envelope["artifact_id"]
        )
        return self._append(
            "publish",
            envelope,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )

    def publish_signed(
        self,
        signed_artifact: Mapping[str, Any],
        *,
        keyring_path: str | os.PathLike[str],
        expected_domain: str,
        expected_key_purpose: str,
        expected_keyring_raw_sha256: str,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
        expected_version: int,
    ) -> dict[str, Any]:
        """Verify then preserve a complete signed wrapper in the receipt chain.

        The keyring is loaded through the pinned-byte trust API before any
        mutable custody state is read or written.  The receipt remains bound to
        the original envelope's canonical/raw/predecessor hashes; the immutable
        record additionally retains the full signature wrapper for readback.
        """

        if expected_domain not in KEY_DOMAINS:
            raise CustodyError("CUSTODY_TRUST_DOMAIN_INVALID")
        try:
            keyring, _raw, digest = load_keyring(
                keyring_path,
                expected_domain=expected_domain,
                expected_raw_sha256=expected_keyring_raw_sha256,
            )
            verified = verify_signed_artifact(
                signed_artifact,
                keyring=keyring,
                expected_domain=expected_domain,
                expected_key_purpose=expected_key_purpose,
            )
        except ContractError as exc:
            raise CustodyError(f"CUSTODY_SIGNED_ARTIFACT_{exc.code}") from exc
        envelope = verified["artifact"]
        if not isinstance(envelope, Mapping):  # verify_signed_artifact guards this
            raise CustodyError("CUSTODY_SIGNED_ARTIFACT_INVALID")
        actor_id, idempotency_key, correlation_id, expected_version = _request_fields(
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        self._validate_schema(envelope)
        state = self._load_state()
        replay = self._replay(
            state,
            receipt_type="publish",
            artifact_id=envelope["artifact_id"],
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        if replay is not None:
            return replay
        self._check_expected(state, expected_version)
        self._validate_lineage(envelope, state)
        self._validate_transition(
            state, receipt_type="publish", artifact_id=envelope["artifact_id"]
        )
        return self._append(
            "publish",
            envelope,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
            signed_artifact=verified,
            signed_artifact_keyring=keyring,
            signed_artifact_keyring_raw_sha256=digest,
            signed_artifact_expected_domain=expected_domain,
            signed_artifact_expected_key_purpose=expected_key_purpose,
        )

    def read_signed_artifact(self, artifact_id: str) -> dict[str, Any]:
        """Read the canonical signed wrapper retained with a publish receipt."""

        wanted = _safe_id(artifact_id, "CUSTODY_ARTIFACT_ID_INVALID")
        # Audit performs the strict snapshot pin/domain/purpose/signature
        # verification before exposing a retained wrapper.
        self._load_state()
        for name in sorted(os.listdir(self._dirs["receipts"])):
            record, _raw = self._read_json(self._dirs["receipts"], name)
            signed = record.get("signed_artifact")
            if (
                isinstance(signed, dict)
                and isinstance(record.get("artifact"), dict)
                and record["artifact"].get("artifact_id") == wanted
            ):
                if record.get("signed_artifact_sha256") != sha256_bytes(
                    canonical_json_line(signed)
                ):
                    raise CustodyError("CUSTODY_SIGNED_ARTIFACT_MISMATCH")
                return dict(signed)
        raise CustodyError("CUSTODY_SIGNED_ARTIFACT_NOT_FOUND")

    def read_receipt(self, receipt_id: str) -> dict[str, Any]:
        """Return one audited receipt without exposing custody records/artifacts."""
        wanted = _safe_id(receipt_id, "CUSTODY_RECEIPT_ID_INVALID")
        state = self._load_state()
        for record in state.receipts:
            receipt = record["receipt"]
            if receipt["receipt_id"] == wanted:
                return dict(receipt)
        raise CustodyError("CUSTODY_RECEIPT_NOT_FOUND")

    def record(
        self,
        receipt_type: str,
        artifact_id: str,
        *,
        actor_id: str,
        idempotency_key: str,
        correlation_id: str,
        expected_version: int,
    ) -> dict[str, Any]:
        if receipt_type not in {"install", "consume", "revoke"}:
            raise CustodyError("CUSTODY_RECEIPT_TYPE_INVALID")
        actor_id, idempotency_key, correlation_id, expected_version = _request_fields(
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        state = self._load_state()
        artifact = state.artifacts.get(
            _safe_id(artifact_id, "CUSTODY_ARTIFACT_ID_INVALID")
        )
        if artifact is None:
            raise CustodyError("CUSTODY_ARTIFACT_NOT_FOUND")
        replay = self._replay(
            state,
            receipt_type=receipt_type,
            artifact_id=artifact["artifact_id"],
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
        if replay is not None:
            return replay
        self._check_expected(state, expected_version)
        self._validate_transition(
            state, receipt_type=receipt_type, artifact_id=artifact["artifact_id"]
        )
        return self._append(
            receipt_type,
            artifact,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            expected_version=expected_version,
        )
