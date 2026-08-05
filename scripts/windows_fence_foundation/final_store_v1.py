"""Small durable high-water/receipt store for final typed admission.

This store is deliberately separate from the immutable WF-1 FROZEN/NONE
volume.  It has one exact schema and no migration reader.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any

try:
    import fcntl
except (
    ImportError
):  # pragma: no cover - native Windows uses the service-owned lock fallback
    fcntl = None  # type: ignore[assignment]

from .admission import WindowsRpcDurableFenceError
from .contracts import canonical_json_bytes

_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_IDEMPOTENCY_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")

FINAL_STORE_SCHEMA_VERSION = "windows_execution_final_admission_store_v1"
FINAL_LEDGER_SCHEMA_VERSION = "windows_execution_final_admission_ledger_v1"
_FIELDS = {
    "schema_version",
    "account_scope",
    "environment",
    "state_version",
    "current_epoch",
    "current_fencing_token",
    "snapshot_generation",
    "receipts",
    "idempotency",
    "previous_state_hash",
    "state_hash",
}
_RECEIPT_FIELDS = {
    "intent_id",
    "receipt_id",
    "receipt_hash",
    "request_hash",
    "account_scope",
    "environment",
    "leader_epoch",
    "fencing_token",
    "idempotency_key",
    "plan_id",
    "plan_hash",
    "action",
}
_LEDGER_FIELDS = {
    "schema_version",
    "state_version",
    "current_epoch",
    "current_fencing_token",
    "state_hash",
    "previous_anchor_hash",
    "anchor_hash",
}


def _error(
    message: str, code: str = "WINDOWS_FINAL_STORE_INVALID"
) -> WindowsRpcDurableFenceError:
    return WindowsRpcDurableFenceError(message, code=code)


def _digest(value: Mapping[str, Any]) -> str:
    candidate = deepcopy(dict(value))
    candidate.pop("state_hash", None)
    return hashlib.sha256(canonical_json_bytes(candidate)).hexdigest()


def _anchor_digest(value: Mapping[str, Any]) -> str:
    candidate = dict(value)
    candidate.pop("anchor_hash", None)
    return hashlib.sha256(canonical_json_bytes(candidate)).hexdigest()


def _anchor_for(state: Mapping[str, Any], previous: str) -> dict[str, Any]:
    anchor = {
        "schema_version": FINAL_LEDGER_SCHEMA_VERSION,
        "state_version": state["state_version"],
        "current_epoch": state["current_epoch"],
        "current_fencing_token": state["current_fencing_token"],
        "state_hash": state["state_hash"],
        "previous_anchor_hash": previous,
        "anchor_hash": "",
    }
    anchor["anchor_hash"] = _anchor_digest(anchor)
    return anchor


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise _error(
            "final admission ledger is missing", "WINDOWS_FINAL_LEDGER_MISSING"
        ) from exc
    except OSError as exc:
        raise _error("final admission ledger cannot be read") from exc
    if not raw or not raw.endswith(b"\n"):
        raise _error("final admission ledger is truncated")
    records: list[dict[str, Any]] = []
    previous = ""
    for index, line in enumerate(raw.splitlines()):
        try:
            decoded = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _error("final admission ledger is corrupt") from exc
        if (
            not isinstance(decoded, dict)
            or set(decoded) != _LEDGER_FIELDS
            or canonical_json_bytes(decoded) != line
            or decoded["schema_version"] != FINAL_LEDGER_SCHEMA_VERSION
            or isinstance(decoded["state_version"], bool)
            or decoded["state_version"] != index
            or isinstance(decoded["current_epoch"], bool)
            or not isinstance(decoded["current_epoch"], int)
            or decoded["current_epoch"] < 0
            or isinstance(decoded["current_fencing_token"], bool)
            or not isinstance(decoded["current_fencing_token"], int)
            or decoded["current_fencing_token"] < 0
            or (decoded["current_epoch"] == 0)
            != (decoded["current_fencing_token"] == 0)
            or not isinstance(decoded["state_hash"], str)
            or _SHA256_RE.fullmatch(decoded["state_hash"]) is None
            or decoded["previous_anchor_hash"] != previous
            or decoded["anchor_hash"] != _anchor_digest(decoded)
        ):
            raise _error("final admission ledger record is invalid")
        if records and (
            decoded["current_epoch"] < records[-1]["current_epoch"]
            or decoded["current_fencing_token"] < records[-1]["current_fencing_token"]
        ):
            raise _error("final admission ledger high-water regressed")
        records.append(decoded)
        previous = decoded["anchor_hash"]
    return records


def _assert_ledger_head(state: Mapping[str, Any], ledger: list[dict[str, Any]]) -> None:
    if not ledger:
        raise _error("final admission ledger is empty", "WINDOWS_FINAL_STORE_ROLLBACK")
    head = ledger[-1]
    expected = {
        "state_version": state["state_version"],
        "current_epoch": state["current_epoch"],
        "current_fencing_token": state["current_fencing_token"],
        "state_hash": state["state_hash"],
    }
    if any(head[field] != value for field, value in expected.items()):
        raise _error(
            "final admission store rolled back from ledger head",
            "WINDOWS_FINAL_STORE_ROLLBACK",
        )


def _assert_state_lineage(
    state: Mapping[str, Any], ledger: list[dict[str, Any]]
) -> None:
    version = int(state["state_version"])
    previous = state["previous_state_hash"]
    if version == 0:
        if previous != "":
            raise _error(
                "final admission store genesis predecessor is invalid",
                "WINDOWS_FINAL_STORE_ROLLBACK",
            )
        return
    if version > len(ledger) - 1 or previous != ledger[version - 1]["state_hash"]:
        raise _error(
            "final admission store predecessor is not in the durable ledger",
            "WINDOWS_FINAL_STORE_ROLLBACK",
        )


def _validate(raw: Any, *, account_scope: str, environment: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != _FIELDS:
        raise _error("final admission store fields are not exact")
    value = deepcopy(dict(raw))
    if value["schema_version"] != FINAL_STORE_SCHEMA_VERSION:
        raise _error("final admission store schema is unknown")
    if (
        not isinstance(value["account_scope"], str)
        or not isinstance(value["environment"], str)
        or value["account_scope"] != account_scope
        or value["environment"] != environment
    ):
        raise _error("final admission store scope is foreign")
    for field in (
        "state_version",
        "current_epoch",
        "current_fencing_token",
        "snapshot_generation",
    ):
        item = value[field]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise _error(f"final admission store {field} is invalid")
    if (value["current_epoch"] == 0) != (value["current_fencing_token"] == 0):
        raise _error("final admission store fence is partially initialized")
    if not isinstance(value["receipts"], dict) or not isinstance(
        value["idempotency"], dict
    ):
        raise _error("final admission store indexes are invalid")
    for intent_id, receipt in value["receipts"].items():
        if not isinstance(intent_id, str) or not isinstance(receipt, dict):
            raise _error("final admission store receipt is invalid")
        if set(receipt) != _RECEIPT_FIELDS or receipt.get("intent_id") != intent_id:
            raise _error("final admission store receipt identity is invalid")
        required_receipt = {
            "intent_id",
            "receipt_id",
            "receipt_hash",
            "request_hash",
            "account_scope",
            "environment",
            "leader_epoch",
            "fencing_token",
            "idempotency_key",
            "plan_id",
            "plan_hash",
            "action",
        }
        if set(receipt) != required_receipt:
            raise _error("final admission store receipt fields are not exact")
        for field in ("intent_id", "receipt_id", "plan_id"):
            if not isinstance(receipt[field], str) or not _IDENTIFIER_RE.fullmatch(
                receipt[field]
            ):
                raise _error("final admission store receipt identifier is invalid")
        for field in ("receipt_hash", "request_hash", "plan_hash"):
            if not isinstance(receipt[field], str) or not _SHA256_RE.fullmatch(
                receipt[field]
            ):
                raise _error("final admission store receipt hash is invalid")
        key = receipt.get("idempotency_key")
        if (
            not isinstance(key, str)
            or not _IDEMPOTENCY_RE.fullmatch(key)
            or value["idempotency"].get(key) != intent_id
            or receipt["account_scope"] != account_scope
            or receipt["environment"] != environment
            or receipt["action"] not in {"send", "cancel"}
        ):
            raise _error("final admission store receipt index is invalid")
        for field in ("leader_epoch", "fencing_token"):
            if (
                isinstance(receipt[field], bool)
                or not isinstance(receipt[field], int)
                or receipt[field] < 1
            ):
                raise _error("final admission store receipt fence is invalid")
            high_water_field = {
                "leader_epoch": "current_epoch",
                "fencing_token": "current_fencing_token",
            }[field]
            if receipt[field] > value[high_water_field]:
                raise _error("final admission store receipt exceeds high-water")
        if receipt["receipt_id"] != f"receipt-{intent_id}":
            raise _error("final admission store receipt identity is invalid")
    if set(value["idempotency"].values()) != set(value["receipts"]):
        raise _error("final admission store idempotency index is incomplete")
    previous = value["previous_state_hash"]
    if not isinstance(previous, str) or (previous and len(previous) != 64):
        raise _error("final admission store predecessor is invalid")
    state_hash = value["state_hash"]
    if (
        not isinstance(state_hash, str)
        or len(state_hash) != 64
        or _digest(value) != state_hash
    ):
        raise _error("final admission store hash is invalid")
    return value


def _read_exact(path: Path, *, account_scope: str, environment: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        decoded = json.loads(raw.decode("utf-8"))
        if canonical_json_bytes(decoded) != raw:
            raise _error("final admission store is not canonical")
        return _validate(decoded, account_scope=account_scope, environment=environment)
    except WindowsRpcDurableFenceError:
        raise
    except FileNotFoundError as exc:
        raise _error(
            "final admission store is missing", "WINDOWS_FINAL_STORE_MISSING"
        ) from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("final admission store cannot be read") from exc


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":  # pragma: no cover - exercised by native Windows acceptance
        import ctypes
        from ctypes import wintypes

        handle = ctypes.windll.kernel32.CreateFileW(
            str(path),
            0xC0000000,
            0x00000007,
            None,
            3,
            0x02000000,
            None,
        )
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError()
        try:
            if not ctypes.windll.kernel32.FlushFileBuffers(handle):
                raise ctypes.WinError()
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _windows_move_new_file(source: Path, target: Path) -> None:
    """Persist an exclusive create through a write-through NTFS move."""

    import ctypes
    from ctypes import wintypes

    move_file_ex = ctypes.windll.kernel32.MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    if not move_file_ex(str(source), str(target), 0x00000008):
        raise ctypes.WinError()


def _windows_replace_file(source: Path, target: Path) -> None:
    """Atomically replace an existing file with write-through semantics."""

    import ctypes
    from ctypes import wintypes

    replace_file = ctypes.windll.kernel32.ReplaceFileW
    replace_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    replace_file.restype = wintypes.BOOL
    if not replace_file(str(target), str(source), None, 0x00000001, None, None):
        raise ctypes.WinError()


class DurableFinalAdmissionStoreV1:
    """Atomic exact-schema state with an in-process rollback high-water."""

    def __init__(
        self, path: str | os.PathLike[str], *, account_scope: str, environment: str
    ) -> None:
        self.path = Path(path)
        self.ledger_path = self.path.with_name(f"{self.path.name}.ledger")
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        self.account_scope = account_scope
        self.environment = environment
        self._lock = RLock()
        with self._cross_process_lock():
            self._state = _read_exact(
                self.path, account_scope=account_scope, environment=environment
            )
            ledger = _read_ledger(self.ledger_path)
            _assert_ledger_head(self._state, ledger)
            _assert_state_lineage(self._state, ledger)
        self._anchor_hash = str(ledger[-1]["anchor_hash"])
        self._highest_version = int(self._state["state_version"])
        self._highest_hash = str(self._state["state_hash"])

    @classmethod
    def bootstrap(
        cls,
        path: str | os.PathLike[str],
        *,
        account_scope: str,
        environment: str,
    ) -> DurableFinalAdmissionStoreV1:
        """Explicitly create only a missing 0/0 store; never overwrite."""

        target = Path(path)
        ledger_target = target.with_name(f"{target.name}.ledger")
        if target.exists() or ledger_target.exists():
            return cls(target, account_scope=account_scope, environment=environment)
        state = {
            "schema_version": FINAL_STORE_SCHEMA_VERSION,
            "account_scope": account_scope,
            "environment": environment,
            "state_version": 0,
            "current_epoch": 0,
            "current_fencing_token": 0,
            "snapshot_generation": 0,
            "receipts": {},
            "idempotency": {},
            "previous_state_hash": "",
            "state_hash": "",
        }
        state["state_hash"] = _digest(state)
        cls._create_only(target, canonical_json_bytes(state))
        genesis = _anchor_for(state, "")
        cls._create_only(ledger_target, canonical_json_bytes(genesis) + b"\n")
        return cls(target, account_scope=account_scope, environment=environment)

    @staticmethod
    def _create_only(path: Path, raw: bytes) -> None:
        if os.name == "nt":  # pragma: no cover - exercised by native Windows acceptance
            temporary: Path | None = None
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{path.name}.", dir=path.parent
                )
                temporary = Path(temporary_name)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                _windows_move_new_file(temporary, path)
            except FileExistsError:
                return
            except OSError as exc:
                raise _error("final admission store bootstrap failed") from exc
            finally:
                if temporary is not None and temporary.exists():
                    temporary.unlink()
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_directory(path.parent)
        except FileExistsError:
            return
        except OSError as exc:
            raise _error("final admission store bootstrap failed") from exc

    def snapshot(self) -> dict[str, Any]:
        with self._lock, self._cross_process_lock():
            return self._refresh()

    def allocate_snapshot_generation(self) -> dict[str, Any]:
        """Durably allocate one globally unique observation generation."""

        def allocate(state: dict[str, Any]) -> None:
            state["snapshot_generation"] = int(state["snapshot_generation"]) + 1

        return self.mutate(allocate)

    def mutate(self, writer: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        with self._lock, self._cross_process_lock():
            previous = self._refresh()
            candidate = deepcopy(previous)
            writer(candidate)
            candidate["state_version"] = int(previous["state_version"]) + 1
            candidate["previous_state_hash"] = previous["state_hash"]
            candidate["state_hash"] = _digest(candidate)
            _validate(
                candidate,
                account_scope=self.account_scope,
                environment=self.environment,
            )
            self._replace(canonical_json_bytes(candidate))
            anchor = _anchor_for(candidate, self._anchor_hash)
            self._append_anchor(canonical_json_bytes(anchor) + b"\n")
            self._state = candidate
            self._anchor_hash = str(anchor["anchor_hash"])
            self._highest_version = int(candidate["state_version"])
            self._highest_hash = str(candidate["state_hash"])
            return deepcopy(candidate)

    @contextmanager
    def _cross_process_lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if (
            fcntl is None
        ):  # pragma: no cover - native Windows uses service ACL + byte-range lock
            import msvcrt

            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "r+b") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                if size == 0:
                    handle.seek(0)
                    handle.write(b"0")
                    handle.flush()
                    os.fsync(handle.fileno())
                elif size != 1:
                    raise _error(
                        "final admission lock file is invalid",
                        "WINDOWS_FINAL_STORE_LOCK_INVALID",
                    )
                acquired = False
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    acquired = True
                    yield
                finally:
                    if acquired:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _refresh(self) -> dict[str, Any]:
        current = _read_exact(
            self.path,
            account_scope=self.account_scope,
            environment=self.environment,
        )
        ledger = _read_ledger(self.ledger_path)
        _assert_ledger_head(current, ledger)
        _assert_state_lineage(current, ledger)
        version = int(current["state_version"])
        if version < self._highest_version or (
            version == self._highest_version
            and current["state_hash"] != self._highest_hash
        ):
            raise _error(
                "final admission store rolled back", "WINDOWS_FINAL_STORE_ROLLBACK"
            )
        if version > self._highest_version and (
            self._highest_version >= len(ledger)
            or ledger[self._highest_version]["state_hash"] != self._highest_hash
        ):
            raise _error(
                "final admission store chain was replaced",
                "WINDOWS_FINAL_STORE_ROLLBACK",
            )
        self._state = current
        self._highest_version = version
        self._highest_hash = str(current["state_hash"])
        self._anchor_hash = str(ledger[-1]["anchor_hash"])
        return deepcopy(current)

    def _append_anchor(self, raw: bytes) -> None:
        try:
            descriptor = os.open(self.ledger_path, os.O_WRONLY | os.O_APPEND)
            with os.fdopen(descriptor, "ab") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                _fsync_directory(self.ledger_path.parent)
        except OSError as exc:
            raise _error("final admission ledger append failed") from exc

    def _replace(self, raw: bytes) -> None:
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{self.path.name}.", dir=self.path.parent
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                if os.name == "nt":
                    _windows_replace_file(Path(temporary), self.path)
                else:
                    os.replace(temporary, self.path)
                    _fsync_directory(self.path.parent)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except OSError as exc:
            raise _error("final admission store write failed") from exc


__all__ = ["FINAL_STORE_SCHEMA_VERSION", "DurableFinalAdmissionStoreV1"]
