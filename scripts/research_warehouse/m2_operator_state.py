"""Root-managed pins for staged M2 manifest and backup operations."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .commit_anchors import ANCHOR_SCHEMA, load_commit_anchor_ledger
from .custody_paths import normalized_absolute
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict, write_all
from .m2_isolation_contracts import false_authority, load_isolation_policy
from .m2_runtime_input import (
    load_runtime_input,
    require_day,
    require_root_managed,
    require_sha,
)
from .timeutil import parse_utc

OPERATOR_STATE_SCHEMA = "vnpy_research_m2_operator_state_v1"
OPERATOR_LOCK_BYTES = b"vnpy-research-m2-operator-state-lock-v1\n"
STATE_KEYS = {
    "schema_version",
    "manifest_sequence",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "commit_anchor_ledger_path",
    "commit_anchor_ledger_raw_sha256",
    "backup_sequence",
    "backup_head_anchor_raw_sha256",
    "last_trade_day",
    "authority",
}
MANIFEST_RESULT_KEYS = {
    "batch_id",
    "batch_seal_sha256",
    "commit_seal_sha256",
    "committed_at",
    "manifest_relative_path",
    "manifest_raw_sha256",
    "parent_batch_seal_sha256",
    "parent_commit_seal_sha256",
    "status",
    "trade_day",
}
BACKUP_RESULT_KEYS = {
    "anchor_id",
    "anchor_raw_sha256",
    "created_at",
    "parent_anchor_raw_sha256",
    "sequence",
    "status",
}


@dataclass(frozen=True)
class OperatorState:
    path: Path
    raw_sha256: str
    payload: dict[str, Any]


def operator_lock_path(state_path: Path) -> Path:
    return state_path.with_name(f"{state_path.name}.lock")


@contextmanager
def operator_state_lock(
    state_path: Path,
    *,
    exclusive: bool,
) -> Iterator[None]:
    path = operator_lock_path(state_path)
    require_root_managed(path)
    raw = read_regular_strict(
        path,
        "M2 operator state lock",
        private=False,
    )
    if raw != OPERATOR_LOCK_BYTES:
        raise RegistryError("M2 operator state lock contract mismatch")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or stat.S_IMODE(opened.st_mode) != 0o444
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise RegistryError("M2 operator state lock identity is unsafe")
        fcntl.flock(
            descriptor,
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _require_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RegistryError("M2 operator state mutation requires root")


def _require_root_parent(path: Path) -> None:
    absolute = normalized_absolute(path)
    try:
        info = absolute.lstat()
    except OSError as exc:
        raise RegistryError("M2 operator state parent is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise RegistryError("M2 operator state parent is unsafe")


def _prepare_public_root_directory(path: Path) -> None:
    path.mkdir(mode=0o755, exist_ok=True)
    _require_root_parent(path)
    os.chmod(path, 0o755, follow_symlinks=False)
    info = path.lstat()
    if stat.S_IMODE(info.st_mode) != 0o755:
        raise RegistryError("M2 public root directory mode is unsafe")
    fsync_dir(path.parent)


def _atomic_root_write(path: Path, raw: bytes, *, create_only: bool) -> None:
    _require_root()
    path = normalized_absolute(path)
    _require_root_parent(path.parent)
    if path.exists():
        require_root_managed(path)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o444
        ):
            raise RegistryError("M2 operator state target is unsafe")
        if create_only:
            existing = read_regular_strict(
                path,
                "M2 operator create-only object",
                private=False,
            )
            if existing != raw:
                raise RegistryError("M2 operator create-only object conflicts")
            return
    elif create_only is False:
        raise RegistryError("M2 operator mutable state is not initialized")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}-",
        suffix=".partial",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if create_only:
            try:
                os.link(temporary, path, follow_symlinks=False)
                fsync_dir(path.parent)
            except FileExistsError:
                existing = read_regular_strict(
                    path,
                    "M2 operator create-only object",
                    private=False,
                )
                if existing != raw:
                    raise RegistryError("M2 operator create-only object conflicts")
        else:
            os.replace(temporary, path)
            fsync_dir(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_state(payload: object) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or set(payload) != STATE_KEYS
        or payload["schema_version"] != OPERATOR_STATE_SCHEMA
        or payload["authority"] != false_authority()
        or isinstance(payload["manifest_sequence"], bool)
        or not isinstance(payload["manifest_sequence"], int)
        or payload["manifest_sequence"] < 0
        or isinstance(payload["backup_sequence"], bool)
        or not isinstance(payload["backup_sequence"], int)
        or payload["backup_sequence"] < 0
    ):
        raise RegistryError("M2 operator state contract mismatch")
    nullable_hashes = (
        "manifest_genesis_seal_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
        "commit_anchor_ledger_raw_sha256",
        "backup_head_anchor_raw_sha256",
    )
    for field in nullable_hashes:
        if payload[field] is not None:
            require_sha(payload[field], field)
    if payload["manifest_sequence"] == 0:
        if any(
            payload[field] is not None
            for field in (
                "manifest_genesis_seal_sha256",
                "manifest_head_seal_sha256",
                "manifest_head_commit_seal_sha256",
                "commit_anchor_ledger_path",
                "commit_anchor_ledger_raw_sha256",
                "last_trade_day",
            )
        ):
            raise RegistryError("M2 operator genesis state is inconsistent")
    else:
        if any(
            payload[field] is None
            for field in (
                "manifest_genesis_seal_sha256",
                "manifest_head_seal_sha256",
                "manifest_head_commit_seal_sha256",
                "commit_anchor_ledger_path",
                "commit_anchor_ledger_raw_sha256",
                "last_trade_day",
            )
        ):
            raise RegistryError("M2 operator committed state is incomplete")
        normalized_absolute(Path(payload["commit_anchor_ledger_path"]))
        require_day(payload["last_trade_day"], "operator last_trade_day")
    if (payload["backup_sequence"] == 0) != (
        payload["backup_head_anchor_raw_sha256"] is None
    ):
        raise RegistryError("M2 operator backup state is inconsistent")
    return payload


def load_operator_state(path: Path) -> OperatorState:
    require_root_managed(path)
    raw = read_regular_strict(
        path,
        "M2 operator state",
        private=False,
    )
    payload = _validate_state(parse_json_strict(raw, "M2 operator state"))
    if raw != canonical_json_line(payload):
        raise RegistryError("M2 operator state is not canonical JSON")
    if payload["commit_anchor_ledger_path"] is not None:
        load_commit_anchor_ledger(
            Path(payload["commit_anchor_ledger_path"]),
            expected_raw_sha256=payload["commit_anchor_ledger_raw_sha256"],
            private=False,
        )
    return OperatorState(path=path, raw_sha256=sha256(raw), payload=payload)


def initialize_operator_state(path: Path) -> OperatorState:
    payload = {
        "schema_version": OPERATOR_STATE_SCHEMA,
        "manifest_sequence": 0,
        "manifest_genesis_seal_sha256": None,
        "manifest_head_seal_sha256": None,
        "manifest_head_commit_seal_sha256": None,
        "commit_anchor_ledger_path": None,
        "commit_anchor_ledger_raw_sha256": None,
        "backup_sequence": 0,
        "backup_head_anchor_raw_sha256": None,
        "last_trade_day": None,
        "authority": false_authority(),
    }
    _atomic_root_write(
        operator_lock_path(path),
        OPERATOR_LOCK_BYTES,
        create_only=True,
    )
    _atomic_root_write(path, canonical_json_line(payload), create_only=True)
    return load_operator_state(path)


def record_manifest_result(
    state: OperatorState,
    *,
    result: dict[str, Any],
) -> OperatorState:
    _require_root()
    if set(result) != MANIFEST_RESULT_KEYS:
        raise RegistryError("M2 manifest signer result contract mismatch")
    for field in (
        "batch_seal_sha256",
        "commit_seal_sha256",
        "manifest_raw_sha256",
    ):
        require_sha(result[field], field)
    require_day(result["trade_day"], "manifest trade_day")
    parse_utc(result["committed_at"], "manifest committed_at")
    if result["status"] != "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR":
        raise RegistryError("M2 manifest signer status is invalid")
    for field in (
        "parent_batch_seal_sha256",
        "parent_commit_seal_sha256",
    ):
        if result[field] is not None:
            require_sha(result[field], field)
    current = state.payload
    if (
        result["parent_batch_seal_sha256"]
        != current["manifest_head_seal_sha256"]
        or result["parent_commit_seal_sha256"]
        != current["manifest_head_commit_seal_sha256"]
    ):
        if (
            result["batch_seal_sha256"]
            == current["manifest_head_seal_sha256"]
            and result["commit_seal_sha256"]
            == current["manifest_head_commit_seal_sha256"]
        ):
            return state
        raise RegistryError("M2 manifest result does not extend root pin")
    entries = []
    if current["commit_anchor_ledger_path"] is not None:
        raw = read_regular_strict(
            Path(current["commit_anchor_ledger_path"]),
            "M2 commit anchor ledger",
            private=False,
        )
        entries = parse_json_strict(raw, "M2 commit anchor ledger")["entries"]
    entries = [
        *entries,
        {
            "sequence": current["manifest_sequence"] + 1,
            "batch_seal_sha256": result["batch_seal_sha256"],
            "commit_seal_sha256": result["commit_seal_sha256"],
            "available_at": result["committed_at"],
        },
    ]
    ledger_raw = canonical_json_line(
        {"schema_version": ANCHOR_SCHEMA, "entries": entries}
    )
    ledger_sha = sha256(ledger_raw)
    ledger_path = state.path.parent / "commit-anchor-ledgers" / (
        f"commit-anchor-ledger-{ledger_sha}.json"
    )
    _prepare_public_root_directory(ledger_path.parent)
    _atomic_root_write(ledger_path, ledger_raw, create_only=True)
    load_commit_anchor_ledger(
        ledger_path,
        expected_raw_sha256=ledger_sha,
        private=False,
    )
    updated = {
        **current,
        "manifest_sequence": current["manifest_sequence"] + 1,
        "manifest_genesis_seal_sha256": (
            current["manifest_genesis_seal_sha256"]
            or result["batch_seal_sha256"]
        ),
        "manifest_head_seal_sha256": result["batch_seal_sha256"],
        "manifest_head_commit_seal_sha256": result["commit_seal_sha256"],
        "commit_anchor_ledger_path": str(ledger_path),
        "commit_anchor_ledger_raw_sha256": ledger_sha,
        "last_trade_day": result["trade_day"],
    }
    _validate_state(updated)
    _atomic_root_write(
        state.path,
        canonical_json_line(updated),
        create_only=False,
    )
    return load_operator_state(state.path)


def record_backup_result(
    state: OperatorState,
    *,
    result: dict[str, Any],
    runtime_input_path: Path,
) -> OperatorState:
    _require_root()
    if set(result) != BACKUP_RESULT_KEYS:
        raise RegistryError("M2 backup signer result contract mismatch")
    require_sha(result["anchor_raw_sha256"], "backup anchor")
    parse_utc(result["created_at"], "backup created_at")
    if (
        result["status"] != "APPEND_ONLY_BACKUP_COMMITTED_AWAITING_ROOT_PIN"
        or isinstance(result["sequence"], bool)
        or not isinstance(result["sequence"], int)
        or result["sequence"] < 1
    ):
        raise RegistryError("M2 backup signer result is invalid")
    if result["parent_anchor_raw_sha256"] is not None:
        require_sha(result["parent_anchor_raw_sha256"], "backup parent anchor")
    if result["parent_anchor_raw_sha256"] != state.payload[
        "backup_head_anchor_raw_sha256"
    ]:
        if result["anchor_raw_sha256"] == state.payload[
            "backup_head_anchor_raw_sha256"
        ] and result["sequence"] == state.payload["backup_sequence"]:
            return state
        raise RegistryError("M2 backup result does not extend root pin")
    if result["sequence"] != state.payload["backup_sequence"] + 1:
        raise RegistryError("M2 backup result sequence is not contiguous")
    policy = load_isolation_policy(
        runtime_input_path.parent / "isolation-policy-v1.json"
    )
    runtime = load_runtime_input(runtime_input_path, policy=policy)
    old_runtime_head = runtime.payload[
        "expected_backup_head_anchor_raw_sha256"
    ]
    expected_old = state.payload["backup_head_anchor_raw_sha256"]
    if expected_old is None:
        expected_old = "0" * 64
    if old_runtime_head not in (expected_old, result["anchor_raw_sha256"]):
        raise RegistryError("M2 runtime backup pin diverged from operator state")
    if old_runtime_head != result["anchor_raw_sha256"]:
        updated_runtime = {
            **runtime.payload,
            "expected_backup_head_anchor_raw_sha256": (
                result["anchor_raw_sha256"]
            ),
        }
        _atomic_root_write(
            runtime_input_path,
            canonical_json_line(updated_runtime),
            create_only=False,
        )
        load_runtime_input(runtime_input_path, policy=policy)
    updated = {
        **state.payload,
        "backup_sequence": result["sequence"],
        "backup_head_anchor_raw_sha256": result["anchor_raw_sha256"],
    }
    _atomic_root_write(
        state.path,
        canonical_json_line(updated),
        create_only=False,
    )
    return load_operator_state(state.path)
