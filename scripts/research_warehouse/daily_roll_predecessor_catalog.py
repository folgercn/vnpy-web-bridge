"""Root-managed immutable custody for verified daily roll-source artifacts.

The catalog is Research-Plane evidence only.  It stores canonical artifacts
and chained day receipts under a fixed directory derived from the M2 operator
state path.  It grants no install, dispatch, order, account, or trading
authority.
"""

from __future__ import annotations

import base64
import grp
import os
import pwd
import re
import select
import signal
import stat
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import fsync_dir, read_regular_strict
from .m2_isolation_contracts import false_authority, load_isolation_policy
from .m2_operator_state import (
    OperatorState,
    _atomic_root_write,
    _prepare_public_root_directory,
    _require_root,
    _require_root_parent,
    load_operator_state,
    operator_state_lock,
)
from .m2_runtime_input import (
    load_runtime_input,
    require_day,
    require_root_managed,
    require_sha,
)
from .timeutil import format_utc

if TYPE_CHECKING:
    from .m2_runtime_loader import RuntimeContext
    from .pit_source_view import SourcePins
    from .verified_daily_pit_main_roll_source import (
        GenesisContinuity,
        PredecessorContinuity,
    )

CATALOG_DIRNAME = "daily-roll-predecessor-catalog-v1"
CATALOG_SCHEMA = "vnpy_research_daily_roll_predecessor_catalog_receipt_v1"
RECEIPT_ID_PREFIX = "daily-roll-catalog-receipt-"
MAX_RECEIPT_RAW_BYTES = 64 * 1024
MAX_ARTIFACT_RAW_BYTES = 4 * 1024 * 1024
_PROTECTED_REPLAY_SCHEMA = "vnpy_research_daily_roll_protected_replay_v1"
_PROTECTED_REPLAY_MAX_BYTES = 8 * 1024 * 1024
_PROTECTED_REPLAY_TIMEOUT_SECONDS = 120.0
_PROTECTED_REPLAY_ACCOUNT_NAME = "vnpyresearch"
_PROTECTED_REPLAY_GROUP_NAME = "vnpyresearch"
_ATOMIC_PARTIAL_RE = re.compile(
    r"^\.(?P<target>[^/]+\.json)-(?P<nonce>[a-z0-9_]{8})\.partial$"
)
_ARTIFACT_FILENAME_RE = re.compile(r"^verified-daily-roll-[0-9a-f]{64}\.json$")
_RECEIPT_FILENAME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$")
RECEIPT_KEYS = {
    "schema_version",
    "receipt_id",
    "sequence",
    "official_day",
    "artifact_id",
    "artifact_raw_sha256",
    "artifact_raw_bytes",
    "artifact_relative_path",
    "previous_receipt_raw_sha256",
    "previous_artifact_id",
    "operator_state_raw_sha256",
    "operator_manifest_sequence",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "authority",
}


class DailyRollPredecessorCatalogError(RegistryError):
    """Fail-closed predecessor catalog custody error."""


@dataclass(frozen=True)
class ProtectedGenesisReplayInputs:
    """Private, config-derived inputs for the root-only Genesis bridge.

    This type is deliberately an implementation input, not a caller-built
    artifact.  The service child rereads every private path and rebuilds the
    artifact before the root parent sees any proof bytes.
    """

    history_receipt_path: Path
    runtime_input_path: Path
    runtime_input_raw_sha256: str
    service_uid: int
    service_gid: int
    history_receipt_raw_sha256: str
    manifest_public_key_path: Path
    manifest_public_key_raw_sha256: str
    signed_baseline_batch_path: Path
    business_public_key_path: Path
    business_public_key_raw_sha256: str
    business_signer_key_id: str
    contract_registry_path: Path
    contract_registry_raw_sha256: str
    source_month: str


@dataclass(frozen=True)
class CurrentCatalogHeadProof:
    """Exact immutable catalog head bound to the current Warehouse root.

    The two raw values are the canonical bytes read from root custody.  This
    proof is deliberately read-only and carries no install, dispatch, account,
    order, or trading authority.
    """

    receipt_raw: bytes
    receipt_raw_sha256: str
    artifact_raw: bytes
    artifact_raw_sha256: str
    operator_state_raw_sha256: str
    operator_manifest_sequence: int
    manifest_genesis_seal_sha256: str
    manifest_head_seal_sha256: str
    manifest_head_commit_seal_sha256: str
    commit_anchor_ledger_raw_sha256: str
    last_trade_day: str
    authority: dict[str, bool]


@dataclass(frozen=True)
class CatalogEntry:
    receipt_raw: bytes
    receipt: dict[str, Any]
    artifact_raw: bytes
    artifact: dict[str, Any]


@dataclass(frozen=True)
class LoadedCatalog:
    root: Path
    entries: tuple[CatalogEntry, ...]

    @property
    def head(self) -> CatalogEntry | None:
        return self.entries[-1] if self.entries else None


def catalog_root(operator_state_path: Path) -> Path:
    return operator_state_path.parent / CATALOG_DIRNAME


def _receipt_id(payload: dict[str, Any]) -> str:
    return RECEIPT_ID_PREFIX + sha256(canonical_json({**payload, "receipt_id": ""}))


def _validate_root_file_fd(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if (
        info.st_uid != 0
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o444
        or info.st_nlink != 1
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog file is not immutable root custody"
        )


def _validate_recovery_root_file_fd(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if (
        info.st_uid != 0
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o444
        or info.st_nlink != 2
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery file is not one root-owned link pair"
        )


def _validate_unpublished_partial_fd(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if (
        info.st_uid != 0
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) not in (0o600, 0o444)
        or info.st_nlink != 1
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished partial custody mismatch"
        )


def _read_root_file(path: Path, label: str, *, limit: int) -> bytes:
    require_root_managed(path)
    return read_regular_strict(
        path,
        label,
        limit=limit,
        private=False,
        descriptor_validator=_validate_root_file_fd,
    )


def _artifact_relative_path(artifact_id: str) -> str:
    return f"artifacts/{artifact_id}.json"


def _artifact_path(root: Path, relative: object) -> Path:
    if not isinstance(relative, str):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog artifact path is invalid"
        )
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or pure.parts != ("artifacts", pure.name)
        or not pure.name.endswith(".json")
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog artifact path is unsafe"
        )
    return root.joinpath(*pure.parts)


def _validate_receipt(raw: bytes, *, path: Path) -> dict[str, Any]:
    payload = parse_json_strict(raw, "daily roll predecessor catalog receipt")
    if (
        not isinstance(payload, dict)
        or set(payload) != RECEIPT_KEYS
        or payload["schema_version"] != CATALOG_SCHEMA
        or payload["authority"] != false_authority()
        or raw != canonical_json_line(payload)
        or isinstance(payload["sequence"], bool)
        or not isinstance(payload["sequence"], int)
        or payload["sequence"] < 1
        or isinstance(payload["artifact_raw_bytes"], bool)
        or not isinstance(payload["artifact_raw_bytes"], int)
        or not 1 <= payload["artifact_raw_bytes"] <= MAX_ARTIFACT_RAW_BYTES
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog receipt contract mismatch"
        )
    official_day = require_day(payload["official_day"], "catalog official_day")
    if path.name != f"{official_day.isoformat()}.json":
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog receipt day/path mismatch"
        )
    for field in (
        "artifact_raw_sha256",
        "operator_state_raw_sha256",
        "manifest_head_seal_sha256",
        "manifest_head_commit_seal_sha256",
    ):
        require_sha(payload[field], f"catalog {field}")
    for field in ("previous_receipt_raw_sha256",):
        if payload[field] is not None:
            require_sha(payload[field], f"catalog {field}")
    if (
        not isinstance(payload["artifact_id"], str)
        or not payload["artifact_id"].startswith("verified-daily-roll-")
        or len(payload["artifact_id"]) != len("verified-daily-roll-") + 64
        or _artifact_relative_path(payload["artifact_id"])
        != payload["artifact_relative_path"]
        or isinstance(payload["operator_manifest_sequence"], bool)
        or not isinstance(payload["operator_manifest_sequence"], int)
        or payload["operator_manifest_sequence"] < 1
        or payload["receipt_id"] != _receipt_id(payload)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog receipt identity mismatch"
        )
    require_sha(
        payload["artifact_id"].removeprefix("verified-daily-roll-"),
        "catalog artifact ID",
    )
    if (payload["sequence"] == 1) != (
        payload["previous_receipt_raw_sha256"] is None
        and payload["previous_artifact_id"] is None
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog genesis linkage mismatch"
        )
    if payload["sequence"] > 1 and (
        not isinstance(payload["previous_artifact_id"], str)
        or not payload["previous_artifact_id"].startswith("verified-daily-roll-")
        or len(payload["previous_artifact_id"]) != len("verified-daily-roll-") + 64
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog parent identity mismatch"
        )
    if payload["sequence"] > 1:
        require_sha(
            payload["previous_artifact_id"].removeprefix("verified-daily-roll-"),
            "catalog previous artifact ID",
        )
    return payload


def _validated_artifact(raw: bytes) -> dict[str, Any]:
    from .verified_daily_pit_main_roll_source import (
        validate_structural_daily_pit_main_roll_source,
    )

    return validate_structural_daily_pit_main_roll_source(raw)


def _catalog_contract_rows(
    artifact: dict[str, Any], field: str
) -> list[dict[str, str]]:
    return [
        {"product": row["product"], "exact_contract": row[field]}
        for row in artifact["mains"]
    ]


def _validate_catalog_continuity(
    entry: CatalogEntry,
    previous: CatalogEntry | None,
) -> None:
    continuity = entry.artifact["verified_lineage"]["continuity"]
    if previous is None:
        if continuity["mode"] != "GENESIS_STATIC_CORE_EQUAL":
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog first artifact is not exact Genesis"
            )
        return
    if continuity["mode"] != "LINKED_ROOT_CATALOG":
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog non-first artifact is not linked continuity"
        )
    previous_contracts = _catalog_contract_rows(previous.artifact, "exact_contract")
    claimed_previous = _catalog_contract_rows(entry.artifact, "previous_exact_contract")
    expected = {
        "catalog_receipt_id": previous.receipt["receipt_id"],
        "catalog_receipt_raw_sha256": sha256(previous.receipt_raw),
        "catalog_sequence": previous.receipt["sequence"],
        "predecessor_artifact_id": previous.artifact["artifact_id"],
        "predecessor_artifact_raw_sha256": sha256(previous.artifact_raw),
        "predecessor_artifact_raw_bytes": len(previous.artifact_raw),
        "predecessor_official_day": previous.artifact["official_day"],
        "predecessor_execution_day": previous.artifact["execution_day"],
        "predecessor_exact_contract_map_sha256": sha256(
            canonical_json(previous_contracts)
        ),
    }
    if claimed_previous != previous_contracts or any(
        continuity[field] != value for field, value in expected.items()
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog linked artifact/predecessor binding mismatch"
        )


def _load_catalog(
    root: Path,
    *,
    allowed_orphan_artifact_id: str | None = None,
) -> LoadedCatalog:
    for directory in (root, root / "artifacts", root / "receipts"):
        _require_root_parent(directory)
    receipt_paths = sorted((root / "receipts").iterdir())
    entries: list[CatalogEntry] = []
    referenced_artifacts: set[str] = set()
    previous_receipt_sha: str | None = None
    previous_entry: CatalogEntry | None = None
    for receipt_path in receipt_paths:
        if receipt_path.suffix != ".json":
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog contains an unexpected receipt entry"
            )
        receipt_raw = _read_root_file(
            receipt_path,
            "daily roll predecessor catalog receipt",
            limit=MAX_RECEIPT_RAW_BYTES,
        )
        receipt = _validate_receipt(receipt_raw, path=receipt_path)
        if receipt["sequence"] != len(entries) + 1:
            raise DailyRollPredecessorCatalogError(
                "daily roll predecessor catalog sequence is not contiguous"
            )
        if receipt["previous_receipt_raw_sha256"] != previous_receipt_sha or receipt[
            "previous_artifact_id"
        ] != (previous_entry.artifact["artifact_id"] if previous_entry else None):
            raise DailyRollPredecessorCatalogError(
                "daily roll predecessor catalog chain diverged"
            )
        artifact_path = _artifact_path(root, receipt["artifact_relative_path"])
        artifact_raw = _read_root_file(
            artifact_path,
            "daily roll predecessor catalog artifact",
            limit=MAX_ARTIFACT_RAW_BYTES,
        )
        artifact = _validated_artifact(artifact_raw)
        artifact_state = artifact["verified_lineage"]["operator_state"]
        if (
            artifact["artifact_id"] != receipt["artifact_id"]
            or artifact["official_day"] != receipt["official_day"]
            or sha256(artifact_raw) != receipt["artifact_raw_sha256"]
            or len(artifact_raw) != receipt["artifact_raw_bytes"]
            or artifact_state["raw_sha256"] != receipt["operator_state_raw_sha256"]
            or artifact_state["manifest_sequence"]
            != receipt["operator_manifest_sequence"]
            or artifact_state["manifest_head_seal_sha256"]
            != receipt["manifest_head_seal_sha256"]
            or artifact_state["manifest_head_commit_seal_sha256"]
            != receipt["manifest_head_commit_seal_sha256"]
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog receipt/artifact binding mismatch"
            )
        if previous_entry is not None and (
            previous_entry.artifact["execution_day"] != artifact["official_day"]
            or previous_entry.artifact["following_official_day"]
            != artifact["execution_day"]
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll predecessor catalog day sequence diverged"
            )
        entry = CatalogEntry(receipt_raw, receipt, artifact_raw, artifact)
        _validate_catalog_continuity(entry, previous_entry)
        referenced_artifacts.add(artifact_path.name)
        entries.append(entry)
        previous_receipt_sha = sha256(receipt_raw)
        previous_entry = entry
    artifact_names = set()
    for artifact_path in (root / "artifacts").iterdir():
        if artifact_path.suffix != ".json":
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog contains an unexpected artifact entry"
            )
        artifact_names.add(artifact_path.name)
    allowed_sets = {frozenset(referenced_artifacts)}
    if allowed_orphan_artifact_id is not None:
        allowed_sets.add(
            frozenset({*referenced_artifacts, f"{allowed_orphan_artifact_id}.json"})
        )
    if frozenset(artifact_names) not in allowed_sets:
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog artifact set mismatch"
        )
    return LoadedCatalog(root=root, entries=tuple(entries))


def _prepare_catalog(root: Path) -> None:
    _require_root()
    _prepare_public_root_directory(root)
    _prepare_public_root_directory(root / "artifacts")
    _prepare_public_root_directory(root / "receipts")


def _recovery_raw(path: Path, label: str, *, limit: int) -> bytes:
    require_root_managed(path)
    return read_regular_strict(
        path,
        label,
        limit=limit,
        private=False,
        expected_nlink=2,
        descriptor_validator=_validate_recovery_root_file_fd,
    )


def _recovery_link_info(path: Path) -> os.stat_result:
    return path.lstat()


def _discard_unpublished_partial(
    *,
    partial: Path,
    target: Path,
    partial_info: os.stat_result,
    is_artifact: bool,
    limit: int,
) -> None:
    """Discard one root-owned temp that never became a published hard link."""

    mode = stat.S_IMODE(partial_info.st_mode)
    if (
        not stat.S_ISREG(partial_info.st_mode)
        or partial_info.st_uid != 0
        or partial_info.st_nlink != 1
        or mode not in (0o600, 0o444)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished partial custody mismatch"
        )
    require_root_managed(partial)
    raw = read_regular_strict(
        partial,
        "daily roll catalog unpublished partial",
        limit=limit,
        private=False,
        expected_nlink=1,
        descriptor_validator=_validate_unpublished_partial_fd,
    )
    if mode == 0o444:
        try:
            if is_artifact:
                artifact = _validated_artifact(raw)
                if target.name != f"{artifact['artifact_id']}.json":
                    raise DailyRollPredecessorCatalogError(
                        "daily roll catalog unpublished artifact identity mismatch"
                    )
            else:
                _validate_receipt(raw, path=target)
        except RegistryError as exc:
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog completed unpublished partial is invalid"
            ) from exc
    try:
        current = _recovery_link_info(partial)
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished partial changed"
        ) from exc
    try:
        _recovery_link_info(target)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished target lookup failed"
        ) from exc
    else:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished target appeared during recovery"
        )
    if (
        current.st_uid != 0
        or not stat.S_ISREG(current.st_mode)
        or stat.S_IMODE(current.st_mode) != mode
        or current.st_nlink != 1
        or (current.st_dev, current.st_ino)
        != (partial_info.st_dev, partial_info.st_ino)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished partial identity changed"
        )
    try:
        partial.unlink()
        fsync_dir(partial.parent)
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog unpublished partial unlink failed"
        ) from exc


def _recover_catalog_partial(root: Path) -> None:
    """Recover exactly one known atomic-write crash window.

    ``_atomic_root_write`` can leave its root-owned ``.partial`` and final
    target as the only two links to one immutable inode if the process dies
    after ``os.link`` succeeds.  A receipt target is retained as its commit
    point; an unreceipted artifact target and its partial are discarded for
    verified replay.  Before the link, one unpublished nlink=1 temp can remain:
    mode 0444 must be a complete canonical object; mode 0600 is an interrupted
    private write.  Both unpublished forms are safely discarded.  No other
    partial shape is recoverable.  Callers must hold the exclusive
    operator-state lock.
    """

    partials = [
        path
        for directory in (root / "artifacts", root / "receipts")
        for path in directory.iterdir()
        if path.name.startswith(".") or path.name.endswith(".partial")
    ]
    if not partials:
        return
    if len(partials) != 1:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog has multiple recovery partials"
        )
    partial = partials[0]
    match = _ATOMIC_PARTIAL_RE.fullmatch(partial.name)
    if match is None:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery partial name is invalid"
        )
    target = partial.with_name(match.group("target"))
    is_artifact = partial.parent == root / "artifacts"
    target_pattern = _ARTIFACT_FILENAME_RE if is_artifact else _RECEIPT_FILENAME_RE
    limit = MAX_ARTIFACT_RAW_BYTES if is_artifact else MAX_RECEIPT_RAW_BYTES
    if target_pattern.fullmatch(target.name) is None:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery target name is invalid"
        )
    try:
        partial_info = _recovery_link_info(partial)
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery partial is unavailable"
        ) from exc
    try:
        target_info = _recovery_link_info(target)
    except FileNotFoundError:
        _discard_unpublished_partial(
            partial=partial,
            target=target,
            partial_info=partial_info,
            is_artifact=is_artifact,
            limit=limit,
        )
        return
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery target is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(partial_info.st_mode)
        or not stat.S_ISREG(target_info.st_mode)
        or partial_info.st_uid != 0
        or target_info.st_uid != 0
        or stat.S_IMODE(partial_info.st_mode) != 0o444
        or stat.S_IMODE(target_info.st_mode) != 0o444
        or partial_info.st_nlink != 2
        or target_info.st_nlink != 2
        or (partial_info.st_dev, partial_info.st_ino)
        != (target_info.st_dev, target_info.st_ino)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery link identity mismatch"
        )
    partial_raw = _recovery_raw(
        partial,
        "daily roll catalog recovery partial",
        limit=limit,
    )
    target_raw = _recovery_raw(
        target,
        "daily roll catalog recovery target",
        limit=limit,
    )
    if partial_raw != target_raw:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery bytes mismatch"
        )
    if is_artifact:
        artifact = _validated_artifact(target_raw)
        if target.name != f"{artifact['artifact_id']}.json":
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog recovery artifact identity mismatch"
            )
    else:
        _validate_receipt(target_raw, path=target)
    try:
        if is_artifact:
            # An artifact is not catalog-published until its receipt exists.
            # Remove the final link first: a crash after this unlink reduces
            # to the safe unpublished-partial case handled above.
            target.unlink()
            fsync_dir(target.parent)
        partial.unlink()
        fsync_dir(partial.parent)
    except OSError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery unlink failed"
        ) from exc
    if not is_artifact and (
        _read_root_file(target, "daily roll catalog recovered target", limit=limit)
        != target_raw
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog recovery readback mismatch"
        )


def _verified_retry_root(
    *,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
) -> tuple[dict[str, Any], str, str]:
    """Verify caller-selected roots and return the exact signed manifest head."""

    from .pit_source_view import verify_root_pins

    _history, chain = verify_root_pins(
        context=context,
        operator_state=operator_state,
        history_receipt_path=history_receipt_path,
        pins=pins,
        manifest_public_key_path=manifest_public_key_path,
    )
    if not chain:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog retry manifest chain is empty"
        )
    manifest = chain[-1]
    commit_receipt = manifest.get("commit_receipt")
    if not isinstance(commit_receipt, dict):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog retry manifest is uncommitted"
        )
    manifest_payload = {
        key: value
        for key, value in manifest.items()
        if key not in {"commit_receipt", "commit_seal_sha256"}
    }
    return (
        manifest,
        sha256(canonical_json_line(manifest_payload)),
        sha256(canonical_json_line(commit_receipt)),
    )


def _verify_idempotent_retry_inputs(
    *,
    entry: CatalogEntry,
    context: RuntimeContext,
    operator_state: OperatorState,
    history_receipt_path: Path,
    pins: SourcePins,
    manifest_public_key_path: Path,
    official_day: date,
    contract_registry_raw: bytes,
    expected_contract_registry_raw_sha256: str,
    genesis: GenesisContinuity | None,
    predecessor: PredecessorContinuity | None,
) -> None:
    """Prove a same-day request is exactly equivalent before skipping rebuild."""

    from .verified_daily_pit_main_roll_source import (
        MAX_CONTRACT_REGISTRY_RAW_BYTES,
        _genesis_map,
    )
    from .verified_daily_pit_main_roll_source import (
        GenesisContinuity as GenesisContinuityType,
    )
    from .verified_daily_pit_main_roll_source import (
        PredecessorContinuity as PredecessorContinuityType,
    )

    try:
        manifest, manifest_raw_sha256, commit_raw_sha256 = _verified_retry_root(
            context=context,
            operator_state=operator_state,
            history_receipt_path=history_receipt_path,
            pins=pins,
            manifest_public_key_path=manifest_public_key_path,
        )
        artifact = entry.artifact
        lineage = artifact["verified_lineage"]
        if (
            not isinstance(contract_registry_raw, bytes)
            or not 1 <= len(contract_registry_raw) <= MAX_CONTRACT_REGISTRY_RAW_BYTES
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog retry contract registry resource limit exceeded"
            )
        registry_sha = sha256(contract_registry_raw)
        expected_registry_sha = require_sha(
            expected_contract_registry_raw_sha256,
            "daily roll catalog retry expected contract registry",
        )
        expected_operator = {
            "raw_sha256": operator_state.raw_sha256,
            "manifest_sequence": operator_state.payload["manifest_sequence"],
            "manifest_genesis_seal_sha256": operator_state.payload[
                "manifest_genesis_seal_sha256"
            ],
            "manifest_head_seal_sha256": operator_state.payload[
                "manifest_head_seal_sha256"
            ],
            "manifest_head_commit_seal_sha256": operator_state.payload[
                "manifest_head_commit_seal_sha256"
            ],
            "commit_anchor_ledger_raw_sha256": operator_state.payload[
                "commit_anchor_ledger_raw_sha256"
            ],
        }
        expected_manifest = {
            "trade_day": manifest["trade_day"],
            "batch_id": manifest["batch_id"],
            "batch_seal_sha256": manifest["batch_seal_sha256"],
            "commit_seal_sha256": manifest["commit_seal_sha256"],
            "manifest_raw_sha256": manifest_raw_sha256,
            "commit_receipt_raw_sha256": commit_raw_sha256,
            "parent_batch_seal_sha256": manifest["parent_batch_seal_sha256"],
            "parent_commit_seal_sha256": manifest["parent_commit_seal_sha256"],
        }
        if (
            registry_sha != expected_registry_sha
            or artifact["official_day"] != official_day.isoformat()
            or artifact["official_day"] != operator_state.payload["last_trade_day"]
            or lineage["runtime"]
            != {
                "runtime_input_raw_sha256": context.runtime_input.raw_sha256,
                "isolation_policy_raw_sha256": context.policy.raw_sha256,
                "warehouse_registry_raw_sha256": context.registry.raw_sha256,
            }
            or lineage["calendar"]
            != {
                "calendar_id": context.calendar.calendar_id,
                "calendar_raw_sha256": context.calendar.raw_sha256,
                "calendar_availability_anchor_raw_sha256": (
                    context.availability.raw_sha256
                ),
                "calendar_available_at": format_utc(
                    context.availability.available_at,
                    "daily roll catalog retry calendar available_at",
                ),
            }
            or lineage["operator_state"] != expected_operator
            or lineage["manifest"] != expected_manifest
            or lineage["contract_registry"]
            != {
                "raw_sha256": registry_sha,
                "raw_bytes": len(contract_registry_raw),
                "expected_raw_sha256": expected_registry_sha,
            }
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog retry inputs do not match stored artifact"
            )
        revisions = {
            item.get("revision_id"): item
            for item in manifest.get("revisions", [])
            if isinstance(item, dict)
        }
        if any(
            source["revision_id"] not in revisions
            or source["observation_id"]
            not in revisions[source["revision_id"]].get("observation_ids", [])
            or any(
                revisions[source["revision_id"]].get(field) != source[field]
                for field in (
                    "source_id",
                    "exchange",
                    "object_id",
                    "revision_id",
                    "raw_sha256",
                    "raw_bytes",
                    "raw_relative_path",
                )
            )
            for source in lineage["sources"]
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog retry signed source lineage diverged"
            )
        continuity = lineage["continuity"]
        if continuity["mode"] == "GENESIS_STATIC_CORE_EQUAL":
            if type(genesis) is not GenesisContinuityType or predecessor is not None:
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog retry continuity request diverged"
                )
            _predecessor_map, expected_continuity = _genesis_map(
                genesis=genesis,
                expected_built=genesis.built_baseline,
                context=context,
                operator_state=operator_state,
                pins=pins,
                official_day=official_day,
                contract_registry_sha256=registry_sha,
            )
            if expected_continuity != continuity:
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog retry Genesis bundle diverged"
                )
        elif (
            continuity["mode"] != "LINKED_ROOT_CATALOG"
            or genesis is not None
            or type(predecessor) is not PredecessorContinuityType
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog retry continuity request diverged"
            )
    except DailyRollPredecessorCatalogError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, RegistryError) as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog retry input verification failed"
        ) from exc


def _require_exact_service_identity(uid: object, gid: object) -> tuple[int, int]:
    if (
        isinstance(uid, bool)
        or isinstance(gid, bool)
        or not isinstance(uid, int)
        or not isinstance(gid, int)
        or (uid, gid) != (503, 503)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay service identity is invalid"
        )
    return uid, gid


def _drop_to_protected_replay_identity(*, uid: int, gid: int) -> None:
    """Irreversibly bind the forked replay child to vnpyresearch 503:503."""

    _require_exact_service_identity(uid, gid)
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay account is missing"
        ) from exc
    if account.pw_uid != uid or account.pw_name != _PROTECTED_REPLAY_ACCOUNT_NAME:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay account identity mismatch"
        )
    try:
        group = grp.getgrgid(gid)
    except KeyError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay group is missing"
        ) from exc
    if group.gr_gid != gid or group.gr_name != _PROTECTED_REPLAY_GROUP_NAME:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay group identity mismatch"
        )
    expected_groups = [gid]
    os.setgroups(expected_groups)
    if hasattr(os, "setresgid"):
        os.setresgid(gid, gid, gid)
    else:
        os.setgid(gid)
    if hasattr(os, "setresuid"):
        os.setresuid(uid, uid, uid)
    else:
        os.setuid(uid)
    if (
        os.getuid() != uid
        or os.geteuid() != uid
        or os.getgid() != gid
        or os.getegid() != gid
        or os.getgroups() != expected_groups
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay privilege drop did not bind exact identity"
        )
    if hasattr(os, "getresuid") and os.getresuid() != (uid, uid, uid):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay retained a privileged saved UID"
        )
    if hasattr(os, "getresgid") and os.getresgid() != (gid, gid, gid):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay retained a privileged saved GID"
        )
    os.umask(0o077)
    os.chdir("/")
    os.environ.clear()
    os.environ.update(
        {
            "HOME": "/Users/Shared/vnpy-research/home",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": "/Users/Shared/vnpy-research/runtime/tmp",
        }
    )


def _close_child_inherited_descriptors(*, result_fd: int) -> int:
    """Keep only one pipe after fork; a replay child has no write authority."""

    if result_fd < 3:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay pipe descriptor is invalid"
        )
    null = os.open(os.devnull, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    try:
        for descriptor in (0, 1, 2):
            os.dup2(null, descriptor, inheritable=False)
        if result_fd != 3:
            os.dup2(result_fd, 3, inheritable=False)
            os.close(result_fd)
    finally:
        if null > 3:
            os.close(null)
    os.closerange(4, 1 << 20)
    return 3


def _protected_replay_payload(
    built: Any,
) -> bytes:
    from .verified_daily_pit_main_roll_source import BuiltVerifiedDailyPitMainRollSource

    if (
        not isinstance(built, BuiltVerifiedDailyPitMainRollSource)
        or not isinstance(built.artifact_raw, bytes)
        or not isinstance(built.artifact_id, str)
        or built.artifact_raw_sha256 != sha256(built.artifact_raw)
        or not 1 <= len(built.artifact_raw) <= MAX_ARTIFACT_RAW_BYTES
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay construction proof is invalid"
        )
    return canonical_json_line(
        {
            "schema_version": _PROTECTED_REPLAY_SCHEMA,
            "artifact_id": built.artifact_id,
            "artifact_raw_base64": base64.b64encode(built.artifact_raw).decode("ascii"),
            "artifact_raw_sha256": built.artifact_raw_sha256,
            "authority": false_authority(),
        }
    )


def _read_protected_replay_payload(
    *,
    descriptor: int,
    child: int,
) -> bytes:
    chunks: list[bytes] = []
    remaining = _PROTECTED_REPLAY_MAX_BYTES + 1
    deadline = time.monotonic() + _PROTECTED_REPLAY_TIMEOUT_SECONDS
    try:
        while True:
            wait = deadline - time.monotonic()
            if wait <= 0:
                raise DailyRollPredecessorCatalogError(
                    "daily roll protected replay timed out"
                )
            ready, _write, _error = select.select([descriptor], [], [], wait)
            if not ready:
                raise DailyRollPredecessorCatalogError(
                    "daily roll protected replay timed out"
                )
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            if remaining <= 0:
                raise DailyRollPredecessorCatalogError(
                    "daily roll protected replay proof exceeds safety limit"
                )
    except BaseException:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child, 0)
        raise
    raw = b"".join(chunks)
    _pid, status = os.waitpid(child, 0)
    if (
        not raw
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 0
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay child failed"
        )
    return raw


def _build_protected_genesis_as_service(
    *,
    operator_state: OperatorState,
    official_day: str,
    inputs: ProtectedGenesisReplayInputs,
) -> Any:
    """Keep the parent shared root lock across the unprivileged replay."""

    with operator_state_lock(operator_state.path, exclusive=False):
        current = load_operator_state(operator_state.path)
        if current != operator_state:
            raise DailyRollPredecessorCatalogError(
                "daily roll protected replay root changed before fork"
            )
        return _build_protected_genesis_as_service_locked(
            operator_state=current,
            official_day=official_day,
            inputs=inputs,
        )


def _build_protected_genesis_as_service_locked(
    *,
    operator_state: OperatorState,
    official_day: str,
    inputs: ProtectedGenesisReplayInputs,
) -> Any:
    """Replay private Genesis facts as 503:503, returning one bounded proof."""

    from .m2_runtime_loader import load_runtime_context_readonly
    from .pit_source_view import SourcePins, verify_root_pins
    from .verified_daily_pit_main_roll_source import (
        GenesisContinuity,
        _root_replayed_genesis_baseline,
        build_verified_daily_pit_main_roll_source,
    )

    _require_root()
    uid, gid = _require_exact_service_identity(inputs.service_uid, inputs.service_gid)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        status = 70
        try:
            os.close(read_fd)
            result_fd = _close_child_inherited_descriptors(result_fd=write_fd)
            _drop_to_protected_replay_identity(uid=uid, gid=gid)
            context = load_runtime_context_readonly(inputs.runtime_input_path)
            if (
                context.runtime_input.raw_sha256 != inputs.runtime_input_raw_sha256
                or context.policy.uid != uid
                or context.policy.gid != gid
            ):
                raise DailyRollPredecessorCatalogError(
                    "daily roll protected replay runtime identity drifted"
                )
            registry_raw = read_regular_strict(
                inputs.contract_registry_path,
                "daily roll protected Genesis contract registry",
                limit=1024 * 1024,
            )
            signed_baseline_raw = read_regular_strict(
                inputs.signed_baseline_batch_path,
                "daily roll protected Genesis signed baseline",
                limit=MAX_ARTIFACT_RAW_BYTES,
            )
            pins = SourcePins(
                history_receipt_raw_sha256=inputs.history_receipt_raw_sha256,
                operator_state_raw_sha256=operator_state.raw_sha256,
                manifest_public_key_raw_sha256=(
                    inputs.manifest_public_key_raw_sha256
                ),
                baseline_public_key_raw_sha256=(
                    inputs.business_public_key_raw_sha256
                ),
            )
            history, chain = verify_root_pins(
                context=context,
                operator_state=operator_state,
                history_receipt_path=inputs.history_receipt_path,
                pins=pins,
                manifest_public_key_path=inputs.manifest_public_key_path,
            )
            baseline = _root_replayed_genesis_baseline(
                context=context,
                operator_state=operator_state,
                history=history,
                chain=chain,
                pins=pins,
                contract_registry_raw=registry_raw,
                source_month=inputs.source_month,
                signer_key_id=inputs.business_signer_key_id,
            )
            built = build_verified_daily_pit_main_roll_source(
                context=context,
                operator_state=operator_state,
                history_receipt_path=inputs.history_receipt_path,
                pins=pins,
                manifest_public_key_path=inputs.manifest_public_key_path,
                official_day=official_day,
                contract_registry_raw=registry_raw,
                expected_contract_registry_raw_sha256=(
                    inputs.contract_registry_raw_sha256
                ),
                genesis=GenesisContinuity(
                    source_month=inputs.source_month,
                    built_baseline=baseline,
                    signed_baseline_batch_raw=signed_baseline_raw,
                    business_public_key_path=inputs.business_public_key_path,
                    expected_business_signer_key_id=inputs.business_signer_key_id,
                ),
            )
            raw = _protected_replay_payload(built)
            offset = 0
            while offset < len(raw):
                offset += os.write(result_fd, raw[offset:])
            status = 0
        except (OSError, RegistryError, ValueError):
            pass
        finally:
            try:
                os.close(3)
            except OSError:
                pass
        os._exit(status)
    os.close(write_fd)
    try:
        raw = _read_protected_replay_payload(descriptor=read_fd, child=child)
    finally:
        os.close(read_fd)
    try:
        payload = parse_json_strict(raw, "daily roll protected replay proof")
    except RegistryError as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay proof is invalid"
        ) from exc
    expected_keys = {
        "schema_version",
        "artifact_id",
        "artifact_raw_base64",
        "artifact_raw_sha256",
        "authority",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or payload["schema_version"] != _PROTECTED_REPLAY_SCHEMA
        or payload["authority"] != false_authority()
        or canonical_json_line(payload) != raw
        or not isinstance(payload["artifact_id"], str)
        or not isinstance(payload["artifact_raw_base64"], str)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay proof contract mismatch"
        )
    try:
        artifact_raw = base64.b64decode(
            payload["artifact_raw_base64"].encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay proof encoding is invalid"
        ) from exc
    if (
        not 1 <= len(artifact_raw) <= MAX_ARTIFACT_RAW_BYTES
        or payload["artifact_raw_sha256"] != sha256(artifact_raw)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay proof hash is invalid"
        )
    artifact = _validated_artifact(artifact_raw)
    if (
        artifact["artifact_id"] != payload["artifact_id"]
        or artifact["verified_lineage"]["continuity"]["mode"]
        != "GENESIS_STATIC_CORE_EQUAL"
        or artifact["official_day"] != official_day
        or artifact["verified_lineage"]["runtime"]["runtime_input_raw_sha256"]
        != inputs.runtime_input_raw_sha256
        or artifact["verified_lineage"]["operator_state"]["raw_sha256"]
        != operator_state.raw_sha256
        or artifact["verified_lineage"]["operator_state"]["manifest_sequence"]
        != operator_state.payload["manifest_sequence"]
        or artifact["verified_lineage"]["operator_state"]["manifest_head_seal_sha256"]
        != operator_state.payload["manifest_head_seal_sha256"]
        or artifact["verified_lineage"]["operator_state"]["manifest_head_commit_seal_sha256"]
        != operator_state.payload["manifest_head_commit_seal_sha256"]
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll protected replay proof root binding is invalid"
        )
    from .verified_daily_pit_main_roll_source import BuiltVerifiedDailyPitMainRollSource

    return BuiltVerifiedDailyPitMainRollSource(
        artifact_raw=artifact_raw,
        artifact_id=payload["artifact_id"],
        artifact_raw_sha256=payload["artifact_raw_sha256"],
    )


def publish_predecessor_artifact(
    *,
    context: RuntimeContext | None,
    operator_state: OperatorState,
    history_receipt_path: Path | None,
    pins: SourcePins | None,
    manifest_public_key_path: Path | None,
    official_day: str,
    contract_registry_raw: bytes | None,
    expected_contract_registry_raw_sha256: str | None,
    genesis: GenesisContinuity | None = None,
    predecessor: PredecessorContinuity | None = None,
    protected_genesis_inputs: ProtectedGenesisReplayInputs | None = None,
) -> CatalogEntry:
    """Root-replay, then publish one exact verified no-authority artifact.

    There is intentionally no ``artifact_raw`` argument: structural validity
    and self-reported root labels are not a custody proof.  This function
    invokes the complete v2 Warehouse root replay itself, then acquires the
    exclusive operator lock and rejects any intervening root change before
    performing create-only writes.  No module-level publisher accepts a
    caller-constructed ``BuiltVerifiedDailyPitMainRollSource``.
    """

    from .verified_daily_pit_main_roll_source import (
        BuiltVerifiedDailyPitMainRollSource,
        build_verified_daily_pit_main_roll_source,
    )

    if protected_genesis_inputs is not None:
        if (
            genesis is not None
            or predecessor is not None
            or any(
                value is not None
                for value in (
                    history_receipt_path,
                    pins,
                    manifest_public_key_path,
                    contract_registry_raw,
                    expected_contract_registry_raw_sha256,
                )
            )
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll protected Genesis invocation is mixed with caller inputs"
            )
        is_genesis = True
    else:
        if context is None:
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog normal replay requires a runtime context"
            )
        if (
            history_receipt_path is None
            or pins is None
            or manifest_public_key_path is None
            or contract_registry_raw is None
            or expected_contract_registry_raw_sha256 is None
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog replay inputs are incomplete"
            )
        is_genesis = genesis is not None
    root = catalog_root(operator_state.path)
    requested_day = require_day(official_day, "daily roll catalog official day")
    # A linked replay reads the catalog while holding a shared operator lock,
    # so clean any prior atomic-write crash under an exclusive lock first.
    with operator_state_lock(operator_state.path, exclusive=True):
        current = load_operator_state(operator_state.path)
        if current != operator_state:
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog operator state changed before recovery"
            )
        _prepare_catalog(root)
        _recover_catalog_partial(root)
        receipt_path = root / "receipts" / f"{requested_day.isoformat()}.json"
        if os.path.lexists(receipt_path) and protected_genesis_inputs is None:
            loaded = _load_catalog(root)
            if (
                loaded.head is None
                or loaded.head.receipt["official_day"] != requested_day.isoformat()
            ):
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog retry day is not the catalog head"
                )
            _verify_idempotent_retry_inputs(
                entry=loaded.head,
                context=context,
                operator_state=operator_state,
                history_receipt_path=history_receipt_path,
                pins=pins,
                manifest_public_key_path=manifest_public_key_path,
                official_day=requested_day,
                contract_registry_raw=contract_registry_raw,
                expected_contract_registry_raw_sha256=(
                    expected_contract_registry_raw_sha256
                ),
                genesis=genesis,
                predecessor=predecessor,
            )
            return loaded.head
        if (
            is_genesis
            and protected_genesis_inputs is None
            and any((root / "receipts").iterdir())
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog cannot append Genesis to a non-empty catalog"
            )
        if (
            is_genesis
            and protected_genesis_inputs is not None
            and not os.path.lexists(receipt_path)
            and any((root / "receipts").iterdir())
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog cannot append Genesis to a non-empty catalog"
            )

    if protected_genesis_inputs is not None:
        built = _build_protected_genesis_as_service(
            operator_state=operator_state,
            official_day=official_day,
            inputs=protected_genesis_inputs,
        )
    else:
        built = build_verified_daily_pit_main_roll_source(
            context=context,
            operator_state=operator_state,
            history_receipt_path=history_receipt_path,
            pins=pins,
            manifest_public_key_path=manifest_public_key_path,
            official_day=official_day,
            contract_registry_raw=contract_registry_raw,
            expected_contract_registry_raw_sha256=expected_contract_registry_raw_sha256,
            genesis=genesis,
            predecessor=predecessor,
        )
    if (
        not isinstance(built, BuiltVerifiedDailyPitMainRollSource)
        or not isinstance(built.artifact_raw, bytes)
        or built.artifact_raw_sha256 != sha256(built.artifact_raw)
        or not isinstance(built.artifact_id, str)
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor construction proof is invalid"
        )
    artifact_raw = built.artifact_raw
    if (
        not isinstance(artifact_raw, bytes)
        or not 1 <= len(artifact_raw) <= MAX_ARTIFACT_RAW_BYTES
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor artifact resource limit exceeded"
        )
    artifact = _validated_artifact(artifact_raw)
    if artifact[
        "artifact_id"
    ] != built.artifact_id or built.artifact_raw_sha256 != sha256(artifact_raw):
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor construction proof drifted"
        )
    with operator_state_lock(operator_state.path, exclusive=True):
        current = load_operator_state(operator_state.path)
        if current != operator_state:
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog operator state changed before publication"
            )
        if protected_genesis_inputs is not None:
            policy = load_isolation_policy(
                protected_genesis_inputs.runtime_input_path.parent
                / "isolation-policy-v1.json"
            )
            runtime_input = load_runtime_input(
                protected_genesis_inputs.runtime_input_path,
                policy=policy,
            )
            if (
                runtime_input.raw_sha256
                != protected_genesis_inputs.runtime_input_raw_sha256
                or policy.uid != protected_genesis_inputs.service_uid
                or policy.gid != protected_genesis_inputs.service_gid
            ):
                raise DailyRollPredecessorCatalogError(
                    "daily roll protected publication runtime root drifted"
                )
        lineage_state = artifact["verified_lineage"]["operator_state"]
        if (
            artifact["official_day"] != current.payload["last_trade_day"]
            or lineage_state["raw_sha256"] != current.raw_sha256
            or lineage_state["manifest_sequence"]
            != current.payload["manifest_sequence"]
            or lineage_state["manifest_head_seal_sha256"]
            != current.payload["manifest_head_seal_sha256"]
            or lineage_state["manifest_head_commit_seal_sha256"]
            != current.payload["manifest_head_commit_seal_sha256"]
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog artifact is not bound to current root"
            )
        _prepare_catalog(root)
        _recover_catalog_partial(root)
        loaded = _load_catalog(
            root,
            allowed_orphan_artifact_id=artifact["artifact_id"],
        )
        if (
            loaded.head is not None
            and loaded.head.receipt["official_day"] == artifact["official_day"]
        ):
            if loaded.head.artifact_raw != artifact_raw:
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog duplicate day conflicts"
                )
            return loaded.head
        continuity_mode = artifact["verified_lineage"]["continuity"]["mode"]
        if (loaded.head is None) != (continuity_mode == "GENESIS_STATIC_CORE_EQUAL"):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog publication continuity branch mismatch"
            )
        if loaded.head is not None and (
            loaded.head.artifact["execution_day"] != artifact["official_day"]
            or loaded.head.artifact["following_official_day"]
            != artifact["execution_day"]
        ):
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog publication is not the next official artifact"
            )
        artifact_path = root / _artifact_relative_path(artifact["artifact_id"])
        if artifact_path.exists():
            recovered_raw = _read_root_file(
                artifact_path,
                "daily roll predecessor catalog recovery artifact",
                limit=MAX_ARTIFACT_RAW_BYTES,
            )
            if recovered_raw != artifact_raw:
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog orphan artifact conflicts"
                )
        else:
            _atomic_root_write(artifact_path, artifact_raw, create_only=True)
        head = loaded.head
        receipt: dict[str, Any] = {
            "schema_version": CATALOG_SCHEMA,
            "receipt_id": "",
            "sequence": len(loaded.entries) + 1,
            "official_day": artifact["official_day"],
            "artifact_id": artifact["artifact_id"],
            "artifact_raw_sha256": sha256(artifact_raw),
            "artifact_raw_bytes": len(artifact_raw),
            "artifact_relative_path": _artifact_relative_path(artifact["artifact_id"]),
            "previous_receipt_raw_sha256": (
                sha256(head.receipt_raw) if head is not None else None
            ),
            "previous_artifact_id": (
                head.artifact["artifact_id"] if head is not None else None
            ),
            "operator_state_raw_sha256": current.raw_sha256,
            "operator_manifest_sequence": current.payload["manifest_sequence"],
            "manifest_head_seal_sha256": current.payload["manifest_head_seal_sha256"],
            "manifest_head_commit_seal_sha256": current.payload[
                "manifest_head_commit_seal_sha256"
            ],
            "authority": false_authority(),
        }
        receipt["receipt_id"] = _receipt_id(receipt)
        receipt_raw = canonical_json_line(receipt)
        receipt_path = root / "receipts" / f"{artifact['official_day']}.json"
        _atomic_root_write(receipt_path, receipt_raw, create_only=True)
        verified = _load_catalog(root)
        if verified.head is None or verified.head.receipt_raw != receipt_raw:
            raise DailyRollPredecessorCatalogError(
                "daily roll catalog publication readback mismatch"
            )
        return verified.head


def load_current_catalog_head(
    operator_state_path: Path,
) -> CurrentCatalogHeadProof:
    """Load the full catalog and bind its unique head to the current root.

    The operator state is intentionally accepted by path, not by caller-built
    value.  It is reloaded while the shared operator lock is held, and the
    complete immutable catalog chain is verified inside that same lock.  This
    reader never prepares directories, recovers partials, or writes state.
    """

    state_path = Path(operator_state_path)
    try:
        with operator_state_lock(state_path, exclusive=False):
            current = load_operator_state(state_path)
            loaded = _load_catalog(catalog_root(state_path))
            head = loaded.head
            if head is None:
                raise DailyRollPredecessorCatalogError(
                    "daily roll predecessor catalog is empty"
                )
            receipt = head.receipt
            artifact = head.artifact
            lineage = artifact["verified_lineage"]
            artifact_state = lineage["operator_state"]
            artifact_manifest = lineage["manifest"]
            current_payload = current.payload
            if (
                receipt["official_day"] != current_payload["last_trade_day"]
                or artifact["official_day"] != current_payload["last_trade_day"]
                or receipt["operator_state_raw_sha256"] != current.raw_sha256
                or artifact_state["raw_sha256"] != current.raw_sha256
                or receipt["operator_manifest_sequence"]
                != current_payload["manifest_sequence"]
                or artifact_state["manifest_sequence"]
                != current_payload["manifest_sequence"]
                or artifact_state["manifest_genesis_seal_sha256"]
                != current_payload["manifest_genesis_seal_sha256"]
                or receipt["manifest_head_seal_sha256"]
                != current_payload["manifest_head_seal_sha256"]
                or artifact_state["manifest_head_seal_sha256"]
                != current_payload["manifest_head_seal_sha256"]
                or artifact_manifest["batch_seal_sha256"]
                != current_payload["manifest_head_seal_sha256"]
                or receipt["manifest_head_commit_seal_sha256"]
                != current_payload["manifest_head_commit_seal_sha256"]
                or artifact_state["manifest_head_commit_seal_sha256"]
                != current_payload["manifest_head_commit_seal_sha256"]
                or artifact_manifest["commit_seal_sha256"]
                != current_payload["manifest_head_commit_seal_sha256"]
                or artifact_state["commit_anchor_ledger_raw_sha256"]
                != current_payload["commit_anchor_ledger_raw_sha256"]
            ):
                raise DailyRollPredecessorCatalogError(
                    "daily roll catalog head is not bound to current root"
                )
            return CurrentCatalogHeadProof(
                receipt_raw=head.receipt_raw,
                receipt_raw_sha256=sha256(head.receipt_raw),
                artifact_raw=head.artifact_raw,
                artifact_raw_sha256=sha256(head.artifact_raw),
                operator_state_raw_sha256=current.raw_sha256,
                operator_manifest_sequence=current_payload["manifest_sequence"],
                manifest_genesis_seal_sha256=current_payload[
                    "manifest_genesis_seal_sha256"
                ],
                manifest_head_seal_sha256=current_payload["manifest_head_seal_sha256"],
                manifest_head_commit_seal_sha256=current_payload[
                    "manifest_head_commit_seal_sha256"
                ],
                commit_anchor_ledger_raw_sha256=current_payload[
                    "commit_anchor_ledger_raw_sha256"
                ],
                last_trade_day=current_payload["last_trade_day"],
                authority=false_authority(),
            )
    except DailyRollPredecessorCatalogError:
        raise
    except (KeyError, OSError, TypeError, ValueError, RegistryError) as exc:
        raise DailyRollPredecessorCatalogError(
            "daily roll current catalog head verification failed"
        ) from exc


def _load_linked_predecessor_locked(
    *,
    operator_state: OperatorState,
    current_official_day: date,
    current_execution_day: date,
    current_manifest: dict[str, Any],
    runtime_input_raw_sha256: str,
    calendar_raw_sha256: str,
    calendar_availability_anchor_raw_sha256: str,
    isolation_policy_raw_sha256: str,
    warehouse_registry_raw_sha256: str,
    contract_registry_raw_sha256: str,
) -> CatalogEntry:
    """Load and bind the unique head while the caller holds operator lock."""

    loaded = _load_catalog(catalog_root(operator_state.path))
    head = loaded.head
    if head is None:
        raise DailyRollPredecessorCatalogError(
            "daily roll predecessor catalog is empty"
        )
    artifact = head.artifact
    lineage = artifact["verified_lineage"]
    if (
        artifact["execution_day"] != current_official_day.isoformat()
        or artifact["following_official_day"] != current_execution_day.isoformat()
        or current_manifest.get("parent_batch_seal_sha256")
        != lineage["manifest"]["batch_seal_sha256"]
        or current_manifest.get("parent_commit_seal_sha256")
        != lineage["manifest"]["commit_seal_sha256"]
        or operator_state.payload["manifest_sequence"]
        != lineage["operator_state"]["manifest_sequence"] + 1
        or operator_state.payload["manifest_genesis_seal_sha256"]
        != lineage["operator_state"]["manifest_genesis_seal_sha256"]
        or lineage["runtime"]["runtime_input_raw_sha256"] != runtime_input_raw_sha256
        or lineage["calendar"]["calendar_raw_sha256"] != calendar_raw_sha256
        or lineage["calendar"]["calendar_availability_anchor_raw_sha256"]
        != calendar_availability_anchor_raw_sha256
        or lineage["runtime"]["isolation_policy_raw_sha256"]
        != isolation_policy_raw_sha256
        or lineage["runtime"]["warehouse_registry_raw_sha256"]
        != warehouse_registry_raw_sha256
        or lineage["contract_registry"]["raw_sha256"] != contract_registry_raw_sha256
    ):
        raise DailyRollPredecessorCatalogError(
            "daily roll catalog predecessor/current-root continuity mismatch"
        )
    return head
