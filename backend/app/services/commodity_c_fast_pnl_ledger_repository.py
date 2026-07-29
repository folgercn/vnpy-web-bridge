from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal, Mapping

from pydantic import ValidationError

from app.schemas.commodity_c_fast_pnl_ledger import (
    CommodityCFastFourLayerPnlLedgerEntryDTO,
    CommodityCFastPnlLedgerAuditDTO,
    sha256_json,
)
from app.schemas.commodity_c_fast_pnl_ledger_repository import (
    CommodityCFastPnlLedgerRepositoryExportDTO,
    CommodityCFastPnlSourceAdapterBindingDTO,
)
from app.services.commodity_c_fast_pnl_ledger import (
    CFastPnlLedgerError,
    reload_and_verify_four_layer_pnl_entry,
    verify_four_layer_pnl_chain,
)


MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_EXPORT_BYTES = 256 * 1024 * 1024
LEDGER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
ENTRY_NAME_PATTERN = re.compile(
    r"^(?P<sequence>[0-9]{10})-(?P<entry_hash>[0-9a-f]{64})\.json$"
)
PENDING_NAME_PATTERN = re.compile(
    r"^\.pending-(?P<sequence>[0-9]{10})-"
    r"(?P<entry_hash>[0-9a-f]{64})\.json$"
)


class CFastPnlLedgerRepositoryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PnlLedgerAppendResult:
    status: Literal["CREATED", "ALREADY_PRESENT"]
    entry_sequence: int
    entry_hash: str
    chain_tip_entry_hash: str


SOURCE_ADAPTER_BINDINGS = (
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-theoretical-target-marks-v1",
        layer_kind="THEORETICAL_TARGET_PNL",
        source_schema_version=(
            "commodity_c_fast_theoretical_target_pnl_source_facts_v1"
        ),
        source_kind="SIGNED_EXACT_TARGET_MARKS",
        verification_rule="FRESH_REPLAY_REALIZED_UNREALIZED_ROLL_SUM",
        amount_authority="DERIVED_RESEARCH_VALUE_ONLY",
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-fee-and-stress-v2",
        layer_kind="FEE_ADJUSTED_PNL",
        source_schema_version=("commodity_c_fast_fee_adjusted_pnl_source_facts_v2"),
        source_kind="FEE_AND_STRESS_ASSUMPTIONS",
        verification_rule=("FRESH_REPLAY_RATE_TIMES_TURNOVER_OR_EXPLICIT_UNBOUND"),
        amount_authority=("DERIVED_WHEN_ALL_FEE_COMPONENTS_BOUND_OTHERWISE_NULL"),
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-book-walk-fill-bounds-v1",
        layer_kind="EXECUTION_QUALITY_INTERVAL_PNL",
        source_schema_version=(
            "commodity_c_fast_execution_quality_interval_pnl_source_facts_v1"
        ),
        source_kind="EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
        verification_rule=("FRESH_REPLAY_BOOK_WALK_FILL_INTERVAL_BOUNDS_ONLY"),
        amount_authority=("UNCALIBRATED_INTERVAL_ONLY_NO_POINT_FILL_PROBABILITY"),
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-simnow-not-provided-v1",
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        source_schema_version=(
            "commodity_c_fast_actual_simnow_not_provided_source_facts_v1"
        ),
        source_kind="ACTUAL_SIMNOW_FACTS_NOT_PROVIDED",
        verification_rule=("NOT_PROVIDED_ACTUAL_AMOUNTS_MUST_REMAIN_NULL"),
        amount_authority="UNVERIFIED_ACTUAL_AMOUNTS_MUST_REMAIN_NULL",
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-simnow-archive-reference-v3",
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        source_schema_version="commodity_c_fast_actual_simnow_facts_v3",
        source_kind=("SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"),
        verification_rule=("ARCHIVE_REFERENCE_ONLY_NO_ACTUAL_AMOUNT_AUTHORITY"),
        amount_authority="UNVERIFIED_ACTUAL_AMOUNTS_MUST_REMAIN_NULL",
    ),
)


def canonical_json_line(payload: Mapping[str, Any]) -> bytes:
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
        raise CFastPnlLedgerRepositoryError("REPOSITORY_CANONICAL_JSON_FAILED") from exc


class CommodityCFastPnlLedgerRepository:
    """Create-only filesystem repository for one four-layer PnL ledger."""

    def __init__(self, root: Path | str, ledger_id: str) -> None:
        if LEDGER_ID_PATTERN.fullmatch(ledger_id) is None:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LEDGER_ID_INVALID")
        self.root = Path(root)
        self.ledger_id = ledger_id
        self.ledger_path = self.root / ledger_id
        self.entries_path = self.ledger_path / "entries"
        self.lock_path = self.ledger_path / ".append.lock"

    @classmethod
    def open_or_create(
        cls,
        root: Path | str,
        ledger_id: str,
    ) -> "CommodityCFastPnlLedgerRepository":
        repository = cls(root, ledger_id)
        repository._ensure_directories()
        with repository._locked():
            repository._recover_pending_locked()
            repository._load_entries_locked(allow_empty=True)
        return repository

    @classmethod
    def open(
        cls,
        root: Path | str,
        ledger_id: str,
    ) -> "CommodityCFastPnlLedgerRepository":
        repository = cls(root, ledger_id)
        repository._validate_directories()
        with repository._locked():
            repository._recover_pending_locked()
            repository._load_entries_locked(allow_empty=True)
        return repository

    def append(
        self,
        payload: Mapping[str, Any],
    ) -> PnlLedgerAppendResult:
        try:
            candidate = reload_and_verify_four_layer_pnl_entry(payload)
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_ENTRY_REJECTED:{exc.code}"
            ) from exc
        if candidate.ledger_id != self.ledger_id:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LEDGER_ID_MISMATCH")
        candidate_raw = _entry_bytes(candidate)
        with self._locked():
            self._recover_pending_locked()
            entries = self._load_entries_locked(allow_empty=True)
            for existing in entries:
                if existing.entry_hash == candidate.entry_hash:
                    if existing.model_dump(mode="json") != candidate.model_dump(
                        mode="json"
                    ):
                        raise CFastPnlLedgerRepositoryError(
                            "REPOSITORY_ENTRY_HASH_COLLISION"
                        )
                    return PnlLedgerAppendResult(
                        status="ALREADY_PRESENT",
                        entry_sequence=existing.entry_sequence,
                        entry_hash=existing.entry_hash,
                        chain_tip_entry_hash=entries[-1].entry_hash,
                    )
            self._validate_next_entry(entries, candidate)
            try:
                verify_four_layer_pnl_chain(
                    [entry.model_dump(mode="json") for entry in (*entries, candidate)]
                )
            except CFastPnlLedgerError as exc:
                raise CFastPnlLedgerRepositoryError(
                    f"REPOSITORY_CHAIN_REJECTED:{exc.code}"
                ) from exc
            pending_path = self.entries_path / _pending_name(candidate)
            final_path = self.entries_path / _entry_name(candidate)
            self._write_create_only(pending_path, candidate_raw)
            self._promote_pending_create_only(
                pending_path,
                final_path,
                candidate_raw,
            )
            committed = self._load_entries_locked(allow_empty=False)
            if committed[-1].entry_hash != candidate.entry_hash:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_COMMIT_TIP_MISMATCH")
            return PnlLedgerAppendResult(
                status="CREATED",
                entry_sequence=candidate.entry_sequence,
                entry_hash=candidate.entry_hash,
                chain_tip_entry_hash=candidate.entry_hash,
            )

    def entries(
        self,
    ) -> tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...]:
        with self._locked():
            self._recover_pending_locked()
            return self._load_entries_locked(allow_empty=False)

    def audit(self) -> CommodityCFastPnlLedgerAuditDTO:
        entries = self.entries()
        try:
            return verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries]
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_AUDIT_FAILED:{exc.code}"
            ) from exc

    def export(self) -> CommodityCFastPnlLedgerRepositoryExportDTO:
        entries = self.entries()
        built = _build_repository_export(entries, self.ledger_id)
        return reload_and_verify_repository_export(built.model_dump(mode="json"))

    def export_json_bytes(self) -> bytes:
        return canonical_json_line(self.export().model_dump(mode="json"))

    def render_audit_report_zh(self) -> str:
        exported = self.export()
        audit = exported.audit
        adapter_lines = "\n".join(
            (
                f"- `{adapter.layer_kind}`："
                f"`{adapter.adapter_id}`；"
                f"`{adapter.verification_rule}`；"
                f"`{adapter.amount_authority}`"
            )
            for adapter in exported.source_adapters
        )
        return (
            "# C_FAST 四层 PnL 不可变账本审计报告\n\n"
            "## 审计结论\n\n"
            f"- 账本：`{exported.ledger_id}`\n"
            f"- 记录数：`{exported.entry_count}`\n"
            f"- Genesis：`{exported.genesis_entry_hash}`\n"
            f"- Chain tip：`{exported.chain_tip_entry_hash}`\n"
            f"- 有 Actual 引用事实的记录数："
            f"`{audit.actual_fact_entry_count}`\n"
            f"- 审计状态：`{audit.audit_state}`\n"
            f"- Export SHA256：`{exported.export_sha256}`\n\n"
            "## Source adapters\n\n"
            f"{adapter_lines}\n\n"
            "## 权限与事实边界\n\n"
            "- 本报告只证明 canonical JSON、fresh replay 与本地 hash-chain "
            "结构一致。\n"
            "- `external_genesis_anchor_state="
            "NOT_PROVIDED_STRUCTURE_ONLY`。\n"
            "- `external_tip_anchor_state=NOT_PROVIDED_STRUCTURE_ONLY`。\n"
            "- 无权威 SimNow raw orders/trades/fill price/multiplier/fee "
            "archive 时，Actual 金额固定为 `null/UNVERIFIED`。\n"
            "- `countable_forward=false`，`authority_granted=false`，"
            "`dispatch_allowed=false`，`replacement_allowed=false`，"
            "`production_allowed=false`。\n"
        )

    def _ensure_directories(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.ledger_path.mkdir(mode=0o700, exist_ok=True)
        self.entries_path.mkdir(mode=0o700, exist_ok=True)
        self._validate_directories()
        _fsync_directory(self.root)
        _fsync_directory(self.ledger_path)

    def _validate_directories(self) -> None:
        for path in (self.root, self.ledger_path, self.entries_path):
            try:
                path_stat = path.lstat()
            except FileNotFoundError as exc:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_NOT_FOUND") from exc
            if not stat.S_ISDIR(path_stat.st_mode):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PATH_NOT_DIRECTORY")
            if (
                path_stat.st_uid != os.geteuid()
                or stat.S_IMODE(path_stat.st_mode) & 0o022
            ):
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_DIRECTORY_CUSTODY_INVALID"
                )
        allowed = {".append.lock", "entries"}
        if any(path.name not in allowed for path in self.ledger_path.iterdir()):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_LEDGER_ARTIFACT")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._validate_directories()
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LOCK_OPEN_FAILED") from exc
        try:
            lock_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != os.geteuid()
                or stat.S_IMODE(lock_stat.st_mode) & 0o077
            ):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_LOCK_NOT_REGULAR")
            try:
                lock_path_stat = self.lock_path.lstat()
            except OSError as exc:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_LOCK_PATH_CHANGED"
                ) from exc
            if _stat_identity(lock_stat) != _stat_identity(lock_path_stat):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_LOCK_PATH_CHANGED")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_entries_locked(
        self,
        *,
        allow_empty: bool,
    ) -> tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...]:
        entry_paths: list[tuple[int, Path]] = []
        for path in self.entries_path.iterdir():
            if PENDING_NAME_PATTERN.fullmatch(path.name):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PENDING_NOT_RECOVERED")
            match = ENTRY_NAME_PATTERN.fullmatch(path.name)
            if match is None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
            entry_paths.append((int(match["sequence"]), path))
        entry_paths.sort(key=lambda item: item[0])
        if not entry_paths:
            if allow_empty:
                return ()
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EMPTY")
        entries = tuple(
            self._read_entry_file(path, ENTRY_NAME_PATTERN) for _, path in entry_paths
        )
        try:
            verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries]
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_CHAIN_INVALID:{exc.code}"
            ) from exc
        return entries

    def _recover_pending_locked(self) -> None:
        pending_paths: list[Path] = []
        for path in self.entries_path.iterdir():
            if PENDING_NAME_PATTERN.fullmatch(path.name):
                pending_paths.append(path)
            elif ENTRY_NAME_PATTERN.fullmatch(path.name) is None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
        pending_paths.sort()
        if len(pending_paths) > 1:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_MULTIPLE_PENDING_FILES")
        if not pending_paths:
            return
        pending_path = pending_paths[0]
        candidate = self._read_entry_file(
            pending_path,
            PENDING_NAME_PATTERN,
        )
        candidate_raw = _entry_bytes(candidate)
        final_path = self.entries_path / _entry_name(candidate)
        if final_path.exists():
            final = self._read_entry_file(final_path, ENTRY_NAME_PATTERN)
            if final != candidate:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PENDING_FINAL_CONFLICT")
            pending_path.unlink()
            _fsync_directory(self.entries_path)
            return
        entries = self._load_entries_without_pending_locked()
        self._validate_next_entry(entries, candidate)
        try:
            verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in (*entries, candidate)]
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_PENDING_CHAIN_INVALID:{exc.code}"
            ) from exc
        self._promote_pending_create_only(
            pending_path,
            final_path,
            candidate_raw,
        )

    def _load_entries_without_pending_locked(
        self,
    ) -> tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...]:
        paths: list[tuple[int, Path]] = []
        for path in self.entries_path.iterdir():
            if PENDING_NAME_PATTERN.fullmatch(path.name):
                continue
            match = ENTRY_NAME_PATTERN.fullmatch(path.name)
            if match is None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
            paths.append((int(match["sequence"]), path))
        paths.sort(key=lambda item: item[0])
        entries = tuple(
            self._read_entry_file(path, ENTRY_NAME_PATTERN) for _, path in paths
        )
        if entries:
            try:
                verify_four_layer_pnl_chain(
                    [entry.model_dump(mode="json") for entry in entries]
                )
            except CFastPnlLedgerError as exc:
                raise CFastPnlLedgerRepositoryError(
                    f"REPOSITORY_CHAIN_INVALID:{exc.code}"
                ) from exc
        return entries

    def _read_entry_file(
        self,
        path: Path,
        name_pattern: re.Pattern[str],
    ) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
        match = name_pattern.fullmatch(path.name)
        if match is None:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ENTRY_FILENAME_INVALID")
        raw = _read_raw_regular(
            path,
            invalid_code="REPOSITORY_ENTRY_FILE_INVALID",
            read_code="REPOSITORY_ENTRY_READ_FAILED",
            changed_code="REPOSITORY_ENTRY_CHANGED_DURING_READ",
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_ENTRY_JSON_INVALID"
            ) from exc
        if not isinstance(payload, dict):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ENTRY_JSON_INVALID")
        try:
            entry = reload_and_verify_four_layer_pnl_entry(payload)
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_ENTRY_INVALID:{exc.code}"
            ) from exc
        if raw != _entry_bytes(entry):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ENTRY_NOT_CANONICAL")
        if (
            int(match["sequence"]) != entry.entry_sequence
            or match["entry_hash"] != entry.entry_hash
        ):
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_ENTRY_FILENAME_BINDING_MISMATCH"
            )
        return entry

    def _validate_next_entry(
        self,
        entries: tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...],
        candidate: CommodityCFastFourLayerPnlLedgerEntryDTO,
    ) -> None:
        expected_sequence = len(entries) + 1
        expected_predecessor = entries[-1].entry_hash if entries else None
        if candidate.entry_sequence != expected_sequence:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_APPEND_SEQUENCE_INVALID")
        if candidate.previous_entry_hash != expected_predecessor:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_APPEND_PREDECESSOR_INVALID")

    def _write_create_only(self, path: Path, raw: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            existing = _read_raw_regular(path)
            if existing != raw:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PENDING_CONFLICT")
            return
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_PENDING_CREATE_FAILED"
            ) from exc
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        _fsync_directory(self.entries_path)
        if _read_raw_regular(path) != raw:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_PENDING_CHANGED_AFTER_WRITE"
            )

    def _promote_pending_create_only(
        self,
        pending_path: Path,
        final_path: Path,
        raw: bytes,
    ) -> None:
        try:
            os.link(
                pending_path,
                final_path,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _read_raw_regular(final_path) != raw:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_FINAL_CONFLICT")
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_FINAL_CREATE_FAILED"
            ) from exc
        _fsync_directory(self.entries_path)
        if _read_raw_regular(final_path) != raw:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_FINAL_CHANGED_AFTER_CREATE")
        pending_path.unlink()
        _fsync_directory(self.entries_path)


def reload_and_verify_repository_export(
    payload_or_raw: Mapping[str, Any] | bytes,
) -> CommodityCFastPnlLedgerRepositoryExportDTO:
    if isinstance(payload_or_raw, bytes):
        if not 0 < len(payload_or_raw) <= MAX_EXPORT_BYTES:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_RESOURCE_LIMIT")
        try:
            payload = json.loads(payload_or_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_EXPORT_JSON_INVALID"
            ) from exc
        if not isinstance(payload, dict):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_JSON_INVALID")
        try:
            canonical = canonical_json_line(payload)
        except CFastPnlLedgerRepositoryError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_EXPORT_NOT_CANONICAL"
            ) from exc
        if payload_or_raw != canonical:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_NOT_CANONICAL")
    elif isinstance(payload_or_raw, Mapping):
        payload = payload_or_raw
        try:
            canonical = canonical_json_line(payload)
        except CFastPnlLedgerRepositoryError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_EXPORT_JSON_INVALID"
            ) from exc
        if len(canonical) > MAX_EXPORT_BYTES:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_RESOURCE_LIMIT")
    else:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_INPUT_INVALID")
    try:
        reloaded = CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_DTO_INVALID") from exc
    try:
        fresh_audit = verify_four_layer_pnl_chain(
            [entry.model_dump(mode="json") for entry in reloaded.entries]
        )
    except CFastPnlLedgerError as exc:
        raise CFastPnlLedgerRepositoryError(
            f"REPOSITORY_EXPORT_CHAIN_INVALID:{exc.code}"
        ) from exc
    if fresh_audit != reloaded.audit:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_FRESH_AUDIT_MISMATCH")
    if tuple(reloaded.source_adapters) != SOURCE_ADAPTER_BINDINGS:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_SOURCE_ADAPTER_MISMATCH")
    expected = _build_repository_export(
        tuple(reloaded.entries),
        reloaded.ledger_id,
        fresh_audit=fresh_audit,
    )
    if expected != reloaded:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_FRESH_REPLAY_MISMATCH")
    return reloaded


def _build_repository_export(
    entries: tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...],
    ledger_id: str,
    *,
    fresh_audit: CommodityCFastPnlLedgerAuditDTO | None = None,
) -> CommodityCFastPnlLedgerRepositoryExportDTO:
    if not entries:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EMPTY")
    if any(entry.ledger_id != ledger_id for entry in entries):
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_LEDGER_ID_MISMATCH")
    if fresh_audit is None:
        try:
            fresh_audit = verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries]
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_EXPORT_CHAIN_INVALID:{exc.code}"
            ) from exc
    core: dict[str, Any] = {
        "schema_version": ("commodity_c_fast_pnl_ledger_repository_export_v1"),
        "ledger_id": ledger_id,
        "entry_count": len(entries),
        "genesis_entry_hash": entries[0].entry_hash,
        "chain_tip_entry_hash": entries[-1].entry_hash,
        "ordered_entry_hashes_sha256": (fresh_audit.ordered_entry_hashes_sha256),
        "entries": [entry.model_dump(mode="json") for entry in entries],
        "audit": fresh_audit.model_dump(mode="json"),
        "source_adapters": [
            adapter.model_dump(mode="json") for adapter in SOURCE_ADAPTER_BINDINGS
        ],
        "repository_semantics": ("APPEND_ONLY_CREATE_ONLY_CANONICAL_JSON_HASH_CHAIN"),
        "recovery_semantics": ("FSYNC_PENDING_THEN_CREATE_ONLY_LINK_AND_FRESH_REPLAY"),
        "audit_report_language": "zh-CN",
        "audit_scope": "DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY",
        "external_genesis_anchor_state": "NOT_PROVIDED_STRUCTURE_ONLY",
        "external_tip_anchor_state": "NOT_PROVIDED_STRUCTURE_ONLY",
        "countable_forward": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    try:
        return CommodityCFastPnlLedgerRepositoryExportDTO.model_validate(
            {**core, "export_sha256": sha256_json(core)}
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_BUILD_FAILED") from exc


def _entry_name(entry: CommodityCFastFourLayerPnlLedgerEntryDTO) -> str:
    return f"{entry.entry_sequence:010d}-{entry.entry_hash}.json"


def _pending_name(entry: CommodityCFastFourLayerPnlLedgerEntryDTO) -> str:
    return f".pending-{entry.entry_sequence:010d}-{entry.entry_hash}.json"


def _entry_bytes(entry: CommodityCFastFourLayerPnlLedgerEntryDTO) -> bytes:
    return canonical_json_line(entry.model_dump(mode="json"))


def _read_raw_regular(
    path: Path,
    *,
    invalid_code: str = "REPOSITORY_ARTIFACT_NOT_REGULAR",
    read_code: str = "REPOSITORY_ARTIFACT_READ_FAILED",
    changed_code: str = "REPOSITORY_ARTIFACT_CHANGED_DURING_READ",
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_size <= 0
                or before.st_size > MAX_ENTRY_BYTES
            ):
                raise CFastPnlLedgerRepositoryError(invalid_code)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(MAX_ENTRY_BYTES + 1)
            after = os.fstat(descriptor)
            current_path = path.lstat()
        finally:
            os.close(descriptor)
    except CFastPnlLedgerRepositoryError:
        raise
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(read_code) from exc
    if (
        _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(current_path)
        or len(raw) != before.st_size
    ):
        raise CFastPnlLedgerRepositoryError(changed_code)
    return raw


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(
            "REPOSITORY_DIRECTORY_FSYNC_FAILED"
        ) from exc
