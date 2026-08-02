from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Mapping

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
from app.services.commodity_c_fast_fee_binding_trust import (
    FeeBindingTrustContext,
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
RESERVATION_NAME_PATTERN = re.compile(r"^\.reservation-(?P<sequence>[0-9]{10})\.json$")


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
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-simnow-session-archive-replay-v4",
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        source_schema_version="commodity_c_fast_actual_simnow_facts_v4",
        source_kind=("SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"),
        verification_rule=(
            "FRESH_REPLAY_SESSION_RAW_TRADES_MARKS_MULTIPLIERS_FEES_UNBOUND"
        ),
        amount_authority="GROSS_AND_SLIPPAGE_REPLAYED_FEES_AND_NET_UNBOUND",
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-simnow-settled-session-archive-replay-v1",
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        source_schema_version=(
            "commodity_c_fast_actual_simnow_settled_archive_facts_v1"
        ),
        source_kind=(
            "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
        ),
        verification_rule=(
            "FRESH_REPLAY_SETTLED_SESSION_RAW_TRADES_MARKS_MULTIPLIERS_FEES_UNBOUND"
        ),
        amount_authority="GROSS_AND_SLIPPAGE_REPLAYED_FEES_AND_NET_UNBOUND",
    ),
    CommodityCFastPnlSourceAdapterBindingDTO(
        adapter_id="cfast-simnow-fee-statement-replay-v5",
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        source_schema_version="commodity_c_fast_actual_simnow_facts_v5",
        source_kind=(
            "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND"
        ),
        verification_rule=(
            "FRESH_REPLAY_EXACT_ARCHIVE_TRADES_AND_SIGNED_FEE_STATEMENT"
        ),
        amount_authority=("GROSS_OFFICIAL_BROKER_ALL_IN_AND_NET_FRESH_REPLAYED"),
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

    def __init__(
        self,
        root: Path | str,
        ledger_id: str,
        *,
        fee_binding_trust_context: FeeBindingTrustContext | None = None,
    ) -> None:
        if LEDGER_ID_PATTERN.fullmatch(ledger_id) is None:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LEDGER_ID_INVALID")
        self.root = Path(root)
        self.ledger_id = ledger_id
        self.ledger_path = self.root / ledger_id
        self.entries_path = self.ledger_path / "entries"
        self.lock_path = self.ledger_path / ".append.lock"
        self.fee_binding_trust_context = fee_binding_trust_context

    @classmethod
    def open_or_create(
        cls,
        root: Path | str,
        ledger_id: str,
        *,
        fee_binding_trust_context: FeeBindingTrustContext | None = None,
    ) -> "CommodityCFastPnlLedgerRepository":
        repository = cls(
            root,
            ledger_id,
            fee_binding_trust_context=fee_binding_trust_context,
        )
        repository._ensure_directories()
        with repository._locked() as locked:
            entries_descriptor, _, _ = locked
            repository._recover_pending_locked(entries_descriptor)
            repository._load_entries_locked(
                entries_descriptor,
                allow_empty=True,
            )
        return repository

    @classmethod
    def open(
        cls,
        root: Path | str,
        ledger_id: str,
        *,
        fee_binding_trust_context: FeeBindingTrustContext | None = None,
    ) -> "CommodityCFastPnlLedgerRepository":
        repository = cls(
            root,
            ledger_id,
            fee_binding_trust_context=fee_binding_trust_context,
        )
        repository._validate_directories()
        with repository._locked() as locked:
            entries_descriptor, _, _ = locked
            repository._recover_pending_locked(entries_descriptor)
            repository._load_entries_locked(
                entries_descriptor,
                allow_empty=True,
            )
        return repository

    def append(
        self,
        payload: Mapping[str, Any],
    ) -> PnlLedgerAppendResult:
        try:
            candidate = reload_and_verify_four_layer_pnl_entry(
                payload,
                fee_binding_trust_context=(self.fee_binding_trust_context),
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_ENTRY_REJECTED:{exc.code}"
            ) from exc
        if candidate.ledger_id != self.ledger_id:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LEDGER_ID_MISMATCH")
        candidate_raw = _entry_bytes(candidate)
        with self._locked() as locked:
            entries_descriptor, assert_lock, assert_entries = locked
            self._recover_pending_locked(entries_descriptor)
            entries = self._load_entries_locked(
                entries_descriptor,
                allow_empty=True,
            )
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
                    [entry.model_dump(mode="json") for entry in (*entries, candidate)],
                    fee_binding_trust_context=(self.fee_binding_trust_context),
                )
            except CFastPnlLedgerError as exc:
                raise CFastPnlLedgerRepositoryError(
                    f"REPOSITORY_CHAIN_REJECTED:{exc.code}"
                ) from exc
            pending_name = _pending_name(candidate)
            final_name = _entry_name(candidate)
            reservation_name = _reservation_name(candidate)
            assert_lock()
            assert_entries()
            self._write_reservation_create_only(
                entries_descriptor,
                reservation_name,
                candidate_raw,
            )
            assert_lock()
            assert_entries()
            self._write_create_only(
                entries_descriptor,
                pending_name,
                candidate_raw,
            )
            assert_lock()
            assert_entries()
            self._promote_pending_create_only(
                entries_descriptor,
                pending_name,
                final_name,
                candidate_raw,
            )
            assert_lock()
            assert_entries()
            committed = self._load_entries_locked(
                entries_descriptor,
                allow_empty=False,
            )
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
        with self._locked() as locked:
            entries_descriptor, _, _ = locked
            self._recover_pending_locked(entries_descriptor)
            return self._load_entries_locked(
                entries_descriptor,
                allow_empty=False,
            )

    def audit(self) -> CommodityCFastPnlLedgerAuditDTO:
        entries = self.entries()
        try:
            return verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries],
                fee_binding_trust_context=(self.fee_binding_trust_context),
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_AUDIT_FAILED:{exc.code}"
            ) from exc

    def export(self) -> CommodityCFastPnlLedgerRepositoryExportDTO:
        entries = self.entries()
        built = _build_repository_export(
            entries,
            self.ledger_id,
            fee_binding_trust_context=self.fee_binding_trust_context,
        )
        return reload_and_verify_repository_export(
            built.model_dump(mode="json"),
            fee_binding_trust_context=self.fee_binding_trust_context,
        )

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
            f"- 有 archive fresh-replay Actual gross/slippage 的记录数："
            f"`{audit.actual_gross_replayed_entry_count}`\n"
            f"- 有完整权威 fee statement 并发布 net 的记录数："
            f"`{audit.actual_net_fee_bound_entry_count}`\n"
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
            "- v4 缺 fee statement 时仍固定 UNBOUND/net null；v5 只有在独立 "
            "Ed25519 fee domain、exact archive/trade join 与完整规则全部通过时，"
            "才发布 official、broker/customer、all-in 与 net。\n"
            "- 已 append 的 settled UNBOUND terminal 只能通过显式 "
            "`NON_COUNTING_FEE_BINDING_CORRECTION` 与 `supersedes_entry_hash` "
            "追加 fee；原 entry 不覆盖，terminal gross 只计一次。\n"
            "- `countable_forward=false`，`authority_granted=false`，"
            "`dispatch_allowed=false`，`replacement_allowed=false`，"
            "`production_allowed=false`。\n"
        )

    def _ensure_directories(self) -> None:
        if not self.root.name:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ROOT_INVALID")
        with _pinned_owned_directory(
            self.root.parent,
            not_found_code="REPOSITORY_ROOT_PARENT_NOT_FOUND",
            invalid_code="REPOSITORY_ROOT_PARENT_CUSTODY_INVALID",
            open_code="REPOSITORY_ROOT_PARENT_OPEN_FAILED",
            changed_code="REPOSITORY_ROOT_PARENT_PATH_CHANGED",
        ) as parent_descriptor:
            _mkdir_create_only_or_existing(
                self.root.name,
                parent_descriptor,
                create_code="REPOSITORY_ROOT_CREATE_FAILED",
            )
            _fsync_descriptor(
                parent_descriptor,
                "REPOSITORY_ROOT_PARENT_FSYNC_FAILED",
            )
            with _pinned_owned_directory(
                self.root,
                relative_name=self.root.name,
                parent_descriptor=parent_descriptor,
                not_found_code="REPOSITORY_NOT_FOUND",
                invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
            ) as root_descriptor:
                _mkdir_create_only_or_existing(
                    self.ledger_id,
                    root_descriptor,
                    create_code="REPOSITORY_LEDGER_DIRECTORY_CREATE_FAILED",
                )
                _fsync_descriptor(
                    root_descriptor,
                    "REPOSITORY_DIRECTORY_FSYNC_FAILED",
                )
                with _pinned_owned_directory(
                    self.ledger_path,
                    relative_name=self.ledger_id,
                    parent_descriptor=root_descriptor,
                    not_found_code="REPOSITORY_NOT_FOUND",
                    invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                    open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                    changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
                ) as ledger_descriptor:
                    _mkdir_create_only_or_existing(
                        "entries",
                        ledger_descriptor,
                        create_code="REPOSITORY_ENTRIES_DIRECTORY_CREATE_FAILED",
                    )
                    _fsync_descriptor(
                        ledger_descriptor,
                        "REPOSITORY_DIRECTORY_FSYNC_FAILED",
                    )
                    with _pinned_owned_directory(
                        self.entries_path,
                        relative_name="entries",
                        parent_descriptor=ledger_descriptor,
                        not_found_code="REPOSITORY_NOT_FOUND",
                        invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                        open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                        changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
                    ):
                        self._validate_ledger_artifacts(ledger_descriptor)

    def _validate_directories(self) -> None:
        with self._pinned_directories():
            return

    @contextmanager
    def _pinned_directories(self) -> Iterator[tuple[int, int, int]]:
        if not self.root.name:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ROOT_INVALID")
        with _pinned_owned_directory(
            self.root.parent,
            not_found_code="REPOSITORY_ROOT_PARENT_NOT_FOUND",
            invalid_code="REPOSITORY_ROOT_PARENT_CUSTODY_INVALID",
            open_code="REPOSITORY_ROOT_PARENT_OPEN_FAILED",
            changed_code="REPOSITORY_ROOT_PARENT_PATH_CHANGED",
        ) as parent_descriptor:
            with _pinned_owned_directory(
                self.root,
                relative_name=self.root.name,
                parent_descriptor=parent_descriptor,
                not_found_code="REPOSITORY_NOT_FOUND",
                invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
            ) as root_descriptor:
                with _pinned_owned_directory(
                    self.ledger_path,
                    relative_name=self.ledger_id,
                    parent_descriptor=root_descriptor,
                    not_found_code="REPOSITORY_NOT_FOUND",
                    invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                    open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                    changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
                ) as ledger_descriptor:
                    with _pinned_owned_directory(
                        self.entries_path,
                        relative_name="entries",
                        parent_descriptor=ledger_descriptor,
                        not_found_code="REPOSITORY_NOT_FOUND",
                        invalid_code="REPOSITORY_DIRECTORY_CUSTODY_INVALID",
                        open_code="REPOSITORY_PATH_NOT_DIRECTORY",
                        changed_code="REPOSITORY_DIRECTORY_PATH_CHANGED",
                    ) as entries_descriptor:
                        self._validate_ledger_artifacts(ledger_descriptor)
                        yield (
                            ledger_descriptor,
                            entries_descriptor,
                            parent_descriptor,
                        )

    def _validate_ledger_artifacts(self, ledger_descriptor: int) -> None:
        allowed = {".append.lock", "entries"}
        if any(name not in allowed for name in os.listdir(ledger_descriptor)):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_LEDGER_ARTIFACT")

    @contextmanager
    def _locked(
        self,
    ) -> Iterator[tuple[int, Callable[[], None], Callable[[], None]]]:
        with self._pinned_directories() as (
            ledger_descriptor,
            entries_descriptor,
            _parent_descriptor,
        ):
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    ".append.lock",
                    flags,
                    0o600,
                    dir_fd=ledger_descriptor,
                )
            except OSError as exc:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_LOCK_OPEN_FAILED"
                ) from exc
            try:
                lock_stat = os.fstat(descriptor)
                self._validate_lock_stat(lock_stat)
                lock_identity = _stat_identity(lock_stat)

                def assert_lock() -> None:
                    try:
                        descriptor_stat = os.fstat(descriptor)
                        self._validate_lock_stat(descriptor_stat)
                        path_stat = os.stat(
                            ".append.lock",
                            dir_fd=ledger_descriptor,
                            follow_symlinks=False,
                        )
                        self._validate_lock_stat(path_stat)
                    except (CFastPnlLedgerRepositoryError, OSError) as exc:
                        raise CFastPnlLedgerRepositoryError(
                            "REPOSITORY_LOCK_PATH_CHANGED"
                        ) from exc
                    if (
                        _stat_identity(descriptor_stat) != lock_identity
                        or _stat_identity(path_stat) != lock_identity
                    ):
                        raise CFastPnlLedgerRepositoryError(
                            "REPOSITORY_LOCK_PATH_CHANGED"
                        )

                def assert_entries() -> None:
                    _assert_retained_directory_entry(
                        parent_descriptor=ledger_descriptor,
                        relative_name="entries",
                        descriptor=entries_descriptor,
                        invalid_code=("REPOSITORY_DIRECTORY_CUSTODY_INVALID"),
                        changed_code=("REPOSITORY_ENTRIES_DIRECTORY_PATH_CHANGED"),
                    )

                assert_lock()
                assert_entries()
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                assert_lock()
                assert_entries()
                yield entries_descriptor, assert_lock, assert_entries
                assert_lock()
                assert_entries()
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _validate_lock_stat(value: os.stat_result) -> None:
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
            or value.st_size != 0
        ):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_LOCK_NOT_REGULAR")

    def _load_entries_locked(
        self,
        entries_descriptor: int,
        *,
        allow_empty: bool,
    ) -> tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...]:
        entry_names: list[tuple[int, str]] = []
        for name in os.listdir(entries_descriptor):
            if PENDING_NAME_PATTERN.fullmatch(name):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PENDING_NOT_RECOVERED")
            if RESERVATION_NAME_PATTERN.fullmatch(name):
                continue
            match = ENTRY_NAME_PATTERN.fullmatch(name)
            if match is None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
            entry_names.append((int(match["sequence"]), name))
        entry_names.sort(key=lambda item: item[0])
        if not entry_names:
            if allow_empty:
                return ()
            raise CFastPnlLedgerRepositoryError("REPOSITORY_EMPTY")
        entries = tuple(
            self._read_entry_file(
                entries_descriptor,
                name,
                ENTRY_NAME_PATTERN,
            )
            for _, name in entry_names
        )
        try:
            verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries],
                fee_binding_trust_context=(self.fee_binding_trust_context),
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_CHAIN_INVALID:{exc.code}"
            ) from exc
        return entries

    def _recover_pending_locked(self, entries_descriptor: int) -> None:
        pending_names: list[str] = []
        reservation_names: dict[int, str] = {}
        final_names: dict[int, list[str]] = {}
        for name in os.listdir(entries_descriptor):
            pending_match = PENDING_NAME_PATTERN.fullmatch(name)
            reservation_match = RESERVATION_NAME_PATTERN.fullmatch(name)
            final_match = ENTRY_NAME_PATTERN.fullmatch(name)
            if pending_match is not None:
                pending_names.append(name)
            elif reservation_match is not None:
                reservation_names[int(reservation_match["sequence"])] = name
            elif final_match is not None:
                final_names.setdefault(
                    int(final_match["sequence"]),
                    [],
                ).append(name)
            else:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
        pending_names.sort()
        if len(pending_names) > 1:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_MULTIPLE_PENDING_FILES")

        reservations = {
            sequence: self._read_entry_file(
                entries_descriptor,
                name,
                RESERVATION_NAME_PATTERN,
            )
            for sequence, name in reservation_names.items()
        }
        if any(
            entry.entry_sequence != sequence for sequence, entry in reservations.items()
        ):
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_RESERVATION_SEQUENCE_MISMATCH"
            )

        for sequence, names in final_names.items():
            if len(names) != 1:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_SEQUENCE_RESERVATION_CONFLICT"
                )
            reservation = reservations.get(sequence)
            if reservation is None:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_SEQUENCE_RESERVATION_MISSING"
                )
            final = self._read_entry_file(
                entries_descriptor,
                names[0],
                ENTRY_NAME_PATTERN,
            )
            if final != reservation:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_SEQUENCE_RESERVATION_CONFLICT"
                )

        pending_name = pending_names[0] if pending_names else None
        pending: CommodityCFastFourLayerPnlLedgerEntryDTO | None = None
        if pending_name is not None:
            pending = self._read_entry_file(
                entries_descriptor,
                pending_name,
                PENDING_NAME_PATTERN,
            )
            reservation = reservations.get(pending.entry_sequence)
            if reservation is None:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_SEQUENCE_RESERVATION_MISSING"
                )
            if pending != reservation:
                raise CFastPnlLedgerRepositoryError(
                    "REPOSITORY_SEQUENCE_RESERVATION_CONFLICT"
                )
            final_for_pending = final_names.get(pending.entry_sequence, [])
            if final_for_pending:
                final = self._read_entry_file(
                    entries_descriptor,
                    final_for_pending[0],
                    ENTRY_NAME_PATTERN,
                )
                if final != pending:
                    raise CFastPnlLedgerRepositoryError(
                        "REPOSITORY_PENDING_FINAL_CONFLICT"
                    )
                try:
                    os.unlink(pending_name, dir_fd=entries_descriptor)
                except OSError as exc:
                    raise CFastPnlLedgerRepositoryError(
                        "REPOSITORY_PENDING_DELETE_FAILED"
                    ) from exc
                _fsync_descriptor(
                    entries_descriptor,
                    "REPOSITORY_DIRECTORY_FSYNC_FAILED",
                )
                pending_name = None
                pending = None

        incomplete_sequences = sorted(set(reservations) - set(final_names))
        if len(incomplete_sequences) > 1:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_MULTIPLE_INCOMPLETE_RESERVATIONS"
            )
        if not incomplete_sequences:
            if pending_name is not None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_PENDING_FINAL_CONFLICT")
            return

        incomplete_sequence = incomplete_sequences[0]
        candidate = reservations[incomplete_sequence]
        candidate_raw = _entry_bytes(candidate)
        final_name = _entry_name(candidate)
        entries = self._load_entries_without_pending_locked(entries_descriptor)
        self._validate_next_entry(entries, candidate)
        try:
            verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in (*entries, candidate)],
                fee_binding_trust_context=(self.fee_binding_trust_context),
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_PENDING_CHAIN_INVALID:{exc.code}"
            ) from exc
        expected_pending_name = _pending_name(candidate)
        if pending_name is None:
            self._write_create_only(
                entries_descriptor,
                expected_pending_name,
                candidate_raw,
            )
            pending_name = expected_pending_name
        elif pending != candidate or pending_name != expected_pending_name:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_SEQUENCE_RESERVATION_CONFLICT"
            )
        self._promote_pending_create_only(
            entries_descriptor,
            pending_name,
            final_name,
            candidate_raw,
        )

    def _load_entries_without_pending_locked(
        self,
        entries_descriptor: int,
    ) -> tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...]:
        names: list[tuple[int, str]] = []
        for name in os.listdir(entries_descriptor):
            if PENDING_NAME_PATTERN.fullmatch(
                name
            ) or RESERVATION_NAME_PATTERN.fullmatch(name):
                continue
            match = ENTRY_NAME_PATTERN.fullmatch(name)
            if match is None:
                raise CFastPnlLedgerRepositoryError("REPOSITORY_UNKNOWN_ENTRY_ARTIFACT")
            names.append((int(match["sequence"]), name))
        names.sort(key=lambda item: item[0])
        entries = tuple(
            self._read_entry_file(
                entries_descriptor,
                name,
                ENTRY_NAME_PATTERN,
            )
            for _, name in names
        )
        if entries:
            try:
                verify_four_layer_pnl_chain(
                    [entry.model_dump(mode="json") for entry in entries],
                    fee_binding_trust_context=(self.fee_binding_trust_context),
                )
            except CFastPnlLedgerError as exc:
                raise CFastPnlLedgerRepositoryError(
                    f"REPOSITORY_CHAIN_INVALID:{exc.code}"
                ) from exc
        return entries

    def _read_entry_file(
        self,
        entries_descriptor: int,
        name: str,
        name_pattern: re.Pattern[str],
    ) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
        match = name_pattern.fullmatch(name)
        if match is None:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ENTRY_FILENAME_INVALID")
        raw = _read_raw_regular_at(
            entries_descriptor,
            name,
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
            entry = reload_and_verify_four_layer_pnl_entry(
                payload,
                fee_binding_trust_context=(self.fee_binding_trust_context),
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_ENTRY_INVALID:{exc.code}"
            ) from exc
        if raw != _entry_bytes(entry):
            raise CFastPnlLedgerRepositoryError("REPOSITORY_ENTRY_NOT_CANONICAL")
        filename_hash = match.groupdict().get("entry_hash")
        if int(match["sequence"]) != entry.entry_sequence or (
            filename_hash is not None and filename_hash != entry.entry_hash
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

    def _write_create_only(
        self,
        entries_descriptor: int,
        name: str,
        raw: bytes,
    ) -> None:
        self._write_create_only_artifact(
            entries_descriptor,
            name,
            raw,
            conflict_code="REPOSITORY_PENDING_CONFLICT",
            create_code="REPOSITORY_PENDING_CREATE_FAILED",
            changed_code="REPOSITORY_PENDING_CHANGED_AFTER_WRITE",
        )

    def _write_reservation_create_only(
        self,
        entries_descriptor: int,
        name: str,
        raw: bytes,
    ) -> None:
        self._write_create_only_artifact(
            entries_descriptor,
            name,
            raw,
            conflict_code="REPOSITORY_SEQUENCE_RESERVATION_CONFLICT",
            create_code="REPOSITORY_SEQUENCE_RESERVATION_CREATE_FAILED",
            changed_code="REPOSITORY_SEQUENCE_RESERVATION_CHANGED_AFTER_WRITE",
        )

    def _write_create_only_artifact(
        self,
        entries_descriptor: int,
        name: str,
        raw: bytes,
        *,
        conflict_code: str,
        create_code: str,
        changed_code: str,
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=entries_descriptor,
            )
        except FileExistsError:
            existing = _read_raw_regular_at(
                entries_descriptor,
                name,
            )
            if existing != raw:
                raise CFastPnlLedgerRepositoryError(conflict_code)
            return
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(create_code) from exc
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        _fsync_descriptor(
            entries_descriptor,
            "REPOSITORY_DIRECTORY_FSYNC_FAILED",
        )
        if _read_raw_regular_at(entries_descriptor, name) != raw:
            raise CFastPnlLedgerRepositoryError(changed_code)

    def _promote_pending_create_only(
        self,
        entries_descriptor: int,
        pending_name: str,
        final_name: str,
        raw: bytes,
    ) -> None:
        try:
            os.link(
                pending_name,
                final_name,
                src_dir_fd=entries_descriptor,
                dst_dir_fd=entries_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            if (
                _read_raw_regular_at(
                    entries_descriptor,
                    final_name,
                )
                != raw
            ):
                raise CFastPnlLedgerRepositoryError("REPOSITORY_FINAL_CONFLICT")
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_FINAL_CREATE_FAILED"
            ) from exc
        _fsync_descriptor(
            entries_descriptor,
            "REPOSITORY_DIRECTORY_FSYNC_FAILED",
        )
        if _read_raw_regular_at(entries_descriptor, final_name) != raw:
            raise CFastPnlLedgerRepositoryError("REPOSITORY_FINAL_CHANGED_AFTER_CREATE")
        try:
            os.unlink(pending_name, dir_fd=entries_descriptor)
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(
                "REPOSITORY_PENDING_DELETE_FAILED"
            ) from exc
        _fsync_descriptor(
            entries_descriptor,
            "REPOSITORY_DIRECTORY_FSYNC_FAILED",
        )


def reload_and_verify_repository_export(
    payload_or_raw: Mapping[str, Any] | bytes,
    *,
    fee_binding_trust_context: FeeBindingTrustContext | None = None,
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
            [entry.model_dump(mode="json") for entry in reloaded.entries],
            fee_binding_trust_context=fee_binding_trust_context,
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
        fee_binding_trust_context=fee_binding_trust_context,
    )
    if expected != reloaded:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_FRESH_REPLAY_MISMATCH")
    return reloaded


def _build_repository_export(
    entries: tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...],
    ledger_id: str,
    *,
    fresh_audit: CommodityCFastPnlLedgerAuditDTO | None = None,
    fee_binding_trust_context: FeeBindingTrustContext | None = None,
) -> CommodityCFastPnlLedgerRepositoryExportDTO:
    if not entries:
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EMPTY")
    if any(entry.ledger_id != ledger_id for entry in entries):
        raise CFastPnlLedgerRepositoryError("REPOSITORY_EXPORT_LEDGER_ID_MISMATCH")
    if fresh_audit is None:
        try:
            fresh_audit = verify_four_layer_pnl_chain(
                [entry.model_dump(mode="json") for entry in entries],
                fee_binding_trust_context=fee_binding_trust_context,
            )
        except CFastPnlLedgerError as exc:
            raise CFastPnlLedgerRepositoryError(
                f"REPOSITORY_EXPORT_CHAIN_INVALID:{exc.code}"
            ) from exc
    core: dict[str, Any] = {
        "schema_version": ("commodity_c_fast_pnl_ledger_repository_export_v2"),
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
        "recovery_semantics": (
            "FSYNC_SEQUENCE_RESERVATION_THEN_PENDING_CREATE_ONLY_LINK_FRESH_REPLAY"
        ),
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


def _reservation_name(entry: CommodityCFastFourLayerPnlLedgerEntryDTO) -> str:
    return f".reservation-{entry.entry_sequence:010d}.json"


def _entry_bytes(entry: CommodityCFastFourLayerPnlLedgerEntryDTO) -> bytes:
    return canonical_json_line(entry.model_dump(mode="json"))


def _mkdir_create_only_or_existing(
    name: str,
    parent_descriptor: int,
    *,
    create_code: str,
) -> bool:
    try:
        os.mkdir(
            name,
            mode=0o700,
            dir_fd=parent_descriptor,
        )
    except FileExistsError:
        return False
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(create_code) from exc
    return True


@contextmanager
def _pinned_owned_directory(
    path: Path,
    *,
    relative_name: str | None = None,
    parent_descriptor: int | None = None,
    not_found_code: str,
    invalid_code: str,
    open_code: str,
    changed_code: str,
) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    target: str | Path = relative_name if relative_name is not None else path
    try:
        if parent_descriptor is None:
            descriptor = os.open(target, flags)
        else:
            descriptor = os.open(
                target,
                flags,
                dir_fd=parent_descriptor,
            )
    except FileNotFoundError as exc:
        raise CFastPnlLedgerRepositoryError(not_found_code) from exc
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(open_code) from exc
    try:
        before = os.fstat(descriptor)
        _validate_owned_directory_stat(before, invalid_code)
        try:
            current_path = path.lstat()
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(changed_code) from exc
        if _directory_identity(before) != _directory_identity(current_path):
            raise CFastPnlLedgerRepositoryError(changed_code)
        yield descriptor
        after = os.fstat(descriptor)
        _validate_owned_directory_stat(after, invalid_code)
        try:
            current_path = path.lstat()
        except OSError as exc:
            raise CFastPnlLedgerRepositoryError(changed_code) from exc
        if _directory_identity(before) != _directory_identity(
            after
        ) or _directory_identity(after) != _directory_identity(current_path):
            raise CFastPnlLedgerRepositoryError(changed_code)
    finally:
        os.close(descriptor)


def _validate_owned_directory_stat(
    value: os.stat_result,
    invalid_code: str,
) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise CFastPnlLedgerRepositoryError(invalid_code)


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
    )


def _fsync_descriptor(descriptor: int, code: str) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(code) from exc


def _assert_retained_directory_entry(
    *,
    parent_descriptor: int,
    relative_name: str,
    descriptor: int,
    invalid_code: str,
    changed_code: str,
) -> None:
    try:
        retained = os.fstat(descriptor)
        current = os.stat(
            relative_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _validate_owned_directory_stat(retained, invalid_code)
        _validate_owned_directory_stat(current, invalid_code)
    except CFastPnlLedgerRepositoryError:
        raise
    except OSError as exc:
        raise CFastPnlLedgerRepositoryError(changed_code) from exc
    if _directory_identity(retained) != _directory_identity(current):
        raise CFastPnlLedgerRepositoryError(changed_code)


def _read_raw_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    invalid_code: str = "REPOSITORY_ARTIFACT_NOT_REGULAR",
    read_code: str = "REPOSITORY_ARTIFACT_READ_FAILED",
    changed_code: str = "REPOSITORY_ARTIFACT_CHANGED_DURING_READ",
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(
            name,
            flags,
            dir_fd=parent_descriptor,
        )
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
            current_path = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
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
