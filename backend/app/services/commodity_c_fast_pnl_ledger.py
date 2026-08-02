from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError

from app.schemas.commodity_c_fast_pnl_ledger import (
    ActualSimNowCalibrationPnlLayerDTO,
    ActualSimNowFactsDTO,
    ActualSimNowFeeBoundArchiveReplayFactsDTO,
    ActualSimNowNotProvidedSourceFactsDTO,
    ActualSimNowPinnedArchiveReplayFactsDTO,
    ActualSimNowSettledArchiveReplayFactsDTO,
    CommodityCFastFourLayerPnlLedgerEntryDTO,
    CommodityCFastPnlLedgerAuditDTO,
    ExecutionQualityIntervalPnlLayerDTO,
    ExecutionQualityIntervalPnlSourceFactsDTO,
    FeeAdjustedPnlLayerDTO,
    FeeAdjustedPnlSourceFactsDTO,
    PnlLayerHashIndexDTO,
    PnlSourceFactsBaseDTO,
    PnlSourceLineageDTO,
    TheoreticalTargetPnlLayerDTO,
    TheoreticalTargetPnlSourceFactsDTO,
    canonical_utc_json,
    money_bounds,
    money_cent_sum,
    money_multiply,
    money_sum,
    replay_actual_simnow_session_archive,
    replay_settled_actual_simnow_session_archive,
    sha256_json,
)
from app.services.commodity_c_fast_fee_binding_trust import (
    FeeBindingTrustContext,
)


MAX_CHAIN_ENTRIES = 10_000
SourceFacts = TypeVar("SourceFacts", bound=PnlSourceFactsBaseDTO)

# Observation/event timestamps embedded in source facts. Validity boundaries
# such as statement expiry and key not-after are deliberately excluded: they
# may be later than the ledger entry without representing future observations.
_SOURCE_CUTOFF_FIELDS = frozenset(
    {
        "as_of_at_utc",
        "captured_at_utc",
        "completed_at_utc",
        "execution_captured_at_utc",
        "issued_at_utc",
        "previewed_at_utc",
        "received_at",
        "received_at_utc",
        "started_at_utc",
        "terminal_completed_at_utc",
        "trade_at_utc",
        "valuation_at_utc",
        "verified_at_utc",
    }
)

DERIVATION_RULES: dict[str, tuple[str, str]] = {
    "SIGNED_EXACT_TARGET_MARKS": (
        "cfast-theoretical-observed-virtual-fill-pnl-v2",
        sha256_json(
            {
                "formula": "realized+unrealized+roll",
                "position_basis": (
                    "observed_virtual_fill_never_assume_unfilled_target"
                ),
            }
        ),
    ),
    "FEE_AND_STRESS_ASSUMPTIONS": (
        "cfast-fee-adjusted-pnl-v3",
        sha256_json(
            {
                "formula": ("rate-times-turnover-plus-tick-and-roll-components"),
                "unbound": ("complete-frozen-component-universe-unknowns-null"),
            }
        ),
    ),
    "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS": (
        "cfast-execution-interval-pnl-v2",
        sha256_json(
            {
                "fill": "filled-lot-pnl-times-fill-bounds",
                "opportunity": ("unfilled-lot-cost-times-derived-unfilled-bounds"),
            }
        ),
    ),
    "ACTUAL_SIMNOW_FACTS_NOT_PROVIDED": (
        "cfast-actual-simnow-not-provided-v2",
        sha256_json({"formula": "no-facts-no-actual-pnl"}),
    ),
    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION": (
        "cfast-actual-simnow-terminal-binding-unverified-amounts-v3",
        sha256_json(
            {
                "terminal_checksum": ("session-plan-status-completed-execution-state"),
                "amounts": ("null-until-raw-fill-price-multiplier-fee-replay"),
            }
        ),
    ),
    "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND": (
        "cfast-actual-simnow-session-archive-replay-v4",
        sha256_json(
            {
                "gross": ("sum(direction*(mark-fill)*multiplier*filled-volume)"),
                "adverse_slippage": (
                    "sum(direction*(fill-decision)*multiplier*filled-volume)"
                ),
                "fees": "unbound-not-assumed-zero",
                "net": "null-until-authoritative-fees-bound",
                "settlement": ("full-fill-complete-terminal-only"),
            }
        ),
    ),
    "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND": (
        "cfast-actual-simnow-settled-session-archive-replay-v1",
        sha256_json(
            {
                "gross": ("sum(direction*(mark-fill)*multiplier*filled-volume)"),
                "adverse_slippage": (
                    "sum(direction*(fill-decision)*multiplier*filled-volume)"
                ),
                "fees": "unbound-not-assumed-zero",
                "net": "null-until-authoritative-fees-bound",
                "settlement": (
                    "stable-terminal-raw-facts-position-reconciliation-"
                    "no-active-order-or-unresolved-intent"
                ),
            }
        ),
    ),
    "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND": (
        "cfast-actual-simnow-session-archive-fee-statement-replay-v5",
        sha256_json(
            {
                "gross": ("sum(direction*(mark-fill)*multiplier*filled-volume)"),
                "fee": ("signed-schedule-exact-trade-join-volume-turnover-minimum"),
                "net": "gross-minus-official-minus-broker-customer-fees",
                "authority": "research-evidence-only-all-authority-false",
            }
        ),
    ),
}


class CFastPnlLedgerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


MAX_SIMNOW_ARCHIVE_BYTES = 32 * 1024 * 1024
_C_FAST_SESSION_ID = re.compile(r"cfast-shakedown-[0-9a-f]{32}")


def _read_pinned_simnow_archive(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read one regular archive file without following a leaf symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_READ_FAILED") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_NOT_REGULAR")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_MODE_INVALID")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SIMNOW_ARCHIVE_BYTES:
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_RESOURCE_LIMIT")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_SIMNOW_ARCHIVE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_SIMNOW_ARCHIVE_BYTES:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_RESOURCE_LIMIT")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_JSON_INVALID")
    return raw, payload


def _load_pinned_simnow_archive_chain(
    *,
    archive_dir: Path,
    session_id: str,
    expected_archive_raw_sha256: str,
    expected_terminal_checksum: str,
    expected_chain_tip_terminal_checksum: str,
) -> tuple[dict[str, Any], str, str | None]:
    """Bind a session file to independently supplied raw and chain-tip pins."""

    if not _C_FAST_SESSION_ID.fullmatch(session_id):
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_SESSION_ID_INVALID")
    if archive_dir.is_symlink() or not archive_dir.is_dir():
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_DIR_INVALID")
    directory_metadata = archive_dir.stat()
    if (
        directory_metadata.st_uid != os.getuid()
        or stat.S_IMODE(directory_metadata.st_mode) & 0o077
    ):
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_MODE_INVALID")
    path = archive_dir / f"{session_id}.json"
    if path.parent != archive_dir or path.is_symlink():
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_PATH_SESSION_MISMATCH")

    rows: list[tuple[dict[str, Any], str]] = []
    target: dict[str, Any] | None = None
    target_raw_sha256: str | None = None
    for candidate in sorted(archive_dir.glob("cfast-shakedown-*.json")):
        if candidate.is_symlink() or not _C_FAST_SESSION_ID.fullmatch(candidate.stem):
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CUSTODY_ENTRY_INVALID")
        raw, payload = _read_pinned_simnow_archive(candidate)
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        if payload.get("session_id") != candidate.stem:
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_PATH_SESSION_MISMATCH")
        execution = payload.get("execution")
        if not isinstance(execution, dict):
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
        execution_core = {
            key: value for key, value in execution.items() if key != "state_checksum"
        }
        execution_checksum = execution.get("state_checksum")
        terminal_checksum = payload.get("terminal_checksum")
        terminal_payload = {
            "session_id": payload.get("session_id"),
            "plan_hash": payload.get("plan_hash"),
            "status": payload.get("status"),
            "completed_at_utc": payload.get("completed_at_utc"),
            "execution_state_checksum": execution_checksum,
        }
        if execution_checksum != sha256_json(
            execution_core
        ) or terminal_checksum != sha256_json(terminal_payload):
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
        rows.append((payload, str(terminal_checksum)))
        if candidate == path:
            target = payload
            target_raw_sha256 = raw_sha256
    if target is None or target_raw_sha256 is None:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_SESSION_NOT_FOUND")
    if target_raw_sha256 != expected_archive_raw_sha256:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_RAW_PIN_MISMATCH")
    if target.get("terminal_checksum") != expected_terminal_checksum:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_TERMINAL_PIN_MISMATCH")

    by_previous: dict[str | None, list[tuple[dict[str, Any], str]]] = {}
    for payload, checksum in rows:
        previous = payload.get("previous_terminal_checksum")
        if previous is not None and not re.fullmatch(r"[0-9a-f]{64}", str(previous)):
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
        by_previous.setdefault(previous, []).append((payload, checksum))
    roots = by_previous.get(None, [])
    if len(roots) != 1:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
    ordered = [roots[0]]
    visited = {roots[0][1]}
    while True:
        children = by_previous.get(ordered[-1][1], [])
        if not children:
            break
        if len(children) != 1 or children[0][1] in visited:
            raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
        ordered.append(children[0])
        visited.add(children[0][1])
    if len(ordered) != len(rows):
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_INVALID")
    chain_tip = ordered[-1][1]
    if chain_tip != expected_chain_tip_terminal_checksum:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_CHAIN_TIP_PIN_MISMATCH")
    if target.get("terminal_checksum") != chain_tip:
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_SESSION_NOT_CHAIN_TIP")
    if not any(payload is target for payload, _ in ordered):
        raise CFastPnlLedgerError("ACTUAL_ARCHIVE_SESSION_OUTSIDE_CHAIN")
    return target, target_raw_sha256, target.get("previous_terminal_checksum")


def build_actual_simnow_archive_replay_source_facts(
    *,
    ledger_id: str,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    valuation_day: str,
    as_of_at_utc: str,
    archive_dir: str | Path,
    session_id: str,
    expected_archive_raw_sha256: str,
    expected_terminal_checksum: str,
    expected_chain_tip_terminal_checksum: str,
) -> ActualSimNowPinnedArchiveReplayFactsDTO:
    """Build unattested v4 facts from a locally pinned service archive chain.

    The expected digests bind this read to caller-selected local bytes and
    chain state.  They are integrity inputs, not an external fact authority.
    """

    try:
        archive, raw_sha256, previous_terminal_checksum = (
            _load_pinned_simnow_archive_chain(
                archive_dir=Path(archive_dir),
                session_id=session_id,
                expected_archive_raw_sha256=expected_archive_raw_sha256,
                expected_terminal_checksum=expected_terminal_checksum,
                expected_chain_tip_terminal_checksum=(
                    expected_chain_tip_terminal_checksum
                ),
            )
        )
        execution = archive["execution"]
        raw = execution["terminal_raw_facts"]
        pnl = execution["pnl"]
        reconciliation = execution["reconciliation"]
        submitted = execution["submitted"]
        marks = pnl["mark_evidence"]
        orders = raw["orders"]
        trades = raw["trades"]
        positions = raw["positions"]
        child_rows = [row for phase in ("close", "open") for row in submitted[phase]]
        expected_lots = sum(int(row["volume"]) for row in child_rows)
        filled_lots = sum(int(row["volume"]) for row in trades)
        if filled_lots == expected_lots:
            order_outcome = "FULL_FILL"
        elif filled_lots > 0:
            order_outcome = "PARTIAL_FILL"
        else:
            order_outcome = (
                "REJECTED"
                if any(
                    "reject" in str(row.get("status") or "").lower() for row in orders
                )
                else "UNFILLED_CANCELLED"
            )
        mark_times = [
            str(row["received_at_utc"])
            for row in marks.values()
            if isinstance(row, Mapping)
        ]
        valuation_at_utc = max(
            mark_times,
            key=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")),
        )

        def row_hash(rows: list[dict[str, Any]]) -> str:
            return sha256_json(sorted(sha256_json(row) for row in rows))

        source = {
            "schema_version": "commodity_c_fast_actual_simnow_facts_v4",
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "ledger_id": ledger_id,
            "snapshot_hash": snapshot_hash,
            "formula_target_binding_sha256": formula_target_binding_sha256,
            "plan_hash": archive["plan_hash"],
            "valuation_day": valuation_day,
            "as_of_at_utc": as_of_at_utc,
            "actual_state": "LOCAL_ARCHIVE_REPLAYED_UNATTESTED",
            "fact_source": (
                "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
            ),
            "execution_lane": "simnow_shakedown",
            "session_id": archive["session_id"],
            "account_sha256": raw["account_sha256"],
            "orders_sha256": row_hash(orders),
            "trades_sha256": row_hash(trades),
            "positions_sha256": row_hash(positions),
            "reconciliation_sha256": sha256_json(reconciliation),
            "execution_state_checksum": execution["state_checksum"],
            "execution_state_checksum_verification_state": (
                "FULL_EMBEDDED_SESSION_ARCHIVE_FRESH_REPLAY"
            ),
            "terminal_checksum": archive["terminal_checksum"],
            "terminal_status": archive["status"],
            "terminal_reconciliation_complete": (
                reconciliation.get("expected_positions")
                == reconciliation.get("observed_positions")
                and execution["terminal_guard"].get("state") == "VALID"
            ),
            "terminal_completed_at_utc": archive["completed_at_utc"],
            "valuation_at_utc": valuation_at_utc,
            "execution_captured_at_utc": pnl["captured_at_utc"],
            "expected_lots": expected_lots,
            "filled_lots": filled_lots,
            "order_outcome": order_outcome,
            "trade_evidence_state": "COMPLETE",
            "mark_source": "CURRENT_L1_MID",
            "fee_binding_state": "UNBOUND_NOT_ASSUMED_ZERO",
            "fee_source_state": "NOT_AVAILABLE_IN_SESSION_ARCHIVE",
            "session_archive_sha256": sha256_json(archive),
            "session_archive_raw_sha256": raw_sha256,
            "archive_chain_tip_terminal_checksum": (
                expected_chain_tip_terminal_checksum
            ),
            "archive_predecessor_terminal_checksum": (previous_terminal_checksum),
            "archive_custody_verification_state": (
                "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
            ),
            "external_fact_authority_state": ("NOT_PROVIDED_STRUCTURE_ONLY"),
            "session_archive": archive,
            "actual_amount_verification_state": (
                "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND"
            ),
            "countable_forward": False,
            "production_allowed": False,
        }
    except CFastPnlLedgerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise CFastPnlLedgerError("INVALID_ACTUAL_SESSION_ARCHIVE") from exc
    try:
        return ActualSimNowPinnedArchiveReplayFactsDTO.model_validate(source)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError("INVALID_ACTUAL_SESSION_ARCHIVE") from exc


def build_actual_simnow_settled_archive_replay_source_facts(
    *,
    ledger_id: str,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    valuation_day: str,
    as_of_at_utc: str,
    archive_dir: str | Path,
    session_id: str,
    expected_archive_raw_sha256: str,
    expected_terminal_checksum: str,
    expected_chain_tip_terminal_checksum: str,
) -> ActualSimNowSettledArchiveReplayFactsDTO:
    """Build exact terminal-reconciled facts for every settled outcome."""

    try:
        archive, raw_sha256, previous_terminal_checksum = (
            _load_pinned_simnow_archive_chain(
                archive_dir=Path(archive_dir),
                session_id=session_id,
                expected_archive_raw_sha256=expected_archive_raw_sha256,
                expected_terminal_checksum=expected_terminal_checksum,
                expected_chain_tip_terminal_checksum=(
                    expected_chain_tip_terminal_checksum
                ),
            )
        )
        return _build_settled_archive_source(
            ledger_id=ledger_id,
            snapshot_hash=snapshot_hash,
            formula_target_binding_sha256=formula_target_binding_sha256,
            valuation_day=valuation_day,
            as_of_at_utc=as_of_at_utc,
            archive=archive,
            raw_sha256=raw_sha256,
            previous_terminal_checksum=previous_terminal_checksum,
            chain_tip_terminal_checksum=(expected_chain_tip_terminal_checksum),
        )
    except CFastPnlLedgerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise CFastPnlLedgerError("INVALID_SETTLED_ACTUAL_SESSION_ARCHIVE") from exc


def settled_archive_replay_from_v4(
    archive_replay: ActualSimNowPinnedArchiveReplayFactsDTO,
) -> ActualSimNowSettledArchiveReplayFactsDTO:
    """Losslessly promote validated full-fill v4 facts to settled archive facts."""

    return _build_settled_archive_source(
        ledger_id=archive_replay.ledger_id,
        snapshot_hash=archive_replay.snapshot_hash,
        formula_target_binding_sha256=(archive_replay.formula_target_binding_sha256),
        valuation_day=archive_replay.valuation_day.isoformat(),
        as_of_at_utc=canonical_utc_json(archive_replay.as_of_at_utc),
        archive=archive_replay.session_archive,
        raw_sha256=archive_replay.session_archive_raw_sha256,
        previous_terminal_checksum=(
            archive_replay.archive_predecessor_terminal_checksum
        ),
        chain_tip_terminal_checksum=(
            archive_replay.archive_chain_tip_terminal_checksum
        ),
    )


def reattest_settled_archive_replay(
    archive_replay: ActualSimNowSettledArchiveReplayFactsDTO,
    *,
    as_of_at_utc: str,
) -> ActualSimNowSettledArchiveReplayFactsDTO:
    """Move only the replay wrapper's observation cutoff forward.

    The embedded immutable archive, its raw/hash identities and every terminal
    fact remain byte-for-byte represented by the already validated DTO.
    """

    try:
        reattested_at = datetime.fromisoformat(
            as_of_at_utc.replace("Z", "+00:00")
        )
        canonical = canonical_utc_json(reattested_at)
        if reattested_at < archive_replay.as_of_at_utc:
            raise ValueError("settled replay as-of cannot move backwards")
        payload = archive_replay.model_dump(mode="json")
        payload["as_of_at_utc"] = canonical
        return ActualSimNowSettledArchiveReplayFactsDTO.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError(
            "INVALID_SETTLED_ACTUAL_REATTESTATION"
        ) from exc


def _build_settled_archive_source(
    *,
    ledger_id: str,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    valuation_day: str,
    as_of_at_utc: str,
    archive: Mapping[str, Any],
    raw_sha256: str,
    previous_terminal_checksum: str | None,
    chain_tip_terminal_checksum: str,
) -> ActualSimNowSettledArchiveReplayFactsDTO:
    try:
        execution = archive["execution"]
        raw = execution["terminal_raw_facts"]
        pnl = execution["pnl"]
        reconciliation = execution["reconciliation"]
        submitted = execution["submitted"]
        marks = pnl["mark_evidence"]
        orders = raw["orders"]
        trades = raw["trades"]
        positions = raw["positions"]
        child_rows = [row for phase in ("close", "open") for row in submitted[phase]]
        expected_lots = sum(int(row["volume"]) for row in child_rows)
        filled_lots = sum(int(row["volume"]) for row in trades)
        statuses = {
            str(row.get("status") or "").strip().lower().replace("-", "_")
            for row in orders
        }
        derived_full = filled_lots == expected_lots and statuses <= {
            "all_traded",
            "alltraded",
            "filled",
            "全部成交",
        }
        settlement = execution.get("settlement")
        if settlement is None:
            if not derived_full or archive.get("status") != "COMPLETE":
                raise ValueError(
                    "non-full settled archive requires terminal settlement"
                )
            outcome = "FULL_FILL"
            unknown_state = "NOT_APPLICABLE"
        else:
            expected_settlement_keys = {
                "schema_version",
                "state",
                "basis",
                "terminal_status",
                "order_outcome",
                "unknown_outcome_settlement_state",
                "expected_volume",
                "filled_volume",
                "actual_trade_count",
                "pre_trade_positions",
            }
            if (
                not isinstance(settlement, Mapping)
                or set(settlement) != expected_settlement_keys
                or settlement.get("schema_version")
                != "commodity_c_fast_terminal_settlement_v1"
                or settlement.get("state") != "SETTLED_COMPLETE"
                or settlement.get("basis")
                != (
                    "STABLE_TERMINAL_RAW_FACTS_POSITION_RECONCILIATION_"
                    "NO_ACTIVE_ORDER_OR_UNRESOLVED_INTENT"
                )
                or settlement.get("terminal_status") != archive.get("status")
                or settlement.get("expected_volume") != expected_lots
                or settlement.get("filled_volume") != filled_lots
                or settlement.get("actual_trade_count") != len(trades)
            ):
                raise ValueError("terminal settlement evidence is invalid")
            outcome = str(settlement.get("order_outcome") or "")
            unknown_state = str(
                settlement.get("unknown_outcome_settlement_state") or ""
            )
        mark_times = [
            str(row["received_at_utc"])
            for row in marks.values()
            if isinstance(row, Mapping)
        ]
        if filled_lots:
            valuation_at_utc = max(
                mark_times,
                key=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")),
            )
            mark_source = "CURRENT_L1_MID"
        else:
            if mark_times:
                raise ValueError("zero-fill settlement must not use marks")
            valuation_at_utc = pnl["captured_at_utc"]
            mark_source = "NOT_REQUIRED_ZERO_FILL"

        def row_hash(rows: list[dict[str, Any]]) -> str:
            return sha256_json(sorted(sha256_json(row) for row in rows))

        source = {
            "schema_version": (
                "commodity_c_fast_actual_simnow_settled_archive_facts_v1"
            ),
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "ledger_id": ledger_id,
            "snapshot_hash": snapshot_hash,
            "formula_target_binding_sha256": formula_target_binding_sha256,
            "plan_hash": archive["plan_hash"],
            "valuation_day": valuation_day,
            "as_of_at_utc": as_of_at_utc,
            "actual_state": "LOCAL_SETTLED_ARCHIVE_REPLAYED",
            "fact_source": (
                "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
            ),
            "execution_lane": "simnow_shakedown",
            "session_id": archive["session_id"],
            "account_sha256": raw["account_sha256"],
            "orders_sha256": row_hash(orders),
            "trades_sha256": row_hash(trades),
            "positions_sha256": row_hash(positions),
            "reconciliation_sha256": sha256_json(reconciliation),
            "execution_state_checksum": execution["state_checksum"],
            "terminal_checksum": archive["terminal_checksum"],
            "terminal_status": archive["status"],
            "terminal_reconciliation_complete": (
                reconciliation.get("expected_positions")
                == reconciliation.get("observed_positions")
                and execution["terminal_guard"].get("state") == "VALID"
            ),
            "terminal_completed_at_utc": archive["completed_at_utc"],
            "valuation_at_utc": valuation_at_utc,
            "execution_captured_at_utc": pnl["captured_at_utc"],
            "expected_lots": expected_lots,
            "filled_lots": filled_lots,
            "order_outcome": outcome,
            "unknown_outcome_settlement_state": unknown_state,
            "mark_source": mark_source,
            "session_archive_sha256": sha256_json(archive),
            "session_archive_raw_sha256": raw_sha256,
            "archive_chain_tip_terminal_checksum": (chain_tip_terminal_checksum),
            "archive_predecessor_terminal_checksum": (previous_terminal_checksum),
            "archive_custody_verification_state": (
                "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
            ),
            "external_fact_authority_state": ("NOT_PROVIDED_STRUCTURE_ONLY"),
            "session_archive": archive,
            "actual_amount_verification_state": (
                "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND"
            ),
            "countable_forward": False,
            "production_allowed": False,
        }
        return ActualSimNowSettledArchiveReplayFactsDTO.model_validate(source)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError("INVALID_SETTLED_ACTUAL_SESSION_ARCHIVE") from exc


def build_actual_simnow_fee_bound_source_facts(
    *,
    archive_replay: ActualSimNowSettledArchiveReplayFactsDTO,
    fee_binding: Mapping[str, Any],
    fee_binding_trust_context: FeeBindingTrustContext,
) -> ActualSimNowFeeBoundArchiveReplayFactsDTO:
    """Bind a verified, separately signed fee statement to v4 replay facts."""

    source = {
        "schema_version": "commodity_c_fast_actual_simnow_facts_v5",
        "candidate_id": archive_replay.candidate_id,
        "ledger_id": archive_replay.ledger_id,
        "snapshot_hash": archive_replay.snapshot_hash,
        "formula_target_binding_sha256": (archive_replay.formula_target_binding_sha256),
        "plan_hash": archive_replay.plan_hash,
        "valuation_day": archive_replay.valuation_day,
        "as_of_at_utc": archive_replay.as_of_at_utc,
        "actual_state": "LOCAL_ARCHIVE_REPLAYED_FEE_BOUND",
        "fact_source": (
            "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND"
        ),
        "execution_lane": "simnow_shakedown",
        "session_id": archive_replay.session_id,
        "account_sha256": archive_replay.account_sha256,
        "archive_replay": archive_replay.model_dump(mode="json"),
        "fee_binding": fee_binding,
        "actual_amount_verification_state": (
            "GROSS_SLIPPAGE_FEES_AND_NET_REPLAYED_FROM_EXACT_BOUND_SOURCES"
        ),
        "archive_fact_authority_state": (
            "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
        ),
        "fee_fact_authority_state": ("SIGNED_FEE_STATEMENT_VERIFIED_SEPARATE_DOMAIN"),
        "countable_forward": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "production_allowed": False,
    }
    try:
        bound = ActualSimNowFeeBoundArchiveReplayFactsDTO.model_validate(source)
        fee_binding_trust_context.assert_matches(bound.fee_binding)
        return bound
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError("INVALID_FEE_BOUND_ACTUAL_SOURCE_FACTS") from exc


def build_four_layer_pnl_entry(
    *,
    ledger_id: str,
    entry_sequence: int,
    previous_entry_hash: str | None,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    plan_hash: str,
    valuation_day: str,
    created_at_utc: str,
    theoretical_target_pnl: Mapping[str, Any],
    fee_adjusted_pnl: Mapping[str, Any],
    execution_quality_interval_pnl: Mapping[str, Any],
    actual_simnow_calibration_pnl: Mapping[str, Any],
    fee_binding_trust_context: FeeBindingTrustContext | None = None,
    economic_counting_state: str = "PRIMARY",
    supersedes_entry_hash: str | None = None,
) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
    """Freshly derive all four layers from strict embedded source facts."""

    raw_inputs: tuple[Any, ...] = (
        ledger_id,
        entry_sequence,
        previous_entry_hash,
        snapshot_hash,
        formula_target_binding_sha256,
        plan_hash,
        valuation_day,
        created_at_utc,
        theoretical_target_pnl,
        fee_adjusted_pnl,
        execution_quality_interval_pnl,
        actual_simnow_calibration_pnl,
        economic_counting_state,
        supersedes_entry_hash,
    )
    _reject_decimal_raw_input(raw_inputs)
    try:
        created_at_utc = canonical_utc_json(
            datetime.fromisoformat(created_at_utc.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise CFastPnlLedgerError("INVALID_CREATED_AT_UTC") from exc
    theoretical_facts = _load_source_facts(
        TheoreticalTargetPnlSourceFactsDTO,
        theoretical_target_pnl,
        "INVALID_THEORETICAL_SOURCE_FACTS",
    )
    fee_facts = _load_source_facts(
        FeeAdjustedPnlSourceFactsDTO,
        fee_adjusted_pnl,
        "INVALID_FEE_SOURCE_FACTS",
    )
    execution_facts = _load_source_facts(
        ExecutionQualityIntervalPnlSourceFactsDTO,
        execution_quality_interval_pnl,
        "INVALID_EXECUTION_SOURCE_FACTS",
    )
    actual_state = actual_simnow_calibration_pnl.get("actual_state")
    actual_facts: PnlSourceFactsBaseDTO
    if actual_state == "NOT_PROVIDED":
        actual_facts = _load_source_facts(
            ActualSimNowNotProvidedSourceFactsDTO,
            actual_simnow_calibration_pnl,
            "INVALID_ACTUAL_SOURCE_FACTS",
        )
    elif actual_simnow_calibration_pnl.get("schema_version") == (
        "commodity_c_fast_actual_simnow_facts_v4"
    ):
        actual_facts = _load_source_facts(
            ActualSimNowPinnedArchiveReplayFactsDTO,
            actual_simnow_calibration_pnl,
            "INVALID_ACTUAL_SOURCE_FACTS",
        )
    elif actual_simnow_calibration_pnl.get("schema_version") == (
        "commodity_c_fast_actual_simnow_settled_archive_facts_v1"
    ):
        actual_facts = _load_source_facts(
            ActualSimNowSettledArchiveReplayFactsDTO,
            actual_simnow_calibration_pnl,
            "INVALID_ACTUAL_SOURCE_FACTS",
        )
    elif actual_simnow_calibration_pnl.get("schema_version") == (
        "commodity_c_fast_actual_simnow_facts_v5"
    ):
        actual_facts = _load_source_facts(
            ActualSimNowFeeBoundArchiveReplayFactsDTO,
            actual_simnow_calibration_pnl,
            "INVALID_ACTUAL_SOURCE_FACTS",
        )
    else:
        actual_facts = _load_source_facts(
            ActualSimNowFactsDTO,
            actual_simnow_calibration_pnl,
            "INVALID_ACTUAL_SOURCE_FACTS",
        )
    sources = (
        theoretical_facts,
        fee_facts,
        execution_facts,
        actual_facts,
    )
    _require_fee_binding_trust_context(
        actual_facts,
        fee_binding_trust_context,
    )
    _verify_source_identity(
        sources,
        ledger_id=ledger_id,
        snapshot_hash=snapshot_hash,
        formula_target_binding_sha256=(formula_target_binding_sha256),
        plan_hash=plan_hash,
        valuation_day=valuation_day,
    )
    _verify_created_at_covers_source_cutoffs(
        created_at_utc=created_at_utc,
        sources=sources,
    )

    theoretical = _build_theoretical_layer(theoretical_facts)
    fee_adjusted = _build_fee_layer(
        fee_facts,
        theoretical=theoretical,
    )
    execution_interval = _build_execution_layer(execution_facts)
    actual = _build_actual_layer(actual_facts)
    layer_hashes = PnlLayerHashIndexDTO(
        theoretical_target_pnl_sha256=theoretical.layer_hash,
        fee_adjusted_pnl_sha256=fee_adjusted.layer_hash,
        execution_quality_interval_pnl_sha256=(execution_interval.layer_hash),
        actual_simnow_calibration_pnl_sha256=actual.layer_hash,
    )
    entry_identity = {
        "ledger_id": ledger_id,
        "entry_sequence": entry_sequence,
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (formula_target_binding_sha256),
        "plan_hash": plan_hash,
        "valuation_day": valuation_day,
        "layer_hashes": layer_hashes.model_dump(mode="json"),
    }
    core: dict[str, Any] = {
        "schema_version": "commodity_c_fast_four_layer_pnl_ledger_v2",
        "ledger_id": ledger_id,
        "entry_id": (f"cfast-pnl-entry-v2-{sha256_json(entry_identity)}"),
        "entry_sequence": entry_sequence,
        "previous_entry_hash": previous_entry_hash,
        "economic_counting_state": economic_counting_state,
        "supersedes_entry_hash": supersedes_entry_hash,
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (formula_target_binding_sha256),
        "plan_hash": plan_hash,
        "valuation_day": valuation_day,
        "created_at_utc": created_at_utc,
        "virtual_nav_cny": 20_000_000,
        "theoretical_target_pnl": theoretical.model_dump(mode="json"),
        "fee_adjusted_pnl": fee_adjusted.model_dump(mode="json"),
        "execution_quality_interval_pnl": (execution_interval.model_dump(mode="json")),
        "actual_simnow_calibration_pnl": actual.model_dump(mode="json"),
        "layer_hashes": layer_hashes.model_dump(mode="json"),
        "layer_isolation": ("FOUR_LAYERS_APPEND_ONLY_NEVER_OVERWRITE_OR_COALESCE"),
        "audit_scope": ("DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY"),
        "countable_forward": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    try:
        return CommodityCFastFourLayerPnlLedgerEntryDTO.model_validate(
            {**core, "entry_hash": sha256_json(core)}
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError("INVALID_LEDGER_ENTRY") from exc


def reload_and_verify_four_layer_pnl_entry(
    payload: Mapping[str, Any],
    *,
    fee_binding_trust_context: FeeBindingTrustContext | None = None,
) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
    """Validate checksums, then freshly replay every embedded source fact."""

    _reject_decimal_raw_input(payload)
    try:
        reloaded = CommodityCFastFourLayerPnlLedgerEntryDTO.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError("LEDGER_ENTRY_VERIFICATION_FAILED") from exc
    expected = build_four_layer_pnl_entry(
        ledger_id=reloaded.ledger_id,
        entry_sequence=reloaded.entry_sequence,
        previous_entry_hash=reloaded.previous_entry_hash,
        snapshot_hash=reloaded.snapshot_hash,
        formula_target_binding_sha256=(reloaded.formula_target_binding_sha256),
        plan_hash=reloaded.plan_hash,
        valuation_day=reloaded.valuation_day.isoformat(),
        created_at_utc=reloaded.created_at_utc.isoformat(),
        theoretical_target_pnl=(
            reloaded.theoretical_target_pnl.source_facts.model_dump(mode="json")
        ),
        fee_adjusted_pnl=(
            reloaded.fee_adjusted_pnl.source_facts.model_dump(mode="json")
        ),
        execution_quality_interval_pnl=(
            reloaded.execution_quality_interval_pnl.source_facts.model_dump(mode="json")
        ),
        actual_simnow_calibration_pnl=(
            reloaded.actual_simnow_calibration_pnl.source_facts.model_dump(mode="json")
        ),
        fee_binding_trust_context=fee_binding_trust_context,
        economic_counting_state=reloaded.economic_counting_state,
        supersedes_entry_hash=reloaded.supersedes_entry_hash,
    )
    if expected.model_dump(mode="json") != reloaded.model_dump(mode="json"):
        raise CFastPnlLedgerError("LEDGER_ENTRY_FRESH_REPLAY_MISMATCH")
    return reloaded


def verify_four_layer_pnl_chain(
    payloads: Sequence[Mapping[str, Any]],
    *,
    fee_binding_trust_context: FeeBindingTrustContext | None = None,
) -> CommodityCFastPnlLedgerAuditDTO:
    if not payloads:
        raise CFastPnlLedgerError("EMPTY_LEDGER_CHAIN")
    if len(payloads) > MAX_CHAIN_ENTRIES:
        raise CFastPnlLedgerError("LEDGER_CHAIN_RESOURCE_LIMIT")
    entries = tuple(
        reload_and_verify_four_layer_pnl_entry(
            payload,
            fee_binding_trust_context=fee_binding_trust_context,
        )
        for payload in payloads
    )
    ledger_id = entries[0].ledger_id
    entry_hashes = [entry.entry_hash for entry in entries]
    entry_ids = [entry.entry_id for entry in entries]
    if len(set(entry_hashes)) != len(entry_hashes) or len(set(entry_ids)) != len(
        entry_ids
    ):
        raise CFastPnlLedgerError("LEDGER_DUPLICATE_ENTRY")
    if any(entry.ledger_id != ledger_id for entry in entries):
        raise CFastPnlLedgerError("LEDGER_ID_MIXED")
    if [entry.entry_sequence for entry in entries] != list(range(1, len(entries) + 1)):
        raise CFastPnlLedgerError("LEDGER_SEQUENCE_INVALID")
    entries_by_hash = {entry.entry_hash: entry for entry in entries}
    correction_targets: set[str] = set()
    for entry in entries:
        if entry.economic_counting_state != ("NON_COUNTING_FEE_BINDING_CORRECTION"):
            continue
        target_hash = entry.supersedes_entry_hash
        target = entries_by_hash.get(target_hash or "")
        current_actual = entry.actual_simnow_calibration_pnl.source_facts
        target_actual = (
            target.actual_simnow_calibration_pnl.source_facts
            if target is not None
            else None
        )
        if (
            target is None
            or target.entry_sequence >= entry.entry_sequence
            or target.economic_counting_state != "PRIMARY"
            or target_hash in correction_targets
            or not isinstance(
                target_actual,
                ActualSimNowSettledArchiveReplayFactsDTO,
            )
            or not isinstance(
                current_actual,
                ActualSimNowFeeBoundArchiveReplayFactsDTO,
            )
            or not _same_immutable_settled_archive(
                current_actual.archive_replay,
                target_actual,
            )
            or current_actual.archive_replay.as_of_at_utc
            < target_actual.as_of_at_utc
        ):
            raise CFastPnlLedgerError("LEDGER_FEE_CORRECTION_LINK_INVALID")
        if (
            entry.ledger_id,
            entry.snapshot_hash,
            entry.formula_target_binding_sha256,
            entry.plan_hash,
            entry.valuation_day,
            entry.theoretical_target_pnl,
            entry.fee_adjusted_pnl,
            entry.execution_quality_interval_pnl,
        ) != (
            target.ledger_id,
            target.snapshot_hash,
            target.formula_target_binding_sha256,
            target.plan_hash,
            target.valuation_day,
            target.theoretical_target_pnl,
            target.fee_adjusted_pnl,
            target.execution_quality_interval_pnl,
        ):
            raise CFastPnlLedgerError("LEDGER_FEE_CORRECTION_SCOPE_MISMATCH")
        correction_targets.add(target_hash)
    source_sets = [_source_fact_set_hash(entry) for entry in entries]
    if len(set(source_sets)) != len(source_sets):
        raise CFastPnlLedgerError("LEDGER_SOURCE_FACT_REPLAY")
    actual_identity_entries: dict[
        str,
        list[CommodityCFastFourLayerPnlLedgerEntryDTO],
    ] = {}
    for entry in entries:
        identity = (
            entry.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
        )
        if identity is not None:
            actual_identity_entries.setdefault(identity, []).append(entry)
    for matches in actual_identity_entries.values():
        if len(matches) == 1:
            if matches[0].economic_counting_state != "PRIMARY":
                raise CFastPnlLedgerError("LEDGER_FEE_CORRECTION_LINK_INVALID")
            continue
        if (
            len(matches) != 2
            or matches[0].economic_counting_state != "PRIMARY"
            or matches[1].economic_counting_state
            != "NON_COUNTING_FEE_BINDING_CORRECTION"
            or matches[1].supersedes_entry_hash != matches[0].entry_hash
        ):
            raise CFastPnlLedgerError(
                "LEDGER_ACTUAL_TERMINAL_REPLAY_OR_DIGEST_CONFLICT"
            )
    for predecessor, current in zip(entries, entries[1:]):
        if current.previous_entry_hash != predecessor.entry_hash:
            raise CFastPnlLedgerError("LEDGER_PREDECESSOR_MISMATCH")
        if current.created_at_utc <= predecessor.created_at_utc:
            raise CFastPnlLedgerError("LEDGER_CREATED_AT_NOT_INCREASING")
    previous_primary: CommodityCFastFourLayerPnlLedgerEntryDTO | None = None
    for current in entries:
        if current.economic_counting_state != "PRIMARY":
            continue
        if (
            previous_primary is not None
            and current.valuation_day < previous_primary.valuation_day
        ):
            raise CFastPnlLedgerError("LEDGER_VALUATION_DAY_REGRESSION")
        if previous_primary is not None:
            previous_cutoffs = _source_cutoffs(previous_primary)
            current_cutoffs = _source_cutoffs(current)
            if any(
                current_cutoffs[key] < previous_cutoffs[key] for key in previous_cutoffs
            ):
                raise CFastPnlLedgerError("LEDGER_SOURCE_AS_OF_REGRESSION")
        previous_primary = current
    return CommodityCFastPnlLedgerAuditDTO(
        schema_version="commodity_c_fast_pnl_ledger_audit_v3",
        ledger_id=ledger_id,
        entry_count=len(entries),
        genesis_entry_hash=entries[0].entry_hash,
        chain_tip_entry_hash=entries[-1].entry_hash,
        ordered_entry_hashes_sha256=sha256_json(entry_hashes),
        audit_state=("PASS_FRESH_REPLAY_STRUCTURE_AND_HASH_CHAIN_ONLY"),
        actual_fact_entry_count=sum(
            entry.actual_simnow_calibration_pnl.actual_state == "FACTS_BOUND"
            for entry in entries
        ),
        actual_gross_replayed_entry_count=sum(
            entry.economic_counting_state == "PRIMARY"
            and entry.actual_simnow_calibration_pnl.actual_amount_verification_state
            in {
                "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND",
                ("GROSS_SLIPPAGE_FEES_AND_NET_REPLAYED_FROM_EXACT_BOUND_SOURCES"),
            }
            for entry in entries
        ),
        actual_net_fee_bound_entry_count=sum(
            entry.actual_simnow_calibration_pnl.fees_state == "BOUND"
            and entry.actual_simnow_calibration_pnl.actual_net_pnl_cny is not None
            for entry in entries
        ),
        external_genesis_anchor_state="NOT_PROVIDED_STRUCTURE_ONLY",
        external_tip_anchor_state="NOT_PROVIDED_STRUCTURE_ONLY",
        countable_forward=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def _same_immutable_settled_archive(
    left: ActualSimNowSettledArchiveReplayFactsDTO,
    right: ActualSimNowSettledArchiveReplayFactsDTO,
) -> bool:
    """Compare a correction to its primary, excluding only wrapper as-of."""

    return left.model_dump(
        mode="json",
        exclude={"as_of_at_utc"},
    ) == right.model_dump(
        mode="json",
        exclude={"as_of_at_utc"},
    )


def _build_lineage(
    facts: PnlSourceFactsBaseDTO,
    source_kind: str,
) -> PnlSourceLineageDTO:
    source_hash = sha256_json(facts.model_dump(mode="json"))
    derivation_rule_id, derivation_code_sha256 = DERIVATION_RULES[source_kind]
    core = {
        "schema_version": "commodity_c_fast_pnl_source_lineage_v2",
        "source_kind": source_kind,
        "source_artifact_id": f"cfast-source-v2-{source_hash}",
        "source_artifact_sha256": source_hash,
        "source_payload_sha256": source_hash,
        "derivation_rule_id": derivation_rule_id,
        "derivation_code_sha256": derivation_code_sha256,
        "input_cutoff_at_utc": canonical_utc_json(facts.as_of_at_utc),
    }
    return PnlSourceLineageDTO.model_validate(
        {**core, "lineage_hash": sha256_json(core)}
    )


def _build_theoretical_layer(
    facts: TheoreticalTargetPnlSourceFactsDTO,
) -> TheoreticalTargetPnlLayerDTO:
    core = {
        "schema_version": ("commodity_c_fast_theoretical_target_pnl_layer_v2"),
        "layer_kind": "THEORETICAL_TARGET_PNL",
        "snapshot_hash": facts.snapshot_hash,
        "source_facts": facts.model_dump(mode="json"),
        "lineage": _build_lineage(
            facts,
            "SIGNED_EXACT_TARGET_MARKS",
        ).model_dump(mode="json"),
        "valuation_day": facts.valuation_day.isoformat(),
        "position_basis": ("OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"),
        "held_lots": facts.held_lots,
        "pending_virtual_lots": facts.pending_virtual_lots,
        "realized_pnl_cny": facts.realized_pnl_cny,
        "unrealized_pnl_cny": facts.unrealized_pnl_cny,
        "roll_pnl_cny": facts.roll_pnl_cny,
        "total_pnl_cny": money_sum(
            facts.realized_pnl_cny,
            facts.unrealized_pnl_cny,
            facts.roll_pnl_cny,
        ),
    }
    return TheoreticalTargetPnlLayerDTO.model_validate(
        {**core, "layer_hash": sha256_json(core)}
    )


def _build_fee_layer(
    facts: FeeAdjustedPnlSourceFactsDTO,
    *,
    theoretical: TheoreticalTargetPnlLayerDTO,
) -> FeeAdjustedPnlLayerDTO:
    official_fee = (
        None
        if facts.official_exchange_fee_rate is None
        else money_multiply(
            facts.official_exchange_fee_rate,
            float(facts.official_exchange_turnover_cny),
        )
    )
    broker_fee = (
        None
        if facts.broker_customer_fee_rate is None
        else money_multiply(
            facts.broker_customer_fee_rate,
            float(facts.broker_customer_turnover_cny),
        )
    )
    component_costs = (
        official_fee,
        broker_fee,
        facts.preregistered_tick_stress_cny,
        facts.roll_round_trip_cost_cny,
    )
    all_in: float | None = None
    adjusted: float | None = None
    if facts.fee_binding_state == "BOUND":
        all_in = money_sum(
            *(float(value) for value in component_costs if value is not None)
        )
        adjusted = money_sum(theoretical.total_pnl_cny, -all_in)
    core = {
        "schema_version": "commodity_c_fast_fee_adjusted_pnl_layer_v2",
        "layer_kind": "FEE_ADJUSTED_PNL",
        "snapshot_hash": facts.snapshot_hash,
        "source_facts": facts.model_dump(mode="json"),
        "lineage": _build_lineage(
            facts,
            "FEE_AND_STRESS_ASSUMPTIONS",
        ).model_dump(mode="json"),
        "source_theoretical_layer_hash": theoretical.layer_hash,
        "source_theoretical_total_pnl_cny": theoretical.total_pnl_cny,
        "fee_binding_state": facts.fee_binding_state,
        "official_exchange_fee_cny": official_fee,
        "broker_customer_fee_cny": broker_fee,
        "preregistered_tick_stress_cny": (facts.preregistered_tick_stress_cny),
        "roll_round_trip_cost_cny": facts.roll_round_trip_cost_cny,
        "all_in_cost_cny": all_in,
        "fee_adjusted_total_pnl_cny": adjusted,
    }
    return FeeAdjustedPnlLayerDTO.model_validate(
        {**core, "layer_hash": sha256_json(core)}
    )


def _build_execution_layer(
    facts: ExecutionQualityIntervalPnlSourceFactsDTO,
) -> ExecutionQualityIntervalPnlLayerDTO:
    unfilled_lower = facts.planned_lots - facts.filled_lots_upper
    unfilled_upper = facts.planned_lots - facts.filled_lots_lower
    pnl_lower, pnl_upper = money_bounds(
        facts.filled_lot_pnl_cny,
        facts.filled_lots_lower,
        facts.filled_lots_upper,
    )
    opportunity_lower, opportunity_upper = money_bounds(
        facts.unfilled_lot_opportunity_cost_cny,
        unfilled_lower,
        unfilled_upper,
    )
    core = {
        "schema_version": ("commodity_c_fast_execution_quality_interval_pnl_layer_v2"),
        "layer_kind": "EXECUTION_QUALITY_INTERVAL_PNL",
        "snapshot_hash": facts.snapshot_hash,
        "source_facts": facts.model_dump(mode="json"),
        "lineage": _build_lineage(
            facts,
            "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
        ).model_dump(mode="json"),
        "fill_evidence_state": facts.fill_evidence_state,
        "point_fill_probability_state": ("FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY"),
        "planned_lots": facts.planned_lots,
        "filled_lots_lower": facts.filled_lots_lower,
        "filled_lots_upper": facts.filled_lots_upper,
        "unfilled_lots_lower": unfilled_lower,
        "unfilled_lots_upper": unfilled_upper,
        "marketable_book_walk_pnl_cny": (facts.marketable_book_walk_pnl_cny),
        "conservative_fill_lower_bound_pnl_cny": pnl_lower,
        "optimistic_fill_upper_bound_pnl_cny": pnl_upper,
        "opportunity_cost_lower_bound_cny": opportunity_lower,
        "opportunity_cost_upper_bound_cny": opportunity_upper,
    }
    return ExecutionQualityIntervalPnlLayerDTO.model_validate(
        {**core, "layer_hash": sha256_json(core)}
    )


def _build_actual_layer(
    facts: PnlSourceFactsBaseDTO,
) -> ActualSimNowCalibrationPnlLayerDTO:
    if isinstance(facts, ActualSimNowNotProvidedSourceFactsDTO):
        source_kind = "ACTUAL_SIMNOW_FACTS_NOT_PROVIDED"
        actual_state = "NOT_PROVIDED"
        stable_actual_fact_identity = None
        amount_verification_state = "NOT_PROVIDED"
        gross = None
        slippage = None
        fees_state = "NOT_AVAILABLE"
        fees = None
        net_state = "NOT_AVAILABLE"
        net = None
    elif isinstance(facts, ActualSimNowFactsDTO):
        source_kind = "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"
        actual_state = "FACTS_BOUND"
        stable_actual_fact_identity = _stable_actual_fact_identity(facts)
        amount_verification_state = facts.actual_amount_verification_state
        gross = None
        slippage = None
        fees_state = "UNVERIFIED"
        fees = None
        net_state = "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
        net = None
    elif isinstance(facts, ActualSimNowPinnedArchiveReplayFactsDTO):
        source_kind = "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
        actual_state = "LOCAL_ARCHIVE_REPLAYED_UNATTESTED"
        stable_actual_fact_identity = _stable_actual_fact_identity(facts)
        amount_verification_state = facts.actual_amount_verification_state
        replay = replay_actual_simnow_session_archive(facts)
        gross, slippage = replay[15:17]
        fees_state = "UNBOUND_NOT_ASSUMED_ZERO"
        fees = None
        net_state = "UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND"
        net = None
        official = None
        broker = None
        all_in = None
    elif isinstance(facts, ActualSimNowSettledArchiveReplayFactsDTO):
        source_kind = (
            "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
        )
        actual_state = "LOCAL_SETTLED_ARCHIVE_REPLAYED_FEES_UNBOUND"
        stable_actual_fact_identity = _stable_actual_fact_identity(facts)
        amount_verification_state = facts.actual_amount_verification_state
        replay = replay_settled_actual_simnow_session_archive(facts)
        gross, slippage = replay[15:17]
        fees_state = "UNBOUND_NOT_ASSUMED_ZERO"
        fees = None
        net_state = "UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND"
        net = None
        official = None
        broker = None
        all_in = None
    elif isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO):
        source_kind = "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND"
        actual_state = "LOCAL_ARCHIVE_REPLAYED_FEE_BOUND"
        stable_actual_fact_identity = _stable_actual_fact_identity(facts)
        amount_verification_state = facts.actual_amount_verification_state
        replay = replay_settled_actual_simnow_session_archive(facts.archive_replay)
        gross, slippage = replay[15:17]
        official = float(facts.fee_binding.official_exchange_fee_cny)
        broker = float(facts.fee_binding.broker_customer_fee_cny)
        all_in = float(facts.fee_binding.all_in_cost_cny)
        fees_state = "BOUND"
        fees = all_in
        net_state = "BOUND_AUTHORITATIVE_FEE_STATEMENT"
        net = money_cent_sum(gross, -all_in)
    else:
        raise CFastPnlLedgerError("INVALID_ACTUAL_SOURCE_FACTS")
    if not isinstance(
        facts,
        (
            ActualSimNowPinnedArchiveReplayFactsDTO,
            ActualSimNowSettledArchiveReplayFactsDTO,
            ActualSimNowFeeBoundArchiveReplayFactsDTO,
        ),
    ):
        official = None
        broker = None
        all_in = None
    core = {
        "schema_version": (
            "commodity_c_fast_actual_simnow_calibration_pnl_layer_v5"
            if isinstance(facts, ActualSimNowSettledArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v3"
            if isinstance(facts, ActualSimNowPinnedArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v4"
            if isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v2"
        ),
        "layer_kind": "ACTUAL_SIMNOW_CALIBRATION_PNL",
        "snapshot_hash": facts.snapshot_hash,
        "source_facts": facts.model_dump(mode="json"),
        "lineage": _build_lineage(
            facts,
            source_kind,
        ).model_dump(mode="json"),
        "actual_state": actual_state,
        "stable_actual_fact_identity_sha256": (stable_actual_fact_identity),
        "actual_amount_verification_state": amount_verification_state,
        "gross_execution_pnl_cny": gross,
        "adverse_slippage_cny": slippage,
        "official_exchange_fee_cny": official,
        "broker_customer_fee_cny": broker,
        "all_in_cost_cny": all_in,
        "fees_state": fees_state,
        "actual_fees_cny": fees,
        "net_pnl_state": net_state,
        "actual_net_pnl_cny": net,
        "countable_forward": False,
    }
    return ActualSimNowCalibrationPnlLayerDTO.model_validate(
        {**core, "layer_hash": sha256_json(core)}
    )


def _stable_actual_fact_identity(
    facts: (
        ActualSimNowFactsDTO
        | ActualSimNowPinnedArchiveReplayFactsDTO
        | ActualSimNowSettledArchiveReplayFactsDTO
        | ActualSimNowFeeBoundArchiveReplayFactsDTO
    ),
) -> str:
    """Identity excludes collection time so one terminal fact is count-once."""

    return sha256_json(
        {
            "snapshot_hash": facts.snapshot_hash,
            "plan_hash": facts.plan_hash,
            "session_id": facts.session_id,
            "terminal_checksum": (
                facts.archive_replay.terminal_checksum
                if isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO)
                else facts.terminal_checksum
            ),
        }
    )


def _require_fee_binding_trust_context(
    facts: PnlSourceFactsBaseDTO,
    context: FeeBindingTrustContext | None,
) -> None:
    if not isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO):
        return
    if context is None:
        raise CFastPnlLedgerError("FEE_BOUND_EXTERNAL_TRUST_CONTEXT_REQUIRED")
    try:
        context.assert_matches(facts.fee_binding)
    except (TypeError, ValueError) as exc:
        raise CFastPnlLedgerError("FEE_BOUND_EXTERNAL_TRUST_CONTEXT_MISMATCH") from exc


def _load_source_facts(
    dto_type: type[SourceFacts],
    payload: Mapping[str, Any],
    code: str,
) -> SourceFacts:
    try:
        return dto_type.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CFastPnlLedgerError(code) from exc


def _verify_source_identity(
    sources: tuple[PnlSourceFactsBaseDTO, ...],
    *,
    ledger_id: str,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    plan_hash: str,
    valuation_day: str,
) -> None:
    expected = (
        ledger_id,
        snapshot_hash,
        formula_target_binding_sha256,
        plan_hash,
        valuation_day,
    )
    for facts in sources:
        actual = (
            facts.ledger_id,
            facts.snapshot_hash,
            facts.formula_target_binding_sha256,
            facts.plan_hash,
            facts.valuation_day.isoformat(),
        )
        if actual != expected:
            raise CFastPnlLedgerError("SOURCE_IDENTITY_MISMATCH")


def _verify_created_at_covers_source_cutoffs(
    *,
    created_at_utc: str,
    sources: tuple[PnlSourceFactsBaseDTO, ...],
) -> None:
    """Reject entries timestamped before any embedded observation cutoff."""

    created_at = datetime.fromisoformat(created_at_utc.replace("Z", "+00:00"))
    pending: list[Any] = [
        source.model_dump(mode="python") for source in sources
    ]
    while pending:
        value = pending.pop()
        if isinstance(value, Mapping):
            for field, item in value.items():
                if field in _SOURCE_CUTOFF_FIELDS and item is not None:
                    cutoff = (
                        item
                        if isinstance(item, datetime)
                        else datetime.fromisoformat(
                            str(item).replace("Z", "+00:00")
                        )
                    )
                    if cutoff > created_at:
                        raise CFastPnlLedgerError(
                            "LEDGER_CREATED_AT_PRECEDES_SOURCE_CUTOFF"
                        )
                if isinstance(item, (Mapping, Sequence)) and not isinstance(
                    item, (str, bytes, bytearray)
                ):
                    pending.append(item)
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            pending.extend(value)


def _source_cutoffs(
    entry: CommodityCFastFourLayerPnlLedgerEntryDTO,
) -> dict[str, Any]:
    return {
        "theoretical": (entry.theoretical_target_pnl.source_facts.as_of_at_utc),
        "fee": entry.fee_adjusted_pnl.source_facts.as_of_at_utc,
        "execution": (entry.execution_quality_interval_pnl.source_facts.as_of_at_utc),
        "actual": (entry.actual_simnow_calibration_pnl.source_facts.as_of_at_utc),
    }


def _source_fact_set_hash(
    entry: CommodityCFastFourLayerPnlLedgerEntryDTO,
) -> str:
    return sha256_json(
        [
            entry.theoretical_target_pnl.lineage.source_payload_sha256,
            entry.fee_adjusted_pnl.lineage.source_payload_sha256,
            (entry.execution_quality_interval_pnl.lineage.source_payload_sha256),
            (entry.actual_simnow_calibration_pnl.lineage.source_payload_sha256),
        ]
    )


def _reject_decimal_raw_input(value: Any) -> None:
    if isinstance(value, Decimal):
        raise CFastPnlLedgerError("DECIMAL_RAW_INPUT_NOT_ALLOWED")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_decimal_raw_input(key)
            _reject_decimal_raw_input(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_decimal_raw_input(item)
