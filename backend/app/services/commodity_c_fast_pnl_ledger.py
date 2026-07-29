from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypeVar

from pydantic import ValidationError

from app.schemas.commodity_c_fast_pnl_ledger import (
    ActualSimNowCalibrationPnlLayerDTO,
    CommodityCFastFourLayerPnlLedgerEntryDTO,
    CommodityCFastPnlLedgerAuditDTO,
    ExecutionQualityIntervalPnlLayerDTO,
    FeeAdjustedPnlLayerDTO,
    PnlLayerHashIndexDTO,
    PnlSourceLineageDTO,
    TheoreticalTargetPnlLayerDTO,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


MAX_CHAIN_ENTRIES = 10_000
LayerDTO = TypeVar(
    "LayerDTO",
    TheoreticalTargetPnlLayerDTO,
    FeeAdjustedPnlLayerDTO,
    ExecutionQualityIntervalPnlLayerDTO,
    ActualSimNowCalibrationPnlLayerDTO,
)


class CFastPnlLedgerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def build_source_lineage(
    payload: Mapping[str, Any],
) -> PnlSourceLineageDTO:
    core = dict(payload)
    if "lineage_hash" in core:
        raise CFastPnlLedgerError("CALLER_MUST_NOT_SUPPLY_LINEAGE_HASH")
    try:
        return PnlSourceLineageDTO.model_validate(
            {**core, "lineage_hash": sha256_json(core)}
        )
    except ValidationError as exc:
        raise CFastPnlLedgerError("INVALID_SOURCE_LINEAGE") from exc


def build_four_layer_pnl_entry(
    *,
    ledger_id: str,
    entry_sequence: int,
    previous_entry_hash: str | None,
    snapshot_hash: str,
    formula_target_binding_sha256: str,
    valuation_day: str,
    created_at_utc: str,
    theoretical_target_pnl: Mapping[str, Any],
    fee_adjusted_pnl: Mapping[str, Any],
    execution_quality_interval_pnl: Mapping[str, Any],
    actual_simnow_calibration_pnl: Mapping[str, Any],
) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
    """Build one deterministic, non-activating four-layer Research entry.

    All inputs are explicit. Hash fields are builder-owned so callers cannot
    smuggle stale or cross-artifact digests into an otherwise valid entry.
    """

    theoretical = _build_layer(
        TheoreticalTargetPnlLayerDTO,
        theoretical_target_pnl,
        snapshot_hash=snapshot_hash,
        schema_version=(
            "commodity_c_fast_theoretical_target_pnl_layer_v1"
        ),
        layer_kind="THEORETICAL_TARGET_PNL",
        require_lineage=True,
    )
    if {
        "source_theoretical_layer_hash",
        "source_theoretical_total_pnl_cny",
    }.intersection(fee_adjusted_pnl):
        raise CFastPnlLedgerError(
            "CALLER_SUPPLIED_BUILDER_OWNED_FIELD"
        )
    fee_core = dict(fee_adjusted_pnl)
    fee_core["source_theoretical_layer_hash"] = theoretical.layer_hash
    fee_core["source_theoretical_total_pnl_cny"] = (
        theoretical.total_pnl_cny
    )
    fee_adjusted = _build_layer(
        FeeAdjustedPnlLayerDTO,
        fee_core,
        snapshot_hash=snapshot_hash,
        schema_version="commodity_c_fast_fee_adjusted_pnl_layer_v1",
        layer_kind="FEE_ADJUSTED_PNL",
        require_lineage=True,
    )
    execution_interval = _build_layer(
        ExecutionQualityIntervalPnlLayerDTO,
        execution_quality_interval_pnl,
        snapshot_hash=snapshot_hash,
        schema_version=(
            "commodity_c_fast_execution_quality_interval_pnl_layer_v1"
        ),
        layer_kind="EXECUTION_QUALITY_INTERVAL_PNL",
        require_lineage=True,
    )
    actual = _build_layer(
        ActualSimNowCalibrationPnlLayerDTO,
        actual_simnow_calibration_pnl,
        snapshot_hash=snapshot_hash,
        schema_version=(
            "commodity_c_fast_actual_simnow_calibration_pnl_layer_v1"
        ),
        layer_kind="ACTUAL_SIMNOW_CALIBRATION_PNL",
        require_lineage=(
            actual_simnow_calibration_pnl.get("actual_state")
            == "FACTS_BOUND"
        ),
    )
    layer_hashes = PnlLayerHashIndexDTO(
        theoretical_target_pnl_sha256=theoretical.layer_hash,
        fee_adjusted_pnl_sha256=fee_adjusted.layer_hash,
        execution_quality_interval_pnl_sha256=(
            execution_interval.layer_hash
        ),
        actual_simnow_calibration_pnl_sha256=actual.layer_hash,
    )
    entry_identity = {
        "ledger_id": ledger_id,
        "entry_sequence": entry_sequence,
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (
            formula_target_binding_sha256
        ),
        "valuation_day": valuation_day,
        "layer_hashes": layer_hashes.model_dump(mode="json"),
    }
    core: dict[str, Any] = {
        "schema_version": "commodity_c_fast_four_layer_pnl_ledger_v1",
        "ledger_id": ledger_id,
        "entry_id": (
            f"cfast-pnl-entry-v1-{sha256_json(entry_identity)}"
        ),
        "entry_sequence": entry_sequence,
        "previous_entry_hash": previous_entry_hash,
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (
            formula_target_binding_sha256
        ),
        "valuation_day": valuation_day,
        "created_at_utc": created_at_utc,
        "virtual_nav_cny": 20_000_000,
        "theoretical_target_pnl": theoretical.model_dump(mode="json"),
        "fee_adjusted_pnl": fee_adjusted.model_dump(mode="json"),
        "execution_quality_interval_pnl": (
            execution_interval.model_dump(mode="json")
        ),
        "actual_simnow_calibration_pnl": (
            actual.model_dump(mode="json")
        ),
        "layer_hashes": layer_hashes.model_dump(mode="json"),
        "layer_isolation": (
            "FOUR_LAYERS_APPEND_ONLY_NEVER_OVERWRITE_OR_COALESCE"
        ),
        "audit_scope": (
            "DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY"
        ),
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
    except ValidationError as exc:
        raise CFastPnlLedgerError("INVALID_LEDGER_ENTRY") from exc


def reload_and_verify_four_layer_pnl_entry(
    payload: Mapping[str, Any],
) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
    try:
        return CommodityCFastFourLayerPnlLedgerEntryDTO.model_validate(
            payload
        )
    except ValidationError as exc:
        raise CFastPnlLedgerError("LEDGER_ENTRY_VERIFICATION_FAILED") from exc


def verify_four_layer_pnl_chain(
    payloads: Sequence[Mapping[str, Any]],
) -> CommodityCFastPnlLedgerAuditDTO:
    if not payloads:
        raise CFastPnlLedgerError("EMPTY_LEDGER_CHAIN")
    if len(payloads) > MAX_CHAIN_ENTRIES:
        raise CFastPnlLedgerError("LEDGER_CHAIN_RESOURCE_LIMIT")
    entries = tuple(
        reload_and_verify_four_layer_pnl_entry(payload)
        for payload in payloads
    )
    ledger_id = entries[0].ledger_id
    entry_hashes = [entry.entry_hash for entry in entries]
    entry_ids = [entry.entry_id for entry in entries]
    if len(set(entry_hashes)) != len(entry_hashes) or len(
        set(entry_ids)
    ) != len(entry_ids):
        raise CFastPnlLedgerError("LEDGER_DUPLICATE_ENTRY")
    if any(entry.ledger_id != ledger_id for entry in entries):
        raise CFastPnlLedgerError("LEDGER_ID_MIXED")
    if [entry.entry_sequence for entry in entries] != list(
        range(1, len(entries) + 1)
    ):
        raise CFastPnlLedgerError("LEDGER_SEQUENCE_INVALID")
    for predecessor, current in zip(entries, entries[1:]):
        if current.previous_entry_hash != predecessor.entry_hash:
            raise CFastPnlLedgerError("LEDGER_PREDECESSOR_MISMATCH")
    return CommodityCFastPnlLedgerAuditDTO(
        schema_version="commodity_c_fast_pnl_ledger_audit_v1",
        ledger_id=ledger_id,
        entry_count=len(entries),
        genesis_entry_hash=entries[0].entry_hash,
        chain_tip_entry_hash=entries[-1].entry_hash,
        ordered_entry_hashes_sha256=sha256_json(entry_hashes),
        audit_state=(
            "PASS_DETERMINISTIC_STRUCTURE_AND_HASH_CHAIN_ONLY"
        ),
        actual_fact_entry_count=sum(
            entry.actual_simnow_calibration_pnl.actual_state
            == "FACTS_BOUND"
            for entry in entries
        ),
        countable_forward=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def _build_layer(
    dto_type: type[LayerDTO],
    payload: Mapping[str, Any],
    *,
    snapshot_hash: str,
    schema_version: str,
    layer_kind: str,
    require_lineage: bool,
) -> LayerDTO:
    core = dict(payload)
    forbidden = {
        "schema_version",
        "layer_kind",
        "snapshot_hash",
        "layer_hash",
    }
    if forbidden.intersection(core):
        raise CFastPnlLedgerError("CALLER_SUPPLIED_BUILDER_OWNED_FIELD")
    lineage_payload = core.pop("lineage", None)
    if require_lineage:
        if not isinstance(lineage_payload, Mapping):
            raise CFastPnlLedgerError("SOURCE_LINEAGE_REQUIRED")
        core["lineage"] = build_source_lineage(
            lineage_payload
        ).model_dump(mode="json")
    elif lineage_payload is not None:
        raise CFastPnlLedgerError("SOURCE_LINEAGE_NOT_ALLOWED")
    else:
        core["lineage"] = None
    layer_core = {
        "schema_version": schema_version,
        "layer_kind": layer_kind,
        "snapshot_hash": snapshot_hash,
        **core,
    }
    try:
        return dto_type.model_validate(
            {**layer_core, "layer_hash": sha256_json(layer_core)}
        )
    except ValidationError as exc:
        raise CFastPnlLedgerError(
            f"INVALID_{layer_kind}"
        ) from exc
