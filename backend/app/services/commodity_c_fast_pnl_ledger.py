from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, TypeVar

from pydantic import ValidationError

from app.schemas.commodity_c_fast_pnl_ledger import (
    ActualSimNowCalibrationPnlLayerDTO,
    ActualSimNowFactsDTO,
    ActualSimNowNotProvidedSourceFactsDTO,
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
    money_multiply,
    money_sum,
    sha256_json,
)


MAX_CHAIN_ENTRIES = 10_000
SourceFacts = TypeVar("SourceFacts", bound=PnlSourceFactsBaseDTO)

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
                "formula": (
                    "rate-times-turnover-plus-tick-and-roll-components"
                ),
                "unbound": (
                    "complete-frozen-component-universe-unknowns-null"
                ),
            }
        ),
    ),
    "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS": (
        "cfast-execution-interval-pnl-v2",
        sha256_json(
            {
                "fill": "filled-lot-pnl-times-fill-bounds",
                "opportunity": (
                    "unfilled-lot-cost-times-derived-unfilled-bounds"
                ),
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
                "terminal_checksum": (
                    "session-plan-status-completed-execution-state"
                ),
                "amounts": ("null-until-raw-fill-price-multiplier-fee-replay"),
            }
        ),
    ),
}


class CFastPnlLedgerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
    _verify_source_identity(
        sources,
        ledger_id=ledger_id,
        snapshot_hash=snapshot_hash,
        formula_target_binding_sha256=(formula_target_binding_sha256),
        plan_hash=plan_hash,
        valuation_day=valuation_day,
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
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (formula_target_binding_sha256),
        "plan_hash": plan_hash,
        "valuation_day": valuation_day,
        "created_at_utc": created_at_utc,
        "virtual_nav_cny": 20_000_000,
        "theoretical_target_pnl": theoretical.model_dump(mode="json"),
        "fee_adjusted_pnl": fee_adjusted.model_dump(mode="json"),
        "execution_quality_interval_pnl": (
            execution_interval.model_dump(mode="json")
        ),
        "actual_simnow_calibration_pnl": actual.model_dump(mode="json"),
        "layer_hashes": layer_hashes.model_dump(mode="json"),
        "layer_isolation": (
            "FOUR_LAYERS_APPEND_ONLY_NEVER_OVERWRITE_OR_COALESCE"
        ),
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
) -> CommodityCFastFourLayerPnlLedgerEntryDTO:
    """Validate checksums, then freshly replay every embedded source fact."""

    _reject_decimal_raw_input(payload)
    try:
        reloaded = CommodityCFastFourLayerPnlLedgerEntryDTO.model_validate(
            payload
        )
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
            reloaded.theoretical_target_pnl.source_facts.model_dump(
                mode="json"
            )
        ),
        fee_adjusted_pnl=(
            reloaded.fee_adjusted_pnl.source_facts.model_dump(mode="json")
        ),
        execution_quality_interval_pnl=(
            reloaded.execution_quality_interval_pnl.source_facts.model_dump(
                mode="json"
            )
        ),
        actual_simnow_calibration_pnl=(
            reloaded.actual_simnow_calibration_pnl.source_facts.model_dump(
                mode="json"
            )
        ),
    )
    if expected.model_dump(mode="json") != reloaded.model_dump(mode="json"):
        raise CFastPnlLedgerError("LEDGER_ENTRY_FRESH_REPLAY_MISMATCH")
    return reloaded


def verify_four_layer_pnl_chain(
    payloads: Sequence[Mapping[str, Any]],
) -> CommodityCFastPnlLedgerAuditDTO:
    if not payloads:
        raise CFastPnlLedgerError("EMPTY_LEDGER_CHAIN")
    if len(payloads) > MAX_CHAIN_ENTRIES:
        raise CFastPnlLedgerError("LEDGER_CHAIN_RESOURCE_LIMIT")
    entries = tuple(
        reload_and_verify_four_layer_pnl_entry(payload) for payload in payloads
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
    source_sets = [_source_fact_set_hash(entry) for entry in entries]
    if len(set(source_sets)) != len(source_sets):
        raise CFastPnlLedgerError("LEDGER_SOURCE_FACT_REPLAY")
    actual_fact_identities = [
        identity
        for entry in entries
        if (
            identity
            := entry.actual_simnow_calibration_pnl.stable_actual_fact_identity_sha256
        )
        is not None
    ]
    if len(set(actual_fact_identities)) != len(actual_fact_identities):
        raise CFastPnlLedgerError(
            "LEDGER_ACTUAL_TERMINAL_REPLAY_OR_DIGEST_CONFLICT"
        )
    for predecessor, current in zip(entries, entries[1:]):
        if current.previous_entry_hash != predecessor.entry_hash:
            raise CFastPnlLedgerError("LEDGER_PREDECESSOR_MISMATCH")
        if current.created_at_utc <= predecessor.created_at_utc:
            raise CFastPnlLedgerError("LEDGER_CREATED_AT_NOT_INCREASING")
        if current.valuation_day < predecessor.valuation_day:
            raise CFastPnlLedgerError("LEDGER_VALUATION_DAY_REGRESSION")
        previous_cutoffs = _source_cutoffs(predecessor)
        current_cutoffs = _source_cutoffs(current)
        if any(
            current_cutoffs[key] < previous_cutoffs[key]
            for key in previous_cutoffs
        ):
            raise CFastPnlLedgerError("LEDGER_SOURCE_AS_OF_REGRESSION")
    return CommodityCFastPnlLedgerAuditDTO(
        schema_version="commodity_c_fast_pnl_ledger_audit_v2",
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
        external_genesis_anchor_state="NOT_PROVIDED_STRUCTURE_ONLY",
        external_tip_anchor_state="NOT_PROVIDED_STRUCTURE_ONLY",
        countable_forward=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
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
        "position_basis": (
            "OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"
        ),
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
        "schema_version": (
            "commodity_c_fast_execution_quality_interval_pnl_layer_v2"
        ),
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
        source_kind = (
            "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"
        )
        actual_state = "FACTS_BOUND"
        stable_actual_fact_identity = _stable_actual_fact_identity(facts)
        amount_verification_state = facts.actual_amount_verification_state
        gross = None
        slippage = None
        fees_state = "UNVERIFIED"
        fees = None
        net_state = "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
        net = None
    else:
        raise CFastPnlLedgerError("INVALID_ACTUAL_SOURCE_FACTS")
    core = {
        "schema_version": (
            "commodity_c_fast_actual_simnow_calibration_pnl_layer_v2"
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
        "fees_state": fees_state,
        "actual_fees_cny": fees,
        "net_pnl_state": net_state,
        "actual_net_pnl_cny": net,
        "countable_forward": False,
    }
    return ActualSimNowCalibrationPnlLayerDTO.model_validate(
        {**core, "layer_hash": sha256_json(core)}
    )


def _stable_actual_fact_identity(facts: ActualSimNowFactsDTO) -> str:
    """Identity excludes collection time so one terminal fact is count-once."""

    return sha256_json(
        {
            "snapshot_hash": facts.snapshot_hash,
            "plan_hash": facts.plan_hash,
            "session_id": facts.session_id,
            "terminal_checksum": facts.terminal_checksum,
        }
    )


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


def _source_cutoffs(
    entry: CommodityCFastFourLayerPnlLedgerEntryDTO,
) -> dict[str, Any]:
    return {
        "theoretical": (
            entry.theoretical_target_pnl.source_facts.as_of_at_utc
        ),
        "fee": entry.fee_adjusted_pnl.source_facts.as_of_at_utc,
        "execution": (
            entry.execution_quality_interval_pnl.source_facts.as_of_at_utc
        ),
        "actual": (
            entry.actual_simnow_calibration_pnl.source_facts.as_of_at_utc
        ),
    }


def _source_fact_set_hash(
    entry: CommodityCFastFourLayerPnlLedgerEntryDTO,
) -> str:
    return sha256_json(
        [
            entry.theoretical_target_pnl.lineage.source_payload_sha256,
            entry.fee_adjusted_pnl.lineage.source_payload_sha256,
            (
                entry.execution_quality_interval_pnl.lineage.source_payload_sha256
            ),
            (
                entry.actual_simnow_calibration_pnl.lineage.source_payload_sha256
            ),
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
