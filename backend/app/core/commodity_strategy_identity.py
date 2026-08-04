"""Frozen cross-plane identity for the ten-product commodity strategy."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from types import MappingProxyType
from typing import Any, Final


COMMODITY_FROZEN_SECTOR_MAP_V1_ID: Final = "COMMODITY_FROZEN_SECTOR_MAP_V1"

COMMODITY_FROZEN_SECTOR_MAP_V1: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ag": "precious",
        "al": "nonferrous",
        "au": "precious",
        "bu": "energy_chemical",
        "cu": "nonferrous",
        "rb": "ferrous",
        "ru": "energy_chemical",
        "sc": "energy",
        "sp": "light_industry",
        "zn": "nonferrous",
    }
)


def commodity_frozen_sector_map_v1() -> dict[str, str]:
    """Return a mutable plane-local copy without exposing the frozen mapping."""

    return dict(COMMODITY_FROZEN_SECTOR_MAP_V1)


COMMODITY_MAP_STRATEGY_IDENTITY_V1: Final = (
    "commodity_fast_tsmom_forward_freeze_v1"
)
COMMODITY_C_FAST_ALLOCATION_POLICY_IDENTITY_V1: Final = (
    "C_FAST_CROSS_SECTION_NEUTRAL"
)


def _canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def commodity_map_strategy_version_projection(snapshot: Any) -> dict[str, Any]:
    """Project stable MAP identity from the repository's executable snapshot.

    Period-specific signals, dates, prices, contracts and target quantities are
    intentionally excluded.  A change to formula, producer, input contract or
    signal/risk semantics changes this projection and requires a new Acceptance.
    """

    bindings = snapshot.research_bindings
    guardrails = snapshot.guardrails
    producer_sha256 = getattr(bindings, "producer_sha256", None)
    if not producer_sha256:
        raise ValueError("MAP_PRODUCER_CODE_IDENTITY_MISSING")
    return {
        "schema_version": "commodity_map_strategy_version_projection_v1",
        "strategy_identity": snapshot.frozen_rule_id,
        "strategy_model_version_sha256": snapshot.frozen_rule_sha256,
        "input_data_contract_sha256": bindings.research_contract_sha256,
        "formula_builder_sha256": bindings.formula_builder_sha256,
        "producer_code_sha256": producer_sha256,
        "trend_horizons_official_days": list(
            snapshot.trend_horizons_official_days
        ),
        "volatility_lookback_official_days": (
            snapshot.volatility_lookback_official_days
        ),
        "volatility_floor": snapshot.volatility_floor,
        "frequency": snapshot.frequency,
        "signal_semantics": "SIGNED_MONTHLY_TSMOM_RISK_SCORE_V1",
        "allowed_output_products": sorted(row.product for row in snapshot.targets),
        "max_source_product_abs": guardrails.source_product_abs_cap,
        "max_source_sector_gross": guardrails.source_sector_gross_cap,
        "max_source_portfolio_gross": guardrails.source_portfolio_gross_cap,
        "source_target_net": guardrails.source_target_net,
    }


def commodity_map_strategy_version_projection_sha256(snapshot: Any) -> str:
    return _canonical_sha256(commodity_map_strategy_version_projection(snapshot))


def commodity_map_output_contract_sha256() -> str:
    """Hash the stable MAP → C_FAST projection contract, not a period output."""

    return _canonical_sha256(
        {
            "schema_version": "commodity_map_to_c_fast_projection_contract_v1",
            "strategy_identity_field": "frozen_rule_id",
            "product_fields": [
                "product",
                "sector",
                "trend_21_sign",
                "trend_63_sign",
                "trend_126_sign",
                "source_score",
                "vol60_annualized",
                "raw_risk_score",
                "source_target_weight",
            ],
            "complete_product_set_required": True,
            "execution_fields_forbidden": True,
        }
    )


def commodity_c_fast_allocation_policy_projection(snapshot: Any) -> dict[str, Any]:
    """Project stable C_FAST allocation/roll/risk policy identity.

    Product selection, exact contracts, integer target lots and execution day
    are outputs and therefore do not force policy re-acceptance.
    """

    bindings = snapshot.research_bindings
    allocator = snapshot.allocator
    guardrails = snapshot.guardrails
    products = sorted(row.product for row in snapshot.targets)
    return {
        "schema_version": "commodity_c_fast_allocation_policy_projection_v1",
        "allocation_policy_identity": snapshot.candidate_id,
        "map_output_contract_sha256": commodity_map_output_contract_sha256(),
        "allocator_runner_sha256": bindings.allocator_runner_sha256,
        "guardband_runner_sha256": bindings.guardband_runner_sha256,
        "allocator_manifest_sha256": bindings.allocator_manifest_sha256,
        "product_pool": products,
        "sector_map": {
            product: COMMODITY_FROZEN_SECTOR_MAP_V1[product]
            for product in products
        },
        "algorithm_id": allocator.algorithm_id,
        "neighbourhood_radius_lots": allocator.neighbourhood_radius_lots,
        "beam_width": allocator.beam_width,
        "net_error_penalty": allocator.net_error_penalty,
        "monthly_target_dates_only": allocator.monthly_target_dates_only,
        "daily_auto_reweight": allocator.daily_auto_reweight,
        "roll_preserves_integer_lots": allocator.roll_preserves_integer_lots,
        "pit_main_definition": snapshot.pit_main_definition,
        "previous_current_target_semantics": (
            "SIGNED_PREVIOUS_AND_CURRENT_EXACT_CONTRACT_INTEGER_TARGET_V1"
        ),
        "max_buffered_product_abs": guardrails.buffered_product_abs_cap,
        "max_buffered_sector_gross": guardrails.buffered_sector_gross_cap,
        "max_buffered_portfolio_gross": guardrails.buffered_portfolio_gross_cap,
        "buffered_target_net": guardrails.buffered_target_net,
        "max_integer_product_abs": guardrails.integer_product_abs_hard_cap,
        "max_integer_sector_gross": guardrails.integer_sector_gross_hard_cap,
        "max_integer_portfolio_gross": guardrails.integer_portfolio_gross_hard_cap,
        "max_integer_abs_net": guardrails.integer_abs_net_hard_cap,
        "executable_snapshot_schema": snapshot.schema_version,
        "execution_policy": "SIMNOW_TWO_PHASE_CLOSE_RECONCILE_OPEN_V1",
    }


def commodity_c_fast_allocation_policy_projection_sha256(snapshot: Any) -> str:
    return _canonical_sha256(
        commodity_c_fast_allocation_policy_projection(snapshot)
    )


def commodity_executable_target_projection(snapshot: Any) -> dict[str, Any]:
    """Return the signed period projection joining MAP, C_FAST and targets."""

    return {
        "schema_version": "commodity_map_c_fast_executable_target_projection_v1",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_schema_version": snapshot.schema_version,
        "map_acceptance_id": snapshot.map_acceptance_id,
        "map_acceptance_raw_sha256": snapshot.map_acceptance_raw_sha256,
        "map_strategy_projection_sha256": (
            snapshot.map_strategy_projection_sha256
        ),
        "map_signal_artifact_sha256": snapshot.map_signal_artifact_sha256,
        "c_fast_allocation_acceptance_id": (
            snapshot.c_fast_allocation_acceptance_id
        ),
        "c_fast_allocation_acceptance_raw_sha256": (
            snapshot.c_fast_allocation_acceptance_raw_sha256
        ),
        "c_fast_allocation_projection_sha256": (
            snapshot.c_fast_allocation_projection_sha256
        ),
        "complete_input_products": sorted(row.product for row in snapshot.targets),
        "selected_products": snapshot.runtime_selected_products,
        "source_month": snapshot.source_month,
        "source_official_day": snapshot.source_official_day.isoformat(),
        "execution_day": snapshot.execution_day.isoformat(),
        "previous_snapshot_hash": snapshot.previous_snapshot_hash,
        "formula_target_binding_sha256": snapshot.formula_target_binding_sha256,
        "producer_code_sha256": snapshot.research_bindings.producer_sha256,
        "source_artifact_sha256": snapshot.research_bindings.input_bundle_sha256,
        "targets": [
            {
                "product": row.product,
                "previous_exact_contract": row.previous_exact_contract,
                "previous_target_quantity": row.previous_target_quantity,
                "exact_contract": row.exact_contract,
                "target_quantity": row.target_quantity,
                "source_target_weight": row.source_target_weight,
                "buffered_target_weight": row.buffered_target_weight,
                "reference_open_price": row.reference_open_price,
                "multiplier": row.multiplier,
                "price_tick": row.price_tick,
            }
            for row in sorted(snapshot.targets, key=lambda item: item.product)
        ],
    }


def commodity_executable_target_projection_sha256(snapshot: Any) -> str:
    return _canonical_sha256(commodity_executable_target_projection(snapshot))
