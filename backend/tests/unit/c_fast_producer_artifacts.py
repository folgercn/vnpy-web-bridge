"""Synthetic canonical #163 artifacts for contract tests only.

These bytes exercise verification.  They are not source-authority evidence and
must never be used as a real Research input or SimNow target.
"""

from __future__ import annotations

from typing import Any, Callable


PRODUCER_STATUS = "PURE_PRODUCER_KERNEL_ONLY_NOT_REAL_ARTIFACT"
PRODUCER_FALSE_AUTHORITY_FIELDS = (
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "simnow_execution_authorized",
    "runtime_activation_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "order_authorized",
    "order_submission_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "production_authorized",
    "automatic_promotion_authorized",
)


def canonical_c_fast_artifacts(
    *,
    targets: list[dict[str, Any]],
    research_as_of_official_day: str,
    execution_day: str,
    generated_at: str,
    canonical_json: Callable[[Any], bytes],
) -> dict[str, bytes]:
    products = tuple(row["product"] for row in targets)
    following_day = targets[0]["pit_main_following_official_day"]
    source_sha256 = "c" * 64
    claimed_receipt_sha256 = "d" * 64

    def base(role: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": f"commodity_c_fast_pure_producer_{role}_v1",
            "purpose": PRODUCER_STATUS,
            "status": PRODUCER_STATUS,
            "artifact_role": role,
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "producer_kernel_id": "commodity_c_fast_pure_producer_kernel_v1",
            "source_view_id": "synthetic-contract-test-source-view",
            "source_view_canonical_sha256": source_sha256,
            "claimed_receipt_sha256": claimed_receipt_sha256,
            "source_receipt_signature_verified": False,
            "source_receipt_keyring_verified": False,
            "source_custody_verified": False,
            "sealed_export_verified": False,
            "generated_at": generated_at,
            "research_evidence_only": True,
        }
        payload.update(
            {field: False for field in PRODUCER_FALSE_AUTHORITY_FIELDS}
        )
        return payload

    freeze = base("freeze_contract")
    freeze.update(
        {
            "frozen_rule_id": "commodity_fast_tsmom_forward_freeze_v1",
            "frozen_rule_sha256": (
                "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
            ),
            "frozen_rule_projection": {
                "universe": list(products),
                "pit_main_definition": "DAILY_PIT_OI_MAIN",
                "trend_horizons_official_days": [21, 63, 126],
                "volatility_lookback_official_days": 60,
                "volatility_floor": 0.05,
                "virtual_nav_cny": 20_000_000,
            },
        }
    )
    manifest = base("research_manifest")
    manifest.update(
        {
            "research_as_of_official_day": research_as_of_official_day,
            "execution_day": execution_day,
        }
    )
    signals = base("signal_evidence")
    signals.update(
        {
            "research_as_of_official_day": research_as_of_official_day,
            "signals": [
                {
                    "product": row["product"],
                    "trend_21_sign": row["trend_21_sign"],
                    "trend_63_sign": row["trend_63_sign"],
                    "trend_126_sign": row["trend_126_sign"],
                    "source_score": row["source_score"],
                    "vol60_annualized": row["vol60_annualized"],
                    "raw_risk_score": row["raw_risk_score"],
                    "pit_main_exact_contract": row["exact_contract"],
                }
                for row in targets
            ],
        }
    )
    target = base("target_evidence")
    target.update(
        {
            "execution_day": execution_day,
            "targets": [
                {
                    "product": row["product"],
                    "source_target_weight": row["source_target_weight"],
                    "buffered_target_weight": row["buffered_target_weight"],
                    "target_quantity": row["target_quantity"],
                    "exact_contract": row["exact_contract"],
                }
                for row in targets
            ],
        }
    )
    allocation = base("allocation_evidence")
    allocation.update(
        {
            "virtual_nav_cny": 20_000_000,
            "quantities": {
                row["product"]: row["target_quantity"] for row in targets
            },
        }
    )
    roll = base("daily_roll_evidence")
    roll.update(
        {
            "pit_main_definition": "DAILY_PIT_OI_MAIN",
            "rows": [
                {
                    "product": row["product"],
                    "pit_main_exact_contract": row["pit_main_exact_contract"],
                    "pit_main_dte": row["pit_main_dte"],
                    "pit_main_official_last_trading_day": row[
                        "pit_main_official_last_trading_day"
                    ],
                    "pit_main_following_official_day": row[
                        "pit_main_following_official_day"
                    ],
                    "pit_main_following_dte": row["pit_main_following_dte"],
                    "pit_main_target_position_allowed": row[
                        "pit_main_target_position_allowed"
                    ],
                    "pit_main_roll": row["pit_main_roll"],
                }
                for row in targets
            ],
        }
    )
    prices = base("reference_price_evidence")
    prices.update(
        {
            "execution_day": execution_day,
            "reference_price_field": "official_open",
            "rows": [
                {
                    "product": row["product"],
                    "exact_contract": row["exact_contract"],
                    "reference_open_price": row["reference_open_price"],
                    "observed_at": row["reference_price_observed_at"],
                    "source_raw_sha256": row[
                        "reference_price_source_sha256"
                    ],
                }
                for row in targets
            ],
        }
    )
    calendar = base("calendar_authority")
    calendar.update(
        {
            "official_days": [
                research_as_of_official_day,
                execution_day,
                following_day,
            ],
            "research_as_of_official_day": research_as_of_official_day,
            "execution_day": execution_day,
            "execution_is_immediate_next_official_day": True,
        }
    )
    specs = base("contract_spec_evidence")
    specs.update(
        {
            "rows": [
                {
                    "product": row["product"],
                    "exact_contract": row["exact_contract"],
                    "multiplier": row["multiplier"],
                    "price_tick": row["price_tick"],
                }
                for row in targets
            ]
        }
    )
    payloads = {
        "freeze_contract": freeze,
        "research_manifest": manifest,
        "signal_evidence": signals,
        "target_evidence": target,
        "allocation_evidence": allocation,
        "daily_roll_evidence": roll,
        "reference_price_evidence": prices,
        "calendar_authority": calendar,
        "contract_spec_evidence": specs,
    }
    return {role: canonical_json(payload) for role, payload in payloads.items()}
