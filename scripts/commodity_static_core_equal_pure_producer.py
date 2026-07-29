#!/usr/bin/env python3
"""Pure Research producer for the frozen STATIC_CORE_EQUAL scheduler.

The producer validates a bounded, unverified PIT OHLC curve view, computes the
frozen C and D sleeves, nets them at product level, reapplies guardband v2 and
selects 20m CNY integer targets.  It returns canonical Research Evidence only.
It cannot sign, install, dispatch or trade.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

import commodity_c_fast_pure_producer_kernel as cfast
import commodity_static_core_equal_formula_v1 as formula


STATUS = "PURE_RESEARCH_PRODUCER_ONLY_NOT_REAL_ARTIFACT"
SOURCE_SCHEMA_VERSION = "commodity_static_core_equal_pit_ohlc_source_view_v1"
SOURCE_PURPOSE = "UNVERIFIED_PIT_OHLC_TYPED_VIEW_INPUT_ONLY"
SOURCE_STATUS = "UNVERIFIED_PIT_OHLC_TYPED_VIEW"
KERNEL_ID = "commodity_static_core_equal_pure_producer_v1"
SCHEDULER_ID = "STATIC_CORE_EQUAL"
SOURCE_COMBINATION_ARM = "CORE_EQUAL_TARGET"
ARTIFACT_SCHEMA_PREFIX = "commodity_static_core_equal_pure_producer"

C_KERNEL_CODE_SHA256 = (
    "23539d801d6ee9ddccd0371c3793282eeedf63b13dd442f9447adc795bc1d995"
)
D_FORMULA_CODE_SHA256 = (
    "653aa9d43f0e9f3aeb78e2a53f27781b48d6a20fcf8e59996af204d1433a5b4e"
)

ARTIFACT_ROLES = cfast.ARTIFACT_ROLES
FALSE_AUTHORITY_FIELDS = cfast.FALSE_AUTHORITY_FIELDS
FALSE_EVIDENCE_VERIFICATION_FIELDS = (
    "source_receipt_signature_verified",
    "source_receipt_keyring_verified",
    "source_custody_verified",
    "sealed_export_verified",
)


class StaticCoreEqualProducerError(cfast.ProducerKernelError):
    """Expected fail-closed producer input, identity or evidence error."""


@dataclass(frozen=True)
class ProducerResult:
    status: str
    source_view_canonical_sha256: str
    source_view_canonical: bytes
    artifacts: Mapping[str, bytes]
    producer_projection: Mapping[str, Any]


def canonical_json(payload: Any) -> bytes:
    return cfast.canonical_json(payload)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StaticCoreEqualProducerError(
            f"{label} must be one finite JSON number"
        )
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StaticCoreEqualProducerError(
            f"{label} must be one finite JSON number"
        )
    return parsed


def _strict_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StaticCoreEqualProducerError(
            f"{label} must be one JSON integer"
        )
    return value


def _source_path(name: str) -> Path:
    return Path(__file__).resolve().with_name(name)


def _verify_code_identity() -> dict[str, str]:
    identities = {
        "c_fast_kernel_code_sha256": (
            _sha256(
                _source_path(
                    "commodity_c_fast_pure_producer_kernel.py"
                ).read_bytes()
            ),
            C_KERNEL_CODE_SHA256,
        ),
        "d_formula_code_sha256": (
            _sha256(
                _source_path(
                    "commodity_static_core_equal_formula_v1.py"
                ).read_bytes()
            ),
            D_FORMULA_CODE_SHA256,
        ),
    }
    mismatches = [
        label
        for label, (observed, expected) in identities.items()
        if observed != expected
    ]
    if mismatches:
        raise StaticCoreEqualProducerError(
            "frozen producer code identity mismatch: "
            + ", ".join(sorted(mismatches))
        )
    return {
        label: expected
        for label, (_observed, expected) in identities.items()
    }


def _validate_ohlc(
    contract: dict[str, Any],
    *,
    label: str,
) -> dict[str, float]:
    raw_open = cfast._finite_positive(contract["open"], f"{label}.open")
    raw_high = cfast._finite_positive(contract["high"], f"{label}.high")
    raw_low = cfast._finite_positive(contract["low"], f"{label}.low")
    settlement = cfast._finite_positive(
        contract["settlement"],
        f"{label}.settlement",
    )
    if not (
        raw_low
        <= min(raw_open, settlement)
        <= max(raw_open, settlement)
        <= raw_high
    ):
        raise StaticCoreEqualProducerError(f"{label} OHLC range is invalid")
    return {
        "open": raw_open,
        "high": raw_high,
        "low": raw_low,
        "settlement": settlement,
    }


def _normalize_source(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> tuple[
    dict[str, Any],
    cfast.PitFrozenSourceView,
    dict[tuple[str, str, str], dict[str, float]],
]:
    source = cfast._bounded_source_view_input(source_view)
    source = cfast._require_exact_keys(
        source,
        {
            "schema_version",
            "purpose",
            "status",
            "source_view_id",
            "claimed_receipt_sha256",
            "generated_at",
            "cutoff_at",
            "research_as_of_official_day",
            "execution_day",
            "official_days",
            "source_bindings",
            "products",
        },
        "source view",
    )
    if (
        source["schema_version"] != SOURCE_SCHEMA_VERSION
        or source["purpose"] != SOURCE_PURPOSE
        or source["status"] != SOURCE_STATUS
    ):
        raise StaticCoreEqualProducerError(
            "source view is not the frozen PIT OHLC typed input"
        )

    raw_products = source["products"]
    if not isinstance(raw_products, list):
        raise StaticCoreEqualProducerError("products must be one array")
    stripped_products: list[dict[str, Any]] = []
    ohlc_lookup: dict[tuple[str, str, str], dict[str, float]] = {}
    for product_index, product_item in enumerate(raw_products):
        product_row = cfast._require_exact_keys(
            product_item,
            {
                "product",
                "exchange",
                "daily",
                "execution_reference",
                "contract_spec",
            },
            f"products[{product_index}]",
        )
        product = str(product_row["product"])
        raw_daily = product_row["daily"]
        if not isinstance(raw_daily, list):
            raise StaticCoreEqualProducerError(
                f"{product}.daily must be one array"
            )
        stripped_daily: list[dict[str, Any]] = []
        for day_index, day_item in enumerate(raw_daily):
            daily = cfast._require_exact_keys(
                day_item,
                {"official_day", "source_binding_id", "contracts"},
                f"{product}.daily[{day_index}]",
            )
            raw_contracts = daily["contracts"]
            if not isinstance(raw_contracts, list):
                raise StaticCoreEqualProducerError(
                    f"{product}.daily[{day_index}].contracts must be one array"
                )
            stripped_contracts: list[dict[str, Any]] = []
            for contract_index, contract_item in enumerate(raw_contracts):
                label = (
                    f"{product}.daily[{day_index}]"
                    f".contracts[{contract_index}]"
                )
                contract = cfast._require_exact_keys(
                    contract_item,
                    {
                        "exact_contract",
                        "delivery_yyyymm",
                        "open",
                        "high",
                        "low",
                        "settlement",
                        "open_interest",
                    },
                    label,
                )
                ohlc = _validate_ohlc(contract, label=label)
                key = (
                    product,
                    str(daily["official_day"]),
                    str(contract["exact_contract"]),
                )
                if key in ohlc_lookup:
                    raise StaticCoreEqualProducerError(
                        f"{label} duplicates an OHLC identity"
                    )
                ohlc_lookup[key] = ohlc
                stripped_contracts.append(
                    {
                        "exact_contract": contract["exact_contract"],
                        "delivery_yyyymm": contract["delivery_yyyymm"],
                        "settlement": ohlc["settlement"],
                        "open_interest": contract["open_interest"],
                    }
                )
            stripped_daily.append(
                {
                    "official_day": daily["official_day"],
                    "source_binding_id": daily["source_binding_id"],
                    "contracts": stripped_contracts,
                }
            )
        stripped_products.append(
            {
                "product": product_row["product"],
                "exchange": product_row["exchange"],
                "daily": stripped_daily,
                "execution_reference": product_row["execution_reference"],
                "contract_spec": product_row["contract_spec"],
            }
        )

    c_source_input = {
        **source,
        "schema_version": cfast.SOURCE_SCHEMA_VERSION,
        "purpose": cfast.SOURCE_PURPOSE,
        "status": cfast.SOURCE_STATUS,
        "products": stripped_products,
    }
    normalized_c_source, _bindings, _official_days = (
        cfast._validate_and_normalize_source_view(c_source_input)
    )

    normalized_products: list[dict[str, Any]] = []
    for product_view in normalized_c_source["products"]:
        product = product_view["product"]
        daily_rows: list[dict[str, Any]] = []
        for daily in product_view["daily"]:
            contracts: list[dict[str, Any]] = []
            for contract in daily["contracts"]:
                key = (
                    product,
                    daily["official_day"],
                    contract["exact_contract"],
                )
                ohlc = ohlc_lookup.get(key)
                if ohlc is None:
                    raise StaticCoreEqualProducerError(
                        "normalized source lost an OHLC identity"
                    )
                contracts.append({**contract, **ohlc})
            daily_rows.append({**daily, "contracts": contracts})
        normalized_products.append({**product_view, "daily": daily_rows})

    normalized_source = {
        **normalized_c_source,
        "schema_version": SOURCE_SCHEMA_VERSION,
        "purpose": SOURCE_PURPOSE,
        "status": SOURCE_STATUS,
        "products": normalized_products,
    }
    return normalized_source, normalized_c_source, ohlc_lookup


def _decode_artifact(raw: bytes, role: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StaticCoreEqualProducerError(
            f"{role} is not canonical JSON"
        ) from exc
    if not isinstance(payload, dict) or canonical_json(payload) != raw:
        raise StaticCoreEqualProducerError(
            f"{role} is not one canonical JSON object"
        )
    return payload


def _artifact_base(
    role: str,
    source: dict[str, Any],
    source_sha256: str,
    c_source_sha256: str,
    code_identity: Mapping[str, str],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": f"{ARTIFACT_SCHEMA_PREFIX}_{role}_v1",
        "purpose": STATUS,
        "status": STATUS,
        "artifact_role": role,
        "scheduler_id": SCHEDULER_ID,
        "source_combination_arm": SOURCE_COMBINATION_ARM,
        "producer_kernel_id": KERNEL_ID,
        "source_view_id": source["source_view_id"],
        "source_view_canonical_sha256": source_sha256,
        "c_fast_derived_source_view_canonical_sha256": c_source_sha256,
        "claimed_receipt_sha256": source["claimed_receipt_sha256"],
        "producer_code_identity": dict(code_identity),
        "source_receipt_signature_verified": False,
        "source_receipt_keyring_verified": False,
        "source_custody_verified": False,
        "sealed_export_verified": False,
        "generated_at": source["generated_at"],
        "research_evidence_only": True,
    }
    for field in FALSE_AUTHORITY_FIELDS:
        payload[field] = False
    return payload


def _produce_research_artifacts_unverified(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> ProducerResult:
    """Build deterministic evidence before the public fresh-replay check."""

    code_identity = _verify_code_identity()
    source, c_source, ohlc_lookup = _normalize_source(source_view)
    source_raw = canonical_json(source)
    source_sha256 = _sha256(source_raw)
    c_source_raw = canonical_json(c_source)
    c_source_sha256 = _sha256(c_source_raw)

    c_result = cfast.produce_research_artifacts(c_source)
    if c_result.source_view_canonical_sha256 != c_source_sha256:
        raise StaticCoreEqualProducerError(
            "C sleeve normalized source identity mismatch"
        )
    c_artifacts = {
        role: _decode_artifact(raw, f"C {role}")
        for role, raw in c_result.artifacts.items()
    }
    c_target_rows = {
        row["product"]: row
        for row in c_artifacts["target_evidence"]["targets"]
    }
    if set(c_target_rows) != set(cfast.PRODUCTS):
        raise StaticCoreEqualProducerError("C sleeve target evidence is incomplete")
    c_weights = {
        product: float(c_target_rows[product]["source_target_weight"])
        for product in cfast.PRODUCTS
    }

    d_signals: dict[str, dict[str, Any]] = {}
    d_traces: dict[str, dict[str, Any]] = {}
    product_views = {
        row["product"]: row for row in c_source["products"]
    }
    for product in cfast.PRODUCTS:
        signal, trace = formula.build_d_signal(
            product_views[product],
            ohlc_lookup,
        )
        d_signals[product] = signal
        d_traces[product] = trace
    d_raw_scores = {
        product: float(d_signals[product]["raw_risk_score"])
        for product in cfast.PRODUCTS
    }
    d_weights = cfast._cap_source_weights(d_raw_scores)
    contributions, composite_source = formula.build_composite_source_target(
        c_weights,
        d_weights,
    )
    buffered = cfast._buffer_weights(composite_source)

    reference_rows = {
        row["product"]: row
        for row in c_artifacts["reference_price_evidence"]["rows"]
    }
    spec_rows = {
        row["product"]: row
        for row in c_artifacts["contract_spec_evidence"]["rows"]
    }
    if set(reference_rows) != set(cfast.PRODUCTS) or set(spec_rows) != set(
        cfast.PRODUCTS
    ):
        raise StaticCoreEqualProducerError(
            "reference/spec evidence is incomplete"
        )
    unit_weights = {
        product: (
            float(reference_rows[product]["reference_open_price"])
            * int(spec_rows[product]["multiplier"])
            / cfast.VIRTUAL_NAV_CNY
        )
        for product in cfast.PRODUCTS
    }
    composite_allocation = formula.allocate_with_safe_zero_status(
        buffered,
        unit_weights,
    )
    allocation = composite_allocation.allocation

    target_rows: list[dict[str, Any]] = []
    for product in cfast.PRODUCTS:
        c_row = c_target_rows[product]
        if (
            d_signals[product]["pit_main_exact_contract"]
            != c_row["exact_contract"]
        ):
            raise StaticCoreEqualProducerError(
                f"{product} C/D PIT-main exact contract mismatch"
            )
        target_rows.append(
            {
                "product": product,
                "sector": cfast.SECTOR_MAP[product],
                "C_source_target_weight": c_weights[product],
                "D_source_target_weight": d_weights[product],
                "C_raw_contribution": contributions[product]["C"],
                "D_raw_contribution": contributions[product]["D"],
                "raw_combined_weight": math.fsum(
                    contributions[product].values()
                ),
                "source_target_weight": composite_source[product],
                "buffered_target_weight": buffered[product],
                "exact_contract": c_row["exact_contract"],
                "target_quantity": allocation.quantities[product],
                "reference_open_price": reference_rows[product][
                    "reference_open_price"
                ],
                "multiplier": spec_rows[product]["multiplier"],
                "price_tick": spec_rows[product]["price_tick"],
            }
        )
    buffered_target_sha256 = _sha256(
        canonical_json(
            {
                row["product"]: row["buffered_target_weight"]
                for row in target_rows
            }
        )
    )

    artifact_payloads: dict[str, dict[str, Any]] = {}
    freeze = _artifact_base(
        "freeze_contract",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    freeze.update(
        {
            "candidate_weights": formula.CANDIDATE_WEIGHTS,
            "C_candidate_id": cfast.CANDIDATE_ID,
            "D_candidate_id": formula.D_CANDIDATE_ID,
            "D_algorithm_id": formula.D_ALGORITHM_ID,
            "D_exact_contract": {
                "price_series": (
                    "roll-safe synthetic OHLC using old PIT main on switch day"
                ),
                "entry": (
                    "settlement strictly above previous 20 official-day highs "
                    "or below previous 20 lows"
                ),
                "exit": (
                    "long strictly below previous 10 lows; short strictly "
                    "above previous 10 highs"
                ),
                "event_order": "exit_before_entry_on_each_source_day",
                "volatility": "roll-safe close return vol60 ddof=1 annualized 252",
                "risk_scaling": "state / max(vol60, 0.05)",
            },
            "source_limits": cfast.SOURCE_LIMITS,
            "guardband_v2": {
                **cfast.BUFFER_LIMITS,
                "target_net": 0.0,
                "policy": "SHRINK_ONLY_PRODUCT_SECTOR_GROSS_THEN_NET_ZERO",
            },
            "allocator": {
                "virtual_nav_cny": cfast.VIRTUAL_NAV_CNY,
                "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
                "neighbourhood_radius_lots": (
                    cfast.NEIGHBOURHOOD_RADIUS_LOTS
                ),
                "beam_width": cfast.BEAM_WIDTH,
                "net_error_penalty": cfast.NET_ERROR_PENALTY,
                "integer_limits_strict": cfast.INTEGER_LIMITS,
                "absolute_lot_cap": cfast.MAX_ABS_TARGET_QUANTITY,
                "no_product_nonzero_policy": "SAFE_ZERO",
            },
            "sector_map_id": cfast.SECTOR_MAP_ID,
            "sector_map": cfast.SECTOR_MAP,
        }
    )
    artifact_payloads["freeze_contract"] = freeze

    manifest = _artifact_base(
        "research_manifest",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    manifest.update(
        {
            "source_schema_version": SOURCE_SCHEMA_VERSION,
            "source_status": source["status"],
            "research_as_of_official_day": source[
                "research_as_of_official_day"
            ],
            "execution_day": source["execution_day"],
            "source_bindings": source["source_bindings"],
            "artifact_roles": list(ARTIFACT_ROLES),
            "C_artifact_digests": [
                {"role": role, "sha256": _sha256(raw)}
                for role, raw in c_result.artifacts.items()
            ],
            "real_artifact_claimed": False,
            "acceptance_authority_claimed": False,
            "execution_permit_claimed": False,
        }
    )
    artifact_payloads["research_manifest"] = manifest

    signal_evidence = _artifact_base(
        "signal_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    signal_evidence.update(
        {
            "research_as_of_official_day": source[
                "research_as_of_official_day"
            ],
            "C_signal_evidence_sha256": _sha256(
                c_result.artifacts["signal_evidence"]
            ),
            "C_signals": c_artifacts["signal_evidence"]["signals"],
            "D_signals": [
                d_signals[product] for product in cfast.PRODUCTS
            ],
        }
    )
    artifact_payloads["signal_evidence"] = signal_evidence

    target_evidence = _artifact_base(
        "target_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    target_evidence.update(
        {
            "execution_day": source["execution_day"],
            "candidate_weights": formula.CANDIDATE_WEIGHTS,
            "signal_netting": (
                "single-account product-level source contribution netting "
                "before guardband and lot conversion"
            ),
            "guardband_order": (
                "product, sector gross, portfolio gross, shrink larger leg "
                "to exact net zero"
            ),
            "buffered_target_sha256": buffered_target_sha256,
            "targets": target_rows,
        }
    )
    artifact_payloads["target_evidence"] = target_evidence

    allocation_evidence = _artifact_base(
        "allocation_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    allocation_evidence.update(
        {
            "buffered_target_sha256": buffered_target_sha256,
            "virtual_nav_cny": cfast.VIRTUAL_NAV_CNY,
            "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": cfast.NEIGHBOURHOOD_RADIUS_LOTS,
            "beam_width": cfast.BEAM_WIDTH,
            "net_error_penalty": cfast.NET_ERROR_PENALTY,
            "integer_limits_strict": cfast.INTEGER_LIMITS,
            "absolute_lot_cap": cfast.MAX_ABS_TARGET_QUANTITY,
            "allocation_status": composite_allocation.allocation_status,
            "nonzero_product_candidate_available": (
                composite_allocation.nonzero_product_candidate_available
            ),
            "raw_quantities": allocation.raw_quantities,
            "quantities": allocation.quantities,
            "realized_weights": allocation.realized_weights,
            "squared_target_error": allocation.squared_target_error,
            "residual_net": allocation.residual_net,
            "objective": allocation.objective,
            "gross": allocation.gross,
            "sector_gross": allocation.sector_gross,
            "states_retained": allocation.states_retained,
        }
    )
    artifact_payloads["allocation_evidence"] = allocation_evidence

    daily_roll = _artifact_base(
        "daily_roll_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    daily_roll.update(
        {
            "pit_main_definition": "DAILY_PIT_OI_MAIN",
            "D_roll_rule": (
                "old PIT main closes switch-day OHLC; new main resets scale "
                "for next official day"
            ),
            "D_rows": [d_traces[product] for product in cfast.PRODUCTS],
        }
    )
    artifact_payloads["daily_roll_evidence"] = daily_roll

    reference = _artifact_base(
        "reference_price_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    reference.update(
        {
            "execution_day": source["execution_day"],
            "reference_price_field": "official_open",
            "C_reference_price_evidence_sha256": _sha256(
                c_result.artifacts["reference_price_evidence"]
            ),
            "rows": [
                reference_rows[product] for product in cfast.PRODUCTS
            ],
        }
    )
    artifact_payloads["reference_price_evidence"] = reference

    c_calendar = c_artifacts["calendar_authority"]
    calendar = _artifact_base(
        "calendar_authority",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    calendar.update(
        {
            "calendar_source_binding": c_calendar[
                "calendar_source_binding"
            ],
            "official_days": c_calendar["official_days"],
            "research_as_of_official_day": c_calendar[
                "research_as_of_official_day"
            ],
            "execution_day": c_calendar["execution_day"],
            "following_official_day": c_calendar[
                "following_official_day"
            ],
            "execution_is_immediate_next_official_day": True,
        }
    )
    artifact_payloads["calendar_authority"] = calendar

    contract_spec = _artifact_base(
        "contract_spec_evidence",
        source,
        source_sha256,
        c_source_sha256,
        code_identity,
    )
    contract_spec.update(
        {
            "C_contract_spec_evidence_sha256": _sha256(
                c_result.artifacts["contract_spec_evidence"]
            ),
            "rows": [spec_rows[product] for product in cfast.PRODUCTS],
        }
    )
    artifact_payloads["contract_spec_evidence"] = contract_spec

    artifacts = {
        role: canonical_json(artifact_payloads[role])
        for role in ARTIFACT_ROLES
    }
    if (
        set(artifacts) != set(ARTIFACT_ROLES)
        or any(not raw for raw in artifacts.values())
        or len(set(artifacts.values())) != len(ARTIFACT_ROLES)
    ):
        raise StaticCoreEqualProducerError(
            "nine canonical artifacts are incomplete or duplicated"
        )
    projection = {
        "projection_type": "research_evidence_projection_v1",
        "status": STATUS,
        "scheduler_id": SCHEDULER_ID,
        "producer_kernel_id": KERNEL_ID,
        "source_view_canonical_sha256": source_sha256,
        "artifact_roles": list(ARTIFACT_ROLES),
        "artifact_digests": [
            {"role": role, "sha256": _sha256(artifacts[role])}
            for role in ARTIFACT_ROLES
        ],
    }
    result = ProducerResult(
        status=STATUS,
        source_view_canonical_sha256=source_sha256,
        source_view_canonical=source_raw,
        artifacts=artifacts,
        producer_projection=projection,
    )
    return result


def produce_research_artifacts(
    source_view: Mapping[str, Any] | bytes | bytearray,
) -> ProducerResult:
    """Produce and freshly replay deterministic non-authoritative evidence."""

    result = _produce_research_artifacts_unverified(source_view)
    verify_research_artifacts(result)
    return result


def verify_research_artifacts(result: ProducerResult) -> None:
    """Fail closed on missing, non-canonical, tampered or cross-spliced bytes."""

    try:
        _verify_research_artifacts(result)
    except StaticCoreEqualProducerError:
        raise
    except (
        ArithmeticError,
        AttributeError,
        LookupError,
        TypeError,
        ValueError,
    ) as exc:
        raise StaticCoreEqualProducerError(
            "producer artifact field validation failed"
        ) from exc


def _verify_research_artifacts(result: ProducerResult) -> None:
    code_identity = _verify_code_identity()
    if result.status != STATUS or cfast.SHA256_PATTERN.fullmatch(
        result.source_view_canonical_sha256
    ) is None:
        raise StaticCoreEqualProducerError("producer result identity mismatch")
    if tuple(result.artifacts) != ARTIFACT_ROLES:
        raise StaticCoreEqualProducerError("producer artifacts are missing or reordered")
    if len(set(result.artifacts.values())) != len(ARTIFACT_ROLES):
        raise StaticCoreEqualProducerError("producer artifact bytes are duplicated")
    if (
        not isinstance(result.source_view_canonical, bytes)
        or len(result.source_view_canonical) > cfast.MAX_SOURCE_VIEW_RAW_BYTES
    ):
        raise StaticCoreEqualProducerError(
            "canonical source view is missing or outside the resource bound"
        )
    source_payload = _decode_artifact(
        result.source_view_canonical,
        "source view",
    )
    normalized_source, normalized_c_source, _ohlc_lookup = _normalize_source(
        source_payload
    )
    if (
        canonical_json(normalized_source) != result.source_view_canonical
        or _sha256(result.source_view_canonical)
        != result.source_view_canonical_sha256
    ):
        raise StaticCoreEqualProducerError(
            "canonical source view identity mismatch"
        )
    source_product_views = {
        row["product"]: row for row in normalized_c_source["products"]
    }
    source_day_pit_mains = {
        product: cfast._pit_main(
            product,
            cfast._parse_date(
                source_product_views[product]["daily"][-1]["official_day"],
                f"{product} source official day",
            ),
            source_product_views[product]["daily"][-1]["contracts"],
        )[0]["exact_contract"]
        for product in cfast.PRODUCTS
    }
    payloads: dict[str, dict[str, Any]] = {}
    for role in ARTIFACT_ROLES:
        payload = _decode_artifact(result.artifacts[role], role)
        if (
            payload.get("artifact_role") != role
            or payload.get("status") != STATUS
            or payload.get("scheduler_id") != SCHEDULER_ID
            or payload.get("producer_kernel_id") != KERNEL_ID
            or payload.get("source_view_canonical_sha256")
            != result.source_view_canonical_sha256
            or payload.get("producer_code_identity") != code_identity
            or payload.get("research_evidence_only") is not True
        ):
            raise StaticCoreEqualProducerError(
                f"{role} immutable identity mismatch"
            )
        for field in FALSE_AUTHORITY_FIELDS:
            if payload.get(field) is not False:
                raise StaticCoreEqualProducerError(
                    f"{role} authority must remain false: {field}"
                )
        for field in FALSE_EVIDENCE_VERIFICATION_FIELDS:
            if payload.get(field) is not False:
                raise StaticCoreEqualProducerError(
                    f"{role} unverified evidence flag must remain false: {field}"
                )
        payloads[role] = payload

    expected_projection = {
        "projection_type": "research_evidence_projection_v1",
        "status": STATUS,
        "scheduler_id": SCHEDULER_ID,
        "producer_kernel_id": KERNEL_ID,
        "source_view_canonical_sha256": (
            result.source_view_canonical_sha256
        ),
        "artifact_roles": list(ARTIFACT_ROLES),
        "artifact_digests": [
            {"role": role, "sha256": _sha256(result.artifacts[role])}
            for role in ARTIFACT_ROLES
        ],
    }
    if result.producer_projection != expected_projection:
        raise StaticCoreEqualProducerError(
            "producer projection digest mismatch"
        )

    target = payloads["target_evidence"]
    allocation = payloads["allocation_evidence"]
    freeze = payloads["freeze_contract"]
    if (
        canonical_json(freeze.get("candidate_weights"))
        != canonical_json(formula.CANDIDATE_WEIGHTS)
        or freeze.get("C_candidate_id") != cfast.CANDIDATE_ID
        or freeze.get("D_candidate_id") != formula.D_CANDIDATE_ID
        or freeze.get("D_algorithm_id") != formula.D_ALGORITHM_ID
        or canonical_json(freeze.get("source_limits"))
        != canonical_json(cfast.SOURCE_LIMITS)
        or freeze.get("sector_map_id") != cfast.SECTOR_MAP_ID
        or canonical_json(freeze.get("sector_map"))
        != canonical_json(cfast.SECTOR_MAP)
        or canonical_json(freeze.get("guardband_v2"))
        != canonical_json(
            {
                **cfast.BUFFER_LIMITS,
                "target_net": 0.0,
                "policy": (
                    "SHRINK_ONLY_PRODUCT_SECTOR_GROSS_THEN_NET_ZERO"
                ),
            }
        )
    ):
        raise StaticCoreEqualProducerError("freeze contract literal mismatch")
    frozen_allocator = freeze.get("allocator")
    expected_frozen_allocator = {
        "virtual_nav_cny": cfast.VIRTUAL_NAV_CNY,
        "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
        "neighbourhood_radius_lots": cfast.NEIGHBOURHOOD_RADIUS_LOTS,
        "beam_width": cfast.BEAM_WIDTH,
        "net_error_penalty": cfast.NET_ERROR_PENALTY,
        "integer_limits_strict": cfast.INTEGER_LIMITS,
        "absolute_lot_cap": cfast.MAX_ABS_TARGET_QUANTITY,
        "no_product_nonzero_policy": "SAFE_ZERO",
    }
    if (
        not isinstance(frozen_allocator, dict)
        or canonical_json(frozen_allocator)
        != canonical_json(expected_frozen_allocator)
    ):
        raise StaticCoreEqualProducerError("freeze allocator literal mismatch")

    signal = payloads["signal_evidence"]
    c_signals = signal.get("C_signals")
    d_signals = signal.get("D_signals")
    if (
        not isinstance(c_signals, list)
        or not isinstance(d_signals, list)
        or [row.get("product") for row in c_signals if isinstance(row, dict)]
        != list(cfast.PRODUCTS)
        or [row.get("product") for row in d_signals if isinstance(row, dict)]
        != list(cfast.PRODUCTS)
        or any(
            row.get("candidate_id") != formula.D_CANDIDATE_ID
            or row.get("algorithm_id") != formula.D_ALGORITHM_ID
            or row.get("entry_lookback_official_days")
            != formula.D_ENTRY_LOOKBACK
            or row.get("exit_lookback_official_days")
            != formula.D_EXIT_LOOKBACK
            or row.get("state") not in {-1, 0, 1}
            for row in d_signals
        )
    ):
        raise StaticCoreEqualProducerError("C/D signal identity mismatch")

    c_signal_rows = {row["product"]: row for row in c_signals}
    d_signal_rows = {row["product"]: row for row in d_signals}
    try:
        for product in cfast.PRODUCTS:
            c_row = c_signal_rows[product]
            c_vol = _strict_finite_number(
                c_row["vol60_annualized"],
                f"{product} C vol60",
            )
            c_source_score = _strict_finite_number(
                c_row["source_score"],
                f"{product} C source score",
            )
            c_raw_risk_score = _strict_finite_number(
                c_row["raw_risk_score"],
                f"{product} C raw risk score",
            )
            c_trend_sign_values = (
                c_row["trend_21_sign"],
                c_row["trend_63_sign"],
                c_row["trend_126_sign"],
            )
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in c_trend_sign_values
            ):
                raise StaticCoreEqualProducerError(
                    f"{product} C signal formula mismatch"
                )
            c_trend_signs = tuple(int(value) for value in c_trend_sign_values)
            if (
                not all(
                    math.isfinite(value)
                    for value in (c_vol, c_source_score, c_raw_risk_score)
                )
                or c_vol <= 0
                or any(value not in {-1, 0, 1} for value in c_trend_signs)
                or not math.isclose(
                    c_source_score,
                    math.fsum(c_trend_signs) / len(cfast.TREND_HORIZONS),
                    rel_tol=0,
                    abs_tol=1e-12,
                )
                or not math.isclose(
                    c_raw_risk_score,
                    c_source_score / max(c_vol, cfast.VOLATILITY_FLOOR),
                    rel_tol=0,
                    abs_tol=1e-12,
                )
            ):
                raise StaticCoreEqualProducerError(
                    f"{product} C signal formula mismatch"
                )

            d_row = d_signal_rows[product]
            d_vol = _strict_finite_number(
                d_row["vol60_annualized"],
                f"{product} D vol60",
            )
            d_state_value = d_row["state"]
            if isinstance(d_state_value, bool) or not isinstance(
                d_state_value, int
            ):
                raise StaticCoreEqualProducerError(
                    f"{product} D signal formula mismatch"
                )
            d_state = int(d_state_value)
            d_raw_risk_score = _strict_finite_number(
                d_row["raw_risk_score"],
                f"{product} D raw risk score",
            )
            if (
                not all(
                    math.isfinite(value)
                    for value in (d_vol, d_raw_risk_score)
                )
                or d_vol <= 0
                or d_state not in {-1, 0, 1}
                or not math.isclose(
                    d_raw_risk_score,
                    d_state / max(d_vol, cfast.VOLATILITY_FLOOR),
                    rel_tol=0,
                    abs_tol=1e-12,
                )
            ):
                raise StaticCoreEqualProducerError(
                    f"{product} D signal formula mismatch"
                )
    except StaticCoreEqualProducerError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise StaticCoreEqualProducerError(
            "C/D signal formula fields are invalid"
        ) from exc

    rows = target.get("targets")
    if not isinstance(rows, list) or [
        row.get("product") for row in rows if isinstance(row, dict)
    ] != list(cfast.PRODUCTS):
        raise StaticCoreEqualProducerError("target rows are incomplete or reordered")
    target_rows_by_product = {row["product"]: row for row in rows}
    reference_rows = payloads["reference_price_evidence"].get("rows")
    spec_rows = payloads["contract_spec_evidence"].get("rows")
    d_roll_rows = payloads["daily_roll_evidence"].get("D_rows")
    if (
        not isinstance(reference_rows, list)
        or not isinstance(spec_rows, list)
        or not isinstance(d_roll_rows, list)
        or any(
            not isinstance(row, dict)
            for row in reference_rows + spec_rows + d_roll_rows
        )
        or [row.get("product") for row in reference_rows]
        != list(cfast.PRODUCTS)
        or [row.get("product") for row in spec_rows]
        != list(cfast.PRODUCTS)
        or [row.get("product") for row in d_roll_rows]
        != list(cfast.PRODUCTS)
    ):
        raise StaticCoreEqualProducerError(
            "target reference/spec/roll rows are incomplete or reordered"
        )
    reference_rows_by_product = {
        row["product"]: row for row in reference_rows
    }
    spec_rows_by_product = {row["product"]: row for row in spec_rows}
    d_roll_rows_by_product = {row["product"]: row for row in d_roll_rows}
    for product in cfast.PRODUCTS:
        target_row = target_rows_by_product[product]
        reference_row = reference_rows_by_product[product]
        spec_row = spec_rows_by_product[product]
        d_roll_row = d_roll_rows_by_product[product]
        product_spec = cfast.PRODUCT_SPECS[product]
        exact_contract = cfast._exact_contract(
            target_row["exact_contract"],
            product,
            product_spec["exchange"],
            f"{product} composite target exact contract",
        )
        source_day_state = d_roll_row.get("source_day_state")
        if (
            exact_contract != source_day_pit_mains[product]
            or reference_row.get("exact_contract") != exact_contract
            or spec_row.get("exact_contract") != exact_contract
            or spec_row.get("exchange") != product_spec["exchange"]
            or not isinstance(source_day_state, dict)
            or source_day_state.get("pit_main_exact_contract")
            != exact_contract
            or c_signal_rows[product].get("pit_main_exact_contract")
            != exact_contract
            or d_signal_rows[product].get("pit_main_exact_contract")
            != exact_contract
            or _strict_finite_number(
                reference_row.get("reference_open_price"),
                f"{product} reference evidence open price",
            )
            != _strict_finite_number(
                target_row["reference_open_price"],
                f"{product} target reference open price",
            )
            or _strict_integer(
                spec_row.get("multiplier"),
                f"{product} spec evidence multiplier",
            )
            != _strict_integer(
                target_row["multiplier"],
                f"{product} target multiplier",
            )
            or _strict_integer(
                target_row["multiplier"],
                f"{product} target multiplier",
            )
            != product_spec["multiplier"]
            or _strict_finite_number(
                spec_row.get("price_tick"),
                f"{product} spec evidence price tick",
            )
            != _strict_finite_number(
                target_row["price_tick"],
                f"{product} target price tick",
            )
            or not math.isclose(
                _strict_finite_number(
                    target_row["price_tick"],
                    f"{product} target price tick",
                ),
                float(product_spec["price_tick"]),
                rel_tol=0,
                abs_tol=1e-12,
            )
        ):
            raise StaticCoreEqualProducerError(
                f"{product} exact-contract/reference/spec/roll binding mismatch"
            )
    buffered = {
        row["product"]: row["buffered_target_weight"] for row in rows
    }
    c_weights = {
        row["product"]: _strict_finite_number(
            row["C_source_target_weight"],
            f"{row['product']} C source target weight",
        )
        for row in rows
    }
    d_weights = {
        row["product"]: _strict_finite_number(
            row["D_source_target_weight"],
            f"{row['product']} D source target weight",
        )
        for row in rows
    }
    expected_c_weights = cfast._cap_source_weights(
        {
            product: _strict_finite_number(
                c_signal_rows[product]["raw_risk_score"],
                f"{product} C raw risk score",
            )
            for product in cfast.PRODUCTS
        }
    )
    expected_d_weights = cfast._cap_source_weights(
        {
            product: _strict_finite_number(
                d_signal_rows[product]["raw_risk_score"],
                f"{product} D raw risk score",
            )
            for product in cfast.PRODUCTS
        }
    )
    if any(
        not math.isclose(
            c_weights[product],
            expected_c_weights[product],
            rel_tol=0,
            abs_tol=1e-12,
        )
        or not math.isclose(
            d_weights[product],
            expected_d_weights[product],
            rel_tol=0,
            abs_tol=1e-12,
        )
        or c_signal_rows[product].get("pit_main_exact_contract")
        != target_rows_by_product[product]["exact_contract"]
        or d_signal_rows[product].get("pit_main_exact_contract")
        != target_rows_by_product[product]["exact_contract"]
        for product in cfast.PRODUCTS
    ):
        raise StaticCoreEqualProducerError(
            "C/D signal-to-target binding mismatch"
        )
    expected_contributions, expected_source = (
        formula.build_composite_source_target(c_weights, d_weights)
    )
    observed_source = {
        row["product"]: _strict_finite_number(
            row["source_target_weight"],
            f"{row['product']} source target weight",
        )
        for row in rows
    }
    for row in rows:
        product = row["product"]
        if (
            not math.isclose(
                _strict_finite_number(
                    row["C_raw_contribution"],
                    f"{product} C raw contribution",
                ),
                expected_contributions[product]["C"],
                rel_tol=0,
                abs_tol=1e-12,
            )
            or not math.isclose(
                _strict_finite_number(
                    row["D_raw_contribution"],
                    f"{product} D raw contribution",
                ),
                expected_contributions[product]["D"],
                rel_tol=0,
                abs_tol=1e-12,
            )
            or not math.isclose(
                _strict_finite_number(
                    row["raw_combined_weight"],
                    f"{product} raw combined weight",
                ),
                math.fsum(expected_contributions[product].values()),
                rel_tol=0,
                abs_tol=1e-12,
            )
            or not math.isclose(
                observed_source[product],
                expected_source[product],
                rel_tol=0,
                abs_tol=1e-12,
            )
        ):
            raise StaticCoreEqualProducerError(
                f"{product} C/D product-level netting mismatch"
            )
    expected_buffered = cfast._buffer_weights(expected_source)
    if any(
        not math.isclose(
            _strict_finite_number(
                buffered[product],
                f"{product} buffered target weight",
            ),
            expected_buffered[product],
            rel_tol=0,
            abs_tol=1e-12,
        )
        for product in cfast.PRODUCTS
    ):
        raise StaticCoreEqualProducerError("guardband v2 target mismatch")

    buffered_sha256 = _sha256(canonical_json(buffered))
    if (
        target.get("buffered_target_sha256") != buffered_sha256
        or allocation.get("buffered_target_sha256") != buffered_sha256
    ):
        raise StaticCoreEqualProducerError(
            "target/allocation buffered identity mismatch"
        )
    quantities = allocation.get("quantities")
    if not isinstance(quantities, dict) or any(
        _strict_integer(
            row["target_quantity"],
            f"{row['product']} target quantity",
        )
        != _strict_integer(
            quantities.get(row["product"]),
            f"{row['product']} allocation quantity",
        )
        for row in rows
    ):
        raise StaticCoreEqualProducerError(
            "target/allocation quantity mismatch"
        )
    unit_weights = {
        row["product"]: (
            _strict_finite_number(
                row["reference_open_price"],
                f"{row['product']} reference open price",
            )
            * _strict_integer(
                row["multiplier"],
                f"{row['product']} multiplier",
            )
            / cfast.VIRTUAL_NAV_CNY
        )
        for row in rows
    }
    expected_composite_allocation = formula.allocate_with_safe_zero_status(
        expected_buffered,
        unit_weights,
    )
    expected_allocation = expected_composite_allocation.allocation
    expected_allocation_fields = {
        "buffered_target_sha256": buffered_sha256,
        "virtual_nav_cny": cfast.VIRTUAL_NAV_CNY,
        "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
        "neighbourhood_radius_lots": cfast.NEIGHBOURHOOD_RADIUS_LOTS,
        "beam_width": cfast.BEAM_WIDTH,
        "net_error_penalty": cfast.NET_ERROR_PENALTY,
        "integer_limits_strict": cfast.INTEGER_LIMITS,
        "absolute_lot_cap": cfast.MAX_ABS_TARGET_QUANTITY,
        "allocation_status": (
            expected_composite_allocation.allocation_status
        ),
        "nonzero_product_candidate_available": (
            expected_composite_allocation.nonzero_product_candidate_available
        ),
        "raw_quantities": expected_allocation.raw_quantities,
        "quantities": expected_allocation.quantities,
        "realized_weights": expected_allocation.realized_weights,
        "squared_target_error": expected_allocation.squared_target_error,
        "residual_net": expected_allocation.residual_net,
        "objective": expected_allocation.objective,
        "gross": expected_allocation.gross,
        "sector_gross": expected_allocation.sector_gross,
        "states_retained": expected_allocation.states_retained,
    }
    if any(
        canonical_json(allocation.get(field)) != canonical_json(value)
        for field, value in expected_allocation_fields.items()
    ):
        raise StaticCoreEqualProducerError(
            "integer allocation deterministic replay mismatch"
        )

    expected_result = _produce_research_artifacts_unverified(source_payload)
    if (
        expected_result.status != result.status
        or expected_result.source_view_canonical_sha256
        != result.source_view_canonical_sha256
        or expected_result.source_view_canonical
        != result.source_view_canonical
        or expected_result.artifacts != result.artifacts
        or expected_result.producer_projection != result.producer_projection
    ):
        raise StaticCoreEqualProducerError(
            "producer artifacts do not match fresh source replay"
        )
