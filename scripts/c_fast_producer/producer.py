"""Offline C_FAST target-candidate producer.

The input boundary is two explicit immutable JSON values: an approved source
envelope and the canonical MAP candidate bytes produced for that same source.
The MAP bytes are predecessor material, never a directory pointer.  Every
calculation is replayed from the frozen pure kernel before a target candidate
is emitted.  This module has no service lifecycle or runtime authority.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import stat
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.trust_contracts.v1 import ContractError, verify_signed_artifact

try:
    import commodity_c_fast_pure_producer_kernel as kernel
except ModuleNotFoundError:  # pragma: no cover - exercised by -m image entrypoint
    _SCRIPTS = Path(__file__).resolve().parents[1]
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    import commodity_c_fast_pure_producer_kernel as kernel


CFAST_CANDIDATE_SCHEMA = "commodity_c_fast_target_candidate_v1"
CFAST_CANDIDATE_ROLE = "unsigned_c_fast_target_candidate"
CFAST_STATUS = "UNSIGNED_C_FAST_TARGET_CANDIDATE"
CFAST_PRODUCER_IDENTITY = "c-fast-producer"
CFAST_PRODUCER_VERSION = "c-fast-producer-v1"
CFAST_POLICY_IDENTITY = "C_FAST_CROSS_SECTION_NEUTRAL"
MAP_CANDIDATE_SCHEMA = "commodity_map_signal_candidate_v1"
MAP_CANDIDATE_ROLE = "unsigned_map_signal_candidate"
MAP_STATUS = "UNSIGNED_MAP_SIGNAL_CANDIDATE"
MAP_PRODUCER_IDENTITY = "map-producer"
MAP_PRODUCER_VERSION = "map-producer-v1"
MAP_STRATEGY_IDENTITY = "commodity_fast_tsmom_forward_freeze_v1"
SOURCE_ENVELOPE_SCHEMA = "commodity_approved_research_source_v1"
SOURCE_ENVELOPE_ROLE = "approved_research_source"
SOURCE_ENVELOPE_STATUS = "APPROVED_IMMUTABLE_SOURCE"
MAP_OUTPUT_CONTRACT_SCHEMA = "commodity_map_to_c_fast_projection_contract_v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024

_MAP_OUTPUT_FIELDS = (
    "product",
    "sector",
    "trend_21_sign",
    "trend_63_sign",
    "trend_126_sign",
    "source_score",
    "vol60_annualized",
    "raw_risk_score",
    "source_target_weight",
)
_AUTHORITY_FIELDS = tuple(kernel.FALSE_AUTHORITY_FIELDS) + (
    "production_allowed",
    "live_allowed",
    "countable_forward",
    "authority_granted",
    "signing_requested",
    "custody_published",
)
_SOURCE_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_role",
        "status",
        "source_view",
        "source_view_canonical_sha256",
        "source_receipt_sha256",
        "approval",
    }
)
_APPROVAL_KEYS = frozenset(
    {"approved", "immutable", "receipt_verified", "custody_verified", "lineage_verified"}
)


class ProducerError(ValueError):
    """Fail-closed producer input, predecessor or calculation error."""


def _verify_map_acceptance(
    *,
    map_payload: Mapping[str, Any],
    map_raw: bytes,
    map_acceptance: Mapping[str, Any],
    map_acceptance_keyring: Mapping[str, Any],
) -> None:
    """Require a domain-signed approval pinned to the exact MAP bytes."""

    try:
        signed = verify_signed_artifact(
            map_acceptance,
            keyring=map_acceptance_keyring,
            expected_domain="map_acceptance",
        )
        envelope = validate_artifact_envelope(signed["artifact"])
    except (ContractError, KeyError, TypeError) as exc:
        raise ProducerError("MAP acceptance signature or envelope is invalid") from exc
    approval = envelope.get("payload")
    expected_fields = {
        "decision",
        "map_candidate_id",
        "map_candidate_sha256",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    }
    if (
        envelope.get("artifact_type") != "map-acceptance"
        or envelope.get("trust_domain") != "map_acceptance"
        or not isinstance(approval, Mapping)
        or set(approval) != expected_fields
        or approval.get("decision") != "approved"
        or approval.get("map_candidate_id") != map_payload.get("candidate_id")
        or approval.get("map_candidate_sha256") != _sha256(map_raw)
        or approval.get("production_allowed") is not False
        or approval.get("live_trading_authorized") is not False
        or approval.get("countable_forward") is not False
    ):
        raise ProducerError("MAP acceptance is not approved or does not pin the predecessor")


@dataclass(frozen=True)
class CFastCandidateResult:
    raw: bytes
    payload: Mapping[str, Any]
    artifact_sha256: str
    map_predecessor_sha256: str
    source_view_canonical_sha256: str


def canonical_json(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProducerError("payload is not finite canonical JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(value: str) -> None:
    raise ProducerError(f"JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProducerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise ProducerError(f"{label} exceeds input byte limit")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError(f"{label} is not strict JSON") from exc
    if not isinstance(decoded, dict) or canonical_json(decoded) != raw:
        raise ProducerError(f"{label} must be canonical JSON object bytes")
    return decoded


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProducerError(f"{label} must be an object")
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        raise ProducerError(
            f"{label} field set mismatch missing={sorted(expected_set - actual)} extra={sorted(actual - expected_set)}"
        )
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ProducerError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ProducerError(f"{label} must be a lowercase SHA-256") from exc
    return value


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProducerError(f"{label} must be finite")
    result = float(value)
    if not math.isfinite(result):
        raise ProducerError(f"{label} must be finite")
    return result


def _module_sha256(module: Any) -> str:
    path = getattr(module, "__file__", None)
    if not isinstance(path, str):
        raise ProducerError("frozen kernel source identity is unavailable")
    try:
        return _sha256(Path(path).read_bytes())
    except OSError as exc:
        raise ProducerError("frozen kernel source identity cannot be read") from exc


def _producer_sha256() -> str:
    try:
        return _sha256(Path(__file__).read_bytes())
    except OSError as exc:
        raise ProducerError("C_FAST producer source identity cannot be read") from exc


def _map_producer_sha256() -> str:
    candidates = (
        Path(__file__).resolve().parents[1] / "map" / "producer.py",
        Path("/app/contracts/map-producer.py"),
    )
    for candidate in candidates:
        try:
            return _sha256(candidate.read_bytes())
        except OSError:
            continue
    raise ProducerError("MAP producer source identity is unavailable")


def _map_contract() -> dict[str, Any]:
    return {
        "schema_version": MAP_OUTPUT_CONTRACT_SCHEMA,
        "strategy_identity_field": "strategy_identity",
        "product_fields": list(_MAP_OUTPUT_FIELDS),
        "complete_product_set_required": True,
        "execution_fields_forbidden": True,
    }


def _map_contract_sha256() -> str:
    return _sha256(canonical_json(_map_contract()))


def _prepare_source(source_input: Mapping[str, Any] | bytes | bytearray) -> tuple[dict[str, Any], str, str]:
    if isinstance(source_input, (bytes, bytearray)):
        envelope = _decode_json(bytes(source_input), "source envelope")
    elif isinstance(source_input, Mapping):
        envelope = dict(source_input)
    else:
        raise ProducerError("source input must be an approved envelope")
    _exact_keys(envelope, _SOURCE_ENVELOPE_KEYS, "source envelope")
    if envelope["schema_version"] != SOURCE_ENVELOPE_SCHEMA or envelope["artifact_role"] != SOURCE_ENVELOPE_ROLE or envelope["status"] != SOURCE_ENVELOPE_STATUS:
        raise ProducerError("source envelope is not approved")
    approval = _exact_keys(envelope["approval"], _APPROVAL_KEYS, "source approval")
    if any(approval[field] is not True for field in _APPROVAL_KEYS):
        raise ProducerError("source approval facts are not all true")
    if not isinstance(envelope["source_view"], Mapping):
        raise ProducerError("source view must be an object")
    try:
        bounded = kernel._bounded_source_view_input(envelope["source_view"])
        normalized, _bindings, _days = kernel._validate_and_normalize_source_view(bounded)
    except Exception as exc:
        raise ProducerError("approved source failed frozen validation") from exc
    source_raw = kernel.canonical_json(normalized)
    source_hash = _sha256(source_raw)
    if _sha(envelope["source_view_canonical_sha256"], "source view hash") != source_hash:
        raise ProducerError("source canonical hash mismatch")
    receipt_hash = _sha(envelope["source_receipt_sha256"], "source receipt hash")
    if canonical_json(envelope["source_view"]) != source_raw:
        raise ProducerError("source view is not normalized canonical JSON")
    return normalized, source_hash, receipt_hash


def _decode_map(candidate_input: Mapping[str, Any] | bytes | bytearray) -> tuple[dict[str, Any], bytes]:
    if isinstance(candidate_input, (bytes, bytearray)):
        raw = bytes(candidate_input)
        return _decode_json(raw, "MAP candidate"), raw
    if isinstance(candidate_input, Mapping):
        payload = dict(candidate_input)
        return payload, canonical_json(payload)
    raise ProducerError("MAP predecessor must be canonical JSON")


def _map_candidate_id(source_hash: str) -> str:
    return "map-signal-v1-" + _sha256(
        canonical_json(
            {
                "producer_identity": MAP_PRODUCER_IDENTITY,
                "producer_version": MAP_PRODUCER_VERSION,
                "strategy_identity": MAP_STRATEGY_IDENTITY,
                "source_view_canonical_sha256": source_hash,
            }
        )
    )


def _check_map_predecessor(
    map_payload: Mapping[str, Any],
    map_raw: bytes,
    source: Mapping[str, Any],
    source_hash: str,
    receipt_hash: str,
) -> None:
    expected = {
        "schema_version",
        "artifact_role",
        "status",
        "candidate_id",
        "producer_identity",
        "strategy_identity",
        "strategy_model_version_sha256",
        "map_output_contract",
        "source",
        "lineage",
        "signals",
        "research_evidence_only",
        "producer_identity_only",
        *_AUTHORITY_FIELDS,
    }
    _exact_keys(map_payload, expected, "MAP predecessor")
    if map_payload["schema_version"] != MAP_CANDIDATE_SCHEMA or map_payload["artifact_role"] != MAP_CANDIDATE_ROLE or map_payload["status"] != MAP_STATUS:
        raise ProducerError("MAP predecessor schema/role/status mismatch")
    if map_payload["strategy_identity"] != MAP_STRATEGY_IDENTITY or map_payload["strategy_model_version_sha256"] != kernel.FROZEN_RULE_SHA256:
        raise ProducerError("MAP predecessor strategy identity mismatch")
    if map_payload["research_evidence_only"] is not True or map_payload["producer_identity_only"] is not True or any(map_payload[field] is not False for field in _AUTHORITY_FIELDS):
        raise ProducerError("MAP predecessor is not unsigned research-only material")
    identity = _exact_keys(map_payload["producer_identity"], {"producer_id", "producer_version", "producer_code_sha256", "kernel_id", "kernel_code_sha256"}, "MAP predecessor identity")
    if identity["producer_id"] != MAP_PRODUCER_IDENTITY or identity["producer_version"] != MAP_PRODUCER_VERSION or identity["kernel_id"] != kernel.KERNEL_ID:
        raise ProducerError("MAP predecessor producer identity mismatch")
    if _sha(identity["producer_code_sha256"], "MAP producer code hash") != _map_producer_sha256():
        raise ProducerError("MAP predecessor producer digest mismatch")
    if _sha(identity["kernel_code_sha256"], "MAP kernel code hash") != _module_sha256(kernel):
        raise ProducerError("MAP predecessor kernel digest mismatch")
    contract = _exact_keys(map_payload["map_output_contract"], {"schema_version", "strategy_identity_field", "product_fields", "complete_product_set_required", "execution_fields_forbidden", "contract_sha256"}, "MAP output contract")
    if contract["schema_version"] != MAP_OUTPUT_CONTRACT_SCHEMA or contract["contract_sha256"] != _map_contract_sha256() or contract["product_fields"] != list(_MAP_OUTPUT_FIELDS) or contract["execution_fields_forbidden"] is not True or contract["complete_product_set_required"] is not True:
        raise ProducerError("MAP output contract mismatch")
    map_source = _exact_keys(map_payload["source"], {"schema_version", "source_view_id", "source_view_canonical_sha256", "source_receipt_sha256", "research_as_of_official_day", "execution_day"}, "MAP source binding")
    if map_source["schema_version"] != kernel.SOURCE_SCHEMA_VERSION or map_source["source_view_id"] != source["source_view_id"] or map_source["source_view_canonical_sha256"] != source_hash or map_source["source_receipt_sha256"] != receipt_hash:
        raise ProducerError("MAP predecessor/source mismatch")
    _sha(map_source["source_view_canonical_sha256"], "MAP source hash")
    _sha(map_source["source_receipt_sha256"], "MAP receipt hash")
    if map_payload["candidate_id"] != _map_candidate_id(source_hash):
        raise ProducerError("MAP predecessor candidate identity mismatch")
    lineage = _exact_keys(map_payload["lineage"], {"source_view_canonical_sha256", "source_receipt_sha256", "lineage_sha256", "frozen_lineage"}, "MAP lineage")
    if lineage["source_view_canonical_sha256"] != source_hash or lineage["source_receipt_sha256"] != receipt_hash or lineage["frozen_lineage"] != dict(kernel.LINEAGE) or lineage["lineage_sha256"] != _sha256(canonical_json(lineage["frozen_lineage"])):
        raise ProducerError("MAP predecessor lineage mismatch")
    expected_signals: list[dict[str, Any]] = []
    products = {row["product"]: row for row in source["products"]}
    signals: dict[str, dict[str, Any]] = {}
    for product in kernel.PRODUCTS:
        signal, _roll = kernel._build_product_signal(products[product])
        signals[product] = signal
    source_weights = kernel._cap_source_weights({product: float(signals[product]["raw_risk_score"]) for product in kernel.PRODUCTS})
    for product in kernel.PRODUCTS:
        signal = signals[product]
        expected_signals.append(
            {
                "product": product,
                "sector": kernel.SECTOR_MAP[product],
                "trend_21_sign": signal["trend_21_sign"],
                "trend_63_sign": signal["trend_63_sign"],
                "trend_126_sign": signal["trend_126_sign"],
                "source_score": signal["source_score"],
                "vol60_annualized": signal["vol60_annualized"],
                "raw_risk_score": signal["raw_risk_score"],
                "source_target_weight": source_weights[product],
            }
        )
    if map_payload["signals"] != expected_signals:
        raise ProducerError("MAP predecessor failed deterministic replay")
    del map_raw  # The digest is bound by the C_FAST predecessor record.


def _policy_projection() -> dict[str, Any]:
    allocator_manifest = {
        "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
        "neighbourhood_radius_lots": kernel.NEIGHBOURHOOD_RADIUS_LOTS,
        "beam_width": kernel.BEAM_WIDTH,
        "net_error_penalty": kernel.NET_ERROR_PENALTY,
        "limits": kernel.INTEGER_LIMITS,
    }
    return {
        "schema_version": "commodity_c_fast_allocation_policy_projection_v1",
        "allocation_policy_identity": CFAST_POLICY_IDENTITY,
        "map_output_contract_sha256": _map_contract_sha256(),
        "allocator_runner_sha256": _module_sha256(kernel),
        "guardband_runner_sha256": _module_sha256(kernel),
        "allocator_manifest_sha256": _sha256(canonical_json(allocator_manifest)),
        "product_pool": list(kernel.PRODUCTS),
        "sector_map": dict(kernel.SECTOR_MAP),
        "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
        "neighbourhood_radius_lots": kernel.NEIGHBOURHOOD_RADIUS_LOTS,
        "beam_width": kernel.BEAM_WIDTH,
        "net_error_penalty": kernel.NET_ERROR_PENALTY,
        "monthly_target_dates_only": True,
        "daily_auto_reweight": False,
        "roll_preserves_integer_lots": True,
        "pit_main_definition": "DAILY_PIT_OI_MAIN",
        "previous_current_target_semantics": "SIGNED_PREVIOUS_AND_CURRENT_EXACT_CONTRACT_INTEGER_TARGET_V1",
        "max_buffered_product_abs": kernel.BUFFER_LIMITS["product"],
        "max_buffered_sector_gross": kernel.BUFFER_LIMITS["sector"],
        "max_buffered_portfolio_gross": kernel.BUFFER_LIMITS["gross"],
        "buffered_target_net": 0.0,
        "max_integer_product_abs": kernel.INTEGER_LIMITS["product"],
        "max_integer_sector_gross": kernel.INTEGER_LIMITS["sector"],
        "max_integer_portfolio_gross": kernel.INTEGER_LIMITS["gross"],
        "max_integer_abs_net": kernel.INTEGER_LIMITS["abs_net"],
    }


def _candidate_id(map_hash: str, source_hash: str) -> str:
    return "c-fast-target-v1-" + _sha256(
        canonical_json(
            {
                "producer_identity": CFAST_PRODUCER_IDENTITY,
                "producer_version": CFAST_PRODUCER_VERSION,
                "allocation_policy_identity": CFAST_POLICY_IDENTITY,
                "map_predecessor_sha256": map_hash,
                "source_view_canonical_sha256": source_hash,
            }
        )
    )


def _build_candidate(
    source: Mapping[str, Any],
    source_hash: str,
    receipt_hash: str,
    map_payload: Mapping[str, Any],
    map_raw: bytes,
) -> dict[str, Any]:
    map_hash = _sha256(map_raw)
    map_rows = {row["product"]: row for row in map_payload["signals"]}
    source_weights = {product: float(map_rows[product]["source_target_weight"]) for product in kernel.PRODUCTS}
    buffered_weights = kernel._buffer_weights(source_weights)
    products = {row["product"]: row for row in source["products"]}
    unit_weights = {
        product: products[product]["execution_reference"]["official_open"]
        * products[product]["contract_spec"]["multiplier"]
        / kernel.VIRTUAL_NAV_CNY
        for product in kernel.PRODUCTS
    }
    allocation = kernel._joint_integer_allocate(buffered_weights, unit_weights)
    execution_day = kernel._parse_date(source["execution_day"], "execution_day")
    following_days = [day for day in source["official_days"] if day > source["execution_day"]]
    if not following_days:
        raise ProducerError("source has no following official day")
    following_day = kernel._parse_date(following_days[0], "following official day")
    targets: list[dict[str, Any]] = []
    for product in kernel.PRODUCTS:
        view = products[product]
        main, _ranked = kernel._pit_main(product, execution_day, view["daily"][-1]["contracts"])
        exact_contract = str(main["exact_contract"])
        reference = view["execution_reference"]
        spec = view["contract_spec"]
        if reference["exact_contract"] != exact_contract or spec["exact_contract"] != exact_contract:
            raise ProducerError(f"{product} exact-contract splice")
        last_day = kernel._parse_date(spec["official_last_trading_day"], "official last trading day")
        dte = (last_day - execution_day).days
        following_dte = (last_day - following_day).days
        if dte < 11 or following_dte < 11:
            raise ProducerError(f"{product} DTE safety boundary")
        row = map_rows[product]
        targets.append(
            {
                "product": product,
                "sector": kernel.SECTOR_MAP[product],
                "trend_21_sign": row["trend_21_sign"],
                "trend_63_sign": row["trend_63_sign"],
                "trend_126_sign": row["trend_126_sign"],
                "source_score": row["source_score"],
                "vol60_annualized": row["vol60_annualized"],
                "raw_risk_score": row["raw_risk_score"],
                "source_target_weight": row["source_target_weight"],
                "buffered_target_weight": buffered_weights[product],
                "exact_contract": exact_contract,
                "target_quantity": allocation.quantities[product],
                "reference_open_price": reference["official_open"],
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
                "pit_main_dte": dte,
                "pit_main_following_official_day": following_day.isoformat(),
                "pit_main_following_dte": following_dte,
            }
        )
    policy = _policy_projection()
    producer_identity = {
        "producer_id": CFAST_PRODUCER_IDENTITY,
        "producer_version": CFAST_PRODUCER_VERSION,
        "producer_code_sha256": _producer_sha256(),
        "kernel_id": kernel.KERNEL_ID,
        "kernel_code_sha256": _module_sha256(kernel),
    }
    payload: dict[str, Any] = {
        "schema_version": CFAST_CANDIDATE_SCHEMA,
        "artifact_role": CFAST_CANDIDATE_ROLE,
        "status": CFAST_STATUS,
        "candidate_id": _candidate_id(map_hash, source_hash),
        "producer_identity": producer_identity,
        "strategy_identity": MAP_STRATEGY_IDENTITY,
        "allocation_policy_identity": CFAST_POLICY_IDENTITY,
        "policy_projection": policy,
        "source": {
            "schema_version": kernel.SOURCE_SCHEMA_VERSION,
            "source_view_id": source["source_view_id"],
            "source_view_canonical_sha256": source_hash,
            "source_receipt_sha256": receipt_hash,
            "research_as_of_official_day": source["research_as_of_official_day"],
            "execution_day": source["execution_day"],
        },
        "predecessor": {
            "artifact_role": MAP_CANDIDATE_ROLE,
            "schema_version": MAP_CANDIDATE_SCHEMA,
            "artifact_sha256": map_hash,
            "candidate_id": map_payload["candidate_id"],
            "source_view_canonical_sha256": source_hash,
            "producer_id": MAP_PRODUCER_IDENTITY,
        },
        "lineage": {
            "map_predecessor_sha256": map_hash,
            "map_candidate_id": map_payload["candidate_id"],
            "source_view_canonical_sha256": source_hash,
            "source_receipt_sha256": receipt_hash,
            "lineage_sha256": _sha256(canonical_json(kernel.LINEAGE)),
            "frozen_lineage": dict(kernel.LINEAGE),
        },
        "targets": targets,
        "allocation": {
            "buffered_target_sha256": _sha256(canonical_json(buffered_weights)),
            "virtual_nav_cny": kernel.VIRTUAL_NAV_CNY,
            "algorithm": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": kernel.NEIGHBOURHOOD_RADIUS_LOTS,
            "beam_width": kernel.BEAM_WIDTH,
            "net_error_penalty": kernel.NET_ERROR_PENALTY,
            "integer_limits_strict": dict(kernel.INTEGER_LIMITS),
            "absolute_lot_cap": kernel.MAX_ABS_TARGET_QUANTITY,
            "raw_quantities": allocation.raw_quantities,
            "quantities": allocation.quantities,
            "realized_weights": allocation.realized_weights,
            "squared_target_error": allocation.squared_target_error,
            "residual_net": allocation.residual_net,
            "objective": allocation.objective,
            "gross": allocation.gross,
            "sector_gross": allocation.sector_gross,
            "states_retained": allocation.states_retained,
        },
        "research_evidence_only": True,
        "producer_identity_only": True,
    }
    for field in _AUTHORITY_FIELDS:
        payload[field] = False
    return payload


def produce_c_fast_candidate(
    map_candidate_input: Mapping[str, Any] | bytes | bytearray,
    source_input: Mapping[str, Any] | bytes | bytearray,
    *,
    map_acceptance: Mapping[str, Any],
    map_acceptance_keyring: Mapping[str, Any],
    expected_map_sha256: str | None = None,
    rejected_predecessor_sha256: Iterable[str] = (),
) -> CFastCandidateResult:
    """Verify MAP predecessor and emit one deterministic target candidate."""

    source, source_hash, receipt_hash = _prepare_source(source_input)
    map_payload, map_raw = _decode_map(map_candidate_input)
    _verify_map_acceptance(
        map_payload=map_payload,
        map_raw=map_raw,
        map_acceptance=map_acceptance,
        map_acceptance_keyring=map_acceptance_keyring,
    )
    map_hash = _sha256(map_raw)
    if expected_map_sha256 is not None and map_hash != _sha(expected_map_sha256, "expected MAP predecessor hash"):
        raise ProducerError("MAP predecessor hash mismatch")
    rejected = {_sha(value, "rejected predecessor hash") for value in rejected_predecessor_sha256}
    if map_hash in rejected:
        raise ProducerError("MAP predecessor replay is rejected by high-water input")
    _check_map_predecessor(map_payload, map_raw, source, source_hash, receipt_hash)
    payload = _build_candidate(source, source_hash, receipt_hash, map_payload, map_raw)
    raw = canonical_json(payload)
    return CFastCandidateResult(
        raw=raw,
        payload=payload,
        artifact_sha256=_sha256(raw),
        map_predecessor_sha256=map_hash,
        source_view_canonical_sha256=source_hash,
    )


def _validate_candidate_shape(payload: Mapping[str, Any]) -> None:
    expected = {
        "schema_version", "artifact_role", "status", "candidate_id", "producer_identity",
        "strategy_identity", "allocation_policy_identity", "policy_projection", "source",
        "predecessor", "lineage", "targets", "allocation", "research_evidence_only",
        "producer_identity_only", *_AUTHORITY_FIELDS,
    }
    _exact_keys(payload, expected, "C_FAST candidate")
    if payload["schema_version"] != CFAST_CANDIDATE_SCHEMA or payload["artifact_role"] != CFAST_CANDIDATE_ROLE or payload["status"] != CFAST_STATUS:
        raise ProducerError("C_FAST candidate schema/role/status mismatch")
    if payload["strategy_identity"] != MAP_STRATEGY_IDENTITY or payload["allocation_policy_identity"] != CFAST_POLICY_IDENTITY:
        raise ProducerError("C_FAST formal identity mismatch")
    if payload["research_evidence_only"] is not True or payload["producer_identity_only"] is not True or any(payload[field] is not False for field in _AUTHORITY_FIELDS):
        raise ProducerError("C_FAST candidate contains authority")
    identity = _exact_keys(payload["producer_identity"], {"producer_id", "producer_version", "producer_code_sha256", "kernel_id", "kernel_code_sha256"}, "C_FAST producer identity")
    if identity["producer_id"] != CFAST_PRODUCER_IDENTITY or identity["producer_version"] != CFAST_PRODUCER_VERSION or identity["kernel_id"] != kernel.KERNEL_ID:
        raise ProducerError("C_FAST producer identity mismatch")
    _sha(identity["producer_code_sha256"], "C_FAST producer code hash")
    _sha(identity["kernel_code_sha256"], "C_FAST kernel code hash")
    policy = _exact_keys(payload["policy_projection"], set(_policy_projection()), "C_FAST policy projection")
    if policy != _policy_projection():
        raise ProducerError("C_FAST policy projection mismatch")
    source = _exact_keys(payload["source"], {"schema_version", "source_view_id", "source_view_canonical_sha256", "source_receipt_sha256", "research_as_of_official_day", "execution_day"}, "C_FAST source binding")
    if source["schema_version"] != kernel.SOURCE_SCHEMA_VERSION:
        raise ProducerError("C_FAST source schema mismatch")
    _sha(source["source_view_canonical_sha256"], "C_FAST source hash")
    _sha(source["source_receipt_sha256"], "C_FAST receipt hash")
    predecessor = _exact_keys(payload["predecessor"], {"artifact_role", "schema_version", "artifact_sha256", "candidate_id", "source_view_canonical_sha256", "producer_id"}, "C_FAST predecessor")
    if predecessor["artifact_role"] != MAP_CANDIDATE_ROLE or predecessor["schema_version"] != MAP_CANDIDATE_SCHEMA or predecessor["producer_id"] != MAP_PRODUCER_IDENTITY:
        raise ProducerError("C_FAST predecessor role mismatch")
    _sha(predecessor["artifact_sha256"], "C_FAST predecessor hash")
    if predecessor["source_view_canonical_sha256"] != source["source_view_canonical_sha256"]:
        raise ProducerError("C_FAST predecessor source mismatch")
    lineage = _exact_keys(payload["lineage"], {"map_predecessor_sha256", "map_candidate_id", "source_view_canonical_sha256", "source_receipt_sha256", "lineage_sha256", "frozen_lineage"}, "C_FAST lineage")
    if lineage["map_predecessor_sha256"] != predecessor["artifact_sha256"] or lineage["map_candidate_id"] != predecessor["candidate_id"] or lineage["source_view_canonical_sha256"] != source["source_view_canonical_sha256"] or lineage["source_receipt_sha256"] != source["source_receipt_sha256"] or lineage["frozen_lineage"] != dict(kernel.LINEAGE) or lineage["lineage_sha256"] != _sha256(canonical_json(lineage["frozen_lineage"])):
        raise ProducerError("C_FAST lineage mismatch")
    targets = payload["targets"]
    if not isinstance(targets, list) or [row.get("product") for row in targets if isinstance(row, dict)] != list(kernel.PRODUCTS):
        raise ProducerError("C_FAST target product set/order mismatch")
    target_fields = {"product", "sector", "trend_21_sign", "trend_63_sign", "trend_126_sign", "source_score", "vol60_annualized", "raw_risk_score", "source_target_weight", "buffered_target_weight", "exact_contract", "target_quantity", "reference_open_price", "multiplier", "price_tick", "pit_main_dte", "pit_main_following_official_day", "pit_main_following_dte"}
    for index, row in enumerate(targets):
        item = _exact_keys(row, target_fields, f"C_FAST target[{index}]")
        if item["product"] != kernel.PRODUCTS[index] or item["sector"] != kernel.SECTOR_MAP[item["product"]]:
            raise ProducerError("C_FAST target product/sector mismatch")
        for field in ("source_score", "vol60_annualized", "raw_risk_score", "source_target_weight", "buffered_target_weight", "reference_open_price", "price_tick"):
            _finite(item[field], f"C_FAST target {field}")
        if isinstance(item["target_quantity"], bool) or not isinstance(item["target_quantity"], int):
            raise ProducerError("C_FAST target quantity must be an integer")
    allocation = _exact_keys(payload["allocation"], {"buffered_target_sha256", "virtual_nav_cny", "algorithm", "neighbourhood_radius_lots", "beam_width", "net_error_penalty", "integer_limits_strict", "absolute_lot_cap", "raw_quantities", "quantities", "realized_weights", "squared_target_error", "residual_net", "objective", "gross", "sector_gross", "states_retained"}, "C_FAST allocation")
    if allocation["algorithm"] != "FINITE_NEIGHBOURHOOD_BEAM_V1" or allocation["virtual_nav_cny"] != kernel.VIRTUAL_NAV_CNY:
        raise ProducerError("C_FAST allocator identity mismatch")
    _sha(allocation["buffered_target_sha256"], "buffered target hash")


def verify_c_fast_candidate(
    candidate_input: Mapping[str, Any] | bytes | bytearray,
    *,
    map_candidate_input: Mapping[str, Any] | bytes | bytearray | None = None,
    source_input: Mapping[str, Any] | bytes | bytearray | None = None,
    map_acceptance: Mapping[str, Any] | None = None,
    map_acceptance_keyring: Mapping[str, Any] | None = None,
    expected_map_sha256: str | None = None,
    rejected_predecessor_sha256: Iterable[str] = (),
) -> CFastCandidateResult:
    """Verify exact bytes, predecessor hash, policy and optional replay."""

    if isinstance(candidate_input, (bytes, bytearray)):
        raw = bytes(candidate_input)
        payload = _decode_json(raw, "C_FAST candidate")
    elif isinstance(candidate_input, Mapping):
        payload = dict(candidate_input)
        raw = canonical_json(payload)
    else:
        raise ProducerError("C_FAST candidate must be canonical JSON")
    _validate_candidate_shape(payload)
    predecessor_hash = payload["predecessor"]["artifact_sha256"]
    rejected = {_sha(value, "rejected predecessor hash") for value in rejected_predecessor_sha256}
    if predecessor_hash in rejected:
        raise ProducerError("C_FAST predecessor replay is rejected by high-water input")
    if expected_map_sha256 is not None and predecessor_hash != _sha(expected_map_sha256, "expected MAP predecessor hash"):
        raise ProducerError("C_FAST predecessor mismatch")
    if map_candidate_input is not None and source_input is not None:
        if map_acceptance is None or map_acceptance_keyring is None:
            raise ProducerError("MAP acceptance and keyring are required for replay")
        expected = produce_c_fast_candidate(
            map_candidate_input,
            source_input,
            map_acceptance=map_acceptance,
            map_acceptance_keyring=map_acceptance_keyring,
            expected_map_sha256=expected_map_sha256,
            rejected_predecessor_sha256=rejected_predecessor_sha256,
        )
        if expected.raw != raw:
            raise ProducerError("C_FAST candidate failed deterministic replay or was tampered")
    return CFastCandidateResult(
        raw=raw,
        payload=payload,
        artifact_sha256=_sha256(raw),
        map_predecessor_sha256=predecessor_hash,
        source_view_canonical_sha256=payload["source"]["source_view_canonical_sha256"],
    )


def _reject_path_latest(path: Path) -> None:
    if any(part.casefold() == "latest" for part in path.parts):
        raise ProducerError("implicit latest paths are forbidden")


def _read_pinned_file(path: Path) -> bytes:
    _reject_path_latest(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProducerError("input file cannot be stat-ed") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProducerError("input must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProducerError("input file cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ProducerError("input changed before read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_INPUT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise ProducerError("input exceeds byte limit")
        after = os.fstat(fd)
        current = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, opened.st_size) or (current.st_dev, current.st_ino, current.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ProducerError("input changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _create_only_atomic(path: Path, raw: bytes) -> None:
    _reject_path_latest(path)
    try:
        parent_stat = path.parent.lstat()
    except OSError as exc:
        raise ProducerError("output parent cannot be stat-ed") from exc
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ProducerError("output parent must be a real directory")
    if path.exists() or path.is_symlink():
        raise ProducerError("output already exists; overwrite is forbidden")
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ProducerError("output already exists; overwrite is forbidden") from exc
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise ProducerError("output already exists; overwrite is forbidden") from exc
        raise ProducerError("atomic candidate publish failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _cli_json(payload: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json(dict(payload)) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="offline C_FAST allocation producer")
    parser.add_argument("--version", action="version", version=f"{CFAST_PRODUCER_IDENTITY} {CFAST_PRODUCER_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health", help="print liveness for the batch image")
    sub.add_parser("ready", help="print readiness for the batch image")
    produce = sub.add_parser("produce", help="create one unsigned C_FAST candidate")
    produce.add_argument("--map-input", required=True, type=Path)
    produce.add_argument("--source", required=True, type=Path)
    produce.add_argument("--map-acceptance", required=True, type=Path)
    produce.add_argument("--map-acceptance-keyring", required=True, type=Path)
    produce.add_argument("--output", required=True, type=Path)
    produce.add_argument("--expected-map-sha256")
    produce.add_argument("--reject-predecessor-sha256", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "health":
            _cli_json({"status": "ok", "producer_identity": CFAST_PRODUCER_IDENTITY, "version": CFAST_PRODUCER_VERSION})
            return 0
        if args.command == "ready":
            _module_sha256(kernel)
            _producer_sha256()
            _cli_json({"status": "ready", "producer_identity": CFAST_PRODUCER_IDENTITY, "version": CFAST_PRODUCER_VERSION})
            return 0
        map_raw = _read_pinned_file(args.map_input)
        source_raw = _read_pinned_file(args.source)
        map_acceptance = _decode_json(
            _read_pinned_file(args.map_acceptance), "MAP acceptance"
        )
        map_acceptance_keyring = _decode_json(
            _read_pinned_file(args.map_acceptance_keyring), "MAP acceptance keyring"
        )
        result = produce_c_fast_candidate(
            map_raw,
            source_raw,
            map_acceptance=map_acceptance,
            map_acceptance_keyring=map_acceptance_keyring,
            expected_map_sha256=args.expected_map_sha256,
            rejected_predecessor_sha256=args.reject_predecessor_sha256,
        )
        _create_only_atomic(args.output, result.raw)
        _cli_json({"status": "created", "producer_identity": CFAST_PRODUCER_IDENTITY, "version": CFAST_PRODUCER_VERSION, "candidate_id": result.payload["candidate_id"], "artifact_sha256": result.artifact_sha256, "map_predecessor_sha256": result.map_predecessor_sha256, "source_view_canonical_sha256": result.source_view_canonical_sha256})
        return 0
    except ProducerError as exc:
        _cli_json({"status": "not_ready", "producer_identity": CFAST_PRODUCER_IDENTITY, "error": str(exc)})
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised by image smoke
    raise SystemExit(main())
