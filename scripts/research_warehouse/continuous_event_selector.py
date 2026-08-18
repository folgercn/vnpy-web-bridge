"""Pure structural event-candidate selection contract for Issue #362.

The selector joins caller-carried monthly STATIC_CORE_EQUAL final-target bytes
with one structurally valid daily PIT-main artifact.  It has no filesystem,
launcher, custody, Execution, broker, RPC, or order dependency.  A selected
candidate is only an immutable input for a later root-verifying installer; it
is neither event-ready nor mutation authority.  In particular, a Python
dataclass and self-consistent hashes are not custody or current-root proof.

``MONTHLY_REBALANCE`` and ``ROLL_ONLY`` are deliberately exclusive.  A new
monthly target always wins on the same execution day and absorbs any daily
contract transition.  A standalone roll requires root-catalog linked daily
continuity plus a pinned terminal predecessor and preserves the complete
ten-product signed integer quantity vector byte-for-byte at the semantic
projection level.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import re
from typing import Any

import commodity_c_fast_pure_producer_kernel as frozen

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .m2_isolation_contracts import false_authority
from .verified_daily_pit_main_roll_source import (
    BuiltVerifiedDailyPitMainRollSource,
    validate_structural_daily_pit_main_roll_source,
)

SELECTION_SCHEMA_VERSION = "vnpy_continuous_event_selection_v1"
EVENT_SCHEMA_VERSION = "vnpy_continuous_event_candidate_v1"
FINAL_TARGET_SCHEMA_VERSION = "commodity_static_core_equal_final_target_projection_v1"
STRATEGY_ID = "STATIC_CORE_EQUAL"
EXECUTION_LANE = "simnow_shakedown"
MONTHLY_REBALANCE = "MONTHLY_REBALANCE"
ROLL_ONLY = "ROLL_ONLY"
PRECEDENCE_RULE_ID = "MONTHLY_OVER_SAME_DAY_ROLL_V1"
VERIFICATION_STATUS = "STRUCTURAL_ONLY_CURRENT_ROOT_AND_COMPLETION_PROOF_REQUIRED"
MAX_RAW_BYTES = 4 * 1024 * 1024
MAX_ABS_TARGET_QUANTITY = 500
_SHA = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_FINAL_TARGET_KEYS = {
    "schema_version",
    "strategy_id",
    "baseline_scheduler_id",
    "execution_lane",
    "candidate_weights",
    "c_sleeve_id",
    "c_map_rule_id",
    "d_sleeve_id",
    "sector_map_id",
    "position_manager_id",
    "source_month",
    "execution_day",
    "authority_granted",
    "dispatch_allowed",
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
    "targets",
}
_FINAL_TARGET_ROW_KEYS = {
    "product",
    "sector",
    "exact_contract",
    "target_quantity",
    "reference_open_price",
    "multiplier",
    "price_tick",
}
_FALSE_TOP_LEVEL_FIELDS = (
    "production_allowed",
    "live_trading_authorized",
    "countable_forward",
    "official_forward_claimed",
    "dispatch_authorized",
    "order_authorized",
    "position_mutation_authorized",
)


class ContinuousEventSelectorError(RegistryError):
    """A candidate set cannot safely produce one continuous event."""


@dataclass(frozen=True, slots=True)
class MonthlyFinalTargetCandidate:
    """Canonical final-target bytes and caller-carried replay lineage hashes.

    This typed value is intentionally *not* proof.  The selector checks its
    canonical shape and binds the hashes into a structural candidate, but only
    a later root-verifying installer may independently replay the sources and
    turn that candidate into an event-ready artifact.
    """

    final_target_raw: bytes
    static_core_equal_sha256: str
    position_manager_sha256: str
    baseline_batch_raw_sha256: str


@dataclass(frozen=True, slots=True)
class TerminalPredecessorPinCandidate:
    """Caller-carried terminal pin; not an Execution completion proof."""

    terminal_target_id: str
    terminal_target_raw_sha256: str
    monthly_final_target_sha256: str
    quantity_vector_sha256: str
    exact_contract_map_sha256: str
    execution_day: str


@dataclass(frozen=True, slots=True)
class BuiltContinuousEventSelection:
    selection_raw: bytes
    selection_id: str
    selection_sha256: str
    candidate_set_sha256: str
    event_candidate_raw: bytes | None
    event_candidate_id: str | None
    selected_trigger_kind: str | None


def _bounded_raw(value: object, label: str) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > MAX_RAW_BYTES:
        raise ContinuousEventSelectorError(f"{label} resource limit exceeded")
    return value


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ContinuousEventSelectorError(f"{label} is not a SHA-256")
    return value


def _require_stable_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise ContinuousEventSelectorError(f"{label} is invalid")
    return value


def _require_day(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise ContinuousEventSelectorError(f"{label} is invalid")
    try:
        result = date.fromisoformat(value)
    except ValueError as exc:
        raise ContinuousEventSelectorError(f"{label} is invalid") from exc
    if result.isoformat() != value:
        raise ContinuousEventSelectorError(f"{label} is not canonical")
    return result


def _exact_contract(value: object, *, product: str) -> str:
    if not isinstance(value, str):
        raise ContinuousEventSelectorError(f"{product} exact contract is invalid")
    spec = frozen.PRODUCT_SPECS[product]
    match = frozen.CONTRACT_PATTERN.fullmatch(value)
    if (
        match is None
        or match.group(1) != spec["exchange"]
        or match.group(2) != product
        or not 1 <= int(value[-2:]) <= 12
    ):
        raise ContinuousEventSelectorError(f"{product} exact contract is invalid")
    return value


def _ordered_contract_map(rows: list[dict[str, Any]], field: str) -> dict[str, str]:
    if len(rows) != len(frozen.PRODUCTS):
        raise ContinuousEventSelectorError("daily exact-contract map is incomplete")
    result: dict[str, str] = {}
    for index, product in enumerate(frozen.PRODUCTS):
        row = rows[index]
        if not isinstance(row, dict) or row.get("product") != product:
            raise ContinuousEventSelectorError(
                "daily exact-contract products are incomplete or reordered"
            )
        result[product] = _exact_contract(row.get(field), product=product)
    return result


def _contract_map_sha(value: dict[str, str]) -> str:
    return sha256(
        canonical_json(
            [
                {"product": product, "exact_contract": value[product]}
                for product in frozen.PRODUCTS
            ]
        )
    )


def _quantity_vector_sha(value: dict[str, int]) -> str:
    return sha256(
        canonical_json(
            [
                {"product": product, "target_quantity": value[product]}
                for product in frozen.PRODUCTS
            ]
        )
    )


def _target_input(
    value: MonthlyFinalTargetCandidate,
    *,
    label: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str, str]:
    if not isinstance(value, MonthlyFinalTargetCandidate):
        raise ContinuousEventSelectorError(f"{label} must be typed candidate input")
    raw = _bounded_raw(value.final_target_raw, f"{label} final target")
    payload = parse_json_strict(raw, f"{label} final target")
    if (
        not isinstance(payload, dict)
        or set(payload) != _FINAL_TARGET_KEYS
        or raw != canonical_json_line(payload)
    ):
        raise ContinuousEventSelectorError(f"{label} final target is not canonical")
    for field, expected in (
        ("schema_version", FINAL_TARGET_SCHEMA_VERSION),
        ("strategy_id", STRATEGY_ID),
        ("baseline_scheduler_id", STRATEGY_ID),
        ("execution_lane", EXECUTION_LANE),
        ("candidate_weights", {"C": 0.5, "D": 0.5}),
        ("c_sleeve_id", "C_FAST_CROSS_SECTION_NEUTRAL"),
        ("c_map_rule_id", "commodity_fast_tsmom_forward_freeze_v1"),
        ("d_sleeve_id", "D_DONCHIAN20_EXIT10_NEUTRAL"),
        ("sector_map_id", "COMMODITY_FROZEN_SECTOR_MAP_V1"),
        ("position_manager_id", "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1"),
    ):
        if payload.get(field) != expected:
            raise ContinuousEventSelectorError(f"{label} frozen identity mismatch")
    if any(
        payload.get(field) is not False
        for field in (
            "authority_granted",
            "dispatch_allowed",
            "production_allowed",
            "live_trading_authorized",
            "countable_forward",
        )
    ):
        raise ContinuousEventSelectorError(f"{label} attempts to grant authority")
    source_month = payload.get("source_month")
    if not isinstance(source_month, str) or len(source_month) != 7:
        raise ContinuousEventSelectorError(f"{label} source month is invalid")
    try:
        if date.fromisoformat(f"{source_month}-01").strftime("%Y-%m") != source_month:
            raise ValueError
    except ValueError as exc:
        raise ContinuousEventSelectorError(f"{label} source month is invalid") from exc
    _require_day(payload.get("execution_day"), f"{label} execution day")
    rows = payload.get("targets")
    if not isinstance(rows, list) or len(rows) != len(frozen.PRODUCTS):
        raise ContinuousEventSelectorError(
            f"{label} must contain the frozen ten targets"
        )
    by_product: dict[str, dict[str, Any]] = {}
    for index, product in enumerate(frozen.PRODUCTS):
        row = rows[index]
        if (
            not isinstance(row, dict)
            or set(row) != _FINAL_TARGET_ROW_KEYS
            or row.get("product") != product
            or row.get("sector") != frozen.SECTOR_MAP[product]
        ):
            raise ContinuousEventSelectorError(
                f"{label} targets are incomplete or reordered"
            )
        _exact_contract(row.get("exact_contract"), product=product)
        quantity = row.get("target_quantity")
        if (
            isinstance(quantity, bool)
            or not isinstance(quantity, int)
            or abs(quantity) > MAX_ABS_TARGET_QUANTITY
        ):
            raise ContinuousEventSelectorError(f"{label} quantity is invalid")
        for field in ("reference_open_price", "multiplier", "price_tick"):
            number = row.get(field)
            if (
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or number <= 0
            ):
                raise ContinuousEventSelectorError(
                    f"{label} contract economics are invalid"
                )
        by_product[product] = row
    _require_sha(value.static_core_equal_sha256, f"{label} STATIC_CORE_EQUAL hash")
    _require_sha(value.position_manager_sha256, f"{label} position-manager hash")
    _require_sha(value.baseline_batch_raw_sha256, f"{label} baseline batch hash")
    final_sha = sha256(canonical_json(payload))
    return (
        payload,
        by_product,
        final_sha,
        _quantity_vector_sha(
            {
                product: int(by_product[product]["target_quantity"])
                for product in frozen.PRODUCTS
            }
        ),
    )


def _terminal_input(
    value: TerminalPredecessorPinCandidate,
) -> TerminalPredecessorPinCandidate:
    if not isinstance(value, TerminalPredecessorPinCandidate):
        raise ContinuousEventSelectorError(
            "ROLL_ONLY requires one verified terminal predecessor"
        )
    _require_stable_id(value.terminal_target_id, "terminal predecessor target ID")
    for field, label in (
        (value.terminal_target_raw_sha256, "terminal predecessor raw hash"),
        (value.monthly_final_target_sha256, "terminal monthly target hash"),
        (value.quantity_vector_sha256, "terminal quantity-vector hash"),
        (value.exact_contract_map_sha256, "terminal exact-contract-map hash"),
    ):
        _require_sha(field, label)
    _require_day(value.execution_day, "terminal predecessor execution day")
    return value


def _candidate_id(payload: dict[str, Any]) -> str:
    return "continuous-candidate-" + sha256(
        canonical_json({**payload, "candidate_id": ""})
    )


def _event_id(payload: dict[str, Any]) -> str:
    return "continuous-event-" + sha256(canonical_json({**payload, "event_id": ""}))


def _candidate(
    *,
    trigger_kind: str,
    daily: dict[str, Any],
    target_input: MonthlyFinalTargetCandidate,
    target_payload: dict[str, Any],
    target_rows: dict[str, dict[str, Any]],
    final_target_sha256: str,
    quantity_vector_sha256: str,
    previous_contracts: dict[str, str],
    current_contracts: dict[str, str],
    predecessor: TerminalPredecessorPinCandidate | None,
) -> dict[str, Any]:
    roll_only = trigger_kind == ROLL_ONLY
    targets = []
    for product in frozen.PRODUCTS:
        quantity = int(target_rows[product]["target_quantity"])
        previous_contract = previous_contracts[product]
        current_contract = current_contracts[product]
        targets.append(
            {
                "product": product,
                "previous_exact_contract": previous_contract,
                "exact_contract": current_contract,
                "previous_target_quantity": quantity if roll_only else None,
                "target_quantity": quantity,
                "exact_contract_changed": previous_contract != current_contract,
            }
        )
    payload: dict[str, Any] = {
        "candidate_id": "",
        "trigger_kind": trigger_kind,
        "strategy_id": STRATEGY_ID,
        "execution_lane": EXECUTION_LANE,
        "execution_day": daily["execution_day"],
        "source_month": target_payload["source_month"],
        "verified_daily_artifact_id": daily["artifact_id"],
        "verified_daily_artifact_raw_sha256": daily["_raw_sha256"],
        "verified_daily_continuity_mode": daily["verified_lineage"]["continuity"][
            "mode"
        ],
        "static_core_equal_sha256": target_input.static_core_equal_sha256,
        "position_manager_sha256": target_input.position_manager_sha256,
        "monthly_final_target_sha256": final_target_sha256,
        "baseline_batch_raw_sha256": target_input.baseline_batch_raw_sha256,
        "quantity_vector_sha256": quantity_vector_sha256,
        "previous_exact_contract_map_sha256": _contract_map_sha(previous_contracts),
        "exact_contract_map_sha256": _contract_map_sha(current_contracts),
        "roll_preserves_integer_lots": roll_only,
        "predecessor_terminal_target_id": (
            predecessor.terminal_target_id if predecessor is not None else None
        ),
        "predecessor_terminal_target_raw_sha256": (
            predecessor.terminal_target_raw_sha256 if predecessor is not None else None
        ),
        "targets": targets,
    }
    payload["candidate_id"] = _candidate_id(payload)
    return payload


def _false_boundary() -> dict[str, Any]:
    return {
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "dispatch_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "authority": false_authority(),
    }


def build_continuous_event_candidate_selection(
    *,
    verified_daily_artifact: BuiltVerifiedDailyPitMainRollSource,
    monthly_candidate: MonthlyFinalTargetCandidate | None = None,
    predecessor_monthly_target: MonthlyFinalTargetCandidate | None = None,
    predecessor_terminal: TerminalPredecessorPinCandidate | None = None,
) -> BuiltContinuousEventSelection:
    """Select at most one structural candidate, permanently not event-ready."""

    if not isinstance(
        verified_daily_artifact,
        BuiltVerifiedDailyPitMainRollSource,
    ):
        raise ContinuousEventSelectorError(
            "daily artifact must be typed verified-construction output"
        )
    raw = _bounded_raw(
        verified_daily_artifact.artifact_raw,
        "verified daily artifact",
    )
    try:
        daily = validate_structural_daily_pit_main_roll_source(raw)
    except RegistryError as exc:
        raise ContinuousEventSelectorError(str(exc)) from exc
    if not isinstance(daily, dict):  # pragma: no cover - validator contract
        raise ContinuousEventSelectorError("verified daily artifact is invalid")
    # The explicitly unverified v1 detector cannot reach this validator.  Keep
    # the consumer-side identity gate as a second, stable fail-closed boundary.
    if (
        daily.get("schema_version")
        != "vnpy_research_commodity_verified_daily_pit_main_roll_source_v2"
        or daily.get("input_lineage_status") != "VERIFIED_AT_CONSTRUCTION_V2"
        or daily.get("execution_lane") != EXECUTION_LANE
        or daily.get("authority") != false_authority()
    ):
        raise ContinuousEventSelectorError("daily artifact is not verified v2")
    if verified_daily_artifact.artifact_id != daily.get(
        "artifact_id"
    ) or verified_daily_artifact.artifact_raw_sha256 != sha256(raw):
        raise ContinuousEventSelectorError(
            "typed daily artifact identity does not match its verified bytes"
        )
    daily = dict(daily)
    daily["_raw_sha256"] = sha256(raw)
    official_day = _require_day(daily["official_day"], "daily official day")
    execution_day = _require_day(daily["execution_day"], "daily execution day")
    if not official_day < execution_day:
        raise ContinuousEventSelectorError("daily event-day ordering is invalid")
    previous_contracts = _ordered_contract_map(
        daily["mains"], "previous_exact_contract"
    )
    current_contracts = _ordered_contract_map(daily["mains"], "exact_contract")
    continuity = daily["verified_lineage"]["continuity"]
    if continuity.get("predecessor_exact_contract_map_sha256") != _contract_map_sha(
        previous_contracts
    ):
        raise ContinuousEventSelectorError("daily predecessor map binding mismatch")

    candidates: list[dict[str, Any]] = []
    observed_trigger_kinds: list[str] = []
    suppressed_trigger_kinds: list[str] = []
    monthly_precedence_applied = False

    if monthly_candidate is not None:
        monthly_payload, monthly_rows, monthly_final_sha, monthly_quantity_sha = (
            _target_input(monthly_candidate, label="monthly candidate")
        )
        if (
            _require_day(
                monthly_payload["execution_day"], "monthly candidate execution day"
            )
            != official_day
        ):
            raise ContinuousEventSelectorError(
                "monthly target does not belong to the daily official day"
            )
        target_contracts = {
            product: _exact_contract(
                monthly_rows[product]["exact_contract"], product=product
            )
            for product in frozen.PRODUCTS
        }
        if target_contracts != current_contracts:
            raise ContinuousEventSelectorError(
                "monthly target exact contracts do not match verified daily PIT main"
            )
        if continuity.get("mode") == "GENESIS_STATIC_CORE_EQUAL" and (
            monthly_candidate.baseline_batch_raw_sha256
            != continuity.get("baseline_batch_raw_sha256")
        ):
            raise ContinuousEventSelectorError(
                "monthly target does not bind the verified Genesis baseline"
            )
        candidates.append(
            _candidate(
                trigger_kind=MONTHLY_REBALANCE,
                daily=daily,
                target_input=monthly_candidate,
                target_payload=monthly_payload,
                target_rows=monthly_rows,
                final_target_sha256=monthly_final_sha,
                quantity_vector_sha256=monthly_quantity_sha,
                previous_contracts=previous_contracts,
                current_contracts=current_contracts,
                predecessor=None,
            )
        )
        observed_trigger_kinds.append(MONTHLY_REBALANCE)
        if daily["roll_change_detected"]:
            observed_trigger_kinds.append(ROLL_ONLY)
            suppressed_trigger_kinds.append(ROLL_ONLY)
            monthly_precedence_applied = True
    elif continuity.get("mode") == "GENESIS_STATIC_CORE_EQUAL":
        raise ContinuousEventSelectorError(
            "verified Genesis daily artifact requires its monthly target"
        )
    elif daily["roll_change_detected"]:
        if continuity.get("mode") != "LINKED_ROOT_CATALOG":
            raise ContinuousEventSelectorError(
                "ROLL_ONLY requires root-catalog linked daily continuity"
            )
        if predecessor_monthly_target is None or predecessor_terminal is None:
            raise ContinuousEventSelectorError(
                "ROLL_ONLY lacks its monthly or terminal predecessor"
            )
        predecessor_payload, predecessor_rows, predecessor_final_sha, quantity_sha = (
            _target_input(
                predecessor_monthly_target,
                label="ROLL_ONLY predecessor monthly target",
            )
        )
        terminal = _terminal_input(predecessor_terminal)
        if (
            terminal.monthly_final_target_sha256 != predecessor_final_sha
            or terminal.quantity_vector_sha256 != quantity_sha
            or terminal.exact_contract_map_sha256
            != _contract_map_sha(previous_contracts)
            or _require_day(
                predecessor_payload["execution_day"],
                "ROLL_ONLY monthly target execution day",
            )
            >= official_day
            or _require_day(
                terminal.execution_day, "terminal predecessor execution day"
            )
            >= execution_day
        ):
            raise ContinuousEventSelectorError(
                "ROLL_ONLY predecessor terminal target binding mismatch"
            )
        candidates.append(
            _candidate(
                trigger_kind=ROLL_ONLY,
                daily=daily,
                target_input=predecessor_monthly_target,
                target_payload=predecessor_payload,
                target_rows=predecessor_rows,
                final_target_sha256=predecessor_final_sha,
                quantity_vector_sha256=quantity_sha,
                previous_contracts=previous_contracts,
                current_contracts=current_contracts,
                predecessor=terminal,
            )
        )
        observed_trigger_kinds.append(ROLL_ONLY)

    if len(candidates) > 1:  # defensive; precedence is resolved before this point
        raise ContinuousEventSelectorError("trigger candidates are not exclusive")
    candidate_set_sha = sha256(canonical_json(candidates))
    selected = candidates[0] if candidates else None
    selection_core = {
        "strategy_id": STRATEGY_ID,
        "execution_lane": EXECUTION_LANE,
        "execution_day": execution_day.isoformat(),
        "precedence_rule_id": PRECEDENCE_RULE_ID,
        "verified_daily_artifact_id": daily["artifact_id"],
        "verified_daily_artifact_raw_sha256": daily["_raw_sha256"],
        "candidate_set_sha256": candidate_set_sha,
        "candidate_ids": [candidate["candidate_id"] for candidate in candidates],
        "observed_trigger_kinds": observed_trigger_kinds,
        "selected_candidate_id": selected["candidate_id"] if selected else None,
        "selected_trigger_kind": selected["trigger_kind"] if selected else None,
        "suppressed_trigger_kinds": suppressed_trigger_kinds,
        "monthly_precedence_applied": monthly_precedence_applied,
    }
    selection_sha = sha256(canonical_json(selection_core))
    selection_id = f"continuous-selection-{selection_sha}"

    event_candidate_raw: bytes | None = None
    event_candidate_id: str | None = None
    event_candidate_raw_sha: str | None = None
    if selected is not None:
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_id": "",
            "selection_id": selection_id,
            "selection_sha256": selection_sha,
            "candidate_set_sha256": candidate_set_sha,
            "candidate": selected,
            "verification_status": VERIFICATION_STATUS,
            "event_ready": False,
            "installable": False,
            **_false_boundary(),
        }
        event["event_id"] = _event_id(event)
        event_candidate_raw = canonical_json_line(event)
        event_candidate_id = event["event_id"]
        event_candidate_raw_sha = sha256(event_candidate_raw)

    selection = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "selection_id": selection_id,
        "selection_sha256": selection_sha,
        **selection_core,
        "candidates": candidates,
        "event_candidate_id": event_candidate_id,
        "event_candidate_raw_sha256": event_candidate_raw_sha,
        "verification_status": VERIFICATION_STATUS,
        "event_ready": False,
        "installable": False,
        **_false_boundary(),
    }
    selection_raw = canonical_json_line(selection)
    validate_continuous_event_selection(selection_raw)
    if event_candidate_raw is not None:
        validate_continuous_event_candidate(
            event_candidate_raw,
            expected_selection_raw=selection_raw,
        )
    return BuiltContinuousEventSelection(
        selection_raw=selection_raw,
        selection_id=selection_id,
        selection_sha256=selection_sha,
        candidate_set_sha256=candidate_set_sha,
        event_candidate_raw=event_candidate_raw,
        event_candidate_id=event_candidate_id,
        selected_trigger_kind=(selected["trigger_kind"] if selected else None),
    )


def _require_false_boundary(payload: dict[str, Any], label: str) -> None:
    if (
        any(payload.get(field) is not False for field in _FALSE_TOP_LEVEL_FIELDS)
        or payload.get("authority") != false_authority()
    ):
        raise ContinuousEventSelectorError(f"{label} attempts to grant authority")


def _validate_candidate(candidate: object) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ContinuousEventSelectorError("continuous candidate is invalid")
    expected_keys = {
        "candidate_id",
        "trigger_kind",
        "strategy_id",
        "execution_lane",
        "execution_day",
        "source_month",
        "verified_daily_artifact_id",
        "verified_daily_artifact_raw_sha256",
        "verified_daily_continuity_mode",
        "static_core_equal_sha256",
        "position_manager_sha256",
        "monthly_final_target_sha256",
        "baseline_batch_raw_sha256",
        "quantity_vector_sha256",
        "previous_exact_contract_map_sha256",
        "exact_contract_map_sha256",
        "roll_preserves_integer_lots",
        "predecessor_terminal_target_id",
        "predecessor_terminal_target_raw_sha256",
        "targets",
    }
    if (
        set(candidate) != expected_keys
        or candidate.get("trigger_kind") not in {MONTHLY_REBALANCE, ROLL_ONLY}
        or candidate.get("strategy_id") != STRATEGY_ID
        or candidate.get("execution_lane") != EXECUTION_LANE
        or candidate.get("verified_daily_continuity_mode")
        not in {"GENESIS_STATIC_CORE_EQUAL", "LINKED_ROOT_CATALOG"}
        or candidate.get("candidate_id") != _candidate_id(candidate)
    ):
        raise ContinuousEventSelectorError("continuous candidate identity mismatch")
    _require_stable_id(
        candidate["verified_daily_artifact_id"],
        "candidate daily artifact ID",
    )
    source_month = candidate["source_month"]
    if not isinstance(source_month, str) or len(source_month) != 7:
        raise ContinuousEventSelectorError("candidate source month is invalid")
    try:
        if date.fromisoformat(f"{source_month}-01").strftime("%Y-%m") != source_month:
            raise ValueError
    except ValueError as exc:
        raise ContinuousEventSelectorError("candidate source month is invalid") from exc
    _require_day(candidate["execution_day"], "candidate execution day")
    for field in (
        "verified_daily_artifact_raw_sha256",
        "static_core_equal_sha256",
        "position_manager_sha256",
        "monthly_final_target_sha256",
        "baseline_batch_raw_sha256",
        "quantity_vector_sha256",
        "previous_exact_contract_map_sha256",
        "exact_contract_map_sha256",
    ):
        _require_sha(candidate[field], f"candidate {field}")
    targets = candidate.get("targets")
    if not isinstance(targets, list) or len(targets) != len(frozen.PRODUCTS):
        raise ContinuousEventSelectorError("candidate target set is incomplete")
    quantities: dict[str, int] = {}
    previous_map: dict[str, str] = {}
    current_map: dict[str, str] = {}
    changed = 0
    roll_only = candidate["trigger_kind"] == ROLL_ONLY
    for index, product in enumerate(frozen.PRODUCTS):
        row = targets[index]
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "product",
                "previous_exact_contract",
                "exact_contract",
                "previous_target_quantity",
                "target_quantity",
                "exact_contract_changed",
            }
            or row.get("product") != product
        ):
            raise ContinuousEventSelectorError("candidate target rows are invalid")
        previous_map[product] = _exact_contract(
            row["previous_exact_contract"], product=product
        )
        current_map[product] = _exact_contract(row["exact_contract"], product=product)
        quantity = row["target_quantity"]
        if isinstance(quantity, bool) or not isinstance(quantity, int):
            raise ContinuousEventSelectorError("candidate quantity is invalid")
        quantities[product] = quantity
        is_changed = previous_map[product] != current_map[product]
        if row["exact_contract_changed"] is not is_changed:
            raise ContinuousEventSelectorError("candidate changed flag mismatch")
        changed += int(is_changed)
        if roll_only and row["previous_target_quantity"] != quantity:
            raise ContinuousEventSelectorError(
                "ROLL_ONLY changed the predecessor quantity vector"
            )
        if not roll_only and row["previous_target_quantity"] is not None:
            raise ContinuousEventSelectorError(
                "MONTHLY_REBALANCE has roll-only predecessor quantity fields"
            )
    if (
        candidate["quantity_vector_sha256"] != _quantity_vector_sha(quantities)
        or candidate["previous_exact_contract_map_sha256"]
        != _contract_map_sha(previous_map)
        or candidate["exact_contract_map_sha256"] != _contract_map_sha(current_map)
    ):
        raise ContinuousEventSelectorError("candidate vector/map hash mismatch")
    if roll_only:
        if (
            changed == 0
            or candidate["roll_preserves_integer_lots"] is not True
            or not isinstance(candidate["predecessor_terminal_target_id"], str)
            or not isinstance(candidate["predecessor_terminal_target_raw_sha256"], str)
        ):
            raise ContinuousEventSelectorError("ROLL_ONLY contract mismatch")
        _require_stable_id(
            candidate["predecessor_terminal_target_id"],
            "candidate predecessor target ID",
        )
        _require_sha(
            candidate["predecessor_terminal_target_raw_sha256"],
            "candidate predecessor target raw hash",
        )
    elif (
        candidate["roll_preserves_integer_lots"] is not False
        or candidate["predecessor_terminal_target_id"] is not None
        or candidate["predecessor_terminal_target_raw_sha256"] is not None
    ):
        raise ContinuousEventSelectorError("MONTHLY_REBALANCE contract mismatch")
    return candidate


def validate_continuous_event_selection(raw: bytes) -> dict[str, Any]:
    """Validate canonical selection bytes and every stable identity/hash."""

    bounded = _bounded_raw(raw, "continuous event selection")
    payload = parse_json_strict(bounded, "continuous event selection")
    expected_keys = {
        "schema_version",
        "selection_id",
        "selection_sha256",
        "strategy_id",
        "execution_lane",
        "execution_day",
        "precedence_rule_id",
        "verified_daily_artifact_id",
        "verified_daily_artifact_raw_sha256",
        "candidate_set_sha256",
        "candidate_ids",
        "observed_trigger_kinds",
        "selected_candidate_id",
        "selected_trigger_kind",
        "suppressed_trigger_kinds",
        "monthly_precedence_applied",
        "candidates",
        "event_candidate_id",
        "event_candidate_raw_sha256",
        "verification_status",
        "event_ready",
        "installable",
        *_FALSE_TOP_LEVEL_FIELDS,
        "authority",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or bounded != canonical_json_line(payload)
        or payload.get("schema_version") != SELECTION_SCHEMA_VERSION
        or payload.get("strategy_id") != STRATEGY_ID
        or payload.get("execution_lane") != EXECUTION_LANE
        or payload.get("precedence_rule_id") != PRECEDENCE_RULE_ID
        or payload.get("verification_status") != VERIFICATION_STATUS
    ):
        raise ContinuousEventSelectorError("continuous selection contract mismatch")
    _require_false_boundary(payload, "continuous selection")
    _require_day(payload["execution_day"], "selection execution day")
    _require_sha(
        payload["verified_daily_artifact_raw_sha256"],
        "selection daily artifact hash",
    )
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 1:
        raise ContinuousEventSelectorError("selection candidates are not exclusive")
    for candidate in candidates:
        _validate_candidate(candidate)
    candidate_ids = [candidate["candidate_id"] for candidate in candidates]
    candidate_set_sha = sha256(canonical_json(candidates))
    if (
        payload["candidate_ids"] != candidate_ids
        or payload["candidate_set_sha256"] != candidate_set_sha
    ):
        raise ContinuousEventSelectorError("selection candidate-set hash mismatch")
    selected = candidates[0] if candidates else None
    if selected is not None and (
        selected["execution_day"] != payload["execution_day"]
        or selected["verified_daily_artifact_id"]
        != payload["verified_daily_artifact_id"]
        or selected["verified_daily_artifact_raw_sha256"]
        != payload["verified_daily_artifact_raw_sha256"]
    ):
        raise ContinuousEventSelectorError("selection/daily candidate binding mismatch")
    selection_core = {
        "strategy_id": STRATEGY_ID,
        "execution_lane": EXECUTION_LANE,
        "execution_day": payload["execution_day"],
        "precedence_rule_id": PRECEDENCE_RULE_ID,
        "verified_daily_artifact_id": payload["verified_daily_artifact_id"],
        "verified_daily_artifact_raw_sha256": payload[
            "verified_daily_artifact_raw_sha256"
        ],
        "candidate_set_sha256": candidate_set_sha,
        "candidate_ids": candidate_ids,
        "observed_trigger_kinds": payload["observed_trigger_kinds"],
        "selected_candidate_id": selected["candidate_id"] if selected else None,
        "selected_trigger_kind": selected["trigger_kind"] if selected else None,
        "suppressed_trigger_kinds": payload["suppressed_trigger_kinds"],
        "monthly_precedence_applied": payload["monthly_precedence_applied"],
    }
    selection_sha = sha256(canonical_json(selection_core))
    if (
        payload["selection_sha256"] != selection_sha
        or payload["selection_id"] != f"continuous-selection-{selection_sha}"
        or payload["selected_candidate_id"] != selection_core["selected_candidate_id"]
        or payload["selected_trigger_kind"] != selection_core["selected_trigger_kind"]
        or payload["event_ready"] is not False
        or payload["installable"] is not False
    ):
        raise ContinuousEventSelectorError("continuous selection identity mismatch")
    observed = payload["observed_trigger_kinds"]
    suppressed = payload["suppressed_trigger_kinds"]
    if not isinstance(observed, list) or not isinstance(suppressed, list):
        raise ContinuousEventSelectorError("selection trigger audit is invalid")
    if payload["monthly_precedence_applied"]:
        if (
            selected is None
            or selected["trigger_kind"] != MONTHLY_REBALANCE
            or observed != [MONTHLY_REBALANCE, ROLL_ONLY]
            or suppressed != [ROLL_ONLY]
        ):
            raise ContinuousEventSelectorError("monthly precedence audit mismatch")
    elif suppressed:
        raise ContinuousEventSelectorError("unexpected suppressed trigger")
    elif observed != ([selected["trigger_kind"]] if selected else []):
        raise ContinuousEventSelectorError("selection observed trigger audit mismatch")
    if selected is None:
        if any(
            payload[field] is not None
            for field in ("event_candidate_id", "event_candidate_raw_sha256")
        ):
            raise ContinuousEventSelectorError("NO_EVENT carries event identity")
    else:
        if not isinstance(payload["event_candidate_id"], str):
            raise ContinuousEventSelectorError("selected event candidate ID is missing")
        _require_stable_id(payload["event_candidate_id"], "selected event candidate ID")
        _require_sha(
            payload["event_candidate_raw_sha256"],
            "selected event candidate raw hash",
        )
    return payload


def validate_continuous_event_candidate(
    raw: bytes,
    *,
    expected_selection_raw: bytes,
) -> dict[str, Any]:
    """Verify candidate bytes against selection; never grant readiness."""

    selection = validate_continuous_event_selection(expected_selection_raw)
    bounded = _bounded_raw(raw, "continuous executable event")
    event = parse_json_strict(bounded, "continuous executable event")
    expected_keys = {
        "schema_version",
        "event_id",
        "selection_id",
        "selection_sha256",
        "candidate_set_sha256",
        "candidate",
        "verification_status",
        "event_ready",
        "installable",
        *_FALSE_TOP_LEVEL_FIELDS,
        "authority",
    }
    if (
        not isinstance(event, dict)
        or set(event) != expected_keys
        or bounded != canonical_json_line(event)
        or event.get("schema_version") != EVENT_SCHEMA_VERSION
        or event.get("verification_status") != VERIFICATION_STATUS
        or event.get("event_ready") is not False
        or event.get("installable") is not False
        or event.get("event_id") != _event_id(event)
        or event.get("selection_id") != selection["selection_id"]
        or event.get("selection_sha256") != selection["selection_sha256"]
        or event.get("candidate_set_sha256") != selection["candidate_set_sha256"]
        or event.get("candidate")
        != (selection["candidates"][0] if selection["candidates"] else None)
        or selection.get("event_candidate_id") != event.get("event_id")
        or selection.get("event_candidate_raw_sha256") != sha256(bounded)
    ):
        raise ContinuousEventSelectorError(
            "continuous event/selection binding mismatch"
        )
    _require_false_boundary(event, "continuous executable event")
    _validate_candidate(event["candidate"])
    return event
