"""Strict TargetPlan v3 start/dispatch quote evidence.

The proof is generated only inside Execution from the authenticated, read-only
formal tick projection.  It is deliberately separate from the immutable
creation proof carried by TargetPlan v3: creation evidence participates in the
plan identity, while this fresh proof admits one start or first dispatch only
within the immutable order limit.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
    TargetPlan,
    sha256_json,
    simnow_experimental_price_contract,
)

from .formal_tick_reader import (
    FORMAL_TICK_FUTURE_SKEW_SECONDS,
    FormalTickBinding,
    FormalTickRequest,
    read_simnow_continuous_v3_formal_tick_bindings,
)
from .models import SHA256_RE, UTC_RE, format_utc, validate_identifier

EXECUTION_START_QUOTE_PROOF_SCHEMA_VERSION = "web_bridge_execution_start_quote_proof_v1"

_PROOF_FIELDS = {
    "schema_version",
    "execution_run_id",
    "phase",
    "plan_id",
    "plan_hash",
    "creation_quote_proof_sha256",
    "validated_at_utc",
    "max_age_seconds",
    "future_skew_seconds",
    "journal_authenticated",
    "start_authorized",
    "bindings",
    "proof_sha256",
}
_BINDING_FIELDS = {
    "order_ref",
    "exact_contract",
    "offset",
    "execution_run_id",
    "phase",
    "plan_id",
    "plan_hash",
    "creation_quote_proof_sha256",
    "source",
    "vt_symbol",
    "price_side",
    "stream_generation",
    "ingest_id",
    "ingest_seq",
    "event_hash",
    "received_at_utc",
    "reference_price",
    "price_tick",
    "protected_price",
}


class ExecutionStartQuoteProofError(ValueError):
    """A start proof is malformed, foreign, or has been tampered with."""


class ExecutionStartQuotePriceIncompatible(ExecutionStartQuoteProofError):
    """The current protected price is outside the immutable order limit."""


@dataclass(frozen=True, slots=True)
class ExecutionStartQuoteProofV1:
    """Typed detached view of one strict v1 start/dispatch proof."""

    raw: dict[str, Any]

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        plan: TargetPlan | None = None,
        expected_order_refs: Sequence[str] | None = None,
    ) -> ExecutionStartQuoteProofV1:
        return cls(
            validate_execution_start_quote_proof(
                value, plan=plan, expected_order_refs=expected_order_refs
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return deepcopy(self.raw)

    @property
    def proof_sha256(self) -> str:
        return str(self.raw["proof_sha256"])


def _detached(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionStartQuoteProofError(f"{label} must be an object")
    try:
        return json.loads(
            json.dumps(
                dict(value),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (TypeError, ValueError) as exc:
        raise ExecutionStartQuoteProofError(f"{label} must be canonical JSON") from exc


def _decimal(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExecutionStartQuoteProofError(f"{label} is invalid")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ExecutionStartQuoteProofError(f"{label} is invalid") from exc
    if not result.is_finite():
        raise ExecutionStartQuoteProofError(f"{label} is invalid")
    return result


def _protected_price(binding: Mapping[str, Any]) -> Decimal:
    reference = _decimal(binding["reference_price"], "quote reference_price")
    tick = _decimal(binding["price_tick"], "quote price_tick")
    if reference <= 0 or tick <= 0 or reference % tick != 0:
        raise ExecutionStartQuoteProofError("quote price/tick is invalid")
    return reference + tick if binding["price_side"] == "ask" else reference - tick


def _protected_price_is_compatible(
    *, price_contract: str, direction: str, protected: Decimal, limit: Decimal
) -> bool:
    """Bounded experimental plans admit only their immutable limit range."""

    if price_contract == "BOUNDED":
        return protected <= limit if direction == "LONG" else protected >= limit
    return protected == limit


def _incompatible_price_message(price_contract: str) -> str:
    if price_contract == "BOUNDED":
        return "fresh protected price is outside immutable order limit"
    return "fresh protected price differs from immutable order price"


def validate_execution_start_quote_proof(
    value: Any,
    *,
    plan: TargetPlan | None = None,
    expected_order_refs: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Validate canonical proof bytes and, when supplied, the exact plan slice."""

    raw = _detached(value, "execution start quote proof")
    if set(raw) != _PROOF_FIELDS:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof fields are not exact"
        )
    if (
        raw["schema_version"] != EXECUTION_START_QUOTE_PROOF_SCHEMA_VERSION
        or type(raw["max_age_seconds"]) is not float
        or raw["max_age_seconds"]
        != V3_FORMAL_QUOTE_MAX_AGE_SECONDS
        or type(raw["future_skew_seconds"]) is not float
        or raw["future_skew_seconds"] != FORMAL_TICK_FUTURE_SKEW_SECONDS
        or raw["journal_authenticated"] is not True
        or raw["start_authorized"] is not True
        or raw["phase"] not in {"CLOSE", "OPEN"}
    ):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof policy is invalid"
        )
    for field in ("execution_run_id", "plan_id"):
        try:
            validate_identifier(raw[field], f"execution_start_quote_proof.{field}")
        except ValueError as exc:
            raise ExecutionStartQuoteProofError(str(exc)) from exc
    for field in ("plan_hash", "creation_quote_proof_sha256", "proof_sha256"):
        if not isinstance(raw[field], str) or not SHA256_RE.fullmatch(raw[field]):
            raise ExecutionStartQuoteProofError(
                f"execution start quote proof {field} is invalid"
            )
    if not isinstance(raw["validated_at_utc"], str) or not UTC_RE.fullmatch(
        raw["validated_at_utc"]
    ):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof timestamp is invalid"
        )
    validated_at = datetime.fromisoformat(raw["validated_at_utc"][:-1] + "+00:00")
    if raw["proof_sha256"] != sha256_json(
        {key: item for key, item in raw.items() if key != "proof_sha256"}
    ):
        raise ExecutionStartQuoteProofError("execution start quote proof hash mismatch")
    bindings = raw["bindings"]
    if not isinstance(bindings, Mapping) or not bindings:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof bindings are invalid"
        )
    for order_ref, binding in bindings.items():
        if not isinstance(binding, Mapping) or set(binding) != _BINDING_FIELDS:
            raise ExecutionStartQuoteProofError(
                "execution start quote binding fields are not exact"
            )
        if binding["order_ref"] != order_ref:
            raise ExecutionStartQuoteProofError(
                "execution start quote order identity mismatches"
            )
        for field in (
            "execution_run_id",
            "phase",
            "plan_id",
            "plan_hash",
            "creation_quote_proof_sha256",
        ):
            if binding[field] != raw[field]:
                raise ExecutionStartQuoteProofError(
                    "execution start quote binding lineage mismatches"
                )
        if (
            binding["source"] != "windows-tick-wire-v1"
            or binding["price_side"] not in {"ask", "bid"}
            or not isinstance(binding["stream_generation"], str)
            or not binding["stream_generation"]
            or not isinstance(binding["ingest_id"], str)
            or not binding["ingest_id"]
            or isinstance(binding["ingest_seq"], bool)
            or not isinstance(binding["ingest_seq"], int)
            or binding["ingest_seq"] < 1
            or not isinstance(binding["event_hash"], str)
            or not SHA256_RE.fullmatch(binding["event_hash"])
            or not isinstance(binding["received_at_utc"], str)
            or not UTC_RE.fullmatch(binding["received_at_utc"])
        ):
            raise ExecutionStartQuoteProofError(
                "execution start quote binding evidence is invalid"
            )
        received_at = datetime.fromisoformat(binding["received_at_utc"][:-1] + "+00:00")
        age = (validated_at - received_at).total_seconds()
        if (
            age > V3_FORMAL_QUOTE_MAX_AGE_SECONDS
            or age < -FORMAL_TICK_FUTURE_SKEW_SECONDS
        ):
            raise ExecutionStartQuoteProofError(
                "execution start quote binding is stale or from the future"
            )
        protected = _protected_price(binding)
        if protected <= 0 or protected != _decimal(
            binding["protected_price"], "quote protected_price"
        ):
            raise ExecutionStartQuoteProofError(
                "execution start quote protected price is invalid"
            )

    if plan is None:
        return raw
    if plan.raw["schema_version"] != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof requires TargetPlan v3"
        )
    expected_creation_hash = sha256_json(plan.raw["creation_quote_proof"])
    if (
        raw["execution_run_id"] != plan.raw["execution_run_id"]
        or raw["phase"] != plan.raw["phase"]
        or raw["plan_id"] != plan.plan_id
        or raw["plan_hash"] != plan.plan_hash
        or raw["creation_quote_proof_sha256"] != expected_creation_hash
    ):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof does not bind immutable plan"
        )
    wanted = tuple(expected_order_refs or (order.reference for order in plan.orders))
    if not wanted or len(set(wanted)) != len(wanted) or set(bindings) != set(wanted):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof order set is not exact"
        )
    by_ref = {order.reference: order for order in plan.orders}
    if set(wanted).difference(by_ref):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof names a foreign order"
        )
    price_contract = simnow_experimental_price_contract(
        execution_run_id=plan.raw["execution_run_id"],
        orders=plan.orders,
        bindings=plan.raw["creation_quote_proof"]["bindings"],
    )
    for order_ref in wanted:
        order = by_ref[order_ref]
        binding = bindings[order_ref]
        exact_contract = f"{order.exchange}.{order.symbol}"
        expected_side = "ask" if order.direction == "LONG" else "bid"
        if (
            binding["exact_contract"] != exact_contract
            or binding["vt_symbol"] != f"{order.symbol}.{order.exchange}"
            or binding["price_side"] != expected_side
            or binding["offset"] != order.offset
            or _decimal(binding["price_tick"], "quote price_tick")
            != _decimal(
                plan.raw["creation_quote_proof"]["bindings"][exact_contract][
                    "price_tick"
                ],
                "creation quote price_tick",
            )
        ):
            raise ExecutionStartQuoteProofError(
                "execution start quote binding does not match order"
            )
        if not _protected_price_is_compatible(
            price_contract=price_contract,
            direction=order.direction,
            protected=_decimal(binding["protected_price"], "quote protected_price"),
            limit=Decimal(str(order.price)),
        ):
            raise ExecutionStartQuotePriceIncompatible(
                _incompatible_price_message(price_contract)
            )
    return raw


def build_execution_start_quote_proof(
    plan: TargetPlan,
    *,
    order_refs: Sequence[str] | None = None,
    reader: Callable[
        [tuple[FormalTickRequest, ...]], tuple[FormalTickBinding, ...]
    ] = read_simnow_continuous_v3_formal_tick_bindings,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Read one atomic formal snapshot and bind it to exact immutable orders."""

    if plan.raw["schema_version"] != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof requires TargetPlan v3"
        )
    wanted = tuple(order_refs or (order.reference for order in plan.orders))
    by_ref = {order.reference: order for order in plan.orders}
    if not wanted or len(set(wanted)) != len(wanted) or set(wanted).difference(by_ref):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof order set is invalid"
        )
    requests_by_symbol: dict[str, FormalTickRequest] = {}
    for order_ref in wanted:
        order = by_ref[order_ref]
        vt_symbol = f"{order.symbol}.{order.exchange}"
        request = FormalTickRequest(
            vt_symbol=vt_symbol,
            price_side="ask" if order.direction == "LONG" else "bid",
            price_tick=float(
                plan.raw["creation_quote_proof"]["bindings"][
                    f"{order.exchange}.{order.symbol}"
                ]["price_tick"]
            ),
        )
        prior = requests_by_symbol.setdefault(vt_symbol, request)
        if prior != request:
            raise ExecutionStartQuoteProofError(
                "execution start quote proof contract use is ambiguous"
            )
    observed = reader(tuple(requests_by_symbol.values()))
    if (
        not isinstance(observed, tuple)
        or len(observed) != len(requests_by_symbol)
        or any(not isinstance(item, FormalTickBinding) for item in observed)
    ):
        raise ExecutionStartQuoteProofError(
            "formal tick reader returned an invalid binding set"
        )
    observed_by_symbol = {item.vt_symbol: item for item in observed}
    if set(observed_by_symbol) != set(requests_by_symbol):
        raise ExecutionStartQuoteProofError(
            "formal tick reader returned a foreign binding set"
        )
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ExecutionStartQuoteProofError("execution quote clock is invalid")
    creation_hash = sha256_json(plan.raw["creation_quote_proof"])
    price_contract = simnow_experimental_price_contract(
        execution_run_id=plan.raw["execution_run_id"],
        orders=plan.orders,
        bindings=plan.raw["creation_quote_proof"]["bindings"],
    )
    common = {
        "execution_run_id": plan.raw["execution_run_id"],
        "phase": plan.raw["phase"],
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash,
        "creation_quote_proof_sha256": creation_hash,
    }
    bindings: dict[str, Any] = {}
    for order_ref in wanted:
        order = by_ref[order_ref]
        tick = observed_by_symbol[f"{order.symbol}.{order.exchange}"]
        raw_tick = tick.as_dict()
        protected = _protected_price(raw_tick)
        if not _protected_price_is_compatible(
            price_contract=price_contract,
            direction=order.direction,
            protected=protected,
            limit=Decimal(str(order.price)),
        ):
            raise ExecutionStartQuotePriceIncompatible(
                _incompatible_price_message(price_contract)
            )
        bindings[order_ref] = {
            "order_ref": order_ref,
            "exact_contract": f"{order.exchange}.{order.symbol}",
            "offset": order.offset,
            **common,
            **raw_tick,
            "protected_price": float(protected),
        }
    preimage = {
        "schema_version": EXECUTION_START_QUOTE_PROOF_SCHEMA_VERSION,
        **common,
        "validated_at_utc": format_utc(now),
        "max_age_seconds": V3_FORMAL_QUOTE_MAX_AGE_SECONDS,
        "future_skew_seconds": FORMAL_TICK_FUTURE_SKEW_SECONDS,
        "journal_authenticated": True,
        "start_authorized": True,
        "bindings": bindings,
    }
    return validate_execution_start_quote_proof(
        {**preimage, "proof_sha256": sha256_json(preimage)},
        plan=plan,
        expected_order_refs=wanted,
    )


def quote_proof_for_order(
    proof: Mapping[str, Any], *, plan: TargetPlan, order_ref: str
) -> dict[str, Any]:
    """Validate a proof slice and return a detached exact-order binding."""

    raw = validate_execution_start_quote_proof(proof)
    raw = validate_execution_start_quote_proof(
        raw, plan=plan, expected_order_refs=tuple(raw["bindings"])
    )
    if order_ref not in raw["bindings"]:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof does not authorize this order"
        )
    preimage = {
        key: deepcopy(item) for key, item in raw.items() if key != "proof_sha256"
    }
    preimage["bindings"] = {order_ref: deepcopy(raw["bindings"][order_ref])}
    return validate_execution_start_quote_proof(
        {**preimage, "proof_sha256": sha256_json(preimage)},
        plan=plan,
        expected_order_refs=(order_ref,),
    )


def require_quote_proof_order_request(
    proof: Mapping[str, Any], request: Mapping[str, Any]
) -> dict[str, Any]:
    """Close a one-order proof against the exact broker request payload."""

    raw = validate_execution_start_quote_proof(proof)
    if not isinstance(request, Mapping) or len(raw["bindings"]) != 1:
        raise ExecutionStartQuoteProofError(
            "execution start quote proof is not one exact order"
        )
    order_ref, binding = next(iter(raw["bindings"].items()))
    direction = request.get("direction")
    expected_side = "ask" if direction == "LONG" else "bid"
    if (
        direction not in {"LONG", "SHORT"}
        or request.get("reference") != order_ref
        or binding["exact_contract"]
        != f"{request.get('exchange')}.{request.get('symbol')}"
        or binding["vt_symbol"] != f"{request.get('symbol')}.{request.get('exchange')}"
        or binding["price_side"] != expected_side
        or binding["offset"] != request.get("offset")
        or _decimal(binding["protected_price"], "quote protected_price")
        != _decimal(request.get("price"), "order price")
    ):
        raise ExecutionStartQuoteProofError(
            "execution start quote proof does not bind order request"
        )
    return raw


__all__ = [
    "EXECUTION_START_QUOTE_PROOF_SCHEMA_VERSION",
    "ExecutionStartQuotePriceIncompatible",
    "ExecutionStartQuoteProofError",
    "ExecutionStartQuoteProofV1",
    "build_execution_start_quote_proof",
    "quote_proof_for_order",
    "require_quote_proof_order_request",
    "validate_execution_start_quote_proof",
]
