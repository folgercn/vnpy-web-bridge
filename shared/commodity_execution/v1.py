"""Strict, immutable, non-authoritative SIMNOW target-plan contracts.

Plans bind the exact custody receipt fingerprint and its trust material.  They
are *not* an authority: all three authority flags are deliberately false and
the Execution process must still enforce its own lifecycle, fencing and
explicit local SIMNOW gate before it can call the Windows gateway.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

TARGET_PLAN_SCHEMA_VERSION = "web-bridge-simnow-target-plan-v1"
KEYLESS_TARGET_PLAN_SCHEMA_VERSION = "web-bridge-simnow-keyless-target-plan-v1"
KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION = "web-bridge-simnow-keyless-target-plan-v2"
KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION = "web-bridge-simnow-keyless-target-plan-v3"
FORMAL_QUOTE_PROOF_SCHEMA_VERSION = "web-bridge-formal-quote-proof-v1"
_KEYLESS_TARGET_PLAN_SCHEMA_VERSIONS = frozenset(
    {
        KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
        KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    }
)
TRUSTED_KEYLESS_SIMNOW_SCOPE = {
    "account_scope": "account:windows",
    "environment": "SIMNOW",
    "gateway_name": "CTP",
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_KEY_VERSION_RE = re.compile(r"^v[0-9]+$")
# TargetPlan orders are sent directly to vn.py.  CTP registers commodity
# symbols using their native lower-case spelling (for example, ``ru2609``),
# while snapshots remain normalized independently for position projections.
_SYMBOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")
_EXACT_COMMODITY_SYMBOL_RE = re.compile(r"^[A-Za-z]+[0-9]{4}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_EXECUTION_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_GATEWAY_NAME_RE = re.compile(r"^(?:CTP|[A-Za-z0-9][A-Za-z0-9._:-]{7,127})$")
_EXCHANGES = frozenset({"CFFEX", "CZCE", "DCE", "GFEX", "INE", "SHFE"})
_CLOSE_ORDER_OFFSETS = frozenset({"CLOSE", "CLOSETODAY", "CLOSEYESTERDAY"})
_YD_AWARE_EXCHANGES = frozenset({"INE", "SHFE"})
_FORMAL_QUOTE_MAX_AGE_SECONDS = 2
_FORMAL_QUOTE_FUTURE_SKEW_SECONDS = 2


class CommodityExecutionContractError(ValueError):
    """A final execution plan or receipt does not meet the exact contract."""


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CommodityExecutionContractError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _projection_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise CommodityExecutionContractError(f"target position {field} is invalid")
    normalized = value.strip()
    if not normalized:
        raise CommodityExecutionContractError(f"target position {field} is invalid")
    return normalized.upper()


def _projection_account_scope(value: Any) -> str:
    if not isinstance(value, str):
        raise CommodityExecutionContractError(
            "target position account_scope is invalid"
        )
    normalized = value.strip()
    if _ID_RE.fullmatch(normalized) is None:
        raise CommodityExecutionContractError(
            "target position account_scope is invalid"
        )
    return normalized


def _projection_position_fields(raw: Mapping[str, Any]) -> tuple[str, str, str, str]:
    gateway_name = _projection_text(raw.get("gateway_name"), "gateway_name")
    symbol = _projection_text(raw.get("symbol"), "symbol")
    exchange = _projection_text(raw.get("exchange"), "exchange")
    direction = _projection_text(raw.get("direction"), "direction")
    if (
        _GATEWAY_NAME_RE.fullmatch(gateway_name) is None
        or _SYMBOL_RE.fullmatch(symbol) is None
        or exchange not in _EXCHANGES
        or direction not in {"LONG", "SHORT"}
    ):
        raise CommodityExecutionContractError("target position semantics are invalid")
    return gateway_name, symbol, exchange, direction


def canonical_target_position_projection(
    positions: Any, *, account_scope: Any, environment: Any
) -> dict[str, Any]:
    """Return the stable target-position projection for TargetPlan v1.

    ``expected_after_position_hash`` is intentionally *not* a hash of opaque
    broker rows.  It commits only to account/environment and aggregated
    non-zero gateway/symbol/exchange/direction/volume positions.  Dynamic
    broker facts (for example price, pnl, frozen, commissions and row IDs) are
    retained elsewhere as complete facts, but are excluded here.

    A former full-row expected-after hash has different semantics and must be
    regenerated and re-signed; it must never be mixed with this projection.
    """

    if not isinstance(positions, Mapping):
        raise CommodityExecutionContractError("target positions must be an object")
    normalized_scope = _projection_account_scope(account_scope)
    normalized_environment = _projection_text(environment, "environment")
    aggregates: dict[tuple[str, str, str, str], int] = {}
    for row_key, raw in positions.items():
        if not isinstance(row_key, str) or not isinstance(raw, Mapping):
            raise CommodityExecutionContractError("target position row is invalid")
        volume = raw.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise CommodityExecutionContractError("target position volume is invalid")
        if volume == 0:
            continue
        semantic_key = _projection_position_fields(raw)
        aggregates[semantic_key] = aggregates.get(semantic_key, 0) + volume
    return {
        "account_scope": normalized_scope,
        "environment": normalized_environment,
        "positions": [
            {
                "gateway_name": gateway_name,
                "symbol": symbol,
                "exchange": exchange,
                "direction": direction,
                "volume": volume,
            }
            for (gateway_name, symbol, exchange, direction), volume in sorted(
                aggregates.items()
            )
        ],
    }


def target_position_projection_hash(
    positions: Any, *, account_scope: Any, environment: Any
) -> str:
    """Hash :func:`canonical_target_position_projection` for TargetPlan v1."""

    return sha256_json(
        canonical_target_position_projection(
            positions, account_scope=account_scope, environment=environment
        )
    )


def canonical_before_position_projection(
    positions: Any, *, account_scope: Any, environment: Any
) -> dict[str, Any]:
    """Return the deterministic current-position proof for TargetPlan start.

    This keeps the target projection's account/environment and aggregated
    position semantics, while binding SHFE/INE close availability to the
    authoritative non-zero ``yd_volume`` facts.  Other broker fields remain
    outside this narrow proof.
    """

    if not isinstance(positions, Mapping):
        raise CommodityExecutionContractError("before positions must be an object")
    normalized_scope = _projection_account_scope(account_scope)
    normalized_environment = _projection_text(environment, "environment")
    aggregates: dict[tuple[str, str, str, str], tuple[int, int | None]] = {}
    for row_key, raw in positions.items():
        if not isinstance(row_key, str) or not isinstance(raw, Mapping):
            raise CommodityExecutionContractError("before position row is invalid")
        volume = raw.get("volume")
        if isinstance(volume, bool) or not isinstance(volume, int) or volume < 0:
            raise CommodityExecutionContractError("before position volume is invalid")
        if volume == 0:
            continue
        semantic_key = _projection_position_fields(raw)
        exchange = semantic_key[2]
        yd_volume: int | None = None
        if exchange in _YD_AWARE_EXCHANGES:
            yd_volume = raw.get("yd_volume")
            if (
                isinstance(yd_volume, bool)
                or not isinstance(yd_volume, int)
                or yd_volume < 0
                or yd_volume > volume
            ):
                raise CommodityExecutionContractError(
                    "before SHFE/INE position yd_volume is invalid"
                )
        prior_volume, prior_yd_volume = aggregates.get(
            semantic_key, (0, 0 if exchange in _YD_AWARE_EXCHANGES else None)
        )
        if prior_yd_volume is None and yd_volume is not None:
            raise CommodityExecutionContractError(
                "before position yd_volume is invalid"
            )
        aggregates[semantic_key] = (
            prior_volume + volume,
            None if yd_volume is None else int(prior_yd_volume or 0) + yd_volume,
        )
    projection_rows: list[dict[str, Any]] = []
    for (gateway_name, symbol, exchange, direction), (volume, yd_volume) in sorted(
        aggregates.items()
    ):
        row = {
            "gateway_name": gateway_name,
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": volume,
        }
        if exchange in _YD_AWARE_EXCHANGES:
            if yd_volume is None:  # pragma: no cover - guarded above
                raise CommodityExecutionContractError(
                    "before position yd_volume is invalid"
                )
            row["yd_volume"] = yd_volume
        projection_rows.append(row)
    return {
        "account_scope": normalized_scope,
        "environment": normalized_environment,
        "positions": projection_rows,
    }


def before_position_projection_hash(
    positions: Any, *, account_scope: Any, environment: Any
) -> str:
    """Hash :func:`canonical_before_position_projection` for TargetPlan start."""

    return sha256_json(
        canonical_before_position_projection(
            positions, account_scope=account_scope, environment=environment
        )
    )


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise CommodityExecutionContractError(f"{field} is invalid")
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CommodityExecutionContractError(
            f"{field} must be a lowercase SHA-256 hash"
        )
    return value


def _utc(value: Any, field: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise CommodityExecutionContractError(f"{field} must be a UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CommodityExecutionContractError(f"{field} is invalid") from exc
    return value


def _short_string(
    value: Any, field: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 128
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise CommodityExecutionContractError(f"{field} is invalid")
    return value


def _detached_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CommodityExecutionContractError(f"{field} must be an object")
    try:
        result = json.loads(canonical_json(dict(value)))
    except json.JSONDecodeError as exc:  # pragma: no cover - canonical_json guards this
        raise CommodityExecutionContractError(f"{field} is invalid") from exc
    if not isinstance(result, dict):  # pragma: no cover - json object roundtrip
        raise CommodityExecutionContractError(f"{field} must be an object")
    return result


@dataclass(frozen=True, slots=True)
class TargetPlanOrder:
    """One immutable order reference and the exact gateway request payload."""

    symbol: str
    exchange: str
    direction: str
    type: str
    volume: int
    price: float
    offset: str
    reference: str
    gateway_name: str

    @classmethod
    def from_mapping(cls, raw: Any, *, max_order_volume: int = 1) -> TargetPlanOrder:
        fields = {
            "symbol",
            "exchange",
            "direction",
            "type",
            "volume",
            "price",
            "offset",
            "reference",
            "gateway_name",
        }
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise CommodityExecutionContractError(
                "target plan order fields are invalid"
            )
        if (
            not isinstance(max_order_volume, int)
            or isinstance(max_order_volume, bool)
            or max_order_volume < 1
        ):
            raise CommodityExecutionContractError("local max order volume is invalid")
        symbol, exchange, direction, order_type = (
            raw["symbol"],
            raw["exchange"],
            raw["direction"],
            raw["type"],
        )
        volume, price, offset = raw["volume"], raw["price"], raw["offset"]
        gateway_name = raw["gateway_name"]
        if (
            not isinstance(symbol, str)
            or _SYMBOL_RE.fullmatch(symbol) is None
            or exchange not in _EXCHANGES
            or direction not in {"LONG", "SHORT"}
            or order_type != "LIMIT"
            or isinstance(volume, bool)
            or not isinstance(volume, int)
            or not 0 < volume <= max_order_volume
            or isinstance(price, bool)
            or not isinstance(price, (int, float))
            or not math.isfinite(price)
            or price <= 0
            or offset not in _CLOSE_ORDER_OFFSETS | {"OPEN"}
            or (
                offset in _CLOSE_ORDER_OFFSETS - {"CLOSE"}
                and exchange not in _YD_AWARE_EXCHANGES
            )
            or not isinstance(gateway_name, str)
            or _GATEWAY_NAME_RE.fullmatch(gateway_name) is None
        ):
            raise CommodityExecutionContractError(
                "target plan order is not a strict SIMNOW limit order"
            )
        return cls(
            symbol,
            exchange,
            direction,
            order_type,
            volume,
            float(price),
            offset,
            _id(raw["reference"], "target plan reference"),
            gateway_name,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "exchange": self.exchange,
            "direction": self.direction,
            "type": self.type,
            "volume": self.volume,
            "price": self.price,
            "offset": self.offset,
            "reference": self.reference,
            "gateway_name": self.gateway_name,
        }


_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id",
        "receipt_type",
        "artifact_id",
        "artifact_type",
        "trust_domain",
        "schema_ref",
        "artifact_sha256",
        "signer_key_id",
        "signer_key_version",
        "keyring_raw_sha256",
        "signed_artifact_sha256",
        "scope",
        "expires_at",
        "custody_version",
        "idempotency_key",
        "verified",
        "installed",
        "custody_writer",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedCustodyReceipt:
    """The exact install receipt that a final target plan is pinned to."""

    raw: dict[str, Any]
    receipt_sha256: str

    @classmethod
    def from_mapping(cls, value: Any) -> VerifiedCustodyReceipt:
        raw = _detached_mapping(value, "custody receipt")
        if set(raw) != _RECEIPT_FIELDS:
            raise CommodityExecutionContractError(
                "custody receipt fields are not exact"
            )
        for field in (
            "receipt_id",
            "artifact_id",
            "idempotency_key",
            "custody_writer",
        ):
            _id(raw[field], f"custody receipt {field}")
        _short_string(raw["signer_key_id"], "custody receipt signer_key_id")
        _short_string(
            raw["signer_key_version"],
            "custody receipt signer_key_version",
            pattern=_KEY_VERSION_RE,
        )
        for field in (
            "artifact_sha256",
            "keyring_raw_sha256",
            "signed_artifact_sha256",
        ):
            _sha(raw[field], f"custody receipt {field}")
        _utc(raw["expires_at"], "custody receipt expires_at")
        accepted_artifact_contracts = {
            (
                "runtime-authorization",
                "runtime_authorization",
                "phase-c-runtime-authorization-v1",
            ),
            ("simnow-target-plan", "runtime_authorization", TARGET_PLAN_SCHEMA_VERSION),
        }
        if (
            raw["receipt_type"] != "install"
            or (raw["artifact_type"], raw["trust_domain"], raw["schema_ref"])
            not in accepted_artifact_contracts
            or raw["verified"] is not True
            or raw["installed"] is not True
            or any(
                raw[field] is not False
                for field in (
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                )
            )
            or isinstance(raw["custody_version"], bool)
            or not isinstance(raw["custody_version"], int)
            or raw["custody_version"] < 1
        ):
            raise CommodityExecutionContractError(
                "custody receipt is not a verified offline install"
            )
        _detached_mapping(raw["scope"], "custody receipt scope")
        return cls(raw=raw, receipt_sha256=sha256_json(raw))

    @property
    def receipt_id(self) -> str:
        return str(self.raw["receipt_id"])

    @property
    def artifact_id(self) -> str:
        return str(self.raw["artifact_id"])

    @property
    def artifact_sha256(self) -> str:
        return str(self.raw["artifact_sha256"])

    @property
    def scope(self) -> dict[str, Any]:
        return _detached_mapping(self.raw["scope"], "custody receipt scope")

    def expires_at(self) -> datetime:
        return datetime.fromisoformat(str(self.raw["expires_at"])[:-1] + "+00:00")

    def as_dict(self) -> dict[str, Any]:
        return _detached_mapping(self.raw, "custody receipt")


_KEYLESS_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id",
        "receipt_type",
        "artifact_id",
        "artifact_type",
        "trust_domain",
        "schema_ref",
        "artifact_sha256",
        "scope",
        "expires_at",
        "custody_version",
        "idempotency_key",
        "verified",
        "installed",
        "custody_writer",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    }
)


@dataclass(frozen=True, slots=True)
class TrustedKeylessCustodyReceipt:
    """Exact create-only custody evidence for the fixed local SIMNOW tuple.

    This is intentionally separate from :class:`VerifiedCustodyReceipt`: it
    cannot carry a signer, keyring pin, or runtime-authorization artifact.
    """

    raw: dict[str, Any]
    receipt_sha256: str

    @classmethod
    def from_mapping(cls, value: Any) -> TrustedKeylessCustodyReceipt:
        raw = _detached_mapping(value, "keyless custody receipt")
        if set(raw) != _KEYLESS_RECEIPT_FIELDS:
            raise CommodityExecutionContractError(
                "keyless custody receipt fields are not exact"
            )
        for field in ("receipt_id", "artifact_id", "idempotency_key", "custody_writer"):
            _id(raw[field], f"keyless custody receipt {field}")
        _sha(raw["artifact_sha256"], "keyless custody receipt artifact_sha256")
        _utc(raw["expires_at"], "keyless custody receipt expires_at")
        scope = _detached_mapping(raw["scope"], "keyless custody receipt scope")
        if (
            raw["receipt_type"] != "install"
            or raw["artifact_type"] != "simnow-target-plan"
            or raw["trust_domain"] != "runtime_authorization"
            or raw["schema_ref"] not in _KEYLESS_TARGET_PLAN_SCHEMA_VERSIONS
            or scope != TRUSTED_KEYLESS_SIMNOW_SCOPE
            or raw["verified"] is not True
            or raw["installed"] is not True
            or any(
                raw[field] is not False
                for field in (
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                )
            )
            or isinstance(raw["custody_version"], bool)
            or not isinstance(raw["custody_version"], int)
            or raw["custody_version"] < 1
        ):
            raise CommodityExecutionContractError(
                "keyless custody receipt is not fixed SIMNOW evidence"
            )
        return cls(raw=raw, receipt_sha256=sha256_json(raw))

    @property
    def receipt_id(self) -> str:
        return str(self.raw["receipt_id"])

    @property
    def artifact_id(self) -> str:
        return str(self.raw["artifact_id"])

    @property
    def artifact_sha256(self) -> str:
        return str(self.raw["artifact_sha256"])

    @property
    def scope(self) -> dict[str, Any]:
        return _detached_mapping(self.raw["scope"], "keyless custody receipt scope")

    def expires_at(self) -> datetime:
        return datetime.fromisoformat(str(self.raw["expires_at"])[:-1] + "+00:00")

    def as_dict(self) -> dict[str, Any]:
        return _detached_mapping(self.raw, "keyless custody receipt")


_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "plan_id",
        "plan_hash",
        "account_scope",
        "environment",
        "authority_artifact_id",
        "authority_artifact_sha256",
        "authority_receipt_id",
        "authority_receipt_sha256",
        "signer_key_id",
        "signer_key_version",
        "keyring_raw_sha256",
        "scope",
        "expires_at",
        "orders",
        "phase",
        "expected_before_position_hash",
        "expected_after_position_hash",
        "order_set_sha256",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    }
)

_KEYLESS_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "plan_id",
        "plan_hash",
        "custody_mode",
        "account_scope",
        "environment",
        "gateway_name",
        "lineage",
        "scope",
        "generated_at",
        "expires_at",
        "orders",
        "phase",
        "expected_before_position_hash",
        "expected_after_position_hash",
        "order_set_sha256",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    }
)

_KEYLESS_PLAN_V3_FIELDS = frozenset(
    {
        *_KEYLESS_PLAN_FIELDS,
        "execution_run_id",
        "creation_quote_proof",
    }
)
_KEYLESS_PLAN_V3_IDENTITY_FIELDS = _KEYLESS_PLAN_V3_FIELDS - {
    "plan_id",
    "plan_hash",
}
_FORMAL_QUOTE_PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "validated_at_utc",
        "max_age_seconds",
        "future_skew_seconds",
        "journal_authenticated",
        "start_authorized",
        "bindings",
    }
)
_FORMAL_QUOTE_BINDING_FIELDS = frozenset(
    {
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
    }
)


def _decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CommodityExecutionContractError(f"{field} is invalid")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CommodityExecutionContractError(f"{field} is invalid") from exc
    if not result.is_finite():
        raise CommodityExecutionContractError(f"{field} is invalid")
    return result


def _creation_quote_proof(
    value: Any, *, orders: tuple[TargetPlanOrder, ...]
) -> dict[str, Any]:
    proof = _detached_mapping(value, "target plan creation_quote_proof")
    if set(proof) != _FORMAL_QUOTE_PROOF_FIELDS:
        raise CommodityExecutionContractError(
            "target plan creation quote proof fields are not exact"
        )
    if (
        proof["schema_version"] != FORMAL_QUOTE_PROOF_SCHEMA_VERSION
        or type(proof["max_age_seconds"]) is not int
        or proof["max_age_seconds"] != _FORMAL_QUOTE_MAX_AGE_SECONDS
        or type(proof["future_skew_seconds"]) is not int
        or proof["future_skew_seconds"] != _FORMAL_QUOTE_FUTURE_SKEW_SECONDS
        or proof["journal_authenticated"] is not False
        or proof["start_authorized"] is not False
    ):
        raise CommodityExecutionContractError(
            "target plan creation quote proof policy is invalid"
        )
    validated_at_raw = _utc(
        proof["validated_at_utc"],
        "target plan creation quote proof validated_at_utc",
    )
    validated_at = datetime.fromisoformat(validated_at_raw[:-1] + "+00:00")
    bindings = _detached_mapping(
        proof["bindings"], "target plan creation quote proof bindings"
    )
    required: dict[str, tuple[str, Decimal]] = {}
    for order in orders:
        if _EXACT_COMMODITY_SYMBOL_RE.fullmatch(order.symbol) is None:
            raise CommodityExecutionContractError(
                "target plan creation quote order contract is not exact"
            )
        exact_contract = f"{order.exchange}.{order.symbol}"
        side = "ask" if order.direction == "LONG" else "bid"
        price = Decimal(str(order.price))
        prior = required.setdefault(exact_contract, (side, price))
        if prior != (side, price):
            raise CommodityExecutionContractError(
                "target plan creation quote proof order set is ambiguous"
            )
    if set(bindings) != set(required):
        raise CommodityExecutionContractError(
            "target plan creation quote proof contract set is not exact"
        )
    for exact_contract, (expected_side, order_price) in required.items():
        raw = bindings[exact_contract]
        if not isinstance(raw, Mapping) or set(raw) != _FORMAL_QUOTE_BINDING_FIELDS:
            raise CommodityExecutionContractError(
                f"target plan creation quote binding is invalid: {exact_contract}"
            )
        try:
            exchange, symbol = exact_contract.split(".", 1)
        except ValueError as exc:  # pragma: no cover - derived from a validated order
            raise CommodityExecutionContractError(
                "target plan creation quote contract is invalid"
            ) from exc
        if (
            raw["source"] != "windows-tick-wire-v1"
            or raw["vt_symbol"] != f"{symbol}.{exchange}"
            or raw["price_side"] != expected_side
        ):
            raise CommodityExecutionContractError(
                f"target plan creation quote identity is invalid: {exact_contract}"
            )
        for identity_field in ("stream_generation", "ingest_id"):
            identity_value = raw[identity_field]
            if not isinstance(identity_value, str) or not identity_value:
                raise CommodityExecutionContractError(
                    "target plan creation quote "
                    f"{identity_field} is invalid: {exact_contract}"
                )
        ingest_seq = raw["ingest_seq"]
        if (
            isinstance(ingest_seq, bool)
            or not isinstance(ingest_seq, int)
            or ingest_seq < 1
        ):
            raise CommodityExecutionContractError(
                f"target plan creation quote sequence is invalid: {exact_contract}"
            )
        _sha(
            raw["event_hash"],
            f"target plan creation quote event_hash: {exact_contract}",
        )
        received_at_raw = _utc(
            raw["received_at_utc"],
            f"target plan creation quote received_at_utc: {exact_contract}",
        )
        received_at = datetime.fromisoformat(received_at_raw[:-1] + "+00:00")
        age = (validated_at - received_at).total_seconds()
        if (
            age > _FORMAL_QUOTE_MAX_AGE_SECONDS
            or age < -_FORMAL_QUOTE_FUTURE_SKEW_SECONDS
        ):
            raise CommodityExecutionContractError(
                f"target plan creation quote is stale or from the future: {exact_contract}"
            )
        reference_price = _decimal(
            raw["reference_price"],
            f"target plan creation quote reference_price: {exact_contract}",
        )
        price_tick = _decimal(
            raw["price_tick"],
            f"target plan creation quote price_tick: {exact_contract}",
        )
        if reference_price <= 0 or price_tick <= 0 or reference_price % price_tick != 0:
            raise CommodityExecutionContractError(
                f"target plan creation quote price is invalid: {exact_contract}"
            )
        protected_price = (
            reference_price + price_tick
            if expected_side == "ask"
            else reference_price - price_tick
        )
        if protected_price <= 0 or protected_price != order_price:
            raise CommodityExecutionContractError(
                f"target plan creation quote does not bind order price: {exact_contract}"
            )
    proof["bindings"] = bindings
    return proof


def trusted_keyless_target_plan_v3_plan_id(value: Any) -> str:
    """Derive the v3 full-portfolio ID solely from persisted plan material."""

    raw = _detached_mapping(value, "keyless target plan v3 identity")
    if set(raw) == _KEYLESS_PLAN_V3_FIELDS:
        raw = {key: raw[key] for key in raw if key not in {"plan_id", "plan_hash"}}
    if set(raw) != _KEYLESS_PLAN_V3_IDENTITY_FIELDS:
        raise CommodityExecutionContractError(
            "keyless target plan v3 identity fields are not exact"
        )
    phase = raw.get("phase")
    if raw.get(
        "schema_version"
    ) != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION or phase not in {"CLOSE", "OPEN"}:
        raise CommodityExecutionContractError(
            "keyless target plan v3 identity is invalid"
        )
    _short_string(
        raw.get("execution_run_id"),
        "keyless target plan v3 execution_run_id",
        pattern=_EXECUTION_RUN_ID_RE,
    )
    return f"static-core-full-{str(phase).lower()}-v3-{sha256_json(raw)}"


@dataclass(frozen=True, slots=True)
class TargetPlan:
    """A plan whose complete canonical payload is locked by ``plan_hash``."""

    raw: dict[str, Any]
    orders: tuple[TargetPlanOrder, ...]

    @classmethod
    def from_mapping(cls, value: Any, *, max_order_volume: int = 1) -> TargetPlan:
        raw = _detached_mapping(value, "target plan")
        is_keyless = raw.get("schema_version") in _KEYLESS_TARGET_PLAN_SCHEMA_VERSIONS
        is_keyless_v3 = (
            raw.get("schema_version") == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
        )
        expected_fields = (
            _KEYLESS_PLAN_V3_FIELDS
            if is_keyless_v3
            else (_KEYLESS_PLAN_FIELDS if is_keyless else _PLAN_FIELDS)
        )
        if set(raw) != expected_fields:
            raise CommodityExecutionContractError("target plan fields are not exact")
        if raw["schema_version"] not in {
            TARGET_PLAN_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
            KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
        }:
            raise CommodityExecutionContractError(
                "target plan schema_version is invalid"
            )
        for field in (
            ("plan_id", "account_scope")
            if is_keyless
            else (
                "plan_id",
                "account_scope",
                "authority_artifact_id",
                "authority_receipt_id",
            )
        ):
            _id(raw[field], f"target plan {field}")
        if not is_keyless:
            _short_string(raw["signer_key_id"], "target plan signer_key_id")
            _short_string(
                raw["signer_key_version"],
                "target plan signer_key_version",
                pattern=_KEY_VERSION_RE,
            )
        for field in (
            (
                "plan_hash",
                "expected_before_position_hash",
                "expected_after_position_hash",
                "order_set_sha256",
            )
            if is_keyless
            else (
                "plan_hash",
                "authority_artifact_sha256",
                "authority_receipt_sha256",
                "keyring_raw_sha256",
                "expected_before_position_hash",
                "expected_after_position_hash",
                "order_set_sha256",
            )
        ):
            _sha(raw[field], f"target plan {field}")
        if raw["environment"] != "SIMNOW":
            raise CommodityExecutionContractError(
                "target plan environment must be SIMNOW"
            )
        _utc(raw["expires_at"], "target plan expires_at")
        scope = _detached_mapping(raw["scope"], "target plan scope")
        if is_keyless:
            _utc(raw["generated_at"], "keyless target plan generated_at")
            if (
                raw["custody_mode"] != "trusted-keyless-simnow"
                or raw["gateway_name"] != "CTP"
                or raw["account_scope"] != "account:windows"
                or scope != TRUSTED_KEYLESS_SIMNOW_SCOPE
            ):
                raise CommodityExecutionContractError(
                    "keyless target plan scope is invalid"
                )
            lineage = _detached_mapping(raw["lineage"], "keyless target plan lineage")
            if raw["schema_version"] == KEYLESS_TARGET_PLAN_SCHEMA_VERSION:
                if set(lineage) != {"map_sha256", "c_fast_sha256"}:
                    raise CommodityExecutionContractError(
                        "keyless target plan lineage is invalid"
                    )
                _sha(lineage["map_sha256"], "keyless target plan MAP lineage")
                _sha(lineage["c_fast_sha256"], "keyless target plan C_FAST lineage")
            else:
                lineage_fields = {
                    "static_core_equal_sha256",
                    "position_manager_sha256",
                    "final_target_sha256",
                }
                if set(lineage) != lineage_fields:
                    raise CommodityExecutionContractError(
                        "keyless target plan lineage is invalid"
                    )
                for field in sorted(lineage_fields):
                    _sha(lineage[field], f"keyless target plan {field} lineage")
            if is_keyless_v3:
                _short_string(
                    raw["execution_run_id"],
                    "keyless target plan v3 execution_run_id",
                    pattern=_EXECUTION_RUN_ID_RE,
                )
        if any(
            raw[field] is not False
            for field in (
                "production_allowed",
                "live_trading_authorized",
                "countable_forward",
            )
        ):
            raise CommodityExecutionContractError(
                "target plan authority flags must remain false"
            )
        orders_raw = raw["orders"]
        if (
            not isinstance(orders_raw, Sequence)
            or isinstance(orders_raw, (str, bytes))
            or not orders_raw
        ):
            raise CommodityExecutionContractError(
                "target plan orders must be a non-empty array"
            )
        orders = tuple(
            TargetPlanOrder.from_mapping(item, max_order_volume=max_order_volume)
            for item in orders_raw
        )
        if is_keyless and any(
            order.gateway_name != raw["gateway_name"] for order in orders
        ):
            raise CommodityExecutionContractError(
                "keyless target plan order gateway is not scope-bound"
            )
        if len({item.reference for item in orders}) != len(orders):
            raise CommodityExecutionContractError(
                "target plan order references must be unique"
            )
        if raw["phase"] not in {"CLOSE", "OPEN"} or any(
            (raw["phase"] == "OPEN" and order.offset != "OPEN")
            or (raw["phase"] == "CLOSE" and order.offset not in _CLOSE_ORDER_OFFSETS)
            for order in orders
        ):
            raise CommodityExecutionContractError(
                "target plan orders must be one phase"
            )
        if raw["order_set_sha256"] != sha256_json(
            [order.as_dict() for order in orders]
        ):
            raise CommodityExecutionContractError("target plan order set hash mismatch")
        if (
            is_keyless
            and raw["expected_before_position_hash"]
            == raw["expected_after_position_hash"]
        ):
            raise CommodityExecutionContractError(
                "keyless target plan order has no position transition"
            )
        if is_keyless_v3:
            raw["creation_quote_proof"] = _creation_quote_proof(
                raw["creation_quote_proof"], orders=orders
            )
            quote_validated_at = datetime.fromisoformat(
                raw["creation_quote_proof"]["validated_at_utc"][:-1] + "+00:00"
            )
            plan_expires_at = datetime.fromisoformat(
                str(raw["expires_at"])[:-1] + "+00:00"
            )
            if quote_validated_at >= plan_expires_at:
                raise CommodityExecutionContractError(
                    "keyless target plan v3 quote proof is not before expiry"
                )
            expected_plan_id = trusted_keyless_target_plan_v3_plan_id(raw)
            if raw["plan_id"] != expected_plan_id:
                raise CommodityExecutionContractError(
                    "keyless target plan v3 plan_id mismatch"
                )
        canonical = {key: raw[key] for key in raw if key != "plan_hash"}
        if sha256_json(canonical) != raw["plan_hash"]:
            raise CommodityExecutionContractError("target plan hash mismatch")
        # Keep a detached scope in the raw object, even though validation above
        # already proved it JSON-safe.
        raw["scope"] = scope
        return cls(raw=raw, orders=orders)

    @property
    def plan_id(self) -> str:
        return str(self.raw["plan_id"])

    @property
    def plan_hash(self) -> str:
        return str(self.raw["plan_hash"])

    @property
    def is_trusted_keyless_simnow(self) -> bool:
        return self.raw["schema_version"] in _KEYLESS_TARGET_PLAN_SCHEMA_VERSIONS

    @property
    def authority_id(self) -> str:
        return (
            self.plan_id
            if self.is_trusted_keyless_simnow
            else str(self.raw["authority_artifact_id"])
        )

    @property
    def authority_hash(self) -> str:
        return (
            self.plan_hash
            if self.is_trusted_keyless_simnow
            else str(self.raw["authority_artifact_sha256"])
        )

    def order(self, order_ref: str) -> TargetPlanOrder:
        wanted = _id(order_ref, "order_ref")
        for item in self.orders:
            if item.reference == wanted:
                return item
        raise CommodityExecutionContractError("target plan order_ref is not present")

    def as_dict(self) -> dict[str, Any]:
        return _detached_mapping(self.raw, "target plan")


def build_target_plan(**fields: Any) -> dict[str, Any]:
    """Build one exact target-plan mapping and derive its immutable hash."""

    raw = dict(fields)
    raw.setdefault("schema_version", TARGET_PLAN_SCHEMA_VERSION)
    for flag in (
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
    ):
        raw.setdefault(flag, False)
    raw.setdefault("order_set_sha256", sha256_json(raw.get("orders", [])))
    raw.pop("plan_hash", None)
    raw["plan_hash"] = sha256_json(raw)
    return TargetPlan.from_mapping(raw).as_dict()


def build_trusted_keyless_target_plan(**fields: Any) -> dict[str, Any]:
    """Build the fixed-tuple, no-key/no-signature SIMNOW TargetPlan variant."""

    raw = dict(fields)
    if raw.get("schema_version", KEYLESS_TARGET_PLAN_SCHEMA_VERSION) != (
        KEYLESS_TARGET_PLAN_SCHEMA_VERSION
    ):
        raise CommodityExecutionContractError(
            "keyless target plan v1 builder requires the v1 schema"
        )
    raw.setdefault("schema_version", KEYLESS_TARGET_PLAN_SCHEMA_VERSION)
    raw.setdefault("custody_mode", "trusted-keyless-simnow")
    raw.setdefault("scope", dict(TRUSTED_KEYLESS_SIMNOW_SCOPE))
    for flag in ("production_allowed", "live_trading_authorized", "countable_forward"):
        raw.setdefault(flag, False)
    raw.setdefault("order_set_sha256", sha256_json(raw.get("orders", [])))
    raw.pop("plan_hash", None)
    raw["plan_hash"] = sha256_json(raw)
    return TargetPlan.from_mapping(raw).as_dict()


def build_trusted_keyless_target_plan_v2(**fields: Any) -> dict[str, Any]:
    """Build the full-strategy, no-key/no-signature SIMNOW TargetPlan v2."""

    raw = dict(fields)
    if raw.get("schema_version", KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION) != (
        KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    ):
        raise CommodityExecutionContractError(
            "keyless target plan v2 builder requires the v2 schema"
        )
    raw.setdefault("schema_version", KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION)
    raw.setdefault("custody_mode", "trusted-keyless-simnow")
    raw.setdefault("scope", dict(TRUSTED_KEYLESS_SIMNOW_SCOPE))
    for flag in ("production_allowed", "live_trading_authorized", "countable_forward"):
        raw.setdefault(flag, False)
    raw.setdefault("order_set_sha256", sha256_json(raw.get("orders", [])))
    raw.pop("plan_hash", None)
    raw["plan_hash"] = sha256_json(raw)
    return TargetPlan.from_mapping(raw).as_dict()


def build_trusted_keyless_target_plan_v3(**fields: Any) -> dict[str, Any]:
    """Build the quote-aware full-portfolio SIMNOW TargetPlan v3.

    The derived plan ID is a hash of every persisted field except ``plan_id``
    and ``plan_hash``.  No planner-local identity preimage is required to
    recover or audit it after custody.
    """

    raw = dict(fields)
    if raw.get("schema_version", KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION) != (
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    ):
        raise CommodityExecutionContractError(
            "keyless target plan v3 builder requires the v3 schema"
        )
    raw.setdefault("schema_version", KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION)
    raw.setdefault("custody_mode", "trusted-keyless-simnow")
    raw.setdefault("scope", dict(TRUSTED_KEYLESS_SIMNOW_SCOPE))
    for flag in ("production_allowed", "live_trading_authorized", "countable_forward"):
        raw.setdefault(flag, False)
    raw.setdefault("order_set_sha256", sha256_json(raw.get("orders", [])))
    raw.pop("plan_hash", None)
    supplied_plan_id = raw.pop("plan_id", None)
    raw["plan_id"] = trusted_keyless_target_plan_v3_plan_id(raw)
    if supplied_plan_id is not None and supplied_plan_id != raw["plan_id"]:
        raise CommodityExecutionContractError(
            "keyless target plan v3 supplied plan_id mismatch"
        )
    raw["plan_hash"] = sha256_json(raw)
    return TargetPlan.from_mapping(raw).as_dict()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
