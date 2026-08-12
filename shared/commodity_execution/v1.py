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
from typing import Any

TARGET_PLAN_SCHEMA_VERSION = "web-bridge-simnow-target-plan-v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_KEY_VERSION_RE = re.compile(r"^v[0-9]+$")
# TargetPlan orders are sent directly to vn.py.  CTP registers commodity
# symbols using their native lower-case spelling (for example, ``ru2609``),
# while snapshots remain normalized independently for position projections.
_SYMBOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_GATEWAY_NAME_RE = re.compile(r"^(?:CTP|[A-Za-z0-9][A-Za-z0-9._:-]{7,127})$")
_EXCHANGES = frozenset({"CFFEX", "CZCE", "DCE", "GFEX", "INE", "SHFE"})
_CLOSE_ORDER_OFFSETS = frozenset({"CLOSE", "CLOSETODAY", "CLOSEYESTERDAY"})
_YD_AWARE_EXCHANGES = frozenset({"INE", "SHFE"})


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


@dataclass(frozen=True, slots=True)
class TargetPlan:
    """A plan whose complete canonical payload is locked by ``plan_hash``."""

    raw: dict[str, Any]
    orders: tuple[TargetPlanOrder, ...]

    @classmethod
    def from_mapping(cls, value: Any, *, max_order_volume: int = 1) -> TargetPlan:
        raw = _detached_mapping(value, "target plan")
        if set(raw) != _PLAN_FIELDS:
            raise CommodityExecutionContractError("target plan fields are not exact")
        if raw["schema_version"] != TARGET_PLAN_SCHEMA_VERSION:
            raise CommodityExecutionContractError(
                "target plan schema_version is invalid"
            )
        for field in (
            "plan_id",
            "account_scope",
            "authority_artifact_id",
            "authority_receipt_id",
        ):
            _id(raw[field], f"target plan {field}")
        _short_string(raw["signer_key_id"], "target plan signer_key_id")
        _short_string(
            raw["signer_key_version"],
            "target plan signer_key_version",
            pattern=_KEY_VERSION_RE,
        )
        for field in (
            "plan_hash",
            "authority_artifact_sha256",
            "authority_receipt_sha256",
            "keyring_raw_sha256",
            "expected_before_position_hash",
            "expected_after_position_hash",
            "order_set_sha256",
        ):
            _sha(raw[field], f"target plan {field}")
        if raw["environment"] != "SIMNOW":
            raise CommodityExecutionContractError(
                "target plan environment must be SIMNOW"
            )
        _utc(raw["expires_at"], "target plan expires_at")
        scope = _detached_mapping(raw["scope"], "target plan scope")
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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
