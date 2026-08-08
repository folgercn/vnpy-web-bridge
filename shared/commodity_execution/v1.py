"""Strict, immutable, non-authoritative SIMNOW target-plan contracts.

Plans bind the exact custody receipt fingerprint and its trust material.  They
are *not* an authority: all three authority flags are deliberately false and
the Execution process must still enforce its own lifecycle, fencing and
explicit local SIMNOW gate before it can call the Windows gateway.
"""

from __future__ import annotations

import hashlib
import json
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

    order_ref: str
    request: dict[str, Any]

    @classmethod
    def from_mapping(cls, raw: Any) -> TargetPlanOrder:
        if not isinstance(raw, Mapping) or set(raw) != {"order_ref", "request"}:
            raise CommodityExecutionContractError(
                "target plan order fields are invalid"
            )
        request = _detached_mapping(raw["request"], "target plan order request")
        if not request:
            raise CommodityExecutionContractError("target plan order request is empty")
        return cls(_id(raw["order_ref"], "target plan order_ref"), request)

    def as_dict(self) -> dict[str, Any]:
        return {"order_ref": self.order_ref, "request": dict(self.request)}


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
        "custody_receipt_id",
        "custody_receipt_sha256",
        "signer_key_id",
        "signer_key_version",
        "keyring_raw_sha256",
        "scope",
        "expires_at",
        "orders",
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
    def from_mapping(cls, value: Any) -> TargetPlan:
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
            "custody_receipt_id",
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
            "custody_receipt_sha256",
            "keyring_raw_sha256",
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
        orders = tuple(TargetPlanOrder.from_mapping(item) for item in orders_raw)
        if len({item.order_ref for item in orders}) != len(orders):
            raise CommodityExecutionContractError(
                "target plan order references must be unique"
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

    def order(self, order_ref: str) -> TargetPlanOrder:
        wanted = _id(order_ref, "order_ref")
        for item in self.orders:
            if item.order_ref == wanted:
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
    raw.pop("plan_hash", None)
    raw["plan_hash"] = sha256_json(raw)
    return TargetPlan.from_mapping(raw).as_dict()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
