"""Strict WF-1 contracts for the only supported durable foundation state."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

FOUNDATION_STATE_SCHEMA_VERSION = "windows_rpc_durable_fence_state_v1"
FOUNDATION_STATE_PURPOSE = "persist_windows_rpc_fail_closed_fence_genesis"
STATE_ID_PREFIX = "windows-fence-state-"
STORE_ID_PREFIX = "windows-fence-store-"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VOLUME_SERIAL_RE = re.compile(r"^[A-F0-9]{8,32}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
SHORT_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

AUTHORITY_FIELDS = frozenset(
    {
        "windows_fence_released",
        "authority_restore_allowed",
        "consume_authorized",
        "reconciliation_authorized",
        "deployment_authorized",
        "automatic_deploy_allowed",
        "production_allowed",
        "live_trading_authorized",
        "send_order_authorized",
        "cancel_order_authorized",
        "countable_forward",
    }
)

STATE_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "state_id",
        "state_core_sha256",
        "store_id",
        "store_format_version",
        "state_sequence",
        "previous_state_raw_sha256",
        "install_attempt_id",
        "attempt_nonce_sha256",
        "bundle_sha256",
        "install_manifest_id",
        "install_manifest_raw_sha256",
        "preflight_receipt_id",
        "preflight_receipt_raw_sha256",
        "service_name",
        "store_path_sha256",
        "store_volume_serial",
        "store_volume_identity_sha256",
        "extension_sha256",
        "launcher_sha256",
        "assembly_sha256",
        "config_sha256",
        "fence_epoch",
        "admission_state",
        "token_state",
        "staged_token",
        "active_token",
        "authority_grant",
        "staged_token_inventory",
        "active_token_inventory",
        "grant_inventory",
        "expected_account_sha256",
        "raw_account_row_sha256",
        "gateway_name",
        "gateway_scope_sha256",
        "preflight_server_instance_id",
        "preflight_fact_generation",
        "preflight_execution_facts_sha256",
        "pending_send_outcomes",
        "active_orders",
        "created_at_utc",
        "trusted_clock_id",
        "authority",
    }
)

SHA_FIELDS = frozenset(
    {
        "state_core_sha256",
        "attempt_nonce_sha256",
        "bundle_sha256",
        "install_manifest_raw_sha256",
        "preflight_receipt_raw_sha256",
        "store_path_sha256",
        "store_volume_identity_sha256",
        "extension_sha256",
        "launcher_sha256",
        "assembly_sha256",
        "config_sha256",
        "expected_account_sha256",
        "raw_account_row_sha256",
        "gateway_scope_sha256",
        "preflight_execution_facts_sha256",
    }
)


class StoreContractError(ValueError):
    """A stable, fail-closed contract rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FrozenNoneState(Mapping[str, Any]):
    value: dict[str, Any]
    raw: bytes
    raw_sha256: str
    core_sha256: str

    @property
    def state_id(self) -> str:
        return str(self.value["state_id"])

    @property
    def store_id(self) -> str:
        return str(self.value["store_id"])

    def __getitem__(self, key: str) -> Any:
        return self.value[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.value)

    def __len__(self) -> int:
        return len(self.value)


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the integer-only NFC subset of RFC 8785 used by WF-0."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not -(2**53) + 1 <= value <= 2**53 - 1:
            raise StoreContractError("JCS_INTEGER_OUTSIDE_EXACT_IEEE754_RANGE")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise StoreContractError("FOUNDATION_JSON_FLOAT_FORBIDDEN")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise StoreContractError("JCS_STRING_NOT_NFC")
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise StoreContractError("JCS_STRING_INVALID_UNICODE") from exc
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(canonical_json_bytes(item) for item in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise StoreContractError("JCS_OBJECT_KEYS_MUST_BE_STRINGS")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return (
            b"{"
            + b",".join(
                canonical_json_bytes(key) + b":" + canonical_json_bytes(item)
                for key, item in items
            )
            + b"}"
        )
    raise StoreContractError("JCS_UNSUPPORTED_JSON_TYPE")


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def reject_float(_: str) -> None:
        raise StoreContractError("FOUNDATION_JSON_FLOAT_FORBIDDEN")

    def reject_constant(_: str) -> None:
        raise StoreContractError("FOUNDATION_JSON_NONFINITE_FORBIDDEN")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise StoreContractError("FOUNDATION_JSON_DUPLICATE_KEY")
            value[key] = item
        return value

    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except StoreContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreContractError("STATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise StoreContractError("STATE_NOT_OBJECT")
    if canonical_json_bytes(value) != raw:
        raise StoreContractError("STATE_RAW_NOT_CANONICAL")
    return value


def _require_exact_fields(value: dict[str, Any]) -> None:
    if set(value) != STATE_FIELDS:
        raise StoreContractError("STATE_SCHEMA_FIELDS_MISMATCH")
    authority = value.get("authority")
    if not isinstance(authority, dict) or set(authority) != AUTHORITY_FIELDS:
        raise StoreContractError("STATE_AUTHORITY_FIELDS_MISMATCH")
    if any(authority[field] is not False for field in AUTHORITY_FIELDS):
        raise StoreContractError("AUTHORITY_OR_TOKEN_NOT_FOUNDATION_FROZEN_NONE")


def _require_foundation_constants(value: dict[str, Any]) -> None:
    if value.get("schema_version") != FOUNDATION_STATE_SCHEMA_VERSION:
        raise StoreContractError("STATE_SCHEMA_VERSION_UNSUPPORTED")
    if (
        type(value.get("store_format_version")) is not int
        or value.get("store_format_version") != 1
    ):
        raise StoreContractError("STORE_FORMAT_VERSION_UNSUPPORTED")
    if type(value.get("state_sequence")) is not int or value.get("state_sequence") != 1:
        raise StoreContractError("STATE_SEQUENCE_UNSUPPORTED")
    exact = {
        "purpose": FOUNDATION_STATE_PURPOSE,
        "previous_state_raw_sha256": None,
        "fence_epoch": 1,
        "admission_state": "FROZEN",
        "token_state": "NONE",
        "staged_token": None,
        "active_token": None,
        "authority_grant": None,
        "staged_token_inventory": [],
        "active_token_inventory": [],
        "grant_inventory": [],
        "pending_send_outcomes": 0,
        "active_orders": [],
    }
    for field, expected in exact.items():
        if value.get(field) != expected or type(value.get(field)) is not type(expected):
            raise StoreContractError("AUTHORITY_OR_TOKEN_NOT_FOUNDATION_FROZEN_NONE")


def _require_shapes(value: dict[str, Any]) -> None:
    for field in SHA_FIELDS:
        if not isinstance(value[field], str) or not SHA256_RE.fullmatch(value[field]):
            raise StoreContractError("STATE_SCHEMA_INVALID")
    patterns = {
        "state_id": re.compile(r"^windows-fence-state-[0-9a-f]{64}$"),
        "store_id": re.compile(r"^windows-fence-store-[0-9a-f]{64}$"),
        "install_attempt_id": re.compile(r"^windows-fence-install-[0-9a-f]{64}$"),
        "install_manifest_id": re.compile(
            r"^windows-fence-install-manifest-[0-9a-f]{64}$"
        ),
        "preflight_receipt_id": re.compile(r"^windows-fence-preflight-[0-9a-f]{64}$"),
    }
    if any(
        not isinstance(value[field], str) or not pattern.fullmatch(value[field])
        for field, pattern in patterns.items()
    ):
        raise StoreContractError("STATE_SCHEMA_INVALID")
    if not isinstance(
        value["store_volume_serial"], str
    ) or not VOLUME_SERIAL_RE.fullmatch(value["store_volume_serial"]):
        raise StoreContractError("STATE_SCHEMA_INVALID")
    for field in ("preflight_server_instance_id", "trusted_clock_id"):
        if not isinstance(value[field], str) or not IDENTIFIER_RE.fullmatch(
            value[field]
        ):
            raise StoreContractError("STATE_SCHEMA_INVALID")
    for field in ("service_name", "gateway_name"):
        if not isinstance(value[field], str) or not SHORT_IDENTIFIER_RE.fullmatch(
            value[field]
        ):
            raise StoreContractError("STATE_SCHEMA_INVALID")
    generation = value["preflight_fact_generation"]
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
    ):
        raise StoreContractError("STATE_SCHEMA_INVALID")
    created = value["created_at_utc"]
    if not isinstance(created, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",
        created,
    ):
        raise StoreContractError("STATE_SCHEMA_INVALID")
    try:
        datetime.fromisoformat(created.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise StoreContractError("STATE_SCHEMA_INVALID") from exc


def parse_frozen_none_state(raw: bytes) -> FrozenNoneState:
    """Parse and fully identify an exact canonical WF-0 genesis state."""
    value = _strict_json_object(raw)
    _require_exact_fields(value)
    _require_foundation_constants(value)
    _require_shapes(value)
    core_payload = {
        key: item
        for key, item in value.items()
        if key not in {"state_id", "state_core_sha256"}
    }
    core_sha256 = hashlib.sha256(canonical_json_bytes(core_payload)).hexdigest()
    if value["state_core_sha256"] != core_sha256:
        raise StoreContractError("STATE_CORE_SHA256_MISMATCH")
    if value["state_id"] != f"{STATE_ID_PREFIX}{core_sha256}":
        raise StoreContractError("STATE_ID_MISMATCH")
    return FrozenNoneState(
        value=value,
        raw=raw,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        core_sha256=core_sha256,
    )
