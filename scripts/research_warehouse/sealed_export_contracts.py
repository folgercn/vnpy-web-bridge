"""Contracts for one-way C_FAST nine-artifact sealed exports."""

from __future__ import annotations

import base64
from datetime import date, datetime, timezone
from typing import Any

from commodity_c_fast_pure_producer_kernel import (
    ARTIFACT_ROLES,
    ARTIFACT_SCHEMA_PREFIX,
    CANDIDATE_ID,
    KERNEL_ID,
    PRODUCTS,
    ProducerKernelError,
    produce_research_artifacts,
)
from commodity_c_fast_pure_producer_kernel import (
    FALSE_AUTHORITY_FIELDS as PRODUCER_FALSE_AUTHORITY_FIELDS,
)
from commodity_c_fast_pure_producer_kernel import (
    STATUS as PRODUCER_STATUS,
)

from .canonical import canonical_json, parse_json_strict, sha256
from .errors import RegistryError
from .manifest_contracts import ID_PATTERN, SHA256_PATTERN
from .timeutil import parse_utc

MANIFEST_SCHEMA = "vnpy_research_sealed_source_export_v1"
RECEIPT_SCHEMA = "vnpy_research_sealed_source_export_receipt_v1"
KEYRING_SCHEMA = "vnpy_research_sealed_source_export_keyring_v1"
PURPOSE = "C_FAST_RESEARCH_EVIDENCE_EXPORT_ONLY"
SIGNING_PURPOSE = "research_sealed_source_export_signer"
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
EXPORT_FALSE_AUTHORITY_FIELDS = (
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "execution_permit_authorized",
    "network_authorized",
    "web_bridge_rpc_authorized",
    "account_data_read",
    "order_authorized",
    "position_mutation_authorized",
    "dispatch_authorized",
    "trading_authorized",
    "production_authorized",
    "replacement_authorized",
)
LINEAGE_KEYS = {
    "registry_raw_sha256",
    "calendar_raw_sha256",
    "calendar_anchor_sha256",
    "commit_anchor_ledger_sha256",
    "manifest_genesis_seal_sha256",
    "manifest_head_seal_sha256",
    "manifest_head_commit_seal_sha256",
    "pit_cutoff_at",
    "research_as_of_official_day",
    "execution_day",
    "source_view_canonical_sha256",
}


def false_authority() -> dict[str, bool]:
    return {field: False for field in EXPORT_FALSE_AUTHORITY_FIELDS}


def _canonical_date(value: object, label: str) -> date:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be canonical YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"{label} is not canonical")
    return parsed


def _producer_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryError(f"{label} must be an ISO UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RegistryError(f"{label} must be UTC")
    return parsed


def validate_lineage(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != LINEAGE_KEYS:
        raise RegistryError("sealed export lineage fields do not match v1")
    for field in LINEAGE_KEYS - {
        "pit_cutoff_at",
        "research_as_of_official_day",
        "execution_day",
    }:
        digest = value[field]
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise RegistryError(f"sealed export {field} is invalid")
    parse_utc(value["pit_cutoff_at"], "sealed export PIT cutoff")
    as_of = _canonical_date(
        value["research_as_of_official_day"],
        "sealed export research as-of day",
    )
    execution = _canonical_date(
        value["execution_day"],
        "sealed export execution day",
    )
    if execution <= as_of:
        raise RegistryError("sealed export execution day must follow as-of day")
    return dict(value)


def _artifact_payload(role: str, raw: bytes) -> dict[str, Any]:
    payload = parse_json_strict(raw, f"C_FAST producer artifact {role}")
    if not isinstance(payload, dict) or canonical_json(payload) != raw:
        raise RegistryError(f"C_FAST producer artifact {role} is not canonical")
    expected_common = {
        "schema_version": f"{ARTIFACT_SCHEMA_PREFIX}_{role}_v1",
        "purpose": PRODUCER_STATUS,
        "status": PRODUCER_STATUS,
        "artifact_role": role,
        "candidate_id": CANDIDATE_ID,
        "producer_kernel_id": KERNEL_ID,
        "source_receipt_signature_verified": False,
        "source_receipt_keyring_verified": False,
        "source_custody_verified": False,
        "sealed_export_verified": False,
        "research_evidence_only": True,
    }
    for field, expected in expected_common.items():
        if payload.get(field) != expected:
            raise RegistryError(f"C_FAST artifact {role} identity mismatch")
    for field in PRODUCER_FALSE_AUTHORITY_FIELDS:
        if payload.get(field) is not False:
            raise RegistryError(f"C_FAST artifact {role} grants authority")
    for field in (
        "source_view_id",
        "source_view_canonical_sha256",
        "claimed_receipt_sha256",
        "generated_at",
    ):
        if field not in payload:
            raise RegistryError(f"C_FAST artifact {role} lacks {field}")
    if SHA256_PATTERN.fullmatch(
        str(payload["source_view_canonical_sha256"])
    ) is None:
        raise RegistryError("C_FAST source-view SHA256 is invalid")
    _producer_utc(payload["generated_at"], "C_FAST artifact generated_at")
    return payload


def _rows_by_product(
    payload: dict[str, Any],
    field: str,
    *,
    label: str,
) -> dict[str, dict[str, Any]]:
    rows = payload.get(field)
    if not isinstance(rows, list) or len(rows) != len(PRODUCTS):
        raise RegistryError(f"{label} must cover exact ten products")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("product") not in PRODUCTS:
            raise RegistryError(f"{label} product row is invalid")
        product = row["product"]
        if product in result:
            raise RegistryError(f"{label} repeats product {product}")
        result[product] = row
    if set(result) != set(PRODUCTS):
        raise RegistryError(f"{label} product set is incomplete")
    return result


def validate_artifact_set(
    artifact_raw: dict[str, bytes],
    *,
    lineage: dict[str, str],
) -> dict[str, dict[str, Any]]:
    if tuple(artifact_raw) != ARTIFACT_ROLES:
        raise RegistryError("sealed export artifact role order/set mismatch")
    if any(not raw for raw in artifact_raw.values()):
        raise RegistryError("sealed export artifacts must be non-empty")
    if len(set(artifact_raw.values())) != len(ARTIFACT_ROLES):
        raise RegistryError("sealed export artifacts must have distinct bytes")
    payloads = {
        role: _artifact_payload(role, artifact_raw[role])
        for role in ARTIFACT_ROLES
    }
    common_fields = (
        "source_view_id",
        "source_view_canonical_sha256",
        "claimed_receipt_sha256",
        "generated_at",
        "producer_kernel_id",
        "candidate_id",
    )
    reference = payloads[ARTIFACT_ROLES[0]]
    for role, payload in payloads.items():
        for field in common_fields:
            if payload[field] != reference[field]:
                raise RegistryError(
                    f"C_FAST artifact {role} common lineage mismatch"
                )
    if (
        reference["source_view_canonical_sha256"]
        != lineage["source_view_canonical_sha256"]
    ):
        raise RegistryError("sealed export source-view lineage mismatch")
    manifest = payloads["research_manifest"]
    if (
        _producer_utc(
            manifest.get("source_cutoff_at"),
            "producer source cutoff",
        )
        != parse_utc(lineage["pit_cutoff_at"], "sealed export PIT cutoff")
        or manifest.get("research_as_of_official_day")
        != lineage["research_as_of_official_day"]
        or manifest.get("execution_day") != lineage["execution_day"]
    ):
        raise RegistryError("sealed export PIT/date lineage mismatch")
    as_of = lineage["research_as_of_official_day"]
    execution = lineage["execution_day"]
    calendar = payloads["calendar_authority"]
    official_days = calendar.get("official_days")
    date_index_valid = bool(
        isinstance(official_days, list)
        and as_of in official_days
        and execution in official_days
    )
    execution_is_immediate = bool(
        date_index_valid
        and official_days.index(execution) == official_days.index(as_of) + 1
    )
    if (
        payloads["signal_evidence"].get("research_as_of_official_day")
        != as_of
        or payloads["target_evidence"].get("execution_day") != execution
        or payloads["reference_price_evidence"].get("execution_day")
        != execution
        or calendar.get("research_as_of_official_day") != as_of
        or calendar.get("execution_day") != execution
        or not date_index_valid
        or calendar.get("execution_is_immediate_next_official_day")
        is not execution_is_immediate
    ):
        raise RegistryError("sealed export cross-artifact date mismatch")
    targets = _rows_by_product(
        payloads["target_evidence"],
        "targets",
        label="target evidence",
    )
    signals = _rows_by_product(
        payloads["signal_evidence"],
        "signals",
        label="signal evidence",
    )
    rolls = _rows_by_product(
        payloads["daily_roll_evidence"],
        "rows",
        label="daily-roll evidence",
    )
    references = _rows_by_product(
        payloads["reference_price_evidence"],
        "rows",
        label="reference-price evidence",
    )
    specs = _rows_by_product(
        payloads["contract_spec_evidence"],
        "rows",
        label="contract-spec evidence",
    )
    allocation = payloads["allocation_evidence"]
    quantities = allocation.get("quantities")
    if not isinstance(quantities, dict) or set(quantities) != set(PRODUCTS):
        raise RegistryError("allocation evidence quantity set is incomplete")
    for product in PRODUCTS:
        target = targets[product]
        exact_contract = target.get("exact_contract")
        if (
            target.get("target_quantity") != quantities[product]
            or references[product].get("exact_contract") != exact_contract
            or specs[product].get("exact_contract") != exact_contract
            or rolls[product].get("pit_main_exact_contract") != exact_contract
            or signals[product].get("pit_main_exact_contract") != exact_contract
        ):
            raise RegistryError(
                f"C_FAST {product} cross-artifact contract/target mismatch"
            )
    return payloads


def artifact_bindings(
    artifact_raw: dict[str, bytes],
    *,
    lineage_sha256: str,
    pit_cutoff_at: str,
) -> dict[str, dict[str, object]]:
    return {
        role: {
            "filename": f"{role}.json",
            "bytes": len(raw),
            "raw_sha256": sha256(raw),
            "lineage_sha256": lineage_sha256,
            "pit_cutoff_at": pit_cutoff_at,
        }
        for role, raw in artifact_raw.items()
    }


def replay_exact_artifact_set(
    source_view_raw: bytes,
    artifact_raw: dict[str, bytes],
    *,
    lineage: dict[str, str],
) -> dict[str, str]:
    """Re-run #163 and require byte-for-byte equality for all nine outputs."""
    try:
        replay = produce_research_artifacts(source_view_raw)
    except ProducerKernelError as exc:
        raise RegistryError("sealed export source-view replay failed") from exc
    if (
        replay.source_view_canonical_sha256
        != lineage["source_view_canonical_sha256"]
    ):
        raise RegistryError("sealed export replay source-view hash mismatch")
    if dict(replay.artifacts) != artifact_raw:
        raise RegistryError("sealed export artifacts differ from exact #163 replay")
    return {
        "status": "EXACT_NINE_ARTIFACT_REPLAY_VERIFIED",
        "producer_kernel_id": KERNEL_ID,
        "source_view_raw_sha256": sha256(source_view_raw),
        "source_view_canonical_sha256": replay.source_view_canonical_sha256,
    }


def derive_export_id(unsigned_manifest: dict[str, Any]) -> str:
    base = {
        key: value
        for key, value in unsigned_manifest.items()
        if key not in {"export_id", "signature"}
    }
    return "sealed-export-" + sha256(canonical_json(base))


def validate_signer_id(value: object) -> str:
    if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
        raise RegistryError("sealed export signer key ID is invalid")
    return value
