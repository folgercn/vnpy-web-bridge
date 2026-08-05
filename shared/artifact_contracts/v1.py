"""Canonical immutable artifact and receipt contracts.

The custody implementation stores these contracts as exact canonical JSON
lines.  This module has no network, database, or trading dependency.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Mapping

from shared.trust_contracts.v1 import (
    ContractError,
    assert_non_authoritative,
    canonical_json,
    canonical_json_line,
    sha256_bytes,
)


ARTIFACT_ENVELOPE_SCHEMA_VERSION = "web-bridge-artifact-envelope-v1"
ARTIFACT_PUBLISH_REQUEST_SCHEMA_VERSION = "web-bridge-artifact-publish-request-v1"
ARTIFACT_RECEIPT_SCHEMA_VERSION = "web-bridge-artifact-receipt-v1"
RECEIPT_TYPES = ("publish", "install", "consume", "revoke")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


def _string(value: Any, code: str, *, max_bytes: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > max_bytes:
        raise ContractError(code)
    return value


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ContractError(code)
    return value


def _id(value: Any, code: str) -> str:
    value = _string(value, code, max_bytes=192)
    if _ID_RE.fullmatch(value) is None:
        raise ContractError(code)
    return value


def _timestamp(value: Any, code: str) -> str:
    value = _string(value, code, max_bytes=128)
    if _ISO_RE.match(value) is None:
        raise ContractError(code)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(code) from exc
    return value


def _predecessors(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise ContractError("ARTIFACT_PREDECESSOR_INVALID")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ContractError("ARTIFACT_PREDECESSOR_INVALID")
        artifact_id = _id(item.get("artifact_id"), "ARTIFACT_PREDECESSOR_ID_INVALID")
        digest = _sha(item.get("canonical_sha256"), "ARTIFACT_PREDECESSOR_HASH_INVALID")
        pair = (artifact_id, digest)
        if pair in seen:
            raise ContractError("ARTIFACT_PREDECESSOR_DUPLICATE")
        seen.add(pair)
        result.append({"artifact_id": artifact_id, "canonical_sha256": digest})
    return result


def _lineage(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 128:
        raise ContractError("ARTIFACT_LINEAGE_INVALID")
    result = [_sha(item, "ARTIFACT_LINEAGE_HASH_INVALID") for item in value]
    if len(result) != len(set(result)):
        raise ContractError("ARTIFACT_LINEAGE_DUPLICATE")
    return result


def payload_hashes(payload: Any, *, raw_payload: bytes | None = None) -> tuple[str, str, bytes]:
    canonical = canonical_json(payload)
    raw = canonical_json_line(payload) if raw_payload is None else raw_payload
    if not raw or len(raw) > 16 * 1024 * 1024:
        raise ContractError("ARTIFACT_PAYLOAD_SIZE_INVALID")
    try:
        import json

        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ContractError("ARTIFACT_RAW_PAYLOAD_INVALID") from exc
    if canonical_json(decoded) != canonical:
        raise ContractError("ARTIFACT_RAW_CANONICAL_MISMATCH")
    return sha256_bytes(canonical), sha256_bytes(raw), raw


def _derived_artifact_id(
    *,
    artifact_type: str,
    trust_domain: str,
    producer_id: str,
    canonical_sha256: str,
    predecessor_refs: list[dict[str, str]],
    lineage: list[str],
    scope: Mapping[str, Any],
) -> str:
    binding = {
        "artifact_type": artifact_type,
        "trust_domain": trust_domain,
        "producer_id": producer_id,
        "canonical_sha256": canonical_sha256,
        "predecessor_refs": predecessor_refs,
        "lineage": lineage,
        "scope": scope,
    }
    return "artifact-" + hashlib.sha256(canonical_json(binding)).hexdigest()


def new_artifact_envelope(
    *,
    artifact_id: str | None = None,
    artifact_type: str,
    trust_domain: str,
    producer_id: str,
    producer_version: str,
    schema_ref: str,
    payload: Any,
    generated_at: str,
    scope: Mapping[str, Any] | None = None,
    predecessor_refs: list[dict[str, str]] | None = None,
    lineage: list[str] | None = None,
    raw_payload: bytes | None = None,
) -> dict[str, Any]:
    artifact_type = _id(artifact_type, "ARTIFACT_TYPE_INVALID")
    trust_domain = _id(trust_domain, "ARTIFACT_TRUST_DOMAIN_INVALID")
    producer_id = _id(producer_id, "ARTIFACT_PRODUCER_ID_INVALID")
    producer_version = _id(producer_version, "ARTIFACT_PRODUCER_VERSION_INVALID")
    schema_ref = _id(schema_ref, "ARTIFACT_SCHEMA_REF_INVALID")
    generated_at = _timestamp(generated_at, "ARTIFACT_GENERATED_AT_INVALID")
    if scope is None:
        scope_payload: dict[str, Any] = {}
    elif isinstance(scope, Mapping):
        scope_payload = dict(scope)
    else:
        raise ContractError("ARTIFACT_SCOPE_INVALID")
    predecessors = _predecessors(predecessor_refs)
    lineage_values = _lineage(lineage)
    canonical_sha, raw_sha, _ = payload_hashes(payload, raw_payload=raw_payload)
    derived = _derived_artifact_id(
        artifact_type=artifact_type,
        trust_domain=trust_domain,
        producer_id=producer_id,
        canonical_sha256=canonical_sha,
        predecessor_refs=predecessors,
        lineage=lineage_values,
        scope=scope_payload,
    )
    if artifact_id is not None and artifact_id != derived:
        raise ContractError("ARTIFACT_ID_MISMATCH")
    return {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
        "artifact_id": derived,
        "artifact_type": artifact_type,
        "trust_domain": trust_domain,
        "producer_id": producer_id,
        "producer_version": producer_version,
        "schema_ref": schema_ref,
        "canonical_sha256": canonical_sha,
        "raw_sha256": raw_sha,
        "predecessor_refs": predecessors,
        "lineage": lineage_values,
        "generated_at": generated_at,
        "scope": scope_payload,
        "payload": payload,
    }


def validate_artifact_envelope(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError("ARTIFACT_ENVELOPE_ROOT_INVALID")
    if set(payload) != {
        "schema_version", "artifact_id", "artifact_type", "trust_domain",
        "producer_id", "producer_version", "schema_ref", "canonical_sha256",
        "raw_sha256", "predecessor_refs", "lineage", "generated_at", "scope",
        "payload",
    }:
        raise ContractError("ARTIFACT_ENVELOPE_FIELDS_INVALID")
    if payload.get("schema_version") != ARTIFACT_ENVELOPE_SCHEMA_VERSION:
        raise ContractError("ARTIFACT_ENVELOPE_SCHEMA_INVALID")
    artifact_type = _id(payload.get("artifact_type"), "ARTIFACT_TYPE_INVALID")
    trust_domain = _id(payload.get("trust_domain"), "ARTIFACT_TRUST_DOMAIN_INVALID")
    producer_id = _id(payload.get("producer_id"), "ARTIFACT_PRODUCER_ID_INVALID")
    producer_version = _id(payload.get("producer_version"), "ARTIFACT_PRODUCER_VERSION_INVALID")
    schema_ref = _id(payload.get("schema_ref"), "ARTIFACT_SCHEMA_REF_INVALID")
    artifact_id = _id(payload.get("artifact_id"), "ARTIFACT_ID_INVALID")
    canonical_sha = _sha(payload.get("canonical_sha256"), "ARTIFACT_CANONICAL_HASH_INVALID")
    raw_sha = _sha(payload.get("raw_sha256"), "ARTIFACT_RAW_HASH_INVALID")
    predecessors = _predecessors(payload.get("predecessor_refs"))
    lineage = _lineage(payload.get("lineage"))
    generated_at = _timestamp(payload.get("generated_at"), "ARTIFACT_GENERATED_AT_INVALID")
    scope = payload.get("scope")
    if not isinstance(scope, Mapping):
        raise ContractError("ARTIFACT_SCOPE_INVALID")
    if "payload" not in payload:
        raise ContractError("ARTIFACT_PAYLOAD_MISSING")
    assert_non_authoritative(payload["payload"])
    canonical_actual, raw_actual, _ = payload_hashes(payload["payload"])
    if canonical_actual != canonical_sha:
        raise ContractError("ARTIFACT_CANONICAL_HASH_MISMATCH")
    if raw_actual != raw_sha:
        raise ContractError("ARTIFACT_RAW_HASH_MISMATCH")
    derived = _derived_artifact_id(
        artifact_type=artifact_type,
        trust_domain=trust_domain,
        producer_id=producer_id,
        canonical_sha256=canonical_sha,
        predecessor_refs=predecessors,
        lineage=lineage,
        scope=scope,
    )
    if artifact_id != derived:
        raise ContractError("ARTIFACT_ID_MISMATCH")
    return {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA_VERSION,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "trust_domain": trust_domain,
        "producer_id": producer_id,
        "producer_version": producer_version,
        "schema_ref": schema_ref,
        "canonical_sha256": canonical_sha,
        "raw_sha256": raw_sha,
        "predecessor_refs": predecessors,
        "lineage": lineage,
        "generated_at": generated_at,
        "scope": dict(scope),
        "payload": payload["payload"],
    }


def build_publish_request(
    artifact: Mapping[str, Any],
    *,
    actor_id: str,
    idempotency_key: str,
    correlation_id: str,
    expected_version: int = 0,
) -> dict[str, Any]:
    envelope = validate_artifact_envelope(artifact)
    actor_id = _id(actor_id, "ARTIFACT_ACTOR_INVALID")
    idempotency_key = _id(idempotency_key, "ARTIFACT_IDEMPOTENCY_INVALID")
    correlation_id = _id(correlation_id, "ARTIFACT_CORRELATION_INVALID")
    if not isinstance(expected_version, int) or expected_version < 0:
        raise ContractError("ARTIFACT_EXPECTED_VERSION_INVALID")
    return {
        "schema_version": ARTIFACT_PUBLISH_REQUEST_SCHEMA_VERSION,
        "request_id": "publish-request-" + hashlib.sha256(
            canonical_json(
                {
                    "artifact_id": envelope["artifact_id"],
                    "artifact_canonical_sha256": envelope["canonical_sha256"],
                    "idempotency_key": idempotency_key,
                }
            )
        ).hexdigest(),
        "artifact": envelope,
        "actor_id": actor_id,
        "idempotency_key": idempotency_key,
        "correlation_id": correlation_id,
        "expected_version": expected_version,
    }


def receipt_id(receipt: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_id"}
    return "receipt-" + hashlib.sha256(canonical_json(unsigned)).hexdigest()


def build_receipt(
    *,
    receipt_type: str,
    artifact: Mapping[str, Any],
    actor_id: str,
    idempotency_key: str,
    correlation_id: str,
    expected_version: int,
    resulting_version: int,
    previous_receipt_sha256: str | None,
    created_at: str,
    fencing_token: str | None = None,
    status: str = "accepted",
) -> dict[str, Any]:
    envelope = validate_artifact_envelope(artifact)
    if receipt_type not in RECEIPT_TYPES:
        raise ContractError("RECEIPT_TYPE_INVALID")
    actor_id = _id(actor_id, "RECEIPT_ACTOR_INVALID")
    idempotency_key = _id(idempotency_key, "RECEIPT_IDEMPOTENCY_INVALID")
    correlation_id = _id(correlation_id, "RECEIPT_CORRELATION_INVALID")
    if not isinstance(expected_version, int) or expected_version < 0:
        raise ContractError("RECEIPT_EXPECTED_VERSION_INVALID")
    if not isinstance(resulting_version, int) or resulting_version != expected_version + 1:
        raise ContractError("RECEIPT_RESULTING_VERSION_INVALID")
    if previous_receipt_sha256 is not None:
        _sha(previous_receipt_sha256, "RECEIPT_PREVIOUS_HASH_INVALID")
    if fencing_token is not None:
        fencing_token = _id(fencing_token, "RECEIPT_FENCING_INVALID")
    created_at = _timestamp(created_at, "RECEIPT_CREATED_AT_INVALID")
    receipt = {
        "schema_version": ARTIFACT_RECEIPT_SCHEMA_VERSION,
        "receipt_type": receipt_type,
        "receipt_id": "",
        "artifact_id": envelope["artifact_id"],
        "artifact_type": envelope["artifact_type"],
        "trust_domain": envelope["trust_domain"],
        "artifact_canonical_sha256": envelope["canonical_sha256"],
        "artifact_raw_sha256": envelope["raw_sha256"],
        "schema_ref": envelope["schema_ref"],
        "predecessor_refs": envelope["predecessor_refs"],
        "lineage": envelope["lineage"],
        "actor_id": actor_id,
        "idempotency_key": idempotency_key,
        "correlation_id": correlation_id,
        "expected_version": expected_version,
        "resulting_version": resulting_version,
        "fencing_token": fencing_token,
        "status": status,
        "created_at": created_at,
        "previous_receipt_sha256": previous_receipt_sha256,
    }
    receipt["receipt_id"] = receipt_id(receipt)
    return receipt


def validate_receipt(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError("RECEIPT_ROOT_INVALID")
    if payload.get("schema_version") != ARTIFACT_RECEIPT_SCHEMA_VERSION:
        raise ContractError("RECEIPT_SCHEMA_INVALID")
    receipt_type = payload.get("receipt_type")
    if receipt_type not in RECEIPT_TYPES:
        raise ContractError("RECEIPT_TYPE_INVALID")
    receipt = dict(payload)
    _id(receipt.get("receipt_id"), "RECEIPT_ID_INVALID")
    _id(receipt.get("artifact_id"), "RECEIPT_ARTIFACT_ID_INVALID")
    _id(receipt.get("artifact_type"), "RECEIPT_ARTIFACT_TYPE_INVALID")
    _id(receipt.get("trust_domain"), "RECEIPT_TRUST_DOMAIN_INVALID")
    _sha(receipt.get("artifact_canonical_sha256"), "RECEIPT_CANONICAL_HASH_INVALID")
    _sha(receipt.get("artifact_raw_sha256"), "RECEIPT_RAW_HASH_INVALID")
    _id(receipt.get("schema_ref"), "RECEIPT_SCHEMA_REF_INVALID")
    _predecessors(receipt.get("predecessor_refs"))
    _lineage(receipt.get("lineage"))
    _id(receipt.get("actor_id"), "RECEIPT_ACTOR_INVALID")
    _id(receipt.get("idempotency_key"), "RECEIPT_IDEMPOTENCY_INVALID")
    _id(receipt.get("correlation_id"), "RECEIPT_CORRELATION_INVALID")
    expected = receipt.get("expected_version")
    resulting = receipt.get("resulting_version")
    if not isinstance(expected, int) or expected < 0:
        raise ContractError("RECEIPT_EXPECTED_VERSION_INVALID")
    if not isinstance(resulting, int) or resulting != expected + 1:
        raise ContractError("RECEIPT_RESULTING_VERSION_INVALID")
    if receipt.get("fencing_token") is not None:
        _id(receipt["fencing_token"], "RECEIPT_FENCING_INVALID")
    if receipt.get("status") not in {"accepted", "revoked"}:
        raise ContractError("RECEIPT_STATUS_INVALID")
    _timestamp(receipt.get("created_at"), "RECEIPT_CREATED_AT_INVALID")
    previous = receipt.get("previous_receipt_sha256")
    if previous is not None:
        _sha(previous, "RECEIPT_PREVIOUS_HASH_INVALID")
    if receipt_id(receipt) != receipt["receipt_id"]:
        raise ContractError("RECEIPT_ID_MISMATCH")
    return receipt
