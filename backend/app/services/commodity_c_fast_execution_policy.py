from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeReceiptDTO,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    sha256_json,
)


MAX_POLICY_FREEZE_JSON_BYTES = 64 * 1024
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
SIGNER_KEY_PURPOSE = "execution_quality_policy_freeze_signer"
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class CFastExecutionPolicyFreezeError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _DuplicateKeyError(ValueError):
    pass


def unsigned_execution_policy_freeze_payload(
    freeze: CFastExecutionPolicyFreezeDTO,
) -> dict[str, Any]:
    return freeze.model_dump(mode="json", exclude={"signature"})


def execution_policy_freeze_sha256(
    freeze: CFastExecutionPolicyFreezeDTO,
) -> str:
    return sha256_json(unsigned_execution_policy_freeze_payload(freeze))


def parse_execution_policy_freeze_json(
    raw: str | bytes,
) -> CFastExecutionPolicyFreezeDTO:
    payload = _strict_json_object(raw)
    try:
        return CFastExecutionPolicyFreezeDTO.model_validate(payload)
    except ValidationError as exc:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_SCHEMA_INVALID"
        ) from exc


def parse_unsigned_execution_policy_freeze_json(
    raw: str | bytes,
) -> CFastExecutionPolicyFreezeDTO:
    payload = _strict_json_object(raw)
    if "signature" in payload:
        raise CFastExecutionPolicyFreezeError(
            "UNSIGNED_POLICY_FREEZE_CONTAINS_SIGNATURE"
        )
    try:
        return CFastExecutionPolicyFreezeDTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )
    except ValidationError as exc:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_SCHEMA_INVALID"
        ) from exc


def verify_execution_policy_freeze(
    freeze: CFastExecutionPolicyFreezeDTO,
    *,
    trusted_public_keys: Mapping[str, Any],
) -> CFastExecutionPolicyFreezeReceiptDTO:
    key = _trusted_keys(trusted_public_keys).get(freeze.signer_key_id)
    if key is None:
        raise CFastExecutionPolicyFreezeError("SIGNER_KEY_NOT_TRUSTED")
    try:
        signature = base64.b64decode(freeze.signature, validate=True)
        if len(signature) != 64:
            raise ValueError
        key.verify(
            signature,
            canonical_json(unsigned_execution_policy_freeze_payload(freeze)),
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise CFastExecutionPolicyFreezeError("SIGNATURE_INVALID") from exc

    return CFastExecutionPolicyFreezeReceiptDTO(
        schema_version=(
            "commodity_c_fast_execution_policy_freeze_receipt_v1"
        ),
        freeze_id=freeze.freeze_id,
        freeze_sha256=execution_policy_freeze_sha256(freeze),
        candidate_id=freeze.candidate_id,
        policy_id=freeze.policy.policy_id,
        policy_hash=freeze.policy_hash,
        signer_key_id=freeze.signer_key_id,
        signer_key_purpose=SIGNER_KEY_PURPOSE,
        signature_verified=True,
        policy_frozen=True,
        protected_price_rule_state="DEFERRED_NOT_COLLECTION_READY",
        p0_pass_required_before_collection=True,
        foundation_only=True,
        collection_authorized=False,
        runtime_activation_authorized=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def _strict_json_object(raw: str | bytes) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CFastExecutionPolicyFreezeError(
                "POLICY_FREEZE_JSON_INVALID"
            ) from exc
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_INVALID")
    if len(encoded) > MAX_POLICY_FREEZE_JSON_BYTES:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_JSON_TOO_LARGE"
        )
    try:
        text = encoded.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
        ValueError,
    ) as exc:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_JSON_INVALID"
        ) from exc
    if not isinstance(payload, dict):
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_JSON_ROOT_INVALID"
        )
    return payload


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _trusted_keys(
    raw: Mapping[str, Any],
) -> dict[str, Ed25519PublicKey]:
    if not isinstance(raw, Mapping) or not raw:
        raise CFastExecutionPolicyFreezeError("TRUSTED_KEYS_EMPTY")
    result: dict[str, Ed25519PublicKey] = {}
    for key_id, entry in raw.items():
        if (
            not isinstance(key_id, str)
            or _KEY_ID_PATTERN.fullmatch(key_id) is None
            or not isinstance(entry, Mapping)
            or set(entry) != {"public_key_base64", "purpose"}
        ):
            raise CFastExecutionPolicyFreezeError(
                "TRUSTED_KEY_ENTRY_INVALID"
            )
        if entry["purpose"] != SIGNER_KEY_PURPOSE:
            raise CFastExecutionPolicyFreezeError(
                "TRUSTED_KEY_PURPOSE_INVALID"
            )
        try:
            key_bytes = base64.b64decode(
                str(entry["public_key_base64"]), validate=True
            )
            if len(key_bytes) != 32:
                raise ValueError
            result[key_id] = Ed25519PublicKey.from_public_bytes(key_bytes)
        except (ValueError, binascii.Error) as exc:
            raise CFastExecutionPolicyFreezeError(
                "TRUSTED_KEY_INVALID"
            ) from exc
    return result
