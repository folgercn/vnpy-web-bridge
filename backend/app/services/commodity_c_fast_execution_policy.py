from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeReceiptDTO,
    CFastExecutionPolicyFreezeReceiptV2DTO,
    CFastExecutionPolicyFreezeV2DTO,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    sha256_json,
)


MAX_POLICY_FREEZE_JSON_BYTES = 64 * 1024
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
SIGNER_KEY_PURPOSE = "execution_quality_policy_freeze_signer"
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


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
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_SCHEMA_INVALID") from exc


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
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_SCHEMA_INVALID") from exc


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
        schema_version=("commodity_c_fast_execution_policy_freeze_receipt_v1"),
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


def unsigned_execution_policy_freeze_v2_payload(
    freeze: CFastExecutionPolicyFreezeV2DTO,
) -> dict[str, Any]:
    return freeze.model_dump(mode="json", exclude={"signature"})


def execution_policy_freeze_v2_sha256(
    freeze: CFastExecutionPolicyFreezeV2DTO,
) -> str:
    return sha256_json(unsigned_execution_policy_freeze_v2_payload(freeze))


def parse_execution_policy_freeze_v2_json(
    raw: str | bytes,
) -> CFastExecutionPolicyFreezeV2DTO:
    payload = _strict_json_object(raw)
    try:
        return CFastExecutionPolicyFreezeV2DTO.model_validate(payload)
    except ValidationError as exc:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_V2_SCHEMA_INVALID"
        ) from exc


def parse_unsigned_execution_policy_freeze_v2_json(
    raw: str | bytes,
) -> CFastExecutionPolicyFreezeV2DTO:
    payload = _strict_json_object(raw)
    if "signature" in payload:
        raise CFastExecutionPolicyFreezeError(
            "UNSIGNED_POLICY_FREEZE_CONTAINS_SIGNATURE"
        )
    try:
        return CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )
    except ValidationError as exc:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_V2_SCHEMA_INVALID"
        ) from exc


def parse_unsigned_execution_policy_freeze_artifact_json(
    raw: str | bytes,
) -> CFastExecutionPolicyFreezeDTO | CFastExecutionPolicyFreezeV2DTO:
    payload = _strict_json_object(raw)
    if "signature" in payload:
        raise CFastExecutionPolicyFreezeError(
            "UNSIGNED_POLICY_FREEZE_CONTAINS_SIGNATURE"
        )
    schema_version = payload.get("schema_version")
    model: type[CFastExecutionPolicyFreezeDTO | CFastExecutionPolicyFreezeV2DTO]
    error_code: str
    if schema_version == "commodity_c_fast_execution_policy_freeze_v1":
        model = CFastExecutionPolicyFreezeDTO
        error_code = "POLICY_FREEZE_SCHEMA_INVALID"
    elif schema_version == "commodity_c_fast_execution_policy_freeze_v2":
        model = CFastExecutionPolicyFreezeV2DTO
        error_code = "POLICY_FREEZE_V2_SCHEMA_INVALID"
    else:
        raise CFastExecutionPolicyFreezeError(
            "POLICY_FREEZE_SCHEMA_VERSION_UNSUPPORTED"
        )
    try:
        return model.model_validate({**payload, "signature": PLACEHOLDER_SIGNATURE})
    except ValidationError as exc:
        raise CFastExecutionPolicyFreezeError(error_code) from exc


def verify_execution_policy_freeze_v2_raw_chain(
    freeze_raw: bytes,
    *,
    superseded_freeze_raw: bytes,
    trusted_public_keys: Mapping[str, Any],
    expected_trusted_public_keys_sha256: str,
) -> CFastExecutionPolicyFreezeReceiptV2DTO:
    if type(freeze_raw) is not bytes or type(superseded_freeze_raw) is not bytes:
        raise CFastExecutionPolicyFreezeError("RAW_FREEZE_BYTES_REQUIRED")
    trusted_public_keys_snapshot = _verify_trusted_public_keys_pin(
        trusted_public_keys,
        expected_trusted_public_keys_sha256,
    )
    superseded_freeze = parse_execution_policy_freeze_json(superseded_freeze_raw)
    freeze = parse_execution_policy_freeze_v2_json(freeze_raw)
    return _verify_execution_policy_freeze_v2_models(
        freeze,
        freeze_raw_sha256=hashlib.sha256(freeze_raw).hexdigest(),
        superseded_freeze=superseded_freeze,
        superseded_freeze_raw_sha256=hashlib.sha256(superseded_freeze_raw).hexdigest(),
        trusted_public_keys=trusted_public_keys_snapshot,
    )


def verify_execution_policy_freeze_v2_raw_chain_files(
    freeze_path: Path,
    *,
    superseded_freeze_path: Path,
    trusted_public_keys_path: Path,
    expected_trusted_public_keys_sha256: str,
) -> CFastExecutionPolicyFreezeReceiptV2DTO:
    freeze_raw = _read_regular_file_strict(
        freeze_path,
        maximum_bytes=MAX_POLICY_FREEZE_JSON_BYTES,
        require_private=False,
    )
    superseded_freeze_raw = _read_regular_file_strict(
        superseded_freeze_path,
        maximum_bytes=MAX_POLICY_FREEZE_JSON_BYTES,
        require_private=False,
    )
    trusted_public_keys_raw = _read_regular_file_strict(
        trusted_public_keys_path,
        maximum_bytes=MAX_POLICY_FREEZE_JSON_BYTES,
        require_private=True,
    )
    trusted_public_keys = _strict_json_object(trusted_public_keys_raw)
    return verify_execution_policy_freeze_v2_raw_chain(
        freeze_raw,
        superseded_freeze_raw=superseded_freeze_raw,
        trusted_public_keys=trusted_public_keys,
        expected_trusted_public_keys_sha256=expected_trusted_public_keys_sha256,
    )


def verify_execution_policy_freeze_v2(
    freeze_raw: bytes,
    *,
    superseded_freeze_raw: bytes,
    trusted_public_keys: Mapping[str, Any],
    expected_trusted_public_keys_sha256: str,
) -> CFastExecutionPolicyFreezeReceiptV2DTO:
    return verify_execution_policy_freeze_v2_raw_chain(
        freeze_raw,
        superseded_freeze_raw=superseded_freeze_raw,
        trusted_public_keys=trusted_public_keys,
        expected_trusted_public_keys_sha256=expected_trusted_public_keys_sha256,
    )


def _verify_execution_policy_freeze_v2_models(
    freeze: CFastExecutionPolicyFreezeV2DTO,
    *,
    freeze_raw_sha256: str,
    superseded_freeze: CFastExecutionPolicyFreezeDTO,
    superseded_freeze_raw_sha256: str,
    trusted_public_keys: Mapping[str, Any],
) -> CFastExecutionPolicyFreezeReceiptV2DTO:
    _verify_freeze_signature(
        freeze.signer_key_id,
        freeze.signature,
        unsigned_execution_policy_freeze_v2_payload(freeze),
        trusted_public_keys,
    )
    ancestry = verify_execution_policy_freeze(
        superseded_freeze,
        trusted_public_keys=trusted_public_keys,
    )
    if freeze.candidate_id != superseded_freeze.candidate_id:
        raise CFastExecutionPolicyFreezeError("SUPERSEDED_FREEZE_CANDIDATE_MISMATCH")
    if freeze.supersedes_freeze_id != superseded_freeze.freeze_id:
        raise CFastExecutionPolicyFreezeError("SUPERSEDED_FREEZE_ID_MISMATCH")
    if freeze.supersedes_freeze_sha256 != ancestry.freeze_sha256:
        raise CFastExecutionPolicyFreezeError("SUPERSEDED_FREEZE_HASH_MISMATCH")
    if freeze.supersedes_freeze_raw_sha256 != superseded_freeze_raw_sha256:
        raise CFastExecutionPolicyFreezeError("SUPERSEDED_FREEZE_RAW_HASH_MISMATCH")
    if freeze.superseded_policy_hash != superseded_freeze.policy_hash:
        raise CFastExecutionPolicyFreezeError("SUPERSEDED_POLICY_HASH_MISMATCH")

    return CFastExecutionPolicyFreezeReceiptV2DTO(
        schema_version=("commodity_c_fast_execution_policy_freeze_receipt_v2"),
        freeze_id=freeze.freeze_id,
        freeze_sha256=execution_policy_freeze_v2_sha256(freeze),
        freeze_raw_sha256=freeze_raw_sha256,
        candidate_id=freeze.candidate_id,
        supersedes_freeze_id=freeze.supersedes_freeze_id,
        supersedes_freeze_sha256=freeze.supersedes_freeze_sha256,
        supersedes_freeze_raw_sha256=freeze.supersedes_freeze_raw_sha256,
        superseded_policy_hash=freeze.superseded_policy_hash,
        policy_id=freeze.policy.policy_id,
        policy_hash=freeze.policy_hash,
        signer_key_id=freeze.signer_key_id,
        signer_key_purpose=SIGNER_KEY_PURPOSE,
        signature_verified=True,
        ancestry_signature_verified=True,
        policy_frozen=True,
        policy_rule_completeness=("COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"),
        receipt_authority_state=("NON_AUTHORITATIVE_REVERIFY_RAW_SIGNED_FREEZES"),
        p0_pass_required_before_collection=True,
        separate_collection_release_required=True,
        offline_policy_only=True,
        collection_authorized=False,
        runtime_activation_authorized=False,
        authority_granted=False,
        dispatch_allowed=False,
        order_authorized=False,
        position_mutation_authorized=False,
        dynamic_selection_allowed=False,
        automatic_promotion_authorized=False,
        database_mutation_authorized=False,
        deployment_mutation_authorized=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def _verify_trusted_public_keys_pin(
    trusted_public_keys: Mapping[str, Any],
    expected_trusted_public_keys_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(expected_trusted_public_keys_sha256, str)
        or _SHA256_PATTERN.fullmatch(expected_trusted_public_keys_sha256) is None
    ):
        raise CFastExecutionPolicyFreezeError("TRUSTED_KEYRING_PIN_INVALID")
    try:
        canonical_keyring = canonical_json(trusted_public_keys)
        actual = hashlib.sha256(canonical_keyring).hexdigest()
    except (TypeError, ValueError) as exc:
        raise CFastExecutionPolicyFreezeError("TRUSTED_KEYRING_INVALID") from exc
    if not hmac.compare_digest(actual, expected_trusted_public_keys_sha256):
        raise CFastExecutionPolicyFreezeError("TRUSTED_KEYRING_PIN_MISMATCH")
    trusted_public_keys_snapshot = _strict_json_object(canonical_keyring)
    _trusted_keys(trusted_public_keys_snapshot)
    return trusted_public_keys_snapshot


def _read_fd_bounded(fd: int, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_file_strict(
    path: Path,
    *,
    maximum_bytes: int,
    require_private: bool,
) -> bytes:
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_INVALID") from exc
    if (
        stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISREG(path_before.st_mode)
        or path_before.st_size > maximum_bytes
    ):
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_INVALID")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_INVALID") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_INVALID")
        first = _read_fd_bounded(fd, maximum_bytes)
        os.lseek(fd, 0, os.SEEK_SET)
        second = _read_fd_bounded(fd, maximum_bytes)
        after = os.fstat(fd)
    finally:
        os.close(fd)

    try:
        path_after = path.lstat()
    except OSError as exc:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_CHANGED") from exc
    if (
        len(
            {
                _file_identity(path_before),
                _file_identity(before),
                _file_identity(after),
                _file_identity(path_after),
            }
        )
        != 1
        or first != second
        or len(first) != before.st_size
    ):
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_CHANGED")
    if len(first) > maximum_bytes:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_FILE_TOO_LARGE")
    if require_private and (
        before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise CFastExecutionPolicyFreezeError(
            "TRUSTED_KEYRING_FILE_PERMISSIONS_INVALID"
        )
    return first


def _verify_freeze_signature(
    signer_key_id: str,
    signature_base64: str,
    unsigned_payload: Mapping[str, Any],
    trusted_public_keys: Mapping[str, Any],
) -> None:
    key = _trusted_keys(trusted_public_keys).get(signer_key_id)
    if key is None:
        raise CFastExecutionPolicyFreezeError("SIGNER_KEY_NOT_TRUSTED")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
        if len(signature) != 64:
            raise ValueError
        key.verify(signature, canonical_json(unsigned_payload))
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise CFastExecutionPolicyFreezeError("SIGNATURE_INVALID") from exc


def _strict_json_object(raw: str | bytes) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_INVALID") from exc
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_INVALID")
    if len(encoded) > MAX_POLICY_FREEZE_JSON_BYTES:
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_TOO_LARGE")
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
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise CFastExecutionPolicyFreezeError("POLICY_FREEZE_JSON_ROOT_INVALID")
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
            raise CFastExecutionPolicyFreezeError("TRUSTED_KEY_ENTRY_INVALID")
        if entry["purpose"] != SIGNER_KEY_PURPOSE:
            raise CFastExecutionPolicyFreezeError("TRUSTED_KEY_PURPOSE_INVALID")
        try:
            key_bytes = base64.b64decode(str(entry["public_key_base64"]), validate=True)
            if len(key_bytes) != 32:
                raise ValueError
            result[key_id] = Ed25519PublicKey.from_public_bytes(key_bytes)
        except (ValueError, binascii.Error) as exc:
            raise CFastExecutionPolicyFreezeError("TRUSTED_KEY_INVALID") from exc
    return result
