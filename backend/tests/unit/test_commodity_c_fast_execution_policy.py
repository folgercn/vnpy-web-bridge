from __future__ import annotations

import base64
import copy
import importlib.util
import json
from pathlib import Path
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeReceiptDTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPolicyDTO,
)
from app.services.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeError,
    PLACEHOLDER_SIGNATURE,
    execution_policy_freeze_sha256,
    parse_execution_policy_freeze_json,
    parse_unsigned_execution_policy_freeze_json,
    unsigned_execution_policy_freeze_payload,
    verify_execution_policy_freeze,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    sha256_json,
)


def policy() -> CFastVirtualIntentPolicyDTO:
    return CFastVirtualIntentPolicyDTO(
        schema_version="commodity_c_fast_virtual_intent_policy_v1",
        policy_id="c-fast-execution-quality-policy-v1",
        max_child_order_lots=3,
        horizon_schedule_ms=(250, 1_000, 5_000, 30_000, 60_000),
        decision_book_levels=5,
        protected_price_rule="DEFERRED_TO_DECISION_SNAPSHOT",
        passive_fill_mode="BOUNDS_ONLY_NO_POINT_PROBABILITY",
        policy_authority_state=(
            "UNSIGNED_FOUNDATION_INPUT_REQUIRES_SEPARATE_FREEZE"
        ),
        foundation_only=True,
        collection_authorized=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def unsigned_freeze_payload() -> dict:
    frozen_policy = policy()
    return {
        "schema_version": "commodity_c_fast_execution_policy_freeze_v1",
        "freeze_id": "c-fast-policy-freeze-20260724-v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "policy_scope": "EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY",
        "policy": frozen_policy.model_dump(mode="json"),
        "policy_hash": sha256_json(frozen_policy.model_dump(mode="json")),
        "frozen_at_utc": "2026-07-24T15:30:00Z",
        "reviewer_role": "human_execution_policy_reviewer",
        "human_reviewed": True,
        "policy_frozen": True,
        "protected_price_rule_state": "DEFERRED_NOT_COLLECTION_READY",
        "p0_pass_required_before_collection": True,
        "foundation_only": True,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
        "signer_key_id": "c-fast-policy-freeze-signer-1",
    }


def sign_payload(
    payload: dict,
    private_key: Ed25519PrivateKey,
) -> CFastExecutionPolicyFreezeDTO:
    draft = CFastExecutionPolicyFreezeDTO.model_validate(
        {**payload, "signature": PLACEHOLDER_SIGNATURE}
    )
    signature = private_key.sign(
        canonical_json(unsigned_execution_policy_freeze_payload(draft))
    )
    return CFastExecutionPolicyFreezeDTO.model_validate(
        {
            **payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def trusted_keys(
    private_key: Ed25519PrivateKey,
    *,
    purpose: str = "execution_quality_policy_freeze_signer",
) -> dict:
    encoded = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return {
        "c-fast-policy-freeze-signer-1": {
            "public_key_base64": encoded,
            "purpose": purpose,
        }
    }


def test_verified_freeze_returns_content_addressed_non_activation_receipt() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)

    receipt = verify_execution_policy_freeze(
        freeze,
        trusted_public_keys=trusted_keys(private_key),
    )

    assert isinstance(receipt, CFastExecutionPolicyFreezeReceiptDTO)
    assert receipt.freeze_sha256 == execution_policy_freeze_sha256(freeze)
    assert receipt.policy_hash == freeze.policy_hash
    assert receipt.policy_id == freeze.policy.policy_id
    assert receipt.signature_verified is True
    assert receipt.policy_frozen is True
    assert receipt.protected_price_rule_state == (
        "DEFERRED_NOT_COLLECTION_READY"
    )
    assert receipt.collection_authorized is False
    assert receipt.runtime_activation_authorized is False
    assert receipt.authority_granted is False
    assert receipt.dispatch_allowed is False
    assert receipt.replacement_allowed is False
    assert receipt.production_allowed is False


def test_freeze_hash_and_receipt_are_deterministic() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)
    keys = trusted_keys(private_key)

    first = verify_execution_policy_freeze(
        freeze, trusted_public_keys=keys
    )
    second = verify_execution_policy_freeze(
        freeze, trusted_public_keys=keys
    )
    reloaded = parse_execution_policy_freeze_json(
        json.dumps(freeze.model_dump(mode="json"))
    )

    assert first == second
    assert execution_policy_freeze_sha256(
        freeze
    ) == execution_policy_freeze_sha256(reloaded)


@pytest.mark.parametrize(
    "field",
    [
        "collection_authorized",
        "runtime_activation_authorized",
        "authority_granted",
        "dispatch_allowed",
        "replacement_allowed",
        "production_allowed",
    ],
)
def test_activation_literals_cannot_be_enabled(field: str) -> None:
    payload = unsigned_freeze_payload()
    payload[field] = True

    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeDTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


def test_policy_hash_mismatch_is_rejected_before_signature_check() -> None:
    payload = unsigned_freeze_payload()
    payload["policy_hash"] = "0" * 64

    with pytest.raises(ValidationError, match="policy_hash mismatch"):
        CFastExecutionPolicyFreezeDTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


def test_rehashed_policy_tamper_still_fails_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)
    tampered = freeze.model_dump(mode="json")
    tampered["policy"]["max_child_order_lots"] = 4
    tampered["policy_hash"] = sha256_json(tampered["policy"])
    self_consistent = CFastExecutionPolicyFreezeDTO.model_validate(tampered)

    with pytest.raises(
        CFastExecutionPolicyFreezeError, match="SIGNATURE_INVALID"
    ):
        verify_execution_policy_freeze(
            self_consistent,
            trusted_public_keys=trusted_keys(private_key),
        )


def test_untrusted_signer_and_wrong_key_purpose_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)
    other_key = Ed25519PrivateKey.generate()

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="SIGNER_KEY_NOT_TRUSTED",
    ):
        verify_execution_policy_freeze(
            freeze,
            trusted_public_keys={
                "another-key": next(
                    iter(trusted_keys(other_key).values())
                )
            },
        )
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="TRUSTED_KEY_PURPOSE_INVALID",
    ):
        verify_execution_policy_freeze(
            freeze,
            trusted_public_keys=trusted_keys(
                private_key,
                purpose="research_snapshot_signer",
            ),
        )


def test_malformed_trusted_key_entries_fail_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)
    entry = next(iter(trusted_keys(private_key).values()))

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="TRUSTED_KEY_ENTRY_INVALID",
    ):
        verify_execution_policy_freeze(
            freeze,
            trusted_public_keys={
                "c-fast-policy-freeze-signer-1": {
                    **entry,
                    "unexpected": True,
                }
            },
        )
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="TRUSTED_KEYS_EMPTY",
    ):
        verify_execution_policy_freeze(
            freeze,
            trusted_public_keys={},
        )


def test_strict_json_rejects_duplicate_key_non_finite_and_extra_field() -> None:
    payload = {
        **unsigned_freeze_payload(),
        "signature": PLACEHOLDER_SIGNATURE,
    }
    raw = json.dumps(payload, separators=(",", ":"))
    duplicate = raw.replace(
        '{"schema_version":',
        '{"freeze_id":"duplicate-freeze","schema_version":',
        1,
    )

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_INVALID",
    ):
        parse_execution_policy_freeze_json(duplicate)
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_INVALID",
    ):
        parse_execution_policy_freeze_json(
            raw[:-1] + ',"non_finite":NaN}'
        )
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_SCHEMA_INVALID",
    ):
        parse_execution_policy_freeze_json(
            json.dumps({**payload, "unexpected": True})
        )


def test_unsigned_parser_rejects_existing_signature() -> None:
    payload = unsigned_freeze_payload()
    parsed = parse_unsigned_execution_policy_freeze_json(
        json.dumps(payload)
    )
    assert parsed.signature == PLACEHOLDER_SIGNATURE

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="UNSIGNED_POLICY_FREEZE_CONTAINS_SIGNATURE",
    ):
        parse_unsigned_execution_policy_freeze_json(
            json.dumps({**payload, "signature": PLACEHOLDER_SIGNATURE})
        )


def test_parser_rejects_invalid_unicode_and_oversized_input() -> None:
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_INVALID",
    ):
        parse_execution_policy_freeze_json("\ud800")
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_TOO_LARGE",
    ):
        parse_execution_policy_freeze_json(b" " * (64 * 1024 + 1))


def _load_signing_script():
    script_path = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "commodity_c_fast_execution_policy_sign.py"
    )
    spec = importlib.util.spec_from_file_location(
        "commodity_c_fast_execution_policy_sign",
        script_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_raw_private_key(
    path: Path,
    private_key: Ed25519PrivateKey,
    *,
    mode: int = 0o600,
) -> None:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_text(
        base64.b64encode(raw).decode("ascii"),
        encoding="utf-8",
    )
    path.chmod(mode)


def test_signing_tool_produces_verifiable_create_only_0600_output(
    tmp_path: Path,
) -> None:
    module = _load_signing_script()
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "policy-freeze.key"
    output_path = tmp_path / "signed-freeze.json"
    _write_raw_private_key(key_path, private_key)

    signed, expected_hash = module.sign_policy_freeze(
        json.dumps(unsigned_freeze_payload()),
        module.load_private_key(key_path),
    )
    module.write_private_json_create_only(output_path, signed)

    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    freeze = parse_execution_policy_freeze_json(output_path.read_bytes())
    receipt = verify_execution_policy_freeze(
        freeze,
        trusted_public_keys=trusted_keys(private_key),
    )
    assert receipt.freeze_sha256 == expected_hash
    with pytest.raises(FileExistsError):
        module.write_private_json_create_only(output_path, signed)
    assert parse_execution_policy_freeze_json(
        output_path.read_bytes()
    ) == freeze


def test_signing_tool_rejects_wide_key_mode_and_symlink(
    tmp_path: Path,
) -> None:
    module = _load_signing_script()
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "policy-freeze.key"
    _write_raw_private_key(key_path, private_key, mode=0o644)

    with pytest.raises(ValueError, match="0600 or stricter"):
        module.load_private_key(key_path)

    key_path.chmod(0o600)
    symlink_path = tmp_path / "policy-freeze-link.key"
    symlink_path.symlink_to(key_path)
    with pytest.raises(ValueError, match="non-symlink"):
        module.load_private_key(symlink_path)


def test_signing_tool_refuses_output_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    module = _load_signing_script()
    target = tmp_path / "existing-target.json"
    target.write_text('{"preserved":true}\n', encoding="utf-8")
    output_link = tmp_path / "signed-freeze.json"
    output_link.symlink_to(target)

    with pytest.raises(FileExistsError):
        module.write_private_json_create_only(
            output_link,
            {"must_not_be_written": True},
        )

    assert target.read_text(encoding="utf-8") == '{"preserved":true}\n'


def test_signature_does_not_change_unsigned_freeze_hash() -> None:
    private_key = Ed25519PrivateKey.generate()
    freeze = sign_payload(unsigned_freeze_payload(), private_key)
    modified = copy.deepcopy(freeze.model_dump(mode="json"))
    modified["signature"] = base64.b64encode(bytes(64)).decode("ascii")
    other_signature = CFastExecutionPolicyFreezeDTO.model_validate(modified)

    assert execution_policy_freeze_sha256(
        freeze
    ) == execution_policy_freeze_sha256(other_signature)
