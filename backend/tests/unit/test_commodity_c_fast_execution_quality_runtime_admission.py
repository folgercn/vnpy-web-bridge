from __future__ import annotations

import ast
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.schemas.commodity_c_fast_execution_quality_runtime_admission import (
    derived_runtime_admission_id,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (
    CFastExecutionQualityRuntimeAdmissionError,
    CommodityCFastExecutionQualityRuntimeAdmissionConsumer,
    canonical_json,
    sha256_bytes,
)


NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
CONTRACTS = ("SHFE.ag2612", "SHFE.cu2612")
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


def _sha256_json(value: object) -> str:
    return sha256_bytes(canonical_json(value))


def revalidation(
    *,
    trigger: str = "startup",
    observed_at: datetime = NOW,
) -> CFastExecutionQualityRuntimeRevalidationDTO:
    core = {
        "schema_version": (
            "commodity_c_fast_execution_quality_runtime_revalidation_v1"
        ),
        "trigger": trigger,
        "revalidated_at_utc": observed_at.isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (observed_at + timedelta(minutes=8))
        .isoformat()
        .replace("+00:00", "Z"),
        "exact_contracts": list(CONTRACTS),
        "signed_p0_acceptance_sha256": "1" * 64,
        "collection_admission_sha256": "2" * 64,
        "execution_policy_sha256": "3" * 64,
        "signed_snapshot_sha256": "4" * 64,
        "virtual_intent_plan_sha256": "5" * 64,
        "contract_spec_set_sha256": "6" * 64,
        "custody_binding_sha256": "7" * 64,
        "p0_acceptance_state": "VERIFIED",
        "collection_admission_state": "VERIFIED",
        "execution_policy_state": "VERIFIED",
        "signed_snapshot_state": "VERIFIED",
        "virtual_intent_plan_state": "VERIFIED",
        "contract_spec_state": "VERIFIED",
        "custody_state": "VERIFIED",
        **FALSE_AUTHORITY,
    }
    return CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
        {**core, "receipt_sha256": _sha256_json(core)}
    )


def build_fixture(
    tmp_path: Path,
    *,
    receipt: CFastExecutionQualityRuntimeRevalidationDTO | None = None,
    now: datetime = NOW,
    expires_at: datetime | None = None,
) -> tuple[
    CommodityCFastExecutionQualityRuntimeAdmissionConsumer,
    CFastExecutionQualityRuntimeRevalidationDTO,
    Path,
    Path,
]:
    receipt = receipt or revalidation()
    root = tmp_path.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    admission_path = root / "runtime-admission.json"
    keyring_path = root / "runtime-admission-keyring.json"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema_version": (
            "commodity_c_fast_execution_quality_runtime_admission_trusted_keys_v1"
        ),
        "purpose": (
            "c_fast_execution_quality_runtime_admission_signature_verification"
        ),
        "trusted_keys": [
            {
                "key_id": "runtime-admission-reviewer-v1",
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "signer_type": "human",
                "reviewer_role": "human_runtime_admission_reviewer",
            }
        ],
    }
    keyring_raw = canonical_json(keyring) + b"\n"
    keyring_path.write_bytes(keyring_raw)
    keyring_path.chmod(0o600)

    core = {
        "schema_version": ("commodity_c_fast_execution_quality_runtime_admission_v1"),
        "purpose": ("c_fast_execution_quality_readonly_sidecar_runtime_admission"),
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "parent_issue_number": 114,
        "issue_number": 217,
        "issued_at_utc": now.isoformat().replace("+00:00", "Z"),
        "not_before_utc": now.isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (expires_at or now + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z"),
        "signer_type": "human",
        "reviewer_role": "human_runtime_admission_reviewer",
        "human_signature": "reviewed-and-signed-for-readonly-sidecar-only",
        "signer_key_id": "runtime-admission-reviewer-v1",
        "revalidation_receipt_sha256": receipt.receipt_sha256,
        "exact_contracts": list(receipt.exact_contracts),
        "artifact_raw_sha256": {
            "signed_p0_acceptance": receipt.signed_p0_acceptance_sha256,
            "collection_admission": receipt.collection_admission_sha256,
            "execution_policy": receipt.execution_policy_sha256,
            "signed_snapshot": receipt.signed_snapshot_sha256,
            "virtual_intent_plan": receipt.virtual_intent_plan_sha256,
            "contract_spec_set": receipt.contract_spec_set_sha256,
            "custody_binding": receipt.custody_binding_sha256,
        },
        "journal_root_path_sha256": "8" * 64,
        "journal_root_identity_sha256": "9" * 64,
        "evidence_export_root_path_sha256": "a" * 64,
        "evidence_export_root_identity_sha256": "b" * 64,
        "tick_input_mode": "LOCAL_COPY_CALLBACK_NO_RPC_CAPABILITY",
        "repository_mode": "CREATE_ONLY_SIDECAR_READ_ONLY_API",
        "questdb_mode": "READ_ONLY_ADAPTER_NOT_CONNECTION_AUTHORITY",
        "full_runtime_build_required": True,
        "admission_is_runtime_capability": False,
        **FALSE_AUTHORITY,
    }
    with_id = {**core, "admission_id": derived_runtime_admission_id(core)}
    signature = private_key.sign(canonical_json(with_id))
    admission = {
        **with_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    admission_path.write_bytes(canonical_json(admission) + b"\n")
    admission_path.chmod(0o600)

    settings = Settings(
        commodity_c_fast_execution_quality_runtime_enabled=True,
        commodity_c_fast_execution_quality_runtime_admission_path=str(admission_path),
        commodity_c_fast_execution_quality_runtime_admission_trusted_keyring_path=str(
            keyring_path
        ),
        commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256=sha256_bytes(
            keyring_raw
        ),
        commodity_c_fast_execution_quality_runtime_admission_expected_owner_uid=os.getuid(),
    )
    return (
        CommodityCFastExecutionQualityRuntimeAdmissionConsumer(
            settings=settings,
            clock=lambda: now,
        ),
        receipt,
        admission_path,
        keyring_path,
    )


def test_signed_runtime_admission_verifies_one_exact_receipt(
    tmp_path: Path,
) -> None:
    consumer, receipt, _, _ = build_fixture(tmp_path)

    verified = consumer.verify_for_receipt(receipt)

    assert verified.admission.revalidation_receipt_sha256 == receipt.receipt_sha256
    assert verified.admission.exact_contracts == CONTRACTS
    assert len(verified.admission_raw_sha256) == 64
    assert len(verified.trusted_keyring_raw_sha256) == 64
    assert all(getattr(verified.admission, field) is False for field in FALSE_AUTHORITY)


def test_signature_tamper_fails_closed(tmp_path: Path) -> None:
    consumer, receipt, admission_path, _ = build_fixture(tmp_path)
    payload = json.loads(admission_path.read_text(encoding="utf-8"))
    signature = bytearray(base64.b64decode(payload["signature"]))
    signature[0] ^= 1
    payload["signature"] = base64.b64encode(signature).decode("ascii")
    admission_path.write_bytes(canonical_json(payload) + b"\n")
    admission_path.chmod(0o600)

    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_SIGNATURE_INVALID",
    ):
        consumer.verify_for_receipt(receipt)


def test_receipt_splice_and_expired_reuse_fail_closed(tmp_path: Path) -> None:
    consumer, receipt, _, _ = build_fixture(tmp_path)
    changed = revalidation(trigger="reload")

    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_RECEIPT_BINDING_MISMATCH",
    ):
        consumer.verify_for_receipt(changed)

    expired_consumer, expired_receipt, _, _ = build_fixture(
        tmp_path / "expired",
        expires_at=NOW + timedelta(minutes=5),
    )
    expired_consumer.clock = lambda: NOW + timedelta(minutes=6)
    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_SCHEMA_INVALID|RUNTIME_ADMISSION_TIMING_INVALID",
    ):
        expired_consumer.verify_for_receipt(expired_receipt)


def test_keyring_pin_and_private_file_custody_are_mandatory(
    tmp_path: Path,
) -> None:
    consumer, receipt, admission_path, _ = build_fixture(tmp_path)
    admission_path.chmod(0o644)

    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_FILE_CUSTODY_INVALID",
    ):
        consumer.verify_for_receipt(receipt)

    consumer, receipt, _, _ = build_fixture(tmp_path / "bad-pin")
    consumer.settings.commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256 = (
        "f" * 64
    )
    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_KEYRING_PIN_MISMATCH",
    ):
        consumer.verify_for_receipt(receipt)


def test_complete_keyring_domain_is_validated_before_signer_selection(
    tmp_path: Path,
) -> None:
    consumer, receipt, _, keyring_path = build_fixture(tmp_path)
    payload = json.loads(keyring_path.read_text(encoding="utf-8"))
    payload["trusted_keys"].append(
        {
            "key_id": "unused-invalid-reviewer-v1",
            "public_key_base64": "A" * 44,
            "signer_type": "human",
            "reviewer_role": "human_runtime_admission_reviewer",
        }
    )
    raw = canonical_json(payload) + b"\n"
    keyring_path.write_bytes(raw)
    keyring_path.chmod(0o600)
    consumer.settings.commodity_c_fast_execution_quality_runtime_admission_expected_keyring_raw_sha256 = sha256_bytes(
        raw
    )

    with pytest.raises(
        CFastExecutionQualityRuntimeAdmissionError,
        match="RUNTIME_ADMISSION_KEYRING_MATERIAL_INVALID",
    ):
        consumer.verify_for_receipt(receipt)


def test_runtime_admission_consumer_has_no_external_or_trading_dependency() -> None:
    service_path = (
        Path(__file__).resolve().parents[2]
        / "app/services/commodity_c_fast_execution_quality_runtime_admission.py"
    )
    tree = ast.parse(service_path.read_text(encoding="utf-8"))
    imports = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}

    assert imports.isdisjoint(
        {
            "app.services.commodity_simnow",
            "app.services.market_data_service",
            "app.services.tick_persistence",
            "app.services.trade_service",
            "app.services.vnpy_rpc_service",
            "psycopg",
            "questdb",
        }
    )
    assert names.isdisjoint(
        {"TradeService", "cancel_order", "rpc_service", "send_order"}
    )
