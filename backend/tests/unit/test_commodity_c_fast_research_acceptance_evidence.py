from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.config import Settings
from app.services.commodity_c_fast_research_acceptance_evidence import (
    CommodityCFastResearchAcceptanceEvidenceError,
    CommodityCFastResearchAcceptanceEvidenceService,
)
from test_commodity_c_fast_simnow_research_acceptance import (
    ACCEPTANCE_NOW,
    ACCOUNT_SHA256,
    acceptance,
    acceptance_inputs as _source_acceptance_inputs_fixture,
    bundle,
    consume_kwargs,
    signed_acceptance,
    write_json,
)


@pytest.fixture
def acceptance_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    return _source_acceptance_inputs_fixture.__wrapped__(tmp_path, monkeypatch)


def build_runtime_evidence(
    inputs: dict,
) -> tuple[
    CommodityCFastResearchAcceptanceEvidenceService,
    Path,
    Path,
    Path,
]:
    signed_path, _verified = signed_acceptance(inputs)
    consume_path, receipt_path = acceptance.consume_signed_acceptance(
        signed_path,
        **consume_kwargs(inputs),
    )
    custody = bundle.custody_facts(inputs["custody_dir"])
    settings = Settings(
        commodity_c_fast_simnow_execution_permit_enabled=True,
        commodity_c_fast_simnow_execution_permit_path=str(
            inputs["private_dir"] / "execution-permit.json"
        ),
        commodity_c_fast_simnow_execution_permit_trusted_keyring_path=str(
            inputs["private_dir"] / "execution-keyring.json"
        ),
        commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256=("9" * 64),
        commodity_c_fast_simnow_research_acceptance_path=str(signed_path),
        commodity_c_fast_simnow_research_acceptance_consume_path=str(consume_path),
        commodity_c_fast_simnow_research_acceptance_receipt_path=str(receipt_path),
        commodity_c_fast_simnow_research_acceptance_trusted_keyring_path=str(
            inputs["acceptance_keyring_path"]
        ),
        commodity_c_fast_simnow_research_acceptance_expected_keyring_raw_sha256=(
            inputs["acceptance_keyring_sha256"]
        ),
        commodity_c_fast_simnow_research_acceptance_custody_root=str(
            inputs["custody_dir"]
        ),
        commodity_c_fast_simnow_research_acceptance_expected_custody_root_path_sha256=(
            custody.root_path_sha256
        ),
        commodity_c_fast_simnow_research_acceptance_expected_custody_identity_sha256=(
            custody.identity_sha256
        ),
        commodity_c_fast_simnow_research_keyring_path=str(
            inputs["research_keyring_path"]
        ),
        commodity_c_fast_simnow_research_expected_keyring_raw_sha256=(
            inputs["research_keyring_sha256"]
        ),
        commodity_c_fast_simnow_research_expected_signer_sha256=(
            inputs["research_signer_sha256"]
        ),
        commodity_c_fast_simnow_research_acceptance_expected_signer_sha256=(
            inputs["acceptance_signer_sha256"]
        ),
        commodity_c_fast_simnow_research_artifact_paths_json=json.dumps(
            {role: str(path) for role, path in inputs["artifacts"].items()}
        ),
        commodity_c_fast_simnow_account_hashes=ACCOUNT_SHA256,
    )
    service = CommodityCFastResearchAcceptanceEvidenceService(
        settings=settings,
        clock=lambda: ACCEPTANCE_NOW,
        full_acceptance_verifier=acceptance.verify_signed_acceptance,
        contract_schema_validator=acceptance.validate_json_schema,
        consume_schema_path=acceptance.CONSUME_SCHEMA_PATH,
        receipt_schema_path=acceptance.RECEIPT_SCHEMA_PATH,
    )
    return service, signed_path, consume_path, receipt_path


def test_runtime_reuses_full_pr165_verifier_and_exact_receipt(
    acceptance_inputs: dict,
) -> None:
    service, _signed, consume_path, receipt_path = build_runtime_evidence(
        acceptance_inputs
    )

    verified = service.verify_existing_receipt()

    assert verified.acceptance["acceptance_state"] == (
        "READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY"
    )
    assert (
        verified.consume_raw_sha256
        == hashlib.sha256(consume_path.read_bytes()).hexdigest()
    )
    assert (
        verified.receipt_raw_sha256
        == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    )


def test_runtime_rejects_post_receipt_research_artifact_tamper(
    acceptance_inputs: dict,
) -> None:
    service, *_ = build_runtime_evidence(acceptance_inputs)
    artifact = acceptance_inputs["artifacts"]["signal_evidence"]
    artifact.write_bytes(artifact.read_bytes() + b"forged\n")

    with pytest.raises(
        CommodityCFastResearchAcceptanceEvidenceError,
        match="FULL_PR165_ACCEPTANCE_CHAIN_INVALID",
    ):
        service.verify_existing_receipt()


@pytest.mark.parametrize(
    ("target", "mutation"),
    [
        (
            "receipt",
            lambda payload: payload.__setitem__(
                "expected_simnow_account_sha256", "f" * 64
            ),
        ),
        (
            "consume",
            lambda payload: payload.__setitem__("selected_products", ["ag"]),
        ),
    ],
)
def test_runtime_rejects_forged_receipt_or_marker_splice(
    acceptance_inputs: dict,
    target: str,
    mutation,
) -> None:
    service, _signed, consume_path, receipt_path = build_runtime_evidence(
        acceptance_inputs
    )
    path = receipt_path if target == "receipt" else consume_path
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutation(payload)
    write_json(path, payload)

    with pytest.raises(CommodityCFastResearchAcceptanceEvidenceError):
        service.verify_existing_receipt()


def test_runtime_rejects_acceptance_signature_or_keyring_change(
    acceptance_inputs: dict,
) -> None:
    service, signed_path, _consume, _receipt = build_runtime_evidence(acceptance_inputs)
    payload = json.loads(signed_path.read_text(encoding="utf-8"))
    payload["human_signature"] = "forged-human-claim"
    write_json(signed_path, payload)

    with pytest.raises(
        CommodityCFastResearchAcceptanceEvidenceError,
        match="FULL_PR165_ACCEPTANCE_CHAIN_INVALID|ACCEPTANCE_EXACT_BYTES_INVALID",
    ):
        service.verify_existing_receipt()


def test_runtime_rejects_expired_acceptance(
    acceptance_inputs: dict,
) -> None:
    service, *_ = build_runtime_evidence(acceptance_inputs)
    service.clock = lambda: ACCEPTANCE_NOW + timedelta(minutes=8)

    with pytest.raises(
        CommodityCFastResearchAcceptanceEvidenceError,
        match="FULL_PR165_ACCEPTANCE_CHAIN_INVALID|ACCEPTANCE_EXPIRED",
    ):
        service.verify_existing_receipt()
