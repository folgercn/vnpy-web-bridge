from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.core.config import Settings
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastShakedownSnapshotDTO,
)
from app.services.commodity_c_fast_execution_permit import (
    CommodityCFastExecutionPermitError,
    CommodityCFastExecutionPermitService,
    canonical_json,
    derived_permit_id,
)
from app.services.commodity_c_fast_research_acceptance_evidence import (
    VerifiedCommodityCFastResearchAcceptanceEvidence,
)
from commodity_c_fast_simnow_execution_permit import (
    prepare_unsigned_execution_permit,
    sign_execution_permit,
)
from test_commodity_c_fast_simnow import sign_payload
from test_commodity_c_fast_shadow import unsigned_payload
from test_commodity_simnow import NOW, make_key


class StaticEvidence:
    def __init__(
        self, evidence: VerifiedCommodityCFastResearchAcceptanceEvidence
    ) -> None:
        self.evidence = evidence

    def verify_existing_receipt(
        self,
    ) -> VerifiedCommodityCFastResearchAcceptanceEvidence:
        return self.evidence


def write_exact(path: Path, payload: dict) -> None:
    path.write_bytes(canonical_json(payload) + b"\n")
    path.chmod(0o600)


def permit_fixture(tmp_path: Path) -> dict:
    signed, snapshot_sha256 = sign_payload(unsigned_payload(), make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    row = next(row for row in snapshot.targets if row.product == "ag")
    research_key = Ed25519PrivateKey.generate()
    acceptance_key = Ed25519PrivateKey.generate()
    acceptance = {
        "acceptance_id": "cfast-simnow-research-accept-v1-" + "a" * 64,
        "acceptance_state": "READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY",
        "signer_key_id": "acceptance-test-key",
        "research_bundle_id": "cfast-simnow-research-v1-" + "b" * 64,
        "research_artifact_index_sha256": "c" * 64,
        "selected_target_index_sha256": "d" * 64,
        "custody_root_path_sha256": "e" * 64,
        "custody_identity_sha256": "f" * 64,
        "formula_target_binding_sha256": snapshot.formula_target_binding_sha256,
        "expected_simnow_account_sha256": snapshot.account_sha256,
        "execution_day": snapshot.execution_day.isoformat(),
        "expires_at": (NOW + timedelta(minutes=9)).isoformat(),
        "selected_products": ["ag"],
        "selected_targets": [
            {
                "product": "ag",
                "exact_contract": row.exact_contract,
                "previous_target_quantity": row.previous_target_quantity,
                "signed_target_quantity": row.target_quantity,
                "signed_target_delta": row.target_quantity
                - row.previous_target_quantity,
                "signed_target_row_sha256": "1" * 64,
            }
        ],
    }
    evidence = VerifiedCommodityCFastResearchAcceptanceEvidence(
        acceptance=acceptance,
        acceptance_raw_sha256="2" * 64,
        acceptance_canonical_sha256="3" * 64,
        consume={"consume_id": "cfast-simnow-research-accept-consume-v1-" + "4" * 64},
        consume_raw_sha256="5" * 64,
        consume_canonical_sha256="6" * 64,
        receipt={"ready_at": (NOW - timedelta(minutes=1)).isoformat()},
        receipt_raw_sha256="7" * 64,
        receipt_canonical_sha256="8" * 64,
        research_signer_key_id="research-test-key",
        research_key_materials=frozenset(
            {research_key.public_key().public_bytes_raw()}
        ),
        acceptance_key_materials=frozenset(
            {acceptance_key.public_key().public_bytes_raw()}
        ),
    )
    execution_key = Ed25519PrivateKey.generate()
    unsigned = prepare_unsigned_execution_permit(
        evidence,
        snapshot,
        snapshot_sha256,
        execution_signer_key_id="execution-test-key",
        reviewer_role="Control Execution reviewer",
        human_signature="human-approved-test-permit",
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    permit = sign_execution_permit(
        unsigned, private_key=execution_key, evidence=evidence
    )
    keyring = {
        "schema_version": "commodity_c_fast_simnow_execution_permit_trusted_keys_v1",
        "purpose": "c_fast_simnow_control_execution_permit_verification",
        "trusted_keys": [
            {
                "key_id": "execution-test-key",
                "public_key_base64": base64.b64encode(
                    execution_key.public_key().public_bytes_raw()
                ).decode("ascii"),
                "signer_type": "human",
                "reviewer_role": "Control Execution reviewer",
            }
        ],
    }
    permit_path = tmp_path / "permit.json"
    keyring_path = tmp_path / "permit-keyring.json"
    write_exact(permit_path, permit)
    write_exact(keyring_path, keyring)
    settings = Settings().model_copy(
        update={
            "commodity_c_fast_simnow_execution_permit_enabled": True,
            "commodity_c_fast_simnow_execution_permit_path": str(permit_path),
            "commodity_c_fast_simnow_execution_permit_trusted_keyring_path": str(
                keyring_path
            ),
            "commodity_c_fast_simnow_execution_permit_expected_keyring_raw_sha256": hashlib.sha256(
                keyring_path.read_bytes()
            ).hexdigest(),
        }
    )
    service = CommodityCFastExecutionPermitService(
        settings=settings,
        clock=lambda: NOW + timedelta(minutes=1),
        acceptance_evidence=StaticEvidence(evidence),
    )
    return {
        "service": service,
        "snapshot": snapshot,
        "snapshot_sha256": snapshot_sha256,
        "permit": permit,
        "permit_path": permit_path,
        "evidence": evidence,
        "execution_key": execution_key,
    }


def test_execution_permit_verifies_exact_acceptance_and_snapshot(
    tmp_path: Path,
) -> None:
    fixture = permit_fixture(tmp_path)

    permit = fixture["service"].verified_permit_for_snapshot(
        fixture["snapshot"], fixture["snapshot_sha256"]
    )

    assert permit.acceptance_receipt_raw_sha256 == "7" * 64
    assert permit.production_allowed is False
    assert permit.live_trading_authorized is False
    assert permit.automatic_promotion_authorized is False


def test_execution_permit_rejects_forged_acceptance_receipt_claim(
    tmp_path: Path,
) -> None:
    fixture = permit_fixture(tmp_path)
    payload = dict(fixture["permit"])
    payload["acceptance_receipt_raw_sha256"] = "9" * 64
    payload["permit_id"] = derived_permit_id(payload)
    payload["signature"] = base64.b64encode(
        fixture["execution_key"].sign(
            canonical_json(
                {key: value for key, value in payload.items() if key != "signature"}
            )
        )
    ).decode("ascii")
    write_exact(fixture["permit_path"], payload)

    with pytest.raises(
        CommodityCFastExecutionPermitError,
        match="ACCEPTANCE_BINDING_MISMATCH",
    ):
        fixture["service"].verified_permit_for_snapshot(
            fixture["snapshot"], fixture["snapshot_sha256"]
        )


def test_execution_permit_rejects_snapshot_splice_or_expiry(
    tmp_path: Path,
) -> None:
    fixture = permit_fixture(tmp_path)
    with pytest.raises(
        CommodityCFastExecutionPermitError,
        match="SNAPSHOT_BINDING_MISMATCH",
    ):
        fixture["service"].verified_permit_for_snapshot(fixture["snapshot"], "0" * 64)

    fixture["service"].clock = lambda: NOW + timedelta(minutes=6)
    with pytest.raises(
        CommodityCFastExecutionPermitError,
        match="TIMING_INVALID",
    ):
        fixture["service"].verified_permit_for_snapshot(
            fixture["snapshot"], fixture["snapshot_sha256"]
        )
