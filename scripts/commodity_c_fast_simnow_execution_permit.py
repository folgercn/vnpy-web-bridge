#!/usr/bin/env python3
"""Pure builders for the #165 Acceptance -> SimNow execution permit bridge.

This module has no RPC, account-query, order, position, deployment or
promotion dependency.  Callers must supply a freshly full-verified #165
evidence object and a separately verified legacy target snapshot.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

from app.schemas.commodity_c_fast_execution_permit import (
    CommodityCFastSimNowExecutionPermitDTO,
)
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastShakedownSnapshotDTO,
)
from app.services.commodity_c_fast_execution_permit import (
    adapter_target_projection_sha256,
    canonical_json,
    derived_permit_id,
)
from app.services.commodity_c_fast_research_acceptance_evidence import (
    VerifiedCommodityCFastResearchAcceptanceEvidence,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def prepare_unsigned_execution_permit(
    evidence: VerifiedCommodityCFastResearchAcceptanceEvidence,
    snapshot: CommodityCFastShakedownSnapshotDTO,
    snapshot_sha256: str,
    *,
    execution_signer_key_id: str,
    reviewer_role: str,
    human_signature: str,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    acceptance = evidence.acceptance
    times = (issued_at, not_before, expires_at)
    if any(value.tzinfo is None or value.utcoffset() is None for value in times):
        raise ValueError("permit times must include UTC offsets")
    issued_at, not_before, expires_at = (
        value.astimezone(timezone.utc) for value in times
    )
    acceptance_expires = datetime.fromisoformat(
        str(acceptance["expires_at"]).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    receipt_ready = datetime.fromisoformat(
        str(evidence.receipt["ready_at"]).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    if not (
        receipt_ready <= issued_at <= not_before < expires_at
        and expires_at - not_before <= timedelta(minutes=10)
        and expires_at <= acceptance_expires
    ):
        raise ValueError("permit timing must be fresh and nested in #165 Acceptance")
    if (
        snapshot.execution_day.isoformat() != acceptance["execution_day"]
        or snapshot.account_sha256 != acceptance["expected_simnow_account_sha256"]
        or snapshot.max_selected_products < len(acceptance["selected_products"])
    ):
        raise ValueError("legacy adapter snapshot scope/account/day mismatch")
    rows = {row.product: row for row in snapshot.targets}
    selected_targets: list[dict[str, Any]] = []
    for signed in acceptance["selected_targets"]:
        row = rows.get(signed["product"])
        if (
            row is None
            or row.exact_contract != signed["exact_contract"]
            or row.previous_target_quantity != signed["previous_target_quantity"]
            or row.target_quantity != signed["signed_target_quantity"]
            or row.target_quantity - row.previous_target_quantity
            != signed["signed_target_delta"]
        ):
            raise ValueError(
                "legacy adapter snapshot does not match #165 selected target"
            )
        selected_targets.append(
            {
                **signed,
                "adapter_target_projection_sha256": adapter_target_projection_sha256(
                    product=row.product,
                    exact_contract=row.exact_contract,
                    previous_target_quantity=(row.previous_target_quantity),
                    target_quantity=row.target_quantity,
                ),
            }
        )
    core = {
        "schema_version": "commodity_c_fast_simnow_execution_permit_v1",
        "purpose": "c_fast_simnow_one_shot_control_execution_permit",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "parent_issue_number": 114,
        "issue_number": 146,
        "issued_at": issued_at.isoformat(),
        "not_before": not_before.isoformat(),
        "expires_at": expires_at.isoformat(),
        "execution_day": acceptance["execution_day"],
        "permit_state": "READY_FOR_EXPLICIT_HUMAN_SIMNOW_SESSION_START_ONLY",
        "execution_environment": "SIMNOW",
        "signer_type": "human",
        "reviewer_role": reviewer_role,
        "human_signature": human_signature,
        "signer_key_id": execution_signer_key_id,
        "acceptance_id": acceptance["acceptance_id"],
        "acceptance_state": acceptance["acceptance_state"],
        "acceptance_signer_key_id": acceptance["signer_key_id"],
        "research_signer_key_id": evidence.research_signer_key_id,
        "acceptance_raw_sha256": evidence.acceptance_raw_sha256,
        "acceptance_canonical_sha256": evidence.acceptance_canonical_sha256,
        "acceptance_receipt_raw_sha256": evidence.receipt_raw_sha256,
        "acceptance_receipt_canonical_sha256": evidence.receipt_canonical_sha256,
        "acceptance_consume_raw_sha256": evidence.consume_raw_sha256,
        "acceptance_consume_canonical_sha256": evidence.consume_canonical_sha256,
        "acceptance_consume_id": evidence.consume["consume_id"],
        "research_bundle_id": acceptance["research_bundle_id"],
        "research_artifact_index_sha256": acceptance["research_artifact_index_sha256"],
        "selected_target_index_sha256": acceptance["selected_target_index_sha256"],
        "custody_root_path_sha256": acceptance["custody_root_path_sha256"],
        "custody_identity_sha256": acceptance["custody_identity_sha256"],
        "source_snapshot_id": snapshot.snapshot_id,
        "source_snapshot_sha256": snapshot_sha256,
        "legacy_control_acceptance_id": snapshot.control_acceptance_id,
        "legacy_execution_permit_id": snapshot.execution_permit_id,
        "formula_target_binding_sha256": acceptance["formula_target_binding_sha256"],
        "source_snapshot_formula_target_binding_sha256": (
            snapshot.formula_target_binding_sha256
        ),
        "expected_simnow_account_sha256": acceptance["expected_simnow_account_sha256"],
        "selected_products": acceptance["selected_products"],
        "selected_targets": selected_targets,
        "human_session_start_required": True,
        "automatic_session_start_authorized": False,
        "simnow_execution_authorized": True,
        "simnow_auto_dispatch_authorized": True,
        "simnow_account_read_authorized": True,
        "simnow_rpc_authorized": True,
        "simnow_order_submission_authorized": True,
        "simnow_position_read_authorized": True,
        "simnow_position_mutation_authorized": True,
        "simnow_reconcile_authorized": True,
        "countable_forward": False,
        "official_forward_claimed": False,
        "production_allowed": False,
        "deployment_authorized": False,
        "live_trading_authorized": False,
        "replacement_authorized": False,
        "automatic_promotion_authorized": False,
        "dynamic_selection_allowed": False,
        "replay_allowed": False,
        "account_data_read_at_issuance": False,
        "execution_data_read_at_issuance": False,
        "orders_sent_at_issuance": 0,
        "positions_modified_at_issuance": 0,
        "web_bridge_rpc_calls_at_issuance": 0,
    }
    candidate = {
        **core,
        "permit_id": "cfast-simnow-execution-permit-v1-" + "0" * 64,
        "signature": PLACEHOLDER_SIGNATURE,
    }
    normalized = CommodityCFastSimNowExecutionPermitDTO.model_validate(
        candidate
    ).model_dump(mode="json")
    normalized["permit_id"] = derived_permit_id(normalized)
    permit = CommodityCFastSimNowExecutionPermitDTO.model_validate(normalized)
    return {
        key: value
        for key, value in permit.model_dump(mode="json").items()
        if key != "signature"
    }


def sign_execution_permit(
    unsigned: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    evidence: VerifiedCommodityCFastResearchAcceptanceEvidence,
) -> dict[str, Any]:
    public_material = private_key.public_key().public_bytes_raw()
    if (
        public_material in evidence.research_key_materials
        or public_material in evidence.acceptance_key_materials
    ):
        raise ValueError(
            "Execution signer key must be distinct from Research/Acceptance"
        )
    payload = {
        **unsigned,
        "signature": base64.b64encode(
            private_key.sign(canonical_json(unsigned))
        ).decode("ascii"),
    }
    return CommodityCFastSimNowExecutionPermitDTO.model_validate(payload).model_dump(
        mode="json"
    )
