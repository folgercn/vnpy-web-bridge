from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.commodity_c_fast_shadow import Product


class StrictFiniteModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class CommodityCFastExecutionPermitTargetDTO(StrictFiniteModel):
    product: Product
    exact_contract: str = Field(min_length=8, max_length=32)
    previous_target_quantity: int
    signed_target_quantity: int
    signed_target_delta: int
    signed_target_row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter_target_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_delta(self) -> "CommodityCFastExecutionPermitTargetDTO":
        if (
            self.signed_target_quantity - self.previous_target_quantity
            != self.signed_target_delta
            or self.signed_target_delta == 0
        ):
            raise ValueError("selected target delta is invalid")
        return self


class CommodityCFastSimNowExecutionPermitDTO(StrictFiniteModel):
    """Independent Control/Execution authority consumed by the adapter.

    The legacy shakedown snapshot remains target input only.  Its embedded
    ``control_acceptance_id`` and ``execution_permit_id`` are audit bindings
    and never execution authority.
    """

    schema_version: Literal["commodity_c_fast_simnow_execution_permit_v1"]
    purpose: Literal["c_fast_simnow_one_shot_control_execution_permit"]
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    parent_issue_number: Literal[114]
    issue_number: Literal[146]
    permit_id: str = Field(pattern=r"^cfast-simnow-execution-permit-v1-[0-9a-f]{64}$")
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    execution_day: date
    permit_state: Literal["READY_FOR_EXPLICIT_HUMAN_SIMNOW_SESSION_START_ONLY"]
    execution_environment: Literal["SIMNOW"]
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)
    human_signature: str = Field(min_length=1, max_length=512)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")

    acceptance_id: str = Field(
        pattern=r"^cfast-simnow-research-accept-v1-[0-9a-f]{64}$"
    )
    acceptance_state: Literal["READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY"]
    acceptance_signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    research_signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_receipt_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_receipt_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_consume_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_consume_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    acceptance_consume_id: str = Field(
        pattern=(r"^cfast-simnow-research-accept-consume-v1-[0-9a-f]{64}$")
    )
    research_bundle_id: str = Field(pattern=r"^cfast-simnow-research-v1-[0-9a-f]{64}$")
    research_artifact_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_target_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_root_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    source_snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    source_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    legacy_control_acceptance_id: str = Field(
        pattern=r"^cfast-accept-[A-Za-z0-9._-]{8,96}$"
    )
    legacy_execution_permit_id: str = Field(
        pattern=r"^cfast-permit-[A-Za-z0-9._-]{8,96}$"
    )
    formula_target_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_simnow_account_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_products: list[Product] = Field(min_length=1, max_length=2)
    selected_targets: list[CommodityCFastExecutionPermitTargetDTO] = Field(
        min_length=1, max_length=2
    )

    human_session_start_required: Literal[True]
    automatic_session_start_authorized: Literal[False]
    simnow_execution_authorized: Literal[True]
    simnow_auto_dispatch_authorized: Literal[True]
    simnow_account_read_authorized: Literal[True]
    simnow_rpc_authorized: Literal[True]
    simnow_order_submission_authorized: Literal[True]
    simnow_position_read_authorized: Literal[True]
    simnow_position_mutation_authorized: Literal[True]
    simnow_reconcile_authorized: Literal[True]
    countable_forward: Literal[False]
    official_forward_claimed: Literal[False]
    production_allowed: Literal[False]
    deployment_authorized: Literal[False]
    live_trading_authorized: Literal[False]
    replacement_authorized: Literal[False]
    automatic_promotion_authorized: Literal[False]
    dynamic_selection_allowed: Literal[False]
    replay_allowed: Literal[False]
    account_data_read_at_issuance: Literal[False]
    execution_data_read_at_issuance: Literal[False]
    orders_sent_at_issuance: Literal[0]
    positions_modified_at_issuance: Literal[0]
    web_bridge_rpc_calls_at_issuance: Literal[0]
    signature: str = Field(min_length=88, max_length=88)

    @model_validator(mode="after")
    def validate_scope(self) -> "CommodityCFastSimNowExecutionPermitDTO":
        products = list(self.selected_products)
        targets = [row.product for row in self.selected_targets]
        if (
            products != sorted(products)
            or len(set(products)) != len(products)
            or targets != products
            or self.signer_key_id
            in {
                self.acceptance_signer_key_id,
                self.research_signer_key_id,
            }
            or self.reviewer_role.startswith("PENDING_")
            or self.human_signature.startswith("PENDING_")
        ):
            raise ValueError("execution permit scope or signer separation invalid")
        return self


class CommodityCFastExecutionPermitTrustedKeyDTO(StrictFiniteModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    public_key_base64: str = Field(min_length=44, max_length=44)
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)


class CommodityCFastExecutionPermitTrustedKeysDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_simnow_execution_permit_trusted_keys_v1"]
    purpose: Literal["c_fast_simnow_control_execution_permit_verification"]
    trusted_keys: list[CommodityCFastExecutionPermitTrustedKeyDTO] = Field(
        min_length=1, max_length=16
    )

    @model_validator(mode="after")
    def validate_unique_keys(
        self,
    ) -> "CommodityCFastExecutionPermitTrustedKeysDTO":
        ids = [row.key_id for row in self.trusted_keys]
        materials = [row.public_key_base64 for row in self.trusted_keys]
        if len(set(ids)) != len(ids) or len(set(materials)) != len(materials):
            raise ValueError("execution permit trusted keys must be unique")
        if any(row.reviewer_role.startswith("PENDING_") for row in self.trusted_keys):
            raise ValueError("trusted key reviewer role is pending")
        return self
