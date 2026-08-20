"""Typed DTOs for Control's Phase C read/command boundary.

No DTO imports custody, signing, TradeService, gateway, or commodity runtime
code.  Control only forwards these values to independently owned adapters.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.phase_c_workflow.continuous_event_v1 import (
    CONTINUOUS_EVENT_ARTIFACT_TYPE,
    CONTINUOUS_EVENT_SCHEMA_VERSION,
    CONTINUOUS_EVENT_SCOPE,
    CONTINUOUS_EVENT_TRUST_DOMAIN,
    canonical_json_line,
    sha256_bytes,
    validate_simnow_continuous_event_v1,
)
from shared.phase_c_workflow.v1 import (
    AUTHORIZATION_COMMAND_SCHEMA_VERSION,
    FALSE_AUTHORITY_FLAGS,
)

TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF = "web-bridge-simnow-keyless-target-plan-v1"
TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF = "web-bridge-simnow-keyless-target-plan-v2"
TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF = "web-bridge-simnow-keyless-target-plan-v3"
TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS = frozenset(
    {
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
    }
)
TRUSTED_KEYLESS_CONTINUOUS_EVENT_SCHEMA_REF = CONTINUOUS_EVENT_SCHEMA_VERSION


def _canonical_day(value: str | None, label: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} is invalid")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{label} is not canonical")


class StrictDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityNegativeDTO(StrictDTO):
    production_allowed: Literal[False] = False
    live_trading_authorized: Literal[False] = False
    countable_forward: Literal[False] = False


class ContinuousEventAuthorityNegativeDTO(AuthorityNegativeDTO):
    official_forward_claimed: Literal[False] = False
    target_plan_authorized: Literal[False] = False
    dispatch_authorized: Literal[False] = False
    order_authorized: Literal[False] = False
    position_mutation_authorized: Literal[False] = False


class SigningRequestCreateDTO(StrictDTO):
    request_id: str = Field(
        min_length=4, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    domain: Literal["map_acceptance", "c_fast_acceptance", "runtime_authorization"]
    key_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    key_version: str = Field(pattern=r"^v[0-9]+$")
    requested_at: str = Field(min_length=20, max_length=64)
    expires_at: str = Field(min_length=20, max_length=64)
    artifact: dict[str, Any]


class SigningRequestDTO(StrictDTO):
    schema_version: Literal["web-bridge-signing-request-v1"] = (
        "web-bridge-signing-request-v1"
    )
    request_id: str
    domain: str
    key_id: str
    key_version: str
    requested_at: str
    expires_at: str
    artifact: dict[str, Any]


class SignedArtifactUploadDTO(StrictDTO):
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    signing_request_id: str = Field(min_length=4, max_length=128)
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    signed_artifact: dict[str, Any]


class TrustedKeylessTargetPlanUploadDTO(StrictDTO):
    """The only unsigned custody input: fixed-tuple SIMNOW target plans."""

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact: dict[str, Any]


class TrustedKeylessSimnowScopeDTO(StrictDTO):
    """The fixed non-production account tuple carried as a publication pin."""

    account_scope: Literal["account:windows"]
    environment: Literal["SIMNOW"]
    gateway_name: Literal["CTP"]


class TrustedKeylessTargetPlanInstallContinuationDTO(StrictDTO):
    """Pins-only install continuation for one stored keyless target plan.

    The order-bearing artifact is deliberately absent.  Custody resolves the
    immutable envelope from its own publication receipt and revalidates it
    before recording the install transition.
    """

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publisher_principal: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    publish_receipt_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publish_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    publish_expected_custody_version: int = Field(ge=0)
    publish_resulting_custody_version: int = Field(ge=1)
    artifact_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_schema_ref: Literal[
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
    ]
    plan_schema_version: Literal[
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
    ]
    plan_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_phase: Literal["CLOSE", "OPEN"]
    scope: TrustedKeylessSimnowScopeDTO
    plan_expires_at: str = Field(
        min_length=20,
        max_length=64,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$",
    )

    @model_validator(mode="after")
    def _publish_versions_are_adjacent(
        self,
    ) -> TrustedKeylessTargetPlanInstallContinuationDTO:
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1
        ):
            raise ValueError("publish custody versions are not adjacent")
        if self.artifact_schema_ref != self.plan_schema_version:
            raise ValueError("artifact schema does not bind target-plan schema")
        return self


class TrustedKeylessContinuousEventUploadDTO(StrictDTO):
    """Publish/install one strict, authority-negative continuous event."""

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact: dict[str, Any]


class TrustedKeylessContinuousEventInstallContinuationDTO(StrictDTO):
    """Install-only continuation for one already-published event."""

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publish_receipt_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publish_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    publish_expected_custody_version: int = Field(ge=0)
    publish_resulting_custody_version: int = Field(ge=1)
    artifact: dict[str, Any]

    @model_validator(mode="after")
    def _publish_versions_are_adjacent(
        self,
    ) -> TrustedKeylessContinuousEventInstallContinuationDTO:
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1
        ):
            raise ValueError("event publish custody versions are not adjacent")
        return self


class ContinuousEventPublicationProjectionDTO(ContinuousEventAuthorityNegativeDTO):
    """Pins-only three-state recovery projection for one continuous event."""

    schema_version: Literal["phase-c-continuous-event-publication-v1"] = (
        "phase-c-continuous-event-publication-v1"
    )
    state: Literal["NOT_PUBLISHED", "PUBLISHED_NOT_INSTALLED", "INSTALLED"]
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    install_idempotency_key: str = Field(
        min_length=16, max_length=136, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    observed_custody_version: int = Field(ge=0)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"
    publisher_principal: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    correlation_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    artifact_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    artifact_canonical_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    artifact_raw_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    artifact_schema_ref: Optional[Literal[CONTINUOUS_EVENT_SCHEMA_VERSION]] = None
    event_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    source_event_raw_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    selection_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    selection_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    selection_raw_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    candidate_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    trigger_kind: Optional[Literal["MONTHLY_REBALANCE", "ROLL_ONLY"]] = None
    monthly_final_target_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    daily_artifact_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    daily_artifact_raw_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    daily_official_day: Optional[str] = Field(
        default=None, min_length=10, max_length=10
    )
    desired_target_position_hash: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    account_facts_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    account_facts_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    predecessor_mode: Optional[Literal["GENESIS_FLAT", "COMPLETION"]] = None
    predecessor_terminal_target_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    predecessor_terminal_target_raw_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    publish_receipt_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    publish_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    publish_expected_custody_version: Optional[int] = Field(default=None, ge=0)
    publish_resulting_custody_version: Optional[int] = Field(default=None, ge=1)
    install_receipt_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    install_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    install_expected_custody_version: Optional[int] = Field(default=None, ge=1)
    install_resulting_custody_version: Optional[int] = Field(default=None, ge=2)

    @model_validator(mode="after")
    def _state_has_exact_evidence(self) -> ContinuousEventPublicationProjectionDTO:
        if self.install_idempotency_key != f"install-{self.idempotency_key}":
            raise ValueError("event install idempotency does not bind publication")
        publication = (
            self.publisher_principal,
            self.correlation_id,
            self.artifact_id,
            self.artifact_canonical_sha256,
            self.artifact_raw_sha256,
            self.artifact_schema_ref,
            self.event_id,
            self.source_event_raw_sha256,
            self.selection_id,
            self.selection_sha256,
            self.selection_raw_sha256,
            self.candidate_id,
            self.trigger_kind,
            self.monthly_final_target_sha256,
            self.daily_artifact_id,
            self.daily_artifact_raw_sha256,
            self.daily_official_day,
            self.desired_target_position_hash,
            self.account_facts_id,
            self.account_facts_sha256,
            self.predecessor_mode,
            self.publish_receipt_id,
            self.publish_receipt_sha256,
            self.publish_expected_custody_version,
            self.publish_resulting_custody_version,
        )
        installation = (
            self.install_receipt_id,
            self.install_receipt_sha256,
            self.install_expected_custody_version,
            self.install_resulting_custody_version,
        )
        if self.state == "NOT_PUBLISHED":
            if any(value is not None for value in publication + installation) or any(
                value is not None
                for value in (
                    self.predecessor_terminal_target_id,
                    self.predecessor_terminal_target_raw_sha256,
                )
            ):
                raise ValueError("unpublished event contains custody evidence")
            return self
        if any(value is None for value in publication):
            raise ValueError("published event lacks custody evidence")
        if self.event_id != self.idempotency_key:
            raise ValueError("published event ID does not bind idempotency")
        _canonical_day(self.daily_official_day, "event daily official day")
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1  # type: ignore[operator]
            or self.observed_custody_version < self.publish_resulting_custody_version  # type: ignore[operator]
        ):
            raise ValueError("event publish custody versions are invalid")
        terminal = (
            self.predecessor_terminal_target_id,
            self.predecessor_terminal_target_raw_sha256,
        )
        if self.predecessor_mode == "GENESIS_FLAT" and any(
            value is not None for value in terminal
        ):
            raise ValueError("Genesis event carries terminal predecessor pins")
        if self.predecessor_mode == "COMPLETION" and any(
            value is None for value in terminal
        ):
            raise ValueError("completion event lacks terminal predecessor pins")
        if self.state == "PUBLISHED_NOT_INSTALLED":
            if any(value is not None for value in installation):
                raise ValueError("uninstalled event contains install evidence")
            return self
        if any(value is None for value in installation) or (
            self.install_expected_custody_version
            != self.publish_resulting_custody_version
            or self.install_resulting_custody_version
            != self.install_expected_custody_version + 1  # type: ignore[operator]
            or self.observed_custody_version < self.install_resulting_custody_version  # type: ignore[operator]
        ):
            raise ValueError("event install custody versions are invalid")
        return self


class TrustedKeylessContinuousEventReceiptDTO(ContinuousEventAuthorityNegativeDTO):
    """Install receipt that can never be presented as TargetPlan authority."""

    receipt_id: str
    receipt_type: Literal["install"]
    artifact_id: str
    artifact_type: Literal[CONTINUOUS_EVENT_ARTIFACT_TYPE]
    trust_domain: Literal[CONTINUOUS_EVENT_TRUST_DOMAIN]
    schema_ref: Literal[CONTINUOUS_EVENT_SCHEMA_VERSION]
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_id: str
    trigger_kind: Literal["MONTHLY_REBALANCE", "ROLL_ONLY"]
    daily_official_day: str = Field(min_length=10, max_length=10)
    custody_version: int = Field(ge=1)
    idempotency_key: str
    verified: Literal[True]
    installed: Literal[True]
    custody_writer: Literal["artifact-custody"]

    @model_validator(mode="after")
    def _event_id_binds_install_idempotency(
        self,
    ) -> TrustedKeylessContinuousEventReceiptDTO:
        if self.idempotency_key != f"install-{self.event_id}":
            raise ValueError("event receipt ID does not bind idempotency")
        _canonical_day(self.daily_official_day, "event receipt daily official day")
        return self


class TrustedKeylessContinuousEventArtifactDTO(ContinuousEventAuthorityNegativeDTO):
    """Control-only readback of one strict event envelope."""

    schema_version: Literal["phase-c-continuous-event-artifact-v1"] = (
        "phase-c-continuous-event-artifact-v1"
    )
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact_id: str
    artifact_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact: dict[str, Any]

    @model_validator(mode="after")
    def _artifact_is_exact_event(self) -> TrustedKeylessContinuousEventArtifactDTO:
        envelope = validate_artifact_envelope(self.artifact)
        payload = validate_simnow_continuous_event_v1(envelope["payload"])
        if (
            envelope["artifact_id"] != self.artifact_id
            or sha256_bytes(canonical_json_line(envelope)) != self.artifact_raw_sha256
            or envelope["artifact_type"] != CONTINUOUS_EVENT_ARTIFACT_TYPE
            or envelope["trust_domain"] != CONTINUOUS_EVENT_TRUST_DOMAIN
            or envelope["schema_ref"] != CONTINUOUS_EVENT_SCHEMA_VERSION
            or envelope["scope"] != CONTINUOUS_EVENT_SCOPE
            or envelope["generated_at"] != payload["verified_at"]
            or payload["event_id"] != self.idempotency_key
            or envelope["predecessor_refs"]
            or envelope["lineage"]
        ):
            raise ValueError("continuous event artifact identity mismatches")
        return self


class TargetPlanPublicationProjectionDTO(AuthorityNegativeDTO):
    """Read-only Phase-C publication/install evidence for one phase key."""

    schema_version: Literal["phase-c-target-plan-publication-v1"] = (
        "phase-c-target-plan-publication-v1"
    )
    state: Literal["NOT_PUBLISHED", "PUBLISHED_NOT_INSTALLED", "INSTALLED"]
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    install_idempotency_key: str = Field(
        min_length=16, max_length=136, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    observed_custody_version: int = Field(ge=0)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"
    publisher_principal: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    correlation_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    artifact_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    artifact_canonical_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    artifact_raw_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    artifact_schema_ref: Optional[
        Literal[
            TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
            TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
            TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
        ]
    ] = None
    plan_schema_version: Optional[
        Literal[
            TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
            TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
            TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
        ]
    ] = None
    plan_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    plan_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    plan_phase: Optional[Literal["CLOSE", "OPEN"]] = None
    scope: Optional[TrustedKeylessSimnowScopeDTO] = None
    plan_expires_at: Optional[str] = Field(
        default=None,
        min_length=20,
        max_length=64,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$",
    )
    publish_receipt_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    publish_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    publish_expected_custody_version: Optional[int] = Field(default=None, ge=0)
    publish_resulting_custody_version: Optional[int] = Field(default=None, ge=1)
    install_receipt_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    )
    install_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    install_expected_custody_version: Optional[int] = Field(default=None, ge=1)
    install_resulting_custody_version: Optional[int] = Field(default=None, ge=2)

    @model_validator(mode="after")
    def _state_has_exact_evidence(self) -> TargetPlanPublicationProjectionDTO:
        if self.install_idempotency_key != f"install-{self.idempotency_key}":
            raise ValueError("install idempotency does not bind publication")
        publication = (
            self.publisher_principal,
            self.correlation_id,
            self.artifact_id,
            self.artifact_canonical_sha256,
            self.artifact_raw_sha256,
            self.artifact_schema_ref,
            self.plan_schema_version,
            self.plan_id,
            self.plan_hash,
            self.plan_phase,
            self.scope,
            self.plan_expires_at,
            self.publish_receipt_id,
            self.publish_receipt_sha256,
            self.publish_expected_custody_version,
            self.publish_resulting_custody_version,
        )
        installation = (
            self.install_receipt_id,
            self.install_receipt_sha256,
            self.install_expected_custody_version,
            self.install_resulting_custody_version,
        )
        if self.state == "NOT_PUBLISHED":
            if any(value is not None for value in publication + installation):
                raise ValueError("unpublished projection contains custody evidence")
            return self
        if any(value is None for value in publication):
            raise ValueError("published projection lacks custody evidence")
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1  # type: ignore[operator]
        ):
            raise ValueError("publish custody versions are not adjacent")
        if self.artifact_schema_ref != self.plan_schema_version:
            raise ValueError("artifact schema does not bind target-plan schema")
        if self.observed_custody_version < self.publish_resulting_custody_version:  # type: ignore[operator]
            raise ValueError("observed custody version precedes publication")
        if self.state == "PUBLISHED_NOT_INSTALLED":
            if any(value is not None for value in installation):
                raise ValueError("uninstalled projection contains install evidence")
            return self
        if any(value is None for value in installation):
            raise ValueError("installed projection lacks install evidence")
        if (
            self.install_expected_custody_version
            != self.publish_resulting_custody_version
            or self.install_resulting_custody_version
            != self.install_expected_custody_version + 1  # type: ignore[operator]
        ):
            raise ValueError("install custody versions do not continue publication")
        if self.observed_custody_version < self.install_resulting_custody_version:  # type: ignore[operator]
            raise ValueError("observed custody version precedes installation")
        return self


class TargetPlanCustodyReceiptEvidenceDTO(AuthorityNegativeDTO):
    """Pins-only read of one immutable publish/install custody receipt."""

    schema_version: Literal["phase-c-target-plan-receipt-evidence-v1"] = (
        "phase-c-target-plan-receipt-evidence-v1"
    )
    receipt_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_type: Literal["publish", "install"]
    artifact_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_schema_ref: Literal[
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
    ]
    actor_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    idempotency_key: str = Field(
        min_length=8, max_length=136, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    resulting_custody_version: int = Field(ge=1)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"

    @model_validator(mode="after")
    def _versions_are_adjacent(self) -> TargetPlanCustodyReceiptEvidenceDTO:
        if self.resulting_custody_version != self.expected_custody_version + 1:
            raise ValueError("target-plan receipt custody versions are not adjacent")
        return self


class CustodyCurrentVersionDTO(AuthorityNegativeDTO):
    """Read-only CAS input projected from the sole custody ledger owner."""

    schema_version: Literal["phase-c-custody-current-version-v1"] = (
        "phase-c-custody-current-version-v1"
    )
    version: int = Field(ge=0)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"


class CustodyReceiptDTO(AuthorityNegativeDTO):
    receipt_id: str
    receipt_type: Literal["install"]
    artifact_id: str
    artifact_type: Literal["runtime-authorization", "simnow-target-plan"] = (
        "runtime-authorization"
    )
    trust_domain: Literal["runtime_authorization"] = "runtime_authorization"
    schema_ref: Literal[
        "phase-c-runtime-authorization-v1", "web-bridge-simnow-target-plan-v1"
    ] = "phase-c-runtime-authorization-v1"
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_id: str = "test-only"
    signer_key_version: str = "v1"
    keyring_raw_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    signed_artifact_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    scope: dict[str, Any] = Field(default_factory=dict)
    expires_at: str = "2099-01-01T00:00:00Z"
    custody_version: int = Field(ge=0)
    idempotency_key: str
    verified: Literal[True] = True
    installed: Literal[True] = True
    custody_writer: Literal["artifact-custody"] = "artifact-custody"

    @model_validator(mode="after")
    def _artifact_type_schema_pair_is_supported(self) -> CustodyReceiptDTO:
        if (self.artifact_type, self.schema_ref) not in {
            ("runtime-authorization", "phase-c-runtime-authorization-v1"),
            ("simnow-target-plan", "web-bridge-simnow-target-plan-v1"),
        }:
            raise ValueError("custody receipt artifact type/schema pair is invalid")
        return self


class TrustedKeylessCustodyReceiptDTO(AuthorityNegativeDTO):
    """Strict receipt returned only by the fixed-tuple keyless custody route."""

    receipt_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    )
    receipt_type: Literal["install"]
    artifact_id: str
    artifact_type: Literal["simnow-target-plan"]
    trust_domain: Literal["runtime_authorization"]
    schema_ref: Literal[
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V3_SCHEMA_REF,
    ]
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: dict[str, Any]
    expires_at: str
    custody_version: int = Field(ge=1)
    idempotency_key: str
    verified: Literal[True]
    installed: Literal[True]
    custody_writer: Literal["artifact-custody"]


class AuthorizationCommandDTO(StrictDTO):
    schema_version: Literal[AUTHORIZATION_COMMAND_SCHEMA_VERSION] = (
        AUTHORIZATION_COMMAND_SCHEMA_VERSION
    )
    command_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_version: int = Field(ge=0)
    action: Literal["enable", "revoke"]
    authorization_artifact_id: str = Field(min_length=4, max_length=256)
    custody_receipt_id: str = Field(min_length=4, max_length=256)
    reason: str = Field(min_length=3, max_length=500)


class AuthorizationStatusDTO(AuthorityNegativeDTO):
    version: int = Field(ge=0)
    requested_state: Literal["DISABLED", "ENABLE_REQUESTED", "REVOKED"]
    effective_state: Literal["DISABLED"] = "DISABLED"
    artifact_id: str | None = None
    receipt_id: str | None = None
    runtime_mutation_allowed: Literal[False] = False


class ExecutionProjectionDTO(AuthorityNegativeDTO):
    status: Literal["OFFLINE", "ARCHIVED"]
    execution_mutation_allowed: Literal[False] = False
    runtime_state_owner: Literal["phase-c-execution"] = "phase-c-execution"
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"
    audit: list[dict[str, Any]] = Field(default_factory=list)
    archive: list[dict[str, Any]] = Field(default_factory=list)


class WorkflowStatusDTO(AuthorityNegativeDTO):
    map_status: Literal["PENDING", "READY"]
    c_fast_status: Literal["PENDING", "READY"]
    signing: Literal["EXPORT_ONLY"] = "EXPORT_ONLY"
    browser_signing: Literal[False] = False
    custody_writer: Literal["artifact-custody"] = "artifact-custody"
    execution_writer: Literal["phase-c-execution"] = "phase-c-execution"
    execution_mutation_allowed: Literal[False] = False


def as_negative(value: dict[str, Any]) -> dict[str, Any]:
    """Force the authority-negative contract on projections from an adapter."""
    return {**value, **FALSE_AUTHORITY_FLAGS}


__all__ = [name for name in globals() if name.endswith("DTO") or name == "as_negative"]
