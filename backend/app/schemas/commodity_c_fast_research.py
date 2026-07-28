from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import Field, model_validator

from app.schemas.commodity_c_fast_shadow import (
    CFastShadowTargetDTO,
    StrictFiniteModel,
)


class CFastResearchEvidenceFileDTO(StrictFiniteModel):
    purpose: Literal[
        "research_manifest",
        "allocation_evidence",
        "daily_roll_evidence",
        "reference_price_source",
    ]
    relative_path: str = Field(
        min_length=1,
        max_length=240,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    )
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CommodityCFastSimNowResearchBundleDTO(StrictFiniteModel):
    schema_version: Literal["commodity_c_fast_simnow_research_bundle_v1"]
    bundle_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    frozen_rule_id: Literal["commodity_fast_tsmom_forward_freeze_v1"]
    frozen_rule_sha256: Literal[
        "d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a"
    ]
    purpose: Literal["SIMNOW_SHAKEDOWN_NON_COUNTABLE_ONLY"]
    production_allowed: Literal[False]
    countable_forward: Literal[False]
    human_confirmation: Literal[
        "HUMAN_CONFIRMED_RESEARCH_INPUT_FOR_SIMNOW_SHAKEDOWN_ONLY"
    ]
    confirmed_by: str = Field(pattern=r"^[A-Za-z0-9._@-]{1,128}$")
    confirmed_at_utc: datetime
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    source_official_day: date
    execution_day: date
    input_cutoff_at_utc: datetime
    snapshot_created_at_utc: datetime
    expires_at_utc: datetime
    previous_snapshot_hash: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    evidence_files: list[CFastResearchEvidenceFileDTO] = Field(
        min_length=4, max_length=32
    )
    targets: list[CFastShadowTargetDTO] = Field(min_length=10, max_length=10)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    bundle_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_bundle_contract(
        self,
    ) -> CommodityCFastSimNowResearchBundleDTO:
        timestamps = (
            self.confirmed_at_utc,
            self.input_cutoff_at_utc,
            self.snapshot_created_at_utc,
            self.expires_at_utc,
        )
        if any(
            value.tzinfo is None or value.utcoffset() is None
            for value in timestamps
        ):
            raise ValueError("all timestamps must be timezone-aware")
        if not (
            self.input_cutoff_at_utc
            <= self.confirmed_at_utc
            <= self.snapshot_created_at_utc
            < self.expires_at_utc
        ):
            raise ValueError("bundle timestamps are not causal")
        if self.source_official_day.strftime("%Y-%m") != self.source_month:
            raise ValueError("source month does not match source official day")
        if self.execution_day <= self.source_official_day:
            raise ValueError("execution day must follow source official day")
        paths = [row.relative_path for row in self.evidence_files]
        if len(paths) != len(set(paths)):
            raise ValueError("evidence paths must be unique")
        if any(
            path.startswith("/")
            or ".." in path.split("/")
            or "\\" in path
            for path in paths
        ):
            raise ValueError("evidence paths must stay below evidence root")
        purposes = [row.purpose for row in self.evidence_files]
        for required in (
            "research_manifest",
            "allocation_evidence",
            "daily_roll_evidence",
            "reference_price_source",
        ):
            if required not in purposes:
                raise ValueError(f"missing evidence purpose: {required}")
        products = [row.product for row in self.targets]
        if len(products) != len(set(products)):
            raise ValueError("target products must be unique")
        return self
