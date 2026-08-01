from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from app.schemas.commodity_c_fast_pnl_ledger import (
    CommodityCFastFourLayerPnlLedgerEntryDTO,
    CommodityCFastPnlLedgerAuditDTO,
    Sha256,
    StrictFalse,
    StrictLedgerModel,
    sha256_json,
)


class CommodityCFastPnlSourceAdapterBindingDTO(StrictLedgerModel):
    adapter_id: Literal[
        "cfast-theoretical-target-marks-v1",
        "cfast-fee-and-stress-v2",
        "cfast-book-walk-fill-bounds-v1",
        "cfast-simnow-not-provided-v1",
        "cfast-simnow-archive-reference-v3",
        "cfast-simnow-session-archive-replay-v4",
    ]
    layer_kind: Literal[
        "THEORETICAL_TARGET_PNL",
        "FEE_ADJUSTED_PNL",
        "EXECUTION_QUALITY_INTERVAL_PNL",
        "ACTUAL_SIMNOW_CALIBRATION_PNL",
    ]
    source_schema_version: Literal[
        "commodity_c_fast_theoretical_target_pnl_source_facts_v1",
        "commodity_c_fast_fee_adjusted_pnl_source_facts_v2",
        "commodity_c_fast_execution_quality_interval_pnl_source_facts_v1",
        "commodity_c_fast_actual_simnow_not_provided_source_facts_v1",
        "commodity_c_fast_actual_simnow_facts_v3",
        "commodity_c_fast_actual_simnow_facts_v4",
    ]
    source_kind: Literal[
        "SIGNED_EXACT_TARGET_MARKS",
        "FEE_AND_STRESS_ASSUMPTIONS",
        "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
        "ACTUAL_SIMNOW_FACTS_NOT_PROVIDED",
        "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION",
        "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND",
    ]
    verification_rule: Literal[
        "FRESH_REPLAY_REALIZED_UNREALIZED_ROLL_SUM",
        "FRESH_REPLAY_RATE_TIMES_TURNOVER_OR_EXPLICIT_UNBOUND",
        "FRESH_REPLAY_BOOK_WALK_FILL_INTERVAL_BOUNDS_ONLY",
        "NOT_PROVIDED_ACTUAL_AMOUNTS_MUST_REMAIN_NULL",
        "ARCHIVE_REFERENCE_ONLY_NO_ACTUAL_AMOUNT_AUTHORITY",
        "FRESH_REPLAY_SESSION_RAW_TRADES_MARKS_MULTIPLIERS_FEES_UNBOUND",
    ]
    amount_authority: Literal[
        "DERIVED_RESEARCH_VALUE_ONLY",
        "DERIVED_WHEN_ALL_FEE_COMPONENTS_BOUND_OTHERWISE_NULL",
        "UNCALIBRATED_INTERVAL_ONLY_NO_POINT_FILL_PROBABILITY",
        "UNVERIFIED_ACTUAL_AMOUNTS_MUST_REMAIN_NULL",
        "GROSS_AND_SLIPPAGE_REPLAYED_FEES_AND_NET_UNBOUND",
    ]


class CommodityCFastPnlLedgerRepositoryExportDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_pnl_ledger_repository_export_v2"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    entry_count: int = Field(ge=1, le=10_000)
    genesis_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    chain_tip_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_entry_hashes_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    entries: tuple[CommodityCFastFourLayerPnlLedgerEntryDTO, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    audit: CommodityCFastPnlLedgerAuditDTO
    source_adapters: tuple[
        CommodityCFastPnlSourceAdapterBindingDTO,
        ...,
    ] = Field(min_length=6, max_length=6)
    repository_semantics: Literal["APPEND_ONLY_CREATE_ONLY_CANONICAL_JSON_HASH_CHAIN"]
    recovery_semantics: Literal[
        "FSYNC_SEQUENCE_RESERVATION_THEN_PENDING_CREATE_ONLY_LINK_FRESH_REPLAY"
    ]
    audit_report_language: Literal["zh-CN"]
    audit_scope: Literal["DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY"]
    external_genesis_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    external_tip_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    replacement_allowed: StrictFalse
    production_allowed: StrictFalse
    export_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_export(
        self,
    ) -> "CommodityCFastPnlLedgerRepositoryExportDTO":
        if self.entry_count != len(self.entries):
            raise ValueError("entry_count does not match entries")
        if any(entry.ledger_id != self.ledger_id for entry in self.entries):
            raise ValueError("export mixes ledger ids")
        entry_hashes = tuple(entry.entry_hash for entry in self.entries)
        if (
            entry_hashes[0] != self.genesis_entry_hash
            or entry_hashes[-1] != self.chain_tip_entry_hash
            or sha256_json(entry_hashes) != self.ordered_entry_hashes_sha256
        ):
            raise ValueError("export entry hash index mismatch")
        if (
            self.audit.ledger_id != self.ledger_id
            or self.audit.entry_count != self.entry_count
            or self.audit.genesis_entry_hash != self.genesis_entry_hash
            or self.audit.chain_tip_entry_hash != self.chain_tip_entry_hash
            or self.audit.ordered_entry_hashes_sha256
            != self.ordered_entry_hashes_sha256
            or self.audit.external_genesis_anchor_state
            != self.external_genesis_anchor_state
            or self.audit.external_tip_anchor_state != self.external_tip_anchor_state
        ):
            raise ValueError("export audit binding mismatch")
        expected_adapters = (
            (
                "cfast-theoretical-target-marks-v1",
                "THEORETICAL_TARGET_PNL",
            ),
            ("cfast-fee-and-stress-v2", "FEE_ADJUSTED_PNL"),
            (
                "cfast-book-walk-fill-bounds-v1",
                "EXECUTION_QUALITY_INTERVAL_PNL",
            ),
            (
                "cfast-simnow-not-provided-v1",
                "ACTUAL_SIMNOW_CALIBRATION_PNL",
            ),
            (
                "cfast-simnow-archive-reference-v3",
                "ACTUAL_SIMNOW_CALIBRATION_PNL",
            ),
            (
                "cfast-simnow-session-archive-replay-v4",
                "ACTUAL_SIMNOW_CALIBRATION_PNL",
            ),
        )
        if (
            tuple(
                (adapter.adapter_id, adapter.layer_kind)
                for adapter in self.source_adapters
            )
            != expected_adapters
        ):
            raise ValueError("source adapter set or order mismatch")
        expected_hash = sha256_json(
            self.model_dump(mode="json", exclude={"export_sha256"})
        )
        if self.export_sha256 != expected_hash:
            raise ValueError("export_sha256 mismatch")
        return self
