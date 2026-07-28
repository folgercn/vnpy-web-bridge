from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.commodity_c_fast_research import (
    CommodityCFastSimNowResearchBundleDTO,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services.commodity_c_fast_shadow import CommodityCFastShadowService
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    formula_target_binding_sha256,
    sha256_json,
)


class CFastResearchBundleInvalidError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


PLACEHOLDER_SIGNATURE = (
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAA=="
)


def research_bundle_checksum(payload: dict[str, Any]) -> str:
    core = copy.deepcopy(payload)
    core.pop("bundle_checksum", None)
    return sha256_json(core)


def load_research_bundle(path: Path) -> CommodityCFastSimNowResearchBundleDTO:
    try:
        raw_bytes = path.read_bytes()
        if len(raw_bytes) > 2 * 1024 * 1024:
            raise CFastResearchBundleInvalidError("BUNDLE_TOO_LARGE")
        raw = json.loads(raw_bytes.decode("utf-8"))
    except CFastResearchBundleInvalidError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CFastResearchBundleInvalidError("BUNDLE_JSON_INVALID") from exc
    if not isinstance(raw, dict):
        raise CFastResearchBundleInvalidError("BUNDLE_ROOT_INVALID")
    if research_bundle_checksum(raw) != raw.get("bundle_checksum"):
        raise CFastResearchBundleInvalidError("BUNDLE_CHECKSUM_MISMATCH")
    try:
        return CommodityCFastSimNowResearchBundleDTO.model_validate(raw)
    except ValidationError as exc:
        raise CFastResearchBundleInvalidError("BUNDLE_SCHEMA_INVALID") from exc


def verify_evidence_files(
    bundle: CommodityCFastSimNowResearchBundleDTO,
    evidence_root: Path,
) -> str:
    root = evidence_root.resolve()
    manifest: list[dict[str, str]] = []
    observed_hashes: set[str] = set()
    for entry in sorted(
        bundle.evidence_files,
        key=lambda row: (row.purpose, row.relative_path),
    ):
        path = (root / entry.relative_path).resolve()
        if path == root or root not in path.parents:
            raise CFastResearchBundleInvalidError(
                "EVIDENCE_PATH_ESCAPES_ROOT"
            )
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise CFastResearchBundleInvalidError(
                "EVIDENCE_FILE_UNREADABLE"
            ) from exc
        if digest != entry.sha256:
            raise CFastResearchBundleInvalidError(
                "EVIDENCE_FILE_HASH_MISMATCH"
            )
        observed_hashes.add(digest)
        manifest.append(entry.model_dump(mode="json"))
    if any(
        row.reference_price_source_sha256 not in observed_hashes
        for row in bundle.targets
    ):
        raise CFastResearchBundleInvalidError(
            "REFERENCE_PRICE_EVIDENCE_UNBOUND"
        )
    return sha256_json(manifest)


def produce_unsigned_snapshot(
    bundle: CommodityCFastSimNowResearchBundleDTO,
    *,
    evidence_manifest_sha256: str,
) -> CommodityCFastShadowDTO:
    evidence_by_purpose: dict[str, list[str]] = {}
    for entry in bundle.evidence_files:
        evidence_by_purpose.setdefault(entry.purpose, []).append(entry.sha256)
    singleton_hashes: dict[str, str] = {}
    for purpose in (
        "research_manifest",
        "allocation_evidence",
        "daily_roll_evidence",
    ):
        values = evidence_by_purpose.get(purpose, [])
        if len(values) != 1:
            raise CFastResearchBundleInvalidError(
                f"{purpose.upper()}_COUNT_INVALID"
            )
        singleton_hashes[purpose] = values[0]
    payload: dict[str, Any] = {
        "schema_version": (
            "commodity_c_fast_cross_section_neutral_simnow_shakedown_v1"
        ),
        "snapshot_id": bundle.snapshot_id,
        "candidate_id": bundle.candidate_id,
        "frozen_rule_id": bundle.frozen_rule_id,
        "frozen_rule_sha256": bundle.frozen_rule_sha256,
        "mode": "simnow_shakedown_only",
        "execution_lane": "simnow_shakedown",
        "frequency": "MONTHLY",
        "pit_main_definition": "DAILY_PIT_OI_MAIN",
        "trend_horizons_official_days": [21, 63, 126],
        "volatility_lookback_official_days": 60,
        "volatility_floor": 0.05,
        "virtual_nav_cny": 20_000_000,
        "source_month": bundle.source_month,
        "source_official_day": bundle.source_official_day.isoformat(),
        "execution_day": bundle.execution_day.isoformat(),
        "input_cutoff_at_utc": bundle.input_cutoff_at_utc.isoformat(),
        "snapshot_created_at_utc": (
            bundle.snapshot_created_at_utc.isoformat()
        ),
        "source_is_month_last_official_day": False,
        "execution_is_next_cross_month_official_day": False,
        "input_cutoff_after_source_close": True,
        "countable_forward": False,
        "expires_at_utc": bundle.expires_at_utc.isoformat(),
        "calendar_alignment": "SIGNED_ASSERTION_NOT_RUNTIME_VERIFIED",
        "allocator_output_validation": (
            "SIGNED_ALLOCATOR_OUTPUT_NOT_RECOMPUTED"
        ),
        "daily_roll_alignment": (
            "SIGNED_DAILY_ROLL_ASSERTION_NOT_RUNTIME_VERIFIED"
        ),
        "previous_snapshot_hash": bundle.previous_snapshot_hash,
        "research_bindings": {
            "research_contract_sha256": (
                "c1639d5f7714fd3989da799ece2743ca392ac8a8edad64a7f1238dd2e51c9d31"
            ),
            "formula_builder_sha256": (
                "7ebe1529173b46cbae17680d872680c7bb7bae39863d09b2d9a37183828a43a9"
            ),
            "target_builder_sha256": (
                "40fd1a27bb1e6dedf483a4c7dcec6d181d325d9c9958d6620f79f04fbdb696db"
            ),
            "historical_fresh_exact_runner_sha256": (
                "7e75ad73a8b037b80937cb449b863305753ec7b2860568422906fd55bb2a2fbe"
            ),
            "snapshot_producer_status": (
                "IMPLEMENTED_HUMAN_CONFIRMED_SIMNOW_RESEARCH_BUNDLE_V1"
            ),
            "research_input_bundle_sha256": bundle.bundle_checksum,
            "research_evidence_manifest_sha256": evidence_manifest_sha256,
            "snapshot_producer_id": (
                "commodity_c_fast_simnow_snapshot_producer_v1"
            ),
            "research_manifest_sha256": singleton_hashes[
                "research_manifest"
            ],
            "calendar_authority_sha256": (
                "57b5341b45cb92d7e991f028d780580ab712e87c9cc86c7036917b638cddc76f"
            ),
            "allocator_runner_sha256": (
                "66497283d1c35383d620ef3c92f2c23316046a9b4b0cbe6f1dcf3f361041f307"
            ),
            "guardband_runner_sha256": (
                "e9871b26af4f0ebebed6e697e8fa1c3064bc3d6557df739bcef9b80697eab353"
            ),
            "allocator_manifest_sha256": (
                "8595fb3d4df57e4b6db0e8a64b02bbc0e90d243d0e6a93060837f5a748c8057f"
            ),
            "allocation_evidence_sha256": singleton_hashes[
                "allocation_evidence"
            ],
            "daily_roll_evidence_sha256": singleton_hashes[
                "daily_roll_evidence"
            ],
        },
        "guardrails": {
            "source_product_abs_cap": 0.20,
            "source_sector_gross_cap": 0.35,
            "source_portfolio_gross_cap": 1.0,
            "source_target_net": 0.0,
            "buffered_product_abs_cap": 0.12,
            "buffered_sector_gross_cap": 0.27,
            "buffered_portfolio_gross_cap": 0.80,
            "buffered_target_net": 0.0,
            "integer_product_abs_hard_cap": 0.15,
            "integer_sector_gross_hard_cap": 0.35,
            "integer_portfolio_gross_hard_cap": 1.0,
            "integer_abs_net_hard_cap": 0.10,
        },
        "allocator": {
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": 2,
            "beam_width": 2048,
            "net_error_penalty": 1.0,
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
        },
        "formula_target_binding_sha256": "0" * 64,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "dynamic_selection_allowed": False,
        "production_allowed": False,
        "targets": [
            row.model_dump(mode="json") for row in bundle.targets
        ],
        "signer_key_id": bundle.signer_key_id,
        "signature": PLACEHOLDER_SIGNATURE,
    }
    snapshot = CommodityCFastShadowDTO.model_validate(payload)
    payload["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(snapshot)
    )
    snapshot = CommodityCFastShadowDTO.model_validate(payload)
    try:
        CommodityCFastShadowService(
            settings=Settings()
        )._verify_targets(snapshot)
    except Exception as exc:
        raise CFastResearchBundleInvalidError(
            getattr(exc, "code", "RESEARCH_TARGETS_INVALID")
        ) from exc
    return snapshot


def unsigned_snapshot_json(snapshot: CommodityCFastShadowDTO) -> bytes:
    payload = snapshot.model_dump(mode="json", exclude={"signature"})
    return canonical_json(payload)
