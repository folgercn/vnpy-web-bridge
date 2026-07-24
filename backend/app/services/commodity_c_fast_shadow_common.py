from __future__ import annotations

import hashlib
import json
from typing import Any

from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def formula_target_binding_payload(
    snapshot: CommodityCFastShadowDTO,
) -> dict[str, Any]:
    return {
        "schema_version": snapshot.schema_version,
        "candidate_id": snapshot.candidate_id,
        "frozen_rule_id": snapshot.frozen_rule_id,
        "frozen_rule_sha256": snapshot.frozen_rule_sha256,
        "frequency": snapshot.frequency,
        "pit_main_definition": snapshot.pit_main_definition,
        "trend_horizons_official_days": list(
            snapshot.trend_horizons_official_days
        ),
        "volatility_lookback_official_days": (
            snapshot.volatility_lookback_official_days
        ),
        "volatility_floor": snapshot.volatility_floor,
        "virtual_nav_cny": snapshot.virtual_nav_cny,
        "source_month": snapshot.source_month,
        "source_official_day": snapshot.source_official_day.isoformat(),
        "execution_day": snapshot.execution_day.isoformat(),
        "input_cutoff_at_utc": snapshot.input_cutoff_at_utc.isoformat(),
        "snapshot_created_at_utc": snapshot.snapshot_created_at_utc.isoformat(),
        "source_is_month_last_official_day": (
            snapshot.source_is_month_last_official_day
        ),
        "execution_is_next_cross_month_official_day": (
            snapshot.execution_is_next_cross_month_official_day
        ),
        "input_cutoff_after_source_close": (
            snapshot.input_cutoff_after_source_close
        ),
        "calendar_alignment": snapshot.calendar_alignment,
        "allocator_output_validation": snapshot.allocator_output_validation,
        "daily_roll_alignment": snapshot.daily_roll_alignment,
        "previous_snapshot_hash": snapshot.previous_snapshot_hash,
        "research_bindings": snapshot.research_bindings.model_dump(mode="json"),
        "guardrails": snapshot.guardrails.model_dump(mode="json"),
        "allocator": snapshot.allocator.model_dump(mode="json"),
        "targets": [
            target.model_dump(mode="json")
            for target in sorted(snapshot.targets, key=lambda row: row.product)
        ],
    }


def formula_target_binding_sha256(snapshot: CommodityCFastShadowDTO) -> str:
    return sha256_json(formula_target_binding_payload(snapshot))


def unsigned_snapshot_payload(snapshot: CommodityCFastShadowDTO) -> dict[str, Any]:
    return snapshot.model_dump(mode="json", exclude={"signature"})
