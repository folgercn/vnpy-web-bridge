from __future__ import annotations

import ast
import base64
import calendar
from copy import deepcopy
from datetime import date, timedelta
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

from jsonschema import Draft202012Validator
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.schemas.commodity_simnow import (
    CommodityPositionManagerShadowDTO,
    CommodityTargetBatchDTO,
)
from app.services.commodity_simnow import CommoditySimNowService


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_relative_vol_snapshot_producer as producer  # noqa: E402


PRICES = {
    "ag": 8000.0,
    "al": 20000.0,
    "au": 500.0,
    "bu": 3800.0,
    "cu": 80000.0,
    "rb": 3600.0,
    "ru": 15000.0,
    "sc": 600.0,
    "sp": 6200.0,
    "zn": 24000.0,
}
SOURCE_WEIGHTS = {
    "ag": 0.10,
    "al": -0.08,
    "au": -0.05,
    "bu": 0.09,
    "cu": 0.07,
    "rb": -0.06,
    "ru": -0.04,
    "sc": 0.03,
    "sp": -0.02,
    "zn": -0.04,
}
PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _weekdays_ending(end: date, count: int) -> list[date]:
    result: list[date] = []
    current = end
    while len(result) < count:
        if current.weekday() < 5:
            result.append(current)
        current -= timedelta(days=1)
    return sorted(result)


def _returns(*, fast_amplitude: float = 0.015) -> list[float]:
    values: list[float] = []
    for index in range(producer.SLOW_LOOKBACK_DAYS):
        amplitude = (
            fast_amplitude
            if index >= producer.SLOW_LOOKBACK_DAYS - producer.FAST_LOOKBACK_DAYS
            else 0.01
        )
        values.append(amplitude if index % 2 == 0 else -amplitude)
    return values


def _official_calendar(cutoff_day: date) -> tuple[dict, list[date]]:
    history = _weekdays_ending(cutoff_day, 140)
    query_start = history[0]
    rows: list[dict] = []
    current = query_start
    while current <= cutoff_day:
        rows.append(
            {
                "calendar_day": current.isoformat(),
                "is_official_day": current.weekday() < 5,
            }
        )
        current += timedelta(days=1)
    official_days = [
        date.fromisoformat(row["calendar_day"])
        for row in rows
        if row["is_official_day"]
    ]
    return (
        {
            "binding_id": f"official-calendar-{cutoff_day.isoformat()}-a01",
            "source_class": "OFFICIAL_TRADING_CALENDAR",
            "source_identity": "official-shfe-ine-calendar-v1",
            "exchange_scope": "SHFE_INE",
            "query_start": query_start.isoformat(),
            "query_end": cutoff_day.isoformat(),
            "research_as_of_official_day": official_days[-1].isoformat(),
            "calendar_rows": rows,
            "calendar_rows_sha256": hashlib.sha256(
                producer.canonical_json(rows)
            ).hexdigest(),
            "lineage_sha256": hashlib.sha256(
                b"official-calendar-lineage"
            ).hexdigest(),
            "claimed_receipt_sha256": hashlib.sha256(
                b"official-calendar-receipt"
            ).hexdigest(),
        },
        official_days,
    )


def _baseline_batch(
    *,
    source_month: str,
    execution_day: date,
    previous_batch_hash: str | None = None,
    execution_lane: str = "official_forward",
) -> tuple[dict, str]:
    buffered = producer.frozen._buffer_weights(SOURCE_WEIGHTS)
    unit_weights = {
        product: (
            PRICES[product]
            * producer.frozen.PRODUCT_SPECS[product]["multiplier"]
            / producer.frozen.VIRTUAL_NAV_CNY
        )
        for product in producer.frozen.PRODUCTS
    }
    allocation = producer.frozen._joint_integer_allocate(buffered, unit_weights)
    rows: list[dict] = []
    for product in producer.frozen.PRODUCTS:
        spec = producer.frozen.PRODUCT_SPECS[product]
        rows.append(
            {
                "product": product,
                "previous_exact_contract": (
                    f"{spec['exchange']}.{product}2612"
                    if previous_batch_hash is not None
                    else None
                ),
                "previous_target_quantity": (
                    allocation.quantities[product]
                    if previous_batch_hash is not None
                    else 0
                ),
                "exact_contract": f"{spec['exchange']}.{product}2612",
                "target_quantity": allocation.quantities[product],
                "source_target_weight": SOURCE_WEIGHTS[product],
                "buffered_target_weight": buffered[product],
                "reference_open_price": PRICES[product],
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
            }
        )
    batch = {
        "schema_version": "commodity_static_core_equal_target_batch_v2",
        "batch_id": f"batch-{execution_day.isoformat()}-static-core",
        "scheduler_id": "STATIC_CORE_EQUAL",
        "source_combination_arm": "CORE_EQUAL_TARGET",
        "execution_lane": execution_lane,
        "source_month": source_month,
        "execution_day": execution_day.isoformat(),
        "virtual_nav_cny": 20_000_000,
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "guardband": {
            "product": 0.12,
            "sector": 0.27,
            "gross": 0.8,
            "target_net": 0.0,
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
        "previous_batch_hash": previous_batch_hash,
        "targets": rows,
        "signer_key_id": "research-key",
        "signature": PLACEHOLDER_SIGNATURE,
    }
    canonical = producer.canonical_json(
        {key: value for key, value in batch.items() if key != "signature"}
    )
    return batch, hashlib.sha256(canonical).hexdigest()


def source_view(
    *,
    source_month: str = "2026-08",
    execution_day: date = date(2026, 9, 1),
    fast_amplitude: float = 0.015,
    previous_snapshot: dict | None = None,
    previous_snapshot_hash: str | None = None,
    previous_batch_hash: str | None = None,
    execution_lane: str = "official_forward",
) -> dict:
    year, month = (int(item) for item in source_month.split("-"))
    cutoff_day = date(
        year,
        month,
        calendar.monthrange(year, month)[1],
    )
    official_calendar, calendar_official_days = _official_calendar(cutoff_day)
    official_days = calendar_official_days[-producer.SLOW_LOOKBACK_DAYS :]
    values = _returns(fast_amplitude=fast_amplitude)
    baseline, baseline_hash = _baseline_batch(
        source_month=source_month,
        execution_day=execution_day,
        previous_batch_hash=previous_batch_hash,
        execution_lane=execution_lane,
    )
    return {
        "schema_version": producer.SOURCE_SCHEMA_VERSION,
        "purpose": producer.SOURCE_PURPOSE,
        "status": producer.SOURCE_STATUS,
        "source_view_id": f"relative-vol-source-{source_month.replace('-', '')}-a01",
        "snapshot_id": f"relative-vol-shadow-{execution_day.isoformat()}-a01",
        "generated_at": f"{execution_day.isoformat()}T09:00:00+08:00",
        "cutoff_at": f"{cutoff_day.isoformat()}T15:00:00+08:00",
        "official_calendar": official_calendar,
        "official_days": [item.isoformat() for item in official_days],
        "baseline_daily_returns": [
            {
                "official_day": official_day.isoformat(),
                "daily_return": value,
            }
            for official_day, value in zip(official_days, values)
        ],
        "baseline_batch_hash": baseline_hash,
        "baseline_batch": baseline,
        "continuity": {
            "mode": "linked" if previous_snapshot is not None else "genesis",
            "previous_snapshot_hash": previous_snapshot_hash,
            "previous_snapshot": previous_snapshot,
        },
    }


def _signed_snapshot_from_result(result: producer.ProducerResult) -> tuple[dict, str]:
    snapshot = json.loads(result.snapshot_draft)
    snapshot["signature"] = PLACEHOLDER_SIGNATURE
    snapshot_hash = hashlib.sha256(
        producer.canonical_json(
            {key: value for key, value in snapshot.items() if key != "signature"}
        )
    ).hexdigest()
    return snapshot, snapshot_hash


def _consumer_signed_snapshot(
    result: producer.ProducerResult,
    private_key: Ed25519PrivateKey,
) -> CommodityPositionManagerShadowDTO:
    snapshot = json.loads(result.snapshot_draft)
    snapshot["signature"] = base64.b64encode(
        private_key.sign(result.snapshot_draft)
    ).decode("ascii")
    return CommodityPositionManagerShadowDTO.model_validate(snapshot)


def _rehash_baseline(source: dict) -> None:
    batch = source["baseline_batch"]
    source["baseline_batch_hash"] = hashlib.sha256(
        producer.canonical_json(
            {key: value for key, value in batch.items() if key != "signature"}
        )
    ).hexdigest()


def _rehash_calendar(source: dict) -> None:
    official_calendar = source["official_calendar"]
    official_calendar["calendar_rows_sha256"] = hashlib.sha256(
        producer.canonical_json(official_calendar["calendar_rows"])
    ).hexdigest()


def linked_source_view() -> dict:
    genesis_source = source_view()
    genesis_result = producer.produce_snapshot(genesis_source)
    previous_snapshot, previous_snapshot_hash = _signed_snapshot_from_result(
        genesis_result
    )
    return source_view(
        source_month="2026-09",
        execution_day=date(2026, 10, 1),
        previous_snapshot=previous_snapshot,
        previous_snapshot_hash=previous_snapshot_hash,
        previous_batch_hash=genesis_source["baseline_batch_hash"],
    )


def test_golden_snapshot_is_deterministic_lagged_and_non_authoritative() -> None:
    source = source_view()
    first = producer.produce_snapshot(source)
    second = producer.produce_snapshot(producer.canonical_json(source))

    assert first == second
    snapshot = json.loads(first.snapshot_draft)
    evidence = json.loads(first.evidence)
    values = [row["daily_return"] for row in source["baseline_daily_returns"]]
    expected_fast = statistics.stdev(values[-21:]) * math.sqrt(252)
    expected_slow = statistics.stdev(values) * math.sqrt(252)
    expected_raw = min(1.2, max(0.8, math.sqrt(expected_slow / expected_fast)))
    expected_smoothed = 0.5 * expected_raw + 0.5

    assert "signature" not in snapshot
    draft_with_placeholder = {**snapshot, "signature": PLACEHOLDER_SIGNATURE}
    CommodityPositionManagerShadowDTO.model_validate(draft_with_placeholder)
    assert snapshot["fast_annual_vol"] == pytest.approx(expected_fast, abs=1e-15)
    assert snapshot["slow_annual_vol"] == pytest.approx(expected_slow, abs=1e-15)
    assert snapshot["raw_scale"] == pytest.approx(expected_raw, abs=1e-15)
    assert snapshot["smoothed_scale"] == pytest.approx(
        expected_smoothed, abs=1e-15
    )
    assert snapshot["input_cutoff_day"] == "2026-08-31"
    assert snapshot["execution_day"] == "2026-09-01"
    assert snapshot["authority_granted"] is False
    assert snapshot["dispatch_allowed"] is False
    assert evidence["sample_ddof"] == 1
    assert evidence["daily_return_count"] == 126
    assert evidence["snapshot_signed"] is False
    assert evidence["snapshot_installed"] is False
    assert evidence["sealed_source_view_verified_by_producer"] is False
    assert evidence["daily_return_source_authority_verified_by_producer"] is False
    assert evidence["baseline_batch_hash_validation"] == (
        "CANONICAL_UNSIGNED_PAYLOAD_HASH_MATCH_ONLY"
    )
    assert evidence["baseline_batch_signature_verified_by_producer"] is False
    assert evidence["frozen_kernel_code_identity"] == {
        "source_file": "commodity_c_fast_pure_producer_kernel.py",
        "actual_source_bytes_sha256": producer.C_FAST_KERNEL_CODE_SHA256,
        "pinned_source_bytes_sha256": producer.C_FAST_KERNEL_CODE_SHA256,
    }
    assert evidence["official_calendar"]["latest_126_alignment_verified"] is True
    assert (
        evidence["official_calendar"]["calendar_authority_verified_by_producer"]
        is False
    )
    assert (
        evidence["official_calendar"]["sealed_issue_181_verification_required"]
        is True
    )
    assert evidence["baseline_chain_rule"] == (
        "FORMAL_GENESIS_COLD_BASELINE_REQUIRED"
    )
    assert evidence["guardband"]["lineage_sha256"] == (
        producer.frozen.LINEAGE["guardband_v2_source_sha256"]
    )
    assert evidence["allocator"]["lineage_sha256"] == (
        producer.frozen.LINEAGE["integer_allocator_source_sha256"]
    )
    for field in producer.FALSE_AUTHORITY_FIELDS:
        assert evidence[field] is False
    assert first.source_view_canonical_sha256 == hashlib.sha256(
        producer.canonical_json(source)
    ).hexdigest()
    assert first.snapshot_draft_sha256 == hashlib.sha256(
        first.snapshot_draft
    ).hexdigest()
    consumer_batch = CommodityTargetBatchDTO.model_validate(
        source["baseline_batch"]
    )
    consumer_batch_hash = hashlib.sha256(
        producer.canonical_json(
            consumer_batch.model_dump(mode="json", exclude={"signature"})
        )
    ).hexdigest()
    assert consumer_batch_hash == source["baseline_batch_hash"]

    rows = {row["product"]: row for row in snapshot["targets"]}
    baseline_quantities = evidence["baseline_allocation"]["quantities"]
    shadow_quantities = evidence["shadow_allocation"]["quantities"]
    assert {
        product: rows[product]["baseline_target_quantity"]
        for product in producer.frozen.PRODUCTS
    } == baseline_quantities
    assert {
        product: rows[product]["shadow_target_quantity"]
        for product in producer.frozen.PRODUCTS
    } == shadow_quantities
    assert first.snapshot_draft_sha256 == (
        "50b86ba46f2079f2489fa7fb4178ece6ba874c664704ad5181156dee492721ee"
    )


def test_linked_continuity_matches_existing_snapshot_contract() -> None:
    source = linked_source_view()

    result = producer.produce_snapshot(source)
    snapshot = json.loads(result.snapshot_draft)

    assert snapshot["continuity_mode"] == "linked"
    assert (
        snapshot["previous_snapshot_hash"]
        == source["continuity"]["previous_snapshot_hash"]
    )
    assert snapshot["previous_smoothed_scale"] == pytest.approx(
        source["continuity"]["previous_snapshot"]["smoothed_scale"],
        abs=1e-15,
    )
    assert snapshot["source_month"] == "2026-09"
    assert snapshot["execution_day"] == "2026-10-01"
    current_ag = next(
        row
        for row in source["baseline_batch"]["targets"]
        if row["product"] == "ag"
    )
    previous_ag = next(
        row
        for row in source["continuity"]["previous_snapshot"]["targets"]
        if row["product"] == "ag"
    )
    assert current_ag["previous_target_quantity"] == previous_ag[
        "baseline_target_quantity"
    ]
    assert current_ag["previous_target_quantity"] != previous_ag[
        "shadow_target_quantity"
    ]
    assert json.loads(result.evidence)["baseline_chain_rule"] == (
        "FORMAL_LINKED_EXACT_PREVIOUS_BASELINE_REQUIRED"
    )


def test_generated_genesis_and_linked_drafts_pass_existing_consumer_verifier() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = object.__new__(CommoditySimNowService)
    verifier._trusted_keys = lambda: {  # type: ignore[method-assign]
        "research-key": private_key.public_key()
    }

    genesis_result = producer.produce_snapshot(source_view())
    genesis = _consumer_signed_snapshot(genesis_result, private_key)
    genesis_hash = verifier._verify_position_manager_shadow(genesis)
    verifier._load_position_manager_shadow_state = lambda: None  # type: ignore[method-assign]
    assert genesis_hash == genesis_result.snapshot_draft_sha256
    assert (
        verifier._verify_position_manager_continuity(genesis, genesis_hash)
        == "genesis"
    )

    linked_result = producer.produce_snapshot(linked_source_view())
    linked = _consumer_signed_snapshot(linked_result, private_key)
    linked_hash = verifier._verify_position_manager_shadow(linked)
    verifier._load_position_manager_shadow_state = lambda: {  # type: ignore[method-assign]
        "snapshot_hash": genesis_hash,
        "source_month": genesis.source_month,
        "smoothed_scale": genesis.smoothed_scale,
        "continuity_state": "genesis",
        "continuity_verified": True,
    }
    assert linked_hash == linked_result.snapshot_draft_sha256
    assert (
        verifier._verify_position_manager_continuity(linked, linked_hash)
        == "verified"
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: (
                value["official_days"].pop(),
                value["baseline_daily_returns"].pop(),
            ),
            "exactly 126",
        ),
        (
            lambda value: (
                value["official_days"].__setitem__(
                    -1, value["baseline_batch"]["execution_day"]
                ),
                value["baseline_daily_returns"][-1].__setitem__(
                    "official_day", value["baseline_batch"]["execution_day"]
                ),
            ),
            "lookahead",
        ),
        (
            lambda value: value["baseline_batch"]["targets"][0].__setitem__(
                "source_target_weight", 0.11
            ),
            "batch hash tamper",
        ),
        (
            lambda value: value["baseline_batch"]["targets"][0].__setitem__(
                "buffered_target_weight", 0.11
            ),
            "batch hash tamper",
        ),
        (
            lambda value: value["baseline_batch"]["targets"][0].__setitem__(
                "target_quantity",
                value["baseline_batch"]["targets"][0]["target_quantity"] + 1,
            ),
            "batch hash tamper",
        ),
    ],
)
def test_missing_lookahead_and_baseline_tamper_fail_closed(
    mutate,
    message: str,
) -> None:
    source = source_view()
    mutate(source)

    with pytest.raises(producer.SnapshotProducerError, match=message):
        producer.produce_snapshot(source)


def test_stale_return_window_cannot_pose_as_latest_126_official_days() -> None:
    source = source_view()
    stale_days = [
        (date.fromisoformat(value) - timedelta(days=365)).isoformat()
        for value in source["official_days"]
    ]
    source["official_days"] = stale_days
    for row, stale_day in zip(source["baseline_daily_returns"], stale_days):
        row["official_day"] = stale_day

    with pytest.raises(
        producer.SnapshotProducerError,
        match="calendar's most recent 126",
    ):
        producer.produce_snapshot(source)


def test_stale_calendar_binding_cannot_move_the_complete_window_back_one_year() -> None:
    source = source_view()
    official_calendar = source["official_calendar"]
    for field in (
        "query_start",
        "query_end",
        "research_as_of_official_day",
    ):
        official_calendar[field] = (
            date.fromisoformat(official_calendar[field]) - timedelta(days=365)
        ).isoformat()
    for row in official_calendar["calendar_rows"]:
        row["calendar_day"] = (
            date.fromisoformat(row["calendar_day"]) - timedelta(days=365)
        ).isoformat()
    stale_days = [
        (date.fromisoformat(value) - timedelta(days=365)).isoformat()
        for value in source["official_days"]
    ]
    source["official_days"] = stale_days
    for row, stale_day in zip(source["baseline_daily_returns"], stale_days):
        row["official_day"] = stale_day
    _rehash_calendar(source)

    with pytest.raises(
        producer.SnapshotProducerError,
        match="does not end at the PIT cutoff",
    ):
        producer.produce_snapshot(source)


def test_calendar_terminal_missing_tamper_and_natural_day_gap_fail_closed() -> None:
    terminal_missing = source_view()
    terminal_calendar = terminal_missing["official_calendar"]
    last_open_index = max(
        index
        for index, row in enumerate(terminal_calendar["calendar_rows"])
        if row["is_official_day"]
    )
    terminal_calendar["calendar_rows"][last_open_index][
        "is_official_day"
    ] = False
    remaining_open = [
        row["calendar_day"]
        for row in terminal_calendar["calendar_rows"]
        if row["is_official_day"]
    ]
    terminal_calendar["research_as_of_official_day"] = remaining_open[-1]
    _rehash_calendar(terminal_missing)
    with pytest.raises(
        producer.SnapshotProducerError,
        match="calendar's most recent 126",
    ):
        producer.produce_snapshot(terminal_missing)

    hash_tamper = source_view()
    hash_tamper["official_calendar"]["calendar_rows"][10][
        "is_official_day"
    ] = not hash_tamper["official_calendar"]["calendar_rows"][10][
        "is_official_day"
    ]
    with pytest.raises(
        producer.SnapshotProducerError,
        match="calendar rows hash tamper",
    ):
        producer.produce_snapshot(hash_tamper)

    gap = source_view()
    gap["official_calendar"]["calendar_rows"].pop(10)
    _rehash_calendar(gap)
    with pytest.raises(
        producer.SnapshotProducerError,
        match="natural-day gap",
    ):
        producer.produce_snapshot(gap)


def test_zero_and_nonfinite_volatility_fail_closed() -> None:
    zero = source_view()
    for row in zero["baseline_daily_returns"]:
        row["daily_return"] = 0.0
    with pytest.raises(
        producer.SnapshotProducerError, match="volatility must be finite and positive"
    ):
        producer.produce_snapshot(zero)

    nonfinite = source_view()
    nonfinite["baseline_daily_returns"][-1]["daily_return"] = float("inf")
    with pytest.raises(producer.SnapshotProducerError, match="finite JSON"):
        producer.produce_snapshot(nonfinite)

    with pytest.raises(
        producer.SnapshotProducerError, match="constant 'NaN' is forbidden"
    ):
        producer.produce_snapshot(
            producer.canonical_json(source_view()).replace(
                b'"daily_return":-0.015', b'"daily_return":NaN', 1
            )
        )


@pytest.mark.parametrize(
    ("field", "mutate", "message"),
    [
        (
            "buffered_target_weight",
            lambda value: float(value) + 0.001,
            "guardband tamper",
        ),
        (
            "target_quantity",
            lambda value: int(value) + 1,
            "integer allocation mismatch",
        ),
    ],
)
def test_semantic_tamper_fails_even_when_claimed_batch_hash_is_rewritten(
    field: str,
    mutate,
    message: str,
) -> None:
    source = source_view()
    row = source["baseline_batch"]["targets"][0]
    row[field] = mutate(row[field])
    _rehash_baseline(source)

    with pytest.raises(producer.SnapshotProducerError, match=message):
        producer.produce_snapshot(source)


@pytest.mark.parametrize("invalid_key_id", [True, 7])
def test_signer_key_id_rejects_non_string_json_types(
    invalid_key_id: object,
) -> None:
    source = source_view()
    source["baseline_batch"]["signer_key_id"] = invalid_key_id
    _rehash_baseline(source)

    with pytest.raises(
        producer.SnapshotProducerError,
        match="signer_key_id must be one key id",
    ):
        producer.produce_snapshot(source)


def test_chain_hash_month_and_missing_proof_fail_closed() -> None:
    hash_tampered = linked_source_view()
    hash_tampered["continuity"]["previous_snapshot_hash"] = "f" * 64
    with pytest.raises(
        producer.SnapshotProducerError, match="previous snapshot hash tamper"
    ):
        producer.produce_snapshot(hash_tampered)

    missing = linked_source_view()
    missing["continuity"]["previous_snapshot"] = None
    with pytest.raises(
        producer.SnapshotProducerError, match="continuity proof is missing"
    ):
        producer.produce_snapshot(missing)

    month_break = linked_source_view()
    previous = month_break["continuity"]["previous_snapshot"]
    previous["source_month"] = "2026-07"
    previous_hash = hashlib.sha256(
        producer.canonical_json(
            {key: value for key, value in previous.items() if key != "signature"}
        )
    ).hexdigest()
    month_break["continuity"]["previous_snapshot_hash"] = previous_hash
    with pytest.raises(
        producer.SnapshotProducerError, match="source month chain break"
    ):
        producer.produce_snapshot(month_break)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda source: source["baseline_batch"].__setitem__(
                "previous_batch_hash", "f" * 64
            ),
            "previous batch hash does not match",
        ),
        (
            lambda source: source["baseline_batch"]["targets"][0].__setitem__(
                "previous_exact_contract", "SHFE.ag2701"
            ),
            "previous exact contract mismatch",
        ),
        (
            lambda source: source["baseline_batch"]["targets"][0].__setitem__(
                "previous_target_quantity",
                source["baseline_batch"]["targets"][0][
                    "previous_target_quantity"
                ]
                + 1,
            ),
            "previous target quantity mismatch",
        ),
    ],
)
def test_linked_baseline_chain_is_bound_to_previous_snapshot(
    mutate,
    message: str,
) -> None:
    source = linked_source_view()
    mutate(source)
    _rehash_baseline(source)

    with pytest.raises(producer.SnapshotProducerError, match=message):
        producer.produce_snapshot(source)


def test_formal_genesis_requires_cold_baseline_but_simnow_is_isolated() -> None:
    formal = source_view(previous_batch_hash="a" * 64)
    with pytest.raises(
        producer.SnapshotProducerError,
        match="formal genesis baseline previous batch hash must be null",
    ):
        producer.produce_snapshot(formal)

    simnow = source_view(
        source_month="2026-07",
        execution_day=date(2026, 8, 3),
        previous_batch_hash="a" * 64,
        execution_lane="simnow_shakedown",
    )
    result = producer.produce_snapshot(simnow)
    snapshot = json.loads(result.snapshot_draft)
    evidence = json.loads(result.evidence)

    assert snapshot["execution_lane"] == "simnow_shakedown"
    assert snapshot["countable_forward"] is False
    assert snapshot["continuity_mode"] == "genesis"
    assert snapshot["previous_snapshot_hash"] is None
    assert snapshot["previous_smoothed_scale"] == 1.0
    assert evidence["baseline_chain_rule"] == (
        "SIMNOW_ISOLATED_POSITION_MANAGER_CHAIN_BASELINE_CHAIN_NOT_REINTERPRETED"
    )


@pytest.mark.parametrize(
    ("fast_amplitude", "expected"),
    [
        (0.05, 0.8),
        (0.001, 1.2),
    ],
)
def test_scale_clip_boundaries(fast_amplitude: float, expected: float) -> None:
    source = source_view(fast_amplitude=fast_amplitude)

    result = producer.produce_snapshot(source)

    assert json.loads(result.snapshot_draft)["raw_scale"] == expected


def test_source_schema_is_strict_bounded_and_fixture_valid() -> None:
    schema_path = (
        ROOT
        / "docs/schemas/commodity-relative-vol-position-manager-source-view-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(source_view())
    Draft202012Validator(schema).validate(linked_source_view())
    assert schema["x-vnpy-resource-limits"] == {
        "max_raw_bytes": producer.MAX_SOURCE_VIEW_RAW_BYTES,
        "max_calendar_rows": producer.MAX_CALENDAR_ROWS,
        "official_daily_returns": producer.SLOW_LOOKBACK_DAYS,
        "baseline_targets": len(producer.frozen.PRODUCTS),
    }

    def assert_strict(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for item in node.values():
                assert_strict(item)
        elif isinstance(node, list):
            for item in node:
                assert_strict(item)

    assert_strict(schema)


def test_frozen_kernel_actual_source_bytes_are_pinned_and_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel_path = ROOT / "scripts/commodity_c_fast_pure_producer_kernel.py"
    assert hashlib.sha256(kernel_path.read_bytes()).hexdigest() == (
        producer.C_FAST_KERNEL_CODE_SHA256
    )

    monkeypatch.setattr(producer, "C_FAST_KERNEL_CODE_SHA256", "0" * 64)
    with pytest.raises(
        producer.SnapshotProducerError,
        match="source code identity mismatch",
    ):
        producer.produce_snapshot(source_view())

    monkeypatch.setattr(
        producer,
        "C_FAST_KERNEL_CODE_SHA256",
        hashlib.sha256(kernel_path.read_bytes()).hexdigest(),
    )
    drifted = tmp_path / "commodity_c_fast_pure_producer_kernel.py"
    drifted.write_bytes(kernel_path.read_bytes() + b"\n# drift\n")
    monkeypatch.setattr(producer, "_frozen_kernel_path", lambda: drifted)
    with pytest.raises(
        producer.SnapshotProducerError,
        match="source code identity mismatch",
    ):
        producer.produce_snapshot(source_view())


def test_import_boundary_excludes_execution_network_signing_and_installation() -> None:
    path = ROOT / "scripts/commodity_relative_vol_snapshot_producer.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)

    forbidden_imports = {
        "app",
        "backend",
        "cryptography",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "vnpy",
        "sqlalchemy",
        "pymongo",
    }
    assert not any(
        module == item or module.startswith(f"{item}.")
        for module in imported
        for item in forbidden_imports
    )
    assert not {"sign", "install", "send_order", "cancel_order"} & functions


def test_source_raw_bytes_and_duplicate_keys_fail_before_semantics() -> None:
    with pytest.raises(producer.SnapshotProducerError, match="raw bytes exceeds"):
        producer.produce_snapshot(
            b"{" + b"x" * producer.MAX_SOURCE_VIEW_RAW_BYTES
        )

    with pytest.raises(producer.SnapshotProducerError, match="duplicate key"):
        producer.produce_snapshot(b'{"schema_version":"a","schema_version":"b"}')


def test_cli_writes_unsigned_outputs_once_and_refuses_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "source.json"
    snapshot_path = tmp_path / "snapshot.json"
    evidence_path = tmp_path / "evidence.json"
    input_path.write_bytes(producer.canonical_json(source_view()))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "commodity_relative_vol_snapshot_producer.py",
            "--input",
            str(input_path),
            "--snapshot-output",
            str(snapshot_path),
            "--evidence-output",
            str(evidence_path),
        ],
    )

    assert producer.main() == 0
    assert "signature" not in json.loads(snapshot_path.read_bytes())
    assert json.loads(evidence_path.read_bytes())["snapshot_signed"] is False
    assert producer.main() == 2


def test_fixture_copy_has_no_accidental_shared_mutation() -> None:
    original = source_view()
    copied = deepcopy(original)
    copied["baseline_daily_returns"][0]["daily_return"] = 0.123

    assert original["baseline_daily_returns"][0]["daily_return"] != 0.123
