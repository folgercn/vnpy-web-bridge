from __future__ import annotations

import ast
from copy import deepcopy
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from collector_ordered_l1_bbo_change_v1 import (  # noqa: E402
    BBOChangeContractError,
    CANDIDATE_ID,
    DATA_CONTRACT_ID,
    RESEARCH_LINE_ID,
    CustodyJournal,
    VerifiedCustodyStream,
    pin_custody_root,
    read_verified_custody_stream_v1,
    replay_multi_signal_raw_v1,
)
from collector_ordered_l1_bbo_change_auditor_v1 import (  # noqa: E402
    audit_raw_to_pnl_v1,
)
import collector_ordered_l1_bbo_change_v1 as producer_module  # noqa: E402


SECOND = 1_000_000_000
BASE_UTC_NS = 1_900_000_000 * SECOND
CONTRACT = "SHFE.rb2701"
DAY = "2030-03-17"
SESSION = "DAY"
SEGMENT = "day-am-1"
CODE_SHA = "a" * 40
SOURCE_SHA = "b" * 64


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def common_record(
    seq: int,
    monotonic_ns: int,
    *,
    provider_update_id: str | None = None,
    provider_update_id_semantics: str = "UNVERIFIED",
    within_batch_rank: int = 1,
) -> dict[str, object]:
    receive_utc_ns = BASE_UTC_NS + monotonic_ns
    return {
        "record_type": "QUOTE",
        "collector_generation": "generation-1",
        "collector_seq": seq,
        "clock_epoch": "clock-1",
        "segment_id": SEGMENT,
        "provider_delivery_semantics": "CALLBACK",
        "provider_batch_id": None,
        "within_batch_rank": within_batch_rank,
        "provider_update_id": provider_update_id,
        "provider_update_id_semantics": provider_update_id_semantics,
        "source_event_time_raw": f"fixture-{receive_utc_ns}",
        "source_event_utc_ns": receive_utc_ns - 1_000_000,
        "source_time_precision_ns": 1_000_000,
        "callback_entry_receive_utc_ns": receive_utc_ns,
        "callback_entry_receive_monotonic_ns": monotonic_ns,
        "clock_sample_id": f"clock-{seq}",
        "clock_sync_state": "SYNCED",
        "clock_offset_ns": 0,
        "clock_uncertainty_ns": 1_000_000,
        "product": "rb",
        "exact_contract": CONTRACT,
        "exchange": "SHFE",
        "official_trading_day": DAY,
        "session_family": SESSION,
    }


def quote_record(
    seq: int,
    seconds: str,
    *,
    bid: str = "100",
    bid_size: str = "10",
    ask: str = "101",
    ask_size: str = "10",
    provider_update_id: str | None = None,
    provider_update_id_semantics: str = "UNVERIFIED",
    duplicate_status: str = "NOT_CLASSIFIED",
    within_batch_rank: int = 1,
) -> dict[str, object]:
    monotonic_ns = int(Decimal(seconds) * SECOND)
    row = common_record(
        seq,
        monotonic_ns,
        provider_update_id=provider_update_id or f"provider-{seq}",
        provider_update_id_semantics=provider_update_id_semantics,
        within_batch_rank=within_batch_rank,
    )
    row.update(
        bid_price1_raw=bid,
        bid_size1_raw=bid_size,
        ask_price1_raw=ask,
        ask_size1_raw=ask_size,
        last_price_raw="100",
        cumulative_volume_raw=str(seq),
        cumulative_amount_raw=str(seq * 100),
        open_interest_raw="1000",
        parse_status="RAW_RETAINED",
        duplicate_status=duplicate_status,
        source_status="OBSERVED",
    )
    return row


def control_record(
    seq: int,
    seconds: str,
    event_type: str,
    *,
    scope: str,
) -> dict[str, object]:
    row = common_record(seq, int(Decimal(seconds) * SECOND))
    row["record_type"] = "CONTROL"
    row.update(
        event_type=event_type,
        reason=f"fixture-{event_type.lower()}",
        scope=scope,
    )
    return row


def frozen_scenarios() -> list[dict[str, object]]:
    common: dict[str, object] = {
        "horizon_ns": 30 * SECOND,
        "lots": 1,
        "min_side_size": "1",
        "exit_grace_ns": 5 * SECOND,
        "position_scope": "scenario_id×exact_contract",
        "event_order_version": "collector-callback-order-v1",
    }
    return [
        {
            "scenario_id": "PRIMARY",
            "entry_delay_ns": 500_000_000,
            "exit_delay_ns": 500_000_000,
            "adverse_ticks": 0,
            **common,
        },
        {
            "scenario_id": "STRESS",
            "entry_delay_ns": SECOND,
            "exit_delay_ns": SECOND,
            "adverse_ticks": 1,
            **common,
        },
    ]


def freeze_bundle(
    *,
    provider_status: str = "UNVERIFIED",
    provider_update_id_semantics: str = "UNVERIFIED",
) -> dict[str, object]:
    authority = {
        "authority": "fixture-authority",
        "source": "fixture-source",
        "version": "v1",
        "source_sha256": SOURCE_SHA,
    }
    valid = {
        "exact_contract": CONTRACT,
        "official_day": DAY,
        "valid_from_utc_ns": BASE_UTC_NS,
        "valid_until_utc_ns": BASE_UTC_NS + 200 * SECOND,
    }
    return {
        "schema_version": "issue488-raw-replay-v1",
        "research_line_id": RESEARCH_LINE_ID,
        "candidate_id": CANDIDATE_ID,
        "data_contract_id": DATA_CONTRACT_ID,
        "thresholds": [
            {
                "exact_contract": CONTRACT,
                "session_family": SESSION,
                "quantile": "0.95",
                "sample_count": 1000,
                "threshold": "0.1",
            }
        ],
        "scenarios": frozen_scenarios(),
        "instrument_terms": [
            {
                "binding_id": "terms-1",
                **valid,
                "tick_size": "1",
                "multiplier": "10",
                **authority,
            }
        ],
        "fee_schedules": [
            {
                "binding_id": f"fee-{offset}",
                **valid,
                "offset": offset,
                "fixed_cny": "1",
                "ratio_per_mille": "0",
                **authority,
            }
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        ],
        "broker_markups": [
            {
                "binding_id": f"markup-{offset}",
                **valid,
                "offset": offset,
                "fixed_cny": "0.5",
                "ratio_per_mille": "0",
                **authority,
            }
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        ],
        "coverage_plan": [
            {
                "exact_contract": CONTRACT,
                "official_day": DAY,
                "session_family": SESSION,
                "segment_id": SEGMENT,
                "start_utc_ns": BASE_UTC_NS + SECOND,
                "end_utc_ns": BASE_UTC_NS + 90 * SECOND,
                "days_to_ltd": 60,
                "eligible": True,
                "source": "fixture-schedule",
                "authority": "fixture-authority",
                "version": "v1",
                "source_sha256": SOURCE_SHA,
            }
        ],
        "provider_semantics": [
            {
                "provider_delivery_semantics": "CALLBACK",
                "provider_update_id_semantics": provider_update_id_semantics,
                "status": provider_status,
            }
        ],
    }


def lifecycle_rows(exit_mode: str = "normal") -> list[dict[str, object]]:
    rows = [
        control_record(1, "1", "COLLECTOR_START", scope="GENERATION_GLOBAL"),
        control_record(
            2,
            "1.5",
            "SESSION_SEGMENT_START",
            scope="EXACT_CONTRACT_SEGMENT",
        ),
        quote_record(3, "2", bid_size="10"),
    ]
    for index in range(1, 11):
        rows.append(
            quote_record(3 + index, str(2 + index), bid_size=str(10 + index))
        )
    if exit_mode == "no_entry":
        rows.append(quote_record(14, "13", bid_size="21", ask_size="0.5"))
        rows.extend(
            [
                control_record(
                    15,
                    "90",
                    "SESSION_SEGMENT_END",
                    scope="EXACT_CONTRACT_SEGMENT",
                ),
                control_record(
                    16,
                    "91",
                    "COLLECTOR_STOP",
                    scope="GENERATION_GLOBAL",
                ),
            ]
        )
        return rows
    rows.append(quote_record(14, "13", bid_size="21"))
    if exit_mode == "unpriced":
        rows.append(
            control_record(
                15,
                "91",
                "COLLECTOR_STOP",
                scope="GENERATION_GLOBAL",
            )
        )
        return rows
    if exit_mode == "timeout_no_horizon":
        rows.append(
            quote_record(
                15,
                "48.000000001",
                bid="105",
                bid_size="21",
                ask="106",
            )
        )
    elif exit_mode == "timeout_small_then_valid":
        rows.append(
            quote_record(
                15,
                "48.000000001",
                bid="105",
                bid_size="0.5",
                ask="106",
            )
        )
    else:
        rows.append(
            quote_record(
                15,
                "43",
                bid="105",
                bid_size="0.5" if exit_mode == "small_horizon" else "21",
                ask="106",
            )
        )
    if exit_mode == "normal":
        rows.extend(
            [
                quote_record(16, "43.5", bid="105", bid_size="21", ask="106"),
                quote_record(17, "44", bid="105", bid_size="21", ask="106"),
            ]
        )
    elif exit_mode == "exact_grace":
        rows.append(quote_record(16, "48", bid="105", bid_size="21", ask="106"))
    elif exit_mode == "timeout":
        rows.append(
            quote_record(
                16,
                "48.000000001",
                bid="105",
                bid_size="21",
                ask="106",
            )
        )
    elif exit_mode == "timeout_no_horizon":
        pass
    elif exit_mode == "small_horizon":
        rows.extend(
            [
                quote_record(16, "43.5", bid="105", bid_size="21", ask="106"),
                quote_record(17, "44", bid="105", bid_size="21", ask="106"),
            ]
        )
    elif exit_mode == "timeout_small_then_valid":
        rows.append(
            quote_record(16, "49", bid="105", bid_size="21", ask="106")
        )
    else:
        raise AssertionError(f"unsupported fixture exit mode: {exit_mode}")
    next_seq = rows[-1]["collector_seq"] + 1
    rows.extend(
        [
            control_record(
                next_seq,
                "90",
                "SESSION_SEGMENT_END",
                scope="EXACT_CONTRACT_SEGMENT",
            ),
            control_record(
                next_seq + 1,
                "91",
                "COLLECTOR_STOP",
                scope="GENERATION_GLOBAL",
            ),
        ]
    )
    return rows


def sealed_stream(tmp_path: Path, rows: list[dict[str, object]]):
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "custody"
    with CustodyJournal(
        root,
        run_id="run-1",
        partition_id="p-1",
        collector_generation="generation-1",
        code_sha=CODE_SHA,
    ) as journal:
        for row in rows:
            journal.append(row)
        head = journal.seal(closed_at_utc="2030-03-17T01:31:01Z")
    pins = pin_custody_root(root)
    return read_verified_custody_stream_v1(
        root,
        expected_root_pins=pins,
        trusted_head_partition_hash=head.partition_hash,
        trusted_head_seal_id=head.seal_id,
    )


def resign_single_partition(
    stream: VerifiedCustodyStream,
    mutate: object,
) -> tuple[list[dict[str, str]], str, str]:
    """Build a cryptographically self-consistent hostile auditor envelope."""

    envelope = dict(stream.partitions[0])
    rows = [
        json.loads(line) for line in envelope["raw_jsonl_utf8"].splitlines()
    ]
    mutate(rows)  # type: ignore[operator]
    previous: str | None = None
    for row in rows:
        row["prev_record_hash"] = previous
        unhashed = dict(row)
        unhashed.pop("record_hash", None)
        row["record_hash"] = sha256(unhashed)
        previous = row["record_hash"]
    raw_jsonl = "".join(
        canonical_bytes(row).decode("utf-8") + "\n" for row in rows
    )
    manifest = json.loads(envelope["manifest_json_utf8"])
    manifest.update(
        exact_bytes=len(raw_jsonl.encode("utf-8")),
        record_count=len(rows),
        first_record_hash=rows[0]["record_hash"],
        last_record_hash=rows[-1]["record_hash"],
        partition_hash=hashlib.sha256(raw_jsonl.encode("utf-8")).hexdigest(),
    )
    manifest_core = dict(manifest)
    manifest_core.pop("seal_id")
    manifest["seal_id"] = sha256(manifest_core)
    return (
        [
            {
                "manifest_json_utf8": canonical_bytes(manifest).decode("utf-8")
                + "\n",
                "raw_jsonl_utf8": raw_jsonl,
            }
        ],
        manifest["partition_hash"],
        manifest["seal_id"],
    )


def resign_manifest_fields(
    stream: VerifiedCustodyStream,
    updates: dict[str, object],
) -> tuple[list[dict[str, str]], str, str]:
    envelope = dict(stream.partitions[0])
    manifest = json.loads(envelope["manifest_json_utf8"])
    manifest.update(updates)
    core = dict(manifest)
    core.pop("seal_id")
    manifest["seal_id"] = sha256(core)
    return (
        [
            {
                "manifest_json_utf8": canonical_bytes(manifest).decode("utf-8")
                + "\n",
                "raw_jsonl_utf8": envelope["raw_jsonl_utf8"],
            }
        ],
        manifest["partition_hash"],
        manifest["seal_id"],
    )


def retarget_rows(
    rows: list[dict[str, object]],
    *,
    generation: str,
    segment: str,
    time_shift_ns: int,
    first_seq: int = 1,
) -> list[dict[str, object]]:
    """Create a custody-valid generation/segment fixture without new helpers."""

    result = deepcopy(rows)
    for index, row in enumerate(result, first_seq):
        row["collector_generation"] = generation
        row["collector_seq"] = index
        row["segment_id"] = segment
        row["clock_epoch"] = f"clock-{generation}"
        row["callback_entry_receive_monotonic_ns"] += time_shift_ns
        row["callback_entry_receive_utc_ns"] += time_shift_ns
        row["source_event_utc_ns"] += time_shift_ns
        row["source_event_time_raw"] = f"fixture-{row['source_event_utc_ns']}"
        row["clock_sample_id"] = f"clock-{generation}-{index}"
    return result


def sealed_generation_chain(
    tmp_path: Path,
    generations: list[list[dict[str, object]]],
):
    """Seal one partition per generation, preserving external custody anchors."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "custody"
    pins = None
    head = None
    for index, rows in enumerate(generations, 1):
        generation = str(rows[0]["collector_generation"])
        kwargs: dict[str, object] = {}
        if pins is not None and head is not None:
            kwargs.update(
                expected_root_pins=pins,
                expected_head_partition_hash=head.partition_hash,
                expected_head_seal_id=head.seal_id,
            )
        with CustodyJournal(
            root,
            run_id="run-1",
            partition_id=f"p-{index}",
            collector_generation=generation,
            code_sha=CODE_SHA,
            **kwargs,
        ) as journal:
            for row in rows:
                journal.append(row)
            head = journal.seal(closed_at_utc=f"2030-03-17T01:31:{index:02d}Z")
        pins = pin_custody_root(root)
    assert pins is not None and head is not None
    return read_verified_custody_stream_v1(
        root,
        expected_root_pins=pins,
        trusted_head_partition_hash=head.partition_hash,
        trusted_head_seal_id=head.seal_id,
    )


def add_plan_cell(
    freeze: dict[str, object],
    *,
    segment: str,
    start_utc_ns: int,
    end_utc_ns: int,
) -> None:
    freeze["coverage_plan"].append(
        {
            "exact_contract": CONTRACT,
            "official_day": DAY,
            "session_family": SESSION,
            "segment_id": segment,
            "start_utc_ns": start_utc_ns,
            "end_utc_ns": end_utc_ns,
            "days_to_ltd": 60,
            "eligible": True,
            "source": "fixture-schedule",
            "authority": "fixture-authority",
            "version": "v1",
            "source_sha256": SOURCE_SHA,
        }
    )


def resequence(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    for sequence, row in enumerate(rows, 1):
        row["collector_seq"] = sequence
        row["clock_sample_id"] = f"clock-{sequence}"
    return rows


def replay_fixture(tmp_path: Path, exit_mode: str = "normal"):
    stream = sealed_stream(tmp_path, lifecycle_rows(exit_mode))
    freeze = freeze_bundle(provider_status="PROVEN_NO_USABLE_ID")
    result = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    )
    return stream, freeze, result.to_bundle()


def audit_fixture(
    stream: VerifiedCustodyStream,
    freeze: dict[str, object],
    producer: dict[str, object],
) -> dict[str, object]:
    return audit_raw_to_pnl_v1(
        sealed_partitions=[dict(item) for item in stream.partitions],
        freeze_bundle=freeze,
        producer_bundle=producer,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    )


def test_multi_signal_replay_closes_primary_and_stress_deterministically(
    tmp_path: Path,
) -> None:
    stream, freeze, bundle = replay_fixture(tmp_path)
    repeated = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert repeated == bundle
    assert [row["status"] for row in bundle["attempts"]] == [
        "CLOSED_NORMAL",
        "CLOSED_NORMAL",
    ]
    assert {row["scenario_id"] for row in bundle["trades"]} == {
        "PRIMARY",
        "STRESS",
    }
    assert [row["decision"] for row in bundle["admissions"]].count("ADMITTED") == 2
    assert [row["decision"] for row in bundle["admissions"]].count("SUPPRESSED") == 2
    assert all(row["all_attempts_resolved"] for row in bundle["coverage"])
    assert all(row["all_attempts_priced"] for row in bundle["coverage"])
    assert all(row["lifecycle_gate_passed"] for row in bundle["coverage"])
    assert all(not row["quality_gate_passed"] for row in bundle["coverage"])
    assert all(not row["data_gate_passed"] for row in bundle["coverage"])
    assert all(row["entry"]["quote"]["provider_update_id"] for row in bundle["trades"])


@pytest.mark.parametrize(
    ("exit_mode", "status", "priced", "gate"),
    [
        ("exact_grace", "CLOSED_NORMAL", True, False),
        ("timeout", "CLOSED_TERMINAL_TIMEOUT", True, False),
        ("timeout_no_horizon", "CLOSED_TERMINAL_TIMEOUT", True, False),
        ("timeout_small_then_valid", "CLOSED_TERMINAL_TIMEOUT", True, False),
        ("small_horizon", "CLOSED_NORMAL", True, False),
        ("no_entry", "FAILED_NO_ENTRY", True, False),
        ("unpriced", "UNPRICED_TERMINAL", False, False),
    ],
)
def test_replay_terminal_boundaries_are_explicit_and_fail_closed(
    tmp_path: Path,
    exit_mode: str,
    status: str,
    priced: bool,
    gate: bool,
) -> None:
    _, _, bundle = replay_fixture(tmp_path, exit_mode)

    assert {row["status"] for row in bundle["attempts"]} == {status}
    assert all(row["all_attempts_priced"] is priced for row in bundle["coverage"])
    assert all(row["data_gate_passed"] is gate for row in bundle["coverage"])
    if status == "UNPRICED_TERMINAL":
        assert not bundle["trades"]
        assert all(row["entry_raw_record_hash"] for row in bundle["attempts"])
        assert all(row["terminal_position_lots"] != 0 for row in bundle["attempts"])
    else:
        assert all(row["terminal_position_lots"] == 0 for row in bundle["attempts"])


def test_accounting_failure_retains_exit_evidence_and_stops_with_residual(
    tmp_path: Path,
) -> None:
    stream = sealed_stream(tmp_path, lifecycle_rows())
    freeze = freeze_bundle()
    for section in ("instrument_terms", "fee_schedules", "broker_markups"):
        for binding in freeze[section]:
            binding["valid_until_utc_ns"] = BASE_UTC_NS + 20 * SECOND

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    attempts = bundle["attempts"]
    accounting_failure = next(
        row for row in attempts
        if str(row["terminal_reason"]).startswith("ACCOUNTING:")
    )
    assert accounting_failure["status"] == "UNPRICED_TERMINAL"
    assert accounting_failure["exit_raw_record_hash"]
    assert accounting_failure["terminal_position_lots"] != 0
    assert not bundle["trades"]
    assert all(not row["data_gate_passed"] for row in bundle["coverage"])


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"clock_sync_state": "UNSYNCED"}, "synced clock"),
        ({"clock_offset_ns": 100_000_001}, "offset is too large"),
        ({"clock_uncertainty_ns": 25_000_001}, "uncertainty is too large"),
        ({"source_time_precision_ns": 1_000_001}, "source time is too coarse"),
    ],
)
def test_economic_replay_rejects_row_level_clock_defects_before_state(
    tmp_path: Path,
    updates: dict[str, object],
    message: str,
) -> None:
    rows = lifecycle_rows()
    next(row for row in rows if row["record_type"] == "QUOTE").update(updates)
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    with pytest.raises(BBOChangeContractError, match=message):
        replay_multi_signal_raw_v1(
            stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(freeze),
        )


def test_economic_replay_rejects_negative_corrected_lag_before_state(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows()
    quote = next(row for row in rows if row["record_type"] == "QUOTE")
    quote["source_event_utc_ns"] = quote["callback_entry_receive_utc_ns"] + 1
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    with pytest.raises(BBOChangeContractError, match="corrected lag is negative"):
        replay_multi_signal_raw_v1(
            stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(freeze),
        )


def test_freeze_anchor_is_checked_before_any_replay_economics(tmp_path: Path) -> None:
    stream = sealed_stream(tmp_path, lifecycle_rows())
    freeze = freeze_bundle()
    trusted = sha256(freeze)
    tampered = deepcopy(freeze)
    tampered["thresholds"][0]["threshold"] = "0.2"

    with pytest.raises(BBOChangeContractError, match="freeze SHA-256 anchor"):
        replay_multi_signal_raw_v1(
            stream,
            tampered,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=trusted,
        )


def test_fully_resigned_stream_cannot_replace_external_terminal_anchors(
    tmp_path: Path,
) -> None:
    stream = sealed_stream(tmp_path, lifecycle_rows())
    envelope = dict(stream.partitions[0])
    rows = [
        json.loads(line)
        for line in envelope["raw_jsonl_utf8"].splitlines()
    ]
    first_quote = next(row for row in rows if row["record_type"] == "QUOTE")
    first_quote["bid_price1_raw"] = "99"
    previous: str | None = None
    for row in rows:
        row["prev_record_hash"] = previous
        unhashed = dict(row)
        unhashed.pop("record_hash", None)
        row["record_hash"] = sha256(unhashed)
        previous = row["record_hash"]
    raw_jsonl = "".join(
        canonical_bytes(row).decode("utf-8") + "\n" for row in rows
    )
    manifest = json.loads(envelope["manifest_json_utf8"])
    manifest.update(
        exact_bytes=len(raw_jsonl.encode("utf-8")),
        first_record_hash=rows[0]["record_hash"],
        last_record_hash=rows[-1]["record_hash"],
        partition_hash=hashlib.sha256(raw_jsonl.encode("utf-8")).hexdigest(),
    )
    manifest_core = dict(manifest)
    manifest_core.pop("seal_id")
    manifest["seal_id"] = sha256(manifest_core)
    forged = VerifiedCustodyStream(
        stream.root_pins,
        manifest["partition_hash"],
        manifest["seal_id"],
        (
            {
                "manifest_json_utf8": canonical_bytes(manifest).decode("utf-8")
                + "\n",
                "raw_jsonl_utf8": raw_jsonl,
            },
        ),
        tuple(rows),
    )
    freeze = freeze_bundle()

    with pytest.raises(BBOChangeContractError, match="forged"):
        replay_multi_signal_raw_v1(
            forged,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(freeze),
        )


def test_unverified_repeated_provider_id_is_retained_not_deduplicated(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows()
    quotes = [row for row in rows if row["record_type"] == "QUOTE"]
    quotes[0]["provider_update_id"] = "unverified-repeat"
    quotes[1]["provider_update_id"] = "unverified-repeat"
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert all(
        "DUPLICATE_SKIPPED" not in row["actions"]
        for row in bundle["callback_trace"]
    )


def test_zero_attempt_plan_cells_still_emit_reconciled_coverage(tmp_path: Path) -> None:
    stream = sealed_stream(tmp_path, lifecycle_rows())
    freeze = freeze_bundle()
    freeze["thresholds"][0]["threshold"] = "100"

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert bundle["attempts"] == []
    assert len(bundle["coverage"]) == 2
    assert {row["scenario_id"] for row in bundle["coverage"]} == {
        "PRIMARY",
        "STRESS",
    }
    assert all(row["admitted_count"] == 0 for row in bundle["coverage"])
    assert all(row["resolved_attempt_count"] == 0 for row in bundle["coverage"])
    assert all(row["all_attempts_resolved"] for row in bundle["coverage"])
    assert all(row["lifecycle_gate_passed"] for row in bundle["coverage"])
    assert all(not row["quality_gate_passed"] for row in bundle["coverage"])
    assert all(not row["data_gate_passed"] for row in bundle["coverage"])


def test_proven_unique_nonadjacent_exact_payload_is_skipped(tmp_path: Path) -> None:
    rows = lifecycle_rows()
    for row in rows:
        if row["record_type"] == "QUOTE":
            row["provider_update_id_semantics"] = "GLOBAL_UNIQUE"
    quote_positions = [
        index for index, row in enumerate(rows) if row["record_type"] == "QUOTE"
    ]
    original = rows[quote_positions[1]]
    duplicate = deepcopy(original)
    duplicate["callback_entry_receive_monotonic_ns"] = int(Decimal("4.5") * SECOND)
    duplicate["callback_entry_receive_utc_ns"] = BASE_UTC_NS + int(
        Decimal("4.5") * SECOND
    )
    duplicate["clock_sample_id"] = "clock-nonadjacent-duplicate"
    rows.insert(quote_positions[2] + 1, duplicate)
    for seq, row in enumerate(rows, 1):
        row["collector_seq"] = seq
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle(
        provider_status="PROVEN_UNIQUE",
        provider_update_id_semantics="GLOBAL_UNIQUE",
    )

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert sum(
        "DUPLICATE_SKIPPED" in row["actions"]
        for row in bundle["callback_trace"]
    ) == 1


def test_proven_unique_conflict_and_unverified_marker_abort_before_pnl(
    tmp_path: Path,
) -> None:
    conflict_rows = lifecycle_rows()
    conflict_quotes = [
        row for row in conflict_rows if row["record_type"] == "QUOTE"
    ]
    for row in conflict_rows:
        if row["record_type"] == "QUOTE":
            row["provider_update_id_semantics"] = "GLOBAL_UNIQUE"
    conflict_quotes[0]["provider_update_id"] = "conflict"
    conflict_quotes[1]["provider_update_id"] = "conflict"
    conflict_stream = sealed_stream(tmp_path / "conflict", conflict_rows)
    proven = freeze_bundle(
        provider_status="PROVEN_UNIQUE",
        provider_update_id_semantics="GLOBAL_UNIQUE",
    )
    with pytest.raises(BBOChangeContractError, match="conflicting payload"):
        replay_multi_signal_raw_v1(
            conflict_stream,
            proven,
            expected_root_pins=conflict_stream.root_pins,
            trusted_head_partition_hash=conflict_stream.terminal_partition_hash,
            trusted_head_seal_id=conflict_stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(proven),
        )

    marker_rows = lifecycle_rows()
    next(row for row in marker_rows if row["record_type"] == "QUOTE")[
        "duplicate_status"
    ] = "PROVEN_ADJACENT_EXACT_DUPLICATE"
    marker_stream = sealed_stream(tmp_path / "marker", marker_rows)
    unverified = freeze_bundle()
    with pytest.raises(BBOChangeContractError, match="requires PROVEN_UNIQUE"):
        replay_multi_signal_raw_v1(
            marker_stream,
            unverified,
            expected_root_pins=marker_stream.root_pins,
            trusted_head_partition_hash=marker_stream.terminal_partition_hash,
            trusted_head_seal_id=marker_stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(unverified),
        )


def test_replay_admission_and_attempt_ids_are_generation_scoped_and_unique(
    tmp_path: Path,
) -> None:
    first = retarget_rows(
        lifecycle_rows(),
        generation="generation-1",
        segment="day-am-1",
        time_shift_ns=0,
    )
    second = retarget_rows(
        lifecycle_rows(),
        generation="generation-2",
        segment="day-pm-1",
        time_shift_ns=100 * SECOND,
    )
    stream = sealed_generation_chain(tmp_path, [first, second])
    freeze = freeze_bundle()
    add_plan_cell(
        freeze,
        segment="day-pm-1",
        start_utc_ns=BASE_UTC_NS + 101 * SECOND,
        end_utc_ns=BASE_UTC_NS + 190 * SECOND,
    )

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    admitted = [row for row in bundle["admissions"] if row["decision"] == "ADMITTED"]
    assert {row["collector_generation"] for row in admitted} == {
        "generation-1",
        "generation-2",
    }
    assert len({row["accepted_trade_id"] for row in admitted}) == len(admitted)
    assert len({row["attempt_id"] for row in bundle["attempts"]}) == len(
        bundle["attempts"]
    )


def test_global_stop_marks_later_complete_plan_cell_not_replay_complete(
    tmp_path: Path,
) -> None:
    first = lifecycle_rows("unpriced")
    first[-1].update(
        event_type="SESSION_SEGMENT_END", scope="EXACT_CONTRACT_SEGMENT"
    )
    second = retarget_rows(
        lifecycle_rows()[1:],
        generation="generation-1",
        segment="day-pm-1",
        time_shift_ns=100 * SECOND,
        first_seq=len(first) + 1,
    )
    stream = sealed_stream(tmp_path, first + second)
    freeze = freeze_bundle()
    add_plan_cell(
        freeze,
        segment="day-pm-1",
        start_utc_ns=BASE_UTC_NS + 101 * SECOND,
        end_utc_ns=BASE_UTC_NS + 190 * SECOND,
    )

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    later = [row for row in bundle["coverage"] if row["segment_id"] == "day-pm-1"]
    assert len(later) == 2
    assert all(row["raw_quote_count"] > 0 for row in later)
    assert all(not row["data_gate_passed"] for row in later)


@pytest.mark.parametrize("event", ["DISCONNECT", "CLOCK_EPOCH_CHANGE"])
def test_in_segment_lifecycle_disruption_blocks_data_gate(
    tmp_path: Path, event: str
) -> None:
    rows = lifecycle_rows()
    disruption = control_record(0, "5.25", event, scope="GENERATION_GLOBAL")
    rows.insert(6, disruption)
    if event == "DISCONNECT":
        rows.insert(7, control_record(0, "5.5", "RECONNECT", scope="GENERATION_GLOBAL"))
    else:
        disruption["clock_epoch"] = "clock-2"
        for row in rows[7:]:
            row["clock_epoch"] = "clock-2"
    stream = sealed_stream(tmp_path, resequence(rows))
    freeze = freeze_bundle()

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert all(not row["lifecycle_gate_passed"] for row in bundle["coverage"])
    assert all(not row["data_gate_passed"] for row in bundle["coverage"])


def test_global_disconnect_after_segment_end_does_not_taint_closed_cell(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows()
    rows.insert(
        -1,
        control_record(0, "90.5", "DISCONNECT", scope="GENERATION_GLOBAL"),
    )
    stream = sealed_stream(tmp_path, resequence(rows))
    freeze = freeze_bundle()

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    assert all(row["lifecycle_gate_passed"] for row in bundle["coverage"])
    assert all(not row["quality_gate_passed"] for row in bundle["coverage"])
    assert all(not row["data_gate_passed"] for row in bundle["coverage"])


def normative_quality_rows() -> list[dict[str, object]]:
    rows = [
        control_record(1, "1", "COLLECTOR_START", scope="GENERATION_GLOBAL"),
        control_record(
            2,
            "1.5",
            "SESSION_SEGMENT_START",
            scope="EXACT_CONTRACT_SEGMENT",
        ),
    ]
    for index in range(5_001):
        seconds = f"{2 + index // 10_000}.{index % 10_000:04d}"
        rows.append(
            quote_record(
                3 + index,
                seconds,
                bid=str(100 + index % 2),
                ask=str(103 + index % 2),
                bid_size=str(index % 25 + 1),
                ask_size=str((index + 1) % 25 + 1),
            )
        )
    rows.extend(
        [
            control_record(
                5_004,
                "90",
                "SESSION_SEGMENT_END",
                scope="EXACT_CONTRACT_SEGMENT",
            ),
            control_record(
                5_005,
                "91",
                "COLLECTOR_STOP",
                scope="GENERATION_GLOBAL",
            ),
        ]
    )
    return rows


def test_normative_quality_denominators_pass_and_auditor_matches(
    tmp_path: Path,
) -> None:
    rows = normative_quality_rows()
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle(provider_status="PROVEN_NO_USABLE_ID")
    freeze["thresholds"][0]["threshold"] = "1000000000000"
    producer = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    audit = audit_fixture(stream, freeze, producer)

    assert audit["audit_status"] == "MATCH"
    assert audit["holdout_gate"] == "BLOCKED"
    for row in producer["coverage"]:
        assert row["raw_quote_count"] == 5_001
        assert row["legal_bbo_count"] == 5_001
        assert row["legal_bbo_rate"] == "1"
        assert row["distinct_positive_bid_sizes"] == 25
        assert row["distinct_positive_ask_sizes"] == 25
        assert row["mirrored_size_count"] == 0
        assert row["mirrored_size_ratio"] == "0"
        assert row["crossed_or_locked_count"] == 0
        assert row["crossed_or_locked_rate"] == "0"
        assert row["state_changing_observation_count"] == 5_000
        assert row["mid_change_count"] == 5_000
        assert row["lifecycle_gate_passed"] is True
        assert row["clock_epoch_gate_passed"] is True
        assert row["coverage_plan_gate_passed"] is True
        assert row["threshold_gate_passed"] is True
        assert row["accounting_binding_gate_passed"] is True
        assert row["provider_semantics_gate_passed"] is True
        assert row["quote_interval_gate_passed"] is True
        assert row["entry_window_gate_passed"] is True
        assert row["quality_gate_passed"] is True
        assert row["data_gate_passed"] is True


@pytest.mark.parametrize(
    "case",
    [
        "ineligible_plan",
        "short_ltd",
        "quote_outside_interval",
        "no_entry_window",
        "silent_epoch_change",
        "missing_threshold",
        "missing_accounting_binding",
        "overlapping_accounting_binding",
        "unverified_provider",
    ],
)
def test_quality_pass_cannot_bypass_plan_or_epoch_gates(
    tmp_path: Path,
    case: str,
) -> None:
    rows = normative_quality_rows()
    freeze = freeze_bundle(provider_status="PROVEN_NO_USABLE_ID")
    freeze["thresholds"][0]["threshold"] = "1000000000000"
    if case == "ineligible_plan":
        freeze["coverage_plan"][0]["eligible"] = False
    elif case == "short_ltd":
        freeze["coverage_plan"][0]["days_to_ltd"] = 10
    elif case == "quote_outside_interval":
        freeze["coverage_plan"][0]["start_utc_ns"] = (
            BASE_UTC_NS + 2_100_000_000
        )
    elif case == "no_entry_window":
        freeze["coverage_plan"][0]["end_utc_ns"] = BASE_UTC_NS + 50 * SECOND
    elif case == "silent_epoch_change":
        for row in rows:
            if row["record_type"] == "QUOTE":
                row["clock_epoch"] = "clock-2"
    elif case == "missing_threshold":
        freeze["thresholds"][0]["exact_contract"] = "DCE.i2701"
    elif case == "missing_accounting_binding":
        freeze["instrument_terms"] = []
    elif case == "overlapping_accounting_binding":
        for section in (
            "instrument_terms",
            "fee_schedules",
            "broker_markups",
        ):
            overlap = deepcopy(freeze[section][0])
            overlap["binding_id"] = f"overlap-{section}"
            overlap["valid_from_utc_ns"] = BASE_UTC_NS + 20 * SECOND
            overlap["valid_until_utc_ns"] = BASE_UTC_NS + 30 * SECOND
            freeze[section].append(overlap)
    else:
        freeze["provider_semantics"][0]["status"] = "UNVERIFIED"
    stream = sealed_stream(tmp_path, rows)
    producer = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()
    audit = audit_fixture(stream, freeze, producer)

    assert audit["audit_status"] == "MATCH"
    assert audit["holdout_gate"] == "FAIL_CLOSED"
    assert all(row["quality_gate_passed"] for row in producer["coverage"])
    assert all(not row["data_gate_passed"] for row in producer["coverage"])
    if case in {"ineligible_plan", "short_ltd"}:
        assert all(
            not row["coverage_plan_gate_passed"]
            for row in producer["coverage"]
        )
    elif case == "quote_outside_interval":
        assert all(
            not row["quote_interval_gate_passed"]
            for row in producer["coverage"]
        )
    elif case == "no_entry_window":
        assert all(
            not row["entry_window_gate_passed"]
            for row in producer["coverage"]
        )
    elif case == "silent_epoch_change":
        assert all(
            not row["clock_epoch_gate_passed"]
            and not row["lifecycle_gate_passed"]
            for row in producer["coverage"]
        )
    elif case == "missing_threshold":
        assert all(
            not row["threshold_gate_passed"] for row in producer["coverage"]
        )
    elif case in {
        "missing_accounting_binding",
        "overlapping_accounting_binding",
    }:
        assert all(
            not row["accounting_binding_gate_passed"]
            for row in producer["coverage"]
        )
    else:
        assert all(
            not row["provider_semantics_gate_passed"]
            for row in producer["coverage"]
        )


def test_crossed_rate_counts_rows_even_when_sizes_are_invalid(
    tmp_path: Path,
) -> None:
    rows = normative_quality_rows()
    crossed = [
        quote_record(
            0,
            f"3.000{index}",
            bid="105",
            ask="104",
            bid_size="BAD",
            ask_size="1",
        )
        for index in range(1, 7)
    ]
    rows[-2:-2] = crossed
    rows = resequence(rows)
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle(provider_status="PROVEN_NO_USABLE_ID")
    freeze["thresholds"][0]["threshold"] = "1000000000000"
    producer = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()
    audit = audit_fixture(stream, freeze, producer)

    assert audit["audit_status"] == "MATCH"
    with localcontext() as context:
        context.prec = 50
        expected_rate = format(Decimal(6) / Decimal(5_007), "f")
    for row in producer["coverage"]:
        assert row["raw_quote_count"] == 5_007
        assert row["legal_bbo_count"] == 5_001
        assert row["crossed_or_locked_count"] == 6
        assert row["crossed_or_locked_rate"] == expected_rate
        assert row["quality_gate_passed"] is False
        assert row["data_gate_passed"] is False


def test_independent_auditor_matches_normal_replay_deterministically(
    tmp_path: Path,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)

    first = audit_fixture(stream, freeze, producer)
    second = audit_fixture(stream, freeze, producer)

    assert first == second
    assert first["audit_status"] == "MATCH"
    assert first["holdout_gate"] == "FAIL_CLOSED"
    assert first["counts"]["mismatch_count"] == 0
    assert all(row["lifecycle_gate_passed"] for row in producer["coverage"])
    assert all(not row["quality_gate_passed"] for row in producer["coverage"])
    assert all(not row["data_gate_passed"] for row in producer["coverage"])
    assert first["independence"] == {
        "stdlib_only": True,
        "project_local_import_count": 0,
        "producer_values_used_for_recalculation": False,
        "input_json_primitives_only": True,
    }
    assert first["report_sha256"] == sha256(
        {key: value for key, value in first.items() if key != "report_sha256"}
    )


def test_independent_auditor_reports_producer_mismatch(tmp_path: Path) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    tampered = deepcopy(producer)
    tampered["attempts"][0]["terminal_reason"] = "forged"

    report = audit_fixture(stream, freeze, tampered)

    assert report["audit_status"] == "MISMATCH"
    assert report["counts"]["mismatch_count"] > 0
    assert any(row["collection"] == "attempts" for row in report["mismatches"])
    assert report["holdout_gate"] == "FAIL_CLOSED"


def test_independent_auditor_rejects_freeze_anchor_tamper(
    tmp_path: Path,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    trusted_freeze_sha256 = sha256(freeze)
    freeze["thresholds"][0]["threshold"] = "9"

    report = audit_raw_to_pnl_v1(
        sealed_partitions=[dict(item) for item in stream.partitions],
        freeze_bundle=freeze,
        producer_bundle=producer,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=trusted_freeze_sha256,
    )

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == "FREEZE_HASH_MISMATCH"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("quantile", "0.94"),
        ("sample_count", 999),
        ("threshold", "0"),
        ("threshold", "NaN"),
    ],
)
def test_independent_auditor_requires_exact_frozen_q95_threshold(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    freeze["thresholds"][0][field] = value

    report = audit_fixture(stream, freeze, producer)

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["holdout_gate"] == "FAIL_CLOSED"
    assert report["mismatches"][0]["kind"] in {
        "INVALID_DECIMAL",
        "THRESHOLD_NOT_FROZEN",
    }


def test_freeze_coverage_rows_reject_extra_fields_in_producer_and_auditor(
    tmp_path: Path,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    freeze["coverage_plan"][0]["smuggled"] = "value"
    trusted_freeze = sha256(freeze)

    with pytest.raises(BBOChangeContractError, match="coverage plan row is not exact"):
        replay_multi_signal_raw_v1(
            stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=trusted_freeze,
        )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=[dict(item) for item in stream.partitions],
        freeze_bundle=freeze,
        producer_bundle=producer,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=trusted_freeze,
    )
    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == "SCHEMA_KEYS"


def test_independent_auditor_rejects_sealed_raw_byte_tamper(
    tmp_path: Path,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    sealed = [dict(item) for item in stream.partitions]
    original = sealed[0]["raw_jsonl_utf8"]
    sealed[0]["raw_jsonl_utf8"] = original.replace(
        '"bid_price1_raw":"100"', '"bid_price1_raw":"999"', 1
    )
    assert sealed[0]["raw_jsonl_utf8"] != original

    report = audit_raw_to_pnl_v1(
        sealed_partitions=sealed,
        freeze_bundle=freeze,
        producer_bundle=producer,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    )

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] in {
        "PARTITION_BYTE_COUNT_MISMATCH",
        "PARTITION_HASH_MISMATCH",
        "RAW_RECORD_HASH_MISMATCH",
    }


@pytest.mark.parametrize(
    ("field", "value", "auditor_kind"),
    [
        (
            "closed_at_utc",
            " 2030-03-17T01:31:01Z ",
            "INVALID_TEXT",
        ),
        ("code_sha", f" {CODE_SHA} ", "INVALID_TEXT"),
        ("closed_at_utc", "x" * 1_049_000, "MANIFEST_TOO_LARGE"),
    ],
)
def test_resigned_manifest_cannot_bypass_canonical_or_size_limits(
    tmp_path: Path,
    field: str,
    value: str,
    auditor_kind: str,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    sealed, trusted_hash, trusted_seal = resign_manifest_fields(
        stream, {field: value}
    )
    forged_stream = VerifiedCustodyStream(
        stream.root_pins,
        trusted_hash,
        trusted_seal,
        tuple(sealed),
        stream.rows,
    )

    with pytest.raises(BBOChangeContractError):
        replay_multi_signal_raw_v1(
            forged_stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=trusted_hash,
            trusted_head_seal_id=trusted_seal,
            trusted_freeze_sha256=sha256(freeze),
        )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=sealed,
        freeze_bundle=freeze,
        producer_bundle=producer,
        trusted_head_partition_hash=trusted_hash,
        trusted_head_seal_id=trusted_seal,
        trusted_freeze_sha256=sha256(freeze),
    )
    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == auditor_kind


def test_independent_auditor_eagerly_rejects_stop_suffix_schema_smuggle(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows("unpriced")
    suffix = quote_record(16, "92")
    rows.append(suffix)
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()
    sealed, trusted_hash, trusted_seal = resign_single_partition(
        stream,
        lambda raw_rows: raw_rows[-1].__setitem__(
            "bid_price1_raw", ["not-a-retained-scalar"]
        ),
    )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=sealed,
        freeze_bundle=freeze,
        producer_bundle={},
        trusted_head_partition_hash=trusted_hash,
        trusted_head_seal_id=trusted_seal,
        trusted_freeze_sha256=sha256(freeze),
    )

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["holdout_gate"] == "FAIL_CLOSED"
    assert report["mismatches"][0]["kind"] == "RAW_BBO_TYPE"


def test_complete_stream_preflight_rejects_record_after_collector_stop(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows("unpriced")
    rows.append(quote_record(16, "92"))
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    with pytest.raises(BBOChangeContractError, match="after terminal"):
        replay_multi_signal_raw_v1(
            stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(freeze),
        )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=[dict(item) for item in stream.partitions],
        freeze_bundle=freeze,
        producer_bundle={},
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    )
    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == "RECORD_AFTER_TERMINAL_CONTROL"


def test_complete_stream_preflight_rejects_unprocessed_duplicate_marker(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows("unpriced")
    rows[-1].update(
        event_type="SESSION_SEGMENT_END",
        scope="EXACT_CONTRACT_SEGMENT",
    )
    rows.extend(
        [
            quote_record(
                16,
                "92",
                duplicate_status="PROVEN_ADJACENT_EXACT_DUPLICATE",
            ),
            control_record(
                17,
                "93",
                "COLLECTOR_STOP",
                scope="GENERATION_GLOBAL",
            ),
        ]
    )
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    with pytest.raises(BBOChangeContractError, match="PROVEN_UNIQUE"):
        replay_multi_signal_raw_v1(
            stream,
            freeze,
            expected_root_pins=stream.root_pins,
            trusted_head_partition_hash=stream.terminal_partition_hash,
            trusted_head_seal_id=stream.terminal_seal_id,
            trusted_freeze_sha256=sha256(freeze),
        )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=[dict(item) for item in stream.partitions],
        freeze_bundle=freeze,
        producer_bundle={},
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    )
    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == (
        "UNPROVEN_DUPLICATE_CLASSIFICATION"
    )


@pytest.mark.parametrize(
    "case",
    [
        "reason_whitespace",
        "segment_contract_whitespace",
        "clock_epoch_whitespace",
        "zero_monotonic",
        "auxiliary_float",
    ],
)
def test_custody_writer_rejects_raw_schema_smuggling(
    tmp_path: Path,
    case: str,
) -> None:
    rows = lifecycle_rows()
    if case == "reason_whitespace":
        rows[0]["reason"] = " fixture-collector-start "
    elif case == "segment_contract_whitespace":
        rows[1]["exact_contract"] = f" {CONTRACT} "
    elif case == "clock_epoch_whitespace":
        rows[0]["clock_epoch"] = " clock-1 "
    elif case == "zero_monotonic":
        rows[0]["callback_entry_receive_monotonic_ns"] = 0
    else:
        next(row for row in rows if row["record_type"] == "QUOTE")[
            "last_price_raw"
        ] = 100.5

    with pytest.raises(BBOChangeContractError):
        sealed_stream(tmp_path, rows)


def test_auditor_rejects_resigned_noncanonical_control(
    tmp_path: Path,
) -> None:
    stream, freeze, _ = replay_fixture(tmp_path)
    sealed, trusted_hash, trusted_seal = resign_single_partition(
        stream,
        lambda raw_rows: raw_rows[0].__setitem__(
            "reason", " fixture-collector-start "
        ),
    )

    report = audit_raw_to_pnl_v1(
        sealed_partitions=sealed,
        freeze_bundle=freeze,
        producer_bundle={},
        trusted_head_partition_hash=trusted_hash,
        trusted_head_seal_id=trusted_seal,
        trusted_freeze_sha256=sha256(freeze),
    )

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == "INVALID_TEXT"


def test_independent_auditor_rejects_non_json_values(tmp_path: Path) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)
    producer["not_json"] = Decimal("1.5")

    report = audit_fixture(stream, freeze, producer)

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["collection"] == "input"


def test_independent_auditor_hard_rejects_clock_defect(
    tmp_path: Path,
) -> None:
    normal_stream, freeze, producer = replay_fixture(tmp_path / "normal")
    del normal_stream
    rows = lifecycle_rows()
    next(row for row in rows if row["record_type"] == "QUOTE")[
        "clock_sync_state"
    ] = "UNSYNCED"
    invalid_stream = sealed_stream(tmp_path / "invalid", rows)

    report = audit_fixture(invalid_stream, freeze, producer)

    assert report["audit_status"] == "INVALID_INPUT"
    assert report["mismatches"][0]["kind"] == "CLOCK_GATE_FAILED"


def test_independent_auditor_has_only_stdlib_imports() -> None:
    source = (
        ROOT / "scripts/collector_ordered_l1_bbo_change_auditor_v1.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed = {
        "__future__", "collections", "dataclasses", "datetime", "decimal",
        "hashlib", "json", "typing",
    }
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.split(".", 1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.level == 0
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots <= allowed
    assert "collector_ordered_l1_bbo_change_v1" not in source
    assert "collector_ordered_l1_bbo_change_accounting_v1" not in source


def test_independent_auditor_does_not_call_producer_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stream, freeze, producer = replay_fixture(tmp_path)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("auditor imported or called producer replay")

    monkeypatch.setattr(producer_module, "replay_multi_signal_raw_v1", forbidden)

    assert audit_fixture(stream, freeze, producer)["audit_status"] == "MATCH"


def test_sealed_end_uses_own_generation_seq_and_has_no_callback_evidence(
    tmp_path: Path,
) -> None:
    """A low-seq final generation must not inherit the prior generation tail."""

    first = lifecycle_rows()
    first[-2] = control_record(
        0, "190", "SESSION_SEGMENT_END", scope="EXACT_CONTRACT_SEGMENT"
    )
    first[-1] = control_record(
        0, "191", "COLLECTOR_STOP", scope="GENERATION_GLOBAL"
    )
    first[-2]["collector_generation"] = "generation-1"
    first[-1]["collector_generation"] = "generation-1"
    for seconds in range(45, 145):
        first.insert(
            -2,
            quote_record(0, str(seconds), bid_size="0", ask_size="10"),
        )
    first = retarget_rows(
        resequence(first),
        generation="generation-1",
        segment="day-am-1",
        time_shift_ns=0,
    )
    second = retarget_rows(
        lifecycle_rows()[:14],
        generation="generation-2",
        segment="day-pm-1",
        time_shift_ns=0,
    )
    assert first[-1]["collector_seq"] > 100
    assert second[-1]["collector_seq"] < 20
    stream = sealed_generation_chain(tmp_path, [first, second])
    freeze = freeze_bundle()
    freeze["coverage_plan"][0]["end_utc_ns"] = BASE_UTC_NS + 200 * SECOND
    add_plan_cell(
        freeze,
        segment="day-pm-1",
        start_utc_ns=BASE_UTC_NS + SECOND,
        end_utc_ns=BASE_UTC_NS + 90 * SECOND,
    )

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()

    sealed_end = [
        row
        for row in bundle["attempts"]
        if row["collector_generation"] == "generation-2"
        and row["terminal_boundary_kind"] == "SEALED_STREAM_END"
    ]
    assert sealed_end
    assert {row["status"] for row in sealed_end} <= {
        "FAILED_NO_ENTRY",
        "UNPRICED_TERMINAL",
    }
    assert all(row["terminal_callback_seq"] is None for row in sealed_end)
    assert all(row["terminal_raw_record_hash"] is None for row in sealed_end)


def test_exit_requires_fresh_source_high_water_and_auditor_matches(
    tmp_path: Path,
) -> None:
    rows = lifecycle_rows()
    quotes = [row for row in rows if row["record_type"] == "QUOTE"]
    for source, row in enumerate(quotes[:11], 1):
        row["source_event_utc_ns"] = source
        row["source_event_time_raw"] = f"fixture-source-{source}"
    entry, pre_horizon, regressed_exit, fresh_exit = quotes[11:15]
    for source, row in (
        (100, entry),
        (200, pre_horizon),
        (150, regressed_exit),
        (200, fresh_exit),
    ):
        row["source_event_utc_ns"] = source
        row["source_event_time_raw"] = f"fixture-source-{source}"
    stream = sealed_stream(tmp_path, rows)
    freeze = freeze_bundle()

    bundle = replay_multi_signal_raw_v1(
        stream,
        freeze,
        expected_root_pins=stream.root_pins,
        trusted_head_partition_hash=stream.terminal_partition_hash,
        trusted_head_seal_id=stream.terminal_seal_id,
        trusted_freeze_sha256=sha256(freeze),
    ).to_bundle()
    audit = audit_fixture(stream, freeze, bundle)
    fresh_hash = next(
        row["record_hash"]
        for row in stream.rows
        if row["collector_seq"] == fresh_exit["collector_seq"]
    )
    regressed_hash = next(
        row["record_hash"]
        for row in stream.rows
        if row["collector_seq"] == regressed_exit["collector_seq"]
    )

    assert all(row["entry"]["quote"]["source_event_utc_ns"] == 100 for row in bundle["trades"])
    assert all(row["exit"]["quote"]["source_event_utc_ns"] == 200 for row in bundle["trades"])
    assert all(
        row["exit_raw_record_hash"] == fresh_hash
        for row in bundle["attempts"]
        if row["status"].startswith("CLOSED_")
    )
    assert all(
        row["exit_raw_record_hash"] != regressed_hash
        for row in bundle["attempts"]
        if row["status"].startswith("CLOSED_")
    )
    assert audit["audit_status"] == "MATCH"
