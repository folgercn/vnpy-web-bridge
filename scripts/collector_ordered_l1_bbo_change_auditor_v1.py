"""Independent, offline raw-to-PnL auditor for Issue #488.

This module intentionally imports no producer, feature-kernel, accounting, or
other repository module.  It accepts only JSON-compatible values and repeats
all custody and research calculations locally.  The integrity result is
relative to caller-supplied external custody-head and freeze anchors; neither
hash chain is a signature or a WORM guarantee.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, ROUND_HALF_UP, localcontext
import hashlib
import json
from typing import Iterable, Mapping, Sequence


AUDITOR_SCHEMA_VERSION = "collector_ordered_l1_bbo_change_auditor_v1"
AUDIT_INPUT_SCHEMA_VERSION = "issue488-raw-replay-v1"
PRODUCER_BUNDLE_SCHEMA_VERSION = "issue488-raw-replay-v1"
RESEARCH_LINE_ID = "CN_COMMODITY_HFT_BBO_CHANGE_LAB_V1"
CANDIDATE_ID = "COLLECTOR_ORDERED_L1_BBO_CHANGE_IMBALANCE_V1"
DATA_CONTRACT_ID = "CN_FUTURES_CONTINUOUS_EXACT_L1_OBSERVED_UPDATE_V1"
CUSTODY_SCHEMA_VERSION = "issue488-custody-v1"

FEATURE_WINDOW_NS = 10_000_000_000
HOLDING_HORIZON_NS = 30_000_000_000
EXIT_GRACE_NS = 5_000_000_000
MINIMUM_CALIBRATION_SCORES = 1_000
FEE_QUANTUM = Decimal("0.01")

_CONTROL_EVENTS = frozenset(
    {
        "COLLECTOR_START",
        "DISCONNECT",
        "RECONNECT",
        "CLOCK_EPOCH_CHANGE",
        "SESSION_SEGMENT_START",
        "SESSION_SEGMENT_END",
        "BACKPRESSURE_ABORT",
        "SINK_FAILURE_ABORT",
        "COLLECTOR_STOP",
    }
)
_GENERATION_GLOBAL_CONTROL_EVENTS = frozenset(
    {
        "COLLECTOR_START",
        "DISCONNECT",
        "RECONNECT",
        "CLOCK_EPOCH_CHANGE",
        "BACKPRESSURE_ABORT",
        "SINK_FAILURE_ABORT",
        "COLLECTOR_STOP",
    }
)
_EXACT_CONTRACT_SEGMENT_CONTROL_EVENTS = frozenset(
    {"SESSION_SEGMENT_START", "SESSION_SEGMENT_END"}
)
_ABORTING_CONTROL_EVENTS = frozenset(
    {"BACKPRESSURE_ABORT", "SINK_FAILURE_ABORT", "COLLECTOR_STOP"}
)
_CUSTODY_COMMON_FIELDS = frozenset(
    {
        "research_line_id",
        "data_contract_id",
        "run_id",
        "partition_id",
        "record_type",
        "collector_generation",
        "clock_epoch",
        "segment_id",
        "collector_seq",
        "provider_delivery_semantics",
        "provider_batch_id",
        "within_batch_rank",
        "provider_update_id",
        "provider_update_id_semantics",
        "source_event_time_raw",
        "source_event_utc_ns",
        "source_time_precision_ns",
        "callback_entry_receive_utc_ns",
        "callback_entry_receive_monotonic_ns",
        "clock_sample_id",
        "clock_sync_state",
        "clock_offset_ns",
        "clock_uncertainty_ns",
        "product",
        "exact_contract",
        "exchange",
        "official_trading_day",
        "session_family",
        "prev_record_hash",
        "record_hash",
    }
)
_CUSTODY_QUOTE_FIELDS = frozenset(
    {
        "bid_price1_raw",
        "bid_size1_raw",
        "ask_price1_raw",
        "ask_size1_raw",
        "last_price_raw",
        "cumulative_volume_raw",
        "cumulative_amount_raw",
        "open_interest_raw",
        "parse_status",
        "duplicate_status",
        "source_status",
    }
)
_CUSTODY_CONTROL_FIELDS = frozenset({"event_type", "reason", "scope"})
_MANIFEST_FIELDS = frozenset(
    {
        "run_id",
        "collector_generation",
        "partition_id",
        "path",
        "exact_bytes",
        "record_count",
        "first_collector_seq",
        "last_collector_seq",
        "first_record_hash",
        "last_record_hash",
        "partition_hash",
        "previous_partition_hash",
        "previous_partition_seal_id",
        "seal_id",
        "closed_at_utc",
        "schema_version",
        "code_sha",
    }
)
_SUCCESS_PARSE_STATUS = "RAW_RETAINED"
_SUCCESS_SOURCE_STATUS = "OBSERVED"
_ORDINARY_DUPLICATE_STATUS = "NOT_CLASSIFIED"
_EXPLICIT_DUPLICATE_STATUSES = frozenset(
    {
        "EXPLICIT_DUPLICATE",
        "PROVEN_EXACT_DUPLICATE",
        "PROVEN_ADJACENT_EXACT_DUPLICATE",
    }
)

_SCENARIOS: dict[str, dict[str, object]] = {
    "PRIMARY": {
        "scenario_id": "PRIMARY",
        "entry_delay_ns": 500_000_000,
        "exit_delay_ns": 500_000_000,
        "adverse_ticks": 0,
        "horizon_ns": HOLDING_HORIZON_NS,
        "lots": 1,
        "min_side_size": "1",
        "exit_grace_ns": EXIT_GRACE_NS,
        "position_scope": "scenario_id×exact_contract",
        "event_order_version": "collector-callback-order-v1",
    },
    "STRESS": {
        "scenario_id": "STRESS",
        "entry_delay_ns": 1_000_000_000,
        "exit_delay_ns": 1_000_000_000,
        "adverse_ticks": 1,
        "horizon_ns": HOLDING_HORIZON_NS,
        "lots": 1,
        "min_side_size": "1",
        "exit_grace_ns": EXIT_GRACE_NS,
        "position_scope": "scenario_id×exact_contract",
        "event_order_version": "collector-callback-order-v1",
    },
}


class AuditorContractError(ValueError):
    """A deterministic, fail-closed audit input error."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _fail(code: str, detail: str) -> None:
    raise AuditorContractError(code, detail)


def _json_value(value: object, path: str = "$") -> None:
    """Require actual JSON primitives, not merely json.dumps-compatible objects."""

    if value is None or type(value) in {str, bool}:
        return
    if type(value) is int:
        return
    if type(value) is float:
        _fail("NON_JSON_FLOAT", f"{path} must not contain float")
    if type(value) is list:
        for index, item in enumerate(value):
            _json_value(item, f"{path}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail("NON_JSON_KEY", f"{path} contains a non-string key")
            _json_value(item, f"{path}.{key}")
        return
    _fail("NON_JSON_VALUE", f"{path} contains {type(value).__name__}")


def _canonical_bytes(value: object) -> bytes:
    _json_value(value)
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AuditorContractError("NON_CANONICAL_JSON", "cannot encode JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _mapping(value: object, path: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail("INVALID_MAPPING", f"{path} must be an object")
    _json_value(value, path)
    return value


def _list(value: object, path: str) -> list[object]:
    if type(value) is not list:
        _fail("INVALID_LIST", f"{path} must be an array")
    _json_value(value, path)
    return value


def _exact_keys(value: Mapping[str, object], keys: Iterable[str], path: str) -> None:
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail("SCHEMA_KEYS", f"{path} missing={missing} extra={extra}")


def _text(value: object, path: str) -> str:
    if type(value) is not str or not value.strip() or value != value.strip():
        _fail("INVALID_TEXT", f"{path} must be non-empty canonical text")
    return value


def _integer(value: object, path: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail("INVALID_INTEGER", f"{path} must be integer >= {minimum}")
    return value


def _safe_name(value: object, path: str) -> str:
    result = _text(value, path)
    if (
        len(result) > 128
        or result in {".", ".."}
        or any(
            not (
                character.isascii()
                and (character.isalnum() or character in "._-")
            )
            for character in result
        )
    ):
        _fail("UNSAFE_CUSTODY_NAME", path)
    return result


def _hash(value: object, path: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail("INVALID_SHA256", f"{path} must be lowercase SHA-256")
    return value


def _decimal(value: object, path: str) -> Decimal:
    if not isinstance(value, str):
        _fail("INVALID_DECIMAL", f"{path} must be a decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise AuditorContractError("INVALID_DECIMAL", f"{path} is invalid") from exc
    if not result.is_finite():
        _fail("INVALID_DECIMAL", f"{path} must be finite")
    return result


def _optional_raw_decimal(value: object) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (str, int)):
        return None
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        return None
    return result if result.is_finite() else None


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        _fail("NONFINITE_RESULT", "auditor produced a non-finite Decimal")
    return format(value, "f")


def _day(value: object, path: str) -> str:
    text = _text(value, path)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise AuditorContractError("INVALID_DAY", f"{path} is not YYYY-MM-DD") from exc
    if parsed.isoformat() != text:
        _fail("INVALID_DAY", f"{path} is not canonical YYYY-MM-DD")
    return text


def _canonical_json_line(value: Mapping[str, object]) -> bytes:
    return _canonical_bytes(dict(value)) + b"\n"


@dataclass(frozen=True)
class _VerifiedPartition:
    manifest: dict[str, object]
    rows: tuple[dict[str, object], ...]
    data_bytes: bytes


@dataclass(frozen=True)
class _CustodyResult:
    rows: tuple[dict[str, object], ...]
    run_id: str
    terminal_partition_hash: str
    terminal_seal_id: str
    partition_count: int
    record_count: int
    chain_sha256: str


def _parse_json_object_line(text: str, path: str) -> dict[str, object]:
    if not isinstance(text, str) or not text.endswith("\n") or text.count("\n") != 1:
        _fail("NON_CANONICAL_MANIFEST", f"{path} must be one JSON object plus newline")
    if len(text.encode("utf-8")) > 1024 * 1024:
        _fail("MANIFEST_TOO_LARGE", path)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditorContractError("INVALID_MANIFEST_JSON", path) from exc
    result = _mapping(value, path)
    if _canonical_json_line(result) != text.encode("utf-8"):
        _fail("NON_CANONICAL_MANIFEST", path)
    return result


def _parse_jsonl(text: str, path: str) -> tuple[tuple[dict[str, object], ...], bytes]:
    if not isinstance(text, str) or not text or not text.endswith("\n"):
        _fail("NON_CANONICAL_JSONL", f"{path} must be non-empty and newline terminated")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditorContractError("NON_CANONICAL_JSONL", path) from exc
    rows: list[dict[str, object]] = []
    for index, line in enumerate(encoded.splitlines()):
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditorContractError(
                "INVALID_RAW_JSON", f"{path}[{index}]"
            ) from exc
        row = _mapping(value, f"{path}[{index}]")
        if _canonical_bytes(row) != line:
            _fail("NON_CANONICAL_RAW_ROW", f"{path}[{index}]")
        rows.append(row)
    if not rows:
        _fail("EMPTY_PARTITION", path)
    if b"".join(_canonical_json_line(row) for row in rows) != encoded:
        _fail("NON_CANONICAL_JSONL", path)
    return tuple(rows), encoded


def _verify_manifest(
    raw_manifest: Mapping[str, object],
    data: bytes,
    rows: Sequence[Mapping[str, object]],
    path: str,
) -> dict[str, object]:
    manifest = dict(raw_manifest)
    _exact_keys(manifest, _MANIFEST_FIELDS, path)
    for field_name in ("run_id", "collector_generation", "partition_id"):
        _safe_name(manifest[field_name], f"{path}.{field_name}")
    for field_name in ("path", "closed_at_utc", "schema_version", "code_sha"):
        _text(manifest[field_name], f"{path}.{field_name}")
    if manifest["schema_version"] != CUSTODY_SCHEMA_VERSION:
        _fail("CUSTODY_SCHEMA_VERSION", path)
    code_sha = manifest["code_sha"]
    if (
        not isinstance(code_sha, str)
        or len(code_sha) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in code_sha)
    ):
        _fail("INVALID_CODE_SHA", path)
    partition_id = str(manifest["partition_id"])
    if manifest["path"] != f"{partition_id}.jsonl":
        _fail("MANIFEST_PATH", path)
    for field_name in (
        "exact_bytes",
        "record_count",
        "first_collector_seq",
        "last_collector_seq",
    ):
        _integer(manifest[field_name], f"{path}.{field_name}", 1)
    if manifest["last_collector_seq"] < manifest["first_collector_seq"]:
        _fail("MANIFEST_SEQUENCE_BOUNDS", path)
    for field_name in (
        "first_record_hash",
        "last_record_hash",
        "partition_hash",
        "seal_id",
    ):
        _hash(manifest[field_name], f"{path}.{field_name}")
    _hash(
        manifest["previous_partition_hash"],
        f"{path}.previous_partition_hash",
        nullable=True,
    )
    _hash(
        manifest["previous_partition_seal_id"],
        f"{path}.previous_partition_seal_id",
        nullable=True,
    )
    core = dict(manifest)
    seal_id = core.pop("seal_id")
    if seal_id != _canonical_sha256(core):
        _fail("MANIFEST_SEAL_MISMATCH", path)
    if manifest["exact_bytes"] != len(data):
        _fail("PARTITION_BYTE_COUNT_MISMATCH", path)
    if manifest["record_count"] != len(rows):
        _fail("PARTITION_RECORD_COUNT_MISMATCH", path)
    if manifest["partition_hash"] != _sha256_bytes(data):
        _fail("PARTITION_HASH_MISMATCH", path)
    return manifest


def _partition_envelope(
    value: object, index: int
) -> _VerifiedPartition:
    item = _mapping(value, f"sealed_partitions[{index}]")
    _exact_keys(
        item,
        {"manifest_json_utf8", "raw_jsonl_utf8"},
        f"sealed_partitions[{index}]",
    )
    manifest = _parse_json_object_line(
        item["manifest_json_utf8"], f"sealed_partitions[{index}].manifest"
    )
    rows, data = _parse_jsonl(
        item["raw_jsonl_utf8"], f"sealed_partitions[{index}].raw"
    )
    verified = _verify_manifest(
        manifest, data, rows, f"sealed_partitions[{index}].manifest"
    )
    return _VerifiedPartition(verified, rows, data)


def _verify_raw_row(
    row: Mapping[str, object],
    *,
    run_id: str,
    partition_id: str,
    generation: str,
    expected_seq: int,
    previous_record_hash: str | None,
    path: str,
) -> str:
    record_type = row.get("record_type")
    required = set(_CUSTODY_COMMON_FIELDS)
    if record_type == "QUOTE":
        required.update(_CUSTODY_QUOTE_FIELDS)
    elif record_type == "CONTROL":
        required.update(_CUSTODY_CONTROL_FIELDS)
    if record_type not in {"QUOTE", "CONTROL"} or set(row) != required:
        _fail("RAW_SCHEMA", path)
    if record_type == "CONTROL":
        for name in (
            "record_type",
            "collector_generation",
            "clock_epoch",
            "segment_id",
            "provider_delivery_semantics",
            "provider_update_id_semantics",
            "source_event_time_raw",
            "clock_sample_id",
            "clock_sync_state",
            "product",
            "exact_contract",
            "exchange",
            "session_family",
            "event_type",
            "reason",
            "scope",
        ):
            _text(row.get(name), f"{path}.{name}")
        _day(row.get("official_trading_day"), f"{path}.official_trading_day")
        for name in ("provider_batch_id", "provider_update_id"):
            value = row.get(name)
            if value is not None:
                _text(value, f"{path}.{name}")
        _integer(row.get("within_batch_rank"), f"{path}.within_batch_rank", 1)
        _integer(row.get("source_event_utc_ns"), f"{path}.source_event_utc_ns", 1)
        _integer(
            row.get("source_time_precision_ns"),
            f"{path}.source_time_precision_ns",
            1,
        )
        _integer(
            row.get("callback_entry_receive_utc_ns"),
            f"{path}.callback_entry_receive_utc_ns",
            1,
        )
        _integer(
            row.get("callback_entry_receive_monotonic_ns"),
            f"{path}.callback_entry_receive_monotonic_ns",
            1,
        )
        _integer(row.get("clock_offset_ns"), f"{path}.clock_offset_ns", -10**18)
        _integer(
            row.get("clock_uncertainty_ns"), f"{path}.clock_uncertainty_ns"
        )
        if row.get("event_type") not in _CONTROL_EVENTS:
            _fail("RAW_CONTROL_EVENT", path)
        event = row.get("event_type")
        scope = row.get("scope")
        if event in _GENERATION_GLOBAL_CONTROL_EVENTS:
            if scope != "GENERATION_GLOBAL":
                _fail("RAW_CONTROL_SCOPE", path)
        elif event in _EXACT_CONTRACT_SEGMENT_CONTROL_EVENTS:
            if scope != "EXACT_CONTRACT_SEGMENT":
                _fail("RAW_CONTROL_SCOPE", path)
            for name in (
                "exact_contract",
                "session_family",
                "segment_id",
                "official_trading_day",
            ):
                _text(row.get(name), f"{path}.{name}")
            _day(row.get("official_trading_day"), f"{path}.official_trading_day")
    if (
        row.get("research_line_id") != RESEARCH_LINE_ID
        or row.get("data_contract_id") != DATA_CONTRACT_ID
        or row.get("run_id") != run_id
        or row.get("partition_id") != partition_id
        or row.get("collector_generation") != generation
        or row.get("collector_seq") != expected_seq
        or row.get("prev_record_hash") != previous_record_hash
    ):
        _fail("RAW_CHAIN_IDENTITY", path)
    _integer(row.get("collector_seq"), f"{path}.collector_seq", 1)
    supplied_hash = _hash(row.get("record_hash"), f"{path}.record_hash")
    unhashed = dict(row)
    unhashed.pop("record_hash")
    if supplied_hash != _canonical_sha256(unhashed):
        _fail("RAW_RECORD_HASH_MISMATCH", path)
    return supplied_hash


def _verify_custody(
    sealed_partitions: object,
    trusted_head_partition_hash: object,
    trusted_head_seal_id: object,
) -> _CustodyResult:
    items = _list(sealed_partitions, "sealed_partitions")
    if not items:
        _fail("EMPTY_CUSTODY", "at least one sealed partition is required")
    trusted_hash = _hash(
        trusted_head_partition_hash, "trusted_head_partition_hash"
    )
    trusted_seal = _hash(trusted_head_seal_id, "trusted_head_seal_id")
    partitions = [_partition_envelope(item, index) for index, item in enumerate(items)]
    by_hash: dict[str, _VerifiedPartition] = {}
    children: dict[str, _VerifiedPartition] = {}
    roots: list[_VerifiedPartition] = []
    for partition in partitions:
        partition_hash = str(partition.manifest["partition_hash"])
        if partition_hash in by_hash:
            _fail("DUPLICATE_PARTITION_HASH", partition_hash)
        by_hash[partition_hash] = partition
        previous = partition.manifest["previous_partition_hash"]
        if previous is None:
            roots.append(partition)
        else:
            previous_hash = str(previous)
            if previous_hash in children:
                _fail("PARTITION_FORK", previous_hash)
            children[previous_hash] = partition
    if len(roots) != 1:
        _fail("PARTITION_ROOT_COUNT", f"got {len(roots)}")
    ordered = [roots[0]]
    seen_partition_hashes: set[str] = set()
    while True:
        current_hash = str(ordered[-1].manifest["partition_hash"])
        if current_hash in seen_partition_hashes:
            _fail("PARTITION_CYCLE", current_hash)
        seen_partition_hashes.add(current_hash)
        child = children.get(current_hash)
        if child is None:
            break
        ordered.append(child)
    if len(ordered) != len(partitions):
        _fail("PARTITION_CHAIN_DISCONNECTED", "not every partition reaches the root")
    terminal = ordered[-1].manifest
    if (
        terminal["partition_hash"] != trusted_hash
        or terminal["seal_id"] != trusted_seal
    ):
        _fail("TRUSTED_HEAD_MISMATCH", "terminal partition hash/seal mismatch")

    run_id = _text(ordered[0].manifest["run_id"], "manifest.run_id")
    schema_version = ordered[0].manifest["schema_version"]
    code_sha = ordered[0].manifest["code_sha"]
    all_rows: list[dict[str, object]] = []
    expected_seq = 1
    previous_hash: str | None = None
    previous_generation: str | None = None
    retired_generations: set[str] = set()
    for partition_index, partition in enumerate(ordered):
        manifest = partition.manifest
        generation = _text(
            manifest["collector_generation"],
            f"ordered_partitions[{partition_index}].collector_generation",
        )
        if (
            manifest["run_id"] != run_id
            or manifest["schema_version"] != schema_version
            or manifest["code_sha"] != code_sha
        ):
            _fail("MANIFEST_RUN_SCHEMA_MISMATCH", str(manifest["partition_id"]))
        if partition_index == 0:
            if (
                manifest["previous_partition_hash"] is not None
                or manifest["previous_partition_seal_id"] is not None
            ):
                _fail("GENESIS_PREDECESSOR", str(manifest["partition_id"]))
        else:
            predecessor = ordered[partition_index - 1].manifest
            if (
                manifest["previous_partition_hash"]
                != predecessor["partition_hash"]
                or manifest["previous_partition_seal_id"] != predecessor["seal_id"]
            ):
                _fail("PARTITION_PREDECESSOR_BINDING", str(manifest["partition_id"]))
        if previous_generation is not None and generation != previous_generation:
            retired_generations.add(previous_generation)
            if generation in retired_generations:
                _fail("GENERATION_REAPPEARED", generation)
            expected_seq = 1
        first_hash: str | None = None
        partition_id = str(manifest["partition_id"])
        for row_index, raw_row in enumerate(partition.rows):
            row = dict(raw_row)
            actual = _verify_raw_row(
                row,
                run_id=run_id,
                partition_id=partition_id,
                generation=generation,
                expected_seq=expected_seq,
                previous_record_hash=previous_hash,
                path=f"partition[{partition_id}].rows[{row_index}]",
            )
            if first_hash is None:
                first_hash = actual
            previous_hash = actual
            expected_seq += 1
            all_rows.append(row)
        if (
            manifest["first_collector_seq"] != expected_seq - len(partition.rows)
            or manifest["last_collector_seq"] != expected_seq - 1
            or manifest["first_record_hash"] != first_hash
            or manifest["last_record_hash"] != previous_hash
        ):
            _fail("MANIFEST_ROW_SUMMARY_MISMATCH", partition_id)
        previous_generation = generation
    chain_projection = [partition.manifest for partition in ordered]
    return _CustodyResult(
        rows=tuple(all_rows),
        run_id=run_id,
        terminal_partition_hash=str(terminal["partition_hash"]),
        terminal_seal_id=str(terminal["seal_id"]),
        partition_count=len(ordered),
        record_count=len(all_rows),
        chain_sha256=_canonical_sha256(chain_projection),
    )


@dataclass(frozen=True)
class _Threshold:
    exact_contract: str
    session_family: str
    quantile: Decimal
    sample_count: int
    threshold: Decimal


@dataclass(frozen=True)
class _Binding:
    binding_id: str
    exact_contract: str
    official_day: str
    valid_from_utc_ns: int
    valid_until_utc_ns: int
    tick_size: Decimal | None
    multiplier: Decimal | None
    offset: str | None
    fixed_cny: Decimal | None
    ratio_per_mille: Decimal | None


@dataclass(frozen=True)
class _Freeze:
    raw: dict[str, object]
    sha256: str
    thresholds: dict[tuple[str, str], _Threshold]
    scenarios: dict[str, dict[str, object]]
    instrument_terms: tuple[_Binding, ...]
    fee_schedules: tuple[_Binding, ...]
    broker_markups: tuple[_Binding, ...]
    coverage_plan: tuple[dict[str, object], ...]
    provider_semantics: tuple[dict[str, object], ...]


def _binding_common(row: Mapping[str, object], path: str) -> tuple[str, str, str, int, int]:
    binding_id = _text(row.get("binding_id"), f"{path}.binding_id")
    contract = _text(row.get("exact_contract"), f"{path}.exact_contract")
    official_day = _day(row.get("official_day"), f"{path}.official_day")
    valid_from = _integer(row.get("valid_from_utc_ns"), f"{path}.valid_from_utc_ns", 1)
    valid_until = _integer(
        row.get("valid_until_utc_ns"), f"{path}.valid_until_utc_ns", 1
    )
    if valid_until <= valid_from:
        _fail("BINDING_INTERVAL", path)
    for name in ("authority", "source", "version"):
        _text(row.get(name), f"{path}.{name}")
    _hash(row.get("source_sha256"), f"{path}.source_sha256")
    return binding_id, contract, official_day, valid_from, valid_until


def _parse_terms(values: object) -> tuple[_Binding, ...]:
    rows = _list(values, "freeze_bundle.instrument_terms")
    result: list[_Binding] = []
    for index, value in enumerate(rows):
        path = f"freeze_bundle.instrument_terms[{index}]"
        row = _mapping(value, path)
        expected = {
            "binding_id",
            "exact_contract",
            "official_day",
            "valid_from_utc_ns",
            "valid_until_utc_ns",
            "tick_size",
            "multiplier",
            "authority",
            "source",
            "version",
            "source_sha256",
        }
        _exact_keys(row, expected, path)
        common = _binding_common(row, path)
        tick_size = _decimal(row["tick_size"], f"{path}.tick_size")
        multiplier = _decimal(row["multiplier"], f"{path}.multiplier")
        if tick_size <= 0 or multiplier <= 0:
            _fail("BINDING_POSITIVE", path)
        result.append(_Binding(*common, tick_size, multiplier, None, None, None))
    return tuple(result)


def _parse_cost_bindings(values: object, name: str) -> tuple[_Binding, ...]:
    rows = _list(values, f"freeze_bundle.{name}")
    result: list[_Binding] = []
    for index, value in enumerate(rows):
        path = f"freeze_bundle.{name}[{index}]"
        row = _mapping(value, path)
        expected = {
            "binding_id",
            "exact_contract",
            "official_day",
            "valid_from_utc_ns",
            "valid_until_utc_ns",
            "offset",
            "fixed_cny",
            "ratio_per_mille",
            "authority",
            "source",
            "version",
            "source_sha256",
        }
        _exact_keys(row, expected, path)
        common = _binding_common(row, path)
        offset = row["offset"]
        if offset not in {"OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY"}:
            _fail("BINDING_OFFSET", path)
        fixed = _decimal(row["fixed_cny"], f"{path}.fixed_cny")
        ratio = _decimal(row["ratio_per_mille"], f"{path}.ratio_per_mille")
        if fixed < 0 or ratio < 0:
            _fail("BINDING_NONNEGATIVE", path)
        result.append(_Binding(*common, None, None, str(offset), fixed, ratio))
    return tuple(result)


def _parse_freeze(freeze_bundle: object, trusted_freeze_sha256: object) -> _Freeze:
    freeze = _mapping(freeze_bundle, "freeze_bundle")
    trusted = _hash(trusted_freeze_sha256, "trusted_freeze_sha256")
    actual_sha = _canonical_sha256(freeze)
    if actual_sha != trusted:
        _fail("FREEZE_HASH_MISMATCH", "freeze bundle does not match external anchor")
    expected_keys = {
        "schema_version",
        "research_line_id",
        "candidate_id",
        "data_contract_id",
        "thresholds",
        "scenarios",
        "instrument_terms",
        "fee_schedules",
        "broker_markups",
        "coverage_plan",
        "provider_semantics",
    }
    _exact_keys(freeze, expected_keys, "freeze_bundle")
    if (
        freeze["schema_version"] != AUDIT_INPUT_SCHEMA_VERSION
        or freeze["research_line_id"] != RESEARCH_LINE_ID
        or freeze["candidate_id"] != CANDIDATE_ID
        or freeze["data_contract_id"] != DATA_CONTRACT_ID
    ):
        _fail("FREEZE_IDENTITY", "freeze identity is not Issue #488 v1")

    scenarios: dict[str, dict[str, object]] = {}
    for index, value in enumerate(_list(freeze["scenarios"], "freeze_bundle.scenarios")):
        path = f"freeze_bundle.scenarios[{index}]"
        row = _mapping(value, path)
        scenario_id = _text(row.get("scenario_id"), f"{path}.scenario_id")
        expected = _SCENARIOS.get(scenario_id)
        if expected is None or row != expected or scenario_id in scenarios:
            _fail("SCENARIO_NOT_FROZEN", path)
        scenarios[scenario_id] = dict(row)
    if scenarios != _SCENARIOS:
        _fail("SCENARIO_SET", "PRIMARY and STRESS are both required exactly once")

    thresholds: dict[tuple[str, str], _Threshold] = {}
    threshold_keys = {
        "exact_contract",
        "session_family",
        "quantile",
        "sample_count",
        "threshold",
    }
    for index, value in enumerate(_list(freeze["thresholds"], "freeze_bundle.thresholds")):
        path = f"freeze_bundle.thresholds[{index}]"
        row = _mapping(value, path)
        _exact_keys(row, threshold_keys, path)
        contract = _text(row["exact_contract"], f"{path}.exact_contract")
        session = _text(row["session_family"], f"{path}.session_family")
        quantile = _decimal(row["quantile"], f"{path}.quantile")
        sample_count = _integer(row["sample_count"], f"{path}.sample_count", 1)
        threshold = _decimal(row["threshold"], f"{path}.threshold")
        if (
            quantile != Decimal("0.95")
            or sample_count < MINIMUM_CALIBRATION_SCORES
            or threshold <= 0
        ):
            _fail("THRESHOLD_NOT_FROZEN", path)
        key = (contract, session)
        if key in thresholds:
            _fail("DUPLICATE_THRESHOLD", path)
        thresholds[key] = _Threshold(
            contract, session, quantile, sample_count, threshold
        )
    if not thresholds:
        _fail("EMPTY_THRESHOLDS", "at least one threshold cell is required")

    coverage_rows: list[dict[str, object]] = []
    coverage_keys = {
        "exact_contract",
        "official_day",
        "session_family",
        "segment_id",
        "start_utc_ns",
        "end_utc_ns",
        "days_to_ltd",
        "eligible",
        "source",
        "authority",
        "version",
        "source_sha256",
    }
    seen_coverage_cells: set[tuple[str, str, str, str]] = set()
    for index, value in enumerate(
        _list(freeze["coverage_plan"], "freeze_bundle.coverage_plan")
    ):
        path = f"freeze_bundle.coverage_plan[{index}]"
        row = _mapping(value, path)
        _exact_keys(row, coverage_keys, path)
        contract = _text(row["exact_contract"], f"{path}.exact_contract")
        official_day = _day(row["official_day"], f"{path}.official_day")
        session = _text(row["session_family"], f"{path}.session_family")
        segment = _text(row["segment_id"], f"{path}.segment_id")
        start = _integer(row["start_utc_ns"], f"{path}.start_utc_ns", 1)
        end = _integer(row["end_utc_ns"], f"{path}.end_utc_ns", 1)
        if end <= start:
            _fail("COVERAGE_INTERVAL", path)
        _integer(row["days_to_ltd"], f"{path}.days_to_ltd")
        if not isinstance(row["eligible"], bool):
            _fail("COVERAGE_ELIGIBLE", path)
        _text(row["source"], f"{path}.source")
        _text(row["authority"], f"{path}.authority")
        _text(row["version"], f"{path}.version")
        _hash(row["source_sha256"], f"{path}.source_sha256")
        cell = (contract, official_day, session, segment)
        if cell in seen_coverage_cells:
            _fail("DUPLICATE_COVERAGE_CELL", path)
        seen_coverage_cells.add(cell)
        coverage_rows.append(dict(row))
    provider_semantics: list[dict[str, object]] = []
    provider_keys = {
        "provider_delivery_semantics",
        "provider_update_id_semantics",
        "status",
    }
    seen_provider_cells: set[tuple[str, str]] = set()
    for index, value in enumerate(
        _list(freeze["provider_semantics"], "freeze_bundle.provider_semantics")
    ):
        path = f"freeze_bundle.provider_semantics[{index}]"
        row = _mapping(value, path)
        _exact_keys(row, provider_keys, path)
        delivery = _text(
            row["provider_delivery_semantics"],
            f"{path}.provider_delivery_semantics",
        )
        identity = _text(
            row["provider_update_id_semantics"],
            f"{path}.provider_update_id_semantics",
        )
        if row["status"] not in {
            "UNVERIFIED",
            "PROVEN_NO_USABLE_ID",
            "PROVEN_UNIQUE",
        }:
            _fail("PROVIDER_SEMANTICS_STATUS", path)
        cell = (delivery, identity)
        if cell in seen_provider_cells:
            _fail("DUPLICATE_PROVIDER_SEMANTICS", path)
        seen_provider_cells.add(cell)
        provider_semantics.append(dict(row))
    return _Freeze(
        raw=dict(freeze),
        sha256=actual_sha,
        thresholds=thresholds,
        scenarios=scenarios,
        instrument_terms=_parse_terms(freeze["instrument_terms"]),
        fee_schedules=_parse_cost_bindings(freeze["fee_schedules"], "fee_schedules"),
        broker_markups=_parse_cost_bindings(freeze["broker_markups"], "broker_markups"),
        coverage_plan=tuple(coverage_rows),
        provider_semantics=tuple(provider_semantics),
    )


@dataclass(frozen=True)
class _Quote:
    row: dict[str, object]
    run_id: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    collector_seq: int
    exact_contract: str
    session_family: str
    official_day: str
    source_event_utc_ns: int
    receive_utc_ns: int
    receive_monotonic_ns: int
    active_time_ns: int
    bid: Decimal | None
    bid_size: Decimal | None
    ask: Decimal | None
    ask_size: Decimal | None
    provider_update_id: str | None
    explicit_duplicate: bool

    @property
    def raw_record_hash(self) -> str:
        return str(self.row["record_hash"])

    @property
    def lane(self) -> tuple[str, str, str, str, str]:
        return (
            self.collector_generation,
            self.clock_epoch,
            self.exact_contract,
            self.session_family,
            self.segment_id,
        )

    def qualified(self) -> bool:
        return (
            self.bid is not None
            and self.bid_size is not None
            and self.ask is not None
            and self.ask_size is not None
            and self.bid > 0
            and self.ask > 0
            and self.bid_size > 0
            and self.ask_size > 0
            and self.bid < self.ask
            and not self.explicit_duplicate
        )

    def execution_usable(self, side: str) -> bool:
        if side not in {"BUY", "SELL"}:
            _fail("EXECUTION_SIDE", side)
        if not self.qualified() or self.row.get("clock_sync_state") != "SYNCED":
            return False
        size = self.ask_size if side == "BUY" else self.bid_size
        return size is not None and size >= Decimal(1)


@dataclass(frozen=True)
class _FeatureOutcome:
    status: str
    reset_reason: str | None
    score: Decimal | None


@dataclass(frozen=True)
class _WindowTerm:
    active_time_ns: int
    contribution: Decimal
    depth: Decimal


@dataclass
class _FeatureState:
    previous: _Quote | None = None
    baseline_active_ns: int | None = None
    terms: deque[_WindowTerm] = field(default_factory=deque)


def _provider_status(freeze: _Freeze, row: Mapping[str, object]) -> str:
    matches = [
        item
        for item in freeze.provider_semantics
        if item["provider_delivery_semantics"]
        == row.get("provider_delivery_semantics")
        and item["provider_update_id_semantics"]
        == row.get("provider_update_id_semantics")
    ]
    if len(matches) != 1:
        _fail("PROVIDER_SEMANTICS_NOT_FROZEN", str(row.get("record_hash")))
    return str(matches[0]["status"])


def _provider_payload_hash(row: Mapping[str, object]) -> str:
    fields = (
        "provider_delivery_semantics",
        "provider_batch_id",
        "within_batch_rank",
        "provider_update_id",
        "provider_update_id_semantics",
        "source_event_time_raw",
        "source_event_utc_ns",
        "source_time_precision_ns",
        "product",
        "exact_contract",
        "exchange",
        "official_trading_day",
        "session_family",
        "bid_price1_raw",
        "bid_size1_raw",
        "ask_price1_raw",
        "ask_size1_raw",
        "last_price_raw",
        "cumulative_volume_raw",
        "cumulative_amount_raw",
        "open_interest_raw",
        "parse_status",
        "source_status",
    )
    if any(name not in row for name in fields):
        _fail("PROVIDER_PAYLOAD_INCOMPLETE", str(row.get("record_hash")))
    return _canonical_sha256({name: row[name] for name in fields})


def _quote_from_raw(
    row: Mapping[str, object],
    freeze: _Freeze,
    *,
    provider_ids: dict[tuple[str, str], str],
) -> _Quote:
    path = f"raw[{row.get('record_hash')}]"
    if (
        row.get("parse_status") != _SUCCESS_PARSE_STATUS
        or row.get("source_status") != _SUCCESS_SOURCE_STATUS
    ):
        _fail("RAW_STATUS_NOT_FROZEN", path)
    provider_status = _provider_status(freeze, row)
    provider_id = row.get("provider_update_id")
    if provider_id is not None:
        provider_id = _text(provider_id, f"{path}.provider_update_id")
    duplicate_status = row.get("duplicate_status")
    if duplicate_status not in {
        _ORDINARY_DUPLICATE_STATUS,
        "PROVEN_ADJACENT_EXACT_DUPLICATE",
    }:
        _fail("DUPLICATE_STATUS", path)
    payload_hash = _provider_payload_hash(row)
    explicit_duplicate = False
    if provider_status == "PROVEN_UNIQUE":
        if provider_id is None:
            _fail("PROVEN_PROVIDER_ID_MISSING", path)
        scope = (
            f"{row.get('provider_delivery_semantics')}|"
            f"{row.get('provider_update_id_semantics')}"
        )
        key = (scope, provider_id)
        previous_payload_hash = provider_ids.get(key)
        if previous_payload_hash is not None:
            if payload_hash != previous_payload_hash:
                _fail("PROVIDER_ID_CONFLICT", path)
            explicit_duplicate = True
        provider_ids[key] = payload_hash
        if (
            duplicate_status == "PROVEN_ADJACENT_EXACT_DUPLICATE"
            and not explicit_duplicate
        ):
            _fail("DUPLICATE_MARKER_WITHOUT_PRIOR", path)
    else:
        if duplicate_status in _EXPLICIT_DUPLICATE_STATUSES:
            _fail("UNPROVEN_DUPLICATE_CLASSIFICATION", path)
    quote = _Quote(
        row=dict(row),
        run_id=_text(row.get("run_id"), f"{path}.run_id"),
        collector_generation=_text(
            row.get("collector_generation"), f"{path}.collector_generation"
        ),
        clock_epoch=_text(row.get("clock_epoch"), f"{path}.clock_epoch"),
        segment_id=_text(row.get("segment_id"), f"{path}.segment_id"),
        collector_seq=_integer(row.get("collector_seq"), f"{path}.collector_seq", 1),
        exact_contract=_text(row.get("exact_contract"), f"{path}.exact_contract"),
        session_family=_text(row.get("session_family"), f"{path}.session_family"),
        official_day=_day(row.get("official_trading_day"), f"{path}.official_day"),
        source_event_utc_ns=_integer(
            row.get("source_event_utc_ns"), f"{path}.source_event_utc_ns", 1
        ),
        receive_utc_ns=_integer(
            row.get("callback_entry_receive_utc_ns"),
            f"{path}.callback_entry_receive_utc_ns",
            1,
        ),
        receive_monotonic_ns=_integer(
            row.get("callback_entry_receive_monotonic_ns"),
            f"{path}.callback_entry_receive_monotonic_ns",
            1,
        ),
        active_time_ns=_integer(
            row.get("callback_entry_receive_monotonic_ns"),
            f"{path}.active_time_ns",
            1,
        ),
        bid=_optional_raw_decimal(row.get("bid_price1_raw")),
        bid_size=_optional_raw_decimal(row.get("bid_size1_raw")),
        ask=_optional_raw_decimal(row.get("ask_price1_raw")),
        ask_size=_optional_raw_decimal(row.get("ask_size1_raw")),
        provider_update_id=provider_id,
        explicit_duplicate=explicit_duplicate,
    )
    return quote


def _contribution(previous: _Quote, current: _Quote) -> Decimal:
    if not previous.qualified() or not current.qualified():
        _fail("FEATURE_UNQUALIFIED_INPUT", current.raw_record_hash)
    assert previous.bid is not None and previous.bid_size is not None
    assert previous.ask is not None and previous.ask_size is not None
    assert current.bid is not None and current.bid_size is not None
    assert current.ask is not None and current.ask_size is not None
    result = Decimal(0)
    if current.bid >= previous.bid:
        result += current.bid_size
    if current.bid <= previous.bid:
        result -= previous.bid_size
    if current.ask <= previous.ask:
        result -= current.ask_size
    if current.ask >= previous.ask:
        result += previous.ask_size
    return result


class _IndependentFeatureEngine:
    def __init__(self) -> None:
        self._states: dict[tuple[str, str, str], _FeatureState] = {}

    def clear_all(self) -> None:
        self._states.clear()

    def clear_lane(self, row: Mapping[str, object]) -> None:
        key = (
            str(row.get("exact_contract")),
            str(row.get("session_family")),
            str(row.get("segment_id")),
        )
        self._states.pop(key, None)

    def preview_reset(
        self,
        quote: _Quote,
        *,
        generation_changed: bool,
        epoch_changed: bool,
    ) -> str | None:
        if quote.explicit_duplicate:
            return None
        if generation_changed:
            return "COLLECTOR_GENERATION"
        if epoch_changed:
            return "CLOCK_EPOCH"
        key = (quote.exact_contract, quote.session_family, quote.segment_id)
        state = self._states.get(key)
        if not quote.qualified():
            return "INVALID_BBO"
        if state is None or state.previous is None:
            return "BASELINE_ONLY"
        previous = state.previous
        if quote.source_event_utc_ns < previous.source_event_utc_ns:
            return "SOURCE_TIME_REGRESSION"
        if quote.active_time_ns < previous.active_time_ns:
            return "ACTIVE_TIME_REGRESSION"
        if quote.active_time_ns - previous.active_time_ns >= FEATURE_WINDOW_NS:
            return "LONG_GAP"
        return None

    def process(
        self,
        quote: _Quote,
        *,
        generation_changed: bool,
        epoch_changed: bool,
    ) -> _FeatureOutcome:
        if generation_changed or epoch_changed:
            self.clear_all()
        key = (quote.exact_contract, quote.session_family, quote.segment_id)
        if quote.explicit_duplicate:
            return _FeatureOutcome("EXPLICIT_DUPLICATE_SKIPPED", None, None)
        current = quote if quote.qualified() else None
        if current is None:
            self._states[key] = _FeatureState()
            return _FeatureOutcome("INVALID_BBO_RESET", "INVALID_BBO", None)
        if generation_changed or epoch_changed:
            self._states[key] = _FeatureState(current, current.active_time_ns)
            reason = "COLLECTOR_GENERATION" if generation_changed else "CLOCK_EPOCH"
            return _FeatureOutcome("BASELINE_RESET", reason, None)
        state = self._states.setdefault(key, _FeatureState())
        if state.previous is None or state.baseline_active_ns is None:
            state.previous = current
            state.baseline_active_ns = current.active_time_ns
            state.terms.clear()
            return _FeatureOutcome("BASELINE_ONLY", None, None)
        previous = state.previous
        if current.source_event_utc_ns < previous.source_event_utc_ns:
            self._states[key] = _FeatureState(current, current.active_time_ns)
            return _FeatureOutcome(
                "SOURCE_TIME_REGRESSION_RESET", "SOURCE_TIME_REGRESSION", None
            )
        if current.active_time_ns < previous.active_time_ns:
            self._states[key] = _FeatureState(current, current.active_time_ns)
            return _FeatureOutcome(
                "ACTIVE_TIME_REGRESSION_RESET", "ACTIVE_TIME_REGRESSION", None
            )
        active_delta = current.active_time_ns - previous.active_time_ns
        monotonic_delta = (
            current.receive_monotonic_ns - previous.receive_monotonic_ns
        )
        if active_delta != monotonic_delta:
            _fail("ACTIVE_MONOTONIC_MISMATCH", current.raw_record_hash)
        if active_delta >= FEATURE_WINDOW_NS:
            self._states[key] = _FeatureState(current, current.active_time_ns)
            return _FeatureOutcome("LONG_GAP_RESET", "LONG_GAP", None)
        contribution = _contribution(previous, current)
        state.previous = current
        assert current.bid_size is not None and current.ask_size is not None
        state.terms.append(
            _WindowTerm(
                current.active_time_ns,
                contribution,
                (current.bid_size + current.ask_size) / Decimal(2),
            )
        )
        lower_bound = current.active_time_ns - FEATURE_WINDOW_NS
        while state.terms and state.terms[0].active_time_ns <= lower_bound:
            state.terms.popleft()
        if current.active_time_ns - state.baseline_active_ns < FEATURE_WINDOW_NS:
            return _FeatureOutcome("WARMING_UP", None, None)
        if not state.terms:
            return _FeatureOutcome("EMPTY_WINDOW", None, None)
        raw_imbalance = sum(
            (term.contribution for term in state.terms), Decimal(0)
        )
        depth_scale = sum((term.depth for term in state.terms), Decimal(0))
        depth_scale /= Decimal(len(state.terms))
        if depth_scale <= 0:
            return _FeatureOutcome("INVALID_DEPTH_SCALE", None, None)
        with localcontext() as context:
            context.prec = 50
            context.rounding = ROUND_HALF_EVEN
            score = raw_imbalance / depth_scale
        return _FeatureOutcome("SCORE_READY", None, score)


def _signal_id(row: Mapping[str, object], direction: str, threshold: Decimal) -> str:
    projection = {
        "kind": "threshold-crossing-v1",
        "candidate_id": CANDIDATE_ID,
        "run_id": row["run_id"],
        "collector_generation": row["collector_generation"],
        "collector_seq": row["collector_seq"],
        "raw_record_hash": row["record_hash"],
        "exact_contract": row["exact_contract"],
        "session_family": row["session_family"],
        "direction": direction,
        "threshold": _decimal_text(threshold),
    }
    return _canonical_sha256(projection)


def _attempt_id(signal_id: str, scenario_id: str) -> str:
    return _canonical_sha256(
        {"kind": "attempt-v1", "signal_id": signal_id, "scenario_id": scenario_id}
    )


@dataclass
class _Attempt:
    attempt_id: str
    signal_id: str
    run_id: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    session_family: str
    official_day: str
    exact_contract: str
    scenario_id: str
    direction: str
    signal_raw_record_hash: str
    entry_cutoff_receive_monotonic_ns: int
    state: str = "ENTRY_PENDING"
    entry_quote: _Quote | None = None
    entry_raw_record_hash: str | None = None
    horizon_active_time_ns: int | None = None
    exit_cutoff_receive_monotonic_ns: int | None = None
    exit_raw_record_hash: str | None = None
    last_source_event_utc_ns: int | None = None

    @property
    def lane(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.collector_generation,
            self.clock_epoch,
            self.exact_contract,
            self.session_family,
            self.segment_id,
            self.official_day,
        )


@dataclass(frozen=True)
class _AdmissionSlot:
    status: str
    attempt_id: str
    lane: tuple[str, str, str, str, str]


class _IndependentAdmissionLedger:
    def __init__(self) -> None:
        self.slots: dict[tuple[str, str], _AdmissionSlot] = {}
        self.admitted_attempt_ids: set[str] = set()
        self.admitted_signal_ids: set[str] = set()

    def admit(
        self,
        *,
        row: Mapping[str, object],
        official_day: str,
        scenario_id: str,
        direction: str,
        signal_id: str,
        attempt_id: str,
        eligible: bool,
    ) -> dict[str, object]:
        contract = str(row["exact_contract"])
        key = (scenario_id, contract)
        current = self.slots.get(key)
        before = current.status if current else "IDLE"
        base: dict[str, object] = {
            "run_id": row["run_id"],
            "collector_generation": row["collector_generation"],
            "clock_epoch": row["clock_epoch"],
            "segment_id": row["segment_id"],
            "official_day": official_day,
            "exact_contract": contract,
            "scenario_id": scenario_id,
            "direction": direction,
            "threshold_crossing_id": signal_id,
            "proposed_trade_id": attempt_id,
            "callback_seq": row["collector_seq"],
        }
        if not eligible:
            return {
                **base,
                "decision": "INELIGIBLE",
                "state_before": before,
                "state_after": before,
                "accepted_trade_id": None,
                "blocker": "SIGNAL_INELIGIBLE",
                "blocking_trade_id": None,
            }
        if current is not None:
            return {
                **base,
                "decision": "SUPPRESSED",
                "state_before": before,
                "state_after": before,
                "accepted_trade_id": None,
                "blocker": f"OCCUPIED_{before}",
                "blocking_trade_id": current.attempt_id,
            }
        if attempt_id in self.admitted_attempt_ids:
            _fail("ATTEMPT_ID_REUSED", attempt_id)
        signal_scenario_key = f"{signal_id}:{scenario_id}"
        if signal_scenario_key in self.admitted_signal_ids:
            _fail("SIGNAL_ID_REUSED", signal_scenario_key)
        lane = (
            str(row["run_id"]),
            str(row["collector_generation"]),
            str(row["clock_epoch"]),
            str(row["segment_id"]),
            official_day,
        )
        self.slots[key] = _AdmissionSlot("ENTRY_PENDING", attempt_id, lane)
        self.admitted_attempt_ids.add(attempt_id)
        self.admitted_signal_ids.add(signal_scenario_key)
        return {
            **base,
            "decision": "ADMITTED",
            "state_before": "IDLE",
            "state_after": "ENTRY_PENDING",
            "accepted_trade_id": attempt_id,
            "blocker": None,
            "blocking_trade_id": None,
        }

    def transition(self, attempt: _Attempt, target: str) -> None:
        key = (attempt.scenario_id, attempt.exact_contract)
        current = self.slots.get(key)
        if current is None or current.attempt_id != attempt.attempt_id:
            _fail("ADMISSION_OWNER", attempt.attempt_id)
        allowed = {
            ("ENTRY_PENDING", "OPEN"),
            ("OPEN", "EXIT_PENDING"),
            ("EXIT_PENDING", "IDLE"),
            ("OPEN", "IDLE"),
            ("ENTRY_PENDING", "IDLE"),
        }
        if (current.status, target) not in allowed:
            _fail("ADMISSION_TRANSITION", f"{current.status}->{target}")
        if target == "IDLE":
            self.slots.pop(key)
        else:
            self.slots[key] = _AdmissionSlot(target, current.attempt_id, current.lane)


def _coverage_eligibility(freeze: _Freeze, row: Mapping[str, object]) -> str | None:
    identity = (
        row.get("exact_contract"),
        row.get("official_trading_day"),
        row.get("session_family"),
        row.get("segment_id"),
    )
    matches = [
        item
        for item in freeze.coverage_plan
        if (
            item["exact_contract"],
            item["official_day"],
            item["session_family"],
            item["segment_id"],
        )
        == identity
    ]
    if len(matches) != 1:
        return "PIT_SEGMENT_NOT_UNIQUE"
    plan = matches[0]
    received = _integer(
        row.get("callback_entry_receive_utc_ns"), "signal.receive_utc_ns", 1
    )
    start = int(plan["start_utc_ns"])
    end = int(plan["end_utc_ns"])
    if not start <= received < end:
        return "PIT_SEGMENT_OUTSIDE_INTERVAL"
    if end - received < 60_000_000_000:
        return "PIT_SEGMENT_REMAINING_TOO_SHORT"
    if int(plan["days_to_ltd"]) <= 10:
        return "PIT_DAYS_TO_LTD_TOO_SHORT"
    return None if plan["eligible"] is True else "PIT_SEGMENT_INELIGIBLE"


def _attempt_trace(
    attempt: _Attempt,
    *,
    status: str,
    terminal_reason: str | None,
    terminal_boundary_kind: str,
    terminal_callback_seq: int | None,
    terminal_raw_record_hash: str | None,
) -> dict[str, object]:
    return {
        "attempt_id": attempt.attempt_id,
        "signal_id": attempt.signal_id,
        "run_id": attempt.run_id,
        "collector_generation": attempt.collector_generation,
        "clock_epoch": attempt.clock_epoch,
        "segment_id": attempt.segment_id,
        "session_family": attempt.session_family,
        "official_day": attempt.official_day,
        "exact_contract": attempt.exact_contract,
        "scenario_id": attempt.scenario_id,
        "direction": attempt.direction,
        "signal_raw_record_hash": attempt.signal_raw_record_hash,
        "entry_raw_record_hash": attempt.entry_raw_record_hash,
        "exit_raw_record_hash": attempt.exit_raw_record_hash,
        "entry_cutoff_receive_monotonic_ns": (
            attempt.entry_cutoff_receive_monotonic_ns
        ),
        "horizon_active_time_ns": attempt.horizon_active_time_ns,
        "exit_cutoff_receive_monotonic_ns": (
            attempt.exit_cutoff_receive_monotonic_ns
        ),
        "grace_active_time_ns": (
            attempt.horizon_active_time_ns + EXIT_GRACE_NS
            if attempt.horizon_active_time_ns is not None
            else None
        ),
        "status": status,
        "terminal_reason": terminal_reason,
        "terminal_boundary_kind": terminal_boundary_kind,
        "terminal_callback_seq": terminal_callback_seq,
        "terminal_raw_record_hash": terminal_raw_record_hash,
        "terminal_position_lots": (
            1
            if status == "UNPRICED_TERMINAL" and attempt.direction == "LONG"
            else -1
            if status == "UNPRICED_TERMINAL"
            else 0
        ),
    }


def _resolve_binding(
    bindings: Sequence[_Binding],
    *,
    exact_contract: str,
    official_day: str,
    utc_ns: int,
    offset: str | None = None,
) -> _Binding:
    matches = [
        item
        for item in bindings
        if item.exact_contract == exact_contract
        and item.official_day == official_day
        and item.valid_from_utc_ns <= utc_ns < item.valid_until_utc_ns
        and (offset is None or item.offset == offset)
    ]
    if len(matches) != 1:
        _fail(
            "PIT_BINDING_COUNT",
            f"exactly one binding is required; got {len(matches)}",
        )
    return matches[0]


def _on_grid(price: Decimal, tick_size: Decimal) -> Decimal:
    if price <= 0 or price / tick_size != (price / tick_size).to_integral_value():
        _fail("OFF_TICK_PRICE", "price is invalid or off tick grid")
    return price


def _fees(
    price: Decimal,
    terms: _Binding,
    exchange: _Binding,
    broker: _Binding,
) -> tuple[Decimal, Decimal]:
    assert terms.multiplier is not None
    assert exchange.fixed_cny is not None and exchange.ratio_per_mille is not None
    assert broker.fixed_cny is not None and broker.ratio_per_mille is not None
    with localcontext() as context:
        context.prec = 50
        base = price * terms.multiplier / Decimal(1000)
        exchange_fee = exchange.fixed_cny + base * exchange.ratio_per_mille
        broker_fee = broker.fixed_cny + base * broker.ratio_per_mille
    return (
        exchange_fee.quantize(FEE_QUANTUM, rounding=ROUND_HALF_UP),
        broker_fee.quantize(FEE_QUANTUM, rounding=ROUND_HALF_UP),
    )


def _quote_json(quote: _Quote) -> dict[str, object]:
    if any(
        item is None
        for item in (quote.bid, quote.bid_size, quote.ask, quote.ask_size)
    ):
        _fail("UNREPRESENTABLE_EXECUTION_QUOTE", quote.raw_record_hash)
    assert quote.bid is not None and quote.bid_size is not None
    assert quote.ask is not None and quote.ask_size is not None
    return {
        "exact_contract": quote.exact_contract,
        "raw_record_hash": quote.raw_record_hash,
        "collector_generation": quote.collector_generation,
        "clock_epoch": quote.clock_epoch,
        "segment_id": quote.segment_id,
        "collector_seq": quote.collector_seq,
        "provider_update_id": quote.provider_update_id,
        "source_event_utc_ns": quote.source_event_utc_ns,
        "receive_utc_ns": quote.receive_utc_ns,
        "receive_monotonic_ns": quote.receive_monotonic_ns,
        "active_time_ns": quote.active_time_ns,
        "official_day": quote.official_day,
        "bid": _decimal_text(quote.bid),
        "bid_size": _decimal_text(quote.bid_size),
        "ask": _decimal_text(quote.ask),
        "ask_size": _decimal_text(quote.ask_size),
        "clock_sync_state": quote.row["clock_sync_state"],
        "reset_reason": None,
        "explicit_duplicate": False,
    }


def _make_leg(
    freeze: _Freeze,
    attempt: _Attempt,
    quote: _Quote,
    *,
    leg: str,
) -> dict[str, object]:
    scenario = _SCENARIOS[attempt.scenario_id]
    buy = (attempt.direction == "LONG" and leg == "OPEN") or (
        attempt.direction == "SHORT" and leg == "CLOSE"
    )
    side = "BUY" if buy else "SELL"
    if not quote.execution_usable(side):
        _fail(
            "EXECUTION_QUOTE_UNUSABLE",
            "quote is not execution-usable for actual side",
        )
    offset = "OPEN" if leg == "OPEN" else "CLOSE_TODAY"
    terms = _resolve_binding(
        freeze.instrument_terms,
        exact_contract=attempt.exact_contract,
        official_day=quote.official_day,
        utc_ns=quote.receive_utc_ns,
    )
    exchange = _resolve_binding(
        freeze.fee_schedules,
        exact_contract=attempt.exact_contract,
        official_day=quote.official_day,
        utc_ns=quote.receive_utc_ns,
        offset=offset,
    )
    broker = _resolve_binding(
        freeze.broker_markups,
        exact_contract=attempt.exact_contract,
        official_day=quote.official_day,
        utc_ns=quote.receive_utc_ns,
        offset=offset,
    )
    assert terms.tick_size is not None and terms.multiplier is not None
    observed = quote.ask if buy else quote.bid
    assert observed is not None
    adverse_ticks = int(scenario["adverse_ticks"])
    execution = (
        observed + terms.tick_size * adverse_ticks
        if buy
        else observed - terms.tick_size * adverse_ticks
    )
    execution = _on_grid(execution, terms.tick_size)
    exchange_fee, broker_fee = _fees(execution, terms, exchange, broker)
    before, after = (
        ((0, 1) if leg == "OPEN" else (1, 0))
        if attempt.direction == "LONG"
        else ((0, -1) if leg == "OPEN" else (-1, 0))
    )
    return {
        "exact_contract": attempt.exact_contract,
        "scenario_id": attempt.scenario_id,
        "direction": attempt.direction,
        "leg": leg,
        "side": side,
        "offset": offset,
        "signed_lots": 1 if buy else -1,
        "abs_lots": 1,
        "position_before": before,
        "position_after": after,
        "quote": _quote_json(quote),
        "observed_aggressive_price": _decimal_text(observed),
        "execution_price": _decimal_text(execution),
        "adverse_ticks": adverse_ticks,
        "tick_size": _decimal_text(terms.tick_size),
        "multiplier": _decimal_text(terms.multiplier),
        "instrument_terms_binding_id": terms.binding_id,
        "fee_schedule_binding_id": exchange.binding_id,
        "broker_markup_binding_id": broker.binding_id,
        "fee_rounding_quantum": "0.01",
        "fee_rounding_mode": "ROUND_HALF_UP",
        "exchange_fee_cny": _decimal_text(exchange_fee),
        "broker_fee_cny": _decimal_text(broker_fee),
    }


def _closed_trade(
    freeze: _Freeze, attempt: _Attempt, exit_quote: _Quote
) -> dict[str, object]:
    if attempt.entry_quote is None:
        _fail("CLOSED_WITHOUT_ENTRY", attempt.attempt_id)
    if (
        exit_quote.collector_seq <= attempt.entry_quote.collector_seq
        or exit_quote.source_event_utc_ns
        < attempt.entry_quote.source_event_utc_ns
        or exit_quote.receive_utc_ns <= attempt.entry_quote.receive_utc_ns
        or exit_quote.receive_monotonic_ns
        <= attempt.entry_quote.receive_monotonic_ns
        or exit_quote.active_time_ns <= attempt.entry_quote.active_time_ns
    ):
        _fail(
            "ACCOUNTING_TIME_ORDER",
            "entry and exit sequence and times must strictly increase",
        )
    entry = _make_leg(freeze, attempt, attempt.entry_quote, leg="OPEN")
    exit_leg = _make_leg(freeze, attempt, exit_quote, leg="CLOSE")
    if attempt.entry_quote.official_day != exit_quote.official_day:
        _fail(
            "CROSS_DAY_CLOSE",
            "current P1 candidates cannot cross official trading day",
        )
    if (
        entry["tick_size"],
        entry["multiplier"],
    ) != (exit_leg["tick_size"], exit_leg["multiplier"]):
        _fail(
            "PIT_TERMS_CHANGED",
            "entry and exit PIT terms must have equal tick size and multiplier",
        )
    entry_price = _decimal(entry["execution_price"], "entry.execution_price")
    exit_price = _decimal(exit_leg["execution_price"], "exit.execution_price")
    tick_size = _decimal(entry["tick_size"], "entry.tick_size")
    multiplier = _decimal(entry["multiplier"], "entry.multiplier")
    gross_ticks = (
        exit_price - entry_price
        if attempt.direction == "LONG"
        else entry_price - exit_price
    ) / tick_size
    gross = gross_ticks * tick_size * multiplier
    exchange_fee = _decimal(entry["exchange_fee_cny"], "entry.exchange_fee")
    exchange_fee += _decimal(exit_leg["exchange_fee_cny"], "exit.exchange_fee")
    broker_fee = _decimal(entry["broker_fee_cny"], "entry.broker_fee")
    broker_fee += _decimal(exit_leg["broker_fee_cny"], "exit.broker_fee")
    return {
        "attempt_id": attempt.attempt_id,
        "exact_contract": attempt.exact_contract,
        "scenario_id": attempt.scenario_id,
        "direction": attempt.direction,
        "status": "CLOSED",
        "failure_reason": None,
        "entry": entry,
        "exit": exit_leg,
        "gross_ticks": _decimal_text(gross_ticks),
        "gross_cny": _decimal_text(gross),
        "exchange_fee_cny": _decimal_text(exchange_fee),
        "broker_fee_cny": _decimal_text(broker_fee),
        "net_cny": _decimal_text(gross - exchange_fee - broker_fee),
    }


@dataclass
class _SegmentFacts:
    run_id: str
    generations: set[str] = field(default_factory=set)
    start_rows: list[dict[str, object]] = field(default_factory=list)
    end_rows: list[dict[str, object]] = field(default_factory=list)
    quote_rows: list[dict[str, object]] = field(default_factory=list)
    lifecycle_failed: bool = False


@dataclass(frozen=True)
class _ReplayResult:
    bundle: dict[str, object]
    holdout_gate: str
    holdout_reasons: tuple[str, ...]


def _plan_key_from_row(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(row.get("exact_contract")),
        str(row.get("official_trading_day")),
        str(row.get("session_family")),
        str(row.get("segment_id")),
    )


def _plan_key(plan: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(plan["exact_contract"]),
        str(plan["official_day"]),
        str(plan["session_family"]),
        str(plan["segment_id"]),
    )


def _control_scope(row: Mapping[str, object]) -> str:
    event = row.get("event_type")
    scope = row.get("scope")
    if event in _GENERATION_GLOBAL_CONTROL_EVENTS:
        if scope != "GENERATION_GLOBAL":
            _fail("CONTROL_SCOPE", str(row.get("record_hash")))
        return "GENERATION_GLOBAL"
    if event in {"SESSION_SEGMENT_START", "SESSION_SEGMENT_END"}:
        if scope != "EXACT_CONTRACT_SEGMENT":
            _fail("CONTROL_SCOPE", str(row.get("record_hash")))
        for name in (
            "exact_contract",
            "session_family",
            "segment_id",
            "official_trading_day",
        ):
            _text(row.get(name), f"control.{name}")
        _day(row.get("official_trading_day"), "control.official_trading_day")
        return "EXACT_CONTRACT_SEGMENT"
    _fail("CONTROL_EVENT", str(event))


def _same_attempt_lane(attempt: _Attempt, quote: _Quote) -> bool:
    return attempt.lane == (
        quote.collector_generation,
        quote.clock_epoch,
        quote.exact_contract,
        quote.session_family,
        quote.segment_id,
        quote.official_day,
    )


def _clock_gate_reasons(rows: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    reasons: set[str] = set()
    lags: list[int] = []
    for row in rows:
        if row.get("record_type") != "QUOTE":
            continue
        if row.get("clock_sync_state") != "SYNCED":
            reasons.add("CLOCK_NOT_SYNCED")
            continue
        offset = _integer(row.get("clock_offset_ns"), "clock_offset_ns", -10**18)
        uncertainty = _integer(
            row.get("clock_uncertainty_ns"), "clock_uncertainty_ns"
        )
        precision = _integer(
            row.get("source_time_precision_ns"), "source_time_precision_ns", 1
        )
        if abs(offset) > 100_000_000:
            reasons.add("CLOCK_OFFSET_TOO_LARGE")
        if uncertainty > 25_000_000:
            reasons.add("CLOCK_UNCERTAINTY_TOO_LARGE")
        if precision > 1_000_000:
            reasons.add("SOURCE_TIME_TOO_COARSE")
        lag = (
            _integer(
                row.get("callback_entry_receive_utc_ns"),
                "callback_entry_receive_utc_ns",
                1,
            )
            + offset
            - _integer(row.get("source_event_utc_ns"), "source_event_utc_ns", 1)
        )
        if lag < 0:
            reasons.add("NEGATIVE_CORRECTED_LAG")
        else:
            lags.append(lag)
    if len(lags) < MINIMUM_CALIBRATION_SCORES:
        reasons.add("INSUFFICIENT_CLOCK_SAMPLES")
    elif not reasons:
        ordered = sorted(lags)
        rank = max(0, (99 * len(ordered) + 99) // 100 - 1)
        if ordered[rank] > 250_000_000:
            reasons.add("P99_LAG_TOO_LARGE")
    return tuple(sorted(reasons))


def _require_raw_quote_semantics(
    rows: Sequence[Mapping[str, object]], freeze: _Freeze
) -> None:
    """Eagerly reject schema smuggling in every QUOTE, including STOP suffixes."""

    canonical_text_fields = (
        "collector_generation",
        "clock_epoch",
        "segment_id",
        "provider_delivery_semantics",
        "provider_update_id_semantics",
        "source_event_time_raw",
        "clock_sample_id",
        "clock_sync_state",
        "product",
        "exact_contract",
        "exchange",
        "official_trading_day",
        "session_family",
        "parse_status",
        "duplicate_status",
        "source_status",
    )
    for row in rows:
        if row.get("record_type") != "QUOTE":
            continue
        for name in canonical_text_fields:
            _text(row.get(name), f"raw_quote.{name}")
        _day(row.get("official_trading_day"), "raw_quote.official_trading_day")
        if row.get("parse_status") != _SUCCESS_PARSE_STATUS:
            _fail("RAW_PARSE_STATUS", "raw quote parse status is not frozen")
        if row.get("source_status") != _SUCCESS_SOURCE_STATUS:
            _fail("RAW_SOURCE_STATUS", "raw quote source status is not frozen")
        if row.get("duplicate_status") not in {
            _ORDINARY_DUPLICATE_STATUS,
            "PROVEN_ADJACENT_EXACT_DUPLICATE",
        }:
            _fail("DUPLICATE_STATUS", "raw quote duplicate status is invalid")
        for name in ("provider_batch_id", "provider_update_id"):
            value = row.get(name)
            if value is not None:
                _text(value, f"raw_quote.{name}")
        _integer(row.get("within_batch_rank"), "raw_quote.within_batch_rank", 1)
        provider_status = _provider_status(freeze, row)
        if provider_status == "PROVEN_UNIQUE" and row.get(
            "provider_update_id"
        ) is None:
            _fail("PROVEN_PROVIDER_ID_MISSING", str(row.get("record_hash")))
        for name in (
            "bid_price1_raw",
            "bid_size1_raw",
            "ask_price1_raw",
            "ask_size1_raw",
            "last_price_raw",
            "cumulative_volume_raw",
            "cumulative_amount_raw",
            "open_interest_raw",
        ):
            value = row.get(name)
            if type(value) not in {str, int, type(None)}:
                _fail(
                    "RAW_BBO_TYPE",
                    f"{name} must retain string, integer, or null raw value",
                )
        _integer(row.get("collector_seq"), "raw_quote.collector_seq", 1)
        _integer(
            row.get("source_event_utc_ns"),
            "raw_quote.source_event_utc_ns",
            1,
        )
        _integer(
            row.get("callback_entry_receive_utc_ns"),
            "raw_quote.callback_entry_receive_utc_ns",
            1,
        )
        _integer(
            row.get("callback_entry_receive_monotonic_ns"),
            "raw_quote.callback_entry_receive_monotonic_ns",
            1,
        )
        _integer(row.get("clock_offset_ns"), "raw_quote.clock_offset_ns", -10**18)
        _integer(
            row.get("clock_uncertainty_ns"),
            "raw_quote.clock_uncertainty_ns",
        )
        _integer(
            row.get("source_time_precision_ns"),
            "raw_quote.source_time_precision_ns",
            1,
        )


def _require_complete_stream_preflight(
    rows: Sequence[Mapping[str, object]], freeze: _Freeze
) -> None:
    """Independently validate suffix lifecycle and provider-ID relations."""

    terminal_generations: set[str] = set()
    provider_ids: dict[tuple[str, str], str] = {}
    for row in rows:
        generation = _text(
            row.get("collector_generation"), "preflight.collector_generation"
        )
        if generation in terminal_generations:
            _fail("RECORD_AFTER_TERMINAL_CONTROL", str(row.get("record_hash")))
        if row.get("record_type") == "CONTROL":
            if row.get("event_type") in _ABORTING_CONTROL_EVENTS:
                terminal_generations.add(generation)
            continue
        status = _provider_status(freeze, row)
        explicit_marker = (
            row.get("duplicate_status")
            == "PROVEN_ADJACENT_EXACT_DUPLICATE"
        )
        provider_id = row.get("provider_update_id")
        if status != "PROVEN_UNIQUE":
            if explicit_marker:
                _fail(
                    "UNPROVEN_DUPLICATE_CLASSIFICATION",
                    str(row.get("record_hash")),
                )
            continue
        if not isinstance(provider_id, str) or not provider_id:
            _fail("PROVEN_PROVIDER_ID_MISSING", str(row.get("record_hash")))
        scope = (
            f"{row.get('provider_delivery_semantics')}|"
            f"{row.get('provider_update_id_semantics')}"
        )
        key = (scope, provider_id)
        payload_hash = _provider_payload_hash(row)
        prior = provider_ids.get(key)
        if prior is not None and prior != payload_hash:
            _fail("PROVIDER_ID_CONFLICT", str(row.get("record_hash")))
        duplicate = prior == payload_hash
        if explicit_marker and not duplicate:
            _fail("DUPLICATE_MARKER_WITHOUT_PRIOR", str(row.get("record_hash")))
        provider_ids[key] = payload_hash


def _coverage_quality_metrics(
    rows: Sequence[Mapping[str, object]],
    duplicate_record_hashes: set[str],
) -> dict[str, object]:
    """Independently recompute the frozen raw quality denominators for a cell."""

    legal_count = 0
    crossed_or_locked_count = 0
    mirrored_size_count = 0
    state_changing_count = 0
    mid_change_count = 0
    bid_sizes: set[Decimal] = set()
    ask_sizes: set[Decimal] = set()
    previous: dict[
        tuple[str, str, str, str, str],
        tuple[Decimal, Decimal, Decimal, Decimal],
    ] = {}
    for row in rows:
        lane = (
            _text(row.get("collector_generation"), "quality.generation"),
            _text(row.get("clock_epoch"), "quality.clock_epoch"),
            _text(row.get("exact_contract"), "quality.exact_contract"),
            _text(row.get("session_family"), "quality.session_family"),
            _text(row.get("segment_id"), "quality.segment_id"),
        )
        record_hash = _text(row.get("record_hash"), "quality.record_hash")
        bid = _optional_raw_decimal(row.get("bid_price1_raw"))
        ask = _optional_raw_decimal(row.get("ask_price1_raw"))
        if bid is not None and ask is not None and bid > 0 and ask > 0 and bid >= ask:
            crossed_or_locked_count += 1
        # A provider-proven exact duplicate remains in every raw-rate
        # numerator/denominator, but does not qualify, clear, or advance the
        # lane baseline used by state-change denominators.
        if record_hash in duplicate_record_hashes:
            continue
        bid_size = _optional_raw_decimal(row.get("bid_size1_raw"))
        ask_size = _optional_raw_decimal(row.get("ask_size1_raw"))
        if None in (bid, bid_size, ask, ask_size):
            previous.pop(lane, None)
            continue
        assert bid is not None and bid_size is not None
        assert ask is not None and ask_size is not None
        legal = (
            row.get("parse_status") == _SUCCESS_PARSE_STATUS
            and row.get("source_status") == _SUCCESS_SOURCE_STATUS
            and bid > 0
            and ask > 0
            and bid_size > 0
            and ask_size > 0
            and bid < ask
        )
        if not legal:
            previous.pop(lane, None)
            continue
        legal_count += 1
        bid_sizes.add(bid_size)
        ask_sizes.add(ask_size)
        if bid_size == ask_size:
            mirrored_size_count += 1
        current = (bid, bid_size, ask, ask_size)
        prior = previous.get(lane)
        if prior is not None:
            if current != prior:
                state_changing_count += 1
            if bid + ask != prior[0] + prior[2]:
                mid_change_count += 1
        previous[lane] = current

    denominator = len(rows)

    def ratio_text(numerator: int, divisor: int) -> str:
        if divisor == 0:
            return "0"
        with localcontext() as context:
            context.prec = 50
            return format(Decimal(numerator) / Decimal(divisor), "f")

    quality_gate = (
        denominator > 0
        and legal_count * 100 >= denominator * 99
        and len(bid_sizes) >= 20
        and len(ask_sizes) >= 20
        and mirrored_size_count * 100 <= legal_count * 95
        and crossed_or_locked_count * 1000 <= denominator
        and state_changing_count >= 5000
        and mid_change_count >= 500
    )
    return {
        "legal_bbo_count": legal_count,
        "legal_bbo_rate": ratio_text(legal_count, denominator),
        "distinct_positive_bid_sizes": len(bid_sizes),
        "distinct_positive_ask_sizes": len(ask_sizes),
        "mirrored_size_count": mirrored_size_count,
        "mirrored_size_ratio": ratio_text(mirrored_size_count, legal_count),
        "crossed_or_locked_count": crossed_or_locked_count,
        "crossed_or_locked_rate": ratio_text(
            crossed_or_locked_count, denominator
        ),
        "state_changing_observation_count": state_changing_count,
        "mid_change_count": mid_change_count,
        "quality_gate_passed": quality_gate,
    }


def _replay_independently(custody: _CustodyResult, freeze: _Freeze) -> _ReplayResult:
    _require_raw_quote_semantics(custody.rows, freeze)
    _require_complete_stream_preflight(custody.rows, freeze)
    preflight_clock_reasons = _clock_gate_reasons(custody.rows)
    hard_clock_reasons = tuple(
        reason
        for reason in preflight_clock_reasons
        if reason != "INSUFFICIENT_CLOCK_SAMPLES"
    )
    if hard_clock_reasons:
        _fail("CLOCK_GATE_FAILED", ",".join(hard_clock_reasons))
    feature_engine = _IndependentFeatureEngine()
    admissions = _IndependentAdmissionLedger()
    callback_trace: list[dict[str, object]] = []
    admission_rows: list[dict[str, object]] = []
    attempt_rows: list[dict[str, object]] = []
    trade_rows: list[dict[str, object]] = []
    open_attempts: dict[tuple[str, str], _Attempt] = {}
    provider_ids: dict[tuple[str, str], str] = {}
    duplicate_record_hashes: set[str] = set()
    segment_facts = {
        _plan_key(plan): _SegmentFacts(custody.run_id)
        for plan in freeze.coverage_plan
    }
    active_plan_cells: set[tuple[str, str, str, str]] = set()
    terminal_generations: set[str] = set()
    processed_record_hashes: set[str] = set()
    stream_generation: str | None = None
    stream_epoch: str | None = None
    last_receive_monotonic: int | None = None
    current_callback_seq: int | None = None
    current_record_hash: str | None = None
    stopped = False

    def finish_no_entry(
        attempt: _Attempt,
        reason: str,
        *,
        boundary_kind: str = "CALLBACK",
        boundary_callback_seq: int | None = None,
        boundary_raw_record_hash: str | None = None,
    ) -> None:
        admissions.transition(attempt, "IDLE")
        attempt_rows.append(
            _attempt_trace(
                attempt,
                status="FAILED_NO_ENTRY",
                terminal_reason=reason,
                terminal_boundary_kind=boundary_kind,
                terminal_callback_seq=(
                    current_callback_seq
                    if boundary_kind == "CALLBACK"
                    else boundary_callback_seq
                ),
                terminal_raw_record_hash=(
                    current_record_hash
                    if boundary_kind == "CALLBACK"
                    else boundary_raw_record_hash
                ),
            )
        )
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)

    def finish_unpriced(
        attempt: _Attempt,
        reason: str,
        *,
        boundary_kind: str = "CALLBACK",
        boundary_callback_seq: int | None = None,
        boundary_raw_record_hash: str | None = None,
    ) -> None:
        admissions.transition(attempt, "IDLE")
        attempt_rows.append(
            _attempt_trace(
                attempt,
                status="UNPRICED_TERMINAL",
                terminal_reason=reason,
                terminal_boundary_kind=boundary_kind,
                terminal_callback_seq=(
                    current_callback_seq
                    if boundary_kind == "CALLBACK"
                    else boundary_callback_seq
                ),
                terminal_raw_record_hash=(
                    current_record_hash
                    if boundary_kind == "CALLBACK"
                    else boundary_raw_record_hash
                ),
            )
        )
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)

    def finish_closed(attempt: _Attempt, quote: _Quote, timeout: bool) -> bool:
        attempt.exit_raw_record_hash = quote.raw_record_hash
        try:
            trade = _closed_trade(freeze, attempt, quote)
        except AuditorContractError as exc:
            admissions.transition(attempt, "IDLE")
            attempt_rows.append(
                _attempt_trace(
                    attempt,
                    status="UNPRICED_TERMINAL",
                    terminal_reason=f"ACCOUNTING:{exc.detail}",
                    terminal_boundary_kind="QUOTE",
                    terminal_callback_seq=quote.collector_seq,
                    terminal_raw_record_hash=quote.raw_record_hash,
                )
            )
            open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)
            return False
        admissions.transition(attempt, "IDLE")
        attempt_rows.append(
            _attempt_trace(
                attempt,
                status=(
                    "CLOSED_TERMINAL_TIMEOUT" if timeout else "CLOSED_NORMAL"
                ),
                terminal_reason="EXIT_GRACE_EXCEEDED" if timeout else None,
                terminal_boundary_kind="QUOTE",
                terminal_callback_seq=quote.collector_seq,
                terminal_raw_record_hash=quote.raw_record_hash,
            )
        )
        trade_rows.append(trade)
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)
        return True

    for row_index, row in enumerate(custody.rows):
        generation = _text(
            row.get("collector_generation"), f"rows[{row_index}].generation"
        )
        epoch = _text(row.get("clock_epoch"), f"rows[{row_index}].clock_epoch")
        seq = _integer(row.get("collector_seq"), f"rows[{row_index}].seq", 1)
        current_callback_seq = seq
        current_record_hash = str(row["record_hash"])
        receive_monotonic = _integer(
            row.get("callback_entry_receive_monotonic_ns"),
            f"rows[{row_index}].receive_monotonic",
            1,
        )
        generation_changed = generation != stream_generation
        clock_epoch_changed = epoch != stream_epoch
        epoch_changed = not generation_changed and clock_epoch_changed
        actions: list[str] = []
        if generation in terminal_generations:
            _fail("RECORD_AFTER_TERMINAL_CONTROL", str(row["record_hash"]))
        if stream_generation is not None and generation_changed:
            prior_generation = stream_generation
            for attempt in tuple(open_attempts.values()):
                if attempt.collector_generation != prior_generation:
                    continue
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(
                        attempt,
                        "COLLECTOR_GENERATION_CHANGE",
                        boundary_kind="COLLECTOR_GENERATION_CHANGE",
                        boundary_callback_seq=seq,
                        boundary_raw_record_hash=current_record_hash,
                    )
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(
                        attempt,
                        "COLLECTOR_GENERATION_CHANGE",
                        boundary_kind="COLLECTOR_GENERATION_CHANGE",
                        boundary_callback_seq=seq,
                        boundary_raw_record_hash=current_record_hash,
                    )
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
                    stopped = True
                    break
            if stopped:
                for attempt in tuple(open_attempts.values()):
                    if attempt.state == "ENTRY_PENDING":
                        finish_no_entry(
                            attempt,
                            "GLOBAL_STOP_AFTER_UNPRICED",
                            boundary_kind="COLLECTOR_GENERATION_CHANGE",
                            boundary_callback_seq=seq,
                            boundary_raw_record_hash=current_record_hash,
                        )
                        actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                    else:
                        finish_unpriced(
                            attempt,
                            "GLOBAL_STOP_AFTER_UNPRICED",
                            boundary_kind="COLLECTOR_GENERATION_CHANGE",
                            boundary_callback_seq=seq,
                            boundary_raw_record_hash=current_record_hash,
                        )
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                callback_trace.append(
                    {
                        "callback_seq": seq,
                        "raw_record_hash": row["record_hash"],
                        "record_type": row.get("record_type"),
                        "event_type": row.get("event_type"),
                        "feature_status": "TERMINAL_STOP",
                        "feature_reset_reason": "COLLECTOR_GENERATION_CHANGE",
                        "signal_ids": [],
                        "actions": actions,
                    }
                )
                break
        if generation_changed or epoch_changed:
            last_receive_monotonic = None
        if (
            last_receive_monotonic is not None
            and receive_monotonic < last_receive_monotonic
        ):
            _fail("RECEIVE_MONOTONIC_REGRESSION", str(row["record_hash"]))
        last_receive_monotonic = receive_monotonic
        stream_generation, stream_epoch = generation, epoch
        if stopped:
            _fail("RECORD_AFTER_UNPRICED_STOP", str(row["record_hash"]))

        if row.get("record_type") == "CONTROL":
            scope = _control_scope(row)
            event = str(row["event_type"])
            if event == "COLLECTOR_START" and not generation_changed:
                _fail("COLLECTOR_START_WITHOUT_NEW_GENERATION", current_record_hash)
            if event == "CLOCK_EPOCH_CHANGE" and not clock_epoch_changed:
                _fail("CLOCK_EPOCH_CONTROL_WITHOUT_CHANGE", current_record_hash)
            affected = [
                attempt
                for attempt in open_attempts.values()
                if scope == "GENERATION_GLOBAL"
                or (
                    attempt.collector_generation == generation
                    and attempt.clock_epoch == epoch
                    and attempt.exact_contract == row.get("exact_contract")
                    and attempt.session_family == row.get("session_family")
                    and attempt.segment_id == row.get("segment_id")
                    and attempt.official_day
                    == row.get("official_trading_day")
                )
            ]
            for attempt in tuple(affected):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(attempt, "CONTROL_LANE_END")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(attempt, "CONTROL_LANE_END")
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
                    stopped = True
                    break
            if stopped:
                # UNPRICED is a global research STOP.  Resolve every other
                # owned slot on the same callback so neither later sealed rows
                # nor the synthetic stream-end phase can disguise its cause.
                for attempt in tuple(open_attempts.values()):
                    if attempt.state == "ENTRY_PENDING":
                        finish_no_entry(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                        actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                    else:
                        finish_unpriced(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
            if scope == "GENERATION_GLOBAL":
                feature_engine.clear_all()
                if event in {
                    "DISCONNECT",
                    "RECONNECT",
                    "BACKPRESSURE_ABORT",
                    "SINK_FAILURE_ABORT",
                    "COLLECTOR_STOP",
                }:
                    for key in active_plan_cells:
                        segment_facts[key].lifecycle_failed = True
                    active_plan_cells.clear()
            else:
                feature_engine.clear_lane(row)
                key = _plan_key_from_row(row)
                facts = segment_facts.get(key)
                if facts is not None:
                    facts.generations.add(generation)
                    if event == "SESSION_SEGMENT_START":
                        facts.start_rows.append(dict(row))
                        if key in active_plan_cells:
                            facts.lifecycle_failed = True
                        active_plan_cells.add(key)
                    else:
                        facts.end_rows.append(dict(row))
                        if key not in active_plan_cells:
                            facts.lifecycle_failed = True
                        active_plan_cells.discard(key)
            if event in _ABORTING_CONTROL_EVENTS:
                terminal_generations.add(generation)
            callback_trace.append(
                {
                    "callback_seq": seq,
                    "raw_record_hash": row["record_hash"],
                    "record_type": "CONTROL",
                    "event_type": event,
                    "feature_status": None,
                    "feature_reset_reason": None,
                    "signal_ids": [],
                    "actions": actions or ["CONTROL"],
                }
            )
            processed_record_hashes.add(str(row["record_hash"]))
            if stopped:
                break
            continue
        if row.get("record_type") != "QUOTE":
            _fail("RAW_RECORD_TYPE", str(row.get("record_hash")))

        quote = _quote_from_raw(row, freeze, provider_ids=provider_ids)
        if quote.explicit_duplicate:
            duplicate_record_hashes.add(quote.raw_record_hash)
        facts = segment_facts.get(_plan_key_from_row(row))
        if facts is not None:
            facts.quote_rows.append(dict(row))
            facts.generations.add(generation)

        # Generation changes were handled above.  Every remaining quote-level
        # lane/day boundary is meaningful only for its exact contract; an
        # interleaved contract may advance global ordering or reset feature
        # state, but cannot terminalize this contract's economic attempt.
        boundary_attempts: list[_Attempt] = []
        for attempt in open_attempts.values():
            contract_boundary = (
                attempt.exact_contract == quote.exact_contract
                and not _same_attempt_lane(attempt, quote)
            )
            if contract_boundary:
                boundary_attempts.append(attempt)
        for attempt in tuple(boundary_attempts):
            if attempt.state == "ENTRY_PENDING":
                finish_no_entry(attempt, "EXACT_CONTRACT_LANE_CHANGE")
                actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
            else:
                finish_unpriced(attempt, "EXACT_CONTRACT_LANE_CHANGE")
                actions.append(f"UNPRICED:{attempt.attempt_id}")
                stopped = True
                break
        if stopped:
            for attempt in tuple(open_attempts.values()):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
            callback_trace.append(
                {
                    "callback_seq": seq,
                    "raw_record_hash": row["record_hash"],
                    "record_type": "QUOTE",
                    "event_type": None,
                    "feature_status": "TERMINAL_STOP",
                    "feature_reset_reason": None,
                    "signal_ids": [],
                    "actions": actions,
                }
            )
            break

        preview_reset = feature_engine.preview_reset(
            quote,
            generation_changed=generation_changed,
            epoch_changed=epoch_changed,
        )
        for scenario_id in ("PRIMARY", "STRESS"):
            key = (scenario_id, quote.exact_contract)
            attempt = open_attempts.get(key)
            if attempt is None or not _same_attempt_lane(attempt, quote):
                continue
            if quote.explicit_duplicate:
                continue
            entry_side = "BUY" if attempt.direction == "LONG" else "SELL"
            exit_side = "SELL" if attempt.direction == "LONG" else "BUY"
            if attempt.state == "ENTRY_PENDING":
                if preview_reset in {
                    "COLLECTOR_GENERATION",
                    "CLOCK_EPOCH",
                    "INVALID_BBO",
                    "SOURCE_TIME_REGRESSION",
                    "ACTIVE_TIME_REGRESSION",
                    "LONG_GAP",
                }:
                    finish_no_entry(attempt, "FEATURE_RESET")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                elif (
                    quote.execution_usable(entry_side)
                    and quote.receive_monotonic_ns
                    >= attempt.entry_cutoff_receive_monotonic_ns
                ):
                    attempt.state = "OPEN"
                    attempt.entry_quote = quote
                    attempt.entry_raw_record_hash = quote.raw_record_hash
                    attempt.horizon_active_time_ns = (
                        quote.active_time_ns + HOLDING_HORIZON_NS
                    )
                    attempt.last_source_event_utc_ns = quote.source_event_utc_ns
                    admissions.transition(attempt, "OPEN")
                    open_attempts[key] = attempt
                    actions.append(f"ENTRY_FILLED:{attempt.attempt_id}")
                continue
            if not quote.qualified() or row.get("clock_sync_state") != "SYNCED":
                continue
            if (
                attempt.last_source_event_utc_ns is not None
                and quote.source_event_utc_ns < attempt.last_source_event_utc_ns
            ):
                continue
            attempt.last_source_event_utc_ns = quote.source_event_utc_ns
            if attempt.horizon_active_time_ns is None:
                _fail("OPEN_WITHOUT_HORIZON", attempt.attempt_id)
            grace = attempt.horizon_active_time_ns + EXIT_GRACE_NS
            if attempt.state == "OPEN":
                if quote.active_time_ns < attempt.horizon_active_time_ns:
                    continue
                if quote.active_time_ns > grace:
                    if quote.execution_usable(exit_side):
                        if finish_closed(attempt, quote, True):
                            actions.append(f"EXIT_TERMINAL:{attempt.attempt_id}")
                        else:
                            actions.append(f"UNPRICED:{attempt.attempt_id}")
                            stopped = True
                            break
                else:
                    attempt.state = "EXIT_PENDING"
                    attempt.exit_cutoff_receive_monotonic_ns = (
                        quote.receive_monotonic_ns
                        + int(_SCENARIOS[scenario_id]["exit_delay_ns"])
                    )
                    admissions.transition(attempt, "EXIT_PENDING")
                    open_attempts[key] = attempt
                    actions.append(f"EXIT_PENDING:{attempt.attempt_id}")
            elif attempt.state == "EXIT_PENDING":
                if quote.active_time_ns > grace:
                    if quote.execution_usable(exit_side):
                        if finish_closed(attempt, quote, True):
                            actions.append(f"EXIT_TERMINAL:{attempt.attempt_id}")
                        else:
                            actions.append(f"UNPRICED:{attempt.attempt_id}")
                            stopped = True
                            break
                elif (
                    attempt.exit_cutoff_receive_monotonic_ns is not None
                    and quote.receive_monotonic_ns
                    >= attempt.exit_cutoff_receive_monotonic_ns
                    and quote.execution_usable(exit_side)
                ):
                    if finish_closed(attempt, quote, False):
                        actions.append(f"EXIT_NORMAL:{attempt.attempt_id}")
                    else:
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                        stopped = True
                        break

        if stopped:
            for attempt in tuple(open_attempts.values()):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(attempt, "GLOBAL_STOP_AFTER_UNPRICED")
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
            callback_trace.append(
                {
                    "callback_seq": seq,
                    "raw_record_hash": row["record_hash"],
                    "record_type": "QUOTE",
                    "event_type": None,
                    "feature_status": "TERMINAL_STOP",
                    "feature_reset_reason": None,
                    "signal_ids": [],
                    "actions": actions,
                }
            )
            break

        if quote.explicit_duplicate:
            if generation_changed or epoch_changed:
                feature_engine.clear_all()
            callback_trace.append(
                {
                    "callback_seq": seq,
                    "raw_record_hash": row["record_hash"],
                    "record_type": "QUOTE",
                    "event_type": None,
                    "feature_status": "EXPLICIT_DUPLICATE_SKIPPED",
                    "feature_reset_reason": None,
                    "signal_ids": [],
                    "actions": actions + ["DUPLICATE_SKIPPED"],
                }
            )
            processed_record_hashes.add(str(row["record_hash"]))
            continue

        feature = feature_engine.process(
            quote,
            generation_changed=generation_changed,
            epoch_changed=epoch_changed,
        )
        signal_ids: list[str] = []
        if feature.status == "SCORE_READY" and feature.score is not None:
            threshold = freeze.thresholds.get(
                (quote.exact_contract, quote.session_family)
            )
            if (
                threshold is not None
                and feature.score != 0
                and abs(feature.score) >= threshold.threshold
            ):
                direction = "LONG" if feature.score > 0 else "SHORT"
                signal_id = _signal_id(row, direction, threshold.threshold)
                signal_ids.append(signal_id)
                actions.append(f"SIGNAL:{signal_id}")
                eligibility_reason = _coverage_eligibility(freeze, row)
                for scenario_id in ("PRIMARY", "STRESS"):
                    attempt_id = _attempt_id(signal_id, scenario_id)
                    admitted = admissions.admit(
                        row=row,
                        official_day=quote.official_day,
                        scenario_id=scenario_id,
                        direction=direction,
                        signal_id=signal_id,
                        attempt_id=attempt_id,
                        eligible=eligibility_reason is None,
                    )
                    admission_rows.append(admitted)
                    if admitted["decision"] == "ADMITTED":
                        open_attempts[(scenario_id, quote.exact_contract)] = _Attempt(
                            attempt_id=attempt_id,
                            signal_id=signal_id,
                            run_id=quote.run_id,
                            collector_generation=quote.collector_generation,
                            clock_epoch=quote.clock_epoch,
                            segment_id=quote.segment_id,
                            session_family=quote.session_family,
                            official_day=quote.official_day,
                            exact_contract=quote.exact_contract,
                            scenario_id=scenario_id,
                            direction=direction,
                            signal_raw_record_hash=quote.raw_record_hash,
                            entry_cutoff_receive_monotonic_ns=(
                                quote.receive_monotonic_ns
                                + int(_SCENARIOS[scenario_id]["entry_delay_ns"])
                            ),
                        )
                        actions.append(
                            f"ADMITTED:{attempt_id}:{scenario_id}"
                        )
                    else:
                        actions.append(
                            f"{admitted['decision']}:{signal_id}:{scenario_id}"
                        )
        callback_trace.append(
            {
                "callback_seq": seq,
                "raw_record_hash": row["record_hash"],
                "record_type": "QUOTE",
                "event_type": None,
                "feature_status": feature.status,
                "feature_reset_reason": feature.reset_reason,
                "signal_ids": signal_ids,
                "actions": actions,
            }
        )
        processed_record_hashes.add(str(row["record_hash"]))

    final_seq = int(callback_trace[-1]["callback_seq"])
    del final_seq  # stream-end terminalization is bound by the trusted head, not a callback
    for attempt in tuple(open_attempts.values()):
        if attempt.state == "ENTRY_PENDING":
            finish_no_entry(
                attempt,
                "SEALED_STREAM_END",
                boundary_kind="SEALED_STREAM_END",
            )
        else:
            finish_unpriced(
                attempt,
                "SEALED_STREAM_END",
                boundary_kind="SEALED_STREAM_END",
            )
            stopped = True

    coverage, coverage_gate, coverage_reasons = _derive_coverage(
        custody,
        freeze,
        segment_facts,
        admission_rows,
        attempt_rows,
        trade_rows,
        processed_record_hashes,
        duplicate_record_hashes,
    )
    clock_reasons = preflight_clock_reasons
    holdout_reasons = tuple(
        sorted(
            set(coverage_reasons)
            | set(clock_reasons)
            | {"AGGREGATION_NOT_COMPUTED"}
        )
    )
    blocking_only = {
        "AGGREGATION_NOT_COMPUTED",
        "HOLDOUT_GRID_NOT_FROZEN",
        "INSUFFICIENT_CLOCK_SAMPLES",
    }
    if coverage_gate == "FAIL_CLOSED" or any(
        reason not in blocking_only for reason in holdout_reasons
    ):
        holdout_gate = "FAIL_CLOSED"
    elif holdout_reasons:
        holdout_gate = "BLOCKED"
    else:
        holdout_gate = "PASS"
    return _ReplayResult(
        bundle={
            "schema_version": PRODUCER_BUNDLE_SCHEMA_VERSION,
            "callback_trace": callback_trace,
            "admissions": admission_rows,
            "attempts": attempt_rows,
            "trades": trade_rows,
            "coverage": coverage,
            "daily": [],
            "best3": [],
        },
        holdout_gate=holdout_gate,
        holdout_reasons=holdout_reasons,
    )


def _derive_coverage(
    custody: _CustodyResult,
    freeze: _Freeze,
    segment_facts: Mapping[tuple[str, str, str, str], _SegmentFacts],
    admissions: Sequence[Mapping[str, object]],
    attempts: Sequence[Mapping[str, object]],
    trades: Sequence[Mapping[str, object]],
    processed_record_hashes: set[str],
    duplicate_record_hashes: set[str],
) -> tuple[list[dict[str, object]], str, tuple[str, ...]]:
    del segment_facts  # independently rescan the sealed rows for coverage evidence
    plans = {_plan_key(plan): plan for plan in freeze.coverage_plan}
    signal_origins: dict[
        str,
        tuple[
            tuple[str, str, str, str],
            dict[str, object],
            str,
        ],
    ] = {}
    quote_counts: dict[tuple[str, str, str, str], int] = defaultdict(int)
    quote_records: dict[
        tuple[str, str, str, str], list[tuple[str, int, str]]
    ] = defaultdict(list)
    quality_rows: dict[
        tuple[str, str, str, str], list[dict[str, object]]
    ] = defaultdict(list)
    segment_events: dict[
        tuple[str, str, str, str], list[tuple[str, str, int, str]]
    ] = defaultdict(list)
    generations: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    clock_epochs: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    global_events: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for row in custody.rows:
        generation = str(row["collector_generation"])
        record_hash = str(row["record_hash"])
        callback_seq = int(row["collector_seq"])
        if row["record_type"] == "QUOTE":
            cell = _plan_key_from_row(row)
            if cell in plans:
                quote_counts[cell] += 1
                quote_records[cell].append(
                    (generation, callback_seq, record_hash)
                )
                quality_rows[cell].append(dict(row))
                generations[cell].add(generation)
                clock_epochs[cell].add(str(row["clock_epoch"]))
            threshold = freeze.thresholds.get(
                (str(row["exact_contract"]), str(row["session_family"]))
            )
            if threshold is not None:
                for direction in ("LONG", "SHORT"):
                    signal_id = _signal_id(row, direction, threshold.threshold)
                    if signal_id in signal_origins:
                        _fail("SIGNAL_ID_COLLISION", signal_id)
                    signal_origins[signal_id] = (cell, dict(row), direction)
            continue
        event = row.get("event_type")
        if row.get("scope") == "GENERATION_GLOBAL":
            global_events[generation].append(
                (str(event), callback_seq, record_hash)
            )
        if (
            row.get("scope") == "EXACT_CONTRACT_SEGMENT"
            and event in {"SESSION_SEGMENT_START", "SESSION_SEGMENT_END"}
        ):
            cell = _plan_key_from_row(row)
            if cell in plans:
                segment_events[cell].append(
                    (str(event), generation, callback_seq, record_hash)
                )
                generations[cell].add(generation)
                clock_epochs[cell].add(str(row["clock_epoch"]))

    coverage: list[dict[str, object]] = []
    reasons: list[str] = []
    for cell in sorted(plans):
        contract, official_day, session_family, segment_id = cell
        events = segment_events[cell]
        starts = [
            seq
            for event, _, seq, _ in events
            if event == "SESSION_SEGMENT_START"
        ]
        ends = [
            seq
            for event, _, seq, _ in events
            if event == "SESSION_SEGMENT_END"
        ]
        generation_values = generations[cell]
        generation = (
            next(iter(generation_values)) if len(generation_values) == 1 else None
        )
        epoch_values = clock_epochs[cell]
        clock_epoch = (
            next(iter(epoch_values)) if len(epoch_values) == 1 else None
        )
        closure_ok = (
            len(starts) == 1
            and len(ends) == 1
            and starts[0] < ends[0]
            and generation is not None
            and clock_epoch is not None
        )
        quotes_bounded = (
            closure_ok
            and all(
                quote_generation == generation
                and starts[0] < quote_seq < ends[0]
                for quote_generation, quote_seq, _ in quote_records[cell]
            )
        )
        cell_record_hashes = [
            record_hash for _, _, _, record_hash in events
        ]
        cell_record_hashes.extend(
            record_hash for _, _, record_hash in quote_records[cell]
        )
        replay_complete = closure_ok and all(
            record_hash in processed_record_hashes
            for record_hash in cell_record_hashes
        )
        quality_metrics = _coverage_quality_metrics(
            quality_rows[cell], duplicate_record_hashes
        )
        plan = plans[cell]
        plan_start = int(plan["start_utc_ns"])
        plan_end = int(plan["end_utc_ns"])
        coverage_plan_ok = (
            plan["eligible"] is True and int(plan["days_to_ltd"]) > 10
        )
        threshold_gate_ok = (contract, session_family) in freeze.thresholds

        def binding_matches_cell(
            binding: _Binding, offset: str | None
        ) -> bool:
            return (
                binding.exact_contract == contract
                and binding.official_day == official_day
                and (offset is None or binding.offset == offset)
            )

        def exact_nonoverlapping_binding(
            bindings: Sequence[_Binding], offset: str | None = None
        ) -> bool:
            overlapping = [
                binding
                for binding in bindings
                if binding_matches_cell(binding, offset)
                and binding.valid_from_utc_ns < plan_end
                and binding.valid_until_utc_ns > plan_start
            ]
            return (
                len(overlapping) == 1
                and overlapping[0].valid_from_utc_ns <= plan_start
                and overlapping[0].valid_until_utc_ns >= plan_end
            )

        accounting_binding_ok = exact_nonoverlapping_binding(
            freeze.instrument_terms
        ) and all(
            exact_nonoverlapping_binding(freeze.fee_schedules, offset)
            and exact_nonoverlapping_binding(freeze.broker_markups, offset)
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        )
        provider_semantics_ok = bool(quality_rows[cell]) and all(
            _provider_status(freeze, row)
            in {"PROVEN_NO_USABLE_ID", "PROVEN_UNIQUE"}
            for row in quality_rows[cell]
        )
        quote_receive_times = [
            _integer(
                row.get("callback_entry_receive_utc_ns"),
                "coverage.quote.receive_utc_ns",
                1,
            )
            for row in quality_rows[cell]
        ]
        quote_interval_ok = all(
            plan_start <= receive_utc_ns < plan_end
            for receive_utc_ns in quote_receive_times
        )
        entry_window_ok = any(
            plan_start <= receive_utc_ns < plan_end
            and plan_end - receive_utc_ns >= 60_000_000_000
            for receive_utc_ns in quote_receive_times
        )
        lifecycle_ok = False
        if generation is not None:
            lifecycle = global_events[generation]
            collector_starts = [
                seq
                for event, seq, _ in lifecycle
                if event == "COLLECTOR_START"
            ]
            collector_stops = [
                seq
                for event, seq, _ in lifecycle
                if event == "COLLECTOR_STOP"
            ]
            lifecycle_ok = len(collector_starts) == len(collector_stops) == 1
            if lifecycle_ok and len(starts) == 1 and len(ends) == 1:
                disruptive_inside_segment = any(
                    starts[0] < event_seq < ends[0]
                    and event
                    in {
                        "DISCONNECT",
                        "RECONNECT",
                        "CLOCK_EPOCH_CHANGE",
                        "BACKPRESSURE_ABORT",
                        "SINK_FAILURE_ABORT",
                    }
                    for event, event_seq, _ in lifecycle
                )
                lifecycle_ok = (
                    collector_starts[0] < starts[0] < ends[0] < collector_stops[0]
                    and not disruptive_inside_segment
                    and quotes_bounded
                )
        cell_attempts = [
            dict(item)
            for item in attempts
            if signal_origins.get(str(item.get("signal_id")), (None, None, None))[0]
            == cell
        ]
        cell_admissions = [
            dict(item)
            for item in admissions
            if signal_origins.get(
                str(item.get("threshold_crossing_id")), (None, None, None)
            )[0]
            == cell
        ]
        for scenario_id in ("PRIMARY", "STRESS"):
            scenario_attempts = [
                item
                for item in cell_attempts
                if item["scenario_id"] == scenario_id
            ]
            scenario_admissions = [
                item
                for item in cell_admissions
                if item["scenario_id"] == scenario_id
            ]
            admission_identity_ok = True
            admitted_id_values: list[str] = []
            for item in scenario_admissions:
                signal_id = str(item["threshold_crossing_id"])
                origin = signal_origins.get(signal_id)
                if origin is None:
                    admission_identity_ok = False
                    continue
                _, origin_row, direction = origin
                expected_attempt_id = _attempt_id(signal_id, scenario_id)
                admission_identity_ok = admission_identity_ok and all(
                    (
                        item.get("run_id") == origin_row.get("run_id"),
                        item.get("collector_generation")
                        == origin_row.get("collector_generation"),
                        item.get("clock_epoch") == origin_row.get("clock_epoch"),
                        item.get("segment_id") == origin_row.get("segment_id"),
                        item.get("official_day")
                        == origin_row.get("official_trading_day"),
                        item.get("exact_contract")
                        == origin_row.get("exact_contract"),
                        item.get("direction") == direction,
                        item.get("proposed_trade_id") == expected_attempt_id,
                    )
                )
                if item.get("decision") == "ADMITTED":
                    admitted_id_values.append(str(item.get("accepted_trade_id")))
                    admission_identity_ok = (
                        admission_identity_ok
                        and item.get("accepted_trade_id") == expected_attempt_id
                    )

            attempt_identity_ok = True
            attempt_id_values: list[str] = []
            for item in scenario_attempts:
                signal_id = str(item["signal_id"])
                origin = signal_origins.get(signal_id)
                if origin is None:
                    attempt_identity_ok = False
                    continue
                _, origin_row, direction = origin
                expected_attempt_id = _attempt_id(signal_id, scenario_id)
                attempt_id_values.append(str(item["attempt_id"]))
                attempt_identity_ok = attempt_identity_ok and all(
                    (
                        item.get("attempt_id") == expected_attempt_id,
                        item.get("signal_raw_record_hash")
                        == origin_row.get("record_hash"),
                        item.get("run_id") == origin_row.get("run_id"),
                        item.get("collector_generation")
                        == origin_row.get("collector_generation"),
                        item.get("clock_epoch") == origin_row.get("clock_epoch"),
                        item.get("segment_id") == origin_row.get("segment_id"),
                        item.get("official_day")
                        == origin_row.get("official_trading_day"),
                        item.get("exact_contract")
                        == origin_row.get("exact_contract"),
                        item.get("direction") == direction,
                    )
                )
            attempt_ids = set(attempt_id_values)
            scenario_trades = [
                dict(item) for item in trades if item.get("attempt_id") in attempt_ids
            ]
            trade_id_values = [str(item.get("attempt_id")) for item in scenario_trades]
            closed_ids = {
                str(item["attempt_id"])
                for item in scenario_attempts
                if item["status"]
                in {"CLOSED_NORMAL", "CLOSED_TERMINAL_TIMEOUT"}
            }
            trade_bijection = (
                len(trade_id_values) == len(set(trade_id_values))
                and set(trade_id_values) == closed_ids
                and all(
                    item.get("status") == "CLOSED"
                    and item.get("scenario_id") == scenario_id
                    and item.get("exact_contract") == contract
                    for item in scenario_trades
                )
            )
            terminal_counts: dict[str, int] = defaultdict(int)
            for item in scenario_attempts:
                terminal_counts[str(item["status"])] += 1
            all_priced = all(
                item["status"]
                in {
                    "CLOSED_NORMAL",
                    "CLOSED_TERMINAL_TIMEOUT",
                    "FAILED_NO_ENTRY",
                }
                for item in scenario_attempts
            )
            admitted_count = sum(
                item["decision"] == "ADMITTED" for item in scenario_admissions
            )
            resolved_count = len(scenario_attempts)
            all_resolved = (
                admission_identity_ok
                and attempt_identity_ok
                and len(admitted_id_values) == len(set(admitted_id_values))
                and len(attempt_id_values) == len(attempt_ids)
                and set(admitted_id_values) == attempt_ids
            )
            data_gate = (
                replay_complete
                and lifecycle_ok
                and bool(quality_metrics["quality_gate_passed"])
                and coverage_plan_ok
                and threshold_gate_ok
                and accounting_binding_ok
                and provider_semantics_ok
                and quote_interval_ok
                and entry_window_ok
                and all_resolved
                and trade_bijection
                and all(
                item["status"] in {"CLOSED_NORMAL", "FAILED_NO_ENTRY"}
                for item in scenario_attempts
                )
            )
            coverage.append(
                {
                    "run_id": custody.run_id,
                    "collector_generation": generation,
                    "exact_contract": contract,
                    "official_day": official_day,
                    "session_family": session_family,
                    "segment_id": segment_id,
                    "scenario_id": scenario_id,
                    "raw_segment_started": len(starts) == 1,
                    "raw_segment_ended": len(ends) == 1,
                    "raw_quote_count": quote_counts[cell],
                    "replay_complete": replay_complete,
                    "lifecycle_gate_passed": lifecycle_ok,
                    "clock_epoch_gate_passed": clock_epoch is not None,
                    "coverage_plan_gate_passed": coverage_plan_ok,
                    "threshold_gate_passed": threshold_gate_ok,
                    "accounting_binding_gate_passed": accounting_binding_ok,
                    "provider_semantics_gate_passed": provider_semantics_ok,
                    "quote_interval_gate_passed": quote_interval_ok,
                    "entry_window_gate_passed": entry_window_ok,
                    **quality_metrics,
                    "admitted_count": admitted_count,
                    "suppressed_count": sum(
                        item["decision"] == "SUPPRESSED"
                        for item in scenario_admissions
                    ),
                    "ineligible_count": sum(
                        item["decision"] == "INELIGIBLE"
                        for item in scenario_admissions
                    ),
                    "terminal_counts": dict(sorted(terminal_counts.items())),
                    "resolved_attempt_count": resolved_count,
                    "all_attempts_resolved": all_resolved,
                    "terminal_partition_hash": custody.terminal_partition_hash,
                    "terminal_seal_id": custody.terminal_seal_id,
                    "coverage_plan_sha256": _canonical_sha256(plans[cell]),
                    "attempt_sha256": _canonical_sha256(
                        {"attempts": scenario_attempts}
                    ),
                    "trade_sha256": _canonical_sha256(
                        {"trades": scenario_trades}
                    ),
                    "all_attempts_priced": all_priced,
                    "data_gate_passed": data_gate,
                }
            )
            if not data_gate:
                reasons.append(
                    "COVERAGE_DATA_GATE_FAILED:"
                    f"{contract}/{official_day}/{session_family}/{segment_id}/"
                    f"{scenario_id}"
                )
    contracts = {str(plan["exact_contract"]) for plan in freeze.coverage_plan}
    days = {str(plan["official_day"]) for plan in freeze.coverage_plan}
    if len(contracts) != 2 or len(days) != 20:
        reasons.append("HOLDOUT_GRID_NOT_FROZEN")
    gate = (
        "FAIL_CLOSED"
        if any(reason.startswith("COVERAGE_DATA_GATE_FAILED") for reason in reasons)
        else "BLOCKED"
        if reasons
        else "PASS"
    )
    return coverage, gate, tuple(sorted(reasons))


_PRODUCER_FIELDS = (
    "schema_version",
    "callback_trace",
    "admissions",
    "attempts",
    "trades",
    "coverage",
    "daily",
    "best3",
)
_COLLECTIONS = _PRODUCER_FIELDS[1:]
_COLLECTION_KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "callback_trace": ("callback_seq", "raw_record_hash"),
    "admissions": ("threshold_crossing_id", "scenario_id"),
    "attempts": ("attempt_id",),
    "trades": ("attempt_id",),
    "coverage": (
        "exact_contract",
        "official_day",
        "session_family",
        "segment_id",
        "scenario_id",
    ),
    "daily": ("product", "scenario_id", "official_day"),
    "best3": ("product",),
}
_MAX_MISMATCH_DETAILS = 256
_MISSING = object()


@dataclass
class _MismatchCollector:
    total: int = 0
    rows: list[dict[str, object]] = field(default_factory=list)

    def add(
        self,
        *,
        collection: str,
        key: str,
        path: str,
        kind: str,
        auditor: object,
        producer: object,
    ) -> None:
        self.total += 1
        if len(self.rows) >= _MAX_MISMATCH_DETAILS:
            return
        self.rows.append(
            {
                "collection": collection,
                "key": key,
                "path": path,
                "kind": kind,
                "auditor": _brief_value(auditor),
                "producer": _brief_value(producer),
            }
        )


def _brief_value(value: object) -> object:
    if value is _MISSING:
        return "<MISSING>"
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is list:
        return {
            "json_type": "array",
            "length": len(value),
            "sha256": _canonical_sha256(value),
        }
    if type(value) is dict:
        return {
            "json_type": "object",
            "field_count": len(value),
            "sha256": _canonical_sha256(value),
        }
    return f"<{type(value).__name__}>"


def _row_key(collection: str, row: object, index: int) -> str:
    if type(row) is not dict:
        return f"@index:{index:012d}"
    fields = _COLLECTION_KEY_FIELDS[collection]
    if any(field_name not in row for field_name in fields):
        return f"@index:{index:012d}"
    values = [row[field_name] for field_name in fields]
    return _canonical_bytes(values).decode("utf-8")


def _index_collection(
    collection: str,
    values: Sequence[object],
    mismatches: _MismatchCollector,
    *,
    producer: bool,
) -> tuple[dict[str, object], list[str]]:
    indexed: dict[str, object] = {}
    ordered: list[str] = []
    side = "producer" if producer else "auditor"
    for index, row in enumerate(values):
        key = _row_key(collection, row, index)
        ordered.append(key)
        if type(row) is not dict:
            mismatches.add(
                collection=collection,
                key=key,
                path=f"$[{index}]",
                kind="ROW_SCHEMA",
                auditor=_MISSING if producer else row,
                producer=row if producer else _MISSING,
            )
        if key in indexed:
            mismatches.add(
                collection=collection,
                key=key,
                path=f"$[{index}]",
                kind=f"DUPLICATE_KEY_{side.upper()}",
                auditor=_MISSING if producer else row,
                producer=row if producer else _MISSING,
            )
            continue
        indexed[key] = row
    return indexed, ordered


def _diff_json(
    auditor: object,
    producer: object,
    *,
    collection: str,
    key: str,
    path: str,
    mismatches: _MismatchCollector,
) -> None:
    if type(auditor) is not type(producer):
        mismatches.add(
            collection=collection,
            key=key,
            path=path,
            kind="TYPE",
            auditor=auditor,
            producer=producer,
        )
        return
    if type(auditor) is dict:
        assert type(producer) is dict
        for name in sorted(set(auditor) | set(producer)):
            expected_value = auditor.get(name, _MISSING)
            producer_value = producer.get(name, _MISSING)
            if expected_value is _MISSING or producer_value is _MISSING:
                mismatches.add(
                    collection=collection,
                    key=key,
                    path=f"{path}.{name}",
                    kind="FIELD_MISSING",
                    auditor=expected_value,
                    producer=producer_value,
                )
            else:
                _diff_json(
                    expected_value,
                    producer_value,
                    collection=collection,
                    key=key,
                    path=f"{path}.{name}",
                    mismatches=mismatches,
                )
        return
    if type(auditor) is list:
        assert type(producer) is list
        if len(auditor) != len(producer):
            mismatches.add(
                collection=collection,
                key=key,
                path=f"{path}.length",
                kind="LENGTH",
                auditor=len(auditor),
                producer=len(producer),
            )
        for index in range(min(len(auditor), len(producer))):
            _diff_json(
                auditor[index],
                producer[index],
                collection=collection,
                key=key,
                path=f"{path}[{index}]",
                mismatches=mismatches,
            )
        return
    if auditor != producer:
        mismatches.add(
            collection=collection,
            key=key,
            path=path,
            kind="VALUE",
            auditor=auditor,
            producer=producer,
        )


def _compare_collection(
    collection: str,
    auditor_values: list[object],
    producer_value: object,
    mismatches: _MismatchCollector,
) -> None:
    if type(producer_value) is not list:
        mismatches.add(
            collection=collection,
            key="$",
            path="$",
            kind="COLLECTION_SCHEMA",
            auditor=auditor_values,
            producer=producer_value,
        )
        return
    producer_values = producer_value
    auditor_index, auditor_order = _index_collection(
        collection, auditor_values, mismatches, producer=False
    )
    producer_index, producer_order = _index_collection(
        collection, producer_values, mismatches, producer=True
    )
    if auditor_order != producer_order:
        mismatches.add(
            collection=collection,
            key="$order",
            path="$order",
            kind="ORDER",
            auditor=auditor_order,
            producer=producer_order,
        )
    for key in sorted(set(auditor_index) | set(producer_index)):
        auditor_row = auditor_index.get(key, _MISSING)
        producer_row = producer_index.get(key, _MISSING)
        if auditor_row is _MISSING or producer_row is _MISSING:
            mismatches.add(
                collection=collection,
                key=key,
                path="$",
                kind="ROW_MISSING",
                auditor=auditor_row,
                producer=producer_row,
            )
            continue
        _diff_json(
            auditor_row,
            producer_row,
            collection=collection,
            key=key,
            path="$",
            mismatches=mismatches,
        )


def _seal_report(report: dict[str, object]) -> dict[str, object]:
    _json_value(report, "audit_report")
    result = dict(report)
    result["report_sha256"] = _canonical_sha256(report)
    return result


def _safe_commitment(value: object) -> str | None:
    try:
        return _canonical_sha256(value)
    except Exception:
        return None


def _invalid_report(
    error: AuditorContractError,
    *,
    sealed_partitions: object,
    freeze_bundle: object,
    producer_bundle: object,
    trusted_head_partition_hash: object,
    trusted_head_seal_id: object,
    trusted_freeze_sha256: object,
) -> dict[str, object]:
    reason = f"INVALID_INPUT:{error.code}"
    primitives_only = not (
        error.code.startswith("NON_JSON")
        or error.code == "AUDITOR_EVALUATION_ERROR"
    )
    report: dict[str, object] = {
        "schema_version": AUDITOR_SCHEMA_VERSION,
        "audit_status": "INVALID_INPUT",
        "holdout_gate": "FAIL_CLOSED",
        "holdout_reasons": [reason],
        "anchors": {
            "trusted_head_partition_hash": (
                trusted_head_partition_hash
                if type(trusted_head_partition_hash) is str
                else None
            ),
            "trusted_head_seal_id": (
                trusted_head_seal_id
                if type(trusted_head_seal_id) is str
                else None
            ),
            "trusted_freeze_sha256": (
                trusted_freeze_sha256
                if type(trusted_freeze_sha256) is str
                else None
            ),
        },
        "commitments": {
            "sealed_partitions_input_sha256": _safe_commitment(
                sealed_partitions
            ),
            "freeze_input_sha256": _safe_commitment(freeze_bundle),
            "producer_input_sha256": _safe_commitment(producer_bundle),
        },
        "counts": {
            "partitions": None,
            "raw_records": None,
            "mismatch_count": 1,
            "mismatch_details_emitted": 1,
            "mismatch_details_truncated": False,
            "collections": {},
        },
        "mismatches": [
            {
                "collection": "input",
                "key": "$",
                "path": "$",
                "kind": error.code,
                "auditor": "VALID_INPUT",
                "producer": error.detail,
            }
        ],
        "independence": {
            "stdlib_only": True,
            "project_local_import_count": 0,
            "producer_values_used_for_recalculation": False,
            "input_json_primitives_only": primitives_only,
        },
    }
    return _seal_report(report)


def audit_raw_to_pnl_v1(
    *,
    sealed_partitions: object,
    freeze_bundle: object,
    producer_bundle: object,
    trusted_head_partition_hash: object,
    trusted_head_seal_id: object,
    trusted_freeze_sha256: object,
) -> dict[str, object]:
    """Audit one sealed raw-to-PnL replay against independent calculations.

    Every argument is an ordinary JSON value.  The producer bundle is used
    only after custody, freeze, feature, signal, admission, execution,
    accounting, and coverage have been independently recomputed.  A ``MATCH``
    does not override ``holdout_gate``: incomplete grids, insufficient clock
    evidence, or omitted aggregation remain independently blocked/fail-closed.
    """

    try:
        _json_value(sealed_partitions, "sealed_partitions")
        _json_value(freeze_bundle, "freeze_bundle")
        _json_value(producer_bundle, "producer_bundle")
        _json_value(trusted_head_partition_hash, "trusted_head_partition_hash")
        _json_value(trusted_head_seal_id, "trusted_head_seal_id")
        _json_value(trusted_freeze_sha256, "trusted_freeze_sha256")
        custody = _verify_custody(
            sealed_partitions,
            trusted_head_partition_hash,
            trusted_head_seal_id,
        )
        freeze = _parse_freeze(freeze_bundle, trusted_freeze_sha256)
        replay = _replay_independently(custody, freeze)
        producer = _mapping(producer_bundle, "producer_bundle")
    except AuditorContractError as exc:
        return _invalid_report(
            exc,
            sealed_partitions=sealed_partitions,
            freeze_bundle=freeze_bundle,
            producer_bundle=producer_bundle,
            trusted_head_partition_hash=trusted_head_partition_hash,
            trusted_head_seal_id=trusted_head_seal_id,
            trusted_freeze_sha256=trusted_freeze_sha256,
        )
    except Exception as exc:  # defensive total API for adversarial JSON values
        return _invalid_report(
            AuditorContractError(
                "AUDITOR_EVALUATION_ERROR", type(exc).__name__
            ),
            sealed_partitions=sealed_partitions,
            freeze_bundle=freeze_bundle,
            producer_bundle=producer_bundle,
            trusted_head_partition_hash=trusted_head_partition_hash,
            trusted_head_seal_id=trusted_head_seal_id,
            trusted_freeze_sha256=trusted_freeze_sha256,
        )

    expected = replay.bundle
    mismatches = _MismatchCollector()
    expected_keys = set(_PRODUCER_FIELDS)
    producer_keys = set(producer)
    for name in sorted(expected_keys - producer_keys):
        mismatches.add(
            collection="producer_bundle",
            key=name,
            path=f"$.{name}",
            kind="FIELD_MISSING",
            auditor=expected[name],
            producer=_MISSING,
        )
    for name in sorted(producer_keys - expected_keys):
        mismatches.add(
            collection="producer_bundle",
            key=name,
            path=f"$.{name}",
            kind="UNEXPECTED_FIELD",
            auditor=_MISSING,
            producer=producer[name],
        )
    if producer.get("schema_version", _MISSING) != expected["schema_version"]:
        mismatches.add(
            collection="producer_bundle",
            key="schema_version",
            path="$.schema_version",
            kind="VALUE",
            auditor=expected["schema_version"],
            producer=producer.get("schema_version", _MISSING),
        )
    for collection in _COLLECTIONS:
        _compare_collection(
            collection,
            expected[collection],
            producer.get(collection, _MISSING),
            mismatches,
        )

    exact_match = producer == expected
    if exact_match and mismatches.total != 0:
        # This is an auditor invariant, never a producer-controlled outcome.
        raise RuntimeError("exact bundle equality disagrees with keyed comparison")
    if not exact_match and mismatches.total == 0:
        mismatches.add(
            collection="producer_bundle",
            key="$",
            path="$",
            kind="BUNDLE_COMMITMENT",
            auditor=expected,
            producer=producer,
        )

    collection_commitments: dict[str, object] = {}
    collection_counts: dict[str, object] = {}
    for collection in _COLLECTIONS:
        actual_value = producer.get(collection, _MISSING)
        collection_commitments[collection] = {
            "auditor_sha256": _canonical_sha256(expected[collection]),
            "producer_sha256": (
                _canonical_sha256(actual_value)
                if actual_value is not _MISSING
                else None
            ),
        }
        collection_counts[collection] = {
            "auditor": len(expected[collection]),
            "producer": (
                len(actual_value) if type(actual_value) is list else None
            ),
        }
    audit_status = "MATCH" if exact_match else "MISMATCH"
    holdout_gate = replay.holdout_gate if exact_match else "FAIL_CLOSED"
    holdout_reasons = list(replay.holdout_reasons)
    if not exact_match:
        holdout_reasons = sorted(set(holdout_reasons) | {"PRODUCER_MISMATCH"})
    report = {
        "schema_version": AUDITOR_SCHEMA_VERSION,
        "audit_status": audit_status,
        "holdout_gate": holdout_gate,
        "holdout_reasons": holdout_reasons,
        "anchors": {
            "trusted_head_partition_hash": custody.terminal_partition_hash,
            "trusted_head_seal_id": custody.terminal_seal_id,
            "trusted_freeze_sha256": freeze.sha256,
        },
        "commitments": {
            "custody_chain_sha256": custody.chain_sha256,
            "sealed_partitions_input_sha256": _canonical_sha256(
                sealed_partitions
            ),
            "freeze_sha256": freeze.sha256,
            "producer_bundle_sha256": _canonical_sha256(producer),
            "auditor_bundle_sha256": _canonical_sha256(expected),
            "collections": collection_commitments,
        },
        "counts": {
            "partitions": custody.partition_count,
            "raw_records": custody.record_count,
            "mismatch_count": mismatches.total,
            "mismatch_details_emitted": len(mismatches.rows),
            "mismatch_details_truncated": mismatches.total
            > len(mismatches.rows),
            "collections": collection_counts,
        },
        "mismatches": mismatches.rows,
        "independence": {
            "stdlib_only": True,
            "project_local_import_count": 0,
            "producer_values_used_for_recalculation": False,
            "input_json_primitives_only": True,
        },
    }
    return _seal_report(report)


__all__ = ["audit_raw_to_pnl_v1"]
