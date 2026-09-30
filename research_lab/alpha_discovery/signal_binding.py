"""Deterministic Signal Binding and PIT Precheck for SHFE Daily Settlement (#502 Stage 2).

Binds admitted Alpha candidates to verifiable, deterministic physical signals derived from
1d SHFE settlement data for RB2701 and HC2701. Enforces fail-closed validation:
- Exact formula parsing and whitelist matching (lookback k in 1..3, momentum and reversal).
- Strict contract isolation (RB2701 vs HC2701, no cross-contract bleeding).
- Strict temporal sequence: feature_availability_time <= as_of_time < target_start_time.
- Deterministic calculation with high-precision float formatting.
- Complete snapshot sealing: SHA256, byte length, row count, and provenance metadata.
- Precheck fail-closed: unsupported formulas, wrong parameters, missing features,
  or temporal leakage raise SignalBindingError and block execution before Critic/Memory.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from research_lab.alpha_discovery.hypothesis import (
    AlphaHypothesis,
    compute_hypothesis_content_hash,
    compute_scientific_identity_hash,
    validate_hypothesis,
)
from research_lab.contracts import v2

SUPPORTED_SYMBOLS = ("RB2701", "HC2701")
SYMBOL_PRODUCT_MAP = {"RB2701": "rb_f", "HC2701": "hc_f"}
SUPPORTED_FREQUENCIES = ("1d",)
SUPPORTED_HORIZONS = ("1d",)
SUPPORTED_SIGNAL_FAMILIES = ("momentum", "reversal")
SUPPORTED_LOOKBACKS = (1, 2, 3)
SUPPORTED_SOURCE_FEATURES = ("settlement", "settlement_price")
CANONICAL_TARGET_DEFINITION = "log(settlement[t+2] / settlement[t+1])"
IMPLEMENTATION_VERSION = "research_lab.signal_binding.v1"


@dataclass(frozen=True)
class SyntheticTestEvidence:
    """Explicit, test-dedicated source evidence for offline mathematical and regression unit tests.

    Cannot be activated via caller-supplied strings in source_days or provenance JSON.
    Must be explicitly instantiated and passed in memory by authorized test code.
    """

    fixture_id: str
    description: str = ""


AUTHORIZED_SYNTHETIC_FIXTURE_IDS = frozenset({
    "synthetic-offline-test-fixture-v1",
})

# Canonical SHA-256 digests of authorized fixed synthetic offline unit-test fixtures.
# Real warehouse custody or arbitrary caller datasets can NEVER match these digests.
KNOWN_SYNTHETIC_SOURCE_DIGESTS = frozenset({
    "d05c1cdaae6b51e8661d2177b50c1207981f6cb877e7f1630dcf9cb758247480",  # Canonical 7-day hand-computable fixture
    "85ea09167dcb48f97c4e3aac17805e659d66554747006fe86a4b5c33733cbf0a",  # Temporal leak negative fixture 1
    "b85765889ffc0c90adedc4d9199747bb55d9b9cb0f9d41210922c7c7d50f98e2",  # Target overlap negative fixture 2
    "f459823038e0feb5f3d9c0998923ea14fc86da50874876ce5fba757c8a222d6b",  # Lagged intermediate late fixture (positive)
    "f6df0f26144ba388fa89995cfa3cf867abcc7d496d8e3dda9e7daea3c0a77816",  # Lagged actual input late fixture (negative)
})

_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_strict_utc_iso8601(ts_str: Any, field_name: str = "timestamp") -> datetime:
    """Parse strictly timezone-aware UTC ISO8601 string, rejecting naive, non-UTC, or invalid formats."""
    if not isinstance(ts_str, str) or not ts_str.strip():
        raise SignalBindingError(
            "INVALID_DATETIME_FORMAT",
            f"{field_name} must be a non-empty string, got {type(ts_str).__name__}",
        )
    s = ts_str.strip()
    if not _ISO_UTC_RE.match(s):
        raise SignalBindingError(
            "INVALID_DATETIME_FORMAT",
            f"{field_name} '{s}' must be valid UTC ISO8601 with Z or +00:00",
        )
    try:
        norm_s = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(norm_s)
    except Exception as exc:
        raise SignalBindingError(
            "INVALID_DATETIME_FORMAT",
            f"{field_name} '{s}' failed ISO8601 parse: {exc}",
        ) from exc
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise SignalBindingError(
            "INVALID_TIMEZONE",
            f"{field_name} '{s}' must be timezone-aware UTC (+00:00 or Z)",
        )
    return dt


def parse_strict_trade_day(day_str: Any, field_name: str = "day") -> date:
    """Parse YYYY-MM-DD trading day, rejecting invalid formats."""
    if not isinstance(day_str, str) or not day_str.strip():
        raise SignalBindingError(
            "INVALID_TRADE_DAY_FORMAT",
            f"{field_name} must be a non-empty string, got {type(day_str).__name__}",
        )
    s = day_str.strip()
    if not _DATE_RE.match(s):
        raise SignalBindingError(
            "INVALID_TRADE_DAY_FORMAT",
            f"{field_name} '{s}' must be format YYYY-MM-DD",
        )
    try:
        return date.fromisoformat(s)
    except Exception as exc:
        raise SignalBindingError(
            "INVALID_TRADE_DAY_FORMAT",
            f"{field_name} '{s}' failed date parse: {exc}",
        ) from exc


# Regex patterns for matching supported signal definitions
_PAT_MOMENTUM = re.compile(
    r"^\+?log\(\s*(?:settlement|settlement_price)\[t\]\s*/\s*(?:settlement|settlement_price)\[t-([1-3])\]\s*\)$",
    re.IGNORECASE,
)
_PAT_MOMENTUM_FUNC = re.compile(
    r"^log_return\(\s*(?:settlement|settlement_price)\s*,\s*(?:k\s*=\s*)?([1-3])\s*\)$",
    re.IGNORECASE,
)
_PAT_REVERSAL_NEG = re.compile(
    r"^-\s*log\(\s*(?:settlement|settlement_price)\[t\]\s*/\s*(?:settlement|settlement_price)\[t-([1-3])\]\s*\)$",
    re.IGNORECASE,
)
_PAT_REVERSAL_INVERTED = re.compile(
    r"^\+?log\(\s*(?:settlement|settlement_price)\[t-([1-3])\]\s*/\s*(?:settlement|settlement_price)\[t\]\s*\)$",
    re.IGNORECASE,
)
_PAT_TARGET = re.compile(
    r"^log\(\s*(?:settlement|settlement_price)\[t\+2\]\s*/\s*(?:settlement|settlement_price)\[t\+1\]\s*\)$",
    re.IGNORECASE,
)
_PAT_TARGET_FUNC = re.compile(
    r"^forward_log_return\(\s*(?:settlement|settlement_price)\s*,\s*(?:start\s*=\s*1\s*,\s*end\s*=\s*2|1\s*,\s*2)\s*\)$",
    re.IGNORECASE,
)


class SignalBindingError(ValueError):
    """Fail-closed error when candidate cannot be deterministically bound to verified data."""

    def __init__(self, reason: str, details: str | None = None) -> None:
        self.reason = reason
        self.details = details or ""
        msg = f"Signal binding rejected [{reason}]" + (f": {details}" if details else "")
        super().__init__(msg)


@dataclass(frozen=True)
class ParsedSignalSpec:
    """Immutable specification of a machine-verified signal formula and execution contract."""

    formula_id: str
    symbol: str
    signal_family: str
    lookback_k: int
    expected_direction: str
    canonical_signal_definition: str
    canonical_target: str
    holding_horizon: str
    frequency: str
    source_features: tuple[str, ...]
    min_history_required: int
    is_negated: bool = False


@dataclass(frozen=True)
class DerivedSnapshotResult:
    """Immutable outcome of deriving a candidate-specific snapshot from raw source days."""

    path: Path
    sha256: str
    byte_length: int
    row_count: int
    symbol: str
    time_range: dict[str, str]
    dataset_binding: dict[str, Any]
    metadata_path: Path
    metadata_sha256: str


@dataclass(frozen=True)
class RowPITVerification:
    """Row-by-row point-in-time and causality verification record."""

    trade_day: str
    symbol: str
    feature_val: str
    target_val: str
    feature_availability_time: str
    as_of_time: str
    target_start_time: str
    feature_start_trade_day: str
    feature_end_trade_day: str
    target_start_trade_day: str
    target_end_trade_day: str
    temporal_order_valid: bool
    target_non_overlapping: bool
    feature_available_at_as_of: bool


def _clean_str(val: Any) -> str:
    return str(val or "").strip()


def parse_and_verify_signal_spec(
    hypothesis: dict[str, Any] | AlphaHypothesis,
) -> ParsedSignalSpec:
    """Fail-closed parsing and validation of an AlphaHypothesis against supported mathematical definitions.

    Enforces:
    - universe: Exactly 'RB2701' or 'HC2701'.
    - frequency: Exactly '1d'.
    - holding_horizon: Exactly '1d'.
    - signal_family: Exactly 'momentum' or 'reversal'.
    - source_features: Strictly subset of {'settlement', 'settlement_price'}.
    - target: Strictly matches canonical execution target log(settlement[t+2] / settlement[t+1]).
    - signal_definition: Matches supported log settlement ratio formula with lookback k in {1, 2, 3}.
    - expected_direction: Matches formula sign and economic logic.
    """
    if isinstance(hypothesis, AlphaHypothesis):
        dump_with = hypothesis.model_dump()
        if compute_hypothesis_content_hash(dump_with) == hypothesis.hypothesis_content_hash:
            data = dump_with
        else:
            data = hypothesis.model_dump(exclude_none=True)
    elif isinstance(hypothesis, dict):
        data = hypothesis
    else:
        raise SignalBindingError("INVALID_INPUT_TYPE", f"Expected dict or AlphaHypothesis, got {type(hypothesis).__name__}")

    # Validate structural fields via AlphaHypothesis contract
    try:
        validated_data = validate_hypothesis(data)
    except Exception as exc:
        raise SignalBindingError("HYPOTHESIS_VALIDATION_FAILED", str(exc)) from exc

    # 1. Universe check
    raw_universe = validated_data.get("universe")
    universe_str = _clean_str(raw_universe)
    if universe_str not in SUPPORTED_SYMBOLS:
        raise SignalBindingError(
            "UNSUPPORTED_UNIVERSE",
            f"Universe '{universe_str}' not in supported contracts {SUPPORTED_SYMBOLS}",
        )
    symbol = universe_str

    # 2. Frequency check
    freq = _clean_str(validated_data.get("frequency"))
    if freq not in SUPPORTED_FREQUENCIES:
        raise SignalBindingError(
            "UNSUPPORTED_FREQUENCY",
            f"Frequency '{freq}' not in supported frequencies {SUPPORTED_FREQUENCIES}",
        )

    # 3. Holding horizon check
    horizon = _clean_str(validated_data.get("holding_horizon"))
    if horizon not in SUPPORTED_HORIZONS:
        raise SignalBindingError(
            "UNSUPPORTED_HORIZON",
            f"Holding horizon '{horizon}' not in supported horizons {SUPPORTED_HORIZONS}",
        )

    # 4. Source features check
    raw_features = validated_data.get("source_features") or []
    if not isinstance(raw_features, (list, tuple)) or not raw_features:
        raise SignalBindingError("MISSING_SOURCE_FEATURES", "source_features must be non-empty list")
    clean_features = [_clean_str(f).lower() for f in raw_features]
    invalid_features = [f for f in clean_features if f not in SUPPORTED_SOURCE_FEATURES]
    if invalid_features:
        raise SignalBindingError(
            "UNSUPPORTED_SOURCE_FEATURES",
            f"Features {invalid_features} are not supported. Supported: {SUPPORTED_SOURCE_FEATURES}",
        )

    # 5. Target check
    target_str = _clean_str(validated_data.get("target"))
    if not (_PAT_TARGET.match(target_str) or _PAT_TARGET_FUNC.match(target_str)):
        raise SignalBindingError(
            "UNSUPPORTED_TARGET",
            f"Target '{target_str}' does not match canonical execution target '{CANONICAL_TARGET_DEFINITION}'",
        )

    # 6. Signal family and definition check
    family = _clean_str(validated_data.get("signal_family")).lower()
    if family not in SUPPORTED_SIGNAL_FAMILIES:
        raise SignalBindingError(
            "UNSUPPORTED_FAMILY",
            f"Signal family '{family}' not in supported families {SUPPORTED_SIGNAL_FAMILIES}",
        )

    expected_dir = _clean_str(validated_data.get("expected_direction")).lower()
    if expected_dir != "positive":
        raise SignalBindingError(
            "UNSUPPORTED_EXPECTED_DIRECTION",
            f"Expected direction '{expected_dir}' is unsupported; screening runner evaluates positive concordance, "
            "so all hypotheses must formulate signals with expected_direction='positive' "
            "(use explicit negation '-log(...)' or inverted ratio 'log(prev/cur)' for reversal)",
        )

    sig_def = _clean_str(validated_data.get("signal_definition"))
    lookback_k: int | None = None
    is_negated = False
    formula_id: str | None = None

    if family == "momentum":
        m_match = _PAT_MOMENTUM.match(sig_def) or _PAT_MOMENTUM_FUNC.match(sig_def)
        if not m_match:
            raise SignalBindingError(
                "UNSUPPORTED_FORMULA",
                f"Signal definition '{sig_def}' is not a supported momentum log return ratio",
            )
        lookback_k = int(m_match.group(1))
        formula_id = f"log_settlement_momentum_k{lookback_k}"
        is_negated = False

    elif family == "reversal":
        # Check Option A: explicit negative sign: -log(settlement[t] / settlement[t-k]) with expected_direction='positive'
        neg_match = _PAT_REVERSAL_NEG.match(sig_def)
        # Check Option B: inverted ratio: log(settlement[t-k] / settlement[t]) with expected_direction='positive'
        inv_match = _PAT_REVERSAL_INVERTED.match(sig_def)
        # Check if caller attempted un-negated ratio with expected_direction='negative' or 'positive'
        std_match = _PAT_MOMENTUM.match(sig_def) or _PAT_MOMENTUM_FUNC.match(sig_def)

        if neg_match:
            lookback_k = int(neg_match.group(1))
            is_negated = True
            formula_id = f"log_settlement_reversal_neg_k{lookback_k}"
        elif inv_match:
            lookback_k = int(inv_match.group(1))
            is_negated = True
            formula_id = f"log_settlement_reversal_inv_k{lookback_k}"
        elif std_match:
            raise SignalBindingError(
                "UNSUPPORTED_REVERSAL_REPRESENTATION",
                f"Reversal definition '{sig_def}' lacks negation or inverted ratio; "
                "Runner direction_consistency requires same-sign concordance with target; "
                "formulate reversal as '-log(cur/prev)' or 'log(prev/cur)' with expected_direction='positive'",
            )
        else:
            raise SignalBindingError(
                "UNSUPPORTED_FORMULA",
                f"Signal definition '{sig_def}' is not a supported reversal log return ratio",
            )

    if lookback_k not in SUPPORTED_LOOKBACKS:
        raise SignalBindingError(
            "INVALID_LOOKBACK_K",
            f"Lookback k={lookback_k} not in supported lookbacks {SUPPORTED_LOOKBACKS}",
        )

    # Minimum history required: k lag days + 1 current day + 2 forward target days = k + 3 days
    min_history = lookback_k + 3

    canon_sig = (
        f"-log(settlement[t] / settlement[t-{lookback_k}])"
        if is_negated
        else f"log(settlement[t] / settlement[t-{lookback_k}])"
    )

    return ParsedSignalSpec(
        formula_id=formula_id or f"{family}_k{lookback_k}",
        symbol=symbol,
        signal_family=family,
        lookback_k=lookback_k,
        expected_direction=expected_dir,
        canonical_signal_definition=canon_sig,
        canonical_target=CANONICAL_TARGET_DEFINITION,
        holding_horizon=horizon,
        frequency=freq,
        source_features=tuple(sorted(set(clean_features))),
        min_history_required=min_history,
        is_negated=is_negated,
    )


def derive_signal_snapshot(
    spec: ParsedSignalSpec,
    source_days: list[dict[str, Any]],
    output_dir: Path,
    *,
    snapshot_filename: str | None = None,
    candidate_identity_hash: str | None = None,
    provenance_path: Path | str | None = None,
    provenance_sha256: str | None = None,
    synthetic_test_evidence: SyntheticTestEvidence | None = None,
) -> DerivedSnapshotResult:
    """Derive deterministic, verified Protocol v2 CSV snapshot strictly for a single contract.

    Enforces:
    - Strict chronological sorting of source_days.
    - Zero cross-contract bleeding: product key is strictly mapped to spec.symbol.
    - Strict PIT ordering for each row:
        feature_availability_time <= as_of_time < target_start_time.
    - Bounded lookback k and target horizon (1d forward).
    - Candidate identity hash file naming isolation to prevent collision across candidates.
    - Three-hash provenance integrity: source provenance sha, candidate identity, implementation hash.
    """
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Strict provenance verification: provenance_path is strictly required and must truly exist
    if not provenance_path:
        raise SignalBindingError(
            "MISSING_PROVENANCE_PATH",
            "derive_signal_snapshot strictly requires provenance_path pointing to verified custody provenance file",
        )
    p_path = Path(provenance_path).resolve()
    if not p_path.exists():
        raise SignalBindingError("MISSING_PROVENANCE_FILE", f"Provenance file not found at {p_path}")
    p_bytes = p_path.read_bytes()
    actual_sha = hashlib.sha256(p_bytes).hexdigest()
    if provenance_sha256 and actual_sha != provenance_sha256:
        raise SignalBindingError(
            "PROVENANCE_HASH_MISMATCH",
            f"Provenance SHA256 {actual_sha} != expected {provenance_sha256}",
        )
    if len(actual_sha) != 64 or not re.match(r"^[a-f0-9]{64}$", actual_sha):
        raise SignalBindingError(
            "INVALID_PROVENANCE_SHA",
            f"Derived snapshot strictly requires verified 64-hex SHA256, got {actual_sha!r}",
        )
    prov_sha_verified = actual_sha

    # Fail-closed check: directly passed source_days must be item-by-item strictly equal to provenance source_days
    try:
        prov_json = json.loads(p_bytes.decode("utf-8"))
    except Exception as exc:
        raise SignalBindingError("INVALID_PROVENANCE_JSON", f"Provenance file is not valid JSON: {exc}") from exc

    prov_source_days = prov_json.get("source_days")
    if not isinstance(prov_source_days, list):
        raise SignalBindingError(
            "MISSING_SOURCE_DAYS",
            f"Provenance file does not contain a list under 'source_days': {p_path}",
        )
    if source_days != prov_source_days:
        raise SignalBindingError(
            "SOURCE_DAYS_MISMATCH",
            f"Passed source_days does not match canonical provenance source_days in {p_path}",
        )

    prod_key = SYMBOL_PRODUCT_MAP.get(spec.symbol)
    if not prod_key:
        raise SignalBindingError("UNSUPPORTED_UNIVERSE", f"No product key for symbol {spec.symbol}")

    if len(source_days) < spec.min_history_required:
        raise SignalBindingError(
            "INSUFFICIENT_HISTORY_WINDOW",
            f"Source days count ({len(source_days)}) < required minimum ({spec.min_history_required}) for k={spec.lookback_k}",
        )

    REQUIRED_SOURCE_DAY_FIELDS = ("day", "first_seen_at", "committed_at", "raw_sha256", "settlement")
    for idx, d in enumerate(source_days):
        if not isinstance(d, dict):
            raise SignalBindingError(
                "MALFORMED_PROVENANCE_SOURCE_DAY",
                f"source_day[{idx}] must be a dict, got {type(d).__name__}",
            )
        for field in REQUIRED_SOURCE_DAY_FIELDS:
            if field not in d or d[field] is None:
                raise SignalBindingError(
                    "MALFORMED_PROVENANCE_SOURCE_DAY",
                    f"source_day[{idx}] missing required field '{field}': {d}",
                )
        if not isinstance(d["settlement"], dict):
            raise SignalBindingError(
                "MALFORMED_PROVENANCE_SETTLEMENT",
                f"source_day[{idx}] 'settlement' must be a dict, got {type(d['settlement']).__name__}",
            )

    # Ensure source days are sorted strictly by trading day
    sorted_days = sorted(source_days, key=lambda d: str(d["day"]))
    # Verify no duplicate trading days and validate trading day format
    day_set = set()
    for d in sorted_days:
        day_val = parse_strict_trade_day(d["day"], "source_days.day")
        if day_val in day_set:
            raise SignalBindingError("DUPLICATE_TRADING_DAY", f"Duplicate trading day {d['day']}")
        day_set.add(day_val)

    output_rows: list[dict[str, str]] = []
    k = spec.lookback_k
    n_days = len(sorted_days)

    # Observations run from index k to n_days - 3 (inclusive)
    # At index i:
    # prev = sorted_days[i - k] (historical base for feature)
    # cur = sorted_days[i]      (as-of day)
    # next_day = sorted_days[i + 1] (target entry day)
    # end = sorted_days[i + 2]      (target exit day)
    for i in range(k, n_days - 2):
        prev = sorted_days[i - k]
        cur = sorted_days[i]
        next_day = sorted_days[i + 1]
        end = sorted_days[i + 2]

        d_prev = parse_strict_trade_day(prev["day"], "prev.day")
        d_cur = parse_strict_trade_day(cur["day"], "cur.day")
        d_next = parse_strict_trade_day(next_day["day"], "next_day.day")
        d_end = parse_strict_trade_day(end["day"], "end.day")

        if not (d_prev < d_cur < d_next < d_end):
            raise SignalBindingError(
                "TRADE_DAY_ORDER_VIOLATION",
                f"Trading days must strictly increase: {d_prev} < {d_cur} < {d_next} < {d_end}",
            )

        # Target timing must come from verifiable market/settlement effective time.
        # Ingestion first_seen_at / committed_at cannot masquerade as market target start/end time.
        tgt_market_start = next_day.get("market_effective_time") or next_day.get("settlement_effective_time")
        tgt_market_end = end.get("market_effective_time") or end.get("settlement_effective_time")
        if not tgt_market_start or not tgt_market_end:
            raise SignalBindingError(
                "UNVERIFIABLE_TARGET_MARKET_TIME",
                f"Day {next_day['day']} / {end['day']}: source provenance lacks verifiable market or settlement effective time; "
                "using ingestion first_seen_at as target_start_time is strictly forbidden",
            )

        # Fail-closed market time verification:
        # Self-attested market_effective_time or self-labeled authority strings in untrusted provenance
        # (e.g. SHFE_OFFICIAL, EXCHANGE_ANNOUNCEMENT) without an independent verifiable exchange source are strictly rejected.
        auth_claimed = next_day.get("market_time_authority") or end.get("market_time_authority")
        if auth_claimed and auth_claimed != "SYNTHETIC_TEST_FIXTURE":
            raise SignalBindingError(
                "UNVERIFIED_MARKET_TIME_AUTHORITY",
                f"Day {next_day['day']} / {end['day']}: provenance claims market_time_authority='{auth_claimed}', "
                "but self-attested authority strings without independent verifiable exchange source are strictly forbidden.",
            )

        if synthetic_test_evidence is None:
            if auth_claimed == "SYNTHETIC_TEST_FIXTURE":
                raise SignalBindingError(
                    "UNVERIFIED_MARKET_TIME_AUTHORITY",
                    f"Day {next_day['day']} / {end['day']}: provenance claims 'SYNTHETIC_TEST_FIXTURE' in untrusted data, "
                    "but no authorized SyntheticTestEvidence was provided; string switches in data are strictly forbidden.",
                )
            raise SignalBindingError(
                "UNVERIFIABLE_TARGET_MARKET_TIME",
                f"Day {next_day['day']} / {end['day']}: source provenance lacks independent verifiable market time source; "
                "self-attested market_effective_time is unverified and strictly forbidden fail-closed.",
            )

        if auth_claimed != "SYNTHETIC_TEST_FIXTURE":
            raise SignalBindingError(
                "UNVERIFIED_MARKET_TIME_AUTHORITY",
                f"Day {next_day['day']} / {end['day']}: synthetic test derivation requires market_time_authority='SYNTHETIC_TEST_FIXTURE', "
                f"got auth_claimed='{auth_claimed}'.",
            )

        if not isinstance(synthetic_test_evidence, SyntheticTestEvidence):
            raise SignalBindingError(
                "UNAUTHORIZED_SYNTHETIC_FIXTURE",
                f"Invalid synthetic_test_evidence type: expected SyntheticTestEvidence, got {type(synthetic_test_evidence).__name__}",
            )
        if synthetic_test_evidence.fixture_id not in AUTHORIZED_SYNTHETIC_FIXTURE_IDS:
            raise SignalBindingError(
                "UNAUTHORIZED_SYNTHETIC_FIXTURE",
                f"Unauthorized synthetic test fixture ID '{synthetic_test_evidence.fixture_id}'. "
                f"Caller-chosen or arbitrary fixture IDs are strictly forbidden. "
                f"Authorized IDs: {sorted(AUTHORIZED_SYNTHETIC_FIXTURE_IDS)}",
            )
        source_days_canonical_sha = hashlib.sha256(
            json.dumps(source_days, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if source_days_canonical_sha not in KNOWN_SYNTHETIC_SOURCE_DIGESTS:
            raise SignalBindingError(
                "UNAUTHORIZED_SYNTHETIC_FIXTURE",
                f"Synthetic test evidence is strictly restricted to known fixed offline unit test fixtures. "
                f"Source dataset digest '{source_days_canonical_sha}' is not an authorized test fixture. "
                "Real or arbitrary datasets cannot bypass market time verification via SyntheticTestEvidence.",
            )

        t_as_of = str(cur["committed_at"])
        dt_as_of = parse_strict_utc_iso8601(t_as_of, "cur.committed_at")

        # Lagged feature availability and commit check across actual inputs for this feature.
        # For momentum/reversal with lookback k, the feature formula is math.log(settle_cur / settle_prev)
        # where cur is sorted_days[i] and prev is sorted_days[i - k].
        # Intermediate days in (i - k, i) are NOT inputs to this feature; only check actual inputs.
        actual_input_days = [prev, cur] if k > 0 else [cur]
        input_avail_times: list[datetime] = []
        for in_d in actual_input_days:
            dt_in_avail = parse_strict_utc_iso8601(in_d["first_seen_at"], f"day[{in_d['day']}].first_seen_at")
            dt_in_commit = parse_strict_utc_iso8601(in_d["committed_at"], f"day[{in_d['day']}].committed_at")
            if dt_in_avail > dt_as_of:
                if in_d["day"] == cur["day"]:
                    raise SignalBindingError(
                        "TEMPORAL_ORDER_VIOLATION",
                        f"Day {cur['day']}: feature_availability_time ({dt_in_avail.isoformat()}) > as_of_time ({dt_as_of.isoformat()})",
                    )
                raise SignalBindingError(
                    "INPUT_NOT_AVAILABLE_AT_AS_OF",
                    f"Day {cur['day']}: input day {in_d['day']} first_seen_at ({dt_in_avail.isoformat()}) > as_of_time ({dt_as_of.isoformat()})",
                )
            if dt_in_commit > dt_as_of:
                raise SignalBindingError(
                    "INPUT_NOT_COMMITTED_AT_AS_OF",
                    f"Day {cur['day']}: input day {in_d['day']} committed_at ({dt_in_commit.isoformat()}) > as_of_time ({dt_as_of.isoformat()})",
                )
            input_avail_times.append(dt_in_avail)

        dt_max_avail = max(input_avail_times)
        t_avail = dt_max_avail.isoformat().replace("+00:00", "Z")

        t_tgt_start = str(tgt_market_start)
        t_tgt_end = str(tgt_market_end)
        dt_tgt_start = parse_strict_utc_iso8601(t_tgt_start, "next_day.market_effective_time")
        dt_tgt_end = parse_strict_utc_iso8601(t_tgt_end, "end.market_effective_time")

        # Temporal checks using real datetime objects
        if dt_max_avail > dt_as_of:
            raise SignalBindingError(
                "TEMPORAL_ORDER_VIOLATION",
                f"Day {cur['day']}: feature_availability_time ({dt_max_avail.isoformat()}) > as_of_time ({dt_as_of.isoformat()})",
            )
        if dt_as_of >= dt_tgt_start:
            raise SignalBindingError(
                "TARGET_OVERLAP_VIOLATION",
                f"Day {cur['day']}: as_of_time ({dt_as_of.isoformat()}) >= target_start_time ({dt_tgt_start.isoformat()})",
            )
        if dt_tgt_start >= dt_tgt_end:
            raise SignalBindingError(
                "TARGET_INTERVAL_VIOLATION",
                f"Target interval start ({dt_tgt_start.isoformat()}) >= end ({dt_tgt_end.isoformat()})",
            )

        # Retrieve settlement prices strictly for target product
        for s_day in (prev, cur, next_day, end):
            s_map = s_day.get("settlement")
            if not isinstance(s_map, dict):
                raise SignalBindingError(
                    "MALFORMED_PROVENANCE_SETTLEMENT",
                    f"Day {s_day.get('day')}: 'settlement' must be a dict, got {type(s_map).__name__}",
                )

        settle_cur = cur["settlement"].get(prod_key)
        settle_prev = prev["settlement"].get(prod_key)
        settle_next = next_day["settlement"].get(prod_key)
        settle_end = end["settlement"].get(prod_key)

        if not all(isinstance(p, (int, float)) and p > 0 for p in (settle_cur, settle_prev, settle_next, settle_end)):
            raise SignalBindingError(
                "NON_POSITIVE_PRICE",
                f"Day {cur['day']}: Non-positive or missing settlement price in window "
                f"({settle_prev}, {settle_cur}, {settle_next}, {settle_end})",
            )

        # Calculate math
        raw_feat = math.log(float(settle_cur) / float(settle_prev))
        feat_val = -raw_feat if spec.is_negated else raw_feat
        target_val = math.log(float(settle_end) / float(settle_next))

        output_rows.append(
            {
                "timestamp": t_as_of,
                "symbol": spec.symbol,
                "feature_val": format(feat_val, ".17g"),
                "target_val": format(target_val, ".17g"),
                "feature_availability_time": t_avail,
                "as_of_time": t_as_of,
                "target_start_time": t_tgt_start,
                "feature_start_trade_day": str(prev["day"]),
                "feature_end_trade_day": str(cur["day"]),
                "target_start_trade_day": str(next_day["day"]),
                "target_end_trade_day": str(end["day"]),
                "feature_start_raw_sha256": str(prev["raw_sha256"]),
                "feature_end_raw_sha256": str(cur["raw_sha256"]),
                "target_start_raw_sha256": str(next_day["raw_sha256"]),
                "target_end_raw_sha256": str(end["raw_sha256"]),
                "feature_end_batch_seal_sha256": str(cur["batch_seal_sha256"]),
                "target_end_batch_seal_sha256": str(end["batch_seal_sha256"]),
            }
        )

    if not output_rows:
        raise SignalBindingError("EMPTY_DERIVED_ROWS", "Derived snapshot yielded zero rows")

    csv_fields = (
        "timestamp",
        "symbol",
        "feature_val",
        "target_val",
        "feature_availability_time",
        "as_of_time",
        "target_start_time",
        "feature_start_trade_day",
        "feature_end_trade_day",
        "target_start_trade_day",
        "target_end_trade_day",
        "feature_start_raw_sha256",
        "feature_end_raw_sha256",
        "target_start_raw_sha256",
        "target_end_raw_sha256",
        "feature_end_batch_seal_sha256",
        "target_end_batch_seal_sha256",
    )

    if snapshot_filename:
        fname = snapshot_filename
    elif candidate_identity_hash:
        cand_short = candidate_identity_hash[:16]
        fname = f"snapshot_{spec.symbol.lower()}_{spec.formula_id}_{cand_short}.csv"
    else:
        fname = f"snapshot_{spec.symbol.lower()}_{spec.formula_id}.csv"
    csv_path = out_dir / fname
    meta_fname = csv_path.stem + ".binding.json"
    meta_path = out_dir / meta_fname
    if csv_path.exists() or meta_path.exists():
        raise SignalBindingError(
            "SNAPSHOT_ALREADY_EXISTS",
            f"Derived snapshot or metadata already exists and overwrite is strictly forbidden: {csv_path}",
        )

    try:
        with csv_path.open("x", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=csv_fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(output_rows)
    except FileExistsError as exc:
        raise SignalBindingError(
            "SNAPSHOT_ALREADY_EXISTS",
            f"Derived snapshot already exists and overwrite is strictly forbidden: {csv_path}",
        ) from exc

    raw_bytes = csv_path.read_bytes()
    raw_sha = v2.sha(raw_bytes)
    raw_len = len(raw_bytes)

    time_range = {
        "start": output_rows[0]["timestamp"],
        "end": output_rows[-1]["timestamp"],
    }

    source_days_digest = v2.digest([
        {
            "batch_seal_sha256": d.get("batch_seal_sha256"),
            "day": d["day"],
            "raw_sha256": d.get("raw_sha256"),
        }
        for d in sorted_days
    ])

    impl_hash = v2.digest({
        "canonical_target": CANONICAL_TARGET_DEFINITION,
        "supported_lookbacks": list(SUPPORTED_LOOKBACKS),
        "version": IMPLEMENTATION_VERSION,
    })

    dataset_binding = {
        "available_fields": list(csv_fields),
        "provenance": f"M2 Research Warehouse SHFE Daily Settlement committed custody for {spec.symbol}",
        "required_fields": list(csv_fields),
        "snapshot_byte_length": raw_len,
        "snapshot_locator": str(csv_path),
        "snapshot_sha256": raw_sha,
        "time_range": time_range,
    }

    metadata = {
        "schema_version": "research_lab.signal_binding_metadata.v1",
        "implementation_version": IMPLEMENTATION_VERSION,
        "implementation_hash": impl_hash,
        "candidate_identity_hash": candidate_identity_hash or "unspecified",
        "source_provenance_sha256": prov_sha_verified or "unspecified",
        "source_days_digest": source_days_digest,
        "spec": {
            "formula_id": spec.formula_id,
            "symbol": spec.symbol,
            "signal_family": spec.signal_family,
            "lookback_k": spec.lookback_k,
            "expected_direction": spec.expected_direction,
            "canonical_signal_definition": spec.canonical_signal_definition,
            "canonical_target": spec.canonical_target,
            "holding_horizon": spec.holding_horizon,
            "frequency": spec.frequency,
            "min_history_required": spec.min_history_required,
        },
        "snapshot": {
            "path": str(csv_path),
            "sha256": raw_sha,
            "byte_length": raw_len,
            "row_count": len(output_rows),
            "time_range": time_range,
        },
        "dataset_binding": dataset_binding,
        "source_summary": {
            "source_days_count": len(source_days),
            "start_trade_day": sorted_days[0]["day"],
            "end_trade_day": sorted_days[-1]["day"],
        },
        "limitations": [
            f"Derived exploratory screening dataset for {spec.symbol} single contract.",
            f"Observations count: {len(output_rows)}; lookback k={spec.lookback_k}.",
            "Source signatures originate from M2 Research Warehouse custody metadata.",
            "Historical availability cannot be claimed prior to recorded first_seen_at.",
        ],
    }
    if synthetic_test_evidence is not None:
        metadata["synthetic_test_fixture_id"] = synthetic_test_evidence.fixture_id

    meta_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        with meta_path.open("xb") as mfh:
            mfh.write(meta_bytes)
    except FileExistsError as exc:
        raise SignalBindingError(
            "SNAPSHOT_ALREADY_EXISTS",
            f"Derived snapshot metadata already exists and overwrite is strictly forbidden: {meta_path}",
        ) from exc
    meta_sha = hashlib.sha256(meta_bytes).hexdigest()

    return DerivedSnapshotResult(
        path=csv_path,
        sha256=raw_sha,
        byte_length=raw_len,
        row_count=len(output_rows),
        symbol=spec.symbol,
        time_range=time_range,
        dataset_binding=dataset_binding,
        metadata_path=meta_path,
        metadata_sha256=meta_sha,
    )


def verify_derived_snapshot_pit(csv_path: Path) -> list[RowPITVerification]:
    """Inspect every row of a derived snapshot and verify point-in-time invariants."""
    p = Path(csv_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Derived snapshot not found: {p}")

    text = p.read_text(encoding="utf-8")
    reader = list(csv.DictReader(text.splitlines()))

    verifications: list[RowPITVerification] = []
    for r in reader:
        day = r["feature_end_trade_day"]
        t_avail = r["feature_availability_time"]
        t_as_of = r["as_of_time"]
        t_tgt = r["target_start_time"]

        dt_avail = parse_strict_utc_iso8601(t_avail, "feature_availability_time")
        dt_as_of = parse_strict_utc_iso8601(t_as_of, "as_of_time")
        dt_tgt = parse_strict_utc_iso8601(t_tgt, "target_start_time")

        d_feat_start = parse_strict_trade_day(r["feature_start_trade_day"], "feature_start_trade_day")
        d_feat_end = parse_strict_trade_day(r["feature_end_trade_day"], "feature_end_trade_day")
        d_tgt_start = parse_strict_trade_day(r["target_start_trade_day"], "target_start_trade_day")
        d_tgt_end = parse_strict_trade_day(r["target_end_trade_day"], "target_end_trade_day")

        trade_day_order_valid = d_feat_start <= d_feat_end < d_tgt_start < d_tgt_end
        temporal_valid = (dt_avail <= dt_as_of < dt_tgt) and trade_day_order_valid
        target_non_overlapping = dt_as_of < dt_tgt
        feat_prior = dt_avail <= dt_as_of

        verifications.append(
            RowPITVerification(
                trade_day=day,
                symbol=r["symbol"],
                feature_val=r["feature_val"],
                target_val=r["target_val"],
                feature_availability_time=t_avail,
                as_of_time=t_as_of,
                target_start_time=t_tgt,
                feature_start_trade_day=r["feature_start_trade_day"],
                feature_end_trade_day=r["feature_end_trade_day"],
                target_start_trade_day=r["target_start_trade_day"],
                target_end_trade_day=r["target_end_trade_day"],
                temporal_order_valid=temporal_valid,
                target_non_overlapping=target_non_overlapping,
                feature_available_at_as_of=feat_prior,
            )
        )

    return verifications


def precheck_candidate_real_data(
    candidate: Any,
    provenance_path: Path | str,
    output_dir: Path | str,
    *,
    provenance_sha256: str | None = None,
    synthetic_test_evidence: SyntheticTestEvidence | None = None,
) -> dict[str, Any]:
    """Execute complete Phase A deterministic binding and row-by-row PIT precheck.

    Returns structured audit dictionary with status 'PRECHECK_PASS' if all invariants hold.
    Never executes external providers, network calls, or mutating operations.
    """
    prov_p = Path(provenance_path).resolve()
    out_d = Path(output_dir).resolve()
    out_d.mkdir(parents=True, exist_ok=True)
    report_p = out_d / "PRECHECK_REPORT.json"
    if report_p.exists():
        raise SignalBindingError(
            "SNAPSHOT_ALREADY_EXISTS",
            f"Precheck report already exists and overwrite is strictly forbidden: {report_p}",
        )

    if not prov_p.exists():
        raise FileNotFoundError(f"Provenance file not found: {prov_p}")

    prov_bytes = prov_p.read_bytes()
    actual_prov_sha = hashlib.sha256(prov_bytes).hexdigest()
    if provenance_sha256 and actual_prov_sha != provenance_sha256:
        raise SignalBindingError(
            "PROVENANCE_HASH_MISMATCH",
            f"Provenance SHA256 {actual_prov_sha} != expected {provenance_sha256}",
        )

    prov_data = json.loads(prov_bytes.decode("utf-8"))
    source_days = prov_data.get("source_days", [])
    if not source_days:
        raise SignalBindingError("MISSING_SOURCE_DAYS", f"No source_days found in provenance {prov_p}")

    hyp_obj = getattr(candidate, "hypothesis", candidate)
    if isinstance(hyp_obj, AlphaHypothesis):
        dump_with = hyp_obj.model_dump()
        hyp_dict = dump_with if compute_hypothesis_content_hash(dump_with) == hyp_obj.hypothesis_content_hash else hyp_obj.model_dump(exclude_none=True)
    elif isinstance(hyp_obj, dict):
        hyp_dict = hyp_obj
    else:
        raise SignalBindingError("INVALID_CANDIDATE", f"Cannot extract hypothesis from {type(candidate).__name__}")

    sci_hash = compute_scientific_identity_hash(hyp_dict)
    content_hash = compute_hypothesis_content_hash(hyp_dict)

    # Step 1: Parse and verify spec
    spec = parse_and_verify_signal_spec(hyp_dict)

    # Step 2: Derive candidate snapshot
    derived = derive_signal_snapshot(
        spec=spec,
        source_days=source_days,
        output_dir=out_d,
        candidate_identity_hash=sci_hash,
        provenance_path=prov_p,
        provenance_sha256=actual_prov_sha,
        synthetic_test_evidence=synthetic_test_evidence,
    )

    # Step 3: Verify row-by-row PIT evidence
    pit_rows = verify_derived_snapshot_pit(derived.path)
    all_temporal_valid = all(r.temporal_order_valid for r in pit_rows)
    all_target_valid = all(r.target_non_overlapping for r in pit_rows)
    all_feat_prior = all(r.feature_available_at_as_of for r in pit_rows)

    if not (all_temporal_valid and all_target_valid and all_feat_prior):
        raise SignalBindingError(
            "PIT_VERIFICATION_FAILED",
            f"Row-by-row PIT verification failed: temporal={all_temporal_valid}, target={all_target_valid}",
        )

    # Step 4: Assemble Precheck Report
    report = {
        "schema_version": "research_lab.precheck_report.v1",
        "precheck_status": "PRECHECK_PASS",
        "candidate": {
            "hypothesis_id": hyp_dict.get("hypothesis_id", "unknown"),
            "scientific_identity_hash": sci_hash,
            "hypothesis_content_hash": content_hash,
            "title": hyp_dict.get("title", ""),
            "symbol": spec.symbol,
            "signal_family": spec.signal_family,
            "formula_id": spec.formula_id,
            "canonical_signal_definition": spec.canonical_signal_definition,
            "canonical_target": spec.canonical_target,
            "expected_direction": spec.expected_direction,
            "lookback_k": spec.lookback_k,
        },
        "source_provenance": {
            "provenance_path": str(prov_p),
            "provenance_sha256": v2.sha(prov_p.read_bytes()),
            "source_days_count": len(source_days),
            "raw_start_trade_day": source_days[0]["day"],
            "raw_end_trade_day": source_days[-1]["day"],
            "source_signatures_disclosed": True,
            "backfill_authenticity_limitations": prov_data.get("limitations", []),
        },
        "derived_snapshot": {
            "path": str(derived.path),
            "sha256": derived.sha256,
            "byte_length": derived.byte_length,
            "row_count": derived.row_count,
            "time_range": derived.time_range,
            "metadata_path": str(derived.metadata_path),
            "metadata_sha256": derived.metadata_sha256,
        },
        "pit_verification": {
            "rows_checked": len(pit_rows),
            "all_temporal_order_valid": all_temporal_valid,
            "all_target_non_overlapping": all_target_valid,
            "all_feature_available_at_as_of": all_feat_prior,
            "row_timeline": [
                {
                    "trade_day": r.trade_day,
                    "symbol": r.symbol,
                    "feature_val": r.feature_val,
                    "target_val": r.target_val,
                    "first_seen_at": r.feature_availability_time,
                    "as_of_time": r.as_of_time,
                    "target_start_time": r.target_start_time,
                    "feature_window": f"{r.feature_start_trade_day}..{r.feature_end_trade_day}",
                    "target_window": f"{r.target_start_trade_day}..{r.target_end_trade_day}",
                }
                for r in pit_rows
            ],
        },
    }

    report_bytes = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    try:
        with report_p.open("xb") as rfh:
            rfh.write(report_bytes)
    except FileExistsError as exc:
        raise SignalBindingError(
            "SNAPSHOT_ALREADY_EXISTS",
            f"Precheck report already exists and overwrite is strictly forbidden: {report_p}",
        ) from exc
    report["report_path"] = str(report_p)
    report["report_sha256"] = hashlib.sha256(report_bytes).hexdigest()

    return report
