from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Iterable
from zoneinfo import ZoneInfo


CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MANIFEST_SCHEMA_VERSION = "commodity_c_fast_l1_l5_audit_manifest_v2"
MAX_AUDIT_WINDOW_HOURS = 96
MAX_ROWS_PER_CONTRACT = 500_000
FROZEN_PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
PRODUCT_EXCHANGES = {
    "ag": "SHFE",
    "al": "SHFE",
    "au": "SHFE",
    "bu": "SHFE",
    "cu": "SHFE",
    "rb": "SHFE",
    "ru": "SHFE",
    "sc": "INE",
    "sp": "SHFE",
    "zn": "SHFE",
}
REQUIRED_CURRENT_SESSIONS = (
    "night_open",
    "night_session",
    "day_open",
    "day_session",
)
CLASSIFICATION_SEVERITY = {
    "L5_USABLE": 0,
    "DEGRADED": 1,
    "L1_ONLY": 2,
    "UNUSABLE": 3,
}
THRESHOLDS: dict[str, float] = {
    "min_l1_complete_ratio": 0.995,
    "min_l5_complete_ratio": 0.95,
    "max_transport_stale_ratio": 0.01,
    "max_clock_skew_ratio": 0.001,
    "max_crossed_ratio": 0.0001,
    "max_locked_ratio": 0.05,
    "max_inverted_depth_ratio": 0.001,
    "transport_stale_seconds": 5.0,
    "clock_skew_seconds": 1.0,
    "cadence_gap_seconds": 5.0,
    "max_continuous_gap_seconds": 300.0,
    "max_execution_window_gap_seconds": 5.0,
    "min_rows_per_required_session": 20.0,
    "min_rows_per_execution_window": 11.0,
    "max_required_session_gap_seconds": 5.0,
    "min_positive_volume_deltas_for_semantics": 10.0,
    "min_last_volume_match_ratio": 0.95,
}
CHINA_TZ = ZoneInfo("Asia/Shanghai")
CANONICAL_SESSION_CLOCKS = {
    "night_open": ("21:00:00", "21:02:05", "night"),
    "night_session": ("21:10:00", "21:20:00", "night"),
    "day_open": ("09:00:00", "09:02:05", "day"),
    "day_session": ("09:10:00", "09:20:00", "day"),
}
VT_SYMBOL_PATTERN = re.compile(
    r"^(?P<symbol>[A-Za-z]+[0-9]{3,4})\.(?P<exchange>[A-Z]+)$"
)
EXACT_CONTRACT_PATTERN = re.compile(
    r"^(?P<exchange>[A-Z]+)\.(?P<symbol>[A-Za-z]+[0-9]{3,4})$"
)
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


class AuditSemanticReplayError(RuntimeError):
    """The signed aggregate evidence cannot be replayed exactly."""


@dataclass(frozen=True)
class ContractSpec:
    product: str
    role: str
    exact_contract: str
    vt_symbol: str


@dataclass(frozen=True)
class ExecutionWindow:
    window_id: str
    product: str
    vt_symbol: str
    execution_time: datetime
    window_seconds: int

    @property
    def start(self) -> datetime:
        return self.execution_time - timedelta(seconds=self.window_seconds)

    @property
    def end(self) -> datetime:
        return self.execution_time + timedelta(seconds=self.window_seconds)


@dataclass(frozen=True)
class SessionWindow:
    name: str
    start: datetime
    end: datetime


def _utc(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditSemanticReplayError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuditSemanticReplayError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 9) if denominator else 0.0


def worst_classification(values: Iterable[str]) -> str:
    normalized = list(values)
    if not normalized:
        return "UNUSABLE"
    return max(
        normalized,
        key=lambda item: CLASSIFICATION_SEVERITY.get(item, 99),
    )


def classify_depth_quality(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> str:
    limits = thresholds or THRESHOLDS
    rows = int(metrics.get("rows") or 0)
    if rows == 0 or float(metrics.get("l1_complete_ratio") or 0) < limits[
        "min_l1_complete_ratio"
    ]:
        return "UNUSABLE"
    if float(metrics.get("l5_complete_ratio") or 0) < limits[
        "min_l5_complete_ratio"
    ]:
        return "L1_ONLY"
    return "L5_USABLE"


def classify_volume_semantics_quality(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> str:
    limits = thresholds or THRESHOLDS
    volume = metrics.get("volume_semantics") or {}
    positive = int(volume.get("positive_volume_deltas") or 0)
    if positive < int(limits["min_positive_volume_deltas_for_semantics"]):
        return "INSUFFICIENT"
    inconsistent = (
        int(volume.get("cumulative_volume_decreases") or 0) > 0
        or int(volume.get("volume_change_without_last_volume") or 0) > 0
        or int(volume.get("last_volume_without_volume_change") or 0) > 0
        or float(volume.get("last_volume_match_ratio") or 0)
        < limits["min_last_volume_match_ratio"]
    )
    return "INCONSISTENT" if inconsistent else "VALIDATED"


def classify_metrics(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> str:
    limits = thresholds or THRESHOLDS
    depth_quality = classify_depth_quality(metrics, limits)
    if depth_quality != "L5_USABLE":
        return depth_quality
    anomalies = metrics.get("anomalies") or {}
    failed = (
        float(anomalies.get("transport_stale_ratio") or 0)
        > limits["max_transport_stale_ratio"]
        or float(anomalies.get("clock_skew_ratio") or 0)
        > limits["max_clock_skew_ratio"]
        or float(anomalies.get("crossed_ratio") or 0) > limits["max_crossed_ratio"]
        or float(anomalies.get("locked_ratio") or 0) > limits["max_locked_ratio"]
        or float(anomalies.get("bid_inverted_ratio") or 0)
        > limits["max_inverted_depth_ratio"]
        or float(anomalies.get("ask_inverted_ratio") or 0)
        > limits["max_inverted_depth_ratio"]
        or any(
            int(anomalies.get(field) or 0) > 0
            for field in (
                "missing_received_at_rows",
                "missing_ingest_id_rows",
                "missing_ingest_seq_rows",
                "missing_trading_day_rows",
                "missing_last_price_rows",
                "duplicate_ingest_ids",
                "non_positive_ingest_seq_rows",
                "ingest_seq_non_increasing_rows",
                "same_ts_duplicate_ingest_seq",
            )
        )
        or classify_volume_semantics_quality(metrics, limits) != "VALIDATED"
    )
    return "DEGRADED" if failed else "L5_USABLE"


def quality_breakdown(
    metrics: dict[str, Any],
    combined_classification: str | None = None,
) -> dict[str, str]:
    return {
        "depth_quality": classify_depth_quality(metrics),
        "volume_semantics_quality": classify_volume_semantics_quality(metrics),
        "combined_classification": (
            combined_classification or str(metrics["classification"])
        ),
    }


def canonical_manifest_sha256(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(
        {key: value for key, value in manifest.items() if key != "roll_expected"},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _contract_spec(product: str, role: str, value: str) -> ContractSpec:
    exact_match = EXACT_CONTRACT_PATTERN.fullmatch(value)
    vt_match = VT_SYMBOL_PATTERN.fullmatch(value)
    if product not in FROZEN_PRODUCTS or not (exact_match or vt_match):
        raise AuditSemanticReplayError(f"invalid contract for frozen product {product}")
    match = exact_match or vt_match
    assert match is not None
    exchange = match.group("exchange")
    symbol = match.group("symbol")
    symbol_product = re.match(r"^[A-Za-z]+", symbol)
    if (
        not symbol_product
        or symbol_product.group(0).lower() != product
        or PRODUCT_EXCHANGES[product] != exchange
    ):
        raise AuditSemanticReplayError("contract product/exchange binding is invalid")
    return ContractSpec(
        product,
        role,
        f"{exchange}.{symbol}",
        f"{symbol}.{exchange}",
    )


def _manifest_audit_window(manifest: dict[str, Any]) -> tuple[datetime, datetime, str]:
    raw = manifest.get("audit_window")
    if not isinstance(raw, dict):
        raise AuditSemanticReplayError("manifest audit window is invalid")
    start = _utc(raw.get("start"), "audit_window.start")
    end = _utc(raw.get("end_exclusive"), "audit_window.end_exclusive")
    trading_day = str(raw.get("trading_day") or "")
    try:
        trading_date = datetime.strptime(trading_day, "%Y%m%d")
    except ValueError as exc:
        raise AuditSemanticReplayError("trading_day is invalid") from exc
    if end <= start or end - start > timedelta(hours=MAX_AUDIT_WINDOW_HOURS):
        raise AuditSemanticReplayError("manifest audit window is invalid")
    return start, end, trading_date.strftime("%Y%m%d")


def _manifest_session_windows(
    manifest: dict[str, Any],
    audit_start: datetime,
    audit_end: datetime,
    trading_day: str,
) -> list[SessionWindow]:
    raw_sessions = manifest.get("session_windows")
    if not isinstance(raw_sessions, dict) or set(raw_sessions) != set(
        REQUIRED_CURRENT_SESSIONS
    ):
        raise AuditSemanticReplayError("manifest session windows are invalid")
    trading_date = datetime.strptime(trading_day, "%Y%m%d").date()
    result: list[SessionWindow] = []
    for name in REQUIRED_CURRENT_SESSIONS:
        raw = raw_sessions[name]
        if not isinstance(raw, dict):
            raise AuditSemanticReplayError("manifest session window is invalid")
        start = _utc(raw.get("start"), f"session_windows.{name}.start")
        end = _utc(raw.get("end_exclusive"), f"session_windows.{name}.end")
        start_clock, end_clock, day_role = CANONICAL_SESSION_CLOCKS[name]
        local_start = start.astimezone(CHINA_TZ)
        local_end = end.astimezone(CHINA_TZ)
        if (
            end <= start
            or start < audit_start
            or end > audit_end
            or local_start.strftime("%H:%M:%S") != start_clock
            or local_end.strftime("%H:%M:%S") != end_clock
            or local_start.date() != local_end.date()
            or (day_role == "day" and local_start.date() != trading_date)
            or (
                day_role == "night"
                and not 1 <= (trading_date - local_start.date()).days <= 3
            )
        ):
            raise AuditSemanticReplayError("manifest session window is not canonical")
        result.append(SessionWindow(name, start, end))
    ordered = sorted(result, key=lambda item: item.start)
    if any(current.start < previous.end for previous, current in zip(ordered, ordered[1:])):
        raise AuditSemanticReplayError("manifest session windows overlap")
    return result


def normalize_manifest_payload(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], list[ContractSpec], list[SessionWindow], list[ExecutionWindow]]:
    allowed = {
        "schema_version",
        "candidate_id",
        "snapshot_id",
        "audit_window",
        "session_windows",
        "targets",
        "execution_windows",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != allowed
        or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION
        or manifest.get("candidate_id") != CANDIDATE_ID
        or ID_PATTERN.fullmatch(str(manifest.get("snapshot_id") or "")) is None
    ):
        raise AuditSemanticReplayError("manifest foundation is invalid")
    audit_start, audit_end, trading_day = _manifest_audit_window(manifest)
    sessions = _manifest_session_windows(manifest, audit_start, audit_end, trading_day)
    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != len(FROZEN_PRODUCTS):
        raise AuditSemanticReplayError("manifest target set is invalid")
    products: set[str] = set()
    contracts: list[ContractSpec] = []
    roll_expected: dict[str, bool] = {}
    for target in targets:
        if not isinstance(target, dict) or set(target) != {
            "product",
            "exact_contract",
            "previous_exact_contract",
            "roll_expected",
        }:
            raise AuditSemanticReplayError("manifest target is invalid")
        product = str(target["product"]).lower()
        if product in products:
            raise AuditSemanticReplayError("manifest product is duplicated")
        products.add(product)
        current = _contract_spec(product, "current", str(target["exact_contract"]))
        contracts.append(current)
        expected = bool(target["roll_expected"])
        roll_expected[product] = expected
        previous_raw = target["previous_exact_contract"]
        if previous_raw:
            previous = _contract_spec(product, "previous", str(previous_raw))
            if previous.vt_symbol != current.vt_symbol:
                contracts.append(previous)
            elif expected:
                raise AuditSemanticReplayError("expected roll aliases current contract")
        elif expected:
            raise AuditSemanticReplayError("expected roll has no previous contract")
    if products != set(FROZEN_PRODUCTS):
        raise AuditSemanticReplayError("manifest frozen product set is incomplete")
    known = {(item.product, item.vt_symbol) for item in contracts}
    windows_raw = manifest.get("execution_windows")
    if not isinstance(windows_raw, list):
        raise AuditSemanticReplayError("manifest execution windows are invalid")
    windows: list[ExecutionWindow] = []
    ids: set[str] = set()
    for raw in windows_raw:
        if not isinstance(raw, dict) or set(raw) != {
            "window_id",
            "product",
            "exact_contract",
            "execution_time",
            "window_seconds",
        }:
            raise AuditSemanticReplayError("manifest execution window is invalid")
        window_id = str(raw["window_id"])
        product = str(raw["product"]).lower()
        spec = _contract_spec(product, "window", str(raw["exact_contract"]))
        execution_time = _utc(raw["execution_time"], "execution window time")
        seconds = int(raw["window_seconds"])
        window = ExecutionWindow(window_id, product, spec.vt_symbol, execution_time, seconds)
        if (
            ID_PATTERN.fullmatch(window_id) is None
            or window_id in ids
            or (product, spec.vt_symbol) not in known
            or not 1 <= seconds <= 3600
            or window.start < audit_start
            or window.end > audit_end
        ):
            raise AuditSemanticReplayError("manifest execution window binding is invalid")
        ids.add(window_id)
        windows.append(window)
    normalized = dict(manifest)
    normalized["roll_expected"] = roll_expected
    return normalized, contracts, sessions, windows


def summarize_products(
    contracts: list[dict[str, Any]],
    windows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    blockers: list[str] = []
    products: list[dict[str, Any]] = []
    roll_expected = manifest.get("roll_expected") or {}
    for product in FROZEN_PRODUCTS:
        product_contracts = [item for item in contracts if item["product"] == product]
        product_windows = [item for item in windows if item["product"] == product]
        classifications = [item["classification"] for item in product_contracts]
        current = next(
            (item for item in product_contracts if item["role"] == "current"),
            None,
        )
        current_windows = [
            item
            for item in product_windows
            if current and item["vt_symbol"] == current["vt_symbol"]
        ]
        if not current_windows:
            classifications.append("DEGRADED")
            blockers.append(f"{product}:missing_current_execution_window")
        else:
            classifications.extend(item["classification"] for item in current_windows)
        if roll_expected.get(product):
            previous = next(
                (item for item in product_contracts if item["role"] == "previous"),
                None,
            )
            if previous is None:
                classifications.append("UNUSABLE")
                blockers.append(f"{product}:missing_previous_roll_contract")
            else:
                previous_windows = [
                    item
                    for item in product_windows
                    if item["vt_symbol"] == previous["vt_symbol"]
                ]
                if not previous_windows:
                    classifications.append("DEGRADED")
                    blockers.append(f"{product}:missing_previous_execution_window")
                else:
                    classifications.extend(
                        item["classification"] for item in previous_windows
                    )
        missing = []
        if current:
            missing = [
                name
                for name in REQUIRED_CURRENT_SESSIONS
                if int(current["sessions"][name]["rows"]) == 0
            ]
        if missing:
            classifications.append("UNUSABLE")
            blockers.append(f"{product}:missing_sessions:{','.join(missing)}")
        insufficient = []
        if current:
            insufficient = [
                name
                for name in REQUIRED_CURRENT_SESSIONS
                if int(current["sessions"][name]["rows"]) > 0
                and current["sessions"][name]["classification"] != "L5_USABLE"
            ]
        if insufficient:
            classifications.append("DEGRADED")
            blockers.append(f"{product}:session_not_l5:{','.join(insufficient)}")
        classification = worst_classification(classifications or ["UNUSABLE"])
        rows = sum(int(item["all"]["rows"]) for item in product_contracts)
        if rows == 0:
            blockers.append(f"{product}:no_rows")
        products.append(
            {
                "product": product,
                "rows": rows,
                "contracts": len(product_contracts),
                "execution_windows": len(product_windows),
                "missing_sessions": missing,
                "insufficient_sessions": insufficient,
                "classification": classification,
            }
        )
    return products, blockers


def _require_metric_projection(metrics: dict[str, Any], label: str) -> str:
    rows = int(metrics["rows"])
    for count_field, ratio_field in (
        ("l1_complete_rows", "l1_complete_ratio"),
        ("l5_complete_rows", "l5_complete_ratio"),
    ):
        count = int(metrics[count_field])
        if count > rows or float(metrics[ratio_field]) != _ratio(count, rows):
            raise AuditSemanticReplayError(f"{label} ratio does not replay")
    anomalies = metrics["anomalies"]
    for count_field, ratio_field in (
        ("crossed_rows", "crossed_ratio"),
        ("locked_rows", "locked_ratio"),
        ("bid_inverted_rows", "bid_inverted_ratio"),
        ("ask_inverted_rows", "ask_inverted_ratio"),
        ("transport_stale_rows", "transport_stale_ratio"),
        ("clock_skew_rows", "clock_skew_ratio"),
    ):
        count = int(anomalies[count_field])
        if count > rows or float(anomalies[ratio_field]) != _ratio(count, rows):
            raise AuditSemanticReplayError(f"{label} anomaly ratio does not replay")
    volume = metrics["volume_semantics"]
    positive = int(volume["positive_volume_deltas"])
    matched = int(volume["last_volume_matches_positive_delta"])
    if matched > positive or float(volume["last_volume_match_ratio"]) != _ratio(
        matched, positive
    ):
        raise AuditSemanticReplayError(f"{label} volume ratio does not replay")
    return classify_metrics(metrics, THRESHOLDS)


def _require_coverage_projection(
    coverage: dict[str, Any],
    *,
    max_boundary_gap_seconds: float,
    label: str,
) -> None:
    gaps = (
        coverage["start_boundary_gap_seconds"],
        coverage["end_boundary_gap_seconds"],
        coverage["max_observed_tick_gap_seconds"],
    )
    finite = [float(value) for value in gaps if value is not None]
    expected_max = max(finite) if finite else None
    expected_complete = bool(
        gaps[0] is not None
        and gaps[1] is not None
        and 0 <= float(gaps[0]) <= max_boundary_gap_seconds
        and 0 <= float(gaps[1]) <= max_boundary_gap_seconds
    )
    if (
        coverage["max_gap_seconds"] != expected_max
        or coverage["boundary_coverage_complete"] is not expected_complete
    ):
        raise AuditSemanticReplayError(f"{label} coverage does not replay")


def replay_audit_evidence_semantics(
    evidence: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[str, ...]:
    normalized, contract_specs, session_windows, expected_windows = (
        normalize_manifest_payload(manifest)
    )
    if (
        evidence["candidate_id"] != CANDIDATE_ID
        or evidence["snapshot_id"] != normalized["snapshot_id"]
        or evidence["manifest_sha256"] != canonical_manifest_sha256(manifest)
        or evidence["thresholds"] != THRESHOLDS
        or evidence["query_limits"]
        != {
            "max_rows_per_contract": MAX_ROWS_PER_CONTRACT,
            "sql_limit_per_contract": MAX_ROWS_PER_CONTRACT + 1,
        }
    ):
        raise AuditSemanticReplayError("audit foundation does not replay")
    start, end, day = _manifest_audit_window(normalized)
    audit_window = evidence["audit_window"]
    if (
        _utc(audit_window["start"], "audit start") != start
        or _utc(audit_window["end_exclusive"], "audit end") != end
        or audit_window["trading_day"] != day
        or audit_window["display_timezone"] != "Asia/Shanghai"
    ):
        raise AuditSemanticReplayError("audit window does not replay")
    actual_contracts: dict[tuple[str, str], dict[str, Any]] = {}
    for item in evidence["contracts"]:
        key = (str(item["product"]), str(item["role"]))
        if key in actual_contracts:
            raise AuditSemanticReplayError("duplicate audit product/role")
        actual_contracts[key] = item
    expected_contracts = {(item.product, item.role): item for item in contract_specs}
    if set(actual_contracts) != set(expected_contracts):
        raise AuditSemanticReplayError("audit contract roles do not replay")
    replayed_contracts: list[dict[str, Any]] = []
    for key, spec in expected_contracts.items():
        item = actual_contracts[key]
        if item["exact_contract"] != spec.exact_contract or item["vt_symbol"] != spec.vt_symbol:
            raise AuditSemanticReplayError("exact_contract/vt_symbol does not replay")
        all_classification = _require_metric_projection(item["all"], f"{spec.vt_symbol}:all")
        if item["all"]["classification"] != all_classification:
            raise AuditSemanticReplayError("all-segment classification does not replay")
        if int(item["scanned_rows"]) != int(item["all"]["rows"]):
            raise AuditSemanticReplayError("scanned rows do not replay")
        replayed_sessions: dict[str, dict[str, Any]] = {}
        session_classifications: list[str] = []
        for session in session_windows:
            metrics = item["sessions"][session.name]
            coverage = item["session_coverage"][session.name]
            classification = _require_metric_projection(metrics, f"{spec.vt_symbol}:{session.name}")
            if _utc(coverage["start"], "coverage start") != session.start or _utc(
                coverage["end_exclusive"], "coverage end"
            ) != session.end:
                raise AuditSemanticReplayError("session window does not replay")
            _require_coverage_projection(
                coverage,
                max_boundary_gap_seconds=THRESHOLDS["max_required_session_gap_seconds"],
                label=f"{spec.vt_symbol}:{session.name}",
            )
            if (
                int(metrics["rows"]) < int(THRESHOLDS["min_rows_per_required_session"])
                or not coverage["boundary_coverage_complete"]
                or coverage["max_gap_seconds"] is None
                or coverage["max_gap_seconds"] > THRESHOLDS["max_required_session_gap_seconds"]
            ):
                classification = worst_classification(
                    [classification, "DEGRADED" if metrics["rows"] else "UNUSABLE"]
                )
            if metrics["classification"] != classification or coverage["classification"] != classification:
                raise AuditSemanticReplayError("session classification does not replay")
            replayed_sessions[session.name] = {**metrics, "classification": classification}
            session_classifications.append(classification)
        contract_classifications = [all_classification]
        if spec.role == "current":
            contract_classifications.extend(session_classifications)
            if any(
                0 < int(metrics["rows"]) < int(THRESHOLDS["min_rows_per_required_session"])
                for metrics in replayed_sessions.values()
            ):
                contract_classifications.append("DEGRADED")
        contract_classification = worst_classification(contract_classifications)
        if item["classification"] != contract_classification:
            raise AuditSemanticReplayError("contract classification does not replay")
        replayed_contracts.append(
            {**item, "classification": contract_classification, "sessions": replayed_sessions}
        )
    actual_windows: dict[str, dict[str, Any]] = {}
    for item in evidence["execution_windows"]:
        window_id = str(item["window_id"])
        if window_id in actual_windows:
            raise AuditSemanticReplayError("duplicate audit execution window")
        actual_windows[window_id] = item
    expected_by_id = {item.window_id: item for item in expected_windows}
    if set(actual_windows) != set(expected_by_id):
        raise AuditSemanticReplayError("execution windows do not replay")
    replayed_windows: list[dict[str, Any]] = []
    for window_id, expected in expected_by_id.items():
        item = actual_windows[window_id]
        if (
            item["product"] != expected.product
            or item["vt_symbol"] != expected.vt_symbol
            or _utc(item["execution_time"], "execution time") != expected.execution_time
            or int(item["window_seconds"]) != expected.window_seconds
            or int(item["rows_before"]) + int(item["rows_after"]) != int(item["metrics"]["rows"])
        ):
            raise AuditSemanticReplayError("execution window identity does not replay")
        classification = _require_metric_projection(item["metrics"], window_id)
        if item["metrics"]["classification"] != classification:
            raise AuditSemanticReplayError("execution-window metrics do not replay")
        _require_coverage_projection(
            item,
            max_boundary_gap_seconds=THRESHOLDS["max_execution_window_gap_seconds"],
            label=window_id,
        )
        if (
            not item["rows_before"]
            or not item["rows_after"]
            or int(item["metrics"]["rows"]) < int(THRESHOLDS["min_rows_per_execution_window"])
            or not item["boundary_coverage_complete"]
            or item["max_gap_seconds"] is None
            or item["max_gap_seconds"] > THRESHOLDS["max_execution_window_gap_seconds"]
        ):
            classification = worst_classification(
                [classification, "DEGRADED" if item["metrics"]["rows"] else "UNUSABLE"]
            )
        if item["classification"] != classification:
            raise AuditSemanticReplayError("execution-window classification does not replay")
        replayed_windows.append({**item, "classification": classification})
    products, blockers = summarize_products(replayed_contracts, replayed_windows, normalized)
    counts = {name: 0 for name in CLASSIFICATION_SEVERITY}
    for item in products:
        counts[item["classification"]] += 1
    overall = worst_classification(item["classification"] for item in products)
    scanned_rows = sum(int(item["scanned_rows"]) for item in replayed_contracts)
    summary = {
        "expected_products": len(FROZEN_PRODUCTS),
        "observed_products": sum(int(item["rows"] > 0) for item in products),
        "contracts": len(replayed_contracts),
        "rows": scanned_rows,
        "scanned_rows": scanned_rows,
        "max_contract_rows_observed": max(
            (int(item["scanned_rows"]) for item in replayed_contracts), default=0
        ),
        "classification_counts": counts,
        "overall_conclusion": overall,
        "p0_pass": overall == "L5_USABLE" and not blockers,
    }
    breakdowns: list[dict[str, Any]] = []
    for item in replayed_contracts:
        for segment, metrics in (("all", item["all"]), *item["sessions"].items()):
            breakdowns.append(
                {
                    "record_type": "contract_segment",
                    "product": item["product"],
                    "role": item["role"],
                    "vt_symbol": item["vt_symbol"],
                    "segment": segment,
                    **quality_breakdown(metrics, metrics["classification"]),
                }
            )
    for item in replayed_windows:
        breakdowns.append(
            {
                "record_type": "execution_window",
                "product": item["product"],
                "role": "window",
                "vt_symbol": item["vt_symbol"],
                "segment": item["window_id"],
                **quality_breakdown(item["metrics"], item["classification"]),
            }
        )
    if (
        evidence["products"] != products
        or evidence["blockers"] != blockers
        or evidence["summary"] != summary
        or evidence["quality_breakdowns"] != breakdowns
    ):
        raise AuditSemanticReplayError("derived audit conclusions do not replay")
    return tuple(sorted(item.exact_contract for item in contract_specs if item.role == "current"))


__all__ = [
    "AuditSemanticReplayError",
    "classify_depth_quality",
    "classify_metrics",
    "classify_volume_semantics_quality",
    "normalize_manifest_payload",
    "quality_breakdown",
    "replay_audit_evidence_semantics",
    "summarize_products",
    "worst_classification",
]
