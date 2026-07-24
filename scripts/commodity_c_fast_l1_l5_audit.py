#!/usr/bin/env python3
"""Read-only QuestDB L1-L5 audit for Issue #114 C_FAST exact contracts."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

try:
    import psycopg
except ImportError:  # pragma: no cover - deployment dependency
    psycopg = None  # type: ignore[assignment]


SCHEMA_VERSION = "commodity_c_fast_l1_l5_audit_v2"
MANIFEST_SCHEMA_VERSION = "commodity_c_fast_l1_l5_audit_manifest_v2"
READONLY_PROOF_SCHEMA_VERSION = (
    "commodity_c_fast_questdb_readonly_proof_v1"
)
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
MAX_AUDIT_WINDOW_HOURS = 96
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DSN_BYTES = 64 * 1024
MAX_ROWS_PER_CONTRACT = 500_000
QUESTDB_CONNECT_TIMEOUT_SECONDS = 10
QUESTDB_STATEMENT_TIMEOUT_MS = 60_000
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
)
READONLY_PROOF_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
)
LEGACY_EVIDENCE_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
)
LEGACY_EVIDENCE_RESOURCE_URI = (
    "urn:vnpy-web-bridge:schema:commodity-c-fast-l1-l5-audit-v1"
)
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
CHINA_TZ = ZoneInfo("Asia/Shanghai")
CANONICAL_SESSION_CLOCKS = {
    "night_open": ("21:00:00", "21:02:05", "night"),
    "night_session": ("21:10:00", "21:20:00", "night"),
    "day_open": ("09:00:00", "09:02:05", "day"),
    "day_session": ("09:10:00", "09:20:00", "day"),
}
QUERY_COLUMNS = (
    "ts",
    "received_at",
    "ingest_id",
    "ingest_seq",
    "trading_day",
    "last_price",
    "last_volume",
    "volume",
    *(f"bid_price_{level}" for level in range(1, 6)),
    *(f"ask_price_{level}" for level in range(1, 6)),
    *(f"bid_volume_{level}" for level in range(1, 6)),
    *(f"ask_volume_{level}" for level in range(1, 6)),
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
VT_SYMBOL_PATTERN = re.compile(r"^(?P<symbol>[A-Za-z]+[0-9]{3,4})\.(?P<exchange>[A-Z]+)$")
EXACT_CONTRACT_PATTERN = re.compile(r"^(?P<exchange>[A-Z]+)\.(?P<symbol>[A-Za-z]+[0-9]{3,4})$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
READONLY_PARAMETER_KEYS = (
    "pg.readonly.password",
    "pg.readonly.user",
    "pg.readonly.user.enabled",
    "pg.security.readonly",
    "pg.user",
    "readonly",
)
READONLY_IDENTITY_SQL = "SELECT current_user(), build()"
READONLY_PARAMETERS_SQL = (
    "(SHOW PARAMETERS) WHERE property_path IN "
    "('pg.readonly.password', 'pg.readonly.user', "
    "'pg.readonly.user.enabled', 'pg.security.readonly', 'pg.user', "
    "'readonly') "
    "ORDER BY property_path"
)


@dataclass(frozen=True)
class ReadonlyProofSnapshot:
    principal: str
    readonly_user: str
    admin_user: str
    questdb_build: str
    readonly_user_enabled_source: str
    readonly_user_source: str
    readonly_password_source: str
    admin_user_source: str
    global_pgwire_readonly_source: str
    instance_readonly_source: str

    def evidence(self) -> dict[str, Any]:
        return {
            "questdb_build": self.questdb_build,
            "readonly_user_enabled": True,
            "principal_matches_readonly_user": True,
            "principal_differs_admin": True,
            "global_pgwire_readonly": False,
            "instance_readonly": False,
            "configuration_sources": {
                "pg.readonly.user.enabled": (
                    self.readonly_user_enabled_source
                ),
                "pg.readonly.user": self.readonly_user_source,
                "pg.readonly.password": self.readonly_password_source,
                "pg.user": self.admin_user_source,
                "pg.security.readonly": (
                    self.global_pgwire_readonly_source
                ),
                "readonly": self.instance_readonly_source,
            },
        }


class AuditError(RuntimeError):
    """Expected audit input or read failure."""


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


@dataclass
class MetricsAccumulator:
    thresholds: dict[str, float]
    expected_trading_day: str | None = None
    row_count: int = 0
    l1_complete_rows: int = 0
    l5_complete_rows: int = 0
    crossed_rows: int = 0
    locked_rows: int = 0
    bid_inverted_rows: int = 0
    ask_inverted_rows: int = 0
    transport_stale_rows: int = 0
    clock_skew_rows: int = 0
    missing_received_at_rows: int = 0
    missing_ingest_id_rows: int = 0
    missing_ingest_seq_rows: int = 0
    missing_trading_day_rows: int = 0
    missing_last_price_rows: int = 0
    duplicate_ingest_ids: int = 0
    non_positive_ingest_seq_rows: int = 0
    ingest_seq_non_increasing_rows: int = 0
    ingest_seq_regression_rows: int = 0
    ingest_seq_repeat_across_timestamp_rows: int = 0
    ingest_seq_reset_candidates: int = 0
    same_ts_duplicate_ingest_seq: int = 0
    duplicate_exchange_timestamps: int = 0
    cadence_gap_count: int = 0
    session_break_gap_count: int = 0
    cumulative_volume_decreases: int = 0
    positive_volume_deltas: int = 0
    last_volume_matches_positive_delta: int = 0
    volume_change_without_last_volume: int = 0
    last_volume_without_volume_change: int = 0
    level_price_rows: dict[str, list[int]] = field(
        default_factory=lambda: {"bid": [0] * 5, "ask": [0] * 5}
    )
    level_volume_rows: dict[str, list[int]] = field(
        default_factory=lambda: {"bid": [0] * 5, "ask": [0] * 5}
    )
    level_pair_rows: dict[str, list[int]] = field(
        default_factory=lambda: {"bid": [0] * 5, "ask": [0] * 5}
    )
    latency_ms: list[float] = field(default_factory=list)
    interval_ms: list[float] = field(default_factory=list)
    seen_ingest_ids: set[str] = field(default_factory=set)
    _last_ts: datetime | None = None
    _last_ingest_seq: int | None = None
    _last_ts_ingest_seqs: set[int] = field(default_factory=set)
    _last_trading_day: str | None = None
    _last_cumulative_volume: float | None = None

    def add(self, row: dict[str, Any]) -> None:
        ts = _as_utc_datetime(row.get("ts"), "market_ticks.ts")
        self.row_count += 1

        received_value = row.get("received_at")
        received_at = None
        if received_value is None or received_value == "":
            self.missing_received_at_rows += 1
        else:
            received_at = _as_utc_datetime(
                received_value,
                "market_ticks.received_at",
            )
        ingest_id = str(row.get("ingest_id") or "")
        if ingest_id:
            if ingest_id in self.seen_ingest_ids:
                self.duplicate_ingest_ids += 1
            else:
                self.seen_ingest_ids.add(ingest_id)
        else:
            self.missing_ingest_id_rows += 1

        ingest_seq_value = row.get("ingest_seq")
        ingest_seq_present = ingest_seq_value is not None and ingest_seq_value != ""
        if not ingest_seq_present:
            self.missing_ingest_seq_rows += 1
        ingest_seq = _as_int(ingest_seq_value, default=0)
        if ingest_seq_present and ingest_seq <= 0:
            self.non_positive_ingest_seq_rows += 1

        previous_ts = self._last_ts
        previous_ingest_seq = self._last_ingest_seq
        if (
            ingest_seq_present
            and previous_ingest_seq is not None
            and previous_ts is not None
            and ts > previous_ts
            and ingest_seq <= previous_ingest_seq
        ):
            self.ingest_seq_non_increasing_rows += 1
            if ingest_seq < previous_ingest_seq:
                self.ingest_seq_regression_rows += 1
                if ingest_seq <= 1:
                    self.ingest_seq_reset_candidates += 1
            else:
                self.ingest_seq_repeat_across_timestamp_rows += 1

        if self._last_ts == ts:
            self.duplicate_exchange_timestamps += 1
            if ingest_seq in self._last_ts_ingest_seqs:
                self.same_ts_duplicate_ingest_seq += 1
            self._last_ts_ingest_seqs.add(ingest_seq)
        else:
            if self._last_ts is not None:
                interval = (ts - self._last_ts).total_seconds()
                if interval >= 0:
                    interval_ms = interval * 1000
                    self.interval_ms.append(interval_ms)
                    if (
                        interval > self.thresholds["cadence_gap_seconds"]
                        and interval <= self.thresholds["max_continuous_gap_seconds"]
                    ):
                        self.cadence_gap_count += 1
                    elif interval > self.thresholds["max_continuous_gap_seconds"]:
                        self.session_break_gap_count += 1
            self._last_ts = ts
            self._last_ts_ingest_seqs = {ingest_seq}
        self._last_ingest_seq = ingest_seq if ingest_seq_present else None

        if received_at is not None:
            latency = (received_at - ts).total_seconds()
            self.latency_ms.append(latency * 1000)
            if latency > self.thresholds["transport_stale_seconds"]:
                self.transport_stale_rows += 1
            if latency < -self.thresholds["clock_skew_seconds"]:
                self.clock_skew_rows += 1

        trading_day_value = str(row.get("trading_day") or "")
        if (
            not trading_day_value
            or (
                self.expected_trading_day is not None
                and trading_day_value != self.expected_trading_day
            )
        ):
            self.missing_trading_day_rows += 1
        last_price = _as_optional_float(row.get("last_price"))
        if last_price is None or last_price <= 0:
            self.missing_last_price_rows += 1

        prices: dict[str, list[float | None]] = {"bid": [], "ask": []}
        volumes: dict[str, list[float | None]] = {"bid": [], "ask": []}
        for side in ("bid", "ask"):
            for level in range(1, 6):
                price = _as_optional_float(row.get(f"{side}_price_{level}"))
                volume = _as_optional_float(row.get(f"{side}_volume_{level}"))
                prices[side].append(price)
                volumes[side].append(volume)
                price_valid = price is not None and price > 0
                volume_valid = volume is not None and volume > 0
                if price_valid:
                    self.level_price_rows[side][level - 1] += 1
                if volume_valid:
                    self.level_volume_rows[side][level - 1] += 1
                if price_valid and volume_valid:
                    self.level_pair_rows[side][level - 1] += 1

        l1_complete = all(
            prices[side][0] is not None
            and prices[side][0] > 0
            and volumes[side][0] is not None
            and volumes[side][0] > 0
            for side in ("bid", "ask")
        )
        l5_complete = all(
            prices[side][level] is not None
            and prices[side][level] > 0
            and volumes[side][level] is not None
            and volumes[side][level] > 0
            for side in ("bid", "ask")
            for level in range(5)
        )
        self.l1_complete_rows += int(l1_complete)
        self.l5_complete_rows += int(l5_complete)

        bid1 = prices["bid"][0]
        ask1 = prices["ask"][0]
        if bid1 is not None and ask1 is not None and bid1 > 0 and ask1 > 0:
            self.crossed_rows += int(bid1 > ask1)
            self.locked_rows += int(bid1 == ask1)
        self.bid_inverted_rows += int(_has_bid_inversion(prices["bid"]))
        self.ask_inverted_rows += int(_has_ask_inversion(prices["ask"]))
        self._add_volume_semantics(row)

    def _add_volume_semantics(self, row: dict[str, Any]) -> None:
        trading_day = str(row.get("trading_day") or "")
        cumulative_volume = _as_optional_float(row.get("volume"))
        last_volume = _as_optional_float(row.get("last_volume"))
        if trading_day != self._last_trading_day:
            self._last_trading_day = trading_day
            self._last_cumulative_volume = cumulative_volume
            return
        if cumulative_volume is None or self._last_cumulative_volume is None:
            self._last_cumulative_volume = cumulative_volume
            return

        delta = cumulative_volume - self._last_cumulative_volume
        if delta < 0:
            self.cumulative_volume_decreases += 1
        elif delta > 0:
            self.positive_volume_deltas += 1
            if last_volume is not None and math.isclose(
                last_volume,
                delta,
                rel_tol=1e-9,
                abs_tol=1e-9,
            ):
                self.last_volume_matches_positive_delta += 1
            if last_volume is None or last_volume <= 0:
                self.volume_change_without_last_volume += 1
        elif last_volume is not None and last_volume > 0:
            self.last_volume_without_volume_change += 1
        self._last_cumulative_volume = cumulative_volume

    def result(self) -> dict[str, Any]:
        rows = self.row_count
        l1_ratio = _ratio(self.l1_complete_rows, rows)
        l5_ratio = _ratio(self.l5_complete_rows, rows)
        anomalies = {
            "crossed_rows": self.crossed_rows,
            "crossed_ratio": _ratio(self.crossed_rows, rows),
            "locked_rows": self.locked_rows,
            "locked_ratio": _ratio(self.locked_rows, rows),
            "bid_inverted_rows": self.bid_inverted_rows,
            "bid_inverted_ratio": _ratio(self.bid_inverted_rows, rows),
            "ask_inverted_rows": self.ask_inverted_rows,
            "ask_inverted_ratio": _ratio(self.ask_inverted_rows, rows),
            "transport_stale_rows": self.transport_stale_rows,
            "transport_stale_ratio": _ratio(self.transport_stale_rows, rows),
            "clock_skew_rows": self.clock_skew_rows,
            "clock_skew_ratio": _ratio(self.clock_skew_rows, rows),
            "missing_received_at_rows": self.missing_received_at_rows,
            "missing_ingest_id_rows": self.missing_ingest_id_rows,
            "missing_ingest_seq_rows": self.missing_ingest_seq_rows,
            "missing_trading_day_rows": self.missing_trading_day_rows,
            "missing_last_price_rows": self.missing_last_price_rows,
            "duplicate_ingest_ids": self.duplicate_ingest_ids,
            "non_positive_ingest_seq_rows": self.non_positive_ingest_seq_rows,
            "ingest_seq_non_increasing_rows": self.ingest_seq_non_increasing_rows,
            "ingest_seq_regression_rows": self.ingest_seq_regression_rows,
            "ingest_seq_repeat_across_timestamp_rows": self.ingest_seq_repeat_across_timestamp_rows,
            "ingest_seq_reset_candidates": self.ingest_seq_reset_candidates,
            "duplicate_exchange_timestamps": self.duplicate_exchange_timestamps,
            "same_ts_duplicate_ingest_seq": self.same_ts_duplicate_ingest_seq,
        }
        payload = {
            "rows": rows,
            "l1_complete_rows": self.l1_complete_rows,
            "l1_complete_ratio": l1_ratio,
            "l5_complete_rows": self.l5_complete_rows,
            "l5_complete_ratio": l5_ratio,
            "depth_levels": [
                {
                    "level": level,
                    "bid_price_nonzero_ratio": _ratio(
                        self.level_price_rows["bid"][level - 1],
                        rows,
                    ),
                    "bid_volume_nonzero_ratio": _ratio(
                        self.level_volume_rows["bid"][level - 1],
                        rows,
                    ),
                    "bid_pair_nonzero_ratio": _ratio(
                        self.level_pair_rows["bid"][level - 1],
                        rows,
                    ),
                    "ask_price_nonzero_ratio": _ratio(
                        self.level_price_rows["ask"][level - 1],
                        rows,
                    ),
                    "ask_volume_nonzero_ratio": _ratio(
                        self.level_volume_rows["ask"][level - 1],
                        rows,
                    ),
                    "ask_pair_nonzero_ratio": _ratio(
                        self.level_pair_rows["ask"][level - 1],
                        rows,
                    ),
                }
                for level in range(1, 6)
            ],
            "transport_latency_ms": _distribution(self.latency_ms),
            "tick_interval_ms": _distribution(self.interval_ms),
            "cadence_gap_count": self.cadence_gap_count,
            "session_break_gap_count": self.session_break_gap_count,
            "volume_semantics": {
                "cumulative_volume_decreases": self.cumulative_volume_decreases,
                "positive_volume_deltas": self.positive_volume_deltas,
                "last_volume_matches_positive_delta": self.last_volume_matches_positive_delta,
                "last_volume_match_ratio": _ratio(
                    self.last_volume_matches_positive_delta,
                    self.positive_volume_deltas,
                ),
                "volume_change_without_last_volume": self.volume_change_without_last_volume,
                "last_volume_without_volume_change": self.last_volume_without_volume_change,
            },
            "anomalies": anomalies,
        }
        payload["classification"] = classify_metrics(payload, self.thresholds)
        return payload


def classify_metrics(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> str:
    limits = thresholds or THRESHOLDS
    depth_quality = classify_depth_quality(metrics, limits)
    if depth_quality != "L5_USABLE":
        return depth_quality

    anomalies = metrics.get("anomalies") or {}
    quality_failed = (
        float(anomalies.get("transport_stale_ratio") or 0)
        > limits["max_transport_stale_ratio"]
        or float(anomalies.get("clock_skew_ratio") or 0)
        > limits["max_clock_skew_ratio"]
        or float(anomalies.get("crossed_ratio") or 0)
        > limits["max_crossed_ratio"]
        or float(anomalies.get("locked_ratio") or 0)
        > limits["max_locked_ratio"]
        or float(anomalies.get("bid_inverted_ratio") or 0)
        > limits["max_inverted_depth_ratio"]
        or float(anomalies.get("ask_inverted_ratio") or 0)
        > limits["max_inverted_depth_ratio"]
        or int(anomalies.get("missing_received_at_rows") or 0) > 0
        or int(anomalies.get("missing_ingest_id_rows") or 0) > 0
        or int(anomalies.get("missing_ingest_seq_rows") or 0) > 0
        or int(anomalies.get("missing_trading_day_rows") or 0) > 0
        or int(anomalies.get("missing_last_price_rows") or 0) > 0
        or int(anomalies.get("duplicate_ingest_ids") or 0) > 0
        or int(anomalies.get("non_positive_ingest_seq_rows") or 0) > 0
        or int(anomalies.get("ingest_seq_non_increasing_rows") or 0) > 0
        or int(anomalies.get("same_ts_duplicate_ingest_seq") or 0) > 0
        or classify_volume_semantics_quality(metrics, limits) != "VALIDATED"
    )
    return "DEGRADED" if quality_failed else "L5_USABLE"


def classify_depth_quality(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> str:
    limits = thresholds or THRESHOLDS
    rows = int(metrics.get("rows") or 0)
    if rows == 0:
        return "UNUSABLE"
    if float(metrics.get("l1_complete_ratio") or 0) < limits[
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
    volume_semantics = metrics.get("volume_semantics") or {}
    positive_volume_deltas = int(
        volume_semantics.get("positive_volume_deltas") or 0
    )
    if positive_volume_deltas < int(
        limits["min_positive_volume_deltas_for_semantics"]
    ):
        return "INSUFFICIENT"
    inconsistent = (
        int(volume_semantics.get("cumulative_volume_decreases") or 0) > 0
        or int(volume_semantics.get("volume_change_without_last_volume") or 0)
        > 0
        or int(volume_semantics.get("last_volume_without_volume_change") or 0)
        > 0
        or float(volume_semantics.get("last_volume_match_ratio") or 0)
        < limits["min_last_volume_match_ratio"]
    )
    return "INCONSISTENT" if inconsistent else "VALIDATED"


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


def load_manifest(
    path: Path,
) -> tuple[
    dict[str, Any],
    list[ContractSpec],
    list[SessionWindow],
    list[ExecutionWindow],
]:
    manifest = _load_json_strict(path, "contracts manifest")
    if not isinstance(manifest, dict):
        raise AuditError("contracts manifest must contain one JSON object")
    validate_json_schema(
        manifest,
        MANIFEST_SCHEMA_PATH,
        "contracts manifest",
    )
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise AuditError(
            f"manifest schema_version must be {MANIFEST_SCHEMA_VERSION}"
        )
    if manifest.get("candidate_id") != CANDIDATE_ID:
        raise AuditError(f"candidate_id must be {CANDIDATE_ID}")
    extra_manifest_fields = set(manifest) - {
        "schema_version",
        "candidate_id",
        "snapshot_id",
        "audit_window",
        "session_windows",
        "targets",
        "execution_windows",
    }
    if extra_manifest_fields:
        raise AuditError(
            "manifest contains unsupported fields: "
            f"{sorted(extra_manifest_fields)}"
        )
    snapshot_id = str(manifest.get("snapshot_id") or "")
    if not ID_PATTERN.fullmatch(snapshot_id):
        raise AuditError("snapshot_id must use 8-128 letters, numbers, dot, dash or underscore")

    audit_start, audit_end, trading_day = _manifest_audit_window(manifest)
    if audit_end <= audit_start:
        raise AuditError("manifest audit end must be later than start")
    if (
        audit_end - audit_start
    ).total_seconds() > MAX_AUDIT_WINDOW_HOURS * 3600:
        raise AuditError(
            f"audit window cannot exceed {MAX_AUDIT_WINDOW_HOURS} hours"
        )

    session_windows = _manifest_session_windows(
        manifest,
        audit_start,
        audit_end,
        trading_day,
    )

    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != len(FROZEN_PRODUCTS):
        raise AuditError("manifest targets must contain exactly ten frozen products")

    products: set[str] = set()
    contracts: list[ContractSpec] = []
    roll_expected: dict[str, bool] = {}
    for target in targets:
        if not isinstance(target, dict):
            raise AuditError("every target must be a JSON object")
        extra = set(target) - {
            "product",
            "exact_contract",
            "previous_exact_contract",
            "roll_expected",
        }
        if extra:
            raise AuditError(f"target contains unsupported fields: {sorted(extra)}")
        product = str(target.get("product") or "").lower()
        if product not in FROZEN_PRODUCTS or product in products:
            raise AuditError(f"invalid or duplicate frozen product: {product}")
        products.add(product)
        current = _contract_spec(
            product,
            "current",
            str(target.get("exact_contract") or ""),
        )
        contracts.append(current)
        previous_raw = target.get("previous_exact_contract")
        expected = bool(target.get("roll_expected"))
        roll_expected[product] = expected
        if previous_raw:
            previous = _contract_spec(product, "previous", str(previous_raw))
            if previous.vt_symbol != current.vt_symbol:
                contracts.append(previous)
            elif expected:
                raise AuditError(
                    f"{product} roll_expected requires different previous/current contracts"
                )
        elif expected:
            raise AuditError(
                f"{product} roll_expected requires previous_exact_contract"
            )
    if products != set(FROZEN_PRODUCTS):
        missing = sorted(set(FROZEN_PRODUCTS) - products)
        raise AuditError(f"manifest missing frozen products: {missing}")

    known_contracts = {
        (contract.product, contract.vt_symbol) for contract in contracts
    }
    windows_raw = manifest.get("execution_windows") or []
    if not isinstance(windows_raw, list):
        raise AuditError("execution_windows must be a list")
    windows: list[ExecutionWindow] = []
    window_ids: set[str] = set()
    for raw in windows_raw:
        if not isinstance(raw, dict):
            raise AuditError("every execution window must be a JSON object")
        extra = set(raw) - {
            "window_id",
            "product",
            "exact_contract",
            "execution_time",
            "window_seconds",
        }
        if extra:
            raise AuditError(
                f"execution window contains unsupported fields: {sorted(extra)}"
            )
        window_id = str(raw.get("window_id") or "")
        if not ID_PATTERN.fullmatch(window_id) or window_id in window_ids:
            raise AuditError(f"invalid or duplicate execution window id: {window_id}")
        window_ids.add(window_id)
        product = str(raw.get("product") or "").lower()
        contract = _contract_spec(
            product,
            "window",
            str(raw.get("exact_contract") or ""),
        )
        if (product, contract.vt_symbol) not in known_contracts:
            raise AuditError(
                f"execution window contract is not bound to target: {product}/{contract.vt_symbol}"
            )
        execution_time = _parse_cli_datetime(
            str(raw.get("execution_time") or ""),
            f"execution_windows[{window_id}].execution_time",
        )
        window_seconds = _as_int(raw.get("window_seconds"), default=60)
        if window_seconds < 1 or window_seconds > 3600:
            raise AuditError("execution window_seconds must be between 1 and 3600")
        window = ExecutionWindow(
            window_id=window_id,
            product=product,
            vt_symbol=contract.vt_symbol,
            execution_time=execution_time,
            window_seconds=window_seconds,
        )
        if window.start < audit_start or window.end > audit_end:
            raise AuditError(
                f"execution window {window.window_id} is outside signed audit window"
            )
        windows.append(window)
    normalized_manifest = dict(manifest)
    normalized_manifest["roll_expected"] = roll_expected
    return normalized_manifest, contracts, session_windows, windows


def audit(
    conn: Any,
    manifest: dict[str, Any],
    contracts: list[ContractSpec],
    session_windows: list[SessionWindow],
    windows: list[ExecutionWindow],
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    signed_start, signed_end, trading_day = _manifest_audit_window(manifest)
    if session_windows != _manifest_session_windows(
        manifest,
        signed_start,
        signed_end,
        trading_day,
    ):
        raise AuditError("session windows do not match signed manifest")
    if start is not None and start != signed_start:
        raise AuditError("CLI start does not match signed manifest audit start")
    if end is not None and end != signed_end:
        raise AuditError("CLI end does not match signed manifest audit end")
    start = signed_start
    end = signed_end
    if end <= start:
        raise AuditError("audit end must be later than start")
    if (end - start).total_seconds() > MAX_AUDIT_WINDOW_HOURS * 3600:
        raise AuditError(
            f"audit window cannot exceed {MAX_AUDIT_WINDOW_HOURS} hours"
        )
    contracts_result: list[dict[str, Any]] = []
    window_results: list[dict[str, Any]] = []
    all_rows = 0
    for contract in contracts:
        contract_windows = [
            window for window in windows if window.vt_symbol == contract.vt_symbol
        ]
        result, contract_window_results = audit_contract(
            conn,
            contract,
            session_windows,
            contract_windows,
            start,
            end,
            trading_day,
        )
        all_rows += int(result["scanned_rows"])
        contracts_result.append(result)
        window_results.extend(contract_window_results)

    products_result, blockers = summarize_products(
        contracts_result,
        window_results,
        manifest,
    )
    counts = {name: 0 for name in CLASSIFICATION_SEVERITY}
    for item in products_result:
        counts[item["classification"]] += 1
    overall = worst_classification(
        [item["classification"] for item in products_result]
    )
    p0_pass = overall == "L5_USABLE" and not blockers
    quality_breakdowns: list[dict[str, Any]] = []
    for contract_result in contracts_result:
        for segment, metrics in (
            ("all", contract_result["all"]),
            *contract_result["sessions"].items(),
        ):
            quality_breakdowns.append(
                {
                    "record_type": "contract_segment",
                    "product": contract_result["product"],
                    "role": contract_result["role"],
                    "vt_symbol": contract_result["vt_symbol"],
                    "segment": segment,
                    **quality_breakdown(metrics),
                }
            )
    for window_result in window_results:
        quality_breakdowns.append(
            {
                "record_type": "execution_window",
                "product": window_result["product"],
                "role": "window",
                "vt_symbol": window_result["vt_symbol"],
                "segment": window_result["window_id"],
                **quality_breakdown(
                    window_result["metrics"],
                    window_result["classification"],
                ),
            }
        )
    canonical_manifest = json.dumps(
        {
            key: value
            for key, value in manifest.items()
            if key != "roll_expected"
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "snapshot_id": manifest["snapshot_id"],
        "manifest_sha256": hashlib.sha256(canonical_manifest).hexdigest(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "database_mutations": 0,
        "audit_window": {
            "start": start.isoformat(),
            "end_exclusive": end.isoformat(),
            "trading_day": trading_day,
            "display_timezone": "Asia/Shanghai",
        },
        "thresholds": dict(THRESHOLDS),
        "query_limits": {
            "max_rows_per_contract": MAX_ROWS_PER_CONTRACT,
            "sql_limit_per_contract": MAX_ROWS_PER_CONTRACT + 1,
        },
        "summary": {
            "expected_products": len(FROZEN_PRODUCTS),
            "observed_products": sum(
                int(item["rows"] > 0) for item in products_result
            ),
            "contracts": len(contracts_result),
            "rows": all_rows,
            "scanned_rows": all_rows,
            "max_contract_rows_observed": max(
                (
                    int(item["scanned_rows"])
                    for item in contracts_result
                ),
                default=0,
            ),
            "classification_counts": counts,
            "overall_conclusion": overall,
            "p0_pass": p0_pass,
        },
        "products": products_result,
        "contracts": contracts_result,
        "execution_windows": window_results,
        "quality_breakdowns": quality_breakdowns,
        "blockers": blockers,
        "limitations": [
            "五档聚合快照不能识别订单队列位置或撤单身份。",
            "本审计不计算被动成交点概率，也不把缺失 L2-L5 回退为乐观 L1 成交。",
            "tick cadence gap 是采集连续性指标，不等同于市场中一定存在可成交量。",
            "last_volume 仅以同一交易日累计 volume 差分验证字段语义，不做未验证的成交归因。",
        ],
    }


def audit_contract(
    conn: Any,
    contract: ContractSpec,
    session_windows: list[SessionWindow],
    windows: list[ExecutionWindow],
    start: datetime,
    end: datetime,
    expected_trading_day: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    overall = MetricsAccumulator(
        dict(THRESHOLDS),
        expected_trading_day=expected_trading_day,
    )
    sessions = {
        window.name: MetricsAccumulator(
            dict(THRESHOLDS),
            expected_trading_day=expected_trading_day,
        )
        for window in session_windows
    }
    session_times: dict[str, list[datetime]] = {
        window.name: [] for window in session_windows
    }
    window_accumulators = {
        window.window_id: MetricsAccumulator(
            dict(THRESHOLDS),
            expected_trading_day=expected_trading_day,
        )
        for window in windows
    }
    window_times: dict[str, list[datetime]] = {
        window.window_id: [] for window in windows
    }

    sql = f"""
        SELECT {", ".join(QUERY_COLUMNS)}
        FROM market_ticks
        WHERE vt_symbol = %s AND ts >= %s AND ts < %s
        ORDER BY ts, ingest_seq
        LIMIT {MAX_ROWS_PER_CONTRACT + 1}
    """
    scanned_rows = 0
    try:
        cursor = conn.execute(sql, (contract.vt_symbol, start, end))
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            for raw in batch:
                scanned_rows += 1
                if scanned_rows > MAX_ROWS_PER_CONTRACT:
                    raise AuditError(
                        f"{contract.vt_symbol} exceeds "
                        f"{MAX_ROWS_PER_CONTRACT} row query limit"
                    )
                row = dict(zip(QUERY_COLUMNS, raw))
                overall.add(row)
                row_ts = _as_utc_datetime(row["ts"], "market_ticks.ts")
                for session_window in session_windows:
                    if session_window.start <= row_ts < session_window.end:
                        sessions[session_window.name].add(row)
                        session_times[session_window.name].append(row_ts)
                for window in windows:
                    if window.start <= row_ts <= window.end:
                        window_accumulators[window.window_id].add(row)
                        window_times[window.window_id].append(row_ts)
    except AuditError:
        raise
    except Exception as exc:
        raise AuditError(
            f"read-only market_ticks query failed for {contract.vt_symbol}: {exc}"
        ) from exc

    session_results: dict[str, dict[str, Any]] = {}
    session_coverage: dict[str, dict[str, Any]] = {}
    for session_window in session_windows:
        name = session_window.name
        result = sessions[name].result()
        timestamps = session_times[name]
        coverage = _coverage_result(
            timestamps,
            session_window.start,
            session_window.end,
            THRESHOLDS["max_required_session_gap_seconds"],
        )
        if (
            int(result["rows"])
            < int(THRESHOLDS["min_rows_per_required_session"])
            or not coverage["boundary_coverage_complete"]
            or coverage["max_gap_seconds"] is None
            or coverage["max_gap_seconds"]
            > THRESHOLDS["max_required_session_gap_seconds"]
        ):
            result["classification"] = worst_classification(
                [result["classification"], "DEGRADED" if result["rows"] else "UNUSABLE"]
            )
        coverage["classification"] = result["classification"]
        session_results[name] = result
        session_coverage[name] = coverage
    all_result = overall.result()
    classifications = [all_result["classification"]]
    if contract.role == "current":
        classifications.extend(
            result["classification"] for result in session_results.values()
        )
        if any(
            0
            < int(result["rows"])
            < int(THRESHOLDS["min_rows_per_required_session"])
            for result in session_results.values()
        ):
            classifications.append("DEGRADED")
    contract_classification = worst_classification(classifications)
    result = {
        "product": contract.product,
        "role": contract.role,
        "exact_contract": contract.exact_contract,
        "vt_symbol": contract.vt_symbol,
        "scanned_rows": scanned_rows,
        "classification": contract_classification,
        "all": all_result,
        "sessions": session_results,
        "session_coverage": session_coverage,
    }

    window_results = []
    for window in windows:
        metrics = window_accumulators[window.window_id].result()
        timestamps = window_times[window.window_id]
        before = [item for item in timestamps if item < window.execution_time]
        after = [item for item in timestamps if item >= window.execution_time]
        coverage = _coverage_result(
            timestamps,
            window.start,
            window.end,
            THRESHOLDS["max_execution_window_gap_seconds"],
        )
        classification = metrics["classification"]
        if (
            not before
            or not after
            or int(metrics["rows"])
            < int(THRESHOLDS["min_rows_per_execution_window"])
            or not coverage["boundary_coverage_complete"]
            or coverage["max_gap_seconds"] is None
            or coverage["max_gap_seconds"]
            > THRESHOLDS["max_execution_window_gap_seconds"]
        ):
            classification = worst_classification(
                [classification, "DEGRADED" if metrics["rows"] else "UNUSABLE"]
            )
        window_results.append(
            {
                "window_id": window.window_id,
                "product": window.product,
                "vt_symbol": window.vt_symbol,
                "execution_time": window.execution_time.isoformat(),
                "window_seconds": window.window_seconds,
                "rows_before": len(before),
                "rows_after": len(after),
                "last_before_delay_ms": (
                    round(
                        (window.execution_time - max(before)).total_seconds()
                        * 1000,
                        6,
                    )
                    if before
                    else None
                ),
                "first_after_delay_ms": (
                    round(
                        (min(after) - window.execution_time).total_seconds()
                        * 1000,
                        6,
                    )
                    if after
                    else None
                ),
                "start_boundary_gap_seconds": coverage[
                    "start_boundary_gap_seconds"
                ],
                "end_boundary_gap_seconds": coverage[
                    "end_boundary_gap_seconds"
                ],
                "max_observed_tick_gap_seconds": coverage[
                    "max_observed_tick_gap_seconds"
                ],
                "max_gap_seconds": coverage["max_gap_seconds"],
                "boundary_coverage_complete": coverage[
                    "boundary_coverage_complete"
                ],
                "classification": classification,
                "metrics": metrics,
            }
        )
    return result, window_results


def summarize_products(
    contracts: list[dict[str, Any]],
    windows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    blockers: list[str] = []
    products: list[dict[str, Any]] = []
    roll_expected = manifest.get("roll_expected") or {}
    for product in FROZEN_PRODUCTS:
        product_contracts = [
            item for item in contracts if item["product"] == product
        ]
        product_windows = [
            item for item in windows if item["product"] == product
        ]
        classifications = [
            item["classification"] for item in product_contracts
        ]
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
            classifications.extend(
                item["classification"] for item in current_windows
            )
        if roll_expected.get(product):
            previous = next(
                (
                    item
                    for item in product_contracts
                    if item["role"] == "previous"
                ),
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
                    blockers.append(
                        f"{product}:missing_previous_execution_window"
                    )
                else:
                    classifications.extend(
                        item["classification"] for item in previous_windows
                    )
        missing_sessions: list[str] = []
        if current:
            missing_sessions = [
                name
                for name in REQUIRED_CURRENT_SESSIONS
                if int(current["sessions"][name]["rows"]) == 0
            ]
        if missing_sessions:
            classifications.append("UNUSABLE")
            blockers.append(
                f"{product}:missing_sessions:{','.join(missing_sessions)}"
            )
        insufficient_sessions = []
        if current:
            insufficient_sessions = [
                name
                for name in REQUIRED_CURRENT_SESSIONS
                if int(current["sessions"][name]["rows"]) > 0
                and current["sessions"][name]["classification"] != "L5_USABLE"
            ]
        if insufficient_sessions:
            classifications.append("DEGRADED")
            blockers.append(
                f"{product}:session_not_l5:"
                f"{','.join(insufficient_sessions)}"
            )
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
                "missing_sessions": missing_sessions,
                "insufficient_sessions": insufficient_sessions,
                "classification": classification,
            }
        )
    return products, blockers


def render_markdown(evidence: dict[str, Any]) -> str:
    summary = evidence["summary"]
    window = evidence["audit_window"]
    lines = [
        "# C_FAST 十品种 L1–L5 盘口数据审计",
        "",
        "## 审计身份",
        "",
        f"- 候选：`{evidence['candidate_id']}`",
        f"- 快照：`{evidence['snapshot_id']}`",
        f"- 输入清单 SHA256：`{evidence['manifest_sha256']}`",
        f"- 交易日：`{window['trading_day']}`",
        f"- UTC 时间窗：`[{window['start']}, {window['end_exclusive']})`",
        "- 数据访问：只读；数据库写入次数 `0`",
        "",
        "## 总结",
        "",
        f"- P0 通过：`{str(summary['p0_pass']).lower()}`",
        f"- 总体结论：`{summary['overall_conclusion']}`",
        f"- 扫描行数：`{summary['scanned_rows']}`；合约数：`{summary['contracts']}`",
        f"- 单合约最大观测行数：`{summary['max_contract_rows_observed']}`；"
        f"硬上限：`{evidence['query_limits']['max_rows_per_contract']}`",
        "",
        "| 品种 | 行数 | 合约数 | 执行窗口 | 缺失时段 | 样本不足时段 | 结论 |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for item in evidence["products"]:
        missing = ",".join(item["missing_sessions"]) or "-"
        insufficient = ",".join(item["insufficient_sessions"]) or "-"
        lines.append(
            f"| {item['product']} | {item['rows']} | {item['contracts']} | "
            f"{item['execution_windows']} | {missing} | {insufficient} | "
            f"{item['classification']} |"
        )

    lines.extend(
        [
            "",
            "## 深度与成交量语义分解",
            "",
            "| 类型 | 品种 | 角色 | 合约 | 时段/窗口 | 深度质量 | "
            "成交量语义 | 综合结论 |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for item in evidence["quality_breakdowns"]:
        lines.append(
            f"| {item['record_type']} | {item['product']} | "
            f"{item['role']} | {item['vt_symbol']} | {item['segment']} | "
            f"{item['depth_quality']} | {item['volume_semantics_quality']} | "
            f"{item['combined_classification']} |"
        )

    lines.extend(
        [
            "",
            "## 合约与时段",
            "",
            "| 品种 | 角色 | 合约 | 时段 | 行数 | L1 完整率 | L5 完整率 | "
            "延迟 P99(ms) | 结论 |",
            "|---|---|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for contract in evidence["contracts"]:
        for name, metrics in (
            ("all", contract["all"]),
            *contract["sessions"].items(),
        ):
            lines.append(
                f"| {contract['product']} | {contract['role']} | "
                f"{contract['vt_symbol']} | {name} | {metrics['rows']} | "
                f"{metrics['l1_complete_ratio']:.6f} | "
                f"{metrics['l5_complete_ratio']:.6f} | "
                f"{_markdown_number(metrics['transport_latency_ms']['p99'])} | "
                f"{metrics['classification']} |"
            )

    lines.extend(
        [
            "",
            "## 必需时段边界覆盖",
            "",
            "| 品种 | 角色 | 时段 | 起/止边界间隔(s) | 最大间隔(s) | 完整覆盖 | 结论 |",
            "|---|---|---|---:|---:|---|---|",
        ]
    )
    for contract in evidence["contracts"]:
        for name, coverage in contract["session_coverage"].items():
            lines.append(
                f"| {contract['product']} | {contract['role']} | {name} | "
                f"{_markdown_number(coverage['start_boundary_gap_seconds'])}/"
                f"{_markdown_number(coverage['end_boundary_gap_seconds'])} | "
                f"{_markdown_number(coverage['max_gap_seconds'])} | "
                f"{str(coverage['boundary_coverage_complete']).lower()} | "
                f"{coverage['classification']} |"
            )

    lines.extend(
        [
            "",
            "## 月度执行窗口（前后固定秒数）",
            "",
            "| 窗口 | 品种 | 合约 | 前/后行数 | 起/止边界间隔(s) | "
            "最大间隔(s) | L1 完整率 | L5 完整率 | 结论 |",
            "|---|---|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    if evidence["execution_windows"]:
        for item in evidence["execution_windows"]:
            metrics = item["metrics"]
            lines.append(
                f"| {item['window_id']} | {item['product']} | "
                f"{item['vt_symbol']} | {item['rows_before']}/{item['rows_after']} | "
                f"{_markdown_number(item['start_boundary_gap_seconds'])}/"
                f"{_markdown_number(item['end_boundary_gap_seconds'])} | "
                f"{_markdown_number(item['max_gap_seconds'])} | "
                f"{metrics['l1_complete_ratio']:.6f} | "
                f"{metrics['l5_complete_ratio']:.6f} | "
                f"{item['classification']} |"
            )
    else:
        lines.append("| - | - | - | 0/0 | - | - | - | - | UNASSESSED |")

    lines.extend(["", "## Blockers", ""])
    if evidence["blockers"]:
        lines.extend(f"- `{item}`" for item in evidence["blockers"])
    else:
        lines.append("- 无")
    lines.extend(
        [
            "",
            "## 解释边界",
            "",
            *[f"- {item}" for item in evidence["limitations"]],
            "",
        ]
    )
    return "\n".join(lines)


def write_csv(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "record_type",
        "product",
        "role",
        "vt_symbol",
        "segment",
        "rows",
        "rows_before",
        "rows_after",
        "l1_complete_ratio",
        "l5_complete_ratio",
        "depth_quality",
        "volume_semantics_quality",
        "transport_stale_ratio",
        "crossed_ratio",
        "locked_ratio",
        "bid_inverted_ratio",
        "ask_inverted_ratio",
        "duplicate_ingest_ids",
        "same_ts_duplicate_ingest_seq",
        "non_positive_ingest_seq_rows",
        "ingest_seq_non_increasing_rows",
        "ingest_seq_regression_rows",
        "ingest_seq_repeat_across_timestamp_rows",
        "ingest_seq_reset_candidates",
        "missing_received_at_rows",
        "missing_ingest_id_rows",
        "missing_ingest_seq_rows",
        "missing_trading_day_rows",
        "missing_last_price_rows",
        "cadence_gap_count",
        "latency_p99_ms",
        "interval_p95_ms",
        "max_gap_seconds",
        "start_boundary_gap_seconds",
        "end_boundary_gap_seconds",
        "max_observed_tick_gap_seconds",
        "boundary_coverage_complete",
        "classification",
    ]
    temporary, descriptor = _create_private_temp(path)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for contract in evidence["contracts"]:
                for segment, metrics in (
                    ("all", contract["all"]),
                    *contract["sessions"].items(),
                ):
                    row = _csv_metric_row(
                        "contract_segment",
                        contract["product"],
                        contract["role"],
                        contract["vt_symbol"],
                        segment,
                        metrics,
                    )
                    coverage = contract.get("session_coverage", {}).get(segment)
                    if coverage:
                        row.update(
                            {
                                "max_gap_seconds": coverage["max_gap_seconds"],
                                "start_boundary_gap_seconds": coverage[
                                    "start_boundary_gap_seconds"
                                ],
                                "end_boundary_gap_seconds": coverage[
                                    "end_boundary_gap_seconds"
                                ],
                                "max_observed_tick_gap_seconds": coverage[
                                    "max_observed_tick_gap_seconds"
                                ],
                                "boundary_coverage_complete": coverage[
                                    "boundary_coverage_complete"
                                ],
                            }
                        )
                    writer.writerow(row)
            for item in evidence["execution_windows"]:
                row = _csv_metric_row(
                    "execution_window",
                    item["product"],
                    "window",
                    item["vt_symbol"],
                    item["window_id"],
                    item["metrics"],
                )
                row.update(
                    {
                        "rows_before": item["rows_before"],
                        "rows_after": item["rows_after"],
                        "max_gap_seconds": item["max_gap_seconds"],
                        "start_boundary_gap_seconds": item[
                            "start_boundary_gap_seconds"
                        ],
                        "end_boundary_gap_seconds": item[
                            "end_boundary_gap_seconds"
                        ],
                        "max_observed_tick_gap_seconds": item[
                            "max_observed_tick_gap_seconds"
                        ],
                        "boundary_coverage_complete": item[
                            "boundary_coverage_complete"
                        ],
                        "classification": item["classification"],
                    }
                )
                writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
        _publish_temp_create_only(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary, descriptor = _create_private_temp(path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _publish_temp_create_only(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _create_private_temp(path: Path) -> tuple[Path, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(32):
        token = os.urandom(16).hex()
        temporary = path.with_name(f".{path.name}.{token}.tmp")
        try:
            return temporary, os.open(temporary, flags, 0o600)
        except FileExistsError:
            continue
    raise AuditError("cannot allocate private audit output temporary file")


def _publish_temp_create_only(temporary: Path, path: Path) -> None:
    published = False
    try:
        os.link(temporary, path, follow_symlinks=False)
        published = True
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise AuditError("audit output already exists") from exc
    except OSError as exc:
        if published:
            try:
                path.unlink()
                _fsync_directory(path.parent)
            except OSError:
                pass
        raise AuditError("cannot publish audit output") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    directory_descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _csv_metric_row(
    record_type: str,
    product: str,
    role: str,
    vt_symbol: str,
    segment: str,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    anomalies = metrics["anomalies"]
    return {
        "record_type": record_type,
        "product": product,
        "role": role,
        "vt_symbol": vt_symbol,
        "segment": segment,
        "rows": metrics["rows"],
        "rows_before": "",
        "rows_after": "",
        "l1_complete_ratio": metrics["l1_complete_ratio"],
        "l5_complete_ratio": metrics["l5_complete_ratio"],
        "depth_quality": classify_depth_quality(metrics),
        "volume_semantics_quality": classify_volume_semantics_quality(metrics),
        "transport_stale_ratio": anomalies["transport_stale_ratio"],
        "crossed_ratio": anomalies["crossed_ratio"],
        "locked_ratio": anomalies["locked_ratio"],
        "bid_inverted_ratio": anomalies["bid_inverted_ratio"],
        "ask_inverted_ratio": anomalies["ask_inverted_ratio"],
        "duplicate_ingest_ids": anomalies["duplicate_ingest_ids"],
        "same_ts_duplicate_ingest_seq": anomalies[
            "same_ts_duplicate_ingest_seq"
        ],
        "non_positive_ingest_seq_rows": anomalies[
            "non_positive_ingest_seq_rows"
        ],
        "ingest_seq_non_increasing_rows": anomalies[
            "ingest_seq_non_increasing_rows"
        ],
        "ingest_seq_regression_rows": anomalies[
            "ingest_seq_regression_rows"
        ],
        "ingest_seq_repeat_across_timestamp_rows": anomalies[
            "ingest_seq_repeat_across_timestamp_rows"
        ],
        "ingest_seq_reset_candidates": anomalies[
            "ingest_seq_reset_candidates"
        ],
        "missing_received_at_rows": anomalies["missing_received_at_rows"],
        "missing_ingest_id_rows": anomalies["missing_ingest_id_rows"],
        "missing_ingest_seq_rows": anomalies["missing_ingest_seq_rows"],
        "missing_trading_day_rows": anomalies["missing_trading_day_rows"],
        "missing_last_price_rows": anomalies["missing_last_price_rows"],
        "cadence_gap_count": metrics["cadence_gap_count"],
        "latency_p99_ms": metrics["transport_latency_ms"]["p99"],
        "interval_p95_ms": metrics["tick_interval_ms"]["p95"],
        "max_gap_seconds": "",
        "start_boundary_gap_seconds": "",
        "end_boundary_gap_seconds": "",
        "max_observed_tick_gap_seconds": "",
        "boundary_coverage_complete": "",
        "classification": metrics["classification"],
    }


def _contract_spec(product: str, role: str, value: str) -> ContractSpec:
    if product not in FROZEN_PRODUCTS:
        raise AuditError(f"invalid frozen product: {product}")
    exact_match = EXACT_CONTRACT_PATTERN.fullmatch(value)
    vt_match = VT_SYMBOL_PATTERN.fullmatch(value)
    if exact_match:
        exchange = exact_match.group("exchange")
        symbol = exact_match.group("symbol")
        exact_contract = value
        vt_symbol = f"{symbol}.{exchange}"
    elif vt_match:
        exchange = vt_match.group("exchange")
        symbol = vt_match.group("symbol")
        exact_contract = f"{exchange}.{symbol}"
        vt_symbol = value
    else:
        raise AuditError(
            f"invalid exact contract {value!r}; use EXCHANGE.symbolYYMM"
        )
    symbol_product = re.match(r"^[A-Za-z]+", symbol)
    if not symbol_product or symbol_product.group(0).lower() != product:
        raise AuditError(f"{value} does not match product {product}")
    if PRODUCT_EXCHANGES[product] != exchange:
        raise AuditError(
            f"{value} exchange must be {PRODUCT_EXCHANGES[product]}"
        )
    return ContractSpec(product, role, exact_contract, vt_symbol)


def _parse_cli_datetime(value: str, name: str) -> datetime:
    if not value:
        raise AuditError(f"{name} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AuditError(f"{name} must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def _as_utc_datetime(value: Any, name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditError(f"{name} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 9) if denominator else 0.0


def _distribution(values: Iterable[float]) -> dict[str, float | int | None]:
    ordered = sorted(value for value in values if math.isfinite(value))
    return {
        "samples": len(ordered),
        "p50": _quantile(ordered, 0.50),
        "p95": _quantile(ordered, 0.95),
        "p99": _quantile(ordered, 0.99),
        "max": round(ordered[-1], 6) if ordered else None,
    }


def _quantile(ordered: list[float], percentile: float) -> float | None:
    if not ordered:
        return None
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        value = ordered[lower]
    else:
        weight = position - lower
        value = ordered[lower] * (1 - weight) + ordered[upper] * weight
    return round(value, 6)


def _has_bid_inversion(prices: list[float | None]) -> bool:
    pairs = zip(prices, prices[1:])
    return any(
        first is not None
        and second is not None
        and first > 0
        and second > 0
        and first < second
        for first, second in pairs
    )


def _has_ask_inversion(prices: list[float | None]) -> bool:
    pairs = zip(prices, prices[1:])
    return any(
        first is not None
        and second is not None
        and first > 0
        and second > 0
        and first > second
        for first, second in pairs
    )


def _max_gap_seconds(values: list[datetime]) -> float | None:
    if len(values) < 2:
        return None
    ordered = sorted(values)
    return round(
        max(
            (current - previous).total_seconds()
            for previous, current in zip(ordered, ordered[1:])
        ),
        6,
    )


def _coverage_result(
    timestamps: list[datetime],
    start: datetime,
    end: datetime,
    max_boundary_gap_seconds: float,
) -> dict[str, Any]:
    ordered = sorted(timestamps)
    observed_gap_seconds = _max_gap_seconds(ordered)
    start_boundary_gap_seconds = (
        round((ordered[0] - start).total_seconds(), 6)
        if ordered
        else None
    )
    end_boundary_gap_seconds = (
        round((end - ordered[-1]).total_seconds(), 6)
        if ordered
        else None
    )
    gap_candidates = [
        value
        for value in (
            observed_gap_seconds,
            start_boundary_gap_seconds,
            end_boundary_gap_seconds,
        )
        if value is not None
    ]
    max_gap_seconds = max(gap_candidates) if gap_candidates else None
    boundary_coverage_complete = bool(
        ordered
        and start_boundary_gap_seconds is not None
        and end_boundary_gap_seconds is not None
        and 0 <= start_boundary_gap_seconds <= max_boundary_gap_seconds
        and 0 <= end_boundary_gap_seconds <= max_boundary_gap_seconds
    )
    return {
        "start": start.isoformat(),
        "end_exclusive": end.isoformat(),
        "start_boundary_gap_seconds": start_boundary_gap_seconds,
        "end_boundary_gap_seconds": end_boundary_gap_seconds,
        "max_observed_tick_gap_seconds": observed_gap_seconds,
        "max_gap_seconds": max_gap_seconds,
        "boundary_coverage_complete": boundary_coverage_complete,
    }


def _manifest_audit_window(
    manifest: dict[str, Any],
) -> tuple[datetime, datetime, str]:
    raw = manifest.get("audit_window")
    if not isinstance(raw, dict):
        raise AuditError("manifest audit_window must be a JSON object")
    start = _parse_cli_datetime(str(raw.get("start") or ""), "audit_window.start")
    end = _parse_cli_datetime(
        str(raw.get("end_exclusive") or ""),
        "audit_window.end_exclusive",
    )
    trading_day = str(raw.get("trading_day") or "")
    if not re.fullmatch(r"[0-9]{8}", trading_day):
        raise AuditError("audit_window.trading_day must be YYYYMMDD")
    try:
        datetime.strptime(trading_day, "%Y%m%d")
    except ValueError as exc:
        raise AuditError(
            "audit_window.trading_day must be a valid calendar date"
        ) from exc
    return start, end, trading_day


def _validate_canonical_session_window(
    name: str,
    start: datetime,
    end: datetime,
    trading_day: str,
) -> None:
    start_clock, end_clock, day_role = CANONICAL_SESSION_CLOCKS[name]
    local_start = start.astimezone(CHINA_TZ)
    local_end = end.astimezone(CHINA_TZ)
    if (
        local_start.strftime("%H:%M:%S") != start_clock
        or local_end.strftime("%H:%M:%S") != end_clock
        or local_start.date() != local_end.date()
    ):
        raise AuditError(
            f"session window {name} must use canonical China time "
            f"{start_clock}-{end_clock}"
        )
    trading_date = datetime.strptime(trading_day, "%Y%m%d").date()
    if day_role == "day" and local_start.date() != trading_date:
        raise AuditError(
            f"session window {name} must fall on signed trading_day"
        )
    if day_role == "night":
        days_before = (trading_date - local_start.date()).days
        if days_before < 1 or days_before > 3:
            raise AuditError(
                f"session window {name} must precede signed trading_day by 1-3 days"
            )


def _manifest_session_windows(
    manifest: dict[str, Any],
    audit_start: datetime,
    audit_end: datetime,
    trading_day: str,
) -> list[SessionWindow]:
    sessions_raw = manifest.get("session_windows")
    if not isinstance(sessions_raw, dict):
        raise AuditError("manifest session_windows must be a JSON object")
    session_windows: list[SessionWindow] = []
    for name in REQUIRED_CURRENT_SESSIONS:
        raw = sessions_raw.get(name)
        if not isinstance(raw, dict):
            raise AuditError(f"session window {name} must be a JSON object")
        session_start = _parse_cli_datetime(
            str(raw.get("start") or ""),
            f"session_windows.{name}.start",
        )
        session_end = _parse_cli_datetime(
            str(raw.get("end_exclusive") or ""),
            f"session_windows.{name}.end_exclusive",
        )
        if session_end <= session_start:
            raise AuditError(f"session window {name} end must be later than start")
        if session_start < audit_start or session_end > audit_end:
            raise AuditError(f"session window {name} is outside signed audit window")
        _validate_canonical_session_window(
            name,
            session_start,
            session_end,
            trading_day,
        )
        session_windows.append(
            SessionWindow(name=name, start=session_start, end=session_end)
        )
    ordered_sessions = sorted(session_windows, key=lambda item: item.start)
    for previous, current in zip(ordered_sessions, ordered_sessions[1:]):
        if current.start < previous.end:
            raise AuditError(
                f"session windows overlap: {previous.name}/{current.name}"
            )
    return session_windows


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _deny_external_schema_retrieval(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


def _read_json_fd(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_JSON_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > MAX_JSON_BYTES:
        raise AuditError(
            f"{label} exceeds {MAX_JSON_BYTES} byte safety limit"
        )
    return raw


def _load_json_strict(path: Path, label: str) -> Any:
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise AuditError(f"{label} must not be a symlink")
        if not stat.S_ISREG(path_stat.st_mode):
            raise AuditError(f"{label} must be a regular file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise AuditError(f"{label} must be a regular file")
            if before.st_size > MAX_JSON_BYTES:
                raise AuditError(
                    f"{label} exceeds {MAX_JSON_BYTES} byte safety limit"
                )
            raw = _read_json_fd(descriptor, label)
            os.lseek(descriptor, 0, os.SEEK_SET)
            verification_raw = _read_json_fd(descriptor, label)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after_stat = path.lstat()
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError(f"cannot read {label}: {exc}") from exc

    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        stat.S_IFMT(before.st_mode),
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        stat.S_IFMT(after.st_mode),
    )
    path_identity = (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_size,
        stat.S_IFMT(path_stat.st_mode),
    )
    path_identity_after = (
        path_after_stat.st_dev,
        path_after_stat.st_ino,
        path_after_stat.st_size,
        stat.S_IFMT(path_after_stat.st_mode),
    )
    if (
        path_identity != identity_before
        or identity_before != identity_after
        or identity_after != path_identity_after
        or len(raw) != before.st_size
        or raw != verification_raw
    ):
        raise AuditError(f"{label} changed while it was being read")
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditError(f"cannot parse {label}: {exc}") from exc


def validate_json_schema(
    payload: Any,
    schema_path: Path,
    label: str,
) -> None:
    schema = _load_json_strict(schema_path, f"{label} schema")
    try:
        json.dumps(payload, allow_nan=False)
        Draft202012Validator.check_schema(schema)
        registry = Registry(retrieve=_deny_external_schema_retrieval)
        if schema_path == EVIDENCE_SCHEMA_PATH:
            legacy_schema = _load_json_strict(
                LEGACY_EVIDENCE_SCHEMA_PATH,
                "legacy audit evidence schema",
            )
            registry = registry.with_resource(
                LEGACY_EVIDENCE_RESOURCE_URI,
                Resource.from_contents(legacy_schema),
            )
        validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
            registry=registry,
        )
        errors = sorted(
            validator.iter_errors(payload),
            key=lambda item: [str(part) for part in item.absolute_path],
        )
    except (SchemaError, TypeError, Unresolvable, ValueError) as exc:
        raise AuditError(f"{label} schema validation failed: {exc}") from exc
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        raise AuditError(
            f"{label} schema validation failed at {location}: {error.message}"
        )


def worst_classification(values: Iterable[str]) -> str:
    normalized = list(values)
    if not normalized:
        return "UNUSABLE"
    return max(
        normalized,
        key=lambda item: CLASSIFICATION_SEVERITY.get(item, 99),
    )


def _markdown_number(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def _read_secret_text_file(path: Path, label: str) -> str:
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise AuditError(f"{label} must not be a symlink")
        if not stat.S_ISREG(path_stat.st_mode):
            raise AuditError(f"{label} must be a regular file")
        if stat.S_IMODE(path_stat.st_mode) & 0o077:
            raise AuditError(f"{label} permissions must be 0600 or stricter")
        if path_stat.st_uid != os.geteuid():
            raise AuditError(f"{label} must be owned by the current user")
        if path_stat.st_size > MAX_DSN_BYTES:
            raise AuditError(f"{label} exceeds {MAX_DSN_BYTES} byte safety limit")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise AuditError(f"{label} must be a regular file")
            first = _read_secret_fd(descriptor, label)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_secret_fd(descriptor, label)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError(f"cannot read {label}") from exc

    identity = (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_size,
        stat.S_IFMT(path_stat.st_mode),
        path_stat.st_uid,
        stat.S_IMODE(path_stat.st_mode),
    )
    fd_before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        stat.S_IFMT(before.st_mode),
        before.st_uid,
        stat.S_IMODE(before.st_mode),
    )
    fd_after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        stat.S_IFMT(after.st_mode),
        after.st_uid,
        stat.S_IMODE(after.st_mode),
    )
    path_after_identity = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_size,
        stat.S_IFMT(path_after.st_mode),
        path_after.st_uid,
        stat.S_IMODE(path_after.st_mode),
    )
    if (
        identity != fd_before_identity
        or fd_before_identity != fd_after_identity
        or fd_after_identity != path_after_identity
        or first != second
        or len(first) != before.st_size
        or fd_before_identity[4] != os.geteuid()
        or fd_before_identity[5] & 0o077
    ):
        raise AuditError(f"{label} changed while it was being read")
    try:
        value = first.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuditError(f"{label} must be UTF-8") from exc
    if not value:
        raise AuditError(f"{label} must not be empty")
    if "\x00" in value:
        raise AuditError(f"{label} must not contain NUL bytes")
    return value


def _read_secret_fd(descriptor: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_DSN_BYTES + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > MAX_DSN_BYTES:
        raise AuditError(f"{label} exceeds {MAX_DSN_BYTES} byte safety limit")
    return raw


def connect_server_enforced_readonly(dsn_file: Path) -> Any:
    if psycopg is None:
        raise AuditError("psycopg is not installed")
    dsn = _read_secret_text_file(dsn_file, "QuestDB readonly DSN file")
    try:
        return psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=QUESTDB_CONNECT_TIMEOUT_SECONDS,
            options=f"-c statement_timeout={QUESTDB_STATEMENT_TIMEOUT_MS}",
        )
    except Exception as exc:
        raise AuditError(
            "cannot connect to QuestDB using readonly DSN file"
        ) from exc


def _fetch_all(cursor: Any) -> list[tuple[Any, ...]]:
    fetchall = getattr(cursor, "fetchall", None)
    if callable(fetchall):
        return list(fetchall())
    rows: list[tuple[Any, ...]] = []
    while True:
        batch = cursor.fetchmany(1024)
        if not batch:
            return rows
        rows.extend(batch)


def _parse_questdb_bool(value: Any, label: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise AuditError(f"{label} must be true or false")


def collect_readonly_proof_snapshot(conn: Any) -> ReadonlyProofSnapshot:
    try:
        identity_rows = _fetch_all(conn.execute(READONLY_IDENTITY_SQL))
        parameter_rows = _fetch_all(conn.execute(READONLY_PARAMETERS_SQL))
    except Exception as exc:
        raise AuditError(
            "cannot query QuestDB readonly identity metadata"
        ) from exc

    if len(identity_rows) != 1 or len(identity_rows[0]) < 2:
        raise AuditError("QuestDB readonly identity query must return one row")
    principal = str(identity_rows[0][0] or "").strip()
    questdb_build = str(identity_rows[0][1] or "").strip()
    if not principal or not questdb_build:
        raise AuditError("QuestDB readonly identity metadata is incomplete")

    parameters: dict[str, tuple[Any, str, bool]] = {}
    for row in parameter_rows:
        if len(row) < 6:
            raise AuditError("QuestDB SHOW PARAMETERS row is incomplete")
        key = str(row[0] or "").strip()
        if key not in READONLY_PARAMETER_KEYS:
            raise AuditError("QuestDB SHOW PARAMETERS returned an unexpected key")
        if key in parameters:
            raise AuditError(f"QuestDB SHOW PARAMETERS duplicated {key}")
        parameters[key] = (
            row[2],
            str(row[3] or "").strip(),
            _parse_questdb_bool(
                row[4],
                f"{key}.sensitive",
            ),
        )
    missing = set(READONLY_PARAMETER_KEYS) - set(parameters)
    if missing:
        raise AuditError(
            "QuestDB SHOW PARAMETERS is missing required readonly metadata"
        )

    readonly_enabled = _parse_questdb_bool(
        parameters["pg.readonly.user.enabled"][0],
        "pg.readonly.user.enabled",
    )
    global_readonly = _parse_questdb_bool(
        parameters["pg.security.readonly"][0],
        "pg.security.readonly",
    )
    instance_readonly = _parse_questdb_bool(
        parameters["readonly"][0],
        "readonly",
    )
    readonly_user = str(parameters["pg.readonly.user"][0] or "").strip()
    admin_user = str(parameters["pg.user"][0] or "").strip()
    if not readonly_enabled:
        raise AuditError("QuestDB dedicated readonly user is not enabled")
    if global_readonly:
        raise AuditError(
            "QuestDB proof must not rely on global PGWire readonly mode"
        )
    if instance_readonly:
        raise AuditError(
            "QuestDB proof must not rely on instance-wide readonly mode"
        )
    if not readonly_user or not admin_user:
        raise AuditError("QuestDB readonly/admin user metadata is incomplete")
    if principal != readonly_user:
        raise AuditError(
            "connected QuestDB principal is not the dedicated readonly user"
        )
    if principal == admin_user:
        raise AuditError(
            "QuestDB readonly principal must differ from the admin user"
        )
    password_source = parameters["pg.readonly.password"][1]
    if not parameters["pg.readonly.password"][2]:
        raise AuditError("pg.readonly.password must be marked sensitive")
    if password_source not in {"conf", "env", "file"}:
        raise AuditError(
            "pg.readonly.password must not use its default value"
        )
    for key, (_, source, _) in parameters.items():
        if not source:
            raise AuditError(f"QuestDB parameter source is missing for {key}")

    return ReadonlyProofSnapshot(
        principal=principal,
        readonly_user=readonly_user,
        admin_user=admin_user,
        questdb_build=questdb_build,
        readonly_user_enabled_source=parameters[
            "pg.readonly.user.enabled"
        ][1],
        readonly_user_source=parameters["pg.readonly.user"][1],
        readonly_password_source=password_source,
        admin_user_source=parameters["pg.user"][1],
        global_pgwire_readonly_source=parameters[
            "pg.security.readonly"
        ][1],
        instance_readonly_source=parameters["readonly"][1],
    )


def build_readonly_proof(
    evidence: dict[str, Any],
    audit_evidence_sha256: str,
    preflight: ReadonlyProofSnapshot,
    postflight: ReadonlyProofSnapshot,
) -> dict[str, Any]:
    if preflight != postflight:
        raise AuditError(
            "QuestDB readonly identity/configuration changed during audit"
        )
    return {
        "schema_version": READONLY_PROOF_SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "snapshot_id": evidence["snapshot_id"],
        "manifest_sha256": evidence["manifest_sha256"],
        "audit_evidence_sha256": audit_evidence_sha256,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proof_method": (
            "questdb_builtin_pgwire_readonly_user_configuration"
        ),
        "same_connection": True,
        "observable_readonly_metadata_stable": True,
        "requested_statement_timeout_ms": QUESTDB_STATEMENT_TIMEOUT_MS,
        "connect_timeout_seconds": QUESTDB_CONNECT_TIMEOUT_SECONDS,
        "write_probe_attempted": False,
        "database_mutations": 0,
        "preflight": preflight.evidence(),
        "postflight": postflight.evidence(),
        "limitations": [
            "只读证明来自同一连接上的 QuestDB 身份和配置元数据；未执行任何 DDL、DML 或试写语句。",
            "statement timeout 是 PGWire 客户端请求值；proof 不读取或保存 readonly password 内容，只核对其配置来源。",
            "该证明不替代 one-shot 人工 release、隔离运行器或产物终态封存。",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="C_FAST ten-product exact-contract audit manifest",
    )
    parser.add_argument(
        "--start",
        help="optional assertion matching signed manifest inclusive start",
    )
    parser.add_argument(
        "--end",
        help="optional assertion matching signed manifest exclusive end",
    )
    parser.add_argument(
        "--dsn-file",
        type=Path,
        required=True,
        help="0600 file containing the dedicated QuestDB readonly PGWire DSN",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("artifacts/commodity-c-fast-l1-l5-audit.json"),
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=Path("artifacts/commodity-c-fast-l1-l5-audit.csv"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("artifacts/commodity-c-fast-l1-l5-audit.md"),
    )
    parser.add_argument(
        "--readonly-proof-output",
        type=Path,
        default=Path(
            "artifacts/commodity-c-fast-questdb-readonly-proof.json"
        ),
    )
    return parser.parse_args()


def validate_artifact_paths(args: argparse.Namespace) -> None:
    input_paths = {
        args.manifest.expanduser().resolve(),
        args.dsn_file.expanduser().resolve(),
    }
    raw_outputs = (
        args.json_output,
        args.csv_output,
        args.markdown_output,
        args.readonly_proof_output,
    )
    output_paths = {
        path.expanduser().resolve()
        for path in raw_outputs
    }
    if len(output_paths) != len(raw_outputs):
        raise AuditError("audit output paths must be distinct")
    if input_paths & output_paths:
        raise AuditError("audit output paths must not overlap input files")
    if any(path.exists() or path.is_symlink() for path in raw_outputs):
        raise AuditError("audit output paths must not already exist")


def main() -> int:
    args = parse_args()
    conn = None
    try:
        validate_artifact_paths(args)
        manifest, contracts, session_windows, windows = load_manifest(
            args.manifest
        )
        start = (
            _parse_cli_datetime(args.start, "start")
            if args.start is not None
            else None
        )
        end = (
            _parse_cli_datetime(args.end, "end")
            if args.end is not None
            else None
        )
        conn = connect_server_enforced_readonly(args.dsn_file)
        preflight = collect_readonly_proof_snapshot(conn)
        evidence = audit(
            conn,
            manifest,
            contracts,
            session_windows,
            windows,
            start,
            end,
        )
        postflight = collect_readonly_proof_snapshot(conn)
        try:
            conn.close()
        except Exception as exc:
            raise AuditError("cannot close QuestDB readonly connection") from exc
        conn = None
        validate_json_schema(evidence, EVIDENCE_SCHEMA_PATH, "audit evidence")
        evidence_text = json.dumps(
            evidence,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        if not evidence_text.endswith("\n"):
            evidence_text += "\n"
        proof = build_readonly_proof(
            evidence,
            hashlib.sha256(evidence_text.encode("utf-8")).hexdigest(),
            preflight,
            postflight,
        )
        validate_json_schema(
            proof,
            READONLY_PROOF_SCHEMA_PATH,
            "QuestDB readonly proof",
        )
        write_text_atomic(
            args.json_output,
            evidence_text,
        )
        write_csv(args.csv_output, evidence)
        report = render_markdown(evidence)
        write_text_atomic(args.markdown_output, report)
        write_text_atomic(
            args.readonly_proof_output,
            json.dumps(
                proof,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            ),
        )
    except (AuditError, OSError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    print(report)
    print(f"json: {args.json_output}")
    print(f"csv: {args.csv_output}")
    print(f"markdown: {args.markdown_output}")
    print(f"readonly proof: {args.readonly_proof_output}")
    return 0 if evidence["summary"]["p0_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
