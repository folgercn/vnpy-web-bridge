"""Read-only SHFE settlement-time evidence for the #502 pilot window.

15:00 Asia/Shanghai is a *lower bound* for determination of that trade day's
settlement price, not a claimed publication or warehouse acquisition time.
The bound comes from the SHFE rules effective 2026-06-12; signed M2 custody
separately proves the exact price version and when this warehouse saw it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from scripts.research_warehouse.canonical import canonical_json_line, parse_json_strict
from scripts.research_warehouse.custody_paths import WarehousePaths
from scripts.research_warehouse.errors import RegistryError
from scripts.research_warehouse.file_integrity import read_regular_strict
from scripts.research_warehouse.manifest_commits import load_commit_receipt
from scripts.research_warehouse.manifest_envelope import validate_manifest_envelope
from scripts.research_warehouse.m2_receipts import load_run_receipt
from scripts.research_warehouse.observation_contracts import observation_id
from scripts.research_warehouse.official_calendar import load_official_calendar
from scripts.research_warehouse.registry import load_registry
from scripts.research_warehouse.signing import load_public_key, public_key_sha256
from scripts.research_warehouse.timeutil import parse_utc

SHFE_RULE_URL = "https://www.shfe.com.cn/regulation/exchangerules/rules/202606/P020260603536202760412.docx"
SHFE_RULE_SHA256 = "2657195f541a79560b60894f3ca7bbc043f30c6c4cf4388e0a6fd1c5ae585e47"
PRODUCT_RULES = {
    "rb_f": ("rb-product-rules-202601.docx", "9cf890ba528c37dffd054a17de8a1fef42db523cb050601dced6a06729d738b2"),
    "hc_f": ("hc-product-rules-202601.docx", "0a2d9d26a558dac71e8e00fe162532c1fdb4fc33a85d645c82fe61ab8df9d9f8"),
}
MANIFEST_KEY_SHA256 = "1fa9fb478128e8a41fdb4893ecb9704d24ec29c61032d086f58d9560a95ab77f"
CALENDAR_KEY_SHA256 = "fc22e285a2c303b5383b7b49b35b429837dc7eb0f88112ee35f19ad355fe2340"
MANIFEST_KEY_FILE_SHA256 = "a22f24acb303a43c86d101f075bcffaed754c82ae50eff6fb4377cd131463102"
CALENDAR_KEY_FILE_SHA256 = "65b9b97c1ada630e26c63751ff5daa300250ffe3f2377775d3fea1433db06b39"
CALENDAR_SHA256 = "b0fddf98c56a68d995edc9be9eb0d1277006d5dcfcc62a26a05b6b61984d4291"
PILOT_FIRST_DAY = date(2026, 8, 31)
PILOT_LAST_DAY = date(2026, 9, 24)
SHANGHAI = ZoneInfo("Asia/Shanghai")
SOURCE_ID = "shfe-daily-market-data-v1"


class RealSourceEvidenceError(ValueError):
    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        super().__init__(detail)


@dataclass(frozen=True)
class VerifiedRealDay:
    trade_day: str
    settlement_not_before: str
    calendar_sha256: str
    rule_sha256: str
    batch_seal_sha256: str
    raw_sha256: str
    revision_id: str
    source_url: str
    first_seen_at: str
    committed_at: str
    settlement: dict[str, float]


def _require_sha(path: Path, expected: str, label: str) -> None:
    raw = read_regular_strict(path, label, private=False)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise RealSourceEvidenceError("SOURCE_EVIDENCE_MISMATCH", f"{label} SHA256 mismatch: {path}")


def _one(paths: list[Path], label: str) -> Path:
    if len(paths) != 1:
        raise RealSourceEvidenceError("SOURCE_EVIDENCE_MISSING", f"expected one {label}, got {len(paths)}")
    return paths[0]


def _verify_shfe_settlement_days(
    source_days: list[dict],
    *,
    bundle_root: Path,
    official_rules_root: Path,
) -> dict[str, VerifiedRealDay]:
    """Verify exact SHFE prices and bound their settlement event to after day close.

    The source bundle is a read-only projection of M2 custody. No writable
    warehouse API, lock, recovery, network call or caller authority flag is used.
    The exact official rule bytes, signer keys and calendar are pinned here.
    This pilot is deliberately capped at the reviewed 2026-08-31..09-24 window.
    """
    if not source_days:
        raise RealSourceEvidenceError("MISSING_SOURCE_DAYS", "source_days is empty")
    root = Path(bundle_root).resolve()
    official = Path(official_rules_root).resolve()
    _require_sha(official / "shfe-trading-rules-202606.docx", SHFE_RULE_SHA256, "SHFE trading rules")
    for filename, digest in PRODUCT_RULES.values():
        _require_sha(official / filename, digest, "SHFE product rules")
    _require_sha(root / "libexec/manifest-public-key.b64", MANIFEST_KEY_FILE_SHA256, "M2 manifest public key")
    _require_sha(root / "libexec/calendar-public-key.b64", CALENDAR_KEY_FILE_SHA256, "M2 calendar public key")

    registry = load_registry(root / "libexec/source-registry-v1.json")
    manifest_key = load_public_key(root / "libexec/manifest-public-key.b64")
    calendar_key = load_public_key(root / "libexec/calendar-public-key.b64")
    if public_key_sha256(manifest_key) != MANIFEST_KEY_SHA256 or public_key_sha256(calendar_key) != CALENDAR_KEY_SHA256:
        raise RealSourceEvidenceError("SOURCE_SIGNER_MISMATCH", "M2 signer key pin mismatch")
    warehouse = root / "warehouse"
    custody = warehouse / "custody"
    paths = WarehousePaths(
        root=custody,
        raw=custody / "raw",
        observations=custody / "observations",
        manifests=custody / "manifests",
        temporary=custody / "tmp",
        locks=custody / "locks",
    )
    calendar = load_official_calendar(
        path=warehouse / "runtime/inputs" / f"official-calendar-{CALENDAR_SHA256}.json",
        public_key=calendar_key,
        expected_raw_sha256=CALENDAR_SHA256,
        source_evidence_root=custody / "calendar-evidence",
    )

    days: list[date] = []
    for record in source_days:
        try:
            day = date.fromisoformat(record["day"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RealSourceEvidenceError("INVALID_TRADE_DAY", "source day is invalid") from exc
        if day.isoformat() != record["day"] or not PILOT_FIRST_DAY <= day <= PILOT_LAST_DAY:
            raise RealSourceEvidenceError("UNSUPPORTED_SOURCE_WINDOW", f"outside reviewed SHFE rule window: {day}")
        days.append(day)
    if days != sorted(set(days)):
        raise RealSourceEvidenceError("TRADE_DAY_ORDER_VIOLATION", "source days must be unique and sorted")
    expected_days = sorted(day for day, item in calendar.days.items() if days[0] <= day <= days[-1] and item.is_official)
    if days != expected_days:
        raise RealSourceEvidenceError("INCOMPLETE_OFFICIAL_DAYS", "source window skips an official trading day")

    verified: dict[str, VerifiedRealDay] = {}
    previous_batch_seal: str | None = None
    previous_commit_seal: str | None = None
    for day in days:
        key = day.isoformat()
        record = source_days[len(verified)]
        if not calendar.require_day(day).is_official:
            raise RealSourceEvidenceError("NON_TRADING_DAY", key)
        receipt = load_run_receipt(warehouse / "runtime/run-receipts" / f"{key}.json")
        if receipt["trade_day"] != key or receipt["calendar_raw_sha256"] != CALENDAR_SHA256 or receipt["registry_raw_sha256"] != registry.raw_sha256:
            raise RealSourceEvidenceError("RUN_RECEIPT_MISMATCH", key)
        manifest_path = _one(sorted((custody / "manifests" / key).glob("batch-*.json")), f"batch for {key}")
        manifest_raw = read_regular_strict(manifest_path, "M2 signed batch")
        manifest = parse_json_strict(manifest_raw, "M2 signed batch")
        if manifest_raw != canonical_json_line(manifest):
            raise RealSourceEvidenceError("SOURCE_EVIDENCE_MISMATCH", f"batch not canonical: {key}")
        manifest = validate_manifest_envelope(paths, manifest, manifest_key, registry)
        if manifest["trade_day"] != key or manifest_path.name != f"{manifest['batch_id']}.json":
            raise RealSourceEvidenceError("BATCH_DAY_MISMATCH", key)
        commit, commit_seal = load_commit_receipt(custody / "manifests" / key / f"commit-{manifest['batch_id']}.json", manifest, manifest_key)
        if previous_batch_seal is not None and (
            manifest["parent_batch_seal_sha256"] != previous_batch_seal
            or manifest["parent_commit_seal_sha256"] != previous_commit_seal
        ):
            raise RealSourceEvidenceError("MANIFEST_CHAIN_MISMATCH", f"signed M2 batch chain breaks at {key}")
        shfe_revisions = [r for r in manifest["revisions"] if r["source_id"] == SOURCE_ID]
        if not shfe_revisions:
            raise RealSourceEvidenceError("SOURCE_EVIDENCE_MISSING", f"no SHFE revision for {key}")
        revision = shfe_revisions[-1]
        shfe_receipt = receipt["sources"][0]
        for field in ("revision_id", "object_id", "raw_sha256", "raw_bytes", "raw_relative_path"):
            if shfe_receipt[field] != revision[field]:
                raise RealSourceEvidenceError("RUN_RECEIPT_MISMATCH", f"{key} {field}")
        if shfe_receipt["observation_id"] not in revision["observation_ids"]:
            raise RealSourceEvidenceError("RUN_RECEIPT_MISMATCH", f"{key} observation")
        observation_path = custody / "observations/shfe" / key / SOURCE_ID / f"{shfe_receipt['observation_id']}.json"
        observation_raw = read_regular_strict(observation_path, "M2 SHFE observation receipt")
        observation = parse_json_strict(observation_raw, "M2 SHFE observation receipt")
        expected_url = registry.source(SOURCE_ID).endpoint_template.replace("{yyyymmdd}", day.strftime("%Y%m%d"))
        body_id = observation.get("observation_id")
        if (
            observation_raw != canonical_json_line(observation)
            or body_id != observation_id(observation)
            or body_id != shfe_receipt["observation_id"]
            or body_id != observation_path.stem
            or body_id not in revision["observation_ids"]
        ):
            raise RealSourceEvidenceError("OBSERVATION_RECEIPT_MISMATCH", key)
        if (
            observation.get("source_url") != expected_url
            or observation.get("http_status") != 200
            or observation.get("trade_day") != key
            or observation.get("revision_id") != revision["revision_id"]
            or observation.get("raw_sha256") != revision["raw_sha256"]
            or observation.get("first_seen_at") != revision["first_seen_at"]
            or observation.get("registry_raw_sha256") != registry.raw_sha256
        ):
            raise RealSourceEvidenceError("OBSERVATION_RECEIPT_MISMATCH", key)
        required = {
            "day": key,
            "first_seen_at": revision["first_seen_at"],
            "committed_at": commit["committed_at"],
            "raw_sha256": revision["raw_sha256"],
            "raw_bytes": revision["raw_bytes"],
            "raw_relative_path": revision["raw_relative_path"],
            "batch_seal_sha256": manifest["batch_seal_sha256"],
        }
        if any(record.get(field) != value for field, value in required.items()):
            raise RealSourceEvidenceError("SOURCE_PROVENANCE_MISMATCH", f"{key} signed custody differs from provenance")
        bound = datetime.combine(day, time(15, 0), SHANGHAI).astimezone(timezone.utc)
        if parse_utc(revision["first_seen_at"], "first_seen_at") < bound or parse_utc(commit["committed_at"], "committed_at") < bound:
            raise RealSourceEvidenceError("SOURCE_BEFORE_MARKET_CLOSE", f"{key} settlement was observed/committed before close")
        if not (
            bound <= parse_utc(observation["observed_at"], "observed_at")
            <= parse_utc(receipt["completed_at"], "completed_at")
            <= parse_utc(commit["committed_at"], "committed_at")
        ):
            raise RealSourceEvidenceError("SOURCE_OBSERVATION_ORDER", key)
        raw = read_regular_strict(custody / revision["raw_relative_path"], "SHFE original daily file")
        if len(raw) != revision["raw_bytes"] or hashlib.sha256(raw).hexdigest() != revision["raw_sha256"]:
            raise RealSourceEvidenceError("SOURCE_EVIDENCE_MISMATCH", f"{key} parsed raw differs from signed revision")
        source = parse_json_strict(raw, "SHFE original daily file")
        if source.get("report_date") != day.strftime("%Y%m%d"):
            raise RealSourceEvidenceError("SOURCE_DAY_MISMATCH", key)
        rows = source.get("o_curinstrument")
        if not isinstance(rows, list):
            raise RealSourceEvidenceError("SOURCE_ROWS_MISSING", key)
        prices: dict[str, float] = {}
        for product in PRODUCT_RULES:
            matches = [row for row in rows if isinstance(row, dict) and row.get("PRODUCTID") == product and str(row.get("DELIVERYMONTH")) == "2701"]
            if len(matches) != 1:
                raise RealSourceEvidenceError("CONTRACT_ROW_MISMATCH", f"{key} {product}2701")
            price = matches[0].get("SETTLEMENTPRICE")
            if not isinstance(price, (int, float)) or isinstance(price, bool) or price <= 0 or record.get("settlement", {}).get(product) != price:
                raise RealSourceEvidenceError("SETTLEMENT_PRICE_MISMATCH", f"{key} {product}2701")
            prices[product] = float(price)
        verified[key] = VerifiedRealDay(
            trade_day=key,
            settlement_not_before=bound.isoformat().replace("+00:00", "Z"),
            calendar_sha256=CALENDAR_SHA256,
            rule_sha256=SHFE_RULE_SHA256,
            batch_seal_sha256=manifest["batch_seal_sha256"],
            raw_sha256=revision["raw_sha256"],
            revision_id=revision["revision_id"],
            source_url=expected_url,
            first_seen_at=revision["first_seen_at"],
            committed_at=commit["committed_at"],
            settlement=prices,
        )
        previous_batch_seal = manifest["batch_seal_sha256"]
        previous_commit_seal = commit_seal
    return verified


def verify_shfe_settlement_days(
    source_days: list[dict],
    *,
    bundle_root: Path,
    official_rules_root: Path,
) -> dict[str, VerifiedRealDay]:
    """Convert malformed or missing external evidence into a controlled gate failure."""
    try:
        return _verify_shfe_settlement_days(
            source_days,
            bundle_root=bundle_root,
            official_rules_root=official_rules_root,
        )
    except RealSourceEvidenceError:
        raise
    except (RegistryError, OSError, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise RealSourceEvidenceError("SOURCE_EVIDENCE_INVALID", str(exc)) from exc
