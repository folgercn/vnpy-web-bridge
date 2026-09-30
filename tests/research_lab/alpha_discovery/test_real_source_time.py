"""Private M2 witness tests; never mutate or delete the original custody cache.

Set ISSUE502_SOURCE_BUNDLE, ISSUE502_OFFICIAL_RULES and ISSUE502_PROVENANCE
to run against the authorized read-only evidence projection. CI without that
private evidence skips these cryptographic witness tests.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from research_lab.alpha_discovery.real_source_time import (
    RealSourceEvidenceError,
    verify_shfe_settlement_days,
)
from research_lab.alpha_discovery.signal_binding import SignalBindingError, precheck_candidate_real_data
from scripts.precheck_issue502_real_source_pit import _candidate


@pytest.fixture(scope="module")
def witness() -> tuple[Path, Path, Path, list[dict]]:
    values = [os.environ.get(name) for name in ("ISSUE502_SOURCE_BUNDLE", "ISSUE502_OFFICIAL_RULES", "ISSUE502_PROVENANCE")]
    if not all(values):
        pytest.skip("private M2 source witness not available in CI")
    bundle, official, provenance = (Path(value) for value in values)
    days = json.loads(provenance.read_bytes())["source_days"]
    return bundle, official, provenance, days


def test_signed_source_window_and_conservative_market_bound(witness: tuple) -> None:
    bundle, official, _, days = witness
    verified = verify_shfe_settlement_days(days, bundle_root=bundle, official_rules_root=official)
    assert len(verified) == 19
    assert verified["2026-09-24"].settlement_not_before == "2026-09-24T07:00:00Z"
    assert verified["2026-09-24"].settlement == {"rb_f": 3111.0, "hc_f": 3293.0}


def test_replacing_official_rule_fails_closed(witness: tuple, tmp_path: Path) -> None:
    bundle, official, _, days = witness
    copy = tmp_path / "rules"
    shutil.copytree(official, copy)
    (copy / "shfe-trading-rules-202606.docx").write_bytes(b"unverified replacement")
    with pytest.raises(RealSourceEvidenceError, match="SHA256 mismatch"):
        verify_shfe_settlement_days(days, bundle_root=bundle, official_rules_root=copy)


def test_rehashed_raw_and_provenance_cannot_bypass_signed_batch(witness: tuple, tmp_path: Path) -> None:
    bundle, official, _, days = witness
    copy_root = tmp_path / "bundle"
    shutil.copytree(bundle, copy_root)
    altered = copy.deepcopy(days)
    first = altered[0]
    raw_path = copy_root / "warehouse/custody" / first["raw_relative_path"]
    original = raw_path.read_bytes()
    source = json.loads(original)
    matches = [row for row in source["o_curinstrument"] if row.get("PRODUCTID") == "rb_f" and str(row.get("DELIVERYMONTH")) == "2701"]
    assert len(matches) == 1
    matches[0]["SETTLEMENTPRICE"] += 1
    raw = json.dumps(source, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert raw != original
    raw_path.write_bytes(raw)
    first["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    first["raw_bytes"] = len(raw)
    with pytest.raises(RealSourceEvidenceError):
        verify_shfe_settlement_days(altered, bundle_root=copy_root, official_rules_root=official)


@pytest.mark.parametrize("change", ["contract", "trade_day", "missing_day"])
def test_signed_source_binding_rejects_mismatch(witness: tuple, change: str) -> None:
    bundle, official, _, days = witness
    altered = copy.deepcopy(days)
    if change == "contract":
        altered[0]["settlement"]["rb_f"] += 1
    elif change == "trade_day":
        altered[0]["day"] = "2026-08-30"
    else:
        del altered[1]
    with pytest.raises(RealSourceEvidenceError):
        verify_shfe_settlement_days(altered, bundle_root=bundle, official_rules_root=official)


def test_corrupted_signed_commit_rejected(witness: tuple, tmp_path: Path) -> None:
    bundle, official, _, days = witness
    copy_root = tmp_path / "bundle"
    shutil.copytree(bundle, copy_root)
    receipt = next((copy_root / "warehouse/custody/manifests/2026-08-31").glob("commit-*.json"))
    payload = json.loads(receipt.read_bytes())
    payload["committed_at"] = "2026-08-31T10:40:12.000000Z"
    receipt.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(RealSourceEvidenceError):
        verify_shfe_settlement_days(days, bundle_root=copy_root, official_rules_root=official)


def test_self_attested_authority_cannot_unlock_real_path(witness: tuple, tmp_path: Path) -> None:
    bundle, official, provenance, days = witness
    altered = json.loads(provenance.read_bytes())
    altered["source_days"][2]["market_time_authority"] = "SHFE_OFFICIAL"
    altered["source_days"][2]["market_effective_time"] = "2026-09-02T07:00:00Z"
    path = tmp_path / "self-attested.json"
    path.write_text(json.dumps(altered, sort_keys=True))
    hypothesis = _candidate("human-momentum-k1-rb", "RB2701", "momentum", "log(settlement[t] / settlement[t-1])")
    with pytest.raises(SignalBindingError) as raised:
        precheck_candidate_real_data(hypothesis, path, tmp_path / "out", provenance_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), real_source_bundle_root=bundle, official_rules_root=official)
    assert raised.value.reason == "UNVERIFIED_MARKET_TIME_AUTHORITY"
